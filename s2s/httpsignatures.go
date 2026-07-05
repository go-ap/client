package s2s

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"slices"
	"time"

	rfc "github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	draft "github.com/go-fed/httpsig"
)

var (
	digestAlgorithm  = draft.DigestSha256
	sigValidDuration = time.Hour
)

type Signer struct {
	// RFC9421 relevant data
	nonceFn           noncer
	coveredComponents []string
	// tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	tag string

	Alg   KeyEncoding
	Key   crypto.PrivateKey
	Actor *vocab.Actor
}

type OptionFn func(transport *Signer) error

func WithNonce(nonceFn func() (string, error)) OptionFn {
	return func(h *Signer) error {
		h.nonceFn = nonceFn
		return nil
	}
}

func WithCoveredComponents(comp ...string) OptionFn {
	return func(h *Signer) error {
		h.coveredComponents = comp
		return nil
	}
}

func WithAlg(alg KeyEncoding) OptionFn {
	return func(h *Signer) error {
		h.Alg = alg
		return nil
	}
}

func WithActor(act *vocab.Actor, prv crypto.PrivateKey) OptionFn {
	return func(h *Signer) error {
		h.Actor = act
		h.Key = prv

		return nil
	}
}

func WithApplicationTag(t string) OptionFn {
	return func(h *Signer) error {
		h.tag = t
		return nil
	}
}

// New initializes the Signer
// that might come from the initialization functions.
func New(initFns ...OptionFn) (*Signer, error) {
	// TODO(marius): we need to add the errors to the return values
	h := new(Signer)
	for _, fn := range initFns {
		if err := fn(h); err != nil {
			return h, err
		}
	}
	return h, nil
}

type noncer func() (string, error)

func (n noncer) GetNonce(_ context.Context) (string, error) {
	return n()
}

func validateActorPublicKey(key crypto.PrivateKey, actorPubKey crypto.PublicKey) error {
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		pub := &pk.PublicKey
		if !pub.Equal(actorPubKey) {
			return keyMismatchErr(pk, actorPubKey)
		}
	case *ecdsa.PrivateKey:
		pub, ok := pk.Public().(*ecdsa.PublicKey)
		if !ok || !pub.Equal(actorPubKey) {
			return keyMismatchErr(pk, actorPubKey)
		}
	case ed25519.PrivateKey:
		pub, _ := pk.Public().(ed25519.PublicKey)
		if !pub.Equal(actorPubKey) {
			return keyMismatchErr(pk, actorPubKey)
		}
	}
	return nil
}

func rfcAlgorithmFromPrivateKey(key crypto.PrivateKey, typ KeyEncoding) rfc.SignatureAlgorithm {
	// NOTE(marius): I'm not sure what purpose it serves to validate the public key of the actor
	// against the private key
	var alg rfc.SignatureAlgorithm = ""

	switch pk := key.(type) {
	case *rsa.PrivateKey:
		switch pk.Size() {
		case 128, 256:
			switch typ {
			case KeyTypePSS:
				alg = rfc.RsaPssSha256
			case KeyTypePKCS:
				fallthrough
			default:
				alg = rfc.RsaPkcs1v15Sha256
			}
		case 384:
			switch typ {
			case KeyTypePSS:
				alg = rfc.RsaPssSha384
			case KeyTypePKCS:
				fallthrough
			default:
				alg = rfc.RsaPkcs1v15Sha384
			}
		case 512:
			switch typ {
			case KeyTypePSS:
				alg = rfc.RsaPssSha512
			case KeyTypePKCS:
				fallthrough
			default:
				alg = rfc.RsaPkcs1v15Sha512
			}
		}
	case *ecdsa.PrivateKey:
		if p := pk.Params(); p != nil {
			switch p.BitSize {
			case 128, 256:
				alg = rfc.EcdsaP256Sha256
			case 384:
				alg = rfc.EcdsaP384Sha384
			case 512:
				alg = rfc.EcdsaP521Sha512
			}
		}
	case ed25519.PrivateKey:
		alg = rfc.Ed25519
	}
	return alg
}

func (s *Signer) signRequestRFC(coveredComponents []string) func(req *http.Request) error {
	return func(req *http.Request) error {
		if s.Actor == nil {
			return errors.Newf("unable to sign request, Actor is invalid")
		}
		if s.Key == nil {
			return errors.Newf("unable to sign request, private key is invalid")
		}

		pubKey, err := toCryptoPublicKey(s.Actor.PublicKey)
		if err != nil {
			return errors.Annotatef(err, "unable to sign request, unable to validate the Actor's public key")
		}
		if err = validateActorPublicKey(s.Key, pubKey); err != nil {
			return errors.Annotatef(err, "unable to sign request, Actor public key does not match it's private key")
		}

		key := rfc.Key{
			KeyID:     string(s.Actor.PublicKey.ID),
			Algorithm: rfcAlgorithmFromPrivateKey(s.Key, s.Alg),
			Key:       s.Key,
		}

		initFns := []rfc.SignerOption{
			rfc.WithTTL(sigValidDuration),
		}

		if s.tag != "" {
			initFns = append(initFns, rfc.WithTag(s.tag))
		}

		if coveredComponents != nil {
			initFns = append(initFns, rfc.WithComponents(coveredComponents...))
		}
		if req.Method == http.MethodPost {
			initFns = append(initFns, rfc.WithContentDigestAlgorithm(rfc.Sha256))
		}
		if s.nonceFn != nil {
			initFns = append(initFns, rfc.WithNonce(s.nonceFn))
		}
		signer, err := rfc.NewSigner(key, initFns...)
		if err != nil {
			return err
		}
		msg := rfc.MessageFromRequest(req)
		// NOTE(marius): for some fetch requests, we have a non empty fragment
		// I'm not clear if this case is handled correctly on the verifier side.
		//if msg.URL.Fragment != "" {
		//	req.URL.Fragment = ""
		//}
		postSignHeaders, err := signer.Sign(msg)
		if err != nil {
			return err
		}
		req.Header = postSignHeaders
		return nil
	}
}

type KeyEncoding int

const (
	KeyTypeUnknown KeyEncoding = 0
	KeyTypePKCS    KeyEncoding = 1
	KeyTypePSS     KeyEncoding = 2
)

func toCryptoPublicKey(key vocab.PublicKey) (crypto.PublicKey, error) {
	pubBytes, _ := pem.Decode([]byte(key.PublicKeyPem))
	if pubBytes == nil {
		return nil, errors.Newf("unable to decode PEM payload for public key")
	}
	pk, _ := x509.ParsePKIXPublicKey(pubBytes.Bytes)
	if pk != nil {
		return pk, nil
	}
	pk, err := x509.ParsePKCS1PublicKey(pubBytes.Bytes)
	return pk, err
}

func keyMismatchErr(pk crypto.PrivateKey, pub crypto.PublicKey) error {
	return errors.Newf("unable to sign request, mismatch between the Actor's public and private key: %T : %T", pub, pk)
}

func (s *Signer) signRequestDraft(req *http.Request) error {
	if s.Actor == nil {
		return errors.Newf("unable to sign request, Actor is invalid")
	}
	if s.Key == nil {
		return errors.Newf("unable to sign request, private key is invalid")
	}
	if !s.Actor.PublicKey.ID.IsValid() {
		return errors.Newf("unable to sign request, invalid Actor public key ID")
	}

	keyID := s.Actor.PublicKey.ID

	headers := HeadersToSign
	bodyBuf := bytes.Buffer{}
	if req.Body != nil {
		if _, err := io.Copy(&bodyBuf, req.Body); err == nil {
			req.Body = io.NopCloser(&bodyBuf)
			if bodyBuf.Len() > 0 {
				headers = append(HeadersToSign, "digest")
			}
		}
	}

	algos := make([]draft.Algorithm, 0)
	switch pk := s.Key.(type) {
	case *rsa.PrivateKey:
		switch pk.Size() {
		case 128, 256:
			algos = append(algos, draft.RSA_SHA256)
		case 384:
			algos = append(algos, draft.RSA_SHA384)
		case 512:
			algos = append(algos, draft.RSA_SHA512)
		}
	case *ecdsa.PrivateKey:
		if p := pk.Params(); p != nil {
			switch p.BitSize {
			case 128, 256:
				algos = append(algos, draft.ECDSA_SHA256)
			case 384:
				algos = append(algos, draft.ECDSA_SHA384)
			case 512:
				algos = append(algos, draft.ECDSA_SHA512)
			}
		}
	case ed25519.PrivateKey:
		algos = append(algos, draft.ED25519)
	}

	secToExpiration := int64(sigValidDuration.Seconds())
	// NOTE(marius): The only http-signatures accepted by Mastodon instances is "Signature", not "Authorization"
	sig, _, err := draft.NewSigner(algos, digestAlgorithm, headers, draft.Signature, secToExpiration)
	if err != nil {
		return err
	}
	return sig.SignRequest(s.Key, string(keyID), req, bodyBuf.Bytes())
}

func (s *Signer) SignRFC9421(req *http.Request) error {
	coveredComponents := s.coveredComponents
	if coveredComponents == nil {
		// NOTE(marius): ideally the caller knows if we're about to sign a Fetch or not,
		// and provide all necessary covered components at initialization time.
		coveredComponents = FetchCoveredComponents
		if !slices.Contains([]string{http.MethodGet, http.MethodHead}, req.Method) {
			coveredComponents = append(coveredComponents, AdditionalPostCoveredComponents...)
		}
	}
	return s.signRequestRFC(coveredComponents)(req)
}

func (s *Signer) SignDraft(req *http.Request) error {
	return s.signRequestDraft(req)
}
