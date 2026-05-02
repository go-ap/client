package s2s

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"git.sr.ht/~mariusor/lw"
	rfc "github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	draft "github.com/go-fed/httpsig"
)

var (
	nilLogger = lw.Dev(lw.SetOutput(io.Discard))

	digestAlgorithm  = draft.DigestSha256
	sigValidDuration = time.Hour
)

type Transport struct {
	Base http.RoundTripper

	// Tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	Tag string

	nonceFn           noncer
	skipRFCSignatures bool

	Key   crypto.PrivateKey
	Actor *vocab.Actor

	l lw.Logger
}

type OptionFn func(transport *Transport) error

func WithTransport(tr http.RoundTripper) OptionFn {
	return func(h *Transport) error {
		h.Base = tr
		return nil
	}
}

func NoRFC9421(h *Transport) error {
	h.skipRFCSignatures = true
	return nil
}

func WithNonce(nonceFn func() (string, error)) OptionFn {
	return func(h *Transport) error {
		h.nonceFn = nonceFn
		return nil
	}
}

func WithActor(act *vocab.Actor, prv crypto.PrivateKey) OptionFn {
	return func(h *Transport) error {
		h.Actor = act
		h.Key = prv

		return nil
	}
}

func WithLogger(l lw.Logger) OptionFn {
	return func(h *Transport) error {
		h.l = l
		return nil
	}
}

func WithApplicationTag(t string) OptionFn {
	return func(h *Transport) error {
		h.Tag = t
		return nil
	}
}

// New initializes the Transport
// TODO(marius): we need to add to the return values the errors
// that might come from the initialization functions.
func New(initFns ...OptionFn) *Transport {
	h := new(Transport)
	h.nonceFn = randomNonce
	h.l = nilLogger
	for _, fn := range initFns {
		if err := fn(h); err != nil {
			h.l.Errorf("unable to initialize HTTP Signature transport: %s", err)
			return h /*, err*/
		}
	}
	return h /*, nil*/
}

type privateKey interface {
	Public() crypto.PublicKey
}

func pemEncodePrivateKey(prvKey crypto.PrivateKey) string {
	prv, ok := prvKey.(privateKey)
	if !ok {
		return fmt.Sprintf("invalid private key: %T", prvKey)
	}
	pubEnc, err := x509.MarshalPKIXPublicKey(prv.Public())
	if err != nil {
		return "invalid public key: %s" + err.Error()
	}
	p := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubEnc,
	}
	return strings.ReplaceAll(string(pem.EncodeToMemory(&p)), "\n", "")
}

func randomNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

type noncer func() (string, error)

func (n noncer) GetNonce(_ context.Context) (string, error) {
	return n()
}

func validateActorPublicKey(key crypto.PrivateKey, act vocab.Actor) error {
	actorPubKey, err := toCryptoPublicKey(act.PublicKey)
	if err != nil {
		return errors.Annotatef(err, "unable to sign request, Actor public key type %T is invalid", actorPubKey)
	}
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

func rfcAlgorithmFromPrivateKey(key crypto.PrivateKey) rfc.SignatureAlgorithm {
	// NOTE(marius): I'm not sure what purpose it serves to validate the public key of the actor
	// against the private key
	var alg rfc.SignatureAlgorithm
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		switch pk.PublicKey.Size() {
		case 128, 256:
			alg = rfc.RsaPkcs1v15Sha256
		case 384:
			alg = rfc.RsaPkcs1v15Sha384
		case 512:
			alg = rfc.RsaPkcs1v15Sha512
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

func (s *Transport) signRequestRFC(req *http.Request) error {
	if s.Actor == nil {
		return errors.Newf("unable to sign request, Actor is invalid")
	}
	if s.Key == nil {
		return errors.Newf("unable to sign request, private key is invalid")
	}

	if err := validateActorPublicKey(s.Key, *s.Actor); err != nil {
		return errors.Annotatef(err, "unable to sign request, Actor public key does not match it's private key")
	}

	key := rfc.Key{
		KeyID:     string(s.Actor.PublicKey.ID),
		Algorithm: rfcAlgorithmFromPrivateKey(s.Key),
		Key:       s.Key,
	}

	initFns := []rfc.SignerOption{
		rfc.WithTTL(sigValidDuration),
		rfc.WithNonce(s.nonceFn),
	}

	if s.Tag != "" {
		initFns = append(initFns, rfc.WithTag(s.Tag))
	}

	switch req.Method {
	case http.MethodHead, http.MethodGet:
		initFns = append(initFns, rfc.WithComponents(FetchCoveredComponents...))
	case http.MethodPost:
		initFns = append(initFns, rfc.WithComponents(PostCoveredComponents...))
		initFns = append(initFns, rfc.WithContentDigestAlgorithm(rfc.Sha256))
	}
	signer, err := rfc.NewSigner(key, initFns...)
	if err != nil {
		return err
	}
	postSignHeaders, err := signer.Sign(rfc.MessageFromRequest(req))
	if err != nil {
		return err
	}
	req.Header = postSignHeaders
	return nil
}

var ErrRetry = errors.Newf("retry")

// RoundTrip dispatches the received request after signing it.
// We currently use the double knocking mechanism Mastodon popularized:
// * we first attempt to sign the request with RFC9421 compliant signature,
// * if it failed, we try again using a draft Cavage-12 version signature.
// Additionally, if everything failed, and we're operating with a fetch request,
// we make one last, non-signed attempt.
func (s *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr := s.Base
	if tr == nil {
		tr = http.DefaultTransport
	}

	roundTripFn := func(req *http.Request, signFn func(*http.Request) error) (*http.Response, error) {
		lctx := lw.Ctx{}
		lastTry := false
		if signFn == nil {
			lastTry = true
		} else {
			lctx["keyType"] = fmt.Sprintf("%T", s.Key)
			if s.Actor != nil {
				lctx["actor"] = s.Actor.ID
				if s.Actor.PublicKey.ID != "" {
					lctx["keyID"] = s.Actor.PublicKey.ID
				}
			}
			if err := signFn(req); err != nil {
				if s.l != nil {
					s.l.WithContext(lctx, lw.Ctx{"err": err.Error()}).Errorf("unable to sign request")
				}
				return nil, ErrRetry
			}
		}

		res, err := tr.RoundTrip(req)
		if lastTry || err != nil {
			return res, err
		}

		switch res.StatusCode {
		case http.StatusBadRequest:
			// NOTE(marius): this is a hack for tags.pub that doesn't
			// return a 403 or 401 error status on failing signatures
			// See https://todo.sr.ht/~mariusor/go-activitypub/473
			fallthrough
		case http.StatusUnauthorized, http.StatusForbidden:
			// NOTE(marius): Not an acceptable response status, so we want to try again.
			// We also need to close the body of discarded response to avoid leaks.
			_ = res.Body.Close()
			if s.l != nil {
				s.l.WithContext(lctx).Errorf("received %s response", res.Status)
			}
			return nil, ErrRetry
		default:
			// NOTE(marius): some kind of success
			return res, nil
		}
	}

	or := *req
	isFetchRequest := slices.Contains([]string{http.MethodGet, http.MethodHead}, req.Method)

	if or.URL != nil && or.URL.Path == "" {
		or.URL.Path = "/"
	}

	var res *http.Response
	var err error
	if s.Actor != nil && s.Key != nil {
		// NOTE(marius): we're to sign the request, so we need to copy the body
		var buff []byte
		if or.Body != nil {
			if buff, err = io.ReadAll(or.Body); err != nil {
				return nil, err
			}
		}
		if !s.skipRFCSignatures {
			// NOTE(marius): try #1: use RFC9421 signature
			res, err = roundTripFn(cloneRequest(&or, buff), s.signRequestRFC)
			if err == nil || !errors.Is(err, ErrRetry) {
				return res, err
			}
			if res != nil && res.Body != nil {
				_ = res.Body.Close()
			}
		}

		// NOTE(marius): try #2: use Cavage-12 draft signature
		res, err = roundTripFn(cloneRequest(&or, buff), s.signRequestDraft)
		if err == nil || !errors.Is(err, ErrRetry) {
			return res, err
		}

		// NOTE(marius): if draft signatures failed also, and this is not
		// a request that we can retry w/o a signature, we return the resulting
		// errors.
		if err != nil && errors.Is(err, ErrRetry) && !isFetchRequest {
			return res, errors.Unauthorizedf("unauthorized")
		}

		if res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
	}

	if isFetchRequest {
		// NOTE(marius): This is a mitigation for loading Public Keys for Actors on other instances,
		// which can create an infinite loop of requests if that instance tries to do an authorize-fetch
		// for our signing Actor.
		// There are more details in ticket: https://todo.sr.ht/~mariusor/go-activitypub/301
		return roundTripFn(&or, nil)
	}

	return nil, errors.Unauthorizedf("unauthorized")
}

func toCryptoPublicKey(key vocab.PublicKey) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(key.PublicKeyPem))
	if block == nil {
		return nil, errors.Errorf("invalid PEM decode on public key")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pk, err
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func keyMismatchErr(pk crypto.PrivateKey, pub crypto.PublicKey) error {
	return errors.Newf("unable to sign request, mismatch between the Actor's public and private key: %T : %T", pub, pk)
}

func (s *Transport) signRequestDraft(req *http.Request) error {
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
		switch pk.PublicKey.Size() {
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

var _ http.RoundTripper = new(Transport)

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request, buff []byte) *http.Request {
	r2 := r.Clone(r.Context())
	if buff != nil {
		r2.Body = io.NopCloser(bytes.NewReader(buff))
	}
	return r2
}
