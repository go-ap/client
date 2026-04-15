package s2s

import (
	"bytes"
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
	e "github.com/common-fate/httpsig/alg_ecdsa"
	ed "github.com/common-fate/httpsig/alg_ed25519"
	r "github.com/common-fate/httpsig/alg_rsa"
	"github.com/common-fate/httpsig/sigbase"
	"github.com/common-fate/httpsig/signature"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/sigset"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-fed/httpsig"
)

var (
	nilLogger = lw.Dev(lw.SetOutput(io.Discard))

	digestAlgorithm     = httpsig.DigestSha256
	signatureExpiration = int64(time.Hour.Seconds())
)

type Transport struct {
	Base http.RoundTripper

	// Tag is an application-specific tag for the signature as a String value.
	// This value is used by applications to help identify signatures relevant for specific applications or protocols.
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3-4.12
	Tag string

	CoveredComponents []string
	nonceFn           func() (string, error)
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

func WithCoveredComponents(s ...string) OptionFn {
	return func(h *Transport) error {
		h.CoveredComponents = s
		return nil
	}
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
//  that might come from the initialization functions.
func New(initFns ...OptionFn) *Transport {
	h := new(Transport)
	h.CoveredComponents = FetchCoveredComponents
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

func pemEncodePublicKey(prvKey crypto.PrivateKey) string {
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

var getCurrentTime = func() time.Time {
	return time.Now().Truncate(time.Millisecond).UTC()
}

func randomNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func (s *Transport) signRequestRFC(or *http.Request) error {
	if s.Actor == nil {
		return errors.Newf("unable to sign request, Actor is invalid")
	}
	if s.Key == nil {
		return errors.Newf("unable to sign request, private key is invalid")
	}

	act := s.Actor
	prv := s.Key
	actorPubKey, err := toCryptoPublicKey(act.PublicKey)
	if err != nil {
		return errors.Annotatef(err, "unable to sign request, Actor public key type %T is invalid", actorPubKey)
	}
	keyID := string(act.PublicKey.ID)

	var alg signer.Algorithm
	switch pk := prv.(type) {
	case *rsa.PrivateKey:
		pub, _ := pk.Public().(*rsa.PublicKey)
		if !pub.Equal(actorPubKey) {
			return keyMismatchErr(pk, actorPubKey)
		}
		alg = r.NewRSAPKCS256Signer(pk)
	case *ecdsa.PrivateKey:
		pub, _ := pk.Public().(*ecdsa.PublicKey)
		if !pub.Equal(actorPubKey) {
			return keyMismatchErr(pk, actorPubKey)
		}
		alg = e.NewP384Signer(pk)
	case ed25519.PrivateKey:
		pub, _ := pk.Public().(ed25519.PublicKey)
		if !pub.Equal(actorPubKey) {
			return keyMismatchErr(pk, actorPubKey)
		}
		alg = &ed.Ed25519{PrivateKey: pk, PublicKey: pub}
	}
	// parse the existing signature set on the request
	set, err := sigset.Unmarshal(or)
	if err != nil {
		return err
	}

	// derive the signature.
	nonce, err := s.nonceFn()
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	params := sigparams.Params{
		KeyID:             keyID,
		Tag:               s.Tag,
		Alg:               alg.Type(),
		Created:           getCurrentTime(),
		CoveredComponents: s.CoveredComponents,
		Nonce:             nonce,
	}

	// derive the signature base following the process in https://www.rfc-editor.org/rfc/rfc9421.html#create-sig-input
	base, err := sigbase.Derive(params, nil, or, alg.ContentDigest())
	if err != nil {
		return fmt.Errorf("deriving signature base: %w", err)
	}

	stringToSign, err := base.CanonicalString(params)
	if err != nil {
		return fmt.Errorf("creating string to sign: %w", err)
	}
	// sign the signature base according to the signing algorithm
	sig, err := alg.Sign(or.Context(), stringToSign)
	if err != nil {
		return fmt.Errorf("error signing request: %w", err)
	}

	// construct the HTTP message signature
	ms := signature.Message{Input: params, Signature: sig}

	// add the signature to the set
	set.Add(&ms)

	// include the signature in the cloned HTTP request.
	return set.Include(or)
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

	errs := make([]error, 0, 3)
	roundTripFn := func(req *http.Request, signFn func(*http.Request) error) (*http.Response, error) {
		if signFn != nil {
			lctx := lw.Ctx{"key": pemEncodePublicKey(s.Key)}
			if s.Actor != nil {
				lctx["actor"] = s.Actor.ID
			}
			err := signFn(req)
			if err != nil {
				if s.l != nil {
					s.l.WithContext(lctx, lw.Ctx{"err": err.Error()}).Errorf("unable to sign request")
				}
				errs = append(errs, err)
				return nil, ErrRetry
			}
		}

		res, err := tr.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		switch res.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			// NOTE(marius): Not an acceptable response status, so we want to try again.
			// We also need to close the body of discarded response to avoid leaks.
			_ = res.Body.Close()
			return nil, ErrRetry
		default:
			// NOTE(marius): some kind of success
			return res, nil
		}
	}

	or := *req
	isFetchRequest := req.Method == http.MethodGet || req.Method == http.MethodHead

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

		// NOTE(marius): try #2: use cavage-12 draft signature
		res, err = roundTripFn(cloneRequest(&or, buff), s.signRequestCavage)
		if err == nil || !errors.Is(err, ErrRetry) {
			return res, err
		}
		if err != nil && errors.Is(err, ErrRetry) && !isFetchRequest {
			slices.Reverse(errs)
			err = errs[0]
			return res, err
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

	return res, errors.Join(errs...)
}

func toCryptoPublicKey(key vocab.PublicKey) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(key.PublicKeyPem))
	if block == nil {
		return nil, errors.Errorf("invalid PEM decode on public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func keyMismatchErr(pk crypto.PrivateKey, pub crypto.PublicKey) error {
	return errors.Newf("unable to sign request, mismatch between the Actor's public and private key: %T : %T", pub, pk)
}

func (s *Transport) signRequestCavage(req *http.Request) error {
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

	algos := make([]httpsig.Algorithm, 0)
	switch s.Key.(type) {
	case *rsa.PrivateKey:
		algos = append(algos, httpsig.RSA_SHA256, httpsig.RSA_SHA512)
	case *ecdsa.PrivateKey:
		algos = append(algos, httpsig.ECDSA_SHA512, httpsig.ECDSA_SHA256)
	case ed25519.PrivateKey:
		algos = append(algos, httpsig.ED25519)
	}

	// NOTE(marius): The only http-signatures accepted by Mastodon instances is "Signature", not "Authorization"
	sig, _, err := httpsig.NewSigner(algos, digestAlgorithm, headers, httpsig.Signature, signatureExpiration)
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
