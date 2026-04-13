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
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.sr.ht/~mariusor/lw"
	e "github.com/common-fate/httpsig/alg_ecdsa"
	ed "github.com/common-fate/httpsig/alg_ed25519"
	r "github.com/common-fate/httpsig/alg_rsa"
	"github.com/common-fate/httpsig/signer"
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
	signer.Transport

	// m is needed for ensuring the signer.Transport CoveredComponents writes and reads
	// don't cause a race condition.
	m     sync.RWMutex
	Key   crypto.PrivateKey
	Actor *vocab.Actor

	l lw.Logger
}

type OptionFn func(transport *Transport) error

func WithTransport(tr http.RoundTripper) OptionFn {
	return func(h *Transport) error {
		h.Transport.BaseTransport = tr
		return nil
	}
}

func NoRFC9421(h *Transport) error {
	h.Transport.Alg = nil
	return nil
}

func WithCoveredComponents(s ...string) OptionFn {
	return func(h *Transport) error {
		h.Transport.CoveredComponents = s
		return nil
	}
}
func WithNonce(nonceFn func() (string, error)) OptionFn {
	return func(h *Transport) error {
		h.Transport.GetNonce = nonceFn
		return nil
	}
}

func WithActor(act *vocab.Actor, prv crypto.PrivateKey) OptionFn {
	return func(h *Transport) error {
		h.Actor = act
		h.Key = prv

		if act == nil {
			return nil
		}

		actorPubKey, err := toCryptoPublicKey(act.PublicKey)
		if err != nil {
			return errors.Annotatef(err, "unable to sign request, Actor public key type %T is invalid", actorPubKey)
		}

		h.Transport.KeyID = string(act.PublicKey.ID)
		if prv == nil {
			return nil
		}
		switch pk := prv.(type) {
		case *rsa.PrivateKey:
			pub, _ := pk.Public().(*rsa.PublicKey)
			if !pub.Equal(actorPubKey) {
				return keyMismatchErr(pk, actorPubKey)
			}
			h.Transport.Alg = r.NewRSAPKCS256Signer(pk)
		case *ecdsa.PrivateKey:
			pub, _ := pk.Public().(*ecdsa.PublicKey)
			if !pub.Equal(actorPubKey) {
				return keyMismatchErr(pk, actorPubKey)
			}
			h.Transport.Alg = e.NewP384Signer(pk)
		case ed25519.PrivateKey:
			pub, _ := pk.Public().(ed25519.PublicKey)
			if !pub.Equal(actorPubKey) {
				return keyMismatchErr(pk, actorPubKey)
			}
			h.Transport.Alg = &ed.Ed25519{PrivateKey: pk, PublicKey: pub}
		}
		return nil
	}
}

func WithLogger(l lw.Logger) OptionFn {
	return func(h *Transport) error {
		h.l = l
		if l != nil {
			h.Transport.OnDeriveSigningString = func(ctx context.Context, stringToSign string) {
				l.Debugf("String to sign: %s", stringToSign)
			}
		}
		return nil
	}
}

func WithApplicationTag(t string) OptionFn {
	return func(h *Transport) error {
		h.Transport.Tag = t
		return nil
	}
}

// New initializes the Transport
// TODO(marius): we need to add to the return values the errors
//  that might come from the initialization functions.
func New(initFns ...OptionFn) *Transport {
	h := new(Transport)
	h.Transport.CoveredComponents = FetchCoveredComponents
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

// RoundTrip dispatches the received request after signing it.
// We currently use the double knocking mechanism Mastodon popularized:
// * we first attempt to sign the request with RFC9421 compliant signature,
// * if it failed, we try again using a draft Cavage-12 version signature.
// Additionally, if everything failed, and we're operating with a fetch request,
// we make one last, non-signed attempt.
func (s *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if s.Transport.BaseTransport == nil {
		s.Transport.BaseTransport = http.DefaultTransport
	}
	tr := s.Transport.BaseTransport
	or := *req
	isFetchRequest := req.Method == http.MethodGet || req.Method == http.MethodHead

	if or.URL != nil && or.URL.Path == "" {
		or.URL.Path = "/"
	}

	if s.Actor != nil {
		if s.Transport.Alg != nil {
			// NOTE(marius): we're to sign the request, so we need to drain the request body
			var buff []byte
			if or.Body != nil {
				var err error
				if buff, err = io.ReadAll(or.Body); err != nil {
					return nil, err
				}
			}

			if res, err := s.Transport.RoundTrip(cloneRequest(&or, buff)); err == nil {
				if res.StatusCode < http.StatusBadRequest {
					return res, nil
				}
				// NOTE(marius): Not an acceptable response, so we want to try again.
				// We also need to close the body of discarded response to avoid leaks.
				_ = res.Body.Close()
			}
			// NOTE(marius): we clone another request to provide a readable body.
			req = cloneRequest(&or, buff)
		}

		// NOTE(marius): when the RFC9421 signed request has failed (possibly due to the server not supporting it)
		// we fall back to signing with the Cavage-12 compatible algorithm.
		lctx := lw.Ctx{"key": pemEncodePublicKey(s.Key), "actor": s.Actor.ID}
		if err := s.signRequest(req); err != nil && s.l != nil {
			s.l.WithContext(lctx, lw.Ctx{"err": err.Error()}).Errorf("unable to sign request")
		} else {
			s.l.WithContext(lctx).Debugf("signed request")
		}
	}

	res, err := tr.RoundTrip(req)
	// NOTE(marius): if the RoundTrip fails to produce a response and this is a fetch request,
	// we can try again with the original non-signed request.
	if err != nil && isFetchRequest {
		// NOTE(marius): This is a mitigation for loading Public Keys for Actors on other instances,
		// which can create an infinite loop of requests if that instance tries to do an authorize-fetch
		// for our signing Actor.
		// There are more details in ticket: https://todo.sr.ht/~mariusor/go-activitypub/301
		return tr.RoundTrip(cloneRequest(&or, nil))
	}

	// For the other types of requests that have succeeded, we return now.
	return res, err
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

func (s *Transport) signRequest(req *http.Request) error {
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
	if err = sig.SignRequest(s.Key, string(keyID), req, bodyBuf.Bytes()); err != nil {
		return err
	}
	return nil
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
