package s2s

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"io"
	"net/http"
	"time"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-fed/httpsig"
)

var (
	digestAlgorithm     = httpsig.DigestSha256
	signatureExpiration = int64(time.Hour.Seconds())
)

type HTTPSignatureTransport struct {
	Base http.RoundTripper

	Key   crypto.PrivateKey
	Actor *vocab.Actor
}

func S2SWrapTransport(base http.RoundTripper, actor *vocab.Actor, key crypto.PrivateKey) HTTPSignatureTransport {
	return HTTPSignatureTransport{
		Base:  base,
		Key:   key,
		Actor: actor,
	}
}

// RoundTrip dispatches the received request after signing it
func (s *HTTPSignatureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	or := req
	attemptUnauthorized := false

	if s.Actor != nil {
		req = cloneRequest(or) // per RoundTripper contract
		_ = s.signRequest(req)

		// NOTE(marius): for GET/HEAD requests we should try again without the authorization header
		// if the RoundTrip fails to produce a response.
		attemptUnauthorized = !(req.Method == http.MethodGet || req.Method == http.MethodHead)
	}

	res1, err := s.Base.RoundTrip(req)
	if !attemptUnauthorized || err == nil {
		return res1, err
	}

	// NOTE(marius): if we received an actual error we try the request again, but unsigned.
	//
	// This is a pretty hacky mitigation for loading Public Keys for Actors on other instances, which
	// sometimes triggers a feedback loop if the instance tries to authorize the signing actor in its turn.
	//
	// I detailed that faulty behaviour in ticket:
	//  https://todo.sr.ht/~mariusor/go-activitypub/301
	req = cloneRequest(or) // per RoundTripper contract
	res2, err := s.Base.RoundTrip(req)
	if err != nil {
		return res1, err
	}
	return res2, nil
}

func (s *HTTPSignatureTransport) signRequest(req *http.Request) error {
	if !s.Actor.PublicKey.ID.IsValid() {
		return errors.Newf("unable to sign request, invalid Actor key ID")
	}

	keyID, err := s.Actor.PublicKey.ID.URL()
	if err != nil {
		return errors.Annotatef(err, "unable to sign request, Actor key ID is not a valid URL")
	}

	headers := headersToSign
	bodyBuf := bytes.Buffer{}
	if req.Body != nil {
		if _, err := io.Copy(&bodyBuf, req.Body); err == nil {
			req.Body = io.NopCloser(&bodyBuf)
		}

		headers = append(headersToSign, "digest")
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
	signer, _, err := httpsig.NewSigner(algos, digestAlgorithm, headers, httpsig.Signature, signatureExpiration)
	if err != nil {
		return err
	}
	if err = signer.SignRequest(s.Key, keyID.String(), req, bodyBuf.Bytes()); err != nil {
		return err
	}
	return nil
}

var _ http.RoundTripper = new(HTTPSignatureTransport)

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
