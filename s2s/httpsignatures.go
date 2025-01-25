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
	headersToSign       = []string{httpsig.RequestTarget, "host", "date"}
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

func (s *HTTPSignatureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if s.Actor != nil {
		_ = s.signRequest(req)
	}
	return s.Base.RoundTrip(req)
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

	signer, _, err := httpsig.NewSigner(algos, digestAlgorithm, headers, httpsig.Authorization, signatureExpiration)
	if err != nil {
		return err
	}
	if err = signer.SignRequest(s.Key, keyID.String(), req, bodyBuf.Bytes()); err != nil {
		return err
	}
	return nil
}

var _ http.RoundTripper = new(HTTPSignatureTransport)
