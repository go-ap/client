package s2s

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/common-fate/httpsig/sigset"
	vocab "github.com/go-ap/activitypub"
)

var (
	prvPemRSA = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`

	block, _  = pem.Decode([]byte(prvPemRSA))
	prvRSA, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	millenium = time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)

	actor = func() *vocab.Actor {
		actor := new(vocab.Actor)
		actor.ID = "https://example.com/~johndoe"
		pub := prvRSA.Public()
		pubEnc, _ := x509.MarshalPKIXPublicKey(pub)
		pubEncoded := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubEnc,
		})

		actor.PublicKey = vocab.PublicKey{
			ID:           vocab.IRI(fmt.Sprintf("%s#main", actor.ID)),
			Owner:        actor.ID,
			PublicKeyPem: string(pubEncoded),
		}
		return actor
	}()
)

func ExampleTransport_RoundTrip_draft() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s\n", r.Header.Get("Signature"))
		w.WriteHeader(http.StatusOK)
	}))
	tr := New(WithTransport(http.DefaultTransport), WithActor(actor, prvRSA), NoRFC9421)

	// The below functionality would be equivalent to the following usage:
	//http.DefaultClient.Transport = tr
	//res, err := http.Get(srv.URL)

	req := httptest.NewRequest(http.MethodGet, srv.URL, nil)
	host := strings.TrimPrefix(srv.URL, "http://")
	host = host[:strings.Index(host, ":")]
	req.Header.Set("Host", host)
	req.Header.Set("Date", millenium.Format(http.TimeFormat))
	_, _ = tr.RoundTrip(req)

	// Output:
	// keyId="https://example.com/~johndoe#main",algorithm="hs2019",headers="(request-target) host date",signature="PYSZQkKUmr9ZDxuNCLe69krLB/0bsprA/K4p4+l0xIINcUBfhDBJNPkN64Omm1tdraTsWfh2JBWQeIdEAW6mm72ERCvqyOldszpiS/PkkVVApduI8tmhSDaoy0I/E3VGanZomEwER5E3VLerAu7ENy8lZrbsYUP7T+pZ+IeMBlM="
}

func sameNonce() (string, error) {
	return "test", nil
}

func ExampleTransport_RoundTrip_rfc9421() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := sigset.Unmarshal(r)
		if sig, ok := s.Messages["sig1"]; ok {
			fmt.Printf("KeyID: %s\n", sig.Input.KeyID)
			fmt.Printf("Alg: %s\n", sig.Input.Alg)
			fmt.Printf("Nonce: %s\n", sig.Input.Nonce)
			fmt.Printf("CoveredComponents: %v\n", sig.Input.CoveredComponents)
		}
		w.WriteHeader(http.StatusOK)
	}))
	tr := New(WithTransport(http.DefaultTransport), WithActor(actor, prvRSA), WithNonce(sameNonce))
	req := httptest.NewRequest(http.MethodPost, srv.URL, nil)
	req.Header.Set("Date", millenium.Format(http.TimeFormat))
	_, _ = tr.RoundTrip(req)

	// Output:
	// KeyID: https://example.com/~johndoe#main
	// Alg: rsa-v1_5-sha256
	// Nonce: test
	// CoveredComponents: [@method @target-uri]
	//
}
