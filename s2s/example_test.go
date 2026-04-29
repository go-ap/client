package s2s

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
)

var (
	testKeyRSAPEM = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----`

	prvKeyRSA, pubKeyRSA, exActorRSA = func() (*rsa.PrivateKey, *rsa.PublicKey, vocab.Actor) {
		pubBlock, remainder := pem.Decode([]byte(testKeyRSAPEM))
		pub, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
		if err != nil {
			panic(err)
		}
		prvBlock, _ := pem.Decode(remainder)
		prv, err := x509.ParsePKCS1PrivateKey(prvBlock.Bytes)
		if err != nil {
			panic(err)
		}
		id := vocab.IRI("https://example.com/~johndoe")
		return prv, pub, vocab.Actor{
			ID: id,
			PublicKey: vocab.PublicKey{
				ID:           vocab.IRI(fmt.Sprintf("%s#main", id)),
				Owner:        id,
				PublicKeyPem: string(pem.EncodeToMemory(pubBlock)),
			},
		}
	}()

	_prvPemRSA = `-----BEGIN RSA PRIVATE KEY-----
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

	block, _  = pem.Decode([]byte(_prvPemRSA))
	prv, _    = x509.ParsePKCS1PrivateKey(block.Bytes)
	pub       = &prv.PublicKey
	pubEnc, _ = x509.MarshalPKIXPublicKey(pub)
	pubPem    = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubEnc,
	})

	millenium = time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)

	jdoeActor = func() *vocab.Actor {
		actor := new(vocab.Actor)
		actor.ID = "https://example.com/~johndoe"

		actor.PublicKey = vocab.PublicKey{
			ID:           vocab.IRI(fmt.Sprintf("%s#main", actor.ID)),
			Owner:        actor.ID,
			PublicKeyPem: string(pubPem),
		}
		return actor
	}()
)

func ExampleTransport_RoundTrip_draft() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s\n", r.Header.Get("Signature"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := New(WithTransport(http.DefaultTransport), WithActor(jdoeActor, prv), NoRFC9421)

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
	// keyId="https://example.com/~johndoe#main",algorithm="hs2019",headers="(request-target) host",signature="RhsET77hrToaCyh/2++dFw0PGn64AoZBR3X2r+rVFWDT1CtobC1sVwXcc91v2c2HmB3A6P3EH1truRnhbNpL2sOgmqUbkRGBoO5afsgaRzRg/z8BwKDlnP9w/6zYlvoYH2VcgQpCTKPUkYDGUexFQDxBJMFime+d361I3ptO/Jc="
}

func sameNonce() (string, error) {
	return "test", nil
}

type mockKeyResolver struct{}

func (m mockKeyResolver) ResolveKey(_ context.Context, keyID string) (httpsig.Key, error) {
	return httpsig.Key{KeyID: string(exActorRSA.PublicKey.ID), Algorithm: httpsig.RsaPkcs1v15Sha256, Key: pubKeyRSA}, nil
}

type mockNonceChecker bool

func (n mockNonceChecker) CheckNonce(ctx context.Context, nonce string) error {
	if n {
		return nil
	}
	return errors.Newf("seen nonce before")
}

func ExampleTransport_RoundTrip_rfc9421() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifier, _ := httpsig.NewVerifier(
			mockKeyResolver{},
			httpsig.WithNonceChecker(mockNonceChecker(true)),
			httpsig.WithValidateAllSignatures(),
			httpsig.WithValidityTolerance(time.Hour),
			httpsig.WithMaxAge(time.Hour),
		)

		err := verifier.Verify(httpsig.MessageFromRequest(r))
		if err != nil {
			fmt.Printf("Verification failed: %s\n", err)
		} else {
			fmt.Printf("Verification succeeded\n")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := New(WithTransport(http.DefaultTransport), WithActor(&exActorRSA, prvKeyRSA), WithNonce(sameNonce))
	req := httptest.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"hello": "world"}`))
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", millenium.Format(http.TimeFormat))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")

	_, _ = tr.RoundTrip(req)

	// Output:
	// Verification succeeded
}
