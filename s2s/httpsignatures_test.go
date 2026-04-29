package s2s

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestWithActor(t *testing.T) {
	type args struct {
		act *vocab.Actor
		prv crypto.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "empty",
			args:    args{},
			wantErr: nil,
		},
		{
			name:    "w/ actor, w/o key",
			args:    args{jdoeActor, nil},
			wantErr: nil,
		},
		{
			name:    "w/o actor, w/ key",
			args:    args{nil, prv},
			wantErr: nil,
		},
		{
			name:    "w/ broken actor, w/ key",
			args:    args{&vocab.Actor{ID: "https://example.com/~johndoe"}, prv},
			wantErr: nil,
		},
		{
			name:    "w/ actor, w/ RSA key",
			args:    args{jdoeActor, prv},
			wantErr: nil,
		},
		{
			name:    "w/ actor, w/ ECDSA key",
			args:    args{actorECDSA, prvECDSA},
			wantErr: nil,
		},
		{
			name:    "w/ actor, w/ ED25519 key",
			args:    args{actorED25519, prvEd25519},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(Transport)
			optionFn := WithActor(tt.args.act, tt.args.prv)

			if err := optionFn(tr); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Fatalf("WithActor() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}

			if tt.args.act != nil {
				if !cmp.Equal(tr.Actor, tt.args.act, EquateItems) {
					t.Errorf("WithActor() = actor mismatch %s", cmp.Diff(tt.args.act, tr.Actor, EquateItems))
				}
			}

			if tt.args.prv != nil {
				if !cmp.Equal(tr.Key, tt.args.prv) {
					t.Errorf("WithActor() = private key mismatch %s", cmp.Diff(tt.args.prv, tr.Key))
				}
			}
		})
	}
}

func TestWithLogger(t *testing.T) {
	tests := []struct {
		name    string
		l       *bytes.Buffer
		wantErr error
	}{
		{
			name: "empty",
			l:    nil,
		},
		{
			name: "logger with test output",
			l:    &bytes.Buffer{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(Transport)
			var ll lw.Logger
			if tt.l != nil {
				ll = lw.Dev(lw.SetOutput(tt.l))
			}
			optionFn := WithLogger(ll)

			if err := optionFn(tr); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithLogger() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}

			if tr.l == nil {
				if tr.l != ll {
					t.Errorf("WithLogger() should not be nil")
				}
			} else if _, ok := tr.l.(lw.Logger); !ok {
				t.Errorf("WithLogger() %T should be compatible with %T", tr.l, lw.Logger(nil))
			}
		})
	}
}

func TestWithApplicationTag(t *testing.T) {
	tests := []struct {
		name    string
		t       string
		wantErr error
	}{
		{
			name:    "empty",
			t:       "",
			wantErr: nil,
		},
		{
			name:    "tag",
			t:       "test-tag",
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(Transport)
			optionFn := WithApplicationTag(tt.t)

			if err := optionFn(tr); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithApplicationTag() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if tt.t != tr.Tag {
				t.Errorf("WithApplicationTag() = %s, want %s", tr.Tag, tt.t)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		initFns []OptionFn
		want    *Transport
	}{
		{
			name:    "empty",
			initFns: nil,
			want:    &Transport{},
		},
		{
			name:    "with Actor",
			initFns: []OptionFn{WithActor(actorED25519, prvEd25519)},
			want: &Transport{
				Key:   prvEd25519,
				Actor: actorED25519,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.initFns...); !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(http.Transport{}, Transport{})) {
				t.Errorf("New() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Transport{}, Transport{})))
			}
		})
	}
}

func mockPostReq(body []byte, hh ...url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://example.com", bytes.NewReader(body))
	for _, h := range hh {
		for k, v := range h {
			r.Header[k] = v
		}
	}
	r.Header.Add("Content-Length", strconv.Itoa(len(body)))
	return r
}

func TestTransport_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		initFns    []OptionFn
		handler    http.HandlerFunc
		req        *http.Request
		wantStatus int
		wantBody   []byte
		wantErr    error
	}{
		{
			name: "empty",
			req:  httptest.NewRequest(http.MethodGet, "http://example.com", nil),
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "no RFC9421 - ED25519",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
					t.Errorf("RoundTrip() Signature-Input should not exist for cavage-12 signature: %s", sigInput)
				}
				if sig := r.Header.Get("Signature"); sig != "" {
					t.Logf("RoundTrip() Signature: %s", sig)
				}
				w.WriteHeader(http.StatusOK)
			},
			initFns: []OptionFn{WithActor(actorED25519, prvEd25519), NoRFC9421},
			req: mockPostReq([]byte("test"), url.Values{
				"Date": []string{time.Now().Format(http.TimeFormat)},
				"Host": []string{"example.com"},
			}),
			wantStatus: http.StatusOK,
		},
		{
			name: "no RFC9421 - RSA",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
					t.Errorf("RoundTrip() Signature-Input should not exist for cavage-12 signature: %s", sigInput)
				}
				if sig := r.Header.Get("Signature"); sig != "" {
					t.Logf("RoundTrip() Signature: %s", sig)
				}
				w.WriteHeader(http.StatusOK)
			},
			initFns: []OptionFn{WithActor(actorRSA, prvRSA), NoRFC9421},
			req: mockPostReq([]byte("test"), url.Values{
				"Date": []string{time.Now().Format(http.TimeFormat)},
				"Host": []string{"example.com"},
			}),
			wantStatus: http.StatusOK,
		},
		{
			name: "no RFC9421 - ECDSA",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
					t.Errorf("RoundTrip() Signature-Input should not exist for cavage-12 signature: %s", sigInput)
				}
				if sig := r.Header.Get("Signature"); sig != "" {
					t.Logf("RoundTrip() Signature: %s", sig)
				}
				w.WriteHeader(http.StatusOK)
			},
			initFns: []OptionFn{WithActor(actorECDSA, prvECDSA), NoRFC9421},
			req: mockPostReq([]byte("test"), url.Values{
				"Date": []string{time.Now().Format(http.TimeFormat)},
				"Host": []string{"example.com"},
			}),
			wantStatus: http.StatusOK,
		},
		{
			name: "with actor - ED25519",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if sig := r.Header.Get("Signature"); sig != "" {
					t.Logf("RoundTrip() Signature: %s", sig)
				}
				if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
					t.Logf("RoundTrip() Signature-Input: %s", sigInput)
				}
				w.WriteHeader(http.StatusOK)
			},
			req: mockPostReq([]byte("test"), url.Values{
				"Host": []string{"example.com"},
				"Date": []string{time.Now().Format(http.TimeFormat)},
			}),
			initFns:    []OptionFn{WithActor(actorED25519, prvEd25519)},
			wantStatus: http.StatusOK,
			wantErr:    nil,
		},
		{
			name: "with actor - RSA",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if sig := r.Header.Get("Signature"); sig != "" {
					t.Logf("RoundTrip() Signature: %s", sig)
				}
				if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
					t.Logf("RoundTrip() Signature-Input: %s", sigInput)
				}
				w.WriteHeader(http.StatusOK)
			},
			req: mockPostReq([]byte("test"), url.Values{
				"Host": []string{"example.com"},
				"Date": []string{time.Now().Format(http.TimeFormat)},
			}),
			initFns:    []OptionFn{WithActor(actorRSA, prvRSA)},
			wantStatus: http.StatusOK,
			wantErr:    nil,
		},
		{
			name: "with actor - ECDSA",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if sig := r.Header.Get("Signature"); sig != "" {
					t.Logf("RoundTrip() Signature: %s", sig)
				}
				if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
					t.Logf("RoundTrip() Signature-Input: %s", sigInput)
				}
				w.WriteHeader(http.StatusOK)
			},
			req: mockPostReq([]byte("test"), url.Values{
				"Host": []string{"example.com"},
				"Date": []string{time.Now().Format(http.TimeFormat)},
			}),
			initFns:    []OptionFn{WithActor(actorECDSA, prvECDSA)},
			wantStatus: http.StatusOK,
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.handler != nil {
				server := httptest.NewServer(tt.handler)
				defer server.Close()

				su, _ := url.Parse(server.URL)
				if tt.req != nil && su != nil {
					tt.req.URL.Host = su.Host
				}
			}

			dt := New(tt.initFns...)
			got, err := dt.RoundTrip(tt.req)
			if !cmp.Equal(tt.wantErr, err, EquateWeakErrors) {
				t.Fatalf("RoundTrip() error = %v, wanted error %v", err, tt.wantErr)
				return
			}
			if got == nil {
				if tt.wantErr == nil {
					t.Errorf("RoundTrip() nil response when no error expected")
				}
				return
			}

			if tt.wantStatus != got.StatusCode {
				t.Errorf("RoundTrip() invalid status received = %s, wanted %d %s", got.Status, tt.wantStatus, http.StatusText(tt.wantStatus))
				return
			}
			if tt.wantBody != nil {
				resBody, err := io.ReadAll(got.Body)
				if err != nil {
					t.Errorf("RoundTrip() unable to read response body = %s", err)
				}
				if !bytes.Equal(resBody, tt.wantBody) {
					t.Errorf("RoundTrip() invalid response body received = %s, wanted %s", resBody, tt.wantBody)
				}
			}
		})
	}
}

var (
	prvPemRSA = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEZNd5f+5jjw7Y
vzhwniZgFOiz80cOWAJtMGtmorjkjaQPE2cmrgWvEHiCYqQ0jnbCSJrMPZXUlXUm
vsdHaczpbHKlnPKUgC35QpXs3NikWvoZFBhJR99lbGuZilsQj/lMi7Ht7lzmZRDR
/ZeapRi+otxjSKNe3FH1ONIaXZdBEfRHKfRW2FV9W3L76gX9jsH/2s26r6LYlyLM
lnQkt2dM+GwYSG4pv/Kl/KE2i/UdJ/o/tealiO5usyZwK3U2vZCJaseMWDbluHTM
Q1RPPV8SeI5pBqREa2XrSwbcZUI+TaB+xiPvIAjrTboxLY5XyIDwjag+a/aMvzRx
JAKRmRqhAgMBAAECggEAGYiEzSqZSz9Xrk1aIKYnFhnR0UeBRvehRSHk7MCeKjTS
DhW3NPuuCH8rM8RwVdbp0MOQwJoHJ07RHtrx3LKALh7n3ulDTpRFpeEGzfc+gUvE
tUr8B1b9T9njOWCYC1S0lEObO/RgBqJAKBUAx13MlEhnP887UkNxsmCTTFM7rX1W
AVgHGZo71M6IebHjoLEFmYAXtFgY3+W29J3JOAUsWWCIZYntnOtNAslRYjzyuTRh
bDTKayKMuRuPo4/jgQhsHS6qsRonK0dQRKLuBX8iHyoXFQP7GVea9liHnm9lqwQ1
Ve4zvD4IUbV71NVZ6xsY3Nfr7/f8ehatMhSZ/H6BKwKBgQD3Eq7yhOmzGk8Woa2b
7NBB9UwCoGHIWh/lXj731a/3zD85sS7VXdvyXOwhilMpx/lNmTBhq2ko5qf122xu
JyQ1DfsKvHs0sHqL1ZVHovpe0lvwxu1Nj/HfsEqlt//qFvXa4Gp5uw/hqcLcxfSa
Yo8z6m/+QPESMPxwD3FaUmKuiwKBgQDLfWYv/t6m+4v0ROSY+oGW/r6HbYkFWodw
UU+S2THwOttddJDEOznEZxmJhqAXPMChTkmXL8kn1aRSmn/AHJDVywCxv0xNiIcR
kjfFmmzdig/HcBoWHPc5aAoZorxDEIb6NWEJt/vEDfnOOLItfufKCy9aKdQ7pwjP
FcPH7TwNAwKBgFTPNP5KYW35Oeyq0s0THOmHKfA83VPIm+o/z52C3ERS9+D10P2s
mjM3claRBLryycC5NMJR9Gb1xfG+wBmPlf4gLmwhBqmvamFVj0hnyUmDK8wafJqD
LqN6ACWiY1YXS402O1ZNv8XWX+0ohi34Zu+LKaY85IM6DWzp4B8A6J7BAoGBALkK
SAE/B6LavXKbrzA5I9x1vDYUcfQPVXfaSLzlipbEPrRmCjqXDLm/cyZu6GcZFKXa
NesoRghWKv3+hkrg7weqePApX65lh0WAK/0hpvtxz1VxaBdRsbJfHEghhoaJoeQm
5B3dUzD98HoJbmUWsJo2v5GC1f6Erur5BLZp0SCXAoGAPFS3336Z1pK0Ne+Qw83x
V9dcGszH2HYfU4AVOyxIRK6DDsw0k/r4zi/0AfRjnPlP89qffTZfkEgW+/jXQYzr
B5MKfJ21HzAim4dyNzhbViNqzQtRZhP7/ESJJVF1CUbyIr3xqwww0rVdWxgTPrra
CymanYHXIAFVDKU/1A099Uw=
-----END PRIVATE KEY-----`
	pubPemRSA = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGTXeX/uY48O2L84cJ4m
YBTos/NHDlgCbTBrZqK45I2kDxNnJq4FrxB4gmKkNI52wkiazD2V1JV1Jr7HR2nM
6WxypZzylIAt+UKV7NzYpFr6GRQYSUffZWxrmYpbEI/5TIux7e5c5mUQ0f2XmqUY
vqLcY0ijXtxR9TjSGl2XQRH0Ryn0VthVfVty++oF/Y7B/9rNuq+i2JcizJZ0JLdn
TPhsGEhuKb/ypfyhNov1HSf6P7XmpYjubrMmcCt1Nr2QiWrHjFg25bh0zENUTz1f
EniOaQakRGtl60sG3GVCPk2gfsYj7yAI6026MS2OV8iA8I2oPmv2jL80cSQCkZka
oQIDAQAB
-----END PUBLIC KEY-----`
	prvPemED25519 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIENuo6tAn+SGsIM2z6bVx7VZpy4HYCeXKl1hV6uT4DVb
-----END PRIVATE KEY-----`
	pubPemED25519 = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAt8TweVNd8pyljWdZzd1GjTi7+QhuwG3/44lkxr4X5dQ=
-----END PUBLIC KEY-----`
	prvPemECDSA = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDDHJkGMt3IYM81fjrMGyySIWs2XixetQ9eVzXO0aPt1rMz2DvMhNGe
ngeqMW2cXACgBwYFK4EEACKhZANiAASNoNI4Gy6L7QRDqlJdBsXRnhRGmPCMUmxT
xUSWByh4ybAXq9FTis4C1QMf7rOlXdf623uVi5m+rR1Uk8nHDeVQ24i4aypjdGAP
Bwxj6JoQCBRMzXABnT3sENgDuyXKo/s=
-----END EC PRIVATE KEY-----`
	pubPemECDSA = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEjaDSOBsui+0EQ6pSXQbF0Z4URpjwjFJs
U8VElgcoeMmwF6vRU4rOAtUDH+6zpV3X+tt7lYuZvq0dVJPJxw3lUNuIuGsqY3Rg
DwcMY+iaEAgUTM1wAZ097BDYA7slyqP7
-----END PUBLIC KEY-----`

	blockECDSA, _ = pem.Decode([]byte(prvPemECDSA))
	prvECDSA, _   = x509.ParseECPrivateKey(blockECDSA.Bytes)

	actorECDSA = &vocab.Actor{
		ID: "https://example.com/~johndoe",
		PublicKey: vocab.PublicKey{
			ID:           "https://example.com/~johndoe#main",
			Owner:        jdoeActor.ID,
			PublicKeyPem: pubPemECDSA,
		},
	}

	blockPrvEd25519, _ = pem.Decode([]byte(prvPemED25519))
	prvEd25519, _      = x509.ParsePKCS8PrivateKey(blockPrvEd25519.Bytes)
	blockPubEd25519, _ = pem.Decode([]byte(pubPemED25519))
	pubED25519, _      = x509.ParsePKIXPublicKey(blockPubEd25519.Bytes)

	actorED25519 = &vocab.Actor{
		ID: "https://example.com/~johndoe",
		PublicKey: vocab.PublicKey{
			ID:           "https://example.com/~johndoe#main",
			Owner:        jdoeActor.ID,
			PublicKeyPem: pubPemED25519,
		},
	}

	blockRSA, _ = pem.Decode([]byte(prvPemRSA))
	prvRSA, _   = x509.ParsePKCS8PrivateKey(blockRSA.Bytes)

	actorRSA = &vocab.Actor{
		ID: "https://example.com/~johndoe",
		PublicKey: vocab.PublicKey{
			ID:           "https://example.com/~johndoe#main",
			Owner:        jdoeActor.ID,
			PublicKeyPem: pubPemRSA,
		},
	}
)

const StatusFailedTest = http.StatusExpectationFailed

func areErrors(a, b any) bool {
	_, ok1 := a.(error)
	_, ok2 := b.(error)
	return ok1 && ok2
}

func compareErrors(x, y any) bool {
	xe := x.(error)
	ye := y.(error)
	if errors.Is(xe, ye) || errors.Is(ye, xe) {
		return true
	}
	return xe.Error() == ye.Error()
}

var EquateWeakErrors = cmp.FilterValues(areErrors, cmp.Comparer(compareErrors))

func areItems(a, b any) bool {
	_, ok1 := a.(vocab.Item)
	_, ok2 := b.(vocab.Item)
	return ok1 && ok2
}

func compareItems(x, y any) bool {
	var i1 vocab.Item
	var i2 vocab.Item
	if ic1, ok := x.(vocab.Item); ok {
		i1 = ic1
	}
	if ic2, ok := y.(vocab.Item); ok {
		i2 = ic2
	}
	return vocab.ItemsEqual(i1, i2) || vocab.ItemsEqual(i2, i1)
}

var EquateItems = cmp.FilterValues(areItems, cmp.Comparer(compareItems))
