package s2s

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"

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
			tr := new(Signer)
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
			tr := new(Signer)
			optionFn := WithApplicationTag(tt.t)

			if err := optionFn(tr); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithApplicationTag() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if tt.t != tr.tag {
				t.Errorf("WithApplicationTag() = %s, want %s", tr.tag, tt.t)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		initFns []OptionFn
		want    *Signer
		wantErr error
	}{
		{
			name:    "empty",
			initFns: nil,
			want:    &Signer{},
		},
		{
			name:    "with Actor",
			initFns: []OptionFn{WithActor(actorED25519, prvEd25519)},
			want: &Signer{
				Key:   prvEd25519,
				Actor: actorED25519,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := New(tt.initFns...)
			if !cmp.Equal(gotErr, tt.wantErr) {
				t.Errorf("New() = error %s", cmp.Diff(tt.wantErr, gotErr, EquateWeakErrors))
			}
			if !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(http.Transport{}, Signer{})) {
				t.Errorf("New() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Transport{}, Signer{})))
			}
		})
	}
}

func mockGetReq(hh ...url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	for _, h := range hh {
		for k, v := range h {
			r.Header[k] = v
		}
	}
	return r
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
	_, _               = x509.ParsePKIXPublicKey(blockPubEd25519.Bytes)

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

func TestWithCoveredComponents(t *testing.T) {
	tests := []struct {
		name    string
		comp    []string
		want    OptionFn
		wantErr error
	}{
		{
			name: "empty",
			comp: nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(Signer)
			optionFn := WithCoveredComponents(tt.comp...)

			if err := optionFn(tr); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithCoveredComponents() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if !slices.Equal(tt.comp, tr.coveredComponents) {
				t.Errorf("WithCoveredComponents() = %s, want %s", tr.coveredComponents, tt.comp)
			}
		})
	}
}
