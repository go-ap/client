package s2s

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.sr.ht/~mariusor/lw"
	"github.com/common-fate/httpsig/alg_ed25519"
	"github.com/common-fate/httpsig/signer"
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
			args:    args{actor, nil},
			wantErr: nil,
		},
		{
			name:    "w/o actor, w/ key",
			args:    args{nil, prvRSA},
			wantErr: nil,
		},
		{
			name:    "w/ broken actor, w/ key",
			args:    args{&vocab.Actor{ID: "https://example.com/~johndoe"}, prvRSA},
			wantErr: errors.Annotatef(fmt.Errorf("invalid PEM decode on public key"), "unable to sign request, Actor public key type %T is invalid", nil),
		},
		{
			name:    "w/ actor, w/ RSA key",
			args:    args{actor, prvRSA},
			wantErr: nil,
		},
		{
			name:    "w/ actor, w/ ECDSA key",
			args:    args{actorECDSA, prvECDSA},
			wantErr: nil,
		},
		{
			name:    "w/ actor, w/ ED25519 key",
			args:    args{actorED25519, prvED25519},
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

				wantKeyID := string(tt.args.act.PublicKey.ID)
				if !cmp.Equal(tr.KeyID, wantKeyID) {
					t.Errorf("WithActor() = key ID mismatch %s", cmp.Diff(wantKeyID, tr.KeyID))
				}
			}

			if tt.args.prv != nil {
				if !cmp.Equal(tr.Key, tt.args.prv) {
					t.Errorf("WithActor() = private key mismatch %s", cmp.Diff(tt.args.prv, tr.Key))
				}

				if tt.args.act != nil && tt.args.act.PublicKey.ID != "" {
					if tr.Alg == nil {
						t.Errorf("WithActor() = RFC9421 Alg must not be nil %v", tr.Alg)
					}
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
			if tt.l != nil {
				if tr.OnDeriveSigningString == nil {
					t.Errorf("WithLogger() RFC9421 debug function should not be nil: %p", tr.OnDeriveSigningString)
				} else {
					mockSignature := "test"
					tr.OnDeriveSigningString(context.Background(), mockSignature)
					logMsg := make(map[string]string)
					_ = json.NewDecoder(tt.l).Decode(&logMsg)
					if msg, ok := logMsg["message"]; ok && !strings.HasSuffix(msg, mockSignature) {
						t.Errorf("WithLogger() logged message %s, does not have expected suffix %s", msg, mockSignature)
					}
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
			tr := new(Transport)
			optionFn := WithApplicationTag(tt.t)

			if err := optionFn(tr); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithApplicationTag() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if tt.t != tr.Transport.Tag {
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
			want: &Transport{
				Transport: signer.Transport{CoveredComponents: FetchCoveredComponents},
			},
		},
		{
			name:    "with Actor",
			initFns: []OptionFn{WithActor(actorED25519, prvED25519)},
			want: &Transport{
				Transport: signer.Transport{
					KeyID:             string(actorED25519.PublicKey.ID),
					CoveredComponents: FetchCoveredComponents,
					Alg: &alg_ed25519.Ed25519{
						PrivateKey: prvED25519.(ed25519.PrivateKey),
						PublicKey:  prvED25519.(ed25519.PrivateKey).Public().(ed25519.PublicKey),
					},
				},
				Key:   prvED25519,
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

func TestTransport_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		initFns    []OptionFn
		body       []byte
		wantStatus int
		wantErr    error
	}{
		{
			name:       "empty",
			wantStatus: http.StatusOK,
		},
		{
			name:       "no RFC9421",
			body:       []byte("test"),
			wantStatus: http.StatusOK,
		},
		{
			name:       "with actor",
			body:       []byte("test"),
			initFns:    []OptionFn{WithActor(actorED25519, prvED25519)},
			wantStatus: http.StatusOK,
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSignatureHandlerFn := func(w http.ResponseWriter, r *http.Request) {
				if sig := r.Header.Get("Signature"); sig != "" {
					t.Logf("RoundTrip() Signature: %s", sig)
				}
				if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
					t.Logf("RoundTrip() Signature-Input: %s", sigInput)
				}
				w.WriteHeader(http.StatusOK)
			}
			server := httptest.NewServer(http.HandlerFunc(testSignatureHandlerFn))

			dt := New(tt.initFns...)
			var req *http.Request
			if tt.body != nil {
				req = httptest.NewRequest(http.MethodPost, server.URL, bytes.NewBuffer(tt.body))
			} else {
				req = httptest.NewRequest(http.MethodPost, server.URL, nil)
			}
			req.Header.Set("Date", time.Now().Format(http.TimeFormat))

			got, err := dt.RoundTrip(req)
			if (err != nil) && !errors.Is(tt.wantErr, err) {
				t.Errorf("RoundTrip() error = %v, wanted error %v", err, tt.wantErr)
				return
			}

			if tt.wantStatus != got.StatusCode {
				t.Errorf("RoundTrip() invalid status received = %s, wanted %d %s", got.Status, tt.wantStatus, http.StatusText(tt.wantStatus))
				return
			}
		})
	}
}

var (
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
			ID:           vocab.IRI(fmt.Sprintf("%s#main", actor.ID)),
			Owner:        actor.ID,
			PublicKeyPem: pubPemECDSA,
		},
	}

	blockED25519, _ = pem.Decode([]byte(prvPemED25519))
	prvED25519, _   = x509.ParsePKCS8PrivateKey(blockED25519.Bytes)

	actorED25519 = &vocab.Actor{
		ID: "https://example.com/~johndoe",
		PublicKey: vocab.PublicKey{
			ID:           vocab.IRI(fmt.Sprintf("%s#main", actor.ID)),
			Owner:        actor.ID,
			PublicKeyPem: pubPemED25519,
		},
	}
)

const StatusFailedTest = http.StatusExpectationFailed

func sameBodyHandler(t *testing.T, bodyBuff, respBuff []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("RoundTrip() handler body read unexpected error = %v", err)
			w.WriteHeader(StatusFailedTest)
			return
		}
		//wantedBuff = append(wantedBuff, 'a', 'b')
		if !bytes.Equal(body, bodyBuff) {
			t.Errorf("RoundTrip() handler request body = %s, different than wanted %s", body, bodyBuff)
			w.WriteHeader(StatusFailedTest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBuff)
	}
}

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
