package s2s

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
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
			tr := new(HTTPSignatureTransport)
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
		l       lw.Logger
		wantErr error
	}{
		{
			name: "empty",
			l:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(HTTPSignatureTransport)
			optionFn := WithLogger(tt.l)

			if err := optionFn(tr); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithLogger() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}

			if !cmp.Equal(tr.l, tt.l) {
				t.Errorf("WithLogger() = %s", cmp.Diff(tt.l, tt.l))
			}
			if tt.l != nil && tr.OnDeriveSigningString == nil {
				t.Errorf("WithLogger() RFC9421 debug function should not be nil: %p", tr.OnDeriveSigningString)
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
			tr := new(HTTPSignatureTransport)
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
