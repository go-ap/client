package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/dadrus/httpsig"
	"github.com/go-ap/activitypub/build"
	"github.com/go-ap/client/c2s"
	"github.com/go-ap/client/internal/requests"
	"github.com/go-ap/client/s2s"
	"golang.org/x/oauth2"
)

type kresolver rsa.PublicKey

func (k kresolver) ResolveKey(_ context.Context, keyID string) (httpsig.Key, error) {
	pk := rsa.PublicKey(k)
	return httpsig.Key{
		KeyID:     keyID,
		Algorithm: httpsig.RsaPkcs1v15Sha256,
		Key:       &pk,
	}, nil
}

func ExampleNew_with_s2s_authorization() {
	var prv crypto.PrivateKey

	rsa, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	prv = rsa
	pub := &rsa.PublicKey
	signActor := build.Person(
		build.WithID("http://example.com/~johndoe"),
		build.WithPublicKey(build.PublicKey("http://example.com/~johndoe#main", pub)),
	)

	vv, err := httpsig.NewVerifier(kresolver(*pub), httpsig.WithValidateAllSignatures())
	if err != nil {
		panic(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := vv.Verify(httpsig.MessageFromRequest(r))
		fmt.Printf("Verify error:    %v\n", err)

		w.Header().Add("Content-Type", requests.ContentTypeJsonActivity)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(signActor)
	}))

	sig := s2s.New(s2s.WithActor(signActor, prv), s2s.WithCoveredComponents("@method", "@path"))
	fetch := New(WithHTTPClient(srv.Client()), WithAuthorizationFn(sig.SignRFC9421))
	actor, err := fetch.Actor(context.Background(), "http://example.com/~jdoe")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Actor ID:        %s\n", actor.ID)
	fmt.Printf("Actor Type:      %s\n", actor.Type)
	fmt.Printf("Actor PublicKey: %s\n", actor.PublicKey.ID)

	// Output:
	// Verify error:    <nil>
	// Actor ID:        http://example.com/~johndoe
	// Actor Type:      Person
	// Actor PublicKey: http://example.com/~johndoe#main
}

func ExampleNew_with_c2s_authorization() {
	rsa, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pub := &rsa.PublicKey
	signActor := build.Person(
		build.WithID("http://example.com/~johndoe"),
		build.WithPublicKey(build.PublicKey("http://example.com/~johndoe#main", pub)),
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Authorization:   %v\n", r.Header.Get("Authorization"))

		w.Header().Add("Content-Type", requests.ContentTypeJsonActivity)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(signActor)
	}))

	// Token obtained in some way from a server, the OAuth2.
	// The OAuth2 authorization flow is a little too complex to recreate
	// here in a similar way we did with the HTTP-Signature authorization
	// Actor in the S2S example.
	tok := &oauth2.Token{
		AccessToken: "S3CR3TC0D3",
		TokenType:   "Bearer",
	}

	fetch := New(WithHTTPClient(srv.Client()), WithAuthorizationFn((*c2s.BearerSigner)(tok).Sign))
	actor, err := fetch.Actor(context.Background(), "http://example.com/~jdoe")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Actor ID:        %s\n", actor.ID)
	fmt.Printf("Actor Type:      %s\n", actor.Type)
	fmt.Printf("Actor PublicKey: %s\n", actor.PublicKey.ID)

	// Output:
	// Authorization:   Bearer S3CR3TC0D3
	// Actor ID:        http://example.com/~johndoe
	// Actor Type:      Person
	// Actor PublicKey: http://example.com/~johndoe#main
}
