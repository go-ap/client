package c2s

import (
	"net/http"

	"github.com/go-ap/errors"
	"golang.org/x/oauth2"
)

type BearerSigner oauth2.Token

func (b *BearerSigner) Sign(r *http.Request) error {
	if b.TokenType == "" {
		return errors.Newf("invalid token type")
	}
	if b.AccessToken == "" {
		return errors.Newf("invalid access token")
	}
	if auth := b.TokenType + " " + b.AccessToken; len(auth) > 1 {
		r.Header.Set("Authorization", auth)
	}
	return nil
}
