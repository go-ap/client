package c2s

import (
	"net/http"

	"golang.org/x/oauth2"
)

type BearerSigner oauth2.Token

func (b BearerSigner) Sign(r *http.Request) error {
	t := oauth2.Token(b)
	t.SetAuthHeader(r)
	return nil
}
