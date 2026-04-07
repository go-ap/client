//go:build dev

package s2s

import "github.com/go-fed/httpsig"

// HeadersToSign is the list of headers that will be used to generate the
// HTTP-Signature
//
// In the development builds, this list is lacking the "Date" header which
// makes it suitable to replay the requests using other clients (for debugging
// purposes), but makes the signatures fail on production servers in the
// fediverse.
var HeadersToSign = []string{httpsig.RequestTarget, "host"}

var (
	// FetchCoveredComponents is the list of components to be used for generating the
	// RFC9421 Signature Base for GET and HEAD requests.
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-derived-components
	FetchCoveredComponents = []string{"@method", "@target-uri"}
	// PostCoveredComponents is the list of components to be used for generating the
	// RFC9421 Signature Base for POST, PUT, DELETE requests.
	PostCoveredComponents = []string{"@method", "@target-uri"}
)
