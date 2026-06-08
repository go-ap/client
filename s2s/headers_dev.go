//go:build dev

package s2s

import "github.com/go-fed/httpsig"

var (
	// HeadersToSign is the list of headers that will be used to generate the
	// Draft version of HTTP-Signature
	//
	// In the development builds, this list is lacking the "Date" header which
	// makes it suitable to replay the requests using other clients (for debugging
	// purposes), but makes the signatures fail on production servers in the
	// fediverse.
	HeadersToSign = []string{httpsig.RequestTarget, "host"}

	// FetchCoveredComponents is the list of components to be used for generating the
	// RFC9421 Signature Base for GET and HEAD requests.
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-derived-components
	FetchCoveredComponents = []string{"@method", "@path"}
	// AdditionalPostCoveredComponents is the list of components to be added for generating the
	// RFC9421 Signature Base for POST, PUT, DELETE requests.
	AdditionalPostCoveredComponents = []string{}
)
