//go:build !dev

package s2s

import "github.com/go-fed/httpsig"

// HeadersToSign is the list of headers that will be used to generate the
// HTTP-Signature
//
// In regular builds, this list contains the "Date" header which makes it
// compatible with the wider fediverse, at the expense of debuggability.
var HeadersToSign = []string{httpsig.RequestTarget, "host", "date"}

var (
	// FetchCoveredComponents is the list of components to be used for generating the
	// RFC9421 Signature Base for GET and HEAD requess.
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-derived-components
	FetchCoveredComponents = []string{"@method", "@target-uri"}
	// PostCoveredComponents is the list of components to be used for generating the
	// RFC9421 Signature Base for POST, PUT, DELETE requests.
	PostCoveredComponents = []string{"@method", "@target-uri", "content-type", "content-length", "content-digest"}
)
