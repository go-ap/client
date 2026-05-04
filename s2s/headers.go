//go:build !dev

package s2s

import "github.com/go-fed/httpsig"

var (
	// HeadersToSign is the list of headers that will be used to generate the
	// Draft version of HTTP-Signature
	//
	// In regular builds, this list contains the "Date" header which makes it
	// compatible with the wider fediverse, at the expense of debuggability.
	HeadersToSign = []string{httpsig.RequestTarget, "host", "date"}

	// FetchCoveredComponents is the list of components to be used for generating the
	// RFC9421 Signature Base for GET and HEAD requests.
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-derived-components
	FetchCoveredComponents = []string{"@method", "@target-uri"}
	// PostCoveredComponents is the list of components to be used for generating the
	// RFC9421 Signature Base for POST, PUT, DELETE requests.
	PostCoveredComponents = []string{"content-type", "content-digest"}
)
