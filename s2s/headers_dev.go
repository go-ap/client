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
