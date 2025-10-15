//go:build !dev

package s2s

import "github.com/go-fed/httpsig"

// HeadersToSign is the list of headers that will be used to generate the
// HTTP-Signature
//
// In regular builds, this list contains the "Date" header which makes it
// compatible with the wider fediverse, at the expense of debuggability.
var HeadersToSign = []string{httpsig.RequestTarget, "host", "date"}
