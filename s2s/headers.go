//go:build !dev

package s2s

import "github.com/go-fed/httpsig"

var headersToSign = []string{httpsig.RequestTarget, "host", "date"}
