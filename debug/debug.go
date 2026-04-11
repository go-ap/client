package debug

import (
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type OptionFn func(transport *Transport) error

func WithTransport(tr http.RoundTripper) OptionFn {
	return func(h *Transport) error {
		h.Base = tr
		return nil
	}
}

func WithPath(where string) OptionFn {
	return func(tr *Transport) error {
		tr.where = where
		return nil
	}
}

// New returns a RoundTripper that dumps the request/response pair
// to disk to the "where" directory
// It needs to be used as a base transport if used to debug the headers produced by the
// OAuth2 or HTTP-Signatures authorization transports.
func New(fn ...OptionFn) http.RoundTripper {
	tr := Transport{}
	for _, initFn := range fn {
		_ = initFn(&tr)
	}
	if tr.Base == nil {
		tr.Base = http.DefaultTransport
	}

	maybeDir, err := os.Stat(tr.where)
	if err != nil {
		return tr.Base
	}
	if !maybeDir.IsDir() {
		return tr.Base
	}
	return &tr
}

type Transport struct {
	Base  http.RoundTripper
	where string
}

const boundary = "\n====================\n"

func (d Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// NOTE(marius): return early if this is not a request with a body
	if req == nil {
		return d.Base.RoundTrip(req)
	}

	fullPath := filepath.Join(d.where, req.URL.Host+strings.ReplaceAll(req.URL.Path, "/", "-")+"-"+time.Now().UTC().Format(time.RFC3339)+".req")
	ff, err := os.OpenFile(fullPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return d.Base.RoundTrip(req)
	}
	defer ff.Close()

	raw, _ := httputil.DumpRequestOut(req, req.Body != nil)
	if raw != nil {
		_, _ = ff.Write(raw)
	}

	res, err := d.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if raw, _ = httputil.DumpResponse(res, res.Body != nil); raw != nil {
		_, _ = ff.WriteString(boundary)
		_, _ = ff.Write(raw)
	}

	return res, nil
}
