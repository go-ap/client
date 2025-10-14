package debug

import (
	"bytes"
	"io"
	"net/http"
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
	tr := Transport{Base: http.DefaultTransport}
	for _, initFn := range fn {
		_ = initFn(&tr)
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

// cloneRequest returns a clone of the provided *http.Request.
func cloneRequest(r *http.Request, ff io.ReadWriter) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r

	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}

	body := bytes.Buffer{}
	// replace old body with the teeReader
	r.Body = io.NopCloser(io.TeeReader(r.Body, io.MultiWriter(ff, &body)))
	// new request body
	r2.Body = io.NopCloser(&body)

	return r2
}

// cloneResponse returns a clone of the provided *http.Response.
func cloneResponse(r *http.Response, ff io.Writer) *http.Response {
	// shallow copy of the struct
	r2 := new(http.Response)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}

	body := bytes.Buffer{}
	r.Body = io.NopCloser(io.TeeReader(r.Body, io.MultiWriter(ff, &body)))
	r2.Body = io.NopCloser(&body)

	return r2
}

const boundary = "\n\n====================\n\n"

func (d Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// NOTE(marius): return early if this is not a request with a body
	if req.Body == nil {
		return d.Base.RoundTrip(req)
	}

	fullPath := filepath.Join(d.where, req.URL.Host+strings.ReplaceAll(req.URL.Path, "/", "-")+"-"+time.Now().UTC().Format(time.RFC3339)+".req")
	ff, err := os.OpenFile(fullPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return d.Base.RoundTrip(req)
	}
	defer ff.Close()

	req2 := cloneRequest(req, ff)

	_, _ = ff.WriteString(req.Method)
	_, _ = ff.WriteString(" ")
	_, _ = ff.WriteString(req.URL.String())
	_, _ = ff.WriteString("\n")
	if len(req.Header) > 0 {
		_ = req.Header.Write(ff)
		_, _ = ff.WriteString("\n\n")
	}
	_, _ = io.ReadAll(req.Body)
	_ = req.Body.Close()

	res, err := d.Base.RoundTrip(req2)
	if err != nil {
		return nil, err
	}

	res2 := cloneResponse(res, ff)
	_, _ = ff.WriteString(boundary)

	_, _ = ff.WriteString(res.Status)
	_, _ = ff.WriteString("\n")
	if len(res.Header) > 0 {
		_ = res.Header.Write(ff)
		_, _ = ff.WriteString("\n\n")
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()

	return res2, nil
}
