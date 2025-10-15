package debug

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ap/errors"
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

	req.Body = teeCloseReader(req.Body, ff)

	_, _ = ff.WriteString(req.Method)
	_, _ = ff.WriteString(" ")
	_, _ = ff.WriteString(req.URL.String())
	_, _ = ff.WriteString("\n")
	if len(req.Header) > 0 {
		_ = req.Header.Write(ff)
		_, _ = ff.WriteString("\n\n")
	}

	res, err := d.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	res.Body = teeCloseReader(res.Body, ff)
	_, _ = ff.WriteString(boundary)

	_, _ = ff.WriteString(res.Status)
	_, _ = ff.WriteString("\n")
	if len(res.Header) > 0 {
		_ = res.Header.Write(ff)
		_, _ = ff.WriteString("\n\n")
	}

	return res, nil
}

type teeCloser struct {
	io.Reader
	closeWriter bool
	from        io.ReadCloser
	to          io.WriteCloser
}

func teeCloseReader(from io.ReadCloser, to io.WriteCloser) *teeCloser {
	return &teeCloser{
		Reader: io.TeeReader(from, to),
		from:   from,
		to:     to,
	}
}

func teeReadCloser(from io.ReadCloser, to io.WriteCloser) *teeCloser {
	return &teeCloser{
		closeWriter: true,
		Reader:      io.TeeReader(from, to),
		from:        from,
		to:          to,
	}
}

func (t *teeCloser) Close() error {
	err1 := t.from.Close()
	if t.closeWriter {
		err2 := t.to.Close()
		return errors.Join(err1, err2)
	}
	return err1
}
