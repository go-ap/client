package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	vocab "github.com/go-ap/activitypub"
)

type Transport struct {
	Base http.RoundTripper

	ProxyURL vocab.IRI
}

var shouldProxyStatuses = []int{http.StatusForbidden, http.StatusUnauthorized}

// RoundTrip only accepts HTTP GET requests to a remote server.
// If a 403 (or 401, for Mastodon servers with secure fetch) error is returned by the Base round-tripper,
// and we have a valid ProxyURL value, we try to request the original HTTP GET URL through the proxying mechanism
// provided by the server owning the proxy URL.
// If the server requires authorization, that should be handled by the Base transport - using most likely the OAuth2
// round tripper.
func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	needsProxying := req.Method == http.MethodGet
	proxyURL, _ := t.ProxyURL.URL()
	// NOTE(marius): if the request is done to the same host as the proxyUrl we most likely don't need to use the proxy
	if proxyURL == nil || strings.EqualFold(proxyURL.Host, req.URL.Host) {
		needsProxying = false
	}

	res, err := t.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// NOTE(marius): if the first attempt failed, and we fulfill the proxying requirements, try again
	if !needsProxying || !slices.Contains(shouldProxyStatuses, res.StatusCode) {
		return res, err
	}

	req1 := buildProxyRequest(req, proxyURL)
	return t.Base.RoundTrip(req1)
}

func setProxyFetchID(req *http.Request, id string) error {
	body := bytes.Buffer{}
	form := make(url.Values)
	form.Add("id", id)
	_, err := body.WriteString(form.Encode())
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(&body)
	return nil
}

type OptionFn func(transport *Transport) error

func WithTransport(tr http.RoundTripper) OptionFn {
	return func(h *Transport) error {
		h.Base = tr
		return nil
	}
}

func WithProxyURL(proxyURL vocab.IRI) OptionFn {
	return func(h *Transport) error {
		if !vocab.EmptyIRI.Equal(proxyURL) {
			h.ProxyURL = proxyURL
		}
		return nil
	}
}

func WithActor(act *vocab.Actor) OptionFn {
	return func(h *Transport) error {
		if act.Endpoints != nil && !vocab.EmptyIRI.Equal(act.Endpoints.ProxyURL) {
			h.ProxyURL = act.Endpoints.ProxyURL
		}
		return nil
	}
}

var _ http.RoundTripper = new(Transport)

func New(initFns ...OptionFn) http.RoundTripper {
	h := new(Transport)
	h.Base = &http.Transport{}

	for _, fn := range initFns {
		_ = fn(h)
	}
	if vocab.EmptyIRI.Equal(h.ProxyURL) {
		return h.Base
	}
	return h
}

// buildProxyRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func buildProxyRequest(r *http.Request, proxyUrl *url.URL) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	r2.Method = http.MethodPost
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2.URL = proxyUrl
	r2.Host = proxyUrl.Host
	_ = setProxyFetchID(r2, r.URL.String())
	return r2
}
