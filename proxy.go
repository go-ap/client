package client

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-ap/errors"
)

var shouldProxyStatuses = []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound}

// tryProxiedRequest only accepts HTTP GET requests to a remote server.
// If a 403 (or 401, for Mastodon servers with secure fetch) error is returned by the Base round-tripper,
// and we have a valid proxyURL value, we try to request the original HTTP GET URL through the proxying mechanism
// provided by the server owning the proxy URL.
// If the server requires authorization, that should be handled by the Base transport - using most likely the OAuth2
// round tripper.
func (c C) tryProxiedRequest(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.Newf("nil request")
	}
	proxyURL, err := c.proxyURL.URL()
	if err != nil {
		return nil, err
	}

	needsProxying := req.Method == http.MethodGet
	// NOTE(marius): if the request is done to the same host as the proxyUrl we most likely don't need to use the proxy
	if proxyURL == nil || strings.EqualFold(proxyURL.Host, req.URL.Host) {
		needsProxying = false
	}

	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	// NOTE(marius): if the first attempt failed, and we fulfill the proxying requirements, try again
	if !needsProxying || !slices.Contains(shouldProxyStatuses, res.StatusCode) {
		return res, err
	}

	req1 := buildProxyRequest(req, proxyURL)
	return c.Do(req1)
}

func setProxyFetchID(req *http.Request, id string) error {
	body := bytes.Buffer{}
	form := make(url.Values)
	form.Add("id", id)
	buff := form.Encode()
	_, err := body.WriteString(buff)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(&body)
	req.ContentLength = int64(body.Len())
	return nil
}

// buildProxyRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func buildProxyRequest(r *http.Request, proxyUrl *url.URL) *http.Request {
	if proxyUrl == nil || r == nil {
		return r
	}
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
