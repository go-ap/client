package client

import "net/http"

type uaTransport struct {
	Base http.RoundTripper
	ua   string
}

func UserAgentTransport(ua string, wrap http.RoundTripper) http.RoundTripper {
	if wrap == nil {
		wrap = defaultTransport
	}
	return uaTransport{Base: wrap, ua: ua}
}

func (t uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if ua := req.Header.Get("User-Agent"); len(ua) == 0 && len(t.ua) > 0 {
		req.Header.Set("User-Agent", t.ua)
	}
	return t.Base.RoundTrip(req)
}
