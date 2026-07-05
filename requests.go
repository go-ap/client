package client

import (
	"context"
	"io"
	"net/http"
	"slices"

	"github.com/go-ap/client/internal/requests"
	"github.com/go-ap/errors"
)

func ActivityPubRequest(ctx context.Context, reqUrl, contentType string, body io.Reader) (*http.Request, error) {
	req, err := requests.ActivityPubBuilder(reqUrl, contentType, body).Request(ctx)
	if err != nil {
		return nil, err
	}
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	return req, nil
}

func FetchRequest(ctx context.Context, reqUrl, method string) (*http.Request, error) {
	if !slices.Contains([]string{http.MethodGet, http.MethodHead}, method) {
		return nil, errors.MethodNotAllowedf("invalid method for building fetch request %s", method)
	}
	req, err := requests.FetchBuilder(reqUrl, method).Request(ctx)
	if err != nil {
		return nil, err
	}
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	return req, nil
}
