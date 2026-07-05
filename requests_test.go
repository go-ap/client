package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-ap/client/internal/requests"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var mockTimeFn = func() time.Time {
	return time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
}

func TestFetchRequest(t *testing.T) {
	requests.TimeNow = mockTimeFn

	type args struct {
		reqUrl string
		method string
	}
	tests := []struct {
		name    string
		args    args
		want    *http.Request
		wantErr error
	}{
		{
			name:    "empty",
			args:    args{},
			wantErr: errors.MethodNotAllowedf("invalid method for building fetch request %s", ""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FetchRequest(context.Background(), tt.args.reqUrl, tt.args.method)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Errorf("FetchRequest() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
				return
			}
			if !cmp.Equal(got, tt.want, EquateRequests) {
				t.Errorf("FetchRequest() got = %s", cmp.Diff(tt.want, got, EquateRequests))
			}
		})
	}
}

func TestActivityPubRequest(t *testing.T) {
	requests.TimeNow = mockTimeFn

	type args struct {
		reqUrl      string
		contentType string
		body        io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    *http.Request
		wantErr error
	}{
		{
			name: "empty",
			args: args{},
			want: &http.Request{
				Method:     http.MethodPost,
				URL:        &url.URL{Scheme: "https"},
				Proto:      "HTTP/2.0",
				ProtoMajor: 2,
				Header: http.Header{
					"Accept":       []string{strings.Join([]string{ContentTypeActivityJson, ContentTypeJsonLD, "application/json;q=0.9"}, ", ")},
					"Content-Type": []string{ContentTypeJsonLD},
					"Date":         []string{mockTimeFn().Format(http.TimeFormat)},
					"Host":         []string{""},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ActivityPubRequest(context.Background(), tt.args.reqUrl, tt.args.contentType, tt.args.body)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Errorf("ActivityPubRequest() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
				return
			}
			if !cmp.Equal(got, tt.want, EquateRequests) {
				t.Errorf("ActivityPubRequest() got = %s", cmp.Diff(tt.want, got, EquateRequests))
			}
		})
	}
}

func areRequests(a, b any) bool {
	_, ok1 := a.(*http.Request)
	_, ok2 := b.(*http.Request)
	return ok1 && ok2
}

func compareRequests(x, y any) bool {
	xe := x.(*http.Request)
	ye := y.(*http.Request)
	if xe == nil || ye == nil {
		return xe == nil && ye == nil
	}
	if xe.ProtoMajor != ye.ProtoMajor {
		return false
	}
	if xe.ProtoMinor != ye.ProtoMinor {
		return false
	}
	if xe.Proto != ye.Proto {
		return false
	}
	if xe.Method != ye.Method {
		return false
	}
	if xe.Host != ye.Host {
		return false
	}
	if xe.RequestURI != ye.RequestURI {
		return false
	}
	if xe.Pattern != ye.Pattern {
		return false
	}
	if !cmp.Equal(xe.URL, ye.URL) {
		return false
	}
	if !cmp.Equal(xe.Header, ye.Header, cmpopts.SortMaps(strings.Compare)) {
		return false
	}
	if xe.ContentLength != ye.ContentLength {
		return false
	}
	if xe.Close != ye.Close {
		return false
	}
	if !cmp.Equal(xe.TransferEncoding, ye.TransferEncoding, cmpopts.SortSlices(strings.Compare)) {
		return false
	}
	if xe.Body != nil {
		if ye.Body == nil {
			return false
		}
		bx, errx := io.ReadAll(xe.Body)
		by, erry := io.ReadAll(ye.Body)
		if (errx != nil) != (erry != nil) {
			return false
		}
		if !bytes.Equal(bx, by) {
			return false
		}
	}
	return true
}

var EquateRequests = cmp.FilterValues(areRequests, cmp.Comparer(compareRequests))
