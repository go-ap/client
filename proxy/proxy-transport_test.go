package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestWithActor(t *testing.T) {
	tests := []struct {
		name    string
		act     *vocab.Actor
		wantErr error
	}{
		{
			name:    "empty",
			act:     nil,
			wantErr: nil,
		},
		{
			name:    "no endpoints",
			act:     &vocab.Actor{ID: "http://example.com/~jdoe"},
			wantErr: nil,
		},
		{
			name:    "no proxyURL",
			act:     &vocab.Actor{ID: "http://example.com/~jdoe", Endpoints: &vocab.Endpoints{}},
			wantErr: nil,
		},
		{
			name:    "with proxyURL",
			act:     &vocab.Actor{ID: "http://example.com/~jdoe", Endpoints: &vocab.Endpoints{ProxyURL: "http://example.com/ap/proxy"}},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(Transport)
			optionFn := WithActor(tt.act)
			err := optionFn(tr)
			if !cmp.Equal(err, tt.wantErr) {
				t.Errorf("WithActor() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if tt.act != nil {
				wantProxyURL := vocab.EmptyID
				if tt.act.Endpoints != nil {
					wantProxyURL = tt.act.Endpoints.ProxyURL
				}
				if !cmp.Equal(tr.ProxyURL, wantProxyURL) {
					t.Errorf("WithActor() = proxyURL mismatch %s", cmp.Diff(wantProxyURL, tr.ProxyURL))
				}
			}
		})
	}
}

func areErrors(a, b any) bool {
	_, ok1 := a.(error)
	_, ok2 := b.(error)
	return ok1 && ok2
}

func compareErrors(x, y any) bool {
	xe := x.(error)
	ye := y.(error)
	if errors.Is(xe, ye) || errors.Is(ye, xe) {
		return true
	}
	return xe.Error() == ye.Error()
}

var EquateWeakErrors = cmp.FilterValues(areErrors, cmp.Comparer(compareErrors))

func TestWithProxyURL(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL vocab.IRI
		wantErr  error
	}{
		{
			name:     "empty",
			proxyURL: "",
			wantErr:  nil,
		},
		{
			name:     "with proxyURL",
			proxyURL: "http://example.com/ap/proxy",
			wantErr:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(Transport)
			optionFn := WithProxyURL(tt.proxyURL)
			err := optionFn(tr)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithProxyURL() = error %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if !cmp.Equal(tr.ProxyURL, tt.proxyURL) {
				t.Errorf("WithProxyURL() = proxyURL mismatch %s", cmp.Diff(tt.wantErr, tr.ProxyURL))
			}
		})
	}
}

func TestWithTransport(t *testing.T) {
	tests := []struct {
		name    string
		tr      http.RoundTripper
		wantErr error
	}{
		{
			name:    "empty",
			tr:      nil,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(Transport)
			optionFn := WithTransport(tt.tr)
			err := optionFn(tr)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithTransport() = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		args []OptionFn
		want http.RoundTripper
	}{
		{
			name: "empty",
		},
		{
			name: "with transport",
			args: []OptionFn{WithTransport(&http.Transport{IdleConnTimeout: time.Second})},
			want: &http.Transport{IdleConnTimeout: time.Second},
		},
		{
			name: "with proxyURL",
			args: []OptionFn{WithProxyURL("http://example.com/proxy")},
			want: &Transport{ProxyURL: "http://example.com/proxy"},
		},
		{
			name: "with actor",
			args: []OptionFn{WithActor(&vocab.Actor{Endpoints: &vocab.Endpoints{ProxyURL: "http://example.com/test/proxy"}})},
			want: &Transport{ProxyURL: "http://example.com/test/proxy"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args...); !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(http.Transport{})) {
				t.Errorf("New() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Transport{})))
			}
		})
	}
}

func TestTransport_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	type fields struct {
		Base     http.RoundTripper
		ProxyURL vocab.IRI
	}
	tests := []struct {
		name       string
		fields     fields
		req        *http.Request
		wantStatus int
		wantBody   []byte
		wantErr    error
	}{
		{
			name:    "empty",
			wantErr: fmt.Errorf("nil request"),
		},
		{
			name: "jdoe",
			fields: fields{
				Base:     http.DefaultTransport,
				ProxyURL: vocab.IRI(proxy.URL),
			},
			req:        httptest.NewRequest(http.MethodGet, srv.URL+"/~jdoe", nil),
			wantStatus: http.StatusOK,
			wantBody:   []byte(`{"id":"http://example.com/~jdoe","type":"Actor"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := Transport{
				Base:     tt.fields.Base,
				ProxyURL: tt.fields.ProxyURL,
			}
			got, err := tr.RoundTrip(tt.req)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Fatalf("RoundTrip() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if got == nil {
				if tt.wantStatus != 0 {
					t.Errorf("RoundTrip() invalid nil response, expected status code %d", tt.wantStatus)
				}
				return
			}
			if got.StatusCode != tt.wantStatus {
				t.Errorf("RoundTrip() invalid status code %d, expected = %d", got.StatusCode, tt.wantStatus)
			}
			body, err := io.ReadAll(got.Body)
			if err != nil {
				t.Errorf("RoundTrip() unable to read body, error = %s", err)
			}
			if bytes.Equal(body, tt.wantBody) {
				t.Errorf("RoundTrip() body = %s", cmp.Diff(tt.wantBody, body))
			}
		})
	}
}

func Test_buildProxyRequest(t *testing.T) {
	type args struct {
		r        *http.Request
		proxyUrl *url.URL
	}
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-Invented", "666")
	req.Header.Add("Authorization", "Bearer =invalid=")
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			name: "empty",
			args: args{},
			want: nil,
		},
		{
			name: "no proxy url",
			args: args{
				r: &http.Request{
					Method: http.MethodGet,
					URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/"}},
			},
			want: &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/"}},
		},
		{
			name: "not empty request",
			args: args{
				r: httptest.NewRequest("GET", "http://example.com", nil),
			},
			want: httptest.NewRequest("GET", "http://example.com", nil),
		},
		{
			name: "not empty request, with proxy",
			args: args{
				r:        httptest.NewRequest("GET", "http://example.com", nil),
				proxyUrl: &url.URL{Scheme: "http", Host: "example.com", Path: "/proxy"},
			},
			want: proxyReq(httptest.NewRequest("GET", "http://example.com", nil), "http://example.com/proxy"),
		},
		{
			name: "request with headers, with proxy",
			args: args{
				r:        req,
				proxyUrl: &url.URL{Scheme: "http", Host: "example.com", Path: "/proxy"},
			},
			want: proxyReq(req, "http://example.com/proxy"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildProxyRequest(tt.args.r, tt.args.proxyUrl)
			if !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(http.Request{}, bytes.Buffer{})) {
				t.Errorf("buildProxyRequest() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Request{}, bytes.Buffer{})))
			}
		})
	}
}

func proxyReq(req *http.Request, proxy string) *http.Request {
	f := url.Values{}
	f.Add("id", req.URL.String())
	body := bytes.NewBuffer([]byte(f.Encode()))
	r := httptest.NewRequest(http.MethodPost, proxy, body)
	r.Header = req.Header.Clone()
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ContentLength = int64(body.Len())
	r.RequestURI = proxy
	return r
}
