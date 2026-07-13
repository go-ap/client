package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	vocab "github.com/go-ap/activitypub"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestWithActor(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL vocab.IRI
		wantErr  error
	}{
		{
			name:    "empty",
			wantErr: nil,
		},
		{
			name:     "with proxyURL",
			proxyURL: "http://example.com/ap/proxy",
			wantErr:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := new(C)
			WithProxyURL(tt.proxyURL)(tr)
			if !cmp.Equal(tr.proxyURL, tt.proxyURL) {
				t.Errorf("WithActor() = proxyURL mismatch %s", cmp.Diff(tt.proxyURL, tr.proxyURL))
			}
		})
	}
}

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
			tr := new(C)
			WithProxyURL(tt.proxyURL)(tr)
			if !cmp.Equal(tr.proxyURL, tt.proxyURL) {
				t.Errorf("WithProxyURL() = proxyURL mismatch %s", cmp.Diff(tt.wantErr, tr.proxyURL))
			}
		})
	}
}

//func TestNew(t *testing.T) {
//	tests := []struct {
//		name string
//		args []OptionFn
//		want http.RoundTripper
//	}{
//		{
//			name: "empty",
//		},
//		{
//			name: "with transport",
//			args: []OptionFn{WithTransport(&http.Transport{IdleConnTimeout: time.Second})},
//			want: &http.Transport{IdleConnTimeout: time.Second},
//		},
//		{
//			name: "with proxyURL",
//			args: []OptionFn{WithProxyURL("http://example.com/proxy")},
//			want: &Transport{ProxyURL: "http://example.com/proxy"},
//		},
//		{
//			name: "with actor",
//			args: []OptionFn{WithActor(&vocab.Actor{Endpoints: &vocab.Endpoints{ProxyURL: "http://example.com/test/proxy"}})},
//			want: &Transport{ProxyURL: "http://example.com/test/proxy"},
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			if got := New(tt.args...); !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(http.Transport{})) {
//				t.Errorf("New() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Transport{})))
//			}
//		})
//	}
//}

func TestC_tryProxiedRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	type fields struct {
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
				ProxyURL: vocab.IRI(proxy.URL),
			},
			req:        newReq(http.MethodGet, srv.URL+"/~jdoe", nil),
			wantStatus: http.StatusOK,
			wantBody:   []byte(`{"id":"http://example.com/~jdoe","type":"Actor"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := C{
				proxyURL: tt.fields.ProxyURL,
			}
			got, err := tr.tryProxiedRequest(tt.req)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Fatalf("RoundTrip() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
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

func newReq(method, target string, body io.Reader) *http.Request {
	r, _ := http.NewRequest(method, target, body)
	return r
}

func Test_buildProxyRequest(t *testing.T) {
	type args struct {
		r        *http.Request
		proxyUrl *url.URL
	}
	req := newReq("GET", "http://example.com", nil)
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
				r: newReq("GET", "http://example.com", nil),
			},
			want: newReq("GET", "http://example.com", nil),
		},
		{
			name: "not empty request, with proxy",
			args: args{
				r:        newReq("GET", "http://example.com", nil),
				proxyUrl: &url.URL{Scheme: "http", Host: "example.com", Path: "/proxy"},
			},
			want: mockProxyReq(newReq("GET", "http://example.com", nil), "http://example.com/proxy"),
		},
		{
			name: "request with headers, with proxy",
			args: args{
				r:        req,
				proxyUrl: &url.URL{Scheme: "http", Host: "example.com", Path: "/proxy"},
			},
			want: mockProxyReq(req, "http://example.com/proxy"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildProxyRequest(tt.args.r, tt.args.proxyUrl)
			if !cmp.Equal(got, tt.want, EquateRequests) {
				t.Errorf("buildProxyRequest() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Request{}, bytes.Buffer{})))
			}
		})
	}
}

func mockProxyReq(req *http.Request, proxy string) *http.Request {
	f := url.Values{}
	f.Add("id", req.URL.String())
	body := bytes.NewBufferString(f.Encode())
	r := httptest.NewRequest(http.MethodPost, proxy, body)
	r.Header = req.Header.Clone()
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//r.ContentLength = int64(body.Len())
	r.URL, _ = url.ParseRequestURI(proxy)
	r.RequestURI = ""
	r.RemoteAddr = ""
	return r
}
