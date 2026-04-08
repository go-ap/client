package proxy

import (
	"fmt"
	"net/http"
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

func areItems(a, b any) bool {
	_, ok1 := a.(vocab.Item)
	_, ok2 := b.(vocab.Item)
	return ok1 && ok2
}

func compareItems(x, y any) bool {
	var i1 vocab.Item
	var i2 vocab.Item
	if ic1, ok := x.(vocab.Item); ok {
		i1 = ic1
	}
	if ic2, ok := y.(vocab.Item); ok {
		i2 = ic2
	}
	return vocab.ItemsEqual(i1, i2) || vocab.ItemsEqual(i2, i1)
}

var EquateItems = cmp.FilterValues(areItems, cmp.Comparer(compareItems))

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
	type fields struct {
		Base     http.RoundTripper
		ProxyURL vocab.IRI
	}
	tests := []struct {
		name    string
		fields  fields
		req     *http.Request
		want    *http.Response
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: fmt.Errorf("nil request"),
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
				t.Errorf("RoundTrip() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want) {
				t.Errorf("RoundTrip() got = %s", cmp.Diff(tt.want, got, EquateWeakErrors))
			}
		})
	}
}

func Test_buildProxyRequest(t *testing.T) {
	type args struct {
		r        *http.Request
		proxyUrl *url.URL
	}
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			name: "empty",
		},
		{
			name: "no proxy url",
			args: args{
				r: &http.Request{
					Method: http.MethodGet,
					URL: &url.URL{
						Scheme: "http",
						Host:   "example.com",
						Path:   "/",
					},
				},
			},
			want: &http.Request{
				Method: http.MethodGet,
				URL: &url.URL{
					Scheme: "http",
					Host:   "example.com",
					Path:   "/",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildProxyRequest(tt.args.r, tt.args.proxyUrl); !cmp.Equal(got, tt.want, cmp.AllowUnexported(http.Request{}, url.URL{})) {
				t.Errorf("buildProxyRequest() = %s", cmp.Diff(tt.want, got, cmp.AllowUnexported(http.Request{}, url.URL{})))
			}
		})
	}
}
