package client

import (
	"crypto/tls"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"git.sr.ht/~mariusor/cache"
	"git.sr.ht/~mariusor/lw"
	"github.com/common-fate/httpsig/signer"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client/debug"
	"github.com/go-ap/client/s2s"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/oauth2"
)

func TestClient_LoadIRI(t *testing.T) {
	empty := vocab.IRI("")
	c := New()

	var err error
	_, err = c.LoadIRI(empty)
	if err == nil {
		t.Errorf("LoadIRI should have failed when using empty IRI value")
	}

	inv := vocab.IRI("example.com")
	_, err = c.LoadIRI(inv)
	if err == nil {
		t.Errorf("LoadIRI should have failed when using invalid http url")
	} else {
		t.Logf("Valid error received: %s", err)
	}
}

func TestClient_Get(t *testing.T) {
	t.Skipf("TODO")
}

func TestClient_Head(t *testing.T) {
	t.Skipf("TODO")
}

func TestClient_Post(t *testing.T) {
	t.Skipf("TODO")
}

func TestClient_Put(t *testing.T) {
	t.Skipf("TODO")
}

func TestClient_Delete(t *testing.T) {
	t.Skipf("TODO")
}

func Test_getTransportWithTLSValidation(t *testing.T) {
	type args struct {
		rt   http.RoundTripper
		skip bool
	}
	tests := []struct {
		name string
		args args
		want http.RoundTripper
	}{
		{
			name: "empty",
			args: args{},
			want: defaultTransport,
		},
		{
			name: "cache, skip false",
			args: args{rt: &cache.Transport{Base: defaultTransport}, skip: false},
			want: &cache.Transport{Base: defaultTransport},
		},
		{
			name: "cache, skip true",
			args: args{rt: &cache.Transport{Base: defaultTransport}, skip: true},
			// NOTE(marius): this is defaultTransport with InsecureSkipVerify set to true
			want: &cache.Transport{Base: uaTransport{
				Base: &http.Transport{
					Proxy:               http.ProxyFromEnvironment,
					MaxIdleConns:        100,
					IdleConnTimeout:     90 * time.Second,
					MaxIdleConnsPerHost: 20,
					DialContext:         (&net.Dialer{Timeout: longTimeout}).DialContext,
					TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
					TLSHandshakeTimeout: longTimeout,
				},
				ua: UserAgent,
			}},
		},
		{
			name: "empty oauth2, skip false",
			args: args{rt: &oauth2.Transport{}, skip: false},
			want: &oauth2.Transport{Base: defaultTransport},
		},
		{
			name: "empty oauth2, skip true",
			args: args{rt: &oauth2.Transport{}, skip: true},
			// NOTE(marius): this is defaultTransport with InsecureSkipVerify set to true
			want: &oauth2.Transport{Base: uaTransport{
				Base: &http.Transport{
					Proxy:               http.ProxyFromEnvironment,
					MaxIdleConns:        100,
					IdleConnTimeout:     90 * time.Second,
					MaxIdleConnsPerHost: 20,
					DialContext:         (&net.Dialer{Timeout: longTimeout}).DialContext,
					TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
					TLSHandshakeTimeout: longTimeout,
				},
				ua: UserAgent,
			}},
		},
		{
			name: "empty s2s, skip false",
			args: args{rt: &s2s.Transport{}, skip: false},
			want: &s2s.Transport{Transport: signer.Transport{BaseTransport: defaultTransport}},
		},
		{
			name: "empty s2s, skip true",
			args: args{rt: &s2s.Transport{}, skip: true,
			},
			// NOTE(marius): this is defaultTransport with InsecureSkipVerify set to true
			want: &s2s.Transport{Transport: signer.Transport{BaseTransport: uaTransport{
				Base: &http.Transport{
					Proxy:               http.ProxyFromEnvironment,
					MaxIdleConns:        100,
					IdleConnTimeout:     90 * time.Second,
					MaxIdleConnsPerHost: 20,
					DialContext:         (&net.Dialer{Timeout: longTimeout}).DialContext,
					TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
					TLSHandshakeTimeout: longTimeout,
				},
				ua: UserAgent,
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getTransportWithTLSValidation(tt.args.rt, tt.args.skip)
			if !cmp.Equal(got, tt.want, ignoredTransports, equateFuncs) {
				t.Errorf("getTransportWithTLSValidation() = %s", cmp.Diff(tt.want, got, ignoredTransports, equateFuncs))
			}
		})
	}
}

var ignoredTransports = cmpopts.IgnoreUnexported(http.Transport{}, tls.Config{}, uaTransport{}, cache.Transport{}, s2s.Transport{})

func TestSkipTLSValidation(t *testing.T) {
	tests := []struct {
		name    string
		skip    bool
		tr      http.RoundTripper
		wantErr error
	}{
		{
			name: "false empty transport",
			skip: false,
		},
		{
			name: "true empty transport",
			skip: true,
		},
		{
			name: "false http.Transport",
			tr:   &http.Transport{},
			skip: false,
		},
		{
			name: "true http.Transport",
			tr:   &http.Transport{},
			skip: true,
		},
		{
			name: "false debug.Transport",
			tr:   &debug.Transport{},
			skip: false,
		},
		{
			name: "true debug.Transport",
			tr:   &debug.Transport{},
			skip: true,
		},
		{
			name: "false s2s.Transport",
			tr:   &s2s.Transport{},
			skip: false,
		},
		{
			name: "true s2s.Transport",
			tr:   &s2s.Transport{},
			skip: true,
		},
		{
			name: "false cache.Transport",
			tr:   &cache.Transport{},
			skip: false,
		},
		{
			name: "true cache.Transport",
			tr:   &cache.Transport{},
			skip: true,
		},
		{
			name: "false uaTransport",
			tr:   &uaTransport{},
			skip: false,
		},
		{
			name: "true uaTransport",
			tr:   &uaTransport{},
			skip: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := new(C)
			cl.c = &http.Client{Transport: tt.tr}

			optionFn := SkipTLSValidation(tt.skip)
			err := optionFn(cl)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("SkipTLSValidation() = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}

			switch tr := cl.c.(*http.Client).Transport.(type) {
			case *http.Transport:
				if tr.TLSClientConfig.InsecureSkipVerify != tt.skip {
					t.Errorf("SkipTLSValidation() got skip validation %t, wanted %t", tt.skip, tr.TLSClientConfig.InsecureSkipVerify)
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

func areFuncs(a, b any) bool {
	ta := reflect.TypeOf(a)
	tb := reflect.TypeOf(b)
	return ta != nil && ta.Kind() == reflect.Func && tb != nil && tb.Kind() == reflect.Func
}

func compareFuncs(x, y any) bool {
	px := *(*unsafe.Pointer)(unsafe.Pointer(&x))
	py := *(*unsafe.Pointer)(unsafe.Pointer(&y))
	return px == py
}

var equateFuncs = cmp.FilterValues(areFuncs, cmp.Comparer(compareFuncs))

func TestWithLogger(t *testing.T) {
	tests := []struct {
		name    string
		l       lw.Logger
		wantErr error
	}{
		{
			name:    "empty",
			l:       nil,
			wantErr: nil,
		},
		{
			name:    "nil logger",
			l:       lw.Nil(),
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := new(C)
			optionFn := WithLogger(tt.l)
			err := optionFn(cl)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithLogger() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if !cmp.Equal(cl.l, tt.l) {
				t.Errorf("WithLogger() = %s", cmp.Diff(tt.l, cl.l))
			}

			if tt.l != nil {
				if cl.infoFn == nil {
					t.Errorf("WithLogger() C.infoFn should not be nil, when logger is present")
				}
				if cl.errFn == nil {
					t.Errorf("WithLogger() C.errFn should not be nil, when logger is present")
				}
			}
		})
	}
}

func TestWithHTTPClient(t *testing.T) {
	tests := []struct {
		name    string
		h       *http.Client
		wantErr error
	}{
		{
			name:    "empty",
			h:       nil,
			wantErr: nil,
		},
		{
			name:    "default client",
			h:       defaultClient,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := new(C)
			optionFn := WithHTTPClient(tt.h)
			err := optionFn(cl)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("WithHTTPClient() = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if !cmp.Equal(cl.c, tt.h, ignoredTransports, equateFuncs) {
				t.Errorf("WithHTTPClient() = %s", cmp.Diff(tt.h, cl.c, ignoredTransports, equateFuncs))
			}
		})
	}
}
