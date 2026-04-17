package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"git.sr.ht/~mariusor/cache"
	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client/debug"
	"github.com/go-ap/client/s2s"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/oauth2"
)

func TestClient_LoadIRI1(t *testing.T) {
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
			want: &s2s.Transport{Base: defaultTransport},
		},
		{
			name: "empty s2s, skip true",
			args: args{rt: &s2s.Transport{}, skip: true,
			},
			// NOTE(marius): this is defaultTransport with InsecureSkipVerify set to true
			want: &s2s.Transport{Base: uaTransport{
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
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Errorf("SkipTLSValidation() = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
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

func compareErrorsWithUrl(url string) func(x, y any) bool {
	return func(x, y any) bool {
		xe := x.(error)
		ye := y.(error)
		if errors.Is(xe, ye) || errors.Is(ye, xe) {
			return true
		}
		xs := strings.ReplaceAll(xe.Error(), ": "+url, "")
		ys := strings.ReplaceAll(ye.Error(), ": "+url, "")
		return xs == ys
	}
}

var EquateWeakErrors = func(url string) cmp.Option {
	return cmp.FilterValues(areErrors, cmp.Comparer(compareErrorsWithUrl(url)))
}

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
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Errorf("WithLogger() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
			}
			if !cmp.Equal(cl.l, tt.l) {
				t.Errorf("WithLogger() = %s", cmp.Diff(tt.l, cl.l))
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
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Errorf("WithHTTPClient() = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
			}
			if !cmp.Equal(cl.c, tt.h, ignoredTransports, equateFuncs) {
				t.Errorf("WithHTTPClient() = %s", cmp.Diff(tt.h, cl.c, ignoredTransports, equateFuncs))
			}
		})
	}
}

func TestHTTPClient(t *testing.T) {
	tests := []struct {
		name   string
		client *C
		want   *http.Client
	}{
		{
			name: "empty",
			want: nil,
		},
		{
			name:   "with http.Client",
			client: &C{c: &http.Client{Timeout: 666 * time.Second}},
			want:   &http.Client{Timeout: 666 * time.Second},
		},
		{
			name:   "with C client",
			client: &C{c: &C{c: &http.Client{Timeout: 66 * time.Second}}},
			want:   &http.Client{Timeout: 66 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTTPClient(tt.client); !cmp.Equal(got, tt.want, ignoredTransports, equateFuncs) {
				t.Errorf("HTTPClient() = %s", cmp.Diff(tt.want, got, ignoredTransports, equateFuncs))
			}
		})
	}
}

func TestC_ToCollection(t *testing.T) {
	type args struct {
		toSend   vocab.Item
		colPaths vocab.CollectionPaths
	}
	tests := []struct {
		name    string
		client  httpClient
		args    args
		wantIRI vocab.IRI
		wantIt  vocab.Item
		wantErr error
	}{
		{
			name:    "empty",
			client:  nil,
			args:    args{},
			wantIRI: "",
			wantIt:  nil,
		},
		{
			name: "no collection IRIs",
			args: args{toSend: &vocab.Actor{}},
		},
		{
			name: "activity type",
			args: args{toSend: &vocab.Activity{}, colPaths: vocab.CollectionPaths{vocab.Inbox}},
		},
		{
			name: "activity type with multiple paths",
			args: args{toSend: &vocab.Activity{}, colPaths: vocab.CollectionPaths{vocab.Inbox, vocab.Outbox}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := vocab.MarshalJSON(tt.wantIt)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			name := "jdoe"
			toCollections := make(vocab.IRIs, 0, len(tt.args.colPaths))
			_ = vocab.OnIntransitiveActivity(tt.args.toSend, func(act *vocab.IntransitiveActivity) error {
				act.Actor = mockActor(vocab.IRI(srv.URL), name)
				return nil
			})

			for _, col := range tt.args.colPaths {
				toCollections = append(toCollections, col.IRI(vocab.IRI(srv.URL).AddPath(name)))
			}

			c := C{
				c: tt.client,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			gotIRI, gotIt, err := c.ToCollection(tt.args.toSend, toCollections...)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Errorf("ToCollection() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
				return
			}
			if gotIRI != tt.wantIRI {
				t.Errorf("ToCollection() got IRI = %v, want %v", gotIRI, tt.wantIRI)
			}
			if !cmp.Equal(gotIt, tt.wantIt, EquateItems) {
				t.Errorf("ToCollection() got Item = %s", cmp.Diff(tt.wantIt, gotIt, EquateItems))
			}
		})
	}
}

func TestC_toCollection(t *testing.T) {
	type args struct {
		ctx     context.Context
		act     vocab.Item
		colPath vocab.CollectionPath
	}
	tests := []struct {
		name      string
		client    httpClient
		handlerFn http.HandlerFunc
		args      args
		wantIRI   vocab.IRI
		wantIt    vocab.Item
		wantErr   error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("invalid IRI to POST to"),
		},
		{
			name:   "nil response",
			client: http.DefaultClient,
			args: args{
				ctx:     context.Background(),
				act:     mockActivity(),
				colPath: vocab.Outbox,
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantIRI: "",
			wantIt:  nil,
			wantErr: nil,
		},
		{
			name:   "nil response with Location",
			client: http.DefaultClient,
			args: args{
				ctx:     context.Background(),
				act:     mockActivity(),
				colPath: vocab.Outbox,
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Location", "http://example.com/1")
				w.WriteHeader(http.StatusOK)
			},
			wantIRI: "http://example.com/1",
			wantIt:  nil,
			wantErr: nil,
		},
		{
			name:   "response with Location",
			client: http.DefaultClient,
			args: args{
				ctx:     context.Background(),
				act:     mockActivity(),
				colPath: vocab.Outbox,
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Location", "http://example.com/666")
				w.WriteHeader(http.StatusOK)
				raw, _ := vocab.MarshalJSON(vocab.Object{ID: "http://example.com/note-1", Type: vocab.NoteType})
				_, _ = w.Write(raw)
			},
			wantIRI: "http://example.com/666",
			wantIt:  &vocab.Object{ID: "http://example.com/note-1", Type: vocab.NoteType},
			wantErr: nil,
		},
		{
			name:   "404 response",
			client: http.DefaultClient,
			args: args{
				ctx:     context.Background(),
				act:     mockActivity(),
				colPath: vocab.Outbox,
			},
			handlerFn: errors.HandleError(errors.NotFoundf("test")).ServeHTTP,
			wantErr:   errors.NotFoundf("test"),
		},
		{
			name:   "401 response",
			client: http.DefaultClient,
			args: args{
				ctx:     context.Background(),
				act:     mockActivity(),
				colPath: vocab.Outbox,
			},
			handlerFn: errors.HandleError(errors.Unauthorizedf("STOP")).ServeHTTP,
			wantErr:   errors.Unauthorizedf("STOP"),
		},
		{
			name:   "500 response",
			client: http.DefaultClient,
			args: args{
				ctx:     context.Background(),
				act:     mockActivity(),
				colPath: vocab.Outbox,
			},
			handlerFn: errors.HandleError(errors.Errorf("¡OOPS!")).ServeHTTP,
			wantErr:   errors.Errorf("invalid status received: 500: test: ¡OOPS!"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: tt.client,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			var colIRI vocab.IRI
			if tt.args.colPath != "" {
				srv := httptest.NewServer(tt.handlerFn)
				defer srv.Close()
				colIRI = tt.args.colPath.IRI(vocab.IRI(srv.URL))
			}

			gotIRI, gotIt, err := c.toCollection(tt.args.ctx, tt.args.act, colIRI)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors("")) {
				t.Errorf("toCollection() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors("")))
				return
			}
			if gotIRI != tt.wantIRI {
				t.Errorf("toCollection() got IRI = %s, want %s", gotIRI, tt.wantIRI)
			}
			if !cmp.Equal(gotIt, tt.wantIt, EquateItems) {
				t.Errorf("toCollection() got item = %s", cmp.Diff(tt.wantIt, gotIt, EquateItems))
			}
		})
	}
}

func TestC_LoadIRI(t *testing.T) {
	tests := []struct {
		name      string
		client    httpClient
		handlerFn http.HandlerFunc
		id        vocab.IRI
		want      vocab.Item
		wantErr   cerr
	}{
		{
			name:    "empty",
			wantErr: errf("invalid nil IRI"),
		},
		{
			name:    "invalid IRI",
			id:      ":",
			wantErr: errf("trying to load an invalid IRI").annotate(errors.Newf(":: parse \":\": missing protocol scheme")),
		},
		{
			name:    "no valid handler",
			id:      "http://example.com",
			wantErr: errf("invalid status received").status(http.StatusGatewayTimeout),
		},
		{
			name: "404 response",
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				errors.HandleError(errors.NotFoundf("NOT FOUND")).ServeHTTP(w, r)
			},
			id:      "http://example.com",
			wantErr: errf("invalid status received").status(http.StatusNotFound).annotate(errors.NotFoundf("NOT FOUND")),
		},
		{
			name: "empty body",
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			id:      "http://example.com",
			wantErr: errf("invalid response from ActivityPub server").annotate(errors.NotImplementedf("not a document and not an error")),
		},
		{
			name: "invalid json body",
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{`))
			},
			id:      "http://example.com",
			wantErr: errf("invalid ActivityPub object returned").annotate(errors.Newf("cannot parse JSON: cannot parse object: missing '}'; unparsed tail: \"\"")),
		},
		{
			name: "empty body but Gone",
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusGone)
			},
			id:      "http://example.com",
			wantErr: errf("").annotate(errors.Gonef("gone")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: tt.client,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}
			if tt.handlerFn == nil {
				tt.handlerFn = func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusGatewayTimeout)
				}
			}

			srv := httptest.NewServer(tt.handlerFn)
			if tt.id != "" {
				u, err := url.Parse(string(tt.id))
				if err == nil {
					su, _ := url.Parse(srv.URL)
					u.Host = su.Host
					tt.id = vocab.IRI(u.String())

					if tt.wantErr.msg != "" || tt.wantErr.err != nil {
						tt.wantErr.i = tt.id
					}
				}
			}

			got, err := c.LoadIRI(tt.id)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors(srv.URL)) {
				t.Errorf("LoadIRI() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors(srv.URL)))
				return
			}
			if !cmp.Equal(got, tt.want) {
				t.Errorf("LoadIRI() got = %s", cmp.Diff(tt.want, got))
			}
		})
	}
}
