package client

import (
	"net/http"
	"reflect"
	"testing"

	"git.sr.ht/~mariusor/cache"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client/debug"
	"github.com/go-ap/client/s2s"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getTransportWithTLSValidation(tt.args.rt, tt.args.skip); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getTransportWithTLSValidation() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
