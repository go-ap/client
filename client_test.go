package client

import (
	"net/http"
	"reflect"
	"testing"

	vocab "github.com/go-ap/activitypub"
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
