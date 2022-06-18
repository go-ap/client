package client

import (
	"testing"

	vocab "github.com/go-ap/activitypub"
)

func TestNew(t *testing.T) {
	c := New()

	if c.signFn != nil {
		t.Errorf("New didn't return a valid client, not nil Sign function")
	}
}

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

func TestSetInfoLogger(t *testing.T) {
	type args struct {
		logFn CtxLogFn
	}
	tests := []struct {
		name string
		args args
		want *C
	}{
		{name: "nil-func", args: args{nil}, want: &C{infoFn: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &C{}
			got := SetInfoLogger(tt.args.logFn)
			if err := got(c); err != nil {
				t.Errorf("SetInfoLogger() returned error :%s", err)
			}
		})
	}
}
