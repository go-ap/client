package client

import (
	"strings"
	"testing"

	pub "github.com/go-ap/activitypub"
)

func TestNew(t *testing.T) {
	c := New()

	if c.signFn == nil {
		t.Errorf("New didn't return a valid client, nil Sign function")
	}
}

func TestErr_Error(t *testing.T) {
	e := err{
		msg: "test",
		iri: pub.IRI(""),
	}

	if len(e.Error()) == 0 {
		t.Errorf("error message should not be empty")
	}
	if !strings.Contains(e.Error(), "test") {
		t.Errorf("error message should contain the 'test' string")
	}
}

func TestClient_LoadIRI(t *testing.T) {
	empty := pub.IRI("")
	c := New()

	var err error
	_, err = c.LoadIRI(empty)
	if err == nil {
		t.Errorf("LoadIRI should have failed when using empty IRI value")
	}

	inv := pub.IRI("example.com")
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
		logFn LogFn
	}
	tests := []struct {
		name string
		args args
		want *client
	}{
		{name: "nil-func", args: args{nil}, want: &client{infoFn: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{}
			got := SetInfoLogger(tt.args.logFn)
			if err := got(c); err != nil {
				t.Errorf("SetInfoLogger() returned error :%s", err)
			}
		})
	}
}
