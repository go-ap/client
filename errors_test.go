package client

import (
	"strings"
	"testing"

	vocab "github.com/go-ap/activitypub"
)

func TestErr_Error(t *testing.T) {
	e := err{
		msg: "test",
		i:   vocab.IRI(""),
	}

	if len(e.Error()) == 0 {
		t.Errorf("error message should not be empty")
	}
	if !strings.Contains(e.Error(), "test") {
		t.Errorf("error message should contain the 'test' string")
	}
}
