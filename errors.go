package client

import (
	"fmt"

	vocab "github.com/go-ap/activitypub"
)

type err struct {
	errs []error
	msg  string
	i    vocab.IRI
}

func (e *err) annotate(errs ...error) *err {
	e.errs = errs
	return e
}

func (e *err) iri(i vocab.IRI) *err {
	e.i = i
	return e
}

func errf(msg string, p ...interface{}) *err {
	return &err{
		msg: fmt.Sprintf(msg, p...),
	}
}

// Error returns the formatted error
func (e *err) Error() string {
	return e.msg
}

func (e *err) Unwrap() error {
	if len(e.errs) == 0 {
		return nil
	}
	return e.errs[0]
}
