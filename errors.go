package client

import (
	"fmt"
	"io"

	vocab "github.com/go-ap/activitypub"
)

type err struct {
	err error
	msg string
	i   vocab.IRI
}

func (e err) annotate(err error) err {
	e.err = err
	return e
}

func (e err) iri(i vocab.IRI) err {
	e.i = i
	return e
}

func errf(msg string, p ...interface{}) err {
	return err{
		msg: fmt.Sprintf(msg, p...),
	}
}

// Error returns the formatted error
func (e err) Error() string {
	return e.msg
}

func (e err) Unwrap() error {
	return e.err
}

func (e err) Format(s fmt.State, verb rune) {
	switch verb {
	case 's', 'v':
		io.WriteString(s, e.msg)
		switch {
		case s.Flag('+'):
			if e.err == nil {
				return
			}
			io.WriteString(s, ": ")
			io.WriteString(s, fmt.Sprintf("%+s", e.err))
		}
	}
}
