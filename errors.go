package client

import (
	"fmt"
	"io"
	"strings"

	vocab "github.com/go-ap/activitypub"
)

type cerr struct {
	err error
	msg string
	i   vocab.IRI
	st  int
}

func (e cerr) annotate(err error) cerr {
	e.err = err
	return e
}

func (e cerr) iri(i vocab.IRI) cerr {
	e.i = i
	return e
}

func (e cerr) status(st int) cerr {
	e.st = st
	return e
}

func errf(msg string, p ...interface{}) cerr {
	return cerr{
		msg: fmt.Sprintf(msg, p...),
	}
}

// Error returns the formatted error
func (e cerr) Error() string {
	s := strings.Builder{}
	s.WriteString(e.msg)
	if e.i != "" {
		s.WriteString(": ")
		s.WriteString(e.i.String())
	}
	if e.err != nil {
		s.WriteString(": ")
		s.WriteString(e.err.Error())
	}
	return s.String()
}

func (e cerr) Unwrap() error {
	return e.err
}

func (e cerr) Format(s fmt.State, verb rune) {
	switch verb {
	case 's', 'v':
		_, _ = io.WriteString(s, e.msg)
		switch {
		case s.Flag('+'):
			if e.err == nil {
				return
			}
			_, _ = io.WriteString(s, ": ")
			_, _ = io.WriteString(s, fmt.Sprintf("%+s", e.err))
		}
	}
}
