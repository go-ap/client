package client

import (
	"fmt"
	"io"
	"strings"

	vocab "github.com/mix/activitypub"
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

type logger struct {
	ctx     Ctx
	infoFn  func(string, ...interface{})
	errorFn func(string, ...interface{})
	ctxStr  string
}

func (l logger) WithContext(ctx ...Ctx) logger {
	ll := l
	ll.ctx = Ctx{}
	for k, v := range l.ctx {
		ll.ctx[k] = v
	}

	for _, c := range ctx {
		for k, v := range c {
			ll.ctx[k] = v
		}
	}
	var logStr = ""
	for k, v := range ll.ctx {
		logStr = logStr + k + " " + fmt.Sprintf("%+v", v) + " "
	}
	ll.ctxStr = strings.TrimSpace(logStr)
	return ll
}

func (l logger) InfoFn(msg string, p ...interface{}) {
	if l.ctxStr != "" {
		msg = l.ctxStr + " " + msg
	}
	l.infoFn(msg, p)
}

func (l logger) ErrorFn(msg string, p ...interface{}) {
	if l.ctxStr != "" {
		msg = l.ctxStr + " " + msg
	}
	l.errorFn(msg, p)
}
