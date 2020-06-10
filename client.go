package client

import (
	"bytes"
	"fmt"
	"github.com/go-ap/errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	pub "github.com/go-ap/activitypub"
)

type RequestSignFn func(*http.Request) error
type LogFn func(string, ...interface{})

type CanSign interface {
	SignFn(fn RequestSignFn)
}

type ActivityPub interface {
	CanSign

	LoadIRI(pub.IRI) (pub.Item, error)
	ToCollection(pub.IRI, pub.Item) (pub.IRI, pub.Item, error)
}

// UserAgent value that the client uses when performing requests
var UserAgent = "activitypub-go-http-client"
var ContentTypeJsonLD = `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`
var ContentTypeActivityJson = `application/activity+json`

// defaultErrorLogger
var defaultErrorLogger LogFn = func(s string, el ...interface{}) {}

// defaultInfoLogger
var defaultInfoLogger LogFn = func(s string, el ...interface{}) {}

var defaultSign RequestSignFn = func(r *http.Request) error { return nil }

type err struct {
	msg string
	iri pub.IRI
}

func errf(i pub.IRI, msg string, p ...interface{}) error {
	return &err{
		msg: fmt.Sprintf(msg, p...),
		iri: i,
	}
}

// Error returns the formatted error
func (e *err) Error() string {
	if len(e.iri) > 0 {
		return fmt.Sprintf("%s: %s", e.iri, e.msg)
	} else {
		return fmt.Sprintf("%s", e.msg)
	}
}

type client struct {
	signFn RequestSignFn
	c      *http.Client
	infoFn LogFn
	errFn  LogFn
}

func SetInfoLogger(logFn LogFn) optionFn {
	return func(c *client) error {
		if logFn != nil {
			c.infoFn = logFn
		}
		return nil
	}
}

func SetErrorLogger(logFn LogFn) optionFn {
	return func(c *client) error {
		if logFn != nil {
			c.errFn = logFn
		}
		return nil
	}
}

func TLSConfigSkipVerify() optionFn {
	return func(c *client) error {
		if tr, ok := c.c.Transport.(*http.Transport); ok {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}
		return nil
	}
}

func SignFn(fn RequestSignFn) optionFn {
	return func(c *client) error {
		if fn != nil {
			c.signFn = fn
		}
		return nil
	}
}

type optionFn func(s *client) error

func New(o ...optionFn) *client {
	c := &client{
		signFn: defaultSign,
		c:      http.DefaultClient,
		infoFn: defaultInfoLogger,
		errFn:  defaultErrorLogger,
	}
	for _, fn := range o {
		fn(c)
	}
	return c
}

func (c *client) SignFn(fn RequestSignFn) {
	if fn == nil {
		return
	}
	c.signFn = fn
}

// LoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c *client) LoadIRI(id pub.IRI) (pub.Item, error) {
	if len(id) == 0 {
		return nil, errf(id, "Invalid IRI, nil value")
	}
	if _, err := url.ParseRequestURI(id.String()); err != nil {
		return nil, errf(id, "Invalid IRI: %s", err)
	}
	var err error
	var obj pub.Item

	var resp *http.Response
	if resp, err = c.Get(id.String()); err != nil {
		c.errFn(err.Error())
		return obj, err
	}
	if resp == nil {
		err := errf(id, "Unable to load from the AP end point: nil response")
		c.errFn(err.Error())
		return obj, err
	}
	if resp.StatusCode != http.StatusOK {
		err := errf(id, "Unable to load from the AP end point: invalid status %d", resp.StatusCode)
		c.errFn(err.Error())
		return obj, err
	}

	defer resp.Body.Close()
	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		c.errFn(err.Error())
		return obj, err
	}

	return pub.UnmarshalJSON(body)
}

func (c client) log(err error) LogFn {
	var log LogFn
	if err != nil {
		log = func(s string, p ...interface{}) {
			c.errFn(s+" Error: %s", append(p, err))
		}
	} else {
		log = c.infoFn
	}
	return log
}

func (c *client) req(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	req.Proto = "HTTP/2.0"
	if err != nil {
		return req, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if method == http.MethodGet {
		req.Header.Add("Accept", ContentTypeJsonLD)
		req.Header.Add("Accept", ContentTypeActivityJson)
		req.Header.Add("Accept", "application/json")
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", ContentTypeJsonLD)
	}
	if c.signFn != nil {
		if err = c.signFn(req); err != nil {
			err := errf(pub.IRI(req.URL.String()), "Unable to sign request (method %q, previous error: %s)", req.Method, err)
			return req, err
		}
	}
	return req, nil
}

// Head
func (c client) Head(url string) (*http.Response, error) {
	req, err := c.req(http.MethodHead, url, nil)
	c.log(err)("%s: %s", http.MethodHead, url)
	return c.c.Do(req)
}

// Get wrapper over the functionality offered by the default http.Client object
func (c client) Get(url string) (*http.Response, error) {
	req, err := c.req(http.MethodGet, url, nil)
	c.log(err)("%s: %s", http.MethodGet, url)
	return c.c.Do(req)
}

// Post wrapper over the functionality offered by the default http.Client object
func (c *client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(http.MethodPost, url, body)
	c.log(err)("%s: %s", http.MethodPost, url)
	req.Header.Set("Content-Type", contentType)
	return c.c.Do(req)
}

// Put wrapper over the functionality offered by the default http.Client object
func (c client) Put(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(http.MethodPut, url, body)
	c.log(err)("%s: %s", http.MethodPut, url)
	req.Header.Set("Content-Type", contentType)
	return c.c.Do(req)
}

// Delete wrapper over the functionality offered by the default http.Client object
func (c client) Delete(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(http.MethodDelete, url, body)
	c.log(err)("%s: %s", http.MethodDelete, url)
	req.Header.Set("Content-Type", contentType)
	return c.c.Do(req)
}

func (c client) ToCollection(url pub.IRI, a pub.Item) (pub.IRI, pub.Item, error) {
	if len(url) == 0 {
		return "", nil, errf(url, "invalid URL to post to")
	}
	body, err := pub.MarshalJSON(a)
	var resp *http.Response
	var it pub.Item
	var iri pub.IRI
	resp, err = c.Post(url.String(), ContentTypeActivityJson, bytes.NewReader(body))
	if err != nil {
		return iri, it, err
	}
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		c.errFn(err.Error())
		return iri, it, err
	}
	if resp.StatusCode != http.StatusGone && resp.StatusCode >= http.StatusBadRequest {
		msg := "invalid status received: %d"
		if errors, err := errors.UnmarshalJSON(body); err == nil {
			if len(errors) > 0 && len(errors[0].Error()) > 0 {
				msg = errors[0].Error()
			}
		}
		return iri, it, errf(iri, msg, resp.StatusCode)
	}
	iri = pub.IRI(resp.Header.Get("Location"))
	it, err = pub.UnmarshalJSON(body)
	return iri, it, err
}
