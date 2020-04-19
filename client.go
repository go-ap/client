package client

import (
	"bytes"
	"fmt"
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

// ErrorLogger
var ErrorLogger LogFn = func(s string, el ...interface{}) {}

// InfoLogger
var InfoLogger LogFn = func(s string, el ...interface{}) {}

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
}

func New() *client {
	return &client{
		signFn: defaultSign,
		c:      http.DefaultClient,
	}
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
		ErrorLogger(err.Error())
		return obj, err
	}
	if resp == nil {
		err := errf(id, "Unable to load from the AP end point: nil response")
		ErrorLogger(err.Error())
		return obj, err
	}
	if resp.StatusCode != http.StatusOK {
		err := errf(id, "Unable to load from the AP end point: invalid status %d", resp.StatusCode)
		ErrorLogger(err.Error())
		return obj, err
	}

	defer resp.Body.Close()
	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		ErrorLogger(err.Error())
		return obj, err
	}

	return pub.UnmarshalJSON(body)
}

func (c *client) req(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
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
	var log LogFn
	if err != nil {
		log = ErrorLogger
	} else {
		log = InfoLogger
	}
	log(http.MethodHead, url)
	return c.c.Do(req)
}

// Get wrapper over the functionality offered by the default http.Client object
func (c client) Get(url string) (*http.Response, error) {
	req, err := c.req(http.MethodGet, url, nil)
	var log LogFn
	if err != nil {
		log = ErrorLogger
	} else {
		log = InfoLogger
	}
	log(http.MethodGet, url)
	return c.c.Do(req)
}

// Post wrapper over the functionality offered by the default http.Client object
func (c *client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(http.MethodPost, url, body)
	var log LogFn
	if err != nil {
		log = ErrorLogger
	} else {
		log = InfoLogger
	}
	log(http.MethodPost, url)
	req.Header.Set("Content-Type", contentType)
	return c.c.Do(req)
}

// Put wrapper over the functionality offered by the default http.Client object
func (c client) Put(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(http.MethodPut, url, body)
	var log LogFn
	if err != nil {
		log = ErrorLogger
	} else {
		log = InfoLogger
	}
	log(http.MethodPut, url)
	req.Header.Set("Content-Type", contentType)
	return c.c.Do(req)
}

// Delete wrapper over the functionality offered by the default http.Client object
func (c client) Delete(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(http.MethodDelete, url, body)
	var log LogFn
	if err != nil {
		log = ErrorLogger
	} else {
		log = InfoLogger
	}
	log(http.MethodDelete, url)
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
		ErrorLogger(err.Error())
		return iri, it, err
	}
	if resp.StatusCode != http.StatusGone && resp.StatusCode >= http.StatusBadRequest {
		return iri, it, errf(iri, "invalid status received: %d", resp.StatusCode)
	}
	iri = pub.IRI(resp.Header.Get("Location"))
	it, err = pub.UnmarshalJSON(body)
	return iri, it, err
}
