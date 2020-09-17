package client

import (
	"bytes"
	"context"
	"fmt"
	"github.com/go-ap/errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	pub "github.com/go-ap/activitypub"
)

type Ctx map[string]interface{}

type RequestSignFn func(*http.Request) error
type CtxLogFn func(...Ctx) LogFn
type LogFn func(string, ...interface{})

type CanSign interface {
	SignFn(fn RequestSignFn)
}

type ActivityPub interface {
	CanSign

	LoadIRI(pub.IRI) (pub.Item, error)
	CtxLoadIRI(context.Context, pub.IRI) (pub.Item, error)
	ToCollection(pub.IRI, pub.Item) (pub.IRI, pub.Item, error)
	CtxToCollection(context.Context, pub.IRI, pub.Item) (pub.IRI, pub.Item, error)
}

// UserAgent value that the client uses when performing requests
var UserAgent = "activitypub-go-http-client"
var ContentTypeJsonLD = `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`
var ContentTypeActivityJson = `application/activity+json`

// defaultLogger
var defaultLogger LogFn = func(s string, el ...interface{}) {}

var defaultCtxLogger CtxLogFn = func(ctx ...Ctx) LogFn { return defaultLogger }

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
	infoFn CtxLogFn
	errFn  CtxLogFn
}

func SetInfoLogger(logFn CtxLogFn) optionFn {
	return func(c *client) error {
		if logFn != nil {
			c.infoFn = logFn
		}
		return nil
	}
}

func SetErrorLogger(logFn CtxLogFn) optionFn {
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
		infoFn: defaultCtxLogger,
		errFn:  defaultCtxLogger,
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

func (c client) load(ctx context.Context, id pub.IRI) (pub.Item, error) {
	errCtx := Ctx{"iri": id}
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
		c.errFn(errCtx)("Error: %s", err)
		return obj, err
	}
	if resp == nil {
		err := errf(id, "Unable to load from the AP end point: nil response")
		c.errFn(errCtx)("Error: %s", err)
		return obj, err
	}
	if resp.StatusCode != http.StatusOK {
		err := errf(id, "Unable to load from the AP end point: invalid status %d", resp.StatusCode)
		c.errFn(errCtx, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}

	defer resp.Body.Close()
	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		c.errFn(errCtx, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}

	return pub.UnmarshalJSON(body)
}

// CtxLoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c *client) CtxLoadIRI(ctx context.Context, id pub.IRI) (pub.Item, error) {
	return c.load(ctx, id)
}

// LoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c client) LoadIRI(id pub.IRI) (pub.Item, error) {
	return c.load(context.Background(), id)
}

func (c client) log(err error) CtxLogFn {
	var logFn CtxLogFn
	if err != nil {
		logFn = func(ctx ...Ctx) LogFn {
			ctx = append(ctx, Ctx{"err": err})
			return c.errFn(ctx...)
		}
	} else {
		logFn = c.infoFn
	}
	return logFn
}

func (c *client) req(ctx context.Context, method string, url, contentType string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	req.Proto = "HTTP/2.0"
	if err != nil {
		return req, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if method == http.MethodGet || method == http.MethodHead {
		req.Header.Add("Accept", ContentTypeJsonLD)
		req.Header.Add("Accept", ContentTypeActivityJson)
		req.Header.Add("Accept", "application/json")
	} else {
		if len(contentType) == 0 {
			contentType = ContentTypeJsonLD
		}
		req.Header.Set("Content-Type", contentType)
	}
	if c.signFn != nil {
		if err = c.signFn(req); err != nil {
			err := errf(pub.IRI(req.URL.String()), "Unable to sign request (method %q, previous error: %s)", req.Method, err)
			return req, err
		}
	}
	return req, nil
}

func (c client) do(ctx context.Context, url, method, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(ctx, method, url, contentType, body)
	c.log(err)(Ctx{"URL": url})(method)
	if err != nil {
		return nil, err
	}
	return c.c.Do(req)
}

// Head
func (c client) Head(url string) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodHead, "", nil)
}

// CtxGet wrapper over the functionality offered by the default http.Client object
func (c client) CtxGet(ctx context.Context, url string) (*http.Response, error) {
	return c.do(ctx, url, http.MethodGet, "", nil)
}

// Get wrapper over the functionality offered by the default http.Client object
func (c client) Get(url string) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodGet, "", nil)
}

// CtxPost wrapper over the functionality offered by the default http.Client object
func (c client) CtxPost(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(ctx, url, http.MethodPost, contentType, body)
}

// Post wrapper over the functionality offered by the default http.Client object
func (c client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodPost, contentType, body)
}

// Put wrapper over the functionality offered by the default http.Client object
func (c client) Put(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodPut, contentType, body)
}

// Delete wrapper over the functionality offered by the default http.Client object
func (c client) Delete(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodDelete, contentType, body)
}

func (c client) toCollection(ctx context.Context, url pub.IRI, a pub.Item) (pub.IRI, pub.Item, error) {
	if len(url) == 0 {
		return "", nil, errf(url, "invalid URL to post to")
	}
	body, err := pub.MarshalJSON(a)
	var resp *http.Response
	var it pub.Item
	var iri pub.IRI
	resp, err = c.do(ctx, url.String(), http.MethodPost, ContentTypeActivityJson, bytes.NewReader(body))
	if err != nil {
		return iri, it, err
	}
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		c.errFn()("Error: %s", err)
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

// ToCollection
func (c client) ToCollection(url pub.IRI, a pub.Item) (pub.IRI, pub.Item, error) {
	return c.toCollection(context.Background(), url, a)
}

// CtxToCollection
func (c client) CtxToCollection(ctx context.Context, url pub.IRI, a pub.Item) (pub.IRI, pub.Item, error) {
	return c.toCollection(ctx, url, a)
}
