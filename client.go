package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	pub "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
)

type Ctx map[string]interface{}

type RequestSignFn func(*http.Request) error
type CtxLogFn func(...Ctx) LogFn
type LogFn func(string, ...interface{})

type CanSign interface {
	SignFn(fn RequestSignFn)
}

type Basic interface {
	CanSign
	LoadIRI(pub.IRI) (pub.Item, error)
	CtxLoadIRI(context.Context, pub.IRI) (pub.Item, error)
	ToCollection(pub.IRI, pub.Item) (pub.IRI, pub.Item, error)
	CtxToCollection(context.Context, pub.IRI, pub.Item) (pub.IRI, pub.Item, error)
}

// UserAgent value that the client uses when performing requests
var UserAgent = "activitypub-go-http-client"
const (
	ContentTypeJsonLD = `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`
	ContentTypeActivityJson = `application/activity+json`
)

// defaultLogger
var defaultLogger LogFn = func(s string, el ...interface{}) {}

var defaultCtxLogger CtxLogFn = func(ctx ...Ctx) LogFn { return defaultLogger }

var defaultSign RequestSignFn = func(*http.Request) error { return nil }

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
	return e.msg
}

type C struct {
	signFn RequestSignFn
	c      *http.Client
	infoFn CtxLogFn
	errFn  CtxLogFn
}

func SetInfoLogger(logFn CtxLogFn) optionFn {
	return func(c *C) error {
		if logFn != nil {
			c.infoFn = logFn
		}
		return nil
	}
}

func SetErrorLogger(logFn CtxLogFn) optionFn {
	return func(c *C) error {
		if logFn != nil {
			c.errFn = logFn
		}
		return nil
	}
}

func SkipTLSValidation(skip bool) optionFn {
	return func(c *C) error {
		if c.c.Transport == nil {
			c.c.Transport = defaultTransport
		}
		if tr, ok := c.c.Transport.(*http.Transport); ok {
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = new(tls.Config)
			}
			tr.TLSClientConfig.InsecureSkipVerify = skip
		}
		return nil
	}
}

func SignFn(fn RequestSignFn) optionFn {
	return func(c *C) error {
		if fn != nil {
			c.signFn = fn
		}
		return nil
	}
}

type optionFn func(s *C) error

var defaultClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: defaultTransport,
}

var defaultTransport http.RoundTripper = &http.Transport{
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	MaxIdleConnsPerHost:   20,
	DialContext: (&net.Dialer{
		// This is the TCP connect timeout in this instance.
		Timeout: 2500 * time.Millisecond,
	}).DialContext,
	TLSHandshakeTimeout: 2500 * time.Millisecond,
}

func New(o ...optionFn) *C {
	c := &C{
		c:      defaultClient,
		infoFn: defaultCtxLogger,
		errFn:  defaultCtxLogger,
	}
	for _, fn := range o {
		fn(c)
	}
	return c
}

func (c *C) SignFn(fn RequestSignFn) {
	if fn == nil {
		return
	}
	c.signFn = fn
}

func (c C) loadCtx(ctx context.Context, id pub.IRI) (pub.Item, error) {
	errCtx := Ctx{"IRI": id}
	st := time.Now()
	if len(id) == 0 {
		return nil, errf(id, "Invalid IRI, nil value")
	}
	if _, err := url.ParseRequestURI(id.String()); err != nil {
		return nil, errf(id, "Invalid IRI: %s", err)
	}
	var err error
	var obj pub.Item

	var resp *http.Response
	if resp, err = c.CtxGet(ctx, id.String()); err != nil {
		c.errFn(errCtx)("Error: %s", err)
		return obj, err
	}
	if resp == nil {
		err := errf(id, "Unable to load from the AP end point: nil response")
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)})("Error: %s", err)
		return obj, err
	}
	// NOTE(marius): here we might want to group the Close with a Flush of the
	// Body using io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusGone {
		err := errf(id, "Unable to load from the AP end point: invalid status %d", resp.StatusCode)
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)}, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}

	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)}, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}
	c.infoFn(errCtx, Ctx{"duration": time.Now().Sub(st), "status": resp.Status})("OK")

	return pub.UnmarshalJSON(body)
}

// CtxLoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c *C) CtxLoadIRI(ctx context.Context, id pub.IRI) (pub.Item, error) {
	return c.loadCtx(ctx, id)
}

// LoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c C) LoadIRI(id pub.IRI) (pub.Item, error) {
	return c.loadCtx(context.Background(), id)
}

func (c C) log(err error) CtxLogFn {
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

func (c *C) req(ctx context.Context, method string, url, contentType string, body io.Reader) (*http.Request, error) {
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
		err = c.signFn(req)
		if err != nil {
			err := errf(pub.IRI(req.URL.String()), "Unable to sign request (method %q, previous error: %s)", req.Method, err)
			return req, err
		}
	}
	return req, nil
}

func (c C) do(ctx context.Context, url, method, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(ctx, method, url, contentType, body)
	if err != nil {
		return nil, err
	}
	return c.c.Do(req)
}

// Head
func (c C) Head(url string) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodHead, "", nil)
}

// CtxGet wrapper over the functionality offered by the default http.Client object
func (c C) CtxGet(ctx context.Context, url string) (*http.Response, error) {
	return c.do(ctx, url, http.MethodGet, "", nil)
}

// Get wrapper over the functionality offered by the default http.Client object
func (c C) Get(url string) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodGet, "", nil)
}

// CtxPost wrapper over the functionality offered by the default http.Client object
func (c C) CtxPost(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(ctx, url, http.MethodPost, contentType, body)
}

// Post wrapper over the functionality offered by the default http.Client object
func (c C) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodPost, contentType, body)
}

// Put wrapper over the functionality offered by the default http.Client object
func (c C) Put(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodPut, contentType, body)
}

// Delete wrapper over the functionality offered by the default http.Client object
func (c C) Delete(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodDelete, contentType, body)
}

func (c C) toCollection(ctx context.Context, url pub.IRI, a pub.Item) (pub.IRI, pub.Item, error) {
	if len(url) == 0 {
		return "", nil, errf(url, "invalid URL to post to")
	}
	body, err := pub.MarshalJSON(a)
	if err != nil {
		return "", nil, errf(url, "unable to marshal activity")
	}
	var resp *http.Response
	var it pub.Item
	var iri pub.IRI
	resp, err = c.do(ctx, url.String(), http.MethodPost, ContentTypeActivityJson, bytes.NewReader(body))
	if err != nil {
		return iri, it, err
	}
	// NOTE(marius): here we might want to group the Close with a Flush of the
	// Body using io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()

	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		c.errFn()("Error: %s", err)
		return iri, it, err
	}
	if resp.StatusCode != http.StatusGone && resp.StatusCode >= http.StatusBadRequest {
		msg := "invalid status received: %d"
		if errors, err := errors.UnmarshalJSON(body); err == nil {
			if len(errors) > 0 && len(errors[0].Error()) > 0 {
				for _, retErr := range errors {
					msg = msg + ", " + retErr.Error()
				}
			}
		}
		return iri, it, errf(iri, msg, resp.StatusCode)
	}
	iri = pub.IRI(resp.Header.Get("Location"))
	it, err = pub.UnmarshalJSON(body)
	return iri, it, err
}

// ToCollection
func (c C) ToCollection(url pub.IRI, a pub.Item) (pub.IRI, pub.Item, error) {
	return c.toCollection(context.Background(), url, a)
}

// CtxToCollection
func (c C) CtxToCollection(ctx context.Context, url pub.IRI, a pub.Item) (pub.IRI, pub.Item, error) {
	return c.toCollection(ctx, url, a)
}
