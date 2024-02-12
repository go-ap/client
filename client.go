package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	vocab "github.com/mix/activitypub"
	"golang.org/x/oauth2"
)

type Ctx = map[string]any

type RequestSignFn func(*http.Request) error
type CtxLogFn func(...Ctx) LogFn
type LogFn func(string, ...interface{})

type CanSign interface {
	SignFn(fn RequestSignFn)
}

type Basic interface {
	CanSign
	LoadIRI(vocab.IRI) (vocab.Item, error)
	CtxLoadIRI(context.Context, vocab.IRI) (vocab.Item, error)
	ToCollection(vocab.IRI, vocab.Item) (vocab.IRI, vocab.Item, error)
	CtxToCollection(context.Context, vocab.IRI, vocab.Item) (vocab.IRI, vocab.Item, error)
}

// UserAgent value that the client uses when performing requests
var UserAgent = "activitypub-go-http-client"

const (
	ContentTypeJsonLD = `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`
	// ContentTypeActivityJson This specification registers the application/activity+json MIME Media Type
	// specifically for identifying documents conforming to the Activity Streams 2.0 format.
	//
	// https://www.w3.org/TR/activitystreams-core/#media-type
	ContentTypeActivityJson = `application/activity+json`
)

// defaultLogger
var (
	defaultLogger LogFn = func(s string, el ...interface{}) {}

	defaultCtxLogger CtxLogFn = func(ctx ...Ctx) LogFn { return defaultLogger }

	defaultSignFn RequestSignFn = func(*http.Request) error { return nil }
)

type C struct {
	signFn RequestSignFn
	c      *http.Client
	l      logger
	infoFn CtxLogFn
	errFn  CtxLogFn
}

// SetDefaultHTTPClient is a hacky solution to modify the default static instance of the http.DefaultClient
// to whatever we have instantiated currently.
// This ensures that options like SkipTLSValidation propagate to the requests that are not done explicitly by us,
// because we assume it will be executed under the same constraints.
func SetDefaultHTTPClient() OptionFn {
	return func(c *C) error {
		http.DefaultClient = c.c
		return nil
	}
}

// WithHTTPClient sets the http client
func WithHTTPClient(h *http.Client) OptionFn {
	return func(c *C) error {
		c.c = h
		return nil
	}
}

func WithLogger(infoFn func(string, ...interface{}), errorFn func(string, ...interface{})) OptionFn {
	return func(c *C) error {
		if infoFn == nil && errorFn == nil {
			return nil
		}
		// persist the injected logging functions
		c.l = logger{infoFn: infoFn, errorFn: errorFn}
		if infoFn != nil {
			c.infoFn = func(ctx ...Ctx) LogFn {
				return c.l.WithContext(ctx...).InfoFn
			}
		}
		if errorFn != nil {
			c.errFn = func(ctx ...Ctx) LogFn {
				return c.l.WithContext(ctx...).ErrorFn
			}
		}
		return nil
	}
}

func getTransportWithTLSValidation(rt http.RoundTripper, skip bool) http.RoundTripper {
	if rt == nil {
		rt = defaultTransport
	}
	if tr, ok := rt.(*http.Transport); ok {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = new(tls.Config)
		}
		tr.TLSClientConfig.InsecureSkipVerify = skip
	}
	return rt
}

// SkipTLSValidation
func SkipTLSValidation(skip bool) OptionFn {
	return func(c *C) error {
		c.c.Transport = getTransportWithTLSValidation(c.c.Transport, skip)
		if tr, ok := c.c.Transport.(*oauth2.Transport); ok {
			tr.Base = getTransportWithTLSValidation(tr.Base, skip)
		}
		return nil
	}
}

// WithSignFn
func WithSignFn(fn RequestSignFn) OptionFn {
	return func(c *C) error {
		if fn != nil {
			c.signFn = fn
		}
		return nil
	}
}

// OptionFn
type OptionFn func(s *C) error

var (
	defaultClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: defaultTransport,
	}

	defaultTransport http.RoundTripper = &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 20,
		DialContext: (&net.Dialer{
			// This is the TCP connect timeout in this instance.
			Timeout: 2500 * time.Millisecond,
		}).DialContext,
		TLSHandshakeTimeout: 2500 * time.Millisecond,
	}
)

func New(o ...OptionFn) *C {
	c := &C{
		c:      defaultClient,
		signFn: defaultSignFn,
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

func (c C) loadCtx(ctx context.Context, id vocab.IRI) (vocab.Item, error) {
	errCtx := Ctx{"IRI": id}
	st := time.Now()
	if len(id) == 0 {
		return nil, errf("Invalid IRI, nil value").iri(id)
	}
	if _, err := url.ParseRequestURI(id.String()); err != nil {
		return nil, errf("Trying to load an invalid IRI").iri(id).annotate(err)
	}
	var err error
	var obj vocab.Item

	var resp *http.Response
	if resp, err = c.CtxGet(ctx, id.String()); err != nil {
		c.errFn(errCtx)("Error: %s", err)
		return obj, err
	}
	if resp == nil {
		err := errf("Unable to load from the AP end point: nil response").iri(id)
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)})("Error: %s", err)
		return obj, err
	}
	// NOTE(marius): here we might want to group the Close with a Flush of the
	// Body using io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusGone {
		var body []byte
		var errReadAll error
		if body, errReadAll = io.ReadAll(resp.Body); errReadAll != nil {
			c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)}, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("errReadAll: %s", errReadAll)
		}
		err := errf("Unable to load from the AP end point: invalid status %d %s", resp.StatusCode, body).iri(id)
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)}, Ctx{"status": resp.Status, "body": string(body), "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)}, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}
	c.infoFn(errCtx, Ctx{"duration": time.Now().Sub(st), "status": resp.Status})("OK")

	return vocab.UnmarshalJSON(body)
}

// CtxLoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c C) CtxLoadIRI(ctx context.Context, id vocab.IRI) (vocab.Item, error) {
	return c.loadCtx(ctx, id)
}

// LoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c C) LoadIRI(id vocab.IRI) (vocab.Item, error) {
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
	if date := req.Header.Get("Date"); date == "" {
		req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}
	if host := req.Header.Get("Host"); host == "" {
		req.Header.Set("Host", req.URL.Host)
	}
	if err := c.signFn(req); err != nil {
		c.errFn(Ctx{"method": req.Method, "iri": req.URL.String()})("Unable to sign request: %+s", err)
	}
	return req, nil
}

func (c *C) Do(req *http.Request) (*http.Response, error) {
	return c.c.Do(req)
}

func (c C) do(ctx context.Context, url, method, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.req(ctx, method, url, contentType, body)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
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

func (c C) toCollection(ctx context.Context, url vocab.IRI, a vocab.Item) (vocab.IRI, vocab.Item, error) {
	if len(url) == 0 {
		return "", nil, errf("invalid URL to post to").iri(url)
	}
	body, err := jsonld.WithContext(jsonld.IRI(vocab.ActivityBaseURI), jsonld.IRI(vocab.SecurityContextURI)).Marshal(a)
	if err != nil {
		return "", nil, errf("unable to marshal activity").iri(url)
	}
	var resp *http.Response
	var iri vocab.IRI
	resp, err = c.do(ctx, url.String(), http.MethodPost, ContentTypeActivityJson, bytes.NewReader(body))
	if err != nil {
		return iri, nil, err
	}
	iri = vocab.IRI(resp.Header.Get("Location"))

	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode != http.StatusGone {
		err := errors.FromResponse(resp)
		c.errFn(Ctx{"iri": url, "status": resp.Status})(err.Error())
		return iri, nil, errf("invalid status received: %d", resp.StatusCode).iri(iri).annotate(err)
	}
	// NOTE(marius): here we might want to group the Close with a Flush of the
	// Body using io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()
	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.errFn(Ctx{"iri": url, "status": resp.Status})(err.Error())
		return iri, nil, err
	}
	if len(resBody) == 0 {
		return iri, nil, nil
	}
	it, err := vocab.UnmarshalJSON(resBody)
	if err != nil {
		return iri, nil, err
	}
	return iri, it, nil
}

// ToCollection
func (c C) ToCollection(url vocab.IRI, a vocab.Item) (vocab.IRI, vocab.Item, error) {
	return c.toCollection(context.Background(), url, a)
}

// CtxToCollection
func (c C) CtxToCollection(ctx context.Context, url vocab.IRI, a vocab.Item) (vocab.IRI, vocab.Item, error) {
	return c.toCollection(ctx, url, a)
}
