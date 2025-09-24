package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"git.sr.ht/~mariusor/cache"
	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client/s2s"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	"golang.org/x/oauth2"
)

type Ctx = lw.Ctx

type RequestSignFn func(*http.Request) error
type CtxLogFn func(...Ctx) LogFn
type LogFn func(string, ...interface{})

type Basic interface {
	LoadIRI(vocab.IRI) (vocab.Item, error)
	CtxLoadIRI(context.Context, vocab.IRI) (vocab.Item, error)
	ToCollection(vocab.IRI, vocab.Item) (vocab.IRI, vocab.Item, error)
	CtxToCollection(context.Context, vocab.IRI, vocab.Item) (vocab.IRI, vocab.Item, error)
}

// UserAgent value that the client uses when performing requests
var UserAgent = "GoActivityPub DefaultClient (https://github.com/go-ap)"

const (
	ContentTypeJsonLD = `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`
	// ContentTypeActivityJson This specification registers the application/activity+json MIME Media Type
	// specifically for identifying documents conforming to the Activity Streams 2.0 format.
	//
	// https://www.w3.org/TR/activitystreams-core/#media-type
	ContentTypeActivityJson = `application/activity+json`
)

var (
	// defaultLogger is a nil logging function that is set as default.
	defaultLogger LogFn = func(s string, el ...interface{}) {}

	// defaultCtxLogger is the nil context logging function that is set as default.
	defaultCtxLogger CtxLogFn = func(ctx ...Ctx) LogFn { return defaultLogger }
)

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type C struct {
	c      httpClient
	l      lw.Logger
	infoFn CtxLogFn
	errFn  CtxLogFn
}

// SetDefaultHTTPClient is a hacky solution to modify the default static instance of the http.DefaultClient
// to whatever we have instantiated currently.
// This ensures that options like SkipTLSValidation propagate to the requests that are not done explicitly by us,
// because we assume it will be executed under the same constraints.
func SetDefaultHTTPClient() OptionFn {
	return func(c *C) error {
		if cl, ok := c.c.(*http.Client); ok {
			http.DefaultClient = cl
		}
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

func WithLogger(l lw.Logger) OptionFn {
	return func(c *C) error {
		c.l = l
		if l != nil {
			c.infoFn = func(ctx ...Ctx) LogFn {
				return l.WithContext(ctx...).Debugf
			}
			c.errFn = func(ctx ...Ctx) LogFn {
				return l.WithContext(ctx...).Warnf
			}
		}
		return nil
	}
}

func getTransportWithTLSValidation(rt http.RoundTripper, skip bool) http.RoundTripper {
	if rt == nil {
		rt = defaultTransport
	}
	switch tr := rt.(type) {
	case *http.Transport:
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = new(tls.Config)
		}
		tr.TLSClientConfig.InsecureSkipVerify = skip
	case *s2s.HTTPSignatureTransport:
		tr.Base = getTransportWithTLSValidation(tr.Base, skip)
	case *oauth2.Transport:
		tr.Base = getTransportWithTLSValidation(tr.Base, skip)
	case cache.Transport:
		tr.Base = getTransportWithTLSValidation(tr.Base, skip)
	case uaTransport:
		tr.Base = getTransportWithTLSValidation(tr.Base, skip)
	}
	return rt
}

// SkipTLSValidation sets the flag for skipping TLS validation on the default HTTP transport.
func SkipTLSValidation(skip bool) OptionFn {
	return func(c *C) error {
		if cl, ok := c.c.(*http.Client); ok {
			cl.Transport = getTransportWithTLSValidation(cl.Transport, skip)
		}
		return nil
	}
}

// OptionFn
type OptionFn func(s *C) error

var (
	defaultClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: cachedTransport(defaultTransport),
	}

	// This is the TCP connect timeout in this instance.
	longTimeout = 2500 * time.Millisecond

	defaultTransport http.RoundTripper = uaTransport{
		Base: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			MaxIdleConnsPerHost: 20,
			DialContext:         (&net.Dialer{Timeout: longTimeout}).DialContext,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
			TLSHandshakeTimeout: longTimeout,
		},
		ua: UserAgent,
	}
)

const MB = 1024 * 1024 * 1024

func cachedTransport(t http.RoundTripper) http.RoundTripper {
	return cache.Shared(t, cache.Mem(MB))
}

func New(o ...OptionFn) *C {
	c := &C{
		c:      defaultClient,
		infoFn: defaultCtxLogger,
		errFn:  defaultCtxLogger,
	}
	for _, fn := range o {
		_ = fn(c)
	}
	return c
}

func (c C) loadCtx(ctx context.Context, id vocab.IRI) (vocab.Item, error) {
	errCtx := Ctx{"IRI": id}
	st := time.Now()
	if len(id) == 0 {
		return nil, errf("Invalid IRI, nil value").iri(id)
	}
	if _, err := id.URL(); err != nil {
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
		err := errf("Unable to load from the AP end point: invalid status %d", resp.StatusCode).iri(id)
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)}, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		c.errFn(errCtx, Ctx{"duration": time.Now().Sub(st)}, Ctx{"status": resp.Status, "headers": resp.Header, "proto": resp.Proto})("Error: %s", err)
		return obj, err
	}
	c.infoFn(errCtx, Ctx{"duration": time.Now().Sub(st), "status": resp.Status})("OK")

	it, err := vocab.UnmarshalJSON(body)
	if err != nil {
		return nil, err
	}

	if it != nil {
		// NOTE(marius): success
		return it, nil
	}

	// NOTE(marius): the body didn't have a recognizable ActivityPub document,
	// maybe it's an error due to being deleted
	if resp.StatusCode == http.StatusGone {
		e, err := errors.UnmarshalJSON(body)
		if err != nil || len(e) == 0 {
			return it, errors.Gonef("gone")
		}

		return it, errors.NewGone(e[0], "unable to load IRI: %q", id)
	}

	return nil, errors.NotImplementedf("invalid response from ActivityPub server, not a document and not an error: %s", id)
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

const contentTypeAny = "*/*"

// Head
func (c C) Head(url string) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodHead, contentTypeAny, nil)
}

// CtxGet wrapper over the functionality offered by the default http.Client object
func (c C) CtxGet(ctx context.Context, url string) (*http.Response, error) {
	return c.do(ctx, url, http.MethodGet, contentTypeAny, nil)
}

// Get wrapper over the functionality offered by the default http.Client object
func (c C) Get(url string) (*http.Response, error) {
	return c.do(context.Background(), url, http.MethodGet, contentTypeAny, nil)
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
		if err = errors.FromResponse(resp); err == nil {
			err = errf("invalid status received: %d", resp.StatusCode).iri(iri)
		} else {
			err = errf("invalid status received: %d", resp.StatusCode).iri(iri).annotate(err)
		}
		return iri, nil, err
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

func HTTPClient(c C) *http.Client {
	switch httpC := c.c.(type) {
	case *C:
		return HTTPClient(*httpC)
	case *http.Client:
		return httpC
	default:
		return nil
	}
}
