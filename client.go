package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"git.sr.ht/~mariusor/cache"
	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client/debug"
	"github.com/go-ap/client/s2s"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	"golang.org/x/oauth2"
)

type Ctx = lw.Ctx

type RequestSignFn func(*http.Request) error
type CtxLogFn func(...Ctx) LogFn
type LogFn func(string, ...any)

type Basic interface {
	LoadIRI(vocab.IRI) (vocab.Item, error)
	CtxLoadIRI(context.Context, vocab.IRI) (vocab.Item, error)
	ToCollection(vocab.Item, ...vocab.IRI) (vocab.IRI, vocab.Item, error)
	CtxToCollection(context.Context, vocab.Item, ...vocab.IRI) (vocab.IRI, vocab.Item, error)
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

// defaultLogger is a nil logging function that is set as default.
var defaultLogger = lw.Nil()

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type C struct {
	c httpClient
	l lw.Logger
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
	case *debug.Transport:
		tr.Base = getTransportWithTLSValidation(tr.Base, skip)
	case *s2s.Transport:
		tr.Base = getTransportWithTLSValidation(tr.Base, skip)
	case *oauth2.Transport:
		tr.Base = getTransportWithTLSValidation(tr.Base, skip)
	case *cache.Transport:
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
			getTransportWithTLSValidation(cl.Transport, skip)
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
			Proxy:               http.ProxyFromEnvironment,
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
	c := &C{c: defaultClient, l: defaultLogger}
	for _, fn := range o {
		err := fn(c)
		if err != nil {
			defaultLogger.WithContext(lw.Ctx{"opt": fmt.Sprintf("%T", fn), "err": err}).Errorf("failed option call")
		}
	}
	return c
}

func (c C) loadCtx(ctx context.Context, id vocab.IRI) (vocab.Item, error) {
	errCtx := Ctx{"IRI": id}
	st := time.Now()
	if len(id) == 0 {
		return nil, errf("invalid nil IRI")
	}
	if _, err := id.URL(); err != nil {
		return nil, errf("trying to load an invalid IRI").iri(id).annotate(err)
	}
	var err error
	var obj vocab.Item

	var resp *http.Response
	if resp, err = c.CtxGet(ctx, id.String()); err != nil {
		c.l.WithContext(errCtx, Ctx{"err": err}).Errorf("failed to load IRI")
		return obj, err
	}

	// NOTE(marius): here we might want to group the Close with a Flush of the
	// Body using io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()

	errCtx["duration"] = time.Now().Sub(st)
	errCtx["status"] = resp.StatusCode
	errCtx["headers"] = resp.Header
	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		c.l.WithContext(errCtx, Ctx{"err": err}).Errorf("unable to read response body")
		return obj, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusGone {
		c.l.WithContext(errCtx, Ctx{"err": err}).Errorf("error response received")
		errb, _ := errors.UnmarshalJSON(body)
		if len(errb) > 0 {
			err = errf("invalid status received").status(resp.StatusCode).iri(id).annotate(errb[0])
		} else {
			err = errf("invalid status received").status(resp.StatusCode).iri(id)
		}

		return obj, err
	}

	c.l.WithContext(errCtx).Infof("OK")

	it, err := vocab.UnmarshalJSON(body)
	if err != nil {
		return nil, errf("invalid ActivityPub object returned").annotate(err)
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

		return it, errors.NewGone(e[0], "unable to load IRI: '%s'", id)
	}

	return nil, errf("invalid response from ActivityPub server").annotate(errors.NotImplementedf("not a document and not an error")).iri(id)
}

// CtxLoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c C) CtxLoadIRI(ctx context.Context, id vocab.IRI) (vocab.Item, error) {
	return c.loadCtx(ctx, id)
}

// LoadIRI tries to dereference an IRI and load the full ActivityPub object it represents
func (c C) LoadIRI(id vocab.IRI) (vocab.Item, error) {
	return c.loadCtx(context.Background(), id)
}

func (c *C) req(ctx context.Context, method string, url, contentType string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Proto = "HTTP/2.0"
	if method == http.MethodGet || method == http.MethodHead {
		acceptedMediaTypes := []string{ContentTypeActivityJson, ContentTypeJsonLD, "application/json;q=0.9"}
		req.Header.Add("Accept", strings.Join(acceptedMediaTypes, ", "))
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
	if c.c == nil {
		c.c = defaultClient
	}
	req, err := c.req(ctx, method, url, contentType, body)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

const contentTypeAny = "*/*"

// CtxGet wrapper over the functionality offered by the default http.Client object
func (c C) CtxGet(ctx context.Context, url string) (*http.Response, error) {
	return c.do(ctx, url, http.MethodGet, contentTypeAny, nil)
}

func (c C) toCollections(ctx context.Context, act vocab.Item, colIRI ...vocab.IRI) (vocab.IRI, vocab.Item, error) {
	result := make(vocab.ItemCollection, 0, len(colIRI))
	actIRIs := make(vocab.IRIs, 0, len(colIRI))

	for _, iri := range colIRI {
		actIRI, it, err := c.toCollection(ctx, act, iri)
		if err != nil {
			return "", result, err
		}
		if !vocab.IsNil(it) {
			result = append(result, it)
		}
		actIRIs = append(actIRIs, actIRI)
	}

	var it vocab.Item
	var iri vocab.IRI

	// NOTE(marius): currently I don't know how to return multiple IRIs if we have multiple actors,
	// so we currently do the wrong thing for len(iris) > 1 and return only the IRI of the first activity.
	if len(actIRIs) >= 1 {
		iri = actIRIs[0]
	}
	// NOTE(marius): we return the created object if there was only one actor, otherwise a collection of them.
	if len(result) == 1 {
		it = result[0]
	} else if len(result) > 1 {
		it = result
	}

	return iri, it, nil
}

func (c C) toCollection(ctx context.Context, act vocab.Item, colIRI vocab.IRI) (vocab.IRI, vocab.Item, error) {
	if len(colIRI) == 0 {
		return "", nil, errf("invalid IRI to POST to")
	}
	body, err := jsonld.WithContext(jsonld.IRI(vocab.ActivityBaseURI), jsonld.IRI(vocab.SecurityContextURI)).Marshal(act)
	if err != nil {
		return "", nil, errf("unable to marshal activity").iri(colIRI)
	}
	var resp *http.Response
	var resultIRI vocab.IRI
	resp, err = c.do(ctx, string(colIRI), http.MethodPost, ContentTypeActivityJson, bytes.NewReader(body))
	if err != nil {
		return resultIRI, nil, err
	}
	resultIRI = vocab.IRI(resp.Header.Get("Location"))

	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode != http.StatusGone {
		if err = errors.FromResponse(resp); err == nil {
			err = errf("invalid status received: %d", resp.StatusCode).iri(resultIRI)
		} else {
			err = errf("invalid status received: %d", resp.StatusCode).iri(resultIRI).annotate(err)
		}
		return resultIRI, nil, err
	}
	// NOTE(marius): here we might want to group the Close with a Flush of the
	// Body using io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()
	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.l.WithContext(Ctx{"iri": colIRI, "status": resp.Status, "err": err}).Errorf("failed to read response body")
		return resultIRI, nil, err
	}
	if len(resBody) == 0 {
		return resultIRI, nil, nil
	}
	it, err := vocab.UnmarshalJSON(resBody)
	if err != nil {
		return resultIRI, nil, err
	}
	return resultIRI, it, nil
}

// ToCollection
func (c C) ToCollection(a vocab.Item, url ...vocab.IRI) (vocab.IRI, vocab.Item, error) {
	return c.toCollections(context.Background(), a, url...)
}

// CtxToCollection
func (c C) CtxToCollection(ctx context.Context, a vocab.Item, url ...vocab.IRI) (vocab.IRI, vocab.Item, error) {
	return c.toCollections(ctx, a, url...)
}

func HTTPClient(c *C) *http.Client {
	if c == nil {
		return nil
	}
	switch httpC := c.c.(type) {
	case *C:
		return HTTPClient(httpC)
	case *http.Client:
		return httpC
	default:
		return nil
	}
}
