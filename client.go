package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"git.sr.ht/~mariusor/cache"
	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client/debug"
	"github.com/go-ap/client/internal/requests"
	"github.com/go-ap/client/s2s"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	"golang.org/x/oauth2"
)

const (
	ContentTypeJsonLD = requests.ContentTypeJsonLD
	// ContentTypeActivityJson This specification registers the application/activity+json MIME Media Type
	// specifically for identifying documents conforming to the Activity Streams 2.0 format.
	//
	// https://www.w3.org/TR/activitystreams-core/#media-type
	ContentTypeActivityJson = requests.ContentTypeActivityJson
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
var UserAgent = "GoAP-Client (+https://github.com/go-ap)"

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

const MB = 1024 * 1024 * 1024

var (
	defaultClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: cache.Shared(defaultTransport, cache.Mem(MB)),
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

var TimeNow = func() time.Time { return time.Now().Truncate(time.Millisecond).UTC() }

func (c C) loadCtx(ctx context.Context, id vocab.IRI) (vocab.Item, error) {
	errCtx := Ctx{"IRI": id}
	st := TimeNow()
	if len(id) == 0 {
		return nil, errf("invalid nil IRI")
	}
	if _, err := id.URL(); err != nil {
		return nil, errf("trying to load an invalid IRI").iri(id).annotate(err)
	}

	var obj vocab.Item

	resp, err := c.CtxGet(ctx, id.String())
	if err != nil {
		c.l.WithContext(errCtx, Ctx{"err": err.Error()}).Errorf("failed to load IRI")
		return obj, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	errCtx["duration"] = time.Since(st)
	errCtx["status"] = resp.StatusCode
	if val := resp.Header.Get("Signature-Input"); val != "" {
		errCtx["sig-input"] = val
	}
	if val := resp.Header.Get("Signature"); val != "" {
		errCtx["sig"] = val
	}
	if val := resp.Header.Get("Authorization"); val != "" {
		errCtx["auth"] = val
	}
	if val := resp.Header.Get("ETag"); val != "" {
		errCtx["etag"] = val
	}
	if val := resp.Header.Get("User-Agent"); val != "" {
		errCtx["ua"] = val
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.l.WithContext(errCtx, Ctx{"err": err}).Errorf("unable to read response body")
		return obj, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusGone {
		c.l.WithContext(errCtx).Errorf("error response received")
		errb, _ := errors.UnmarshalJSON(body)
		if len(errb) > 0 {
			err = errf("invalid status received").status(resp.StatusCode).iri(id).annotate(errors.Join(errb...))
		} else {
			// NOTE(marius): treat the body as a wrapped error
			err = errf("invalid status received").status(resp.StatusCode).iri(id).annotate(fmt.Errorf("%s", body[:min(512, len(body))]))
		}

		return obj, err
	}

	it, err := vocab.UnmarshalJSON(body)
	if err != nil {
		return nil, errf("invalid ActivityPub object returned").iri(id).annotate(err)
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
			return it, errf("").iri(id).annotate(errors.Gonef("gone"))
		}

		return it, errf("unable to load IRI").iri(id).annotate(errors.NewGone(errors.Join(e...), ""))
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

func (c C) FetchRequest(ctx context.Context, url string) (*http.Request, error) {
	return FetchRequest(ctx, url, http.MethodGet)
}

func (c C) PostRequest(ctx context.Context, url, contentType string, body io.Reader) (*http.Request, error) {
	return ActivityPubRequest(ctx, url, contentType, body)
}

func (c C) Do(req *http.Request) (*http.Response, error) {
	if c.c == nil {
		c.c = defaultClient
	}
	return c.c.Do(req)
}

// CtxGet wrapper over the functionality offered by the default http.Client object
func (c C) CtxGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := FetchRequest(ctx, url, http.MethodGet)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
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

	cont, err := jsonld.WithContext(jsonld.IRI(vocab.ActivityBaseURI), jsonld.IRI(vocab.SecurityContextURI)).Marshal(act)
	if err != nil {
		return "", nil, errf("unable to marshal activity").iri(colIRI)
	}

	req, err := ActivityPubRequest(ctx, string(colIRI), requests.ContentTypeActivityJson, bytes.NewReader(cont))
	if err != nil {
		return "", nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return "", nil, err
	}

	resultIRI := vocab.IRI(resp.Header.Get("Location"))

	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode != http.StatusGone {
		if err = errors.FromResponse(resp); err == nil {
			err = errf("invalid status received: %d", resp.StatusCode).iri(resultIRI)
		} else {
			err = errf("invalid status received: %d", resp.StatusCode).iri(resultIRI).annotate(err)
		}
		return resultIRI, nil, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.l.WithContext(Ctx{"iri": colIRI, "status": resp.Status, "err": err}).Errorf("failed to read response body")
		return resultIRI, nil, err
	}
	if len(body) == 0 {
		return resultIRI, nil, nil
	}
	it, err := vocab.UnmarshalJSON(body)
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

func HTTPClient(c httpClient) *http.Client {
	if c == nil {
		return nil
	}
	switch httpC := c.(type) {
	case *C:
		if httpC == nil {
			return nil
		}
		return HTTPClient(httpC.c)
	case *http.Client:
		return httpC
	default:
		return nil
	}
}
