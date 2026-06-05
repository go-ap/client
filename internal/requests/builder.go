package requests

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/carlmjohnson/requests"
)

var TimeNow = time.Now().Truncate(time.Millisecond).UTC

const (
	ContentTypeJsonLD = `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`
	// ContentTypeActivityJson This specification registers the application/activity+json MIME Media Type
	// specifically for identifying documents conforming to the Activity Streams 2.0 format.
	//
	// https://www.w3.org/TR/activitystreams-core/#media-type
	ContentTypeActivityJson = `application/activity+json`
)

func ActivityPubBuilder(reqUrl, contentType string, body io.Reader) *requests.Builder {
	rb := requests.URL(reqUrl).Method(http.MethodPost)
	if len(contentType) == 0 {
		contentType = ContentTypeJsonLD
	}
	rb.ContentType(contentType)
	if body != nil {
		rb.BodyReader(body)
	}
	if u, err := rb.URL(); err == nil {
		rb.Host(u.Hostname())
		rb.Header("Host", u.Hostname())
	}
	rb.Header("Date", TimeNow().Format(http.TimeFormat))
	return rb
}

const plainJson = "application/json;q=0.9"

func FetchBuilder(reqUrl, method string) *requests.Builder {
	rb := requests.URL(reqUrl).Method(method)
	acceptedMediaTypes := []string{ContentTypeActivityJson, ContentTypeJsonLD, plainJson}
	rb.Header("Accept", strings.Join(acceptedMediaTypes, ", "))
	rb.Header("Date", TimeNow().Format(http.TimeFormat))
	if u, err := rb.URL(); err == nil {
		rb.Host(u.Hostname())
		rb.Header("Host", u.Hostname())
	}
	return rb
}
