package requests

import (
	"io"
	"net/http"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/go-ap/jsonld"
)

var TimeNow = func() time.Time { return time.Now().Truncate(time.Millisecond).UTC() }

const (
	ContentTypeJsonLD = jsonld.ContentType

	// ContentTypeJsonActivity This specification registers the application/activity+json MIME Media Type
	// specifically for identifying documents conforming to the Activity Streams 2.0 format.
	//
	// https://www.w3.org/TR/activitystreams-core/#media-type
	ContentTypeJsonActivity = `application/activity+json`

	ContentTypeJson = "application/json;q=0.9"
)

func ActivityPubBuilder(reqUrl, contentType string, body io.Reader) *requests.Builder {
	rb := FetchBuilder(reqUrl, http.MethodPost)
	if len(contentType) == 0 {
		contentType = ContentTypeJsonLD
	}
	rb.ContentType(contentType)
	if body != nil {
		rb.BodyReader(body)
	}
	return rb
}

var defaultAcceptedMediaTypes = []string{ContentTypeJsonActivity, ContentTypeJsonLD, ContentTypeJson}

func FetchBuilder(reqUrl, method string) *requests.Builder {
	rb := requests.URL(reqUrl).Method(method)
	// NOTE(marius): these are required when signing requests with our draft HTTP-Signatures
	rb.Header("Accept", defaultAcceptedMediaTypes...)
	if u, err := rb.URL(); err == nil {
		rb.Header("Host", u.Host)
	}
	rb.Header("Date", TimeNow().Format(http.TimeFormat))
	return rb
}
