package msgsig

import (
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/go-ap/errors"
)

// Derived Components
// This specification defines the following derived components:

const (
	// Method is the method used for a request (Section 2.2.1).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.2.1
	Method = "@method"

	// TargetURI is the full target URI for a request (Section 2.2.2).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.4.1
	TargetURI = "@target-uri"

	// Authority is the authority of the target URI for a request (Section 2.2.3).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.6.1
	Authority = "@authority"

	// Scheme is the scheme of the target URI for a request (Section 2.2.4).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.8.1
	Scheme = "@scheme"

	// RequestTarget is the request target (Section 2.2.5).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.10.1
	RequestTarget = "@request-target"

	// Path is the absolute path portion of the target URI for a request (Section 2.2.6).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.12.1
	Path = "@path"

	// Query is the query portion of the target URI for a request (Section 2.2.7).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.14.1
	Query = "@query"

	// QueryParam is the parsed and encoded query parameter of the target URI for a request (Section 2.2.8).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.16.1
	QueryParam = "@query-param"

	// Status is the status code for a response (Section 2.2.9).
	// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2-4.18.1
	Status = "@status"
)

// DeriveMethod derives the @method component of the signature.
// The @method derived component refers to the HTTP method of a request message.
// The component value is canonicalized by taking the value of the method as a string.
// Note that the method name is case sensitive as per [HTTP], Section 9.1.
// While conventionally standardized method names are uppercase [ASCII],
// no transformation to the input method value's case is performed.
// https://www.rfc-editor.org/rfc/rfc9421.html#name-method
func DeriveMethod(r *http.Request) string {
	return r.Method
}

// DeriveTargetURI derives the @target-uri component of the signature.
// The @target-uri derived component refers to the target URI of a request message.
// The component value is the target URI of the request ([HTTP], Section 7.1),
// assembled from all available URI components, including the authority.
// https://www.rfc-editor.org/rfc/rfc9421.html#name-target-uri
func DeriveTargetURI(r *http.Request) string {
	return filepath.Join(r.RequestURI, r.URL.String())
}

// DeriveAuthority derives the @authority component of the signature.
// The @authority derived component refers to the authority component of the target URI of the HTTP request message,
// as defined in [HTTP], Section 7.2. In HTTP/1.1, this is usually conveyed using the Host header field,
// while in HTTP/2 and HTTP/3 it is conveyed using the :authority pseudo-header.
// The value is the fully qualified authority component of the request, comprised of the host and, optionally,
// port of the request target, as a string. The component value MUST be normalized according to the rules provided
// in [HTTP], Section 4.2.3. Namely, the hostname is normalized to lowercase, and the default port is omitted.
// https://www.rfc-editor.org/rfc/rfc9421.html#name-authority
func DeriveAuthority(r *http.Request) string {
	authority := r.Header.Get(":authority")
	if authority != "" {
		return authority
	}
	if u, err := url.ParseRequestURI(r.RequestURI); err == nil {
		authority = u.Host
	}
	// NOTE(marius): this should be normalized according to HTTP normalization rules in RFC9110:
	// https://www.rfc-editor.org/rfc/rfc9110#section-4.2.3
	return authority
}

// DeriveScheme derives the @scheme component of the signature.
// The @scheme derived component refers to the scheme of the target URL of the HTTP request message.
// The component value is the scheme as a lowercase string as defined in [HTTP], Section 4.2.
// While the scheme itself is case insensitive, it MUST be normalized to lowercase for inclusion in the signature base.
// https://www.rfc-editor.org/rfc/rfc9421.html#name-scheme
func DeriveScheme(r *http.Request) string {
	return r.URL.Scheme
}

// DeriveRequestTarget derives the @request-target component of the signature.
// For HTTP/1.1, the component value is equivalent to the request target portion of the request line.
// However, this value is more difficult to reliably construct in other versions of HTTP. Therefore,
// it is NOT RECOMMENDED that this component be used when versions of HTTP other than 1.1 might be in use.
// The origin form value is a combination of the absolute path and query components of the request URL
// https://www.rfc-editor.org/rfc/rfc9421.html#name-request-target
func DeriveRequestTarget(r *http.Request) string {
	return r.URL.Path
}

// DerivePath derives the @path component of the signature.
// The @path derived component refers to the target path of the HTTP request message.
// The component value is the absolute path of the request target defined by [URI],
// with no query component and no trailing question mark (?) character.
// The value is normalized according to the rules provided in [HTTP], Section 4.2.3.
// Namely, an empty path string is normalized as a single slash (/) character.
// Path components are represented by their values before decoding any percent-encoded octets,
// as described in the simple string comparison rules provided in Section 6.2.1 of [URI].
// https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.6
func DerivePath(r *http.Request) string {
	return r.URL.Path
}

// DeriveQuery derives the @query component of the signature.
// The @query derived component refers to the query component of the HTTP request message.
// The component value is the entire normalized query string defined by [URI], including the leading ? character.
// The value is read using the simple string comparison rules provided in Section 6.2.1 of [URI].
// Namely, percent-encoded octets are not decoded.
// https://www.rfc-editor.org/rfc/rfc9421.html#name-query
func DeriveQuery(r *http.Request) string {
	return r.URL.RawQuery
}

// DeriveQueryParameters derives the @query-param component of the signature.
// If the query portion of a request target URI uses HTML form parameters in the format defined in Section 5
// ("application/x-www-form-urlencoded") of [HTMLURL], the @query-param derived component allows addressing
// of these individual query parameters. The query parameters MUST be parsed according to Section 5.1
// ("application/x-www-form-urlencoded parsing") of [HTMLURL], resulting in a list of (nameString, valueString) tuples.
// The REQUIRED name parameter of each component identifier contains the encoded nameString of a single query parameter
// as a String value. The component value of a single named parameter is the encoded valueString of that single query
// parameter. Several different named query parameters MAY be included in the covered components.
// Single named parameters MAY occur in any order in the covered components, regardless of the order they
// occur in the query string.
//
// The value of the name parameter and the component value of a single named parameter are calculated
// via the following process:
// * Parse the nameString or valueString of the named query parameter defined by Section 5.1
// ("application/x-www-form-urlencoded parsing") of [HTMLURL]; this is the value after percent-encoded
// octets are decoded.
// * Encode the nameString or valueString using the "percent-encode after encoding" process defined
// by Section 5.2 ("application/x-www-form-urlencoded serializing") of [HTMLURL]; this results in
// an ASCII string [ASCII].
// * Output the ASCII string.
// Note that the component value does not include any leading question mark (?) characters,
// equals sign (=) characters, or separating ampersand (&) characters. Named query parameters with an empty
// valueString have an empty string as the component value. Note that due to inconsistencies in implementations,
// some query parameter parsing libraries drop such empty values.
//
// If a query parameter is named as a covered component but it does not occur in the query parameters, this MUST
// cause an error in the signature base generation.
// https://www.rfc-editor.org/rfc/rfc9421.html#name-query-parameters
func DeriveQueryParameters(r *http.Request) string {
	panic(errors.NotImplementedf("TODO"))
	return ""
}

// DeriveStatus derives the @status component of the signature.
// The @status derived component refers to the three-digit numeric HTTP status code of a response message
// as defined in [HTTP], Section 15. The component value is the serialized three-digit integer of the HTTP
// status code, with no descriptive text.
// https://www.rfc-editor.org/rfc/rfc9421.html#name-status-code
func DeriveStatus(h *http.Request) string {
	panic(errors.NotImplementedf("TODO"))
	return ""
}
