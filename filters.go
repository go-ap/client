package client

import (
	"net/url"

	"github.com/go-ap/filters"
)

type FilterFn func() url.Values

// Filters is a convenience wrapper around filters.ToValues to generate the query values for the PubGetter methods.
// It receives a list of filters.Check and converts them to url.Values
func Filters(ff ...filters.Check) FilterFn {
	q := filters.ToValues(ff...)
	return func() url.Values {
		return q
	}
}

func rawFilterQuery(f ...FilterFn) string {
	if len(f) == 0 {
		return ""
	}
	q := make(url.Values)
	for _, ff := range f {
		qq := ff()
		for k, v := range qq {
			q[k] = append(q[k], v...)
		}
	}
	if len(q) == 0 {
		return ""
	}

	return "?" + q.Encode()
}
