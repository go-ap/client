package client

import (
	"github.com/go-ap/filters"
	"net/url"
	"reflect"
	"testing"
)

func kv(key string, values ...string) url.Values {
	return url.Values{
		key: values,
	}
}

func urlValues(v ...url.Values) url.Values {
	res := url.Values{}
	for _, vv := range v {
		for k, vvv := range vv {
			for _, s := range vvv {
				res.Add(k, s)
			}
		}
	}
	return res
}

func TestFilters(t *testing.T) {
	tests := []struct {
		name string
		args []filters.Check
		want url.Values
	}{
		{
			name: "empty",
			args: nil,
			want: url.Values{},
		},
		{
			name: "maxItems",
			args: []filters.Check{
				filters.WithMaxCount(666),
			},
			want: urlValues(kv("maxItems", "666")),
		},
		{
			name: "id",
			args: []filters.Check{
				filters.SameID("http://example.com"),
			},
			want: urlValues(kv("id", "http://example.com")),
		},
		{
			name: "similar id",
			args: []filters.Check{
				filters.IDLike("http://example.com"),
			},
			want: urlValues(kv("id", "~http://example.com")),
		},
		{
			name: "not id",
			args: []filters.Check{
				filters.Not(filters.SameID("http://example.com")),
			},
			want: urlValues(kv("id", "!http://example.com")),
		},
		{
			name: "id and type",
			args: []filters.Check{
				filters.SameID("http://example.com"),
				filters.HasType("Accept", "Reject"),
			},
			want: urlValues(
				kv("id", "http://example.com"),
				kv("type", "Accept", "Reject"),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filterFn := Filters(tt.args...)
			if got := filterFn(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Filters() = %v, want %v", got, tt.want)
			}
		})
	}
}
