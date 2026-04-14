package client

import (
	"testing"

	"github.com/go-ap/activitypub"
	"github.com/go-ap/filters"
)

func Test_irif(t *testing.T) {
	type args struct {
		i activitypub.IRI
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want activitypub.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "empty filters",
			args: args{
				i: "http://example.com",
			},
			want: "http://example.com",
		},
		{
			name: "with maxItems",
			args: args{
				i: "http://example.com",
				f: []filters.Check{filters.WithMaxCount(2)},
			},
			want: "http://example.com?maxItems=2",
		},
		{
			name: "with after",
			args: args{
				i: "http://example.com",
				f: []filters.Check{filters.After(filters.SameID("http://social.example.com/jdoe"))},
			},
			want: "http://example.com?after=http%3A%2F%2Fsocial.example.com%2Fjdoe",
		},
		{
			name: "with type+name",
			args: args{
				i: "http://example.com",
				f: []filters.Check{filters.HasType("test"), filters.NameIs("jdoe")},
			},
			// NOTE(marius): I am not sure yet, what in the url.Values logic makes this always return in this order
			want: "http://example.com?name=jdoe&type=test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := irif(tt.args.i, tt.args.f...); got != tt.want {
				t.Errorf("irif() = %v, want %v", got, tt.want)
			}
		})
	}
}
