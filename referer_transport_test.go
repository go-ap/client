package client

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUserAgentTransport(t *testing.T) {
	type args struct {
		ua   string
		wrap http.RoundTripper
	}
	tests := []struct {
		name string
		args args
		want http.RoundTripper
	}{
		{
			name: "empty",
			args: args{},
			want: defaultTransport,
		},
		{
			name: "nil transport",
			args: args{
				ua:   "test-123",
				wrap: nil,
			},
			want: defaultTransport,
		},
		{
			name: "non-nil transport",
			args: args{
				ua:   "test-123",
				wrap: &http.Transport{},
			},
			want: uaTransport{
				ua:   "test-123",
				Base: &http.Transport{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UserAgentTransport(tt.args.ua, tt.args.wrap); !cmp.Equal(got, tt.want, ignoredTransports, equateFuncs) {
				t.Errorf("UserAgentTransport() = %s", cmp.Diff(tt.want, got, ignoredTransports, equateFuncs))
			}
		})
	}
}
