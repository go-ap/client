package credentials

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ap/activitypub"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/oauth2"
)

func TestCodeVerifier(t *testing.T) {
	got := CodeVerifier()
	if len(got) != 43 {
		t.Errorf("CodeVerifier() returned string of length %d, expected %d", len(got), 43)
	}
	for i, ch := range got {
		if strings.Index(pkceAlphabet, string(ch)) < 0 {
			t.Errorf("CodeVerifier() invalid character at pos %d, %s", i, string(ch))
		}
	}
}

func TestOAuth2Client(t *testing.T) {
	type args struct {
		ctx context.Context
		c   *C2S
	}
	tests := []struct {
		name string
		args args
		want *http.Client
	}{
		{
			name: "empty",
			args: args{},
			want: &http.Client{},
		},
		{
			name: "empty client",
			args: args{
				ctx: context.Background(),
			},
			want: &http.Client{},
		},
		{
			name: "client in context",
			args: args{
				ctx: context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: 666 * time.Millisecond}),
			},
			want: &http.Client{Timeout: 666 * time.Millisecond},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OAuth2Client(tt.args.ctx, tt.args.c); !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(http.Client{})) {
				t.Errorf("OAuth2Client() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Client{})))
			}
		})
	}
}

func TestC2S_Refresh(t *testing.T) {
	type fields struct {
		Conf oauth2.Config
		Tok  *oauth2.Token
	}
	tests := []struct {
		name    string
		fields  fields
		ctx     context.Context
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.New("oauth2: token expired and refresh token is not set"),
		},
		{
			name: "with refresh tok",
			fields: fields{
				Conf: oauth2.Config{},
				Tok: &oauth2.Token{
					AccessToken:  "test",
					TokenType:    "Bear",
					RefreshToken: "666",
					//Expiry:       time.Time{},
					//ExpiresIn:    10,
				},
			},
			ctx:     nil,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &C2S{
				Conf: tt.fields.Conf,
				Tok:  tt.fields.Tok,
			}
			if err := c.Refresh(tt.ctx); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Refresh() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func areErrors(a, b any) bool {
	_, ok1 := a.(error)
	_, ok2 := b.(error)
	return ok1 && ok2
}

func compareErrors(x, y interface{}) bool {
	xe := x.(error)
	ye := y.(error)
	if errors.Is(xe, ye) || errors.Is(ye, xe) {
		return true
	}
	return xe.Error() == ye.Error()
}

var EquateWeakErrors = cmp.FilterValues(areErrors, cmp.Comparer(compareErrors))

func TestC2S_Config(t *testing.T) {
	type fields struct {
	}
	tests := []struct {
		name string
		conf oauth2.Config
		want *oauth2.Config
	}{
		{
			name: "empty",
			conf: oauth2.Config{},
			want: &oauth2.Config{},
		},
		{
			name: "not empty",
			conf: oauth2.Config{
				ClientID:     "1",
				ClientSecret: "dsa",
				Endpoint: oauth2.Endpoint{
					AuthURL:       "http://example.com/a",
					DeviceAuthURL: "http://example.com/d",
					TokenURL:      "http://example.com/t",
					AuthStyle:     oauth2.AuthStyleInHeader,
				},
				RedirectURL: "http://example.com",
				Scopes:      []string{"1", "2"},
			},
			want: &oauth2.Config{
				ClientID:     "1",
				ClientSecret: "dsa",
				Endpoint: oauth2.Endpoint{
					AuthURL:       "http://example.com/a",
					DeviceAuthURL: "http://example.com/d",
					TokenURL:      "http://example.com/t",
					AuthStyle:     oauth2.AuthStyleInHeader,
				},
				RedirectURL: "http://example.com",
				Scopes:      []string{"1", "2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &C2S{Conf: tt.conf}
			if got := c.Config(); !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(oauth2.Config{})) {
				t.Errorf("Config() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(oauth2.Config{})))
			}
		})
	}

	var c *C2S
	if got := c.Config(); got != nil {
		t.Errorf("Config() on nil is not nil")
	}
}

func TestC2S_Token(t *testing.T) {
	tests := []struct {
		name string
		tok  *oauth2.Token
		want *oauth2.Token
	}{
		{
			name: "empty",
			tok:  nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &C2S{Tok: tt.tok}
			if got := c.Token(); !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(oauth2.Token{})) {
				t.Errorf("Token() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(oauth2.Token{})))
			}
		})
	}
	var c *C2S
	if got := c.Token(); got != nil {
		t.Errorf("Token() on nil is not nil")
	}
}

func TestC2S_ID(t *testing.T) {
	tests := []struct {
		name string
		IRI  activitypub.IRI
		want activitypub.IRI
	}{
		{
			name: "empty",
			IRI:  "",
			want: "",
		},
		{
			name: "not empty",
			IRI:  "http://example.com",
			want: "http://example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &C2S{IRI: tt.IRI}
			if got := c.ID(); got != tt.want {
				t.Errorf("ID() = %v, want %v", got, tt.want)
			}
		})
	}
	var c *C2S
	if got := c.ID(); got != activitypub.EmptyIRI {
		t.Errorf("ID() on nil is not an empty IRI")
	}
}

func TestC2S_Sign(t *testing.T) {
	type fields struct {
		Tok *oauth2.Token
	}
	tests := []struct {
		name    string
		fields  fields
		r       *http.Request
		wantErr error
	}{
		{
			name:    "empty",
			fields:  fields{},
			wantErr: nil,
		},
		{
			name: "not empty",
			fields: fields{
				Tok: &oauth2.Token{
					AccessToken: "test",
					TokenType:   "Bear",
				},
			},
			r:       &http.Request{Method: "TEST", Header: make(http.Header)},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &C2S{Tok: tt.fields.Tok}
			if err := c.Sign(tt.r); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Sign() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if tt.r != nil && tt.fields.Tok != nil {
				if c.Tok == nil {
					t.Fatalf("Sign() token should not be nil")
				}
				auth := tt.r.Header.Get("Authorization")
				wantAuth := c.Tok.Type() + " " + c.Tok.AccessToken
				if auth != wantAuth {
					t.Errorf("Sign() Authorization header mismatch %s, expected %s", auth, wantAuth)
				}
			}
		})
	}
}

func Test_dumbProgressBar(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		waitTime time.Duration
		want     string
	}{
		{
			name: "1s run time",
			want: "\rWaiting for 1s\r",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultAuthDuration := authWaitDuration
			authWaitDuration = time.Second
			t.Cleanup(func() {
				authWaitDuration = defaultAuthDuration
			})

			old := os.Stdout // keep backup of the real stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			buf := bytes.Buffer{}
			go func() {
				_, _ = io.Copy(&buf, r)
			}()

			t.Cleanup(func() {
				os.Stdout = old
				_ = w.Close()
				_ = r.Close()
			})

			dumbProgressBar(context.Background())

			output := buf.String()
			if output != tt.want {
				t.Errorf("dumbProgressBar(): output %s", cmp.Diff(tt.want, output))
			}
		})
	}
}

func TestC2S_Transport(t *testing.T) {
	type fields struct {
		IRI      activitypub.IRI
		Conf     oauth2.Config
		Tok      *oauth2.Token
		ProxyURL activitypub.IRI
	}
	tests := []struct {
		name   string
		fields fields
		ctx    context.Context
		want   http.RoundTripper
	}{
		{
			name:   "empty",
			fields: fields{},
			want:   &http.Transport{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &C2S{
				IRI:      tt.fields.IRI,
				Conf:     tt.fields.Conf,
				Tok:      tt.fields.Tok,
				ProxyURL: tt.fields.ProxyURL,
			}
			if got := c.Transport(tt.ctx); !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(http.Transport{})) {
				t.Errorf("Transport() = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(http.Transport{})))
			}
		})
	}
}
