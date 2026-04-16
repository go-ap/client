package credentials

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
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
			wantErr: errors.Newf("oauth2: token expired and refresh token is not set"),
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
		IRI  vocab.IRI
		want vocab.IRI
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
	if got := c.ID(); got != vocab.EmptyIRI {
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
		waitTime time.Duration
		want     string
	}{
		{
			name: "1s run time",
			want: "\rWaiting for 1s\r",
		},
		{
			name:     "10ms run time",
			waitTime: 10 * time.Millisecond,
			want:     "",
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

			ctx := context.Background()
			if tt.waitTime > 0 {
				var cancelFn func()
				ctx, cancelFn = context.WithTimeout(ctx, tt.waitTime)
				defer cancelFn()
			}
			dumbProgressBar(ctx)

			output := buf.String()
			if output != tt.want {
				t.Errorf("dumbProgressBar(): output %s", cmp.Diff(tt.want, output))
			}
		})
	}
}

func TestC2S_Transport(t *testing.T) {
	type fields struct {
		IRI      vocab.IRI
		Conf     oauth2.Config
		Tok      *oauth2.Token
		ProxyURL vocab.IRI
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

func Test_normalizeActorURL(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name     string
		actorURL vocab.IRI
		want     vocab.IRI
		wantErr  error
	}{
		{
			name:     "empty",
			actorURL: "",
			want:     "",
			wantErr:  errors.Newf("invalid actor URL: empty IRI"),
		},
		{
			name:     "no proto",
			actorURL: "example.com",
			want:     "https://example.com",
		},
		{
			name:     "w/ http proto",
			actorURL: "http://example.com/test",
			want:     "http://example.com/test",
		},
		{
			name:     "w/ https proto",
			actorURL: "https://example.com/~jdoe",
			want:     "https://example.com/~jdoe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeActorIRI(tt.actorURL)
			if !cmp.Equal(tt.wantErr, err, EquateWeakErrors) {
				t.Errorf("normalizeActorURL() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if got != tt.want {
				t.Errorf("normalizeActorURL() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getActorOAuthEndpoint(t *testing.T) {
	tests := []struct {
		name  string
		actor vocab.Actor
		want  oauth2.Endpoint
	}{
		{
			name:  "empty",
			actor: vocab.Actor{},
			want:  oauth2.Endpoint{},
		},
		{
			name:  "with ID",
			actor: vocab.Actor{ID: "http://example.com/~jdoe"},
			want: oauth2.Endpoint{
				AuthURL:  "http://example.com/~jdoe/oauth/authorize",
				TokenURL: "http://example.com/~jdoe/oauth/token",
			},
		},
		{
			name: "with Endpoints",
			actor: vocab.Actor{ID: "http://example.com/~jdoe", Endpoints: &vocab.Endpoints{
				OauthAuthorizationEndpoint: vocab.IRI("http://example.com/~jdoe/authorize"),
				OauthTokenEndpoint:         vocab.IRI("http://example.com/~jdoe/token"),
			}},
			want: oauth2.Endpoint{
				AuthURL:  "http://example.com/~jdoe/authorize",
				TokenURL: "http://example.com/~jdoe/token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getActorOAuthEndpoint(tt.actor); !cmp.Equal(got, tt.want) {
				t.Errorf("getActorOAuthEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_handleCallback(t *testing.T) {
	tests := []struct {
		name       string
		state      string
		params     string
		wantStatus int
		wantTok    string
		wantErr    error
	}{
		{
			name:       "empty",
			wantStatus: http.StatusUnauthorized,
			wantErr:    errors.Newf("token is missing"),
		},
		{
			name:       "w/ error, w/o description",
			params:     (url.Values{"error": []string{"test"}}).Encode(),
			wantStatus: http.StatusUnauthorized,
			wantErr:    errors.Newf("test"),
		},
		{
			name:       "w/ error, w/ description",
			params:     (url.Values{"error": []string{"test"}, "error_description": []string{"description"}}).Encode(),
			wantStatus: http.StatusUnauthorized,
			wantErr:    errors.Newf("test: description"),
		},
		{
			name:       "state mismatch",
			state:      "test",
			params:     (url.Values{"state": []string{"invalid"}}).Encode(),
			wantStatus: http.StatusUnauthorized,
			wantErr:    errors.Newf("state parameter mismatch"),
		},
		{
			name:       "good response",
			state:      "OK",
			params:     (url.Values{"state": []string{"OK"}, "code": []string{"g00d"}}).Encode(),
			wantStatus: http.StatusOK,
			wantTok:    "g00d",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callbackCh := make(chan callbackResponse, 1)
			handlerFn := handleCallback(callbackCh, tt.state)
			srv := httptest.NewServer(handlerFn)
			defer srv.Close()

			{
				// NOTE(marius): test favicon returns not found
				res, err := http.Get(srv.URL + "/favicon.ico")
				if err != nil {
					t.Errorf("handleCallback() GET /favicon.ico request returned unexpected error: %s", err)
				}
				if res.StatusCode != http.StatusNotFound {
					t.Errorf("handleCallback() GET /favicon.ico unexpected status: %d, wanted %d", res.StatusCode, tt.wantStatus)
				}
			}

			res, err := http.Get(srv.URL + "?" + tt.params)
			if err != nil {
				t.Errorf("handleCallback() GET request returned unexpected error: %s", err)
			}
			if res.StatusCode != tt.wantStatus {
				t.Errorf("handleCallback() GET unexpected status: %d, wanted %d", res.StatusCode, tt.wantStatus)
			}
			cbRes := <-callbackCh
			if !cmp.Equal(cbRes.err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("handleCallback() error = %s", cmp.Diff(tt.wantErr, cbRes.err, EquateWeakErrors))
			}
			if cbRes.tok != tt.wantTok {
				t.Errorf("handleCallback() tok = %v, want %v", cbRes.tok, tt.wantTok)
			}
		})
	}
}

func Test_handleOAuth2Flow(t *testing.T) {
	tests := []struct {
		name    string
		params  url.Values
		want    *oauth2.Token
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Annotatef(context.DeadlineExceeded, "unable to authorize, reached timeout"),
		},
		//{
		//	name:   "valid",
		//	params: url.Values{"state": []string{"OK"}, "code": []string{"g00d"}},
		//	want: &oauth2.Token{
		//		AccessToken:  "test",
		//		TokenType:    "Bearer",
		//		RefreshToken: "ref",
		//	},
		//},
	}
	// NOTE(marius): to avoid calling xdg-open in openbrowser()
	_ = os.Setenv(testingEnvVariable, "1")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Location", "http://"+LocalInterfaceAddress+":"+strconv.Itoa(RandPort)+"?"+tt.params.Encode())
				w.WriteHeader(http.StatusSeeOther)

				cancelFn()
			}))

			// ?client_id=&code_challenge=7_rCPj49TXNag-HvBC0VajFFg54CGkyD5C8OD-_m2cU&code_challenge_method=S256&response_type=code&state=IYQ4DMBFMAOPKK22XC7HXLDZP7
			conf := oauth2.Config{
				ClientID:     "test-client",
				ClientSecret: "no-s3cr3t",
				Endpoint: oauth2.Endpoint{
					AuthURL:  srv.URL + "/auth",
					TokenURL: srv.URL + "/tok",
				},
				RedirectURL: "http://" + LocalInterfaceAddress + ":" + strconv.Itoa(RandPort),
				Scopes:      []string{"s1", "s2"},
			}

			got, err := handleOAuth2Flow(ctx, &conf)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("handleOAuth2Flow() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, cmpopts.IgnoreUnexported(oauth2.Token{})) {
				t.Errorf("handleOAuth2Flow() got = %s", cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(oauth2.Token{})))
			}
			cancelFn()
		})
	}
}
