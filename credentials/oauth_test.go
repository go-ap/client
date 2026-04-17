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
	"github.com/go-ap/client/proxy"
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
			wantErr:  errors.Newf("empty IRI"),
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

func Test_waitForOAuth2Callback(t *testing.T) {
	tests := []struct {
		name         string
		state        string
		codeVerifier string
		params       url.Values
		handlerFn    http.HandlerFunc
		want         *oauth2.Token
		wantErr      error
	}{
		{
			name: "empty",
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantErr: errors.Annotatef(context.DeadlineExceeded, "unable to authorize, reached timeout"),
		},
		{
			name:         "valid",
			state:        "OK",
			codeVerifier: "test-verif",
			params:       url.Values{"state": []string{"OK"}, "code": []string{"g00d"}},
			want: &oauth2.Token{
				AccessToken:  "test",
				TokenType:    "Bearer",
				RefreshToken: "ref",
			},
		},
	}

	// NOTE(marius): to avoid calling xdg-open in openbrowser()
	_ = os.Setenv(testingEnvVariable, "1")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
			defer cancelFn()

			conf := oauth2.Config{
				ClientID:     "test-client",
				ClientSecret: "no-s3cr3t",
				RedirectURL:  "http://" + LocalInterfaceAddress + ":" + strconv.Itoa(RandPort),
				Scopes:       []string{"s1", "s2"},
			}
			if tt.handlerFn == nil {
				tt.handlerFn = func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/tok" {
						_ = r.ParseForm()
						vals := r.Form
						// code=g00d&code_verifier=test-verif&grant_type=authorization_code&redirect_uri=http://127.0.0.1:1434
						if code := vals.Get("code"); code != tt.params.Get("code") {
							t.Errorf("OAuth2 token code %s, expected %s", code, tt.params.Get("code"))
						}
						if verif := vals.Get("code_verifier"); verif != tt.codeVerifier {
							t.Errorf("OAuth2 token code_verifier %s, expected %s", verif, tt.codeVerifier)
						}
						if grant := vals.Get("grant_type"); grant != "authorization_code" {
							t.Errorf("OAuth2 token code_verifier %s, expected %s", grant, "authorization_code")
						}
						redirectURI := vals.Get("redirect_uri")
						if redirectURI == "" {
							t.Errorf("OAuth2 token redirect_uri")
						}
						result := url.Values{
							"access_token":  []string{tt.want.AccessToken},
							"token_type":    []string{tt.want.TokenType},
							"refresh_token": []string{tt.want.RefreshToken},
						}
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(result.Encode()))
					} else if r.URL.Path == "/auth" {
						vals := r.URL.Query()
						if clientID := vals.Get("client_id"); clientID != conf.ClientID {
							t.Errorf("OAuth2 authorization URL client_id %s, expected %s", clientID, conf.ClientID)
						}
						if vals.Get("code_challenge") == "" {
							t.Errorf("OAuth2 authorization URL is missing code_challenge")
						}
						if codeMethod := vals.Get("code_challenge_method"); codeMethod != "S256" {
							t.Errorf("OAuth2 authorization URL code_challenge_method %s, expected %s", codeMethod, "S256")
						}
						if respType := vals.Get("response_type"); respType != "code" {
							t.Errorf("OAuth2 authorization URL response_type %s, expected %s", respType, "code")
						}
						state := vals.Get("state")
						if state != tt.params.Get("state") {
							t.Errorf("OAuth2 authorization URL state %s, expected %s", state, tt.params.Get("state"))
						}
						redirectURI := vals.Get("redirect_uri")
						if redirectURI == "" {
							t.Errorf("OAuth2 authorization URL is missing redirect_uri")
						}
						if len(tt.params) > 0 {
							redirectURI = redirectURI + "?" + tt.params.Encode()
						}
						w.Header().Add("Location", redirectURI)
						w.WriteHeader(http.StatusSeeOther)
					}
				}
			}

			srv := httptest.NewServer(tt.handlerFn)

			conf.Endpoint = oauth2.Endpoint{
				AuthURL:  srv.URL + "/auth",
				TokenURL: srv.URL + "/tok",
			}

			opts := make([]oauth2.AuthCodeOption, 0)
			if tt.codeVerifier != "" {
				opts = append(opts, oauth2.S256ChallengeOption(tt.codeVerifier))
			}

			go func() {
				_, _ = http.Get(conf.AuthCodeURL(tt.state, opts...))
			}()

			got, err := waitForOAuth2Callback(ctx, &conf, tt.state, tt.codeVerifier)
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

func TestOAuth2Client1(t *testing.T) {
	mockConfig := oauth2.Config{}
	mockToken := oauth2.Token{
		AccessToken:  "ggg",
		TokenType:    "Bear",
		RefreshToken: "rrr",
	}
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
			name: "from context",
			args: args{
				ctx: context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: 666 * time.Millisecond}),
				c:   nil,
			},
			want: &http.Client{Timeout: 666 * time.Millisecond},
		},
		{
			name: "direct oauth2",
			args: args{
				ctx: context.Background(),
				c: &C2S{
					IRI:  "http://example.com",
					Conf: mockConfig,
					Tok:  &mockToken,
				},
			},
			want: &http.Client{
				Transport: &oauth2.Transport{
					Source: mockConfig.TokenSource(context.Background(), &mockToken),
				},
			},
		},
		{
			name: "with proxy url",
			args: args{
				ctx: context.Background(),
				c: &C2S{
					IRI:      "http://example.com",
					Conf:     mockConfig,
					Tok:      &mockToken,
					ProxyURL: "http://example.com/proxy",
				},
			},
			want: &http.Client{
				Transport: &proxy.Transport{
					Base: &oauth2.Transport{
						Source: mockConfig.TokenSource(context.Background(), &mockToken),
					},
					ProxyURL: "http://example.com/proxy",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OAuth2Client(tt.args.ctx, tt.args.c); !cmp.Equal(got, tt.want, ignoreTokenSource) {
				t.Errorf("OAuth2Client() = %s", cmp.Diff(tt.want, got, ignoreTokenSource))
			}
		})
	}
}

func TestC2S_Transport1(t *testing.T) {
	mockConfig := oauth2.Config{}
	mockToken := oauth2.Token{
		AccessToken:  "ggg",
		TokenType:    "bear",
		RefreshToken: "rrr",
	}
	type fields struct {
		IRI      vocab.IRI
		Conf     oauth2.Config
		Tok      *oauth2.Token
		ProxyURL vocab.IRI
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   http.RoundTripper
	}{
		{
			name:   "empty",
			fields: fields{},
			args:   args{},
			want:   &http.Transport{},
		},
		{
			name: "empty",
			fields: fields{
				Tok: &mockToken,
			},
			args: args{},
			want: mockConfig.Client(context.Background(), &mockToken).Transport,
		},
		{
			name: "with proxy url",
			fields: fields{
				IRI:      "http://example.com",
				Conf:     mockConfig,
				Tok:      &mockToken,
				ProxyURL: "http://example.com/proxy",
			},
			args: args{
				ctx: context.Background(),
			},
			want: &proxy.Transport{
				Base: &oauth2.Transport{
					Source: mockConfig.TokenSource(context.Background(), &mockToken),
				},
				ProxyURL: "http://example.com/proxy",
			},
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
			if got := c.Transport(tt.args.ctx); !cmp.Equal(got, tt.want, ignoreTokenSource, ignoredTransports) {
				t.Errorf("Transport() = %s", cmp.Diff(tt.want, got, ignoreTokenSource, ignoredTransports))
			}
		})
	}
}

var ignoreOAuth2Config = cmpopts.IgnoreUnexported(oauth2.Config{})
var ignoreTokenSource = cmpopts.IgnoreInterfaces(struct{ oauth2.TokenSource }{})
var ignoredTransports = cmpopts.IgnoreUnexported(http.Transport{})

func TestAuthorize(t *testing.T) {
	mockActor := vocab.Actor{
		ID:   "http://example.com/~jdoe",
		Type: vocab.PersonType,
		PublicKey: vocab.PublicKey{
			ID:    "http://example.com/~jdoe#main",
			Owner: "http://example.com/~jdoe",
		},
		PreferredUsername: vocab.DefaultNaturalLanguage("jdoe"),
	}
	type args struct {
		ctx      context.Context
		actorURL string
		auth     ClientConfig
	}
	tests := []struct {
		name      string
		args      args
		handlerFn http.HandlerFunc
		want      *C2S
		wantErr   error
	}{
		{
			name:    "empty",
			args:    args{},
			want:    nil,
			wantErr: errors.Annotatef(errors.Newf("empty IRI"), "invalid actor URL"),
		},
		{
			name: "nil body",
			args: args{
				ctx:      context.Background(),
				actorURL: "http://example.com/~jdoe",
				auth:     ClientConfig{},
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantErr: errors.Annotatef(
				errors.Annotatef(errors.NotImplementedf("not a document and not an error"), "invalid response from ActivityPub server"),
				"unable to load actor",
			),
		},
		{
			name: "no OAuth2 endpoints",
			args: args{
				ctx:      context.Background(),
				actorURL: "http://example.com/~jdoe",
				auth:     ClientConfig{},
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				raw, _ := vocab.MarshalJSON(mockActor)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			},
			wantErr: errors.Newf("the Actor has no OAuth2 endpoints exposed"),
		},
		{
			name: "no ID",
			args: args{
				ctx:      context.Background(),
				actorURL: "http://example.com/~jdoe",
				auth:     ClientConfig{},
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				act := mockActor
				act.ID = vocab.EmptyIRI
				raw, _ := vocab.MarshalJSON(act)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			},
			wantErr: errors.Newf("unable to load OAuth2 client application actor"),
		},
		{
			name: "OAuth2 with endpoints",
			args: args{
				ctx:      context.Background(),
				actorURL: "http://example.com/~jdoe",
				auth:     ClientConfig{},
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				act := mockActor
				act.Endpoints = &vocab.Endpoints{
					OauthAuthorizationEndpoint: act.ID.AddPath("auth"),
					OauthTokenEndpoint:         act.ID.AddPath("tok"),
				}
				raw, _ := vocab.MarshalJSON(act)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			},
			want: &C2S{
				IRI: "http://example.com/~jdoe",
				Conf: oauth2.Config{
					Endpoint: oauth2.Endpoint{
						AuthURL:  "http://example.com/~jdoe/auth",
						TokenURL: "http://example.com/~jdoe/tok",
					},
					RedirectURL: "http://" + LocalInterfaceAddress + ":" + strconv.Itoa(RandPort),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handlerFn)
			if tt.args.actorURL != "" {
				u, err := url.Parse(tt.args.actorURL)
				if err == nil {
					su, _ := url.Parse(srv.URL)
					u.Host = su.Host
					tt.args.actorURL = u.String()
				}
			}

			got, err := Authorize(tt.args.ctx, tt.args.actorURL, tt.args.auth)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Authorize() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, ignoreTokenSource, ignoreOAuth2Config) {
				t.Errorf("Authorize() got = %s", cmp.Diff(tt.want, got, ignoreTokenSource, ignoreOAuth2Config))
			}
		})
	}
}
