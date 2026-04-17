package credentials

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"git.sr.ht/~mariusor/cache"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/client/proxy"
	"github.com/go-ap/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	successCallbackHTML = `<html><title>Success</title><body>You can now close this browser window/tab.</body></html>`
	errorCallbackHTML   = `<html><title>Error</title><body>%s</body></html>`

	minPort               = 1024
	LocalInterfaceAddress = "127.0.0.1"
)

var authWaitDuration = 90 * time.Second

var RandPort = minPort + mrand.IntN(65536-minPort)

type C2S struct {
	IRI      vocab.IRI
	Conf     oauth2.Config
	Tok      *oauth2.Token
	ProxyURL vocab.IRI
}

type ClientConfig struct {
	UserAgent    string
	Interactive  bool
	ClientID     string
	ClientSecret string
	RedirectURL  string
	IssuedAt     time.Time
	Expiration   time.Duration
}

func normalizeActorIRI(i vocab.IRI) (vocab.IRI, error) {
	actorIRI := i
	if len(i) > 4 && !strings.HasPrefix(string(actorIRI), "http") {
		actorIRI = "https://" + actorIRI
	}
	ur, err := actorIRI.URL()
	if err != nil {
		return i, errors.Newf("invalid actor URL: %s", err)
	}
	if ur.Host == "" {
		actorIRI = i
		err = errors.Newf("invalid actor URL")
	}
	return actorIRI, err
}

func Authorize(ctx context.Context, actorURL string, auth ClientConfig) (*C2S, error) {
	actorIRI, err := normalizeActorIRI(vocab.IRI(actorURL))
	if err != nil {
		return nil, errors.Newf("invalid actor URL: %s", err)
	}
	if ctx.Value(oauth2.HTTPClient) == nil {
		transport := client.UserAgentTransport(auth.UserAgent, cache.Private(http.DefaultTransport, cache.Mem(MByte)))
		// Set up the default HTTP client for the oauth2 module
		// which gets used by both Person and Application authorization flows.
		plainHTTPClient := http.DefaultClient
		plainHTTPClient.Transport = transport
		ctx = context.WithValue(ctx, oauth2.HTTPClient, plainHTTPClient)
	}

	app := new(C2S)
	httpC := OAuth2Client(ctx, app)
	get := client.New(client.WithHTTPClient(httpC), client.SkipTLSValidation(InsecureTLSConnection))

	actor, err := get.Actor(ctx, actorIRI)
	if err != nil {
		return nil, err
	}
	if vocab.IsNil(actor) || actor.ID == "" {
		return nil, errors.Newf("unable to load OAuth2 client application actor")
	}
	if actor.ID == "" {
		return nil, errors.Newf("invalid Actor with empty ID")
	}
	if vocab.PersonType.Match(actor.Type) {
		if actor.Endpoints == nil {
			return nil, errors.Newf("the Actor has no OAuth2 endpoints exposed")
		}
		if vocab.IsNil(actor.Endpoints.OauthAuthorizationEndpoint) {
			return nil, errors.Newf("the Actor has no OAuth2 authorization endpoint")
		}
		if vocab.IsNil(actor.Endpoints.OauthTokenEndpoint) {
			return nil, errors.Newf("the Actor has no OAuth2 token endpoint")
		}
	}

	app.IRI = actor.ID
	app.Conf = oauth2.Config{
		ClientID:     auth.ClientID,
		ClientSecret: auth.ClientSecret,
		Endpoint:     getActorOAuthEndpoint(*actor),
		RedirectURL:  "http://" + LocalInterfaceAddress + ":" + strconv.Itoa(RandPort),
	}
	if auth.RedirectURL != "" {
		app.Conf.RedirectURL = auth.RedirectURL
	}
	if actor.Endpoints != nil {
		app.ProxyURL = actor.Endpoints.ProxyURL
	}

	nonUserTypes := vocab.ActivityVocabularyTypes{vocab.ApplicationType, vocab.ServiceType, vocab.GroupType}
	if nonUserTypes.Match(actor.Type) && auth.ClientSecret != "" {
		conf := clientcredentials.Config{
			ClientID:     app.Conf.ClientID,
			ClientSecret: app.Conf.ClientSecret,
			TokenURL:     app.Conf.Endpoint.TokenURL,
		}
		// NOTE(marius): if we received a OAuth2 client secret and the authorization actor is not a Person,
		// we try a ClientCredentials flow first.
		app.Tok, err = conf.Token(ctx)
	}

	// NOTE(marius): if we support an interactive session, we try to authenticate through the browser.
	if app.Tok == nil && auth.Interactive {
		// NOTE(marius): For all Person actors, or a failed password credentials flow, we try  an authorization flow.
		state := rand.Text()

		codeVerifier := CodeVerifier()
		authURL := app.Config().AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))
		if err := openbrowser(authURL); err != nil {
			slog.With(slog.String("err", err.Error())).Warn("Unable to open browser window.")
			slog.With(slog.String("url", authURL)).Info("Please manually open the authorization URL in your browser.")
		} else {
			fmt.Printf("Opened browser window for authorization: %s.\n", authURL)
		}
		tok, err := waitForOAuth2Callback(ctx, &app.Conf, state, codeVerifier)
		if err != nil {
			return nil, err
		}
		app.Tok, err = app.Conf.TokenSource(ctx, tok).Token()
	}

	return app, err
}

type RequestAuthorizer interface {
	SetAuthHeader(*http.Request)
}

func (c *C2S) Refresh(ctx context.Context) error {
	tok := c.Tok

	var err error

	oauth := c.Conf.Client(ctx, tok)
	tr, ok := oauth.Transport.(*oauth2.Transport)
	if !ok {
		return fmt.Errorf("invalid http transport")
	}

	c.Tok, err = tr.Source.Token()
	if err != nil {
		return err
	}

	return nil
}

func (c *C2S) Config() *oauth2.Config {
	if c == nil {
		return nil
	}
	return &c.Conf
}

func (c *C2S) Token() *oauth2.Token {
	if c == nil {
		return nil
	}
	tok := c.Tok
	return tok
}

func (c *C2S) ID() vocab.IRI {
	if c == nil {
		return vocab.EmptyIRI
	}
	return c.IRI
}

func (c *C2S) Sign(r *http.Request) error {
	if c != nil && c.Tok != nil {
		c.Tok.SetAuthHeader(r)
	}
	return nil
}

func getActorOAuthEndpoint(actor vocab.Actor) oauth2.Endpoint {
	var e oauth2.Endpoint
	if actor.ID != "" {
		e = oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", actor.ID),
			TokenURL: fmt.Sprintf("%s/oauth/token", actor.ID),
		}
	}
	if actor.Endpoints != nil {
		if !vocab.IsNil(actor.Endpoints.OauthAuthorizationEndpoint) {
			e.AuthURL = actor.Endpoints.OauthAuthorizationEndpoint.GetLink().String()
		}
		if !vocab.IsNil(actor.Endpoints.OauthTokenEndpoint) {
			e.TokenURL = actor.Endpoints.OauthTokenEndpoint.GetLink().String()
		}
	}
	return e
}

const (
	KByte = 1024
	MByte = 1024 * KByte
)

var DefaultClient = &http.Client{}

func (c *C2S) Transport(ctx context.Context) http.RoundTripper {
	var transport http.RoundTripper = &http.Transport{}
	if tok := c.Token(); tok != nil {
		transport = c.Config().Client(ctx, tok).Transport
	}
	if !vocab.EmptyIRI.Equal(c.ProxyURL) {
		transport = proxy.New(proxy.WithTransport(transport), proxy.WithProxyURL(c.ProxyURL))
	}
	return transport
}

func OAuth2Client(ctx context.Context, c *C2S) *http.Client {
	httpC := DefaultClient
	if ctx != nil {
		if oauthCl, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
			httpC = oauthCl
		}
	}
	if httpC == nil {
		httpC = &http.Client{}
	}

	// NOTE(marius): I'm not sure in which order we should wrap the OAuth2 and Cached transports
	// The initial feeling is that they serve different purposes:
	//  * the cache transport needs to be used on fetches
	//  * the OAuth2 transport needs to be used on writes
	if c != nil {
		httpC.Transport = c.Transport(ctx)
	}

	return httpC
}

const testingEnvVariable = "_ISTEST"

func openbrowser(url string) error {
	if os.Getenv(testingEnvVariable) != "" {
		return nil
	}
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}

func dumbProgressBar(ctx context.Context) {
	start := time.Now().Truncate(time.Second)
	ticker := time.NewTicker(time.Second)
	wd := authWaitDuration + time.Second
	wait := time.NewTimer(wd)
	for {
		select {
		case <-ctx.Done():
			return
		case <-wait.C:
			return
		case cur := <-ticker.C:
			fmt.Printf("\rWaiting for %s\r", (wd - cur.Truncate(time.Second).Sub(start)).Truncate(time.Second).String())
		}
	}
}

const pkceAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ234567-._~"

var pkceAlphabetLen = byte(len(pkceAlphabet))

func CodeVerifier() string {
	src := make([]byte, 43)
	_, _ = rand.Read(src)
	for i := range src {
		src[i] = pkceAlphabet[src[i]%pkceAlphabetLen]
	}
	return string(src)
}

type callbackResponse struct {
	tok string
	err error
}

func handleCallback(callbackCh chan callbackResponse, state string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		if token := r.Form.Get("code"); token != "" {
			callbackCh <- callbackResponse{tok: token}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(successCallbackHTML))
			return
		}

		var cbErr error
		if r.Form.Get("error") != "" {
			var desc string
			if ed := r.Form.Get("error_description"); len(ed) > 0 {
				desc = ": " + ed
			}
			cbErr = fmt.Errorf("%s%s", r.Form.Get("error"), desc)
		} else if r.Form.Get("state") != state {
			cbErr = fmt.Errorf("state parameter mismatch")
		} else {
			cbErr = fmt.Errorf("token is missing")
		}
		callbackCh <- callbackResponse{err: cbErr}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(fmt.Sprintf(errorCallbackHTML, cbErr)))
	}
}

func waitForOAuth2Callback(ctx context.Context, app *oauth2.Config, state, codeVerifier string) (*oauth2.Token, error) {
	// NOTE(marius) The clients are using the 127.0.0.1 IP verbatim which allows for wildcard port number when the
	// authorization server validates the return URL.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8252#section-7.3
	l, err := net.Listen("tcp", LocalInterfaceAddress+":"+strconv.Itoa(RandPort))
	if err != nil {
		return nil, err
	}
	defer l.Close()

	callbackCh := make(chan callbackResponse)

	ctx, cancelFn := context.WithTimeout(ctx, authWaitDuration)
	defer cancelFn()

	srv := &http.Server{Handler: handleCallback(callbackCh, state)}

	go srv.Serve(l)
	go dumbProgressBar(ctx)
	defer srv.Close()

	select {
	case <-ctx.Done():
		if err = ctx.Err(); err != nil {
			return nil, errors.Annotatef(err, "unable to authorize, reached timeout")
		}
		return nil, errors.Newf("context done")
	case resp := <-callbackCh:
		if resp.err != nil {
			return nil, resp.err
		}
		return app.Exchange(ctx, resp.tok, oauth2.VerifierOption(codeVerifier))
	}
}
