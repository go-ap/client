package credentials

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"git.sr.ht/~mariusor/cache"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"golang.org/x/oauth2"
)

const (
	successCallbackHTML = `<html><title>Success</title><body>You can now close this browser window/tab.</body></html>`
	errorCallbackHTML   = `<html><title>Error</title><body>%s</body></html>`

	listenOn     = "localhost:3000"
	authWaitTime = 90 * time.Second
)

type C2S struct {
	IRI  vocab.IRI
	Conf oauth2.Config
	Tok  *oauth2.Token
}

type ClientConfig struct {
	UserAgent    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func Authorize(ctx context.Context, actorURL string, auth ClientConfig) (*C2S, error) {
	actorIRI := vocab.IRI(actorURL)
	if u, _ := actorIRI.URL(); u == nil {
		actorIRI = vocab.IRI(fmt.Sprintf("https://%s", actorURL))
	}

	transport := client.UserAgentTransport(auth.UserAgent, cache.Private(http.DefaultTransport, cache.Mem(MByte)))
	// Set up the default HTTP client for the oauth2 module
	// which gets used by both Person and Application authorization flows.
	plainHTTPClient := &http.Client{Transport: transport}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, plainHTTPClient)

	app := new(C2S)
	httpC := OAuth2Client(ctx, app)
	initFns := []client.OptionFn{
		client.WithHTTPClient(httpC),
		client.SkipTLSValidation(true),
	}
	get := client.New(initFns...)

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
	if actor.Type == vocab.PersonType {
		if actor.Endpoints == nil {
			return nil, errors.Newf("unable to load OAuth2 endpoints for Actor")
		}
		if vocab.IsNil(actor.Endpoints.OauthAuthorizationEndpoint) {
			return nil, errors.Newf("unable to load OAuth2 authorization endpoint from Actor")
		}
		if vocab.IsNil(actor.Endpoints.OauthTokenEndpoint) {
			return nil, errors.Newf("unable to load OAuth2 token endpoint from Actor")
		}
	}

	app.IRI = actor.ID
	app.Conf = oauth2.Config{
		ClientID:     auth.ClientID,
		ClientSecret: auth.ClientSecret,
		Endpoint:     getActorOAuthEndpoint(*actor),
		RedirectURL:  fmt.Sprintf("http://%s", listenOn),
	}

	var tok *oauth2.Token
	switch actor.Type {
	case vocab.PersonType:
		tok, err = handleOAuth2Flow(ctx, &app.Conf)
		if err != nil {
			return nil, err
		}
		app.Tok, err = app.Conf.TokenSource(ctx, tok).Token()
		if err != nil {
			return nil, err
		}
	case vocab.ApplicationType, vocab.ServiceType, vocab.GroupType:
		app.Tok, err = app.Conf.PasswordCredentialsToken(ctx, actor.ID.String(), app.Conf.ClientSecret)
		if err != nil {
			return nil, err
		}
	}

	return app, nil
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
	return &c.Conf
}

func (c *C2S) Token() *oauth2.Token {
	tok := c.Tok
	return tok
}

func (c *C2S) ID() vocab.IRI {
	return c.IRI
}

func (c *C2S) Sign(r *http.Request) error {
	if c.Tok != nil {
		c.Tok.SetAuthHeader(r)
	}
	return nil
}

func getActorOAuthEndpoint(actor vocab.Actor) oauth2.Endpoint {
	e := oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/oauth/authorize", actor.ID),
		TokenURL: fmt.Sprintf("%s/oauth/token", actor.ID),
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
	if tok := c.Token(); tok != nil {
		return c.Config().Client(ctx, tok).Transport
	}
	return &http.Transport{}
}

func OAuth2Client(ctx context.Context, c *C2S) *http.Client {
	httpC := DefaultClient
	if oauthCl, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		httpC = oauthCl
	}
	if httpC == nil {
		httpC = &http.Client{}
	}

	// NOTE(marius): I'm not sure in which order we should wrap the OAuth2 and Cached transports
	// The initial feeling is that they serve different purposes:
	//  * the cache transport needs to be used on fetches
	//  * the OAuth2 transport needs to be used on writes
	if c != nil {
		if tok := c.Token(); tok != nil {
			httpC.Transport = c.Config().Client(ctx, tok).Transport
		}
	}

	return httpC
}

func openbrowser(url string) error {
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
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			break
		default:
			time.Sleep(time.Second)
			dur := time.Now().Sub(start.Add(time.Second))
			fmt.Printf("Waiting for %s", (authWaitTime - dur).Truncate(time.Second).String())
			fmt.Print("\r")
		}
	}
}

func handleOAuth2Flow(ctx context.Context, app *oauth2.Config) (*oauth2.Token, error) {
	state := ""

	authURL := app.AuthCodeURL(state)
	if err := openbrowser(authURL); err != nil {
		slog.With(slog.String("err", err.Error())).Warn("Unable to open browser window.")
		slog.With(slog.String("url", authURL)).Info("Please manually open the authorization URL in your browser.")
	} else {
		fmt.Printf("Opened browser window for authorization: %s.\n", authURL)
	}

	l, err := net.Listen("tcp", listenOn)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	type callbackResponse struct {
		tok string
		err error
	}

	callbackCh := make(chan callbackResponse)

	ctx, cancelFn := context.WithTimeout(ctx, authWaitTime)
	defer cancelFn()

	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		token := r.Form.Get("code")
		if token != "" {
			callbackCh <- callbackResponse{tok: token}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(successCallbackHTML))
			return
		}
		cbErr := fmt.Errorf("%s: %s", r.Form.Get("error"), r.Form.Get("error_description"))
		callbackCh <- callbackResponse{err: cbErr}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(fmt.Sprintf(errorCallbackHTML, cbErr)))
	})
	srv := &http.Server{Handler: fn}

	go srv.Serve(l)
	go dumbProgressBar(ctx)
	defer srv.Close()

	select {
	case <-ctx.Done():
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("unable to authorize, reached timeout: %w", err)
		}
		return nil, fmt.Errorf("context done")
	case resp := <-callbackCh:
		if err != nil {
			return nil, resp.err
		}
		tok, err := app.Exchange(ctx, resp.tok)
		if err != nil {
			return nil, err
		}
		return tok, nil
	}
}
