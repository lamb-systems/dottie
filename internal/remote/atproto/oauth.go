package atproto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
)

var ErrSessionUnavailable = errors.New("stored session is unusable; sign in again")

type SessionStore interface {
	Save(context.Context, string, []byte) error
	Load(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

type TXTLookup func(context.Context, string) ([]string, error)

type Client struct {
	ClientID         string
	HTTPClient       *http.Client
	Clock            func() time.Time
	Random           io.Reader
	Store            SessionStore
	lookupTXT        TXTLookup
	callbackAttempts int
	nonceMu          sync.Mutex
	nonces           map[string]string
}

type ClientOption func(*Client)

func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) { c.HTTPClient = client }
}

func WithClock(clock func() time.Time) ClientOption {
	return func(c *Client) { c.Clock = clock }
}

func WithRandom(random io.Reader) ClientOption {
	return func(c *Client) { c.Random = random }
}

func WithTXTLookup(lookup TXTLookup) ClientOption {
	return func(c *Client) { c.lookupTXT = lookup }
}

func WithCallbackAttemptLimit(limit int) ClientOption {
	return func(c *Client) { c.callbackAttempts = limit }
}

func NewClient(clientID string, store SessionStore, options ...ClientOption) (*Client, error) {
	if _, err := validateHTTPSURL(clientID); err != nil {
		return nil, errors.New("client id must be an absolute HTTPS URL")
	}
	client := &Client{
		ClientID:         clientID,
		HTTPClient:       &http.Client{Timeout: 15 * time.Second},
		Clock:            time.Now,
		Random:           rand.Reader,
		Store:            store,
		callbackAttempts: 8,
		nonces:           make(map[string]string),
	}
	for _, option := range options {
		option(client)
	}
	if client.Clock == nil || client.Random == nil || client.callbackAttempts < 1 {
		return nil, errors.New("invalid OAuth client options")
	}
	client.HTTPClient = noRedirectClient(client.HTTPClient)
	return client, nil
}

func noRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	} else {
		copy := *client
		client = &copy
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		return noRedirectClient(nil)
	}
	return noRedirectClient(c.HTTPClient)
}

type Flow struct {
	client           *Client
	identity         Identity
	requested        []string
	required         []string
	verifier         Secret
	state            string
	key              *ecdsa.PrivateKey
	listener         net.Listener
	server           *http.Server
	redirectURI      string
	authorizationURL string
	callback         chan callbackResult
	attemptsMu       sync.Mutex
	attempts         int
	callbackAccepted bool
	closeOnce        sync.Once
	waitOnce         sync.Once
}

type callbackResult struct {
	code Secret
	err  error
}

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	Sub          string `json:"sub"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (c *Client) Begin(ctx context.Context, handle string, requestedScopes, requiredScopes []string) (*Flow, error) {
	requested, err := canonicalScopes(requestedScopes)
	if err != nil {
		return nil, err
	}
	required, err := canonicalScopes(requiredScopes)
	if err != nil {
		return nil, err
	}
	if err := ValidateScopes(requested, required, requested); err != nil {
		return nil, err
	}
	identity, err := c.Discover(ctx, handle)
	if err != nil {
		return nil, err
	}
	verifierBytes := make([]byte, 32)
	stateBytes := make([]byte, 32)
	if _, err := io.ReadFull(c.Random, verifierBytes); err != nil {
		return nil, errors.New("cannot generate PKCE verifier")
	}
	if _, err := io.ReadFull(c.Random, stateBytes); err != nil {
		return nil, errors.New("cannot generate OAuth state")
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	key, err := ecdsa.GenerateKey(elliptic.P256(), c.Random)
	if err != nil {
		return nil, errors.New("cannot generate DPoP key")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("cannot open loopback OAuth listener")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := "http://127.0.0.1:" + strconv.Itoa(port) + "/callback"
	flow := &Flow{
		client:      c,
		identity:    identity,
		requested:   requested,
		required:    required,
		verifier:    NewSecret(verifier),
		state:       state,
		key:         key,
		listener:    listener,
		redirectURI: redirectURI,
		callback:    make(chan callbackResult, 1),
	}
	flow.server = &http.Server{Handler: http.HandlerFunc(flow.serveCallback), ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = flow.server.Serve(listener) }()
	challengeDigest := sha256.Sum256([]byte(verifier))
	form := url.Values{
		"client_id":             {c.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challengeDigest[:])},
		"code_challenge_method": {"S256"},
	}
	var response parResponse
	if err := c.postFormDPoP(ctx, identity.PARSEndpoint, form, key, &response); err != nil {
		flow.Close()
		return nil, err
	}
	if response.RequestURI == "" {
		flow.Close()
		return nil, errors.New("PAR response did not contain a request URI")
	}
	authorizationURL, err := url.Parse(identity.AuthorizationEndpoint)
	if err != nil {
		flow.Close()
		return nil, errors.New("invalid authorization endpoint")
	}
	query := authorizationURL.Query()
	query.Set("client_id", c.ClientID)
	query.Set("request_uri", response.RequestURI)
	authorizationURL.RawQuery = query.Encode()
	flow.authorizationURL = authorizationURL.String()
	return flow, nil
}

func canonicalScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, errors.New("at least one atproto scope is required")
	}
	for _, scope := range scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return nil, errors.New("scope entries must contain exactly one scope token")
		}
	}
	return ParseScopes(strings.Join(scopes, " "))
}

func (f *Flow) AuthorizationURL() string {
	if f == nil {
		return ""
	}
	return f.authorizationURL
}

func (f *Flow) RedirectURI() string {
	if f == nil {
		return ""
	}
	return f.redirectURI
}

func (f *Flow) CodeVerifier() Secret {
	if f == nil {
		return Secret{}
	}
	return f.verifier
}

func (f *Flow) serveCallback(writer http.ResponseWriter, request *http.Request) {
	f.attemptsMu.Lock()
	f.attempts++
	attempts := f.attempts
	f.attemptsMu.Unlock()
	if attempts > f.client.callbackAttempts {
		http.Error(writer, "too many callback attempts", http.StatusTooManyRequests)
		f.callback <- callbackResult{err: errors.New("callback attempt limit exceeded")}
		f.Close()
		return
	}
	if request.Method != http.MethodGet || request.URL.Path != "/callback" {
		http.Error(writer, "invalid callback request", http.StatusNotFound)
		return
	}
	query := request.URL.Query()
	states := query["state"]
	if len(states) != 1 || !constantStateEqual(query.Get("state"), f.state) {
		http.Error(writer, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	f.attemptsMu.Lock()
	if f.callbackAccepted {
		f.attemptsMu.Unlock()
		http.Error(writer, "callback already accepted", http.StatusBadRequest)
		return
	}
	f.callbackAccepted = true
	f.attemptsMu.Unlock()
	f.closeListener()
	if len(query["error"]) > 1 || query.Get("error") != "" {
		writer.WriteHeader(http.StatusBadRequest)
		f.callback <- callbackResult{err: errors.New("authorization was denied")}
		return
	}
	issuers := query["iss"]
	if len(issuers) != 1 || issuers[0] != f.identity.Issuer {
		writer.WriteHeader(http.StatusBadRequest)
		f.callback <- callbackResult{err: errors.New("authorization response issuer does not match discovery")}
		return
	}
	codes := query["code"]
	if len(codes) != 1 || codes[0] == "" {
		writer.WriteHeader(http.StatusBadRequest)
		f.callback <- callbackResult{err: errors.New("authorization response is missing a code")}
		return
	}
	code := codes[0]
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, "Authorization received. You may close this window.")
	f.callback <- callbackResult{code: NewSecret(code)}
}

func constantStateEqual(left, right string) bool {
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}

func (f *Flow) closeListener() {
	if f == nil || f.listener == nil {
		return
	}
	f.closeOnce.Do(func() { _ = f.listener.Close() })
}

func (f *Flow) Close() {
	if f == nil {
		return
	}
	f.closeListener()
	if f.server != nil {
		_ = f.server.Close()
	}
}

func (f *Flow) Wait(ctx context.Context) (*Session, error) {
	if f == nil {
		return nil, errors.New("OAuth flow is nil")
	}
	used := false
	f.waitOnce.Do(func() { used = true })
	if !used {
		return nil, errors.New("OAuth flow has already been consumed")
	}
	defer f.Close()
	select {
	case <-ctx.Done():
		return nil, errors.New("OAuth callback timed out")
	case callback := <-f.callback:
		if callback.err != nil {
			return nil, callback.err
		}
		return f.exchangeCode(ctx, callback.code)
	}
}

func (f *Flow) exchangeCode(ctx context.Context, code Secret) (*Session, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientID},
		"code":          {code.Reveal()},
		"redirect_uri":  {f.redirectURI},
		"code_verifier": {f.verifier.Reveal()},
	}
	var result tokenResponse
	if err := f.client.postFormDPoP(ctx, f.identity.TokenEndpoint, form, f.key, &result); err != nil {
		return nil, err
	}
	return f.client.finishToken(ctx, f.identity, f.requested, f.required, f.key, result, "")
}

func (c *Client) postFormDPoP(ctx context.Context, endpoint string, form url.Values, key *ecdsa.PrivateKey, output any) error {
	body := form.Encode()
	response, err := c.doDPoP(ctx, http.MethodPost, endpoint, strings.NewReader(body), int64(len(body)), "application/x-www-form-urlencoded", nil, key, Secret{})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		cleaned := strings.Join(strings.Fields(string(detail)), " ")
		if cleaned == "" {
			return fmt.Errorf("OAuth endpoint returned HTTP %d with an empty body", response.StatusCode)
		}
		return fmt.Errorf("OAuth endpoint returned HTTP %d: %s", response.StatusCode, cleaned)
	}
	const maximum = 1 << 20
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(encoded) > maximum {
		return errors.New("OAuth response is unreadable or oversized")
	}
	if err := json.Unmarshal(encoded, output); err != nil {
		return errors.New("OAuth response is invalid JSON")
	}
	return nil
}

func (c *Client) doDPoP(ctx context.Context, method, endpoint string, body io.Reader, bodySize int64, contentType string, headers http.Header, key *ecdsa.PrivateKey, accessToken Secret) (*http.Response, error) {
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil || parsedEndpoint.Scheme != "https" || parsedEndpoint.Host == "" || parsedEndpoint.User != nil || parsedEndpoint.Fragment != "" {
		return nil, errors.New("credential-bearing endpoint must use HTTPS")
	}
	validated := parsedEndpoint.String()
	bodyBytes, err := io.ReadAll(io.LimitReader(body, bodySize+1))
	if err != nil || int64(len(bodyBytes)) != bodySize {
		return nil, errors.New("cannot prepare OAuth request")
	}
	origin := urlOrigin(validated)
	for attempt := 0; attempt < 2; attempt++ {
		nonce := c.getNonce(origin)
		proof, err := makeDPoPProof(key, method, validated, c.Clock(), c.Random, accessToken, nonce)
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, method, validated, strings.NewReader(string(bodyBytes)))
		if err != nil {
			return nil, errors.New("cannot construct OAuth request")
		}
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		request.Header.Set("DPoP", proof)
		if accessToken.Reveal() != "" {
			request.Header.Set("Authorization", "DPoP "+accessToken.Reveal())
		}
		response, err := c.httpClient().Do(request)
		if err != nil {
			return nil, errors.New("OAuth request failed")
		}
		if nonce := response.Header.Get("DPoP-Nonce"); nonce != "" {
			c.setNonce(origin, nonce)
		}
		if response.StatusCode != http.StatusBadRequest {
			return response, nil
		}
		detail, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		response.Body = io.NopCloser(bytes.NewReader(detail))
		if readErr != nil {
			return response, nil
		}
		signal := strings.ToLower(response.Header.Get("WWW-Authenticate") + " " + string(detail))
		challenge := strings.Contains(signal, "use_dpop_nonce") && response.Header.Get("DPoP-Nonce") != ""
		if challenge && attempt == 0 {
			continue
		}
		return response, nil
	}
	return nil, errors.New("OAuth nonce retry failed")
}

func (c *Client) getNonce(origin string) string {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	return c.nonces[origin]
}

func (c *Client) setNonce(origin, nonce string) {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	c.nonces[origin] = nonce
}

func urlOrigin(endpoint string) string {
	parsed, _ := url.Parse(endpoint)
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

func (c *Client) finishToken(ctx context.Context, identity Identity, requested, required []string, key *ecdsa.PrivateKey, result tokenResponse, existingRefresh string) (*Session, error) {
	if result.Sub != identity.DID {
		return nil, errors.New("token subject does not match the discovered DID")
	}
	if result.AccessToken == "" || !strings.EqualFold(result.TokenType, "DPoP") {
		return nil, errors.New("token response is missing a DPoP-bound access token")
	}
	granted := requested
	if result.Scope != "" {
		var err error
		granted, err = ParseScopes(result.Scope)
		if err != nil {
			return nil, err
		}
	}
	if err := ValidateScopes(requested, required, granted); err != nil {
		return nil, err
	}
	refreshToken := result.RefreshToken
	if refreshToken == "" {
		refreshToken = existingRefresh
	}
	if refreshToken == "" {
		return nil, errors.New("token response is missing a refresh token")
	}
	privateKey, err := marshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	session := &Session{
		DID:            identity.DID,
		Issuer:         identity.Issuer,
		TokenEndpoint:  identity.TokenEndpoint,
		Scopes:         append([]string(nil), granted...),
		AccessToken:    NewSecret(result.AccessToken),
		RefreshToken:   NewSecret(refreshToken),
		DPoPPrivateKey: privateKey,
	}
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if err := c.SaveSession(ctx, session); err != nil {
		return nil, fmt.Errorf("cannot save OAuth session to the keyring: %w", err)
	}
	return session, nil
}

func (c *Client) SaveSession(ctx context.Context, session *Session) error {
	if c.Store == nil || session == nil {
		return platform.ErrKeyringUnavailable
	}
	if err := session.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(sessionEnvelope{
		Version:        sessionEnvelopeVersion,
		DID:            session.DID,
		Issuer:         session.Issuer,
		TokenEndpoint:  session.TokenEndpoint,
		Scopes:         session.Scopes,
		RefreshToken:   session.RefreshToken.Reveal(),
		DPoPPrivateKey: session.DPoPPrivateKey.Reveal(),
	})
	if err != nil {
		return errors.New("cannot encode OAuth session")
	}
	return c.Store.Save(ctx, sessionItemName(c.ClientID, session.DID), encoded)
}

func (c *Client) LoadSession(ctx context.Context, did string) (*Session, error) {
	if c.Store == nil || !validDID(did) {
		return nil, ErrSessionUnavailable
	}
	encoded, err := c.Store.Load(ctx, sessionItemName(c.ClientID, did))
	if err != nil {
		if errors.Is(err, platform.ErrKeyringLocked) || errors.Is(err, platform.ErrKeyringUnavailable) {
			return nil, err
		}
		return nil, ErrSessionUnavailable
	}
	var envelope sessionEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Version != sessionEnvelopeVersion || envelope.DID != did {
		return nil, ErrSessionUnavailable
	}
	session := &Session{
		DID:            envelope.DID,
		Issuer:         envelope.Issuer,
		TokenEndpoint:  envelope.TokenEndpoint,
		Scopes:         append([]string(nil), envelope.Scopes...),
		RefreshToken:   NewSecret(envelope.RefreshToken),
		DPoPPrivateKey: NewSecret(envelope.DPoPPrivateKey),
	}
	if err := session.Validate(); err != nil {
		return nil, ErrSessionUnavailable
	}
	return session, nil
}

func (c *Client) DeleteSession(ctx context.Context, did string) error {
	if c.Store == nil || !validDID(did) {
		return ErrSessionUnavailable
	}
	return c.Store.Delete(ctx, sessionItemName(c.ClientID, did))
}

func (c *Client) Refresh(ctx context.Context, handle string, session *Session) (*Session, error) {
	if session == nil || session.Validate() != nil {
		return nil, ErrSessionUnavailable
	}
	identity, err := c.Discover(ctx, handle)
	if err != nil {
		return nil, err
	}
	if identity.DID != session.DID {
		return nil, errors.New("discovered DID does not match the stored session")
	}
	if identity.Issuer != session.Issuer || identity.TokenEndpoint != session.TokenEndpoint {
		return nil, errors.New("discovered issuer or token endpoint changed; sign in again")
	}
	key, err := parsePrivateKey(session.DPoPPrivateKey)
	if err != nil {
		return nil, ErrSessionUnavailable
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.ClientID},
		"refresh_token": {session.RefreshToken.Reveal()},
	}
	var result tokenResponse
	if err := c.postFormDPoP(ctx, session.TokenEndpoint, form, key, &result); err != nil {
		return nil, err
	}
	return c.finishToken(ctx, identity, session.Scopes, session.Scopes, key, result, session.RefreshToken.Reveal())
}

func sessionItemName(clientID, did string) string {
	digest := sha256.Sum256([]byte(clientID + "\x00" + did))
	return "session:" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func (c *Client) DoResource(ctx context.Context, session *Session, method, endpoint string, body []byte, headers http.Header) (*http.Response, error) {
	if session == nil || session.Validate() != nil || session.AccessToken.Reveal() == "" {
		return nil, ErrSessionUnavailable
	}
	key, err := parsePrivateKey(session.DPoPPrivateKey)
	if err != nil {
		return nil, ErrSessionUnavailable
	}
	return c.doDPoP(ctx, method, endpoint, strings.NewReader(string(body)), int64(len(body)), "application/octet-stream", headers, key, session.AccessToken)
}
