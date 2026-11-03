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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
)

var (
	ErrSessionUnavailable          = errors.New("stored session is unusable; sign in again")
	ErrSessionRefreshPending       = errors.New("account refresh was interrupted; sign in again")
	ErrSessionBusy                 = errors.New("another dottie command is updating the account session; retry when it finishes")
	ErrSessionRelocated            = errors.New("account authorization server or token endpoint changed; sign in again")
	ErrRevocationUnsupported       = errors.New("authorization server does not advertise a revocation endpoint")
	ErrSessionNotFound             = errors.New("no stored account session")
	ErrSessionLockUnavailable      = errors.New("cannot lock the account session; check the runtime directory and retry")
	ErrSessionPersistenceUncertain = errors.New("authorization was obtained but keyring persistence is uncertain")
)

type SessionLockFunc func(context.Context, string) (func() error, error)

type OAuthEndpointError struct {
	Status int
	Code   string
}

func (e *OAuthEndpointError) Error() string {
	if e.Code == "" || !safeOAuthErrorCode.MatchString(e.Code) {
		return fmt.Sprintf("OAuth endpoint returned HTTP %d", e.Status)
	}
	if _, ok := allowedOAuthErrorCodes[e.Code]; !ok {
		return fmt.Sprintf("OAuth endpoint returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("OAuth endpoint returned HTTP %d (%s)", e.Status, e.Code)
}

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
	sessionLock      SessionLockFunc
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

func WithSessionLock(lock SessionLockFunc) ClientOption {
	return func(c *Client) { c.sessionLock = lock }
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

func (f *Flow) Identity() Identity {
	if f == nil {
		return Identity{}
	}
	identity := f.identity
	identity.VerificationMethods = append([]VerificationMethod(nil), f.identity.VerificationMethods...)
	identity.ScopesSupported = append([]string(nil), f.identity.ScopesSupported...)
	return identity
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
		return nil, authorizationContextError(ctx.Err())
	case callback := <-f.callback:
		if callback.err != nil {
			return nil, callback.err
		}
		if err := ctx.Err(); err != nil {
			return nil, authorizationContextError(err)
		}
		return f.exchangeCode(ctx, callback.code)
	}
}

func authorizationContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("authorization timed out: %w", err)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("authorization canceled: %w", err)
	}
	return err
}

func (f *Flow) exchangeCode(ctx context.Context, code Secret) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, authorizationContextError(err)
	}
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
	if err := ctx.Err(); err != nil {
		return nil, authorizationContextError(err)
	}
	session, err := f.client.finishToken(ctx, f.identity, f.requested, f.required, f.key, result, "")
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, authorizationContextError(err)
	}
	if err := f.client.saveUsableSession(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

var safeOAuthErrorCode = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

var allowedOAuthErrorCodes = map[string]struct{}{
	"invalid_request": {}, "invalid_client": {}, "invalid_grant": {}, "unauthorized_client": {},
	"unsupported_grant_type": {}, "invalid_scope": {}, "use_dpop_nonce": {}, "server_error": {},
	"temporarily_unavailable": {}, "access_denied": {},
}

func sanitizedOAuthCode(body []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if len(body) == 0 || json.Unmarshal(body, &payload) != nil || !safeOAuthErrorCode.MatchString(payload.Error) {
		return ""
	}
	if _, ok := allowedOAuthErrorCodes[payload.Error]; !ok {
		return ""
	}
	return payload.Error
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
		return &OAuthEndpointError{Status: response.StatusCode, Code: sanitizedOAuthCode(detail)}
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
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, authorizationContextError(contextErr)
			}
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

func (c *Client) finishToken(_ context.Context, identity Identity, requested, required []string, key *ecdsa.PrivateKey, result tokenResponse, existingRefresh string) (*Session, error) {
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
		Handle:         identity.Handle,
		Issuer:         identity.Issuer,
		TokenEndpoint:  identity.TokenEndpoint,
		Scopes:         append([]string(nil), granted...),
		State:          SessionStateUsable,
		AccessToken:    NewSecret(result.AccessToken),
		RefreshToken:   NewSecret(refreshToken),
		DPoPPrivateKey: privateKey,
	}
	if err := session.Validate(); err != nil {
		return nil, err
	}
	return session, nil
}

func (c *Client) saveSession(ctx context.Context, session *Session) error {
	if c.Store == nil || session == nil {
		return platform.ErrKeyringUnavailable
	}
	if err := session.Validate(); err != nil {
		return err
	}
	return c.Store.Save(ctx, sessionItemName(c.ClientID, session.DID), encodeSessionEnvelope(session))
}

func encodeSessionEnvelope(session *Session) []byte {
	state := session.State
	if state == "" {
		state = SessionStateUsable
	}
	encoded, _ := json.Marshal(sessionEnvelope{
		Version:        sessionEnvelopeVersion,
		DID:            session.DID,
		Handle:         session.Handle,
		Issuer:         session.Issuer,
		TokenEndpoint:  session.TokenEndpoint,
		Scopes:         session.Scopes,
		State:          state,
		RefreshToken:   session.RefreshToken.Reveal(),
		DPoPPrivateKey: session.DPoPPrivateKey.Reveal(),
	})
	return encoded
}

func (c *Client) saveUsableSession(ctx context.Context, session *Session) error {
	if session == nil {
		return platform.ErrKeyringUnavailable
	}
	item := sessionItemName(c.ClientID, session.DID)
	release, err := c.acquireSessionLock(ctx, item)
	if err != nil {
		return err
	}
	defer release()
	if err := c.saveSession(ctx, session); err != nil {
		return fmt.Errorf("%w: %w", ErrSessionPersistenceUncertain, err)
	}
	return nil
}

func (c *Client) LoadSessionStatus(ctx context.Context, did string) (SessionStatus, error) {
	envelope, _, err := c.loadEnvelope(ctx, did)
	if err != nil {
		return SessionStatus{}, err
	}
	status, err := envelope.status()
	if err != nil || status.DID != did {
		return SessionStatus{}, ErrSessionUnavailable
	}
	return status, nil
}

func (c *Client) loadEnvelope(ctx context.Context, did string) (sessionEnvelope, []byte, error) {
	if c.Store == nil || !validDID(did) {
		return sessionEnvelope{}, nil, ErrSessionUnavailable
	}
	encoded, err := c.Store.Load(ctx, sessionItemName(c.ClientID, did))
	if err != nil {
		if errors.Is(err, platform.ErrKeyringLocked) || errors.Is(err, platform.ErrKeyringUnavailable) {
			return sessionEnvelope{}, nil, err
		}
		if errors.Is(err, platform.ErrKeyringItemNotFound) {
			return sessionEnvelope{}, nil, ErrSessionNotFound
		}
		return sessionEnvelope{}, nil, ErrSessionUnavailable
	}
	var envelope sessionEnvelope
	if json.Unmarshal(encoded, &envelope) != nil || envelope.Version != sessionEnvelopeVersion || envelope.DID != did {
		return sessionEnvelope{}, nil, ErrSessionUnavailable
	}
	return envelope, append([]byte(nil), encoded...), nil
}

func sessionFromEnvelope(envelope sessionEnvelope) (*Session, error) {
	status, err := envelope.status()
	if err != nil {
		return nil, err
	}
	if status.State == SessionStateRefreshPending {
		return nil, ErrSessionRefreshPending
	}
	session := &Session{
		DID:            envelope.DID,
		Handle:         envelope.Handle,
		Issuer:         envelope.Issuer,
		TokenEndpoint:  envelope.TokenEndpoint,
		Scopes:         append([]string(nil), envelope.Scopes...),
		State:          SessionStateUsable,
		RefreshToken:   NewSecret(envelope.RefreshToken),
		DPoPPrivateKey: NewSecret(envelope.DPoPPrivateKey),
	}
	if err := session.Validate(); err != nil {
		return nil, ErrSessionUnavailable
	}
	return session, nil
}

func (c *Client) LoadSession(ctx context.Context, did string) (*Session, error) {
	envelope, _, err := c.loadEnvelope(ctx, did)
	if err != nil {
		return nil, err
	}
	return sessionFromEnvelope(envelope)
}

func (c *Client) DeleteSession(ctx context.Context, did string) error {
	if c.Store == nil || !validDID(did) {
		return ErrSessionUnavailable
	}
	item := sessionItemName(c.ClientID, did)
	release, err := c.acquireSessionLock(ctx, item)
	if err != nil {
		return err
	}
	defer release()
	return c.Store.Delete(ctx, item)
}

var localSessionLocks = struct {
	sync.Mutex
	locks map[string]chan struct{}
}{locks: make(map[string]chan struct{})}

func (c *Client) acquireSessionLock(ctx context.Context, item string) (func() error, error) {
	lock := c.sessionLock
	if lock == nil {
		lock = localSessionLock
	}
	return lock(ctx, item)
}

func localSessionLock(ctx context.Context, item string) (func() error, error) {
	localSessionLocks.Lock()
	lock := localSessionLocks.locks[item]
	if lock == nil {
		lock = make(chan struct{}, 1)
		localSessionLocks.locks[item] = lock
	}
	localSessionLocks.Unlock()
	select {
	case lock <- struct{}{}:
		return func() error { <-lock; return nil }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) Refresh(ctx context.Context, handle string, session *Session) (*Session, Identity, error) {
	if session == nil {
		return nil, Identity{}, ErrSessionUnavailable
	}
	if session.State == SessionStateRefreshPending {
		return nil, Identity{}, ErrSessionRefreshPending
	}
	if session.Validate() != nil {
		return nil, Identity{}, ErrSessionUnavailable
	}
	if handle == "" {
		handle = session.Handle
	}
	if handle == "" {
		return nil, Identity{}, errors.New("account handle is required to refresh this legacy session")
	}
	identity, err := c.Discover(ctx, handle)
	if err != nil {
		return nil, Identity{}, err
	}
	if err := checkSessionBinding(identity, session); err != nil {
		return nil, identity, err
	}
	if err := ctx.Err(); err != nil {
		return nil, identity, authorizationContextError(err)
	}
	item := sessionItemName(c.ClientID, session.DID)
	release, err := c.acquireSessionLock(ctx, item)
	if err != nil {
		return nil, identity, err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return nil, identity, authorizationContextError(err)
	}
	latestEnvelope, _, err := c.loadEnvelope(ctx, session.DID)
	if err != nil {
		return nil, identity, err
	}
	latestStatus, err := latestEnvelope.status()
	if err != nil {
		return nil, identity, ErrSessionUnavailable
	}
	if latestStatus.State == SessionStateRefreshPending {
		return nil, identity, ErrSessionRefreshPending
	}
	latest, err := sessionFromEnvelope(latestEnvelope)
	if err != nil {
		return nil, identity, err
	}
	if err := checkSessionBinding(identity, latest); err != nil {
		return nil, identity, err
	}
	if err := ctx.Err(); err != nil {
		return nil, identity, authorizationContextError(err)
	}
	pending := latestEnvelope
	pending.State = SessionStateRefreshPending
	pending.Handle = identity.Handle
	pending.RefreshToken = ""
	pending.DPoPPrivateKey = ""
	encodedPending, err := json.Marshal(pending)
	if err != nil {
		return nil, identity, errors.New("cannot encode refresh-pending session")
	}
	if err := c.Store.Save(ctx, item, encodedPending); err != nil {
		return nil, identity, fmt.Errorf("cannot save refresh-pending session: %w", err)
	}
	key, err := parsePrivateKey(latest.DPoPPrivateKey)
	if err != nil {
		return nil, identity, fmt.Errorf("%w; refresh outcome is unknown, sign in again", ErrSessionUnavailable)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.ClientID},
		"refresh_token": {latest.RefreshToken.Reveal()},
	}
	var result tokenResponse
	if err := c.postFormDPoP(ctx, identity.TokenEndpoint, form, key, &result); err != nil {
		return nil, identity, fmt.Errorf("%w; refresh outcome is unknown, sign in again", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, identity, authorizationContextError(err)
	}
	refreshed, err := c.finishToken(ctx, identity, latest.Scopes, latest.Scopes, key, result, latest.RefreshToken.Reveal())
	if err != nil {
		return nil, identity, fmt.Errorf("%w; refresh outcome is unknown, sign in again", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, identity, authorizationContextError(err)
	}
	if err := c.saveSession(ctx, refreshed); err != nil {
		return nil, identity, fmt.Errorf("%w: %w", ErrSessionPersistenceUncertain, err)
	}
	return refreshed, identity, nil
}

func checkSessionBinding(identity Identity, session *Session) error {
	if identity.DID != session.DID || identity.Issuer != session.Issuer || identity.TokenEndpoint != session.TokenEndpoint {
		return ErrSessionRelocated
	}
	return nil
}

type LogoutResult struct {
	RemoteRevocationAccepted bool
	LocalDeleted             bool
}

func (c *Client) Logout(ctx context.Context, did, handle string, session *Session, remote bool) (LogoutResult, error) {
	if c.Store == nil || !validDID(did) {
		return LogoutResult{}, ErrSessionUnavailable
	}
	item := sessionItemName(c.ClientID, did)
	if !remote {
		release, err := c.acquireSessionLock(ctx, item)
		if err != nil {
			return LogoutResult{}, err
		}
		defer release()
		if err := c.Store.Delete(ctx, item); err != nil {
			return LogoutResult{}, err
		}
		return LogoutResult{LocalDeleted: true}, nil
	}
	if session == nil || session.Validate() != nil || session.DID != did {
		return LogoutResult{}, ErrSessionUnavailable
	}
	if handle == "" {
		handle = session.Handle
	}
	if handle == "" {
		return LogoutResult{}, errors.New("account handle is required for remote logout")
	}
	identity, err := c.Discover(ctx, handle)
	if err != nil {
		return LogoutResult{}, err
	}
	if err := checkSessionBinding(identity, session); err != nil {
		return LogoutResult{}, err
	}
	if identity.RevocationEndpoint == "" {
		return LogoutResult{}, ErrRevocationUnsupported
	}
	release, err := c.acquireSessionLock(ctx, item)
	if err != nil {
		return LogoutResult{}, err
	}
	defer release()
	latestEnvelope, _, err := c.loadEnvelope(ctx, did)
	if err != nil {
		return LogoutResult{}, err
	}
	latest, err := sessionFromEnvelope(latestEnvelope)
	if err != nil {
		return LogoutResult{}, err
	}
	if err := checkSessionBinding(identity, latest); err != nil {
		return LogoutResult{}, err
	}
	key, err := parsePrivateKey(latest.DPoPPrivateKey)
	if err != nil {
		return LogoutResult{}, ErrSessionUnavailable
	}
	form := url.Values{
		"token":           {latest.RefreshToken.Reveal()},
		"token_type_hint": {"refresh_token"},
		"client_id":       {c.ClientID},
	}
	body := form.Encode()
	response, err := c.doDPoP(ctx, http.MethodPost, identity.RevocationEndpoint, strings.NewReader(body), int64(len(body)), "application/x-www-form-urlencoded", nil, key, Secret{})
	if err != nil {
		return LogoutResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return LogoutResult{}, &OAuthEndpointError{Status: response.StatusCode, Code: sanitizedOAuthCode(detail)}
	}
	result := LogoutResult{RemoteRevocationAccepted: true}
	if err := c.Store.Delete(ctx, item); err != nil {
		return result, fmt.Errorf("revocation request accepted but local session could not be deleted: %w", err)
	}
	result.LocalDeleted = true
	return result, nil
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
