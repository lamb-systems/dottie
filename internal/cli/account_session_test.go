package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	accountTestDID    = "did:plc:abcdefghijklmnopqrstuvwx"
	accountTestHandle = "alice.example"
)

type memoryOAuthKeyring struct {
	*memoryAccountKeyring
	mu                sync.Mutex
	items             map[string][]byte
	loadErr           error
	saveErr           error
	saveApplyThenFail error
	deleteErr         error
}

func newMemoryOAuthKeyring() *memoryOAuthKeyring {
	return &memoryOAuthKeyring{memoryAccountKeyring: &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}, items: make(map[string][]byte)}
}

func (k *memoryOAuthKeyring) Save(_ context.Context, name string, payload []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.saveErr != nil {
		return k.saveErr
	}
	k.items[name] = bytes.Clone(payload)
	if k.saveApplyThenFail != nil {
		return k.saveApplyThenFail
	}
	return nil
}

func (k *memoryOAuthKeyring) Load(_ context.Context, name string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.loadErr != nil {
		return nil, k.loadErr
	}
	payload, ok := k.items[name]
	if !ok {
		return nil, platform.ErrKeyringItemNotFound
	}
	return bytes.Clone(payload), nil
}

func (k *memoryOAuthKeyring) Delete(_ context.Context, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.deleteErr != nil {
		return k.deleteErr
	}
	delete(k.items, name)
	return nil
}

type cliOAuthFake struct {
	server             *httptest.Server
	mu                 sync.Mutex
	parForm            url.Values
	parReady           chan struct{}
	parReadyOnce       sync.Once
	requests           []string
	did                string
	documentID         string
	pds                string
	issuer             string
	tokenEndpoint      string
	revocationEndpoint string
	tokenStatus        int
	tokenBody          string
	tokenRefresh       string
	tokenAccess        string
	tokenScope         string
	tokenRequests      int
	refreshTokens      []string
	revokeStatus       int
	revokeRequests     int
}

type cliRewriteTransport struct {
	server    *url.URL
	transport *http.Transport
}

func (r cliRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("X-Original-Host", request.URL.Host)
	copy.URL.Scheme = r.server.Scheme
	copy.URL.Host = r.server.Host
	copy.Host = request.URL.Host
	return r.transport.RoundTrip(copy)
}

func newCLIOAuthFake(t *testing.T) *cliOAuthFake {
	t.Helper()
	fake := &cliOAuthFake{
		parReady:           make(chan struct{}),
		did:                accountTestDID,
		documentID:         accountTestDID,
		pds:                "https://pds.example",
		issuer:             "https://issuer.example",
		tokenEndpoint:      "https://issuer.example/token",
		revocationEndpoint: "https://issuer.example/revoke",
		tokenRefresh:       "rotated-refresh-secret",
		tokenAccess:        "access-token-secret",
	}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(fake.serveHTTP))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *cliOAuthFake) httpClient() *http.Client {
	serverURL, _ := url.Parse(f.server.URL)
	return &http.Client{Transport: cliRewriteTransport{server: serverURL, transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}
}

func (f *cliOAuthFake) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	host := request.Header.Get("X-Original-Host")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, host+request.URL.Path)
	switch {
	case host == accountTestHandle && request.URL.Path == "/.well-known/atproto-did":
		_, _ = io.WriteString(writer, f.did)
	case host == "plc.directory" && strings.HasPrefix(request.URL.Path, "/did:"):
		writeCLIJSON(writer, map[string]any{"id": f.documentID, "alsoKnownAs": []string{"at://" + accountTestHandle}, "service": []map[string]string{{"id": f.documentID + "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": f.pds}}})
	case host == "pds.example" && request.URL.Path == "/.well-known/oauth-protected-resource":
		writeCLIJSON(writer, map[string]any{"resource": f.pds, "authorization_servers": []string{f.issuer}})
	case host == "issuer.example" && request.URL.Path == "/.well-known/oauth-authorization-server":
		writeCLIJSON(writer, map[string]any{"issuer": f.issuer, "authorization_endpoint": f.issuer + "/authorize", "token_endpoint": f.tokenEndpoint, "pushed_authorization_request_endpoint": f.issuer + "/par", "revocation_endpoint": f.revocationEndpoint})
	case host == "issuer.example" && request.URL.Path == "/par":
		_ = request.ParseForm()
		f.parForm = request.Form
		f.parReadyOnce.Do(func() { close(f.parReady) })
		writeCLIJSON(writer, map[string]string{"request_uri": "urn:cli:request:1"})
	case host == "issuer.example" && request.URL.Path == "/token":
		f.tokenRequests++
		_ = request.ParseForm()
		if request.Form.Get("grant_type") == "refresh_token" {
			f.refreshTokens = append(f.refreshTokens, request.Form.Get("refresh_token"))
		}
		if f.tokenStatus != 0 {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(f.tokenStatus)
			_, _ = io.WriteString(writer, f.tokenBody)
			return
		}
		writeCLIJSON(writer, map[string]any{"access_token": f.tokenAccess, "refresh_token": f.tokenRefresh, "token_type": "DPoP", "scope": f.tokenScope, "sub": accountTestDID})
	case host == "issuer.example" && request.URL.Path == "/revoke":
		f.revokeRequests++
		if f.revokeRequests == 1 && f.revokeStatus != 0 {
			writer.WriteHeader(f.revokeStatus)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (f *cliOAuthFake) sendCallback() error {
	f.mu.Lock()
	form := f.parForm
	f.mu.Unlock()
	if form == nil {
		return errors.New("PAR form was not recorded")
	}
	callback, err := url.Parse(form.Get("redirect_uri"))
	if err != nil {
		return err
	}
	query := callback.Query()
	query.Set("state", form.Get("state"))
	query.Set("iss", f.issuer)
	query.Set("code", "authorization-code-secret")
	callback.RawQuery = query.Encode()
	response, err := http.Get(callback.String())
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("callback returned HTTP %d", response.StatusCode)
	}
	return nil
}

func writeCLIJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func cliSessionOptions(fake *cliOAuthFake) accountSessionOptions {
	return accountSessionOptions{
		oauthOptions: []atproto.ClientOption{atproto.WithHTTPClient(fake.httpClient()), atproto.WithTXTLookup(func(context.Context, string) ([]string, error) { return nil, errors.New("not found") })},
		browser:      func(string) error { return fake.sendCallback() },
		env:          os.Getenv,
		sessionLock:  func(context.Context, string) (func() error, error) { return func() error { return nil }, nil },
	}
}

func runAccountWithSession(args []string, open accountKeyringFactory, options accountSessionOptions, stdout, stderr *bytes.Buffer) int {
	exitCode := 0
	command := newAccountCommandWithSession(stdout, stderr, open, &exitCode, options)
	ctx := context.Background()
	arguments := append([]string{"account"}, args...)
	if err := command.Run(ctx, arguments); err != nil && exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return exitCode
}

func TestAccountLoginPersistsFullScopesAndPrintsSafeFollowups(t *testing.T) {
	fake := newCLIOAuthFake(t)
	keyring := newMemoryOAuthKeyring()
	options := cliSessionOptions(fake)
	var stdout, stderr bytes.Buffer
	code := runAccountWithSession([]string{"login", "--handle", accountTestHandle}, func() (accountKeyring, error) { return keyring, nil }, options, &stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Empty(t, stderr.String())
	assert.Contains(t, stdout.String(), "authorization URL:")
	assert.Contains(t, stdout.String(), "status: dottie account status --did "+accountTestDID)
	assert.Contains(t, stdout.String(), "logout: dottie account logout --did "+accountTestDID)
	assert.Contains(t, stdout.String(), strings.Join(atproto.VaultScopes(), " "))
	for _, secret := range []string{"authorization-code-secret", "access-token-secret", "rotated-refresh-secret", "dpop_private_key"} {
		assert.NotContains(t, stdout.String(), secret)
		assert.NotContains(t, stderr.String(), secret)
	}
	require.Equal(t, strings.Join(atproto.VaultScopes(), " "), fake.parForm.Get("scope"))
	require.Equal(t, 1, fake.tokenRequests)
	require.Len(t, keyring.items, 1)
}

func TestAccountLoginNoBrowserAndBrowserFailureStillComplete(t *testing.T) {
	for _, test := range []struct {
		name          string
		args          []string
		browserResult error
		wantBrowser   bool
	}{
		{name: "no browser", args: []string{"login", "--handle", accountTestHandle, "--no-browser"}},
		{name: "browser failure", args: []string{"login", "--handle", accountTestHandle}, browserResult: errors.New("browser failed"), wantBrowser: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newCLIOAuthFake(t)
			keyring := newMemoryOAuthKeyring()
			options := cliSessionOptions(fake)
			browserCalls := 0
			options.browser = func(string) error {
				browserCalls++
				if test.browserResult != nil {
					if err := fake.sendCallback(); err != nil {
						return err
					}
					return test.browserResult
				}
				return fake.sendCallback()
			}
			if !test.wantBrowser {
				options.browser = func(string) error { browserCalls++; return nil }
				callbackDone := make(chan error, 1)
				go func() {
					<-fake.parReady
					callbackDone <- fake.sendCallback()
				}()
				var stdout, stderr bytes.Buffer
				code := runAccountWithSession(test.args, func() (accountKeyring, error) { return keyring, nil }, options, &stdout, &stderr)
				require.Equal(t, 0, code)
				assert.NoError(t, <-callbackDone)
				assert.Equal(t, 0, browserCalls)
				assert.Empty(t, stderr.String())
				return
			}
			var stdout, stderr bytes.Buffer
			code := runAccountWithSession(test.args, func() (accountKeyring, error) { return keyring, nil }, options, &stdout, &stderr)
			require.Equal(t, 0, code)
			assert.Equal(t, 1, browserCalls)
			assert.Contains(t, stderr.String(), "could not open a browser")
			assert.Len(t, keyring.items, 1)
		})
	}
}

func TestAccountLoginTimeoutBoundsAreValidatedBeforeKeyringAccess(t *testing.T) {
	for _, timeout := range []string{"0s", "16m", "not-a-duration"} {
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"login", "--handle", accountTestHandle, "--timeout", timeout}, func() (accountKeyring, error) {
			return nil, errors.New("keyring must not be opened")
		}, accountSessionOptions{}, &stdout, &stderr)
		assert.Equal(t, 2, code)
		assert.Contains(t, stderr.String(), "--timeout must be between 1s and 15m")
	}
	assert.Equal(t, 5*time.Minute, func() time.Duration { duration, _ := accountLoginTimeout(""); return duration }())
}

func TestAccountLoginTimeoutExitsWithoutSession(t *testing.T) {
	fake := newCLIOAuthFake(t)
	keyring := newMemoryOAuthKeyring()
	options := cliSessionOptions(fake)
	options.browser = func(string) error { return nil }
	var stdout, stderr bytes.Buffer
	code := runAccountWithSession([]string{"login", "--handle", accountTestHandle, "--no-browser", "--timeout", "1s"}, func() (accountKeyring, error) { return keyring, nil }, options, &stdout, &stderr)
	require.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "authorization timed out")
	assert.Contains(t, stderr.String(), "no session was stored")
	assert.Empty(t, keyring.items)
	assert.Equal(t, 0, fake.tokenRequests)
}

func TestAccountLoginOAuthFailureIsActionableAndDoesNotLeakBody(t *testing.T) {
	fake := newCLIOAuthFake(t)
	fake.tokenStatus = http.StatusBadRequest
	fake.tokenBody = `{"error":"invalid_grant","error_description":"authorization-code-secret"}`
	keyring := newMemoryOAuthKeyring()
	callbackDone := make(chan error, 1)
	go func() {
		<-fake.parReady
		callbackDone <- fake.sendCallback()
	}()
	var stdout, stderr bytes.Buffer
	code := runAccountWithSession([]string{"login", "--handle", accountTestHandle, "--no-browser"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
	assert.NoError(t, <-callbackDone)
	require.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "HTTP 400 (invalid_grant)")
	assert.Contains(t, stderr.String(), "no session was stored")
	assert.NotContains(t, stderr.String(), "authorization-code-secret")
	assert.NotContains(t, stdout.String(), "authorization-code-secret")
	assert.Empty(t, keyring.items)
}

func TestAccountLoginPersistenceUncertaintyDoesNotClaimNothingStored(t *testing.T) {
	fake := newCLIOAuthFake(t)
	keyring := newMemoryOAuthKeyring()
	keyring.saveApplyThenFail = errors.New("synthetic lost keyring reply")
	callbackDone := make(chan error, 1)
	go func() {
		<-fake.parReady
		callbackDone <- fake.sendCallback()
	}()
	var stdout, stderr bytes.Buffer
	code := runAccountWithSession([]string{"login", "--handle", accountTestHandle, "--no-browser"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
	assert.NoError(t, <-callbackDone)
	require.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "keyring persistence is uncertain")
	assert.NotContains(t, stderr.String(), "no session was stored")
	assert.Contains(t, stderr.String(), accountTestDID)
	assert.NotEmpty(t, keyring.items[cliSessionItemName()])
	stdout.Reset()
	stderr.Reset()
	code = runAccountWithSession([]string{"status", "--did", accountTestDID}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "authorization: usable")
}

func TestAccountLoginBusyLockIsNotPersistenceUncertain(t *testing.T) {
	fake := newCLIOAuthFake(t)
	keyring := newMemoryOAuthKeyring()
	options := cliSessionOptions(fake)
	options.sessionLock = func(context.Context, string) (func() error, error) { return nil, atproto.ErrSessionBusy }
	callbackDone := make(chan error, 1)
	go func() {
		<-fake.parReady
		callbackDone <- fake.sendCallback()
	}()
	var stdout, stderr bytes.Buffer
	code := runAccountWithSession([]string{"login", "--handle", accountTestHandle, "--no-browser"}, func() (accountKeyring, error) { return keyring, nil }, options, &stdout, &stderr)
	assert.NoError(t, <-callbackDone)
	require.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "another dottie command")
	assert.NotContains(t, stderr.String(), "persistence is uncertain")
	assert.Empty(t, keyring.items)
}

func TestAccountRefreshFailurePersistenceUncertaintyGuidance(t *testing.T) {
	failure := accountRefreshFailure(fmt.Errorf("%w: lost reply", atproto.ErrSessionPersistenceUncertain), "", accountTestDID)
	assert.Contains(t, failure.Error(), "keyring persistence is uncertain")
	assert.Contains(t, failure.Error(), accountTestDID)
	assert.NotContains(t, failure.Error(), "sign in again")
}

func TestAccountStatusOfflineUsablePendingMissingCorruptAndKeyringErrors(t *testing.T) {
	for _, test := range []struct {
		name      string
		seed      func(*testing.T, *memoryOAuthKeyring)
		loadErr   error
		wantCode  int
		wantText  string
		wantState string
	}{
		{name: "usable", seed: func(t *testing.T, keyring *memoryOAuthKeyring) {
			seedCLISession(t, keyring, atproto.SessionStateUsable)
		}, wantText: "authorization: usable"},
		{name: "pending", seed: func(t *testing.T, keyring *memoryOAuthKeyring) {
			seedCLISession(t, keyring, atproto.SessionStateRefreshPending)
		}, wantText: "authorization: refresh interrupted; sign in again"},
		{name: "missing", wantCode: 1, wantText: "not signed in; run dottie account login --handle HANDLE"},
		{name: "corrupt", seed: func(_ *testing.T, keyring *memoryOAuthKeyring) {
			keyring.items[cliSessionItemName()] = []byte("not-json")
		}, wantCode: 1, wantText: "corrupt or unusable"},
		{name: "locked", loadErr: platform.ErrKeyringLocked, wantCode: 1, wantText: "keyring is locked"},
		{name: "unavailable", loadErr: platform.ErrKeyringUnavailable, wantCode: 1, wantText: "keyring is unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newCLIOAuthFake(t)
			keyring := newMemoryOAuthKeyring()
			if test.seed != nil {
				test.seed(t, keyring)
			}
			keyring.loadErr = test.loadErr
			var stdout, stderr bytes.Buffer
			code := runAccountWithSession([]string{"status", "--did", accountTestDID}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
			require.Equal(t, test.wantCode, code)
			if test.wantCode == 0 {
				assert.Contains(t, stdout.String(), test.wantText)
				assert.Empty(t, stderr.String())
			} else {
				assert.Contains(t, stderr.String(), test.wantText)
			}
			assert.Empty(t, fake.requests, "--did status must not perform discovery")
		})
	}
}

func TestAccountStatusHandleResolutionAndRefreshOutcomes(t *testing.T) {
	t.Run("handle resolution", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"status", "--handle", accountTestHandle}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 0, code)
		assert.Contains(t, stdout.String(), "authorization: usable")
		assert.NotEmpty(t, fake.requests)
	})
	t.Run("refresh success", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		fake.tokenScope = strings.Join(atproto.VaultScopes(), " ")
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"status", "--did", accountTestDID, "--refresh"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 0, code)
		assert.Contains(t, stdout.String(), "pds: https://pds.example")
		assert.Contains(t, stdout.String(), "refresh token: present")
		assert.Equal(t, []string{"stored-refresh-token"}, fake.refreshTokens)
		assert.NotContains(t, stdout.String(), "rotated-refresh-secret")
	})
	for _, test := range []struct {
		name      string
		setup     func(*cliOAuthFake, *memoryOAuthKeyring, *accountSessionOptions)
		wantText  string
		wantState string
	}{
		{name: "busy", setup: func(_ *cliOAuthFake, _ *memoryOAuthKeyring, options *accountSessionOptions) {
			options.sessionLock = func(context.Context, string) (func() error, error) { return nil, atproto.ErrSessionBusy }
		}, wantText: "another dottie command", wantState: atproto.SessionStateUsable},
		{name: "pending", setup: func(_ *cliOAuthFake, keyring *memoryOAuthKeyring, _ *accountSessionOptions) {
			seedCLISession(t, keyring, atproto.SessionStateRefreshPending)
		}, wantText: "refresh was interrupted", wantState: atproto.SessionStateRefreshPending},
		{name: "locked", setup: func(_ *cliOAuthFake, keyring *memoryOAuthKeyring, _ *accountSessionOptions) {
			keyring.loadErr = platform.ErrKeyringLocked
		}, wantText: "keyring is locked"},
		{name: "relocated", setup: func(fake *cliOAuthFake, _ *memoryOAuthKeyring, _ *accountSessionOptions) {
			fake.tokenEndpoint = "https://issuer.example/changed"
		}, wantText: "authorization server or token endpoint changed", wantState: atproto.SessionStateUsable},
		{name: "rejected", setup: func(fake *cliOAuthFake, _ *memoryOAuthKeyring, _ *accountSessionOptions) {
			fake.tokenStatus = http.StatusBadRequest
			fake.tokenBody = `{"error":"invalid_grant"}`
		}, wantText: "HTTP 400 (invalid_grant)", wantState: atproto.SessionStateRefreshPending},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newCLIOAuthFake(t)
			keyring := newMemoryOAuthKeyring()
			options := cliSessionOptions(fake)
			seedCLISession(t, keyring, atproto.SessionStateUsable)
			test.setup(fake, keyring, &options)
			var stdout, stderr bytes.Buffer
			code := runAccountWithSession([]string{"status", "--did", accountTestDID, "--refresh"}, func() (accountKeyring, error) { return keyring, nil }, options, &stdout, &stderr)
			require.Equal(t, 1, code)
			assert.Contains(t, stderr.String(), test.wantText)
			assert.Contains(t, stderr.String(), "pending local changes are preserved")
			payload := keyring.items[cliSessionItemName()]
			assert.NotEmpty(t, payload)
			if test.wantState != "" {
				var envelope cliSessionEnvelope
				require.NoError(t, json.Unmarshal(payload, &envelope))
				assert.Equal(t, test.wantState, envelope.State)
			}
		})
	}
}

func TestAccountLogoutLocalCorruptPendingUsableAndRemoteOutcomes(t *testing.T) {
	for _, stateName := range []string{"corrupt", atproto.SessionStateRefreshPending, atproto.SessionStateUsable} {
		t.Run("local "+stateName, func(t *testing.T) {
			fake := newCLIOAuthFake(t)
			keyring := newMemoryOAuthKeyring()
			switch stateName {
			case "corrupt":
				keyring.items[cliSessionItemName()] = []byte("bad envelope")
			case atproto.SessionStateRefreshPending:
				seedCLISession(t, keyring, atproto.SessionStateRefreshPending)
			default:
				seedCLISession(t, keyring, atproto.SessionStateUsable)
			}
			var stdout, stderr bytes.Buffer
			code := runAccountWithSession([]string{"logout", "--did", accountTestDID}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
			require.Equal(t, 0, code)
			assert.Contains(t, stdout.String(), "local authorization deleted")
			assert.Empty(t, stderr.String())
			assert.Empty(t, keyring.items)
			assert.Empty(t, fake.requests)
		})
	}
	t.Run("local locked keyring", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		keyring.deleteErr = platform.ErrKeyringLocked
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"logout", "--did", accountTestDID}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 1, code)
		assert.Contains(t, stderr.String(), "keyring is locked")
		assert.NotEmpty(t, keyring.items[cliSessionItemName()])
		assert.Empty(t, fake.requests)
	})

	t.Run("remote accepted", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"logout", "--did", accountTestDID, "--remote"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 0, code)
		assert.Contains(t, stdout.String(), "revocation request accepted")
		assert.Contains(t, stdout.String(), "previously issued access tokens may remain valid")
		assert.NotContains(t, stdout.String(), "all sessions revoked")
		assert.Empty(t, keyring.items)
		assert.Equal(t, 1, fake.revokeRequests)
	})
	t.Run("remote rejection preserves item", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		fake.revokeStatus = http.StatusBadRequest
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"logout", "--did", accountTestDID, "--remote"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 1, code)
		assert.Contains(t, stderr.String(), "HTTP 400")
		assert.NotEmpty(t, keyring.items[cliSessionItemName()])
		assert.Equal(t, 1, fake.revokeRequests)
	})
	t.Run("handle local logout", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"logout", "--handle", accountTestHandle}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 0, code)
		assert.Contains(t, stdout.String(), "local authorization deleted")
		assert.NotEmpty(t, fake.requests)
		assert.Empty(t, fake.revokeRequests)
	})
	t.Run("remote unsupported preserves item", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		fake.revocationEndpoint = ""
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"logout", "--did", accountTestDID, "--remote"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 1, code)
		assert.Contains(t, stderr.String(), "does not advertise a revocation endpoint")
		assert.NotEmpty(t, keyring.items[cliSessionItemName()])
		assert.Equal(t, 0, fake.revokeRequests)
	})
	t.Run("remote accepted but local delete fails", func(t *testing.T) {
		fake := newCLIOAuthFake(t)
		keyring := newMemoryOAuthKeyring()
		seedCLISession(t, keyring, atproto.SessionStateUsable)
		keyring.deleteErr = errors.New("synthetic delete failure")
		var stdout, stderr bytes.Buffer
		code := runAccountWithSession([]string{"logout", "--did", accountTestDID, "--remote"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
		require.Equal(t, 1, code)
		assert.Contains(t, stderr.String(), "revocation request accepted")
		assert.Contains(t, stderr.String(), "local authorization could not be deleted")
		assert.NotEmpty(t, keyring.items[cliSessionItemName()])
		assert.Equal(t, 1, fake.revokeRequests)
	})
}

func TestAccountFileSessionLockMapsHeldFileToBusy(t *testing.T) {
	runtimeDir := t.TempDir()
	path := platform.SessionLockPath(func(name string) string {
		if name == "XDG_RUNTIME_DIR" {
			return runtimeDir
		}
		return ""
	})
	lock, err := platform.LockFile(path)
	require.NoError(t, err)
	defer lock.Close()
	options := accountFileSessionLock(func(name string) string {
		if name == "XDG_RUNTIME_DIR" {
			return runtimeDir
		}
		return ""
	})
	_, err = options(context.Background(), "item")
	require.ErrorIs(t, err, atproto.ErrSessionBusy)
}

func TestAccountStatusCommandsPreservePendingStateDirectoryBytes(t *testing.T) {
	home := t.TempDir()
	stateHome := filepath.Join(t.TempDir(), "state-home")
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", stateHome)
	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	store, err := state.Open(paths)
	require.NoError(t, err)
	descriptor := state.TargetDescriptor{ID: "target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, LogicalBase: model.RootHome, LogicalPath: "prefs", Kind: model.SelectionDirectory, Mode: "review", CreatedAt: 1}
	require.NoError(t, store.PutTarget(context.Background(), descriptor))
	identity := model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "prefs/settings.toml"}
	preimage := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("after"))
	_, err = store.AppendJournal(context.Background(), state.JournalEntry{ID: "pending-change", Operation: "replace", State: "pending", Stage: state.JournalStagePending, Identity: identity, Preimage: preimage, Postimage: postimage, CreatedAt: 1}, []byte("before"))
	require.NoError(t, err)
	require.NoError(t, store.Close())
	before := snapshotStateTree(t, paths.AppStateDir())

	fake := newCLIOAuthFake(t)
	fake.tokenStatus = http.StatusInternalServerError
	keyring := newMemoryOAuthKeyring()
	seedCLISession(t, keyring, atproto.SessionStateUsable)
	var stdout, stderr bytes.Buffer
	code := runAccountWithSession([]string{"status", "--did", accountTestDID, "--refresh"}, func() (accountKeyring, error) { return keyring, nil }, cliSessionOptions(fake), &stdout, &stderr)
	require.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "pending local changes are preserved")
	after := snapshotStateTree(t, paths.AppStateDir())
	assert.Equal(t, before, after)
	var pendingEnvelope cliSessionEnvelope
	require.NoError(t, json.Unmarshal(keyring.items[cliSessionItemName()], &pendingEnvelope))
	assert.Equal(t, atproto.SessionStateRefreshPending, pendingEnvelope.State)
	second, err := state.Open(paths)
	require.NoError(t, err)
	entries, err := second.PendingJournalEntries(context.Background())
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	require.NoError(t, second.Close())
}

func TestAccountRootHelpListsLoginLogoutStatusButTopLevelLoginStaysUnsupported(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := newAccountCommand(&stdout, &stderr, func() (accountKeyring, error) { return newMemoryOAuthKeyring(), nil }, new(int))
	err := root.Run(context.Background(), []string{"account", "--help"})
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "login")
	assert.Contains(t, stdout.String(), "logout")
	assert.Contains(t, stdout.String(), "status")
	stdout.Reset()
	stderr.Reset()
	assert.Equal(t, 2, Run([]string{"login"}, &stdout, &stderr))
	assert.Contains(t, stderr.String(), "unsupported command")
}

type cliSessionEnvelope struct {
	Version        int      `json:"version"`
	DID            string   `json:"did"`
	Handle         string   `json:"handle,omitempty"`
	Issuer         string   `json:"issuer"`
	TokenEndpoint  string   `json:"token_endpoint"`
	Scopes         []string `json:"scopes"`
	State          string   `json:"state,omitempty"`
	RefreshToken   string   `json:"refresh_token,omitempty"`
	DPoPPrivateKey string   `json:"dpop_private_key,omitempty"`
}

func seedCLISession(t *testing.T, keyring *memoryOAuthKeyring, sessionState string) {
	t.Helper()
	if sessionState == atproto.SessionStateRefreshPending {
		envelope := cliSessionEnvelope{Version: 1, DID: accountTestDID, Handle: accountTestHandle, Issuer: "https://issuer.example", TokenEndpoint: "https://issuer.example/token", Scopes: atproto.VaultScopes(), State: sessionState}
		encoded, err := json.Marshal(envelope)
		require.NoError(t, err)
		keyring.items[cliSessionItemName()] = encoded
		return
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	envelope := cliSessionEnvelope{Version: 1, DID: accountTestDID, Handle: accountTestHandle, Issuer: "https://issuer.example", TokenEndpoint: "https://issuer.example/token", Scopes: atproto.VaultScopes(), State: atproto.SessionStateUsable, RefreshToken: "stored-refresh-token", DPoPPrivateKey: base64.RawURLEncoding.EncodeToString(der)}
	encoded, err := json.Marshal(envelope)
	require.NoError(t, err)
	keyring.items[cliSessionItemName()] = encoded
}

func cliSessionItemName() string {
	digest := sha256.Sum256([]byte(accountClientID + "\x00" + accountTestDID))
	return "session:" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func snapshotStateTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		value := fmt.Sprintf("%s|%o|%d|%d", relative, info.Mode().Perm(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(contents)
			value += "|" + base64.RawURLEncoding.EncodeToString(digest[:])
		}
		snapshot[relative] = value
		return nil
	})
	require.NoError(t, err)
	return snapshot
}
