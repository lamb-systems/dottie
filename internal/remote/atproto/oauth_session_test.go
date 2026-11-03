package atproto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"syscall"
	"testing"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storedRefreshSession(t *testing.T, client *Client) *Session {
	t.Helper()
	privateKey, err := marshalPrivateKey(generateTestKey(t))
	require.NoError(t, err)
	session := &Session{
		DID:            testDID,
		Handle:         testHandle,
		Issuer:         "https://bsky.social",
		TokenEndpoint:  "https://bsky.social/token",
		Scopes:         VaultScopes(),
		State:          SessionStateUsable,
		AccessToken:    NewSecret("expired-access-token"),
		RefreshToken:   NewSecret("original-refresh-token"),
		DPoPPrivateKey: privateKey,
	}
	require.NoError(t, client.saveSession(context.Background(), session))
	return session
}

func TestRefreshPersistsPendingBeforeTokenRequest(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	name := sessionItemName(client.ClientID, testDID)
	fake.pendingCheck = func() bool {
		var envelope sessionEnvelope
		err := json.Unmarshal(store.raw(name), &envelope)
		return err == nil && envelope.State == SessionStateRefreshPending && envelope.RefreshToken == "" && envelope.DPoPPrivateKey == ""
	}
	fake.tokenRefresh = "rotated-refresh-token"
	fake.rejectRefreshReuse = true
	refreshed, _, err := client.Refresh(context.Background(), testHandle, session)
	require.NoError(t, err)
	assert.True(t, fake.pendingAtToken)
	assert.Equal(t, []string{"original-refresh-token"}, fake.presentedRefreshTokens)
	assert.Equal(t, "rotated-refresh-token", refreshed.RefreshToken.Reveal())
	status, err := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, err)
	assert.Equal(t, SessionStateUsable, status.State)
}

func TestRefreshPendingMarkerSaveFailureSendsNoToken(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	name := sessionItemName(client.ClientID, testDID)
	original := store.raw(name)
	store.saveHook = func(_ string, payload []byte) error {
		var envelope sessionEnvelope
		if json.Unmarshal(payload, &envelope) == nil && envelope.State == SessionStateRefreshPending {
			return errors.New("synthetic save failure")
		}
		return nil
	}
	_, _, err := client.Refresh(context.Background(), testHandle, session)
	require.Error(t, err)
	assert.Equal(t, 0, fake.tokenRequests)
	assert.Equal(t, original, store.raw(name))
	status, statusErr := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, statusErr)
	assert.Equal(t, SessionStateUsable, status.State)
}

func TestRefreshFinalSaveFailureLeavesPendingAndForbidsReplay(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	fake.tokenRefresh = "rotated-refresh-token"
	fake.rejectRefreshReuse = true
	store.saveHook = func(_ string, payload []byte) error {
		var envelope sessionEnvelope
		if json.Unmarshal(payload, &envelope) == nil && envelope.State == SessionStateUsable && envelope.RefreshToken == "rotated-refresh-token" {
			return errors.New("synthetic final save failure")
		}
		return nil
	}
	_, _, err := client.Refresh(context.Background(), testHandle, session)
	require.Error(t, err)
	status, err := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, err)
	assert.Equal(t, SessionStateRefreshPending, status.State)
	_, _, err = client.Refresh(context.Background(), testHandle, session)
	require.ErrorIs(t, err, ErrSessionRefreshPending)
	assert.Equal(t, 1, fake.tokenRequests)
	assert.Equal(t, []string{"original-refresh-token"}, fake.presentedRefreshTokens)
}

func TestRefreshConsumedTokenWithLostResponseLeavesPending(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	fake.rejectRefreshReuse = true
	fake.tokenRefresh = "unreachable-rotated-token"
	base := client.HTTPClient.Transport
	client.HTTPClient.Transport = loseResponseTransport{base: base, path: "/token"}
	_, _, err := client.Refresh(context.Background(), testHandle, session)
	require.Error(t, err)
	assert.Equal(t, []string{"original-refresh-token"}, fake.presentedRefreshTokens)
	status, statusErr := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, statusErr)
	assert.Equal(t, SessionStateRefreshPending, status.State)
	client.HTTPClient.Transport = base
	_, _, err = client.Refresh(context.Background(), testHandle, session)
	require.ErrorIs(t, err, ErrSessionRefreshPending)
	assert.Equal(t, []string{"original-refresh-token"}, fake.presentedRefreshTokens)
	assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, testDID)))
}

func TestRefreshPostWriteFailureLeavesPending(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	fake.tokenStatus = http.StatusInternalServerError
	_, _, err := client.Refresh(context.Background(), testHandle, session)
	require.Error(t, err)
	var endpointError *OAuthEndpointError
	require.ErrorAs(t, err, &endpointError)
	assert.Equal(t, http.StatusInternalServerError, endpointError.Status)
	status, statusErr := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, statusErr)
	assert.Equal(t, SessionStateRefreshPending, status.State)
	assert.Equal(t, 1, fake.tokenRequests)
	assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, testDID)))
}

func TestRefreshReloadsEnvelopeAfterAcquiringLock(t *testing.T) {
	fake, originalClient, store := newFakeOAuth(t)
	oldSession := storedRefreshSession(t, originalClient)
	entered := make(chan struct{})
	continueRefresh := make(chan struct{})
	var once sync.Once
	client, err := NewClient(originalClient.ClientID, store,
		WithHTTPClient(originalClient.HTTPClient),
		WithClock(originalClient.Clock),
		WithRandom(&counterReader{}),
		WithTXTLookup(func(context.Context, string) ([]string, error) { return nil, errors.New("unused") }),
		WithSessionLock(func(ctx context.Context, _ string) (func() error, error) {
			once.Do(func() { close(entered) })
			select {
			case <-continueRefresh:
				return func() error { return nil }, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
	)
	require.NoError(t, err)
	fake.rejectRefreshReuse = true
	fake.tokenRefresh = "newest-token-rotated"
	done := make(chan error, 1)
	go func() {
		_, _, refreshErr := client.Refresh(context.Background(), testHandle, oldSession)
		done <- refreshErr
	}()
	<-entered
	newest := *oldSession
	newest.RefreshToken = NewSecret("concurrently-rotated-token")
	newest.DPoPPrivateKey = oldSession.DPoPPrivateKey
	require.NoError(t, client.saveSession(context.Background(), &newest))
	close(continueRefresh)
	assert.NoError(t, <-done)
	assert.Equal(t, []string{"concurrently-rotated-token"}, fake.presentedRefreshTokens)
	assert.Equal(t, "newest-token-rotated", fake.tokenRefresh)
}

func TestRefreshBusyLockDoesNotWriteOrSend(t *testing.T) {
	fake, baseClient, store := newFakeOAuth(t)
	session := storedRefreshSession(t, baseClient)
	original := store.raw(sessionItemName(baseClient.ClientID, testDID))
	client, err := NewClient(baseClient.ClientID, store,
		WithHTTPClient(baseClient.HTTPClient), WithClock(baseClient.Clock), WithRandom(&counterReader{}),
		WithSessionLock(func(context.Context, string) (func() error, error) { return nil, ErrSessionBusy }))
	require.NoError(t, err)
	_, _, err = client.Refresh(context.Background(), testHandle, session)
	require.ErrorIs(t, err, ErrSessionBusy)
	assert.Equal(t, 0, fake.tokenRequests)
	assert.Equal(t, original, store.raw(sessionItemName(client.ClientID, testDID)))
}

func TestRefreshComposesWithRealFileLockAndReload(t *testing.T) {
	fake, baseClient, store := newFakeOAuth(t)
	session := storedRefreshSession(t, baseClient)
	lockPath := t.TempDir() + "/session.lock"
	lockFunc := func(_ context.Context, _ string) (func() error, error) {
		lock, err := platform.LockFile(lockPath)
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrSessionBusy
		}
		if err != nil {
			return nil, err
		}
		return lock.Close, nil
	}
	client, err := NewClient(baseClient.ClientID, store, WithHTTPClient(baseClient.HTTPClient), WithClock(baseClient.Clock), WithRandom(&counterReader{}), WithSessionLock(lockFunc))
	require.NoError(t, err)
	lock, err := platform.LockFile(lockPath)
	require.NoError(t, err)
	before := store.raw(sessionItemName(client.ClientID, testDID))
	_, _, err = client.Refresh(context.Background(), testHandle, session)
	require.ErrorIs(t, err, ErrSessionBusy)
	assert.Equal(t, 0, fake.tokenRequests)
	assert.Equal(t, before, store.raw(sessionItemName(client.ClientID, testDID)))
	rotated := *session
	rotated.RefreshToken = NewSecret("file-lock-rotated-token")
	require.NoError(t, client.saveSession(context.Background(), &rotated))
	require.NoError(t, lock.Close())
	fake.rejectRefreshReuse = true
	fake.tokenRefresh = "file-lock-next-token"
	_, _, err = client.Refresh(context.Background(), testHandle, session)
	require.NoError(t, err)
	assert.Equal(t, []string{"file-lock-rotated-token"}, fake.presentedRefreshTokens)
}

type loseResponseTransport struct {
	base http.RoundTripper
	path string
}

func (l loseResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host == issuerHost && request.URL.Path == l.path {
		response, err := l.base.RoundTrip(request)
		if err == nil && response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errors.New("synthetic lost response")
	}
	return l.base.RoundTrip(request)
}

func TestFlowWaitCancellationAfterCallbackSelectionDoesNotExchange(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	flow, err := client.Begin(context.Background(), testHandle, VaultScopes(), VaultScopes())
	require.NoError(t, err)
	defer flow.Close()
	flow.callback <- callbackResult{code: NewSecret("single-use-code")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = flow.Wait(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, err.Error(), "authorization canceled")
	assert.NotContains(t, err.Error(), "timed out")
	assert.Equal(t, 0, fake.tokenRequests)
	assert.Empty(t, store.items)
}

func TestFlowCancellationAfterTokenResponseStoresNothing(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	flow, err := client.Begin(context.Background(), testHandle, VaultScopes(), VaultScopes())
	require.NoError(t, err)
	defer flow.Close()
	ctx, cancel := context.WithCancel(context.Background())
	flow.callback <- callbackResult{code: NewSecret("single-use-code")}
	client.HTTPClient.Transport = cancelAfterResponseTransport{base: client.HTTPClient.Transport, cancel: cancel, path: "/token"}
	_, err = flow.Wait(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, err.Error(), "authorization canceled")
	assert.NotContains(t, err.Error(), "timed out")
	assert.Equal(t, 1, fake.tokenRequests)
	assert.Empty(t, store.items)
}

type cancelAfterResponseTransport struct {
	base   http.RoundTripper
	cancel context.CancelFunc
	path   string
}

func (c cancelAfterResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := c.base.RoundTrip(request)
	if err != nil || request.URL.Path != c.path {
		return response, err
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	c.cancel()
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

func TestSessionEnvelopeRetainsHandleStateAndAcceptsLegacyWithoutHandle(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	status, err := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, err)
	assert.Equal(t, testHandle, status.Handle)
	assert.Equal(t, SessionStateUsable, status.State)
	assert.Len(t, status.Scopes, 9)
	var envelope sessionEnvelope
	require.NoError(t, json.Unmarshal(store.raw(sessionItemName(client.ClientID, testDID)), &envelope))
	assert.Equal(t, testHandle, envelope.Handle)
	assert.Equal(t, SessionStateUsable, envelope.State)
	assert.NotContains(t, string(store.raw(sessionItemName(client.ClientID, testDID))), "expired-access-token")

	legacy := *session
	legacy.Handle = ""
	legacy.State = ""
	require.NoError(t, client.saveSession(context.Background(), &legacy))
	loaded, err := client.LoadSession(context.Background(), testDID)
	require.NoError(t, err)
	assert.Empty(t, loaded.Handle)
	fake.tokenRefresh = "legacy-rotated-token"
	_, identity, err := client.Refresh(context.Background(), testHandle, loaded)
	require.NoError(t, err)
	assert.Equal(t, testDID, identity.DID)

	pending := sessionEnvelope{Version: sessionEnvelopeVersion, DID: testDID, Issuer: session.Issuer, TokenEndpoint: session.TokenEndpoint, Scopes: session.Scopes, State: SessionStateRefreshPending}
	pendingBytes, err := json.Marshal(pending)
	require.NoError(t, err)
	require.NoError(t, store.Save(context.Background(), sessionItemName(client.ClientID, testDID), pendingBytes))
	_, err = client.LoadSession(context.Background(), testDID)
	require.ErrorIs(t, err, ErrSessionRefreshPending)
	_, err = client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, err)
}

func TestLoadSessionStatusPropagatesKeyringFailureAndRejectsCorruptState(t *testing.T) {
	_, client, store := newFakeOAuth(t)
	for _, keyringErr := range []error{platform.ErrKeyringLocked, platform.ErrKeyringUnavailable} {
		store.loadErr = keyringErr
		_, err := client.LoadSessionStatus(context.Background(), testDID)
		assert.ErrorIs(t, err, keyringErr)
	}
	store.loadErr = nil
	require.NoError(t, store.Save(context.Background(), sessionItemName(client.ClientID, testDID), []byte(`{"version":99}`)))
	_, err := client.LoadSessionStatus(context.Background(), testDID)
	require.ErrorIs(t, err, ErrSessionUnavailable)
}

func TestSessionStatusContainsNoSecrets(t *testing.T) {
	_, client, _ := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	status, err := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, err)
	encoded, err := json.Marshal(status)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), session.RefreshToken.Reveal())
	assert.NotContains(t, string(encoded), session.DPoPPrivateKey.Reveal())
	assert.NotContains(t, string(encoded), "expired-access-token")
}

func TestRefreshCancellationAfterTokenResponseLeavesPending(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	ctx, cancel := context.WithCancel(context.Background())
	client.HTTPClient.Transport = cancelAfterResponseTransport{base: client.HTTPClient.Transport, cancel: cancel, path: "/token"}
	_, _, err := client.Refresh(ctx, testHandle, session)
	require.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, err.Error(), "authorization canceled")
	assert.NotContains(t, err.Error(), "timed out")
	assert.Equal(t, 1, fake.tokenRequests)
	status, statusErr := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, statusErr)
	assert.Equal(t, SessionStateRefreshPending, status.State)
	assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, testDID)))
}

func TestRefreshKeyringFailuresRemainTypedAndFailClosed(t *testing.T) {
	t.Run("load", func(t *testing.T) {
		fake, client, store := newFakeOAuth(t)
		session := storedRefreshSession(t, client)
		store.loadErr = platform.ErrKeyringLocked
		_, _, err := client.Refresh(context.Background(), testHandle, session)
		require.ErrorIs(t, err, platform.ErrKeyringLocked)
		assert.Equal(t, 0, fake.tokenRequests)
	})
	t.Run("pending marker save", func(t *testing.T) {
		fake, client, store := newFakeOAuth(t)
		session := storedRefreshSession(t, client)
		store.saveHook = func(_ string, payload []byte) error {
			var envelope sessionEnvelope
			if json.Unmarshal(payload, &envelope) == nil && envelope.State == SessionStateRefreshPending {
				return platform.ErrKeyringUnavailable
			}
			return nil
		}
		_, _, err := client.Refresh(context.Background(), testHandle, session)
		require.ErrorIs(t, err, platform.ErrKeyringUnavailable)
		assert.Equal(t, 0, fake.tokenRequests)
	})
	t.Run("final save", func(t *testing.T) {
		fake, client, store := newFakeOAuth(t)
		session := storedRefreshSession(t, client)
		store.saveHook = func(_ string, payload []byte) error {
			var envelope sessionEnvelope
			if json.Unmarshal(payload, &envelope) == nil && envelope.State == SessionStateUsable && envelope.RefreshToken != "original-refresh-token" {
				return platform.ErrKeyringUnavailable
			}
			return nil
		}
		_, _, err := client.Refresh(context.Background(), testHandle, session)
		require.ErrorIs(t, err, platform.ErrKeyringUnavailable)
		assert.Equal(t, 1, fake.tokenRequests)
		status, statusErr := client.LoadSessionStatus(context.Background(), testDID)
		require.NoError(t, statusErr)
		assert.Equal(t, SessionStateRefreshPending, status.State)
	})
}

func TestRefreshFinalSaveUncertaintyLeavesNewUsableEnvelope(t *testing.T) {
	fake, baseClient, memory := newFakeOAuth(t)
	client, err := NewClient(baseClient.ClientID, appliedThenFailStore{
		memoryStore: memory,
		err:         errors.New("synthetic lost reply"),
		match: func(payload []byte) bool {
			var envelope sessionEnvelope
			return json.Unmarshal(payload, &envelope) == nil && envelope.State == SessionStateUsable && envelope.RefreshToken == "rotated-refresh-token"
		},
	}, WithHTTPClient(baseClient.HTTPClient), WithClock(baseClient.Clock), WithRandom(&counterReader{}),
		WithTXTLookup(func(context.Context, string) ([]string, error) { return nil, errors.New("unused") }))
	require.NoError(t, err)
	session := storedRefreshSession(t, client)
	fake.rejectRefreshReuse = true
	fake.tokenRefresh = "rotated-refresh-token"
	_, _, err = client.Refresh(context.Background(), testHandle, session)
	require.ErrorIs(t, err, ErrSessionPersistenceUncertain)
	assert.NotContains(t, err.Error(), "original-refresh-token")
	assert.NotContains(t, err.Error(), "rotated-refresh-token")
	status, statusErr := client.LoadSessionStatus(context.Background(), testDID)
	require.NoError(t, statusErr)
	assert.Equal(t, SessionStateUsable, status.State)
	loaded, loadErr := client.LoadSession(context.Background(), testDID)
	require.NoError(t, loadErr)
	assert.Equal(t, "rotated-refresh-token", loaded.RefreshToken.Reveal())
	fake.tokenRefresh = "second-rotated-token"
	_, _, err = client.Refresh(context.Background(), testHandle, loaded)
	require.NoError(t, err)
	assert.Equal(t, []string{"original-refresh-token", "rotated-refresh-token"}, fake.presentedRefreshTokens)
}
