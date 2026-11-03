package atproto

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPARFailureStoresNothing(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	fake.parStatus = http.StatusBadRequest
	_, err := client.Begin(context.Background(), testHandle, VaultScopes(), VaultScopes())
	require.Error(t, err)
	var endpointError *OAuthEndpointError
	require.ErrorAs(t, err, &endpointError)
	assert.Equal(t, http.StatusBadRequest, endpointError.Status)
	assert.Equal(t, "invalid_request", endpointError.Code)
	assert.Empty(t, store.items)
	assert.Equal(t, 0, fake.tokenRequests)
}

func TestTokenInvalidGrantErrorIsSanitized(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	secret := "submitted-authorization-code-secret"
	fake.tokenStatus = http.StatusBadRequest
	fake.tokenErrorBody = `{"error":"invalid_grant","error_description":"` + secret + `"}`
	flow, err := client.Begin(context.Background(), testHandle, VaultScopes(), VaultScopes())
	require.NoError(t, err)
	defer flow.Close()
	callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {secret}})
	_, err = flow.Wait(context.Background())
	require.Error(t, err)
	var endpointError *OAuthEndpointError
	require.ErrorAs(t, err, &endpointError)
	assert.Equal(t, http.StatusBadRequest, endpointError.Status)
	assert.Equal(t, "invalid_grant", endpointError.Code)
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, err.Error(), "error_description")
	assert.Empty(t, store.items)
	assert.Equal(t, 1, fake.tokenRequests)
}

func TestTokenInvalidJSONStoresNothing(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	fake.tokenStatus = http.StatusOK
	fake.tokenErrorBody = "not-json"
	flow, err := client.Begin(context.Background(), testHandle, VaultScopes(), VaultScopes())
	require.NoError(t, err)
	defer flow.Close()
	flow.callback <- callbackResult{code: NewSecret("code")}
	_, err = flow.Wait(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
	assert.Empty(t, store.items)
	assert.Equal(t, 1, fake.tokenRequests)
}

func TestCallbackAttemptLimitStoresNothing(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	client.callbackAttempts = 1
	flow, err := client.Begin(context.Background(), testHandle, VaultScopes(), VaultScopes())
	require.NoError(t, err)
	defer flow.Close()
	for range 2 {
		request := httptest.NewRequest(http.MethodGet, "/callback?state=wrong&iss=https%3A%2F%2Fbsky.social&code=code", nil)
		flow.serveCallback(httptest.NewRecorder(), request)
	}
	_, err = flow.Wait(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attempt limit")
	assert.Empty(t, store.items)
	assert.Equal(t, 0, fake.tokenRequests)
}

func TestOAuthEndpointErrorCodeAllowList(t *testing.T) {
	for _, test := range []struct {
		body string
		want string
	}{
		{body: `{"error":"invalid_grant","error_description":"secret"}`, want: "invalid_grant"},
		{body: `{"error":"use_dpop_nonce"}`, want: "use_dpop_nonce"},
		{body: `{"error":"secret-value"}`, want: ""},
		{body: `{"error":"invalid_grant\u001b[31m"}`, want: ""},
		{body: strings.Repeat("x", 100), want: ""},
	} {
		assert.Equal(t, test.want, sanitizedOAuthCode([]byte(test.body)))
	}
}

type appliedThenFailStore struct {
	*memoryStore
	err   error
	match func([]byte) bool
}

func (s appliedThenFailStore) Save(ctx context.Context, name string, payload []byte) error {
	if err := s.memoryStore.Save(ctx, name, payload); err != nil {
		return err
	}
	if s.match == nil || s.match(payload) {
		return s.err
	}
	return nil
}

func TestLoginPersistenceErrorIsUncertainAndLeavesItem(t *testing.T) {
	fake, baseClient, store := newFakeOAuth(t)
	client, err := NewClient(baseClient.ClientID, appliedThenFailStore{memoryStore: store, err: errors.New("synthetic lost reply")},
		WithHTTPClient(baseClient.HTTPClient), WithClock(baseClient.Clock), WithRandom(&counterReader{}),
		WithTXTLookup(func(context.Context, string) ([]string, error) { return nil, errors.New("unused") }))
	require.NoError(t, err)
	flow, err := client.Begin(context.Background(), testHandle, VaultScopes(), VaultScopes())
	require.NoError(t, err)
	defer flow.Close()
	callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {"single-use-code"}})
	_, err = flow.Wait(context.Background())
	require.ErrorIs(t, err, ErrSessionPersistenceUncertain)
	assert.NotContains(t, err.Error(), "single-use-code")
	assert.Equal(t, 1, fake.tokenRequests)
	assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, testDID)))
}
