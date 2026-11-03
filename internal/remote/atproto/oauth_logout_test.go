package atproto

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalLogoutDeletesEnvelopesWithoutParsingOrNetwork(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	name := sessionItemName(client.ClientID, testDID)
	pendingBytes, err := json.Marshal(sessionEnvelope{Version: sessionEnvelopeVersion, DID: testDID, Issuer: "https://bsky.social", TokenEndpoint: "https://bsky.social/token", Scopes: VaultScopes(), State: SessionStateRefreshPending})
	require.NoError(t, err)
	for _, encoded := range [][]byte{
		[]byte("not-json"),
		[]byte(`{"version":99,"did":"` + testDID + `"}`),
		pendingBytes,
	} {
		require.NoError(t, store.Save(context.Background(), name, encoded))
		result, logoutErr := client.Logout(context.Background(), testDID, "", nil, false)
		require.NoError(t, logoutErr)
		assert.True(t, result.LocalDeleted)
		assert.Empty(t, store.raw(name))
	}
	session := storedRefreshSession(t, client)
	result, err := client.Logout(context.Background(), testDID, "", session, false)
	require.NoError(t, err)
	assert.True(t, result.LocalDeleted)
	assert.Empty(t, store.raw(name))
	assert.Equal(t, 0, fake.tokenRequests)
	assert.Empty(t, fake.revocationRequests)
}

func TestRemoteLogoutRevokesLatestRefreshTokenThenDeletes(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	stale := storedRefreshSession(t, client)
	latest := *stale
	latest.RefreshToken = NewSecret("latest-refresh-token")
	require.NoError(t, client.saveSession(context.Background(), &latest))
	result, err := client.Logout(context.Background(), testDID, testHandle, stale, true)
	require.NoError(t, err)
	assert.True(t, result.RemoteRevocationAccepted)
	assert.True(t, result.LocalDeleted)
	require.Len(t, fake.revocationRequests, 1)
	request := fake.revocationRequests[0]
	assert.Equal(t, "latest-refresh-token", request.form.Get("token"))
	assert.Equal(t, "refresh_token", request.form.Get("token_type_hint"))
	assert.Equal(t, client.ClientID, request.form.Get("client_id"))
	assert.Empty(t, request.authorization)
	claims, err := readClaims(request.proof)
	require.NoError(t, err)
	assert.Empty(t, claims.ATH)
	assert.Empty(t, request.form.Get("access_token"))
	assert.Empty(t, store.raw(sessionItemName(client.ClientID, testDID)))
}

func TestRemoteLogoutRequiresSupportedEndpointAndUsableSession(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	fake.revocationEndpoint = ""
	result, err := client.Logout(context.Background(), testDID, testHandle, session, true)
	require.ErrorIs(t, err, ErrRevocationUnsupported)
	assert.False(t, result.RemoteRevocationAccepted)
	assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, testDID)))
	assert.Empty(t, fake.revocationRequests)

	fake.revocationEndpoint = "https://bsky.social/revoke?unsafe=1"
	_, err = client.Discover(context.Background(), testHandle)
	require.Error(t, err)
}

func TestRemoteLogoutPendingFailureAndRelocationKeepLocalSession(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	name := sessionItemName(client.ClientID, testDID)
	pending := sessionEnvelope{Version: sessionEnvelopeVersion, DID: testDID, Handle: testHandle, Issuer: session.Issuer, TokenEndpoint: session.TokenEndpoint, Scopes: session.Scopes, State: SessionStateRefreshPending}
	pendingBytes, err := json.Marshal(pending)
	require.NoError(t, err)
	require.NoError(t, store.Save(context.Background(), name, pendingBytes))
	_, err = client.Logout(context.Background(), testDID, testHandle, session, true)
	require.ErrorIs(t, err, ErrSessionRefreshPending)
	assert.Empty(t, fake.revocationRequests)

	require.NoError(t, client.saveSession(context.Background(), session))
	fake.revocationResponses = []fakeResourceResponse{{status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"private detail"}`}}
	_, err = client.Logout(context.Background(), testDID, testHandle, session, true)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "private detail")
	assert.NotEmpty(t, store.raw(name))

	fake.revocationResponses = nil
	fake.metadataIssuer = "https://changed.example"
	_, err = client.Logout(context.Background(), testDID, testHandle, session, true)
	require.Error(t, err)
	assert.NotEmpty(t, store.raw(name))
}

func TestRemoteLogoutReportsAcceptedRequestWhenLocalDeleteFails(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	store.deleteErr = errors.New("synthetic delete failure")
	result, err := client.Logout(context.Background(), testDID, testHandle, session, true)
	require.Error(t, err)
	assert.True(t, result.RemoteRevocationAccepted)
	assert.False(t, result.LocalDeleted)
	assert.Contains(t, err.Error(), "request accepted")
	assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, testDID)))
	assert.Len(t, fake.revocationRequests, 1)
}

func TestRevocationDPoPNonceRetryAcceptsEmptySuccess(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	fake.revocationResponses = []fakeResourceResponse{
		{status: http.StatusBadRequest, header: http.Header{"Dpop-Nonce": {"revocation-nonce"}}, body: `{"error":"use_dpop_nonce"}`},
		{status: http.StatusNoContent},
	}
	result, err := client.Logout(context.Background(), testDID, testHandle, session, true)
	require.NoError(t, err)
	assert.True(t, result.RemoteRevocationAccepted)
	assert.True(t, result.LocalDeleted)
	require.Len(t, fake.revocationRequests, 2)
	first, err := readClaims(fake.revocationRequests[0].proof)
	require.NoError(t, err)
	second, err := readClaims(fake.revocationRequests[1].proof)
	require.NoError(t, err)
	assert.Empty(t, first.ATH)
	assert.Empty(t, second.ATH)
	assert.Equal(t, "revocation-nonce", second.Nonce)
	assert.NotEqual(t, first.JTI, second.JTI)
	assert.Empty(t, fake.revocationRequests[1].authorization)
	assert.Empty(t, store.raw(sessionItemName(client.ClientID, testDID)))
}

func TestRevocationErrorOnlyContainsStatusAndSafeCode(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	secret := "refresh-token-that-must-not-leak"
	session.RefreshToken = NewSecret(secret)
	require.NoError(t, client.saveSession(context.Background(), session))
	fake.revocationResponses = []fakeResourceResponse{{status: http.StatusBadRequest, body: `{"error":"provider-echo","error_description":"` + secret + `"}`}}
	_, err := client.Logout(context.Background(), testDID, testHandle, session, true)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, err.Error(), "provider-echo")
	var endpointError *OAuthEndpointError
	require.ErrorAs(t, err, &endpointError)
	assert.Equal(t, http.StatusBadRequest, endpointError.Status)
	assert.Empty(t, endpointError.Code)
}

func TestRemoteLogoutUsesHandleResolvedIdentity(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	result, err := client.Logout(context.Background(), testDID, "", session, true)
	require.NoError(t, err)
	assert.True(t, result.RemoteRevocationAccepted)
	assert.True(t, result.LocalDeleted)
	assert.Empty(t, store.raw(sessionItemName(client.ClientID, testDID)))
	assert.Len(t, fake.revocationRequests, 1)
}

func TestRemoteLogoutPOSTIsBoundToValidatedRevocationEndpoint(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	session := storedRefreshSession(t, client)
	fake.revocationEndpoint = "http://bsky.social/revoke"
	_, err := client.Logout(context.Background(), testDID, testHandle, session, true)
	require.Error(t, err)
	assert.Empty(t, fake.revocationRequests)
	assert.NotContains(t, err.Error(), "refresh-token-that-must-not-leak")
}
