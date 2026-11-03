package atproto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthMethodRejectsSessionBindingMismatch(t *testing.T) {
	_, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	for _, mutate := range []func(*Session){
		func(session *Session) { session.Issuer = "https://other.example" },
		func(session *Session) { session.TokenEndpoint = "https://other.example/token" },
		func(session *Session) { session.DID = "did:plc:zyxwvutsrqponmlkjihgfedc" },
	} {
		session := testAuthSession(t, identity, "access-token-shape")
		mutate(session)
		_, err := NewAuthMethod(client, identity, testHandle, session)
		assert.ErrorIs(t, err, ErrAuthMethodConfiguration)
	}
	_, err = NewAuthMethod(client, identity, "bob.example", testAuthSession(t, identity, "access-token-shape"))
	assert.ErrorIs(t, err, ErrAuthMethodConfiguration)
}

func TestAuthMethodRejectsSessionBindingChangeAfterConstruction(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	session.Issuer = "https://other.example"
	_, err = auth.DoWithAuth(client.HTTPClient, mustAuthRequest(t, "https://shard.example/resource"), syntax.NSID("com.atproto.sync.getBlob"))
	require.ErrorIs(t, err, ErrAuthMethodSession)
	require.Empty(t, fake.resourceRequests)
}

func TestAuthMethodRejectsHostBeforeRefreshingOrSending(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	for _, endpoint := range []string{"https://other.example/resource", "http://shard.example/resource"} {
		request, err := http.NewRequest(http.MethodGet, endpoint, nil)
		require.NoError(t, err)
		_, err = auth.DoWithAuth(client.HTTPClient, request, syntax.NSID("com.atproto.sync.getBlob"))
		assert.ErrorIs(t, err, ErrAuthMethodHost)
	}
	assert.Empty(t, fake.resourceRequests)
	assert.Equal(t, 0, fake.tokenRequests)
}

func TestAuthMethodNonceChallengeRetriesWithoutRefresh(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.resourceResponses = []fakeResourceResponse{
		{status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {`DPoP error="use_dpop_nonce"`}, "Dpop-Nonce": {"fresh-nonce"}}},
		{status: http.StatusNoContent},
	}
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	response := doAuthMethodRequest(t, auth, client.HTTPClient, "https://shard.example/resource?cid=abc")
	_ = response.Body.Close()
	assert.Equal(t, 0, fake.tokenRequests)
	require.Len(t, fake.resourceRequests, 2)
	first, err := readClaims(fake.resourceRequests[0].proof)
	require.NoError(t, err)
	second, err := readClaims(fake.resourceRequests[1].proof)
	require.NoError(t, err)
	assert.Equal(t, "fresh-nonce", second.Nonce)
	assert.NotEqual(t, first.JTI, second.JTI)
	assert.Equal(t, tokenHash("access-token-shape"), first.ATH)
	assert.Equal(t, tokenHash("access-token-shape"), second.ATH)
	assert.Equal(t, "DPoP access-token-shape", fake.resourceRequests[1].authorization)
}

func TestAuthMethodInvalidTokenRefreshesOnceAndRetries(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.tokenAccess = "rotated-access-token-shape"
	fake.tokenRefresh = "rotated-refresh-token-shape"
	fake.resourceResponses = []fakeResourceResponse{
		{status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {`DPoP error="invalid_token"`}}},
		{status: http.StatusNoContent},
	}
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "expired-access-token-shape")
	require.NoError(t, client.saveSession(context.Background(), session))
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	response := doAuthMethodRequest(t, auth, client.HTTPClient, "https://shard.example/resource")
	_ = response.Body.Close()
	assert.Equal(t, 1, fake.tokenRequests)
	require.Len(t, fake.resourceRequests, 2)
	assert.Equal(t, "DPoP expired-access-token-shape", fake.resourceRequests[0].authorization)
	assert.Equal(t, "DPoP rotated-access-token-shape", fake.resourceRequests[1].authorization)
	assert.Equal(t, "rotated-access-token-shape", session.AccessToken.Reveal())
	claims, err := readClaims(fake.resourceRequests[1].proof)
	require.NoError(t, err)
	assert.Equal(t, tokenHash("rotated-access-token-shape"), claims.ATH)
}

func TestAuthMethodRefreshesBeforeRequestWhenAccessTokenIsAbsent(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.tokenAccess = "loaded-access-token-shape"
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "")
	require.NoError(t, client.saveSession(context.Background(), session))
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	response := doAuthMethodRequest(t, auth, client.HTTPClient, "https://shard.example/resource")
	_ = response.Body.Close()
	assert.Equal(t, 1, fake.tokenRequests)
	require.Len(t, fake.resourceRequests, 1)
	assert.Equal(t, "DPoP loaded-access-token-shape", fake.resourceRequests[0].authorization)
}

func TestAuthMethodDoesNotRetryNonReplayableBody(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.resourceResponses = []fakeResourceResponse{{status: http.StatusBadRequest, header: http.Header{"Dpop-Nonce": {"body-nonce"}}, body: `{"error":"use_dpop_nonce"}`}}
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "https://shard.example/resource", io.NopCloser(strings.NewReader("payload")))
	require.NoError(t, err)
	request.GetBody = nil
	_, err = auth.DoWithAuth(client.HTTPClient, request, syntax.NSID("com.atproto.repo.createRecord"))
	assert.ErrorIs(t, err, ErrAuthMethodNonReplayable)
	assert.Len(t, fake.resourceRequests, 1)
	assert.Equal(t, 0, fake.tokenRequests)
}

func TestAuthMethodNeverExceedsTwoAttempts(t *testing.T) {
	challenge := fakeResourceResponse{status: http.StatusBadRequest, header: http.Header{"Www-Authenticate": {`DPoP error="use_dpop_nonce"`}, "Dpop-Nonce": {"challenge-nonce"}}}
	fake, client, _ := newFakeOAuth(t)
	fake.resourceResponses = []fakeResourceResponse{challenge, challenge, {status: http.StatusNoContent}}
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	auth, err := NewAuthMethod(client, identity, testHandle, testAuthSession(t, identity, "access-token-shape"))
	require.NoError(t, err)
	_, err = auth.DoWithAuth(client.HTTPClient, mustAuthRequest(t, "https://shard.example/resource"), syntax.NSID("com.atproto.sync.getBlob"))
	require.ErrorIs(t, err, ErrAuthMethodNonce)
	require.Len(t, fake.resourceRequests, 2)
	var typed *AuthMethodError
	require.ErrorAs(t, err, &typed)
}

func TestAuthMethodRefusesPDSRelocationBeforeRefreshRequest(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "")
	require.NoError(t, client.saveSession(context.Background(), session))
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	fake.pds = "https://new-shard.example"
	fake.resource = fake.pds
	fake.tokenAccess = "relocated-access-token"
	_, err = auth.DoWithAuth(client.HTTPClient, mustAuthRequest(t, "https://shard.example/resource"), syntax.NSID("com.atproto.sync.getBlob"))
	require.ErrorIs(t, err, ErrAuthMethodRelocated)
	assert.Empty(t, fake.resourceRequests)
	assert.Equal(t, 1, fake.tokenRequests)
	stored, err := client.LoadSession(context.Background(), testDID)
	require.NoError(t, err)
	assert.Equal(t, "refresh-secret-value", stored.RefreshToken.Reveal())
	assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, testDID)))
}

func TestAuthMethodRefusesPDSRelocationAfterInvalidTokenBeforeRetry(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.resourceResponses = []fakeResourceResponse{{status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {`DPoP error="invalid_token"`}}}}
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, "stale-access-token")
	require.NoError(t, client.saveSession(context.Background(), session))
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	require.NoError(t, err)
	fake.afterResourceRequest = func(index int) {
		if index == 0 {
			fake.pds = "https://new-shard.example"
			fake.resource = fake.pds
		}
	}
	_, err = auth.DoWithAuth(client.HTTPClient, mustAuthRequest(t, "https://shard.example/resource"), syntax.NSID("com.atproto.sync.getBlob"))
	require.ErrorIs(t, err, ErrAuthMethodRelocated)
	require.Len(t, fake.resourceRequests, 1)
	assert.Equal(t, "shard.example", fake.resourceRequests[0].host)
	assert.Equal(t, 1, fake.tokenRequests)
}

func testAuthSession(t *testing.T, identity Identity, accessToken string) *Session {
	t.Helper()
	key, err := marshalPrivateKey(generateTestKey(t))
	require.NoError(t, err)
	return &Session{
		DID:            identity.DID,
		Handle:         identity.Handle,
		Issuer:         identity.Issuer,
		TokenEndpoint:  identity.TokenEndpoint,
		Scopes:         []string{"atproto"},
		AccessToken:    NewSecret(accessToken),
		RefreshToken:   NewSecret("refresh-token-shape"),
		DPoPPrivateKey: key,
	}
}

func doAuthMethodRequest(t *testing.T, auth interface {
	DoWithAuth(*http.Client, *http.Request, syntax.NSID) (*http.Response, error)
}, client *http.Client, endpoint string) *http.Response {
	t.Helper()
	response, err := auth.DoWithAuth(client, mustAuthRequest(t, endpoint), syntax.NSID("com.atproto.sync.getBlob"))
	require.NoError(t, err)
	return response
}

func mustAuthRequest(t *testing.T, endpoint string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	return request
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
