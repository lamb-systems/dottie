package atproto

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionAPIClientPinsOriginAndUsesSessionAuth(t *testing.T) {
	fake, client, identity, session, roundTripper := sessionClientFixture(t, "access-token-shape")
	api, err := newSessionAPIClient(client, identity, testHandle, session, roundTripper)
	require.NoError(t, err)
	assert.Equal(t, "https://shard.example", api.Host)
	assert.NotNil(t, api.Auth)

	request, err := http.NewRequest(http.MethodGet, "https://other.example/resource", nil)
	require.NoError(t, err)
	_, err = api.Client.Do(request)
	require.ErrorIs(t, err, ErrAuthMethodHost)
	assert.Empty(t, fake.resourceRequests)

	request, err = http.NewRequest(http.MethodGet, "https://shard.example/resource", nil)
	require.NoError(t, err)
	_, err = api.Auth.DoWithAuth(api.Client, request, syntax.NSID("com.atproto.sync.getBlob"))
	require.NoError(t, err)
	assert.Len(t, fake.resourceRequests, 1)
}

func TestNewSessionAPIClientRefreshesStoredSessionBeforeRequest(t *testing.T) {
	fake, client, identity, session, roundTripper := sessionClientFixture(t, "")
	require.NoError(t, client.saveSession(context.Background(), session))
	stored, err := client.LoadSession(context.Background(), identity.DID)
	require.NoError(t, err)
	assert.Empty(t, stored.AccessToken.Reveal())

	api, err := newSessionAPIClient(client, identity, testHandle, stored, roundTripper)
	require.NoError(t, err)
	response := doSessionAPIRequest(t, api, "https://shard.example/resource")
	assert.NoError(t, response.Body.Close())
	assert.Equal(t, 1, fake.tokenRequests)
	require.Len(t, fake.resourceRequests, 1)
	assert.Equal(t, "DPoP access-secret-value", fake.resourceRequests[0].authorization)
}

func TestNewSessionAPIClientUsesOneBoundedInvalidTokenRetry(t *testing.T) {
	fake, client, identity, session, roundTripper := sessionClientFixture(t, "expired-access-token-shape")
	fake.tokenAccess = "rotated-access-token-shape"
	fake.resourceResponses = []fakeResourceResponse{
		{status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {`DPoP error="invalid_token"`}}},
		{status: http.StatusNoContent},
		{status: http.StatusNoContent},
	}
	require.NoError(t, client.saveSession(context.Background(), session))
	api, err := newSessionAPIClient(client, identity, testHandle, session, roundTripper)
	require.NoError(t, err)
	response := doSessionAPIRequest(t, api, "https://shard.example/resource")
	assert.NoError(t, response.Body.Close())
	assert.Equal(t, 1, fake.tokenRequests)
	require.Len(t, fake.resourceRequests, 2)
	assert.Equal(t, "DPoP expired-access-token-shape", fake.resourceRequests[0].authorization)
	assert.Equal(t, "DPoP rotated-access-token-shape", fake.resourceRequests[1].authorization)
}

func TestNewSessionAPIClientRefusesNonReplayableChallengeBody(t *testing.T) {
	fake, client, identity, session, roundTripper := sessionClientFixture(t, "access-token-shape")
	fake.resourceResponses = []fakeResourceResponse{{status: http.StatusBadRequest, header: http.Header{"Dpop-Nonce": {"fresh-nonce"}}, body: `{"error":"use_dpop_nonce"}`}}
	api, err := newSessionAPIClient(client, identity, testHandle, session, roundTripper)
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "https://shard.example/resource", io.NopCloser(strings.NewReader("synthetic body")))
	require.NoError(t, err)
	request.GetBody = nil
	_, err = api.Auth.DoWithAuth(api.Client, request, syntax.NSID("com.atproto.repo.applyWrites"))
	require.ErrorIs(t, err, ErrAuthMethodNonReplayable)
	assert.Len(t, fake.resourceRequests, 1)
	assert.Equal(t, 0, fake.tokenRequests)
}

func TestNewSessionAPIClientRedactsTransportErrors(t *testing.T) {
	_, client, identity, session, _ := sessionClientFixture(t, "access-secret-never-returned")
	api, err := newSessionAPIClient(client, identity, testHandle, session, errorSessionRoundTripper{})
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodGet, "https://shard.example/resource", nil)
	require.NoError(t, err)
	_, err = api.Auth.DoWithAuth(api.Client, request, syntax.NSID("com.atproto.sync.getBlob"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "access-secret-never-returned")
	assert.NotContains(t, err.Error(), "refresh-secret-value")
	assert.NotContains(t, err.Error(), "dpop-private")
}

func sessionClientFixture(t *testing.T, accessToken string) (*fakeOAuth, *Client, Identity, *Session, http.RoundTripper) {
	t.Helper()
	fake, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	require.NoError(t, err)
	session := testAuthSession(t, identity, accessToken)
	serverURL, err := url.Parse(fake.server.URL)
	require.NoError(t, err)
	roundTripper := &rewriteTransport{server: serverURL, transport: fake.server.Client().Transport.(*http.Transport)}
	return fake, client, identity, session, roundTripper
}

func doSessionAPIRequest(t *testing.T, api *atclient.APIClient, endpoint string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	response, err := api.Auth.DoWithAuth(api.Client, request, syntax.NSID("com.atproto.sync.getBlob"))
	require.NoError(t, err)
	return response
}

type errorSessionRoundTripper struct{}

func (errorSessionRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport failed with access-secret-never-returned refresh-secret-value dpop-private")
}
