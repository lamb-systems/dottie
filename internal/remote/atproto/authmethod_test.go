package atproto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

func TestNewAuthMethodRejectsSessionBindingMismatch(t *testing.T) {
	_, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Session){
		func(session *Session) { session.Issuer = "https://other.example" },
		func(session *Session) { session.TokenEndpoint = "https://other.example/token" },
		func(session *Session) { session.DID = "did:plc:zyxwvutsrqponmlkjihgfedc" },
	} {
		session := testAuthSession(t, identity, "access-token-shape")
		mutate(session)
		if _, err := NewAuthMethod(client, identity, testHandle, session); !errors.Is(err, ErrAuthMethodConfiguration) {
			t.Errorf("NewAuthMethod error = %v, want configuration binding error", err)
		}
	}
	if _, err := NewAuthMethod(client, identity, "bob.example", testAuthSession(t, identity, "access-token-shape")); !errors.Is(err, ErrAuthMethodConfiguration) {
		t.Errorf("NewAuthMethod accepted a mismatched handle: %v", err)
	}
}

func TestAuthMethodRejectsSessionBindingChangeAfterConstruction(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	if err != nil {
		t.Fatal(err)
	}
	session.Issuer = "https://other.example"
	_, err = auth.DoWithAuth(client.HTTPClient, mustAuthRequest(t, "https://shard.example/resource"), syntax.NSID("com.atproto.sync.getBlob"))
	if !errors.Is(err, ErrAuthMethodSession) || len(fake.resourceRequests) != 0 {
		t.Fatalf("changed session binding error=%v resource requests=%d", err, len(fake.resourceRequests))
	}
}

func TestAuthMethodRejectsHostBeforeRefreshingOrSending(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"https://other.example/resource", "http://shard.example/resource"} {
		request, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = auth.DoWithAuth(client.HTTPClient, request, syntax.NSID("com.atproto.sync.getBlob"))
		if !errors.Is(err, ErrAuthMethodHost) {
			t.Errorf("DoWithAuth(%s) error = %v, want host refusal", endpoint, err)
		}
	}
	if len(fake.resourceRequests) != 0 || fake.tokenRequests != 0 {
		t.Fatalf("host refusal sent resource or refresh requests: resource=%d refresh=%d", len(fake.resourceRequests), fake.tokenRequests)
	}
}

func TestAuthMethodNonceChallengeRetriesWithoutRefresh(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.resourceResponses = []fakeResourceResponse{
		{status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {`DPoP error="use_dpop_nonce"`}, "Dpop-Nonce": {"fresh-nonce"}}},
		{status: http.StatusNoContent},
	}
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	if err != nil {
		t.Fatal(err)
	}
	response := doAuthMethodRequest(t, auth, client.HTTPClient, "https://shard.example/resource?cid=abc")
	_ = response.Body.Close()
	if fake.tokenRequests != 0 || len(fake.resourceRequests) != 2 {
		t.Fatalf("nonce challenge did %d refreshes and %d resource requests", fake.tokenRequests, len(fake.resourceRequests))
	}
	first, err := readClaims(fake.resourceRequests[0].proof)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readClaims(fake.resourceRequests[1].proof)
	if err != nil {
		t.Fatal(err)
	}
	if second.Nonce != "fresh-nonce" || first.JTI == second.JTI || first.ATH != tokenHash("access-token-shape") || second.ATH != tokenHash("access-token-shape") {
		t.Fatalf("nonce retry proofs are incorrect: first=%+v second=%+v", first, second)
	}
	if fake.resourceRequests[1].authorization != "DPoP access-token-shape" {
		t.Fatalf("Authorization = %q", fake.resourceRequests[1].authorization)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	session := testAuthSession(t, identity, "expired-access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	if err != nil {
		t.Fatal(err)
	}
	response := doAuthMethodRequest(t, auth, client.HTTPClient, "https://shard.example/resource")
	_ = response.Body.Close()
	if fake.tokenRequests != 1 || len(fake.resourceRequests) != 2 {
		t.Fatalf("invalid_token did %d refreshes and %d resource requests", fake.tokenRequests, len(fake.resourceRequests))
	}
	if fake.resourceRequests[0].authorization != "DPoP expired-access-token-shape" || fake.resourceRequests[1].authorization != "DPoP rotated-access-token-shape" {
		t.Fatalf("resource Authorization sequence = %#v", fake.resourceRequests)
	}
	if session.AccessToken.Reveal() != "rotated-access-token-shape" {
		t.Fatal("auth method did not replace the in-memory session after refresh")
	}
	claims, err := readClaims(fake.resourceRequests[1].proof)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ATH != tokenHash("rotated-access-token-shape") {
		t.Fatalf("refreshed proof ath = %q", claims.ATH)
	}
}

func TestAuthMethodRefreshesBeforeRequestWhenAccessTokenIsAbsent(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.tokenAccess = "loaded-access-token-shape"
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	session := testAuthSession(t, identity, "")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	if err != nil {
		t.Fatal(err)
	}
	response := doAuthMethodRequest(t, auth, client.HTTPClient, "https://shard.example/resource")
	_ = response.Body.Close()
	if fake.tokenRequests != 1 || len(fake.resourceRequests) != 1 || fake.resourceRequests[0].authorization != "DPoP loaded-access-token-shape" {
		t.Fatalf("missing token refresh sequence: refresh=%d requests=%#v", fake.tokenRequests, fake.resourceRequests)
	}
}

func TestAuthMethodDoesNotRetryNonReplayableBody(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.resourceResponses = []fakeResourceResponse{{status: http.StatusBadRequest, header: http.Header{"Dpop-Nonce": {"body-nonce"}}, body: `{"error":"use_dpop_nonce"}`}}
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	session := testAuthSession(t, identity, "access-token-shape")
	auth, err := NewAuthMethod(client, identity, testHandle, session)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://shard.example/resource", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	request.GetBody = nil
	_, err = auth.DoWithAuth(client.HTTPClient, request, syntax.NSID("com.atproto.repo.createRecord"))
	if !errors.Is(err, ErrAuthMethodNonReplayable) {
		t.Fatalf("DoWithAuth error = %v, want non-replayable typed error", err)
	}
	if len(fake.resourceRequests) != 1 || fake.tokenRequests != 0 {
		t.Fatalf("non-replayable request was retried or refreshed: resource=%d refresh=%d", len(fake.resourceRequests), fake.tokenRequests)
	}
}

func TestAuthMethodNeverExceedsTwoAttempts(t *testing.T) {
	challenge := fakeResourceResponse{status: http.StatusBadRequest, header: http.Header{"Www-Authenticate": {`DPoP error="use_dpop_nonce"`}, "Dpop-Nonce": {"challenge-nonce"}}}
	fake, client, _ := newFakeOAuth(t)
	fake.resourceResponses = []fakeResourceResponse{challenge, challenge, {status: http.StatusNoContent}}
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthMethod(client, identity, testHandle, testAuthSession(t, identity, "access-token-shape"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.DoWithAuth(client.HTTPClient, mustAuthRequest(t, "https://shard.example/resource"), syntax.NSID("com.atproto.sync.getBlob"))
	if !errors.Is(err, ErrAuthMethodNonce) || len(fake.resourceRequests) != 2 {
		t.Fatalf("two-attempt bound: requests=%d error=%v", len(fake.resourceRequests), err)
	}
	var typed *AuthMethodError
	if !errors.As(err, &typed) {
		t.Fatalf("error type = %T, want *AuthMethodError", err)
	}
}

func testAuthSession(t *testing.T, identity Identity, accessToken string) *Session {
	t.Helper()
	key, err := marshalPrivateKey(generateTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return &Session{
		DID:            identity.DID,
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
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func mustAuthRequest(t *testing.T, endpoint string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
