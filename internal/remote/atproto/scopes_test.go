package atproto

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

func TestVaultScopesContainEveryRecordCollectionAndBlob(t *testing.T) {
	expected := []string{
		"atproto",
		"repo:" + VaultHeadNSID, "repo:" + VaultControlNSID, "repo:" + VaultSnapshotNSID,
		"repo:" + VaultPolicyNSID, "repo:" + VaultCertificateNSID, "repo:" + VaultCheckpointNSID,
		"repo:" + VaultAttestationNSID,
		"repo:" + publication.HeadNSID, "repo:" + publication.SnapshotNSID,
		"blob:application/octet-stream",
	}
	sort.Strings(expected)
	assert.Equal(t, expected, VaultScopes())
	assert.NoError(t, ValidateScopes(VaultScopes(), VaultScopes(), VaultScopes()))
	assert.NoError(t, ValidatePublicationScopes(VaultScopes()))
}

func TestValidatePublicationScopesRequiresTheV2Collections(t *testing.T) {
	legacy := make([]string, 0, len(VaultScopes()))
	for _, scope := range VaultScopes() {
		if scope == "repo:"+publication.HeadNSID || scope == "repo:"+publication.SnapshotNSID {
			continue
		}
		legacy = append(legacy, scope)
	}
	require.Len(t, legacy, len(VaultScopes())-2)

	err := ValidatePublicationScopes(legacy)
	require.ErrorIs(t, err, ErrInsufficientPublicationScope)
	var refusal *PublicationScopeError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, PublicationScopes(), refusal.Missing)
	assert.Contains(t, err.Error(), "sign in again")

	snapshotMissing := append(append([]string(nil), legacy...), "repo:"+publication.HeadNSID)
	err = ValidatePublicationScopes(snapshotMissing)
	require.ErrorIs(t, err, ErrInsufficientPublicationScope)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, []string{"repo:" + publication.SnapshotNSID}, refusal.Missing)
	assert.Contains(t, err.Error(), "repo:"+publication.SnapshotNSID)

	err = ValidatePublicationScopes([]string{"atproto"})
	require.ErrorIs(t, err, ErrInsufficientPublicationScope)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, PublicationScopes(), refusal.Missing)

	err = ValidatePublicationScopes([]string{"atproto", "not-a-scope"})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInsufficientPublicationScope)

	require.NoError(
		t,
		ValidatePublicationScopes(
			[]string{"atproto", "repo:" + publication.HeadNSID, "repo:" + publication.SnapshotNSID},
		),
	)
	session := &Session{Scopes: VaultScopes()}
	require.NoError(t, session.RequirePublicationScopes())
	var absent *Session
	require.ErrorIs(t, absent.RequirePublicationScopes(), ErrSessionUnavailable)
	session.Scopes = legacy
	require.ErrorIs(t, session.RequirePublicationScopes(), ErrInsufficientPublicationScope)
}

func TestLegacyScopeSessionRefusesPublicationUseWithoutChangingStorage(t *testing.T) {
	t.Run("refusal-before-outbound-work", func(t *testing.T) {
		store := newMemoryStore()
		outbound := &countingRoundTripper{}
		client, err := NewClient("https://dottie.example/client-metadata.json", store,
			WithHTTPClient(&http.Client{Transport: outbound}),
			WithTXTLookup(func(context.Context, string) ([]string, error) { return nil, errorsNewNotFound{} }),
		)
		require.NoError(t, err)
		session := legacyScopeSession(t)
		require.NoError(t, client.saveSession(context.Background(), session))
		item := sessionItemName(client.ClientID, testDID)
		stored := store.raw(item)
		require.NotEmpty(t, stored)

		status, err := client.LoadSessionStatus(context.Background(), testDID)
		require.NoError(t, err)
		assert.Equal(t, SessionStateUsable, status.State)
		assert.Equal(t, session.Scopes, status.Scopes)
		loaded, err := client.LoadSession(context.Background(), testDID)
		require.NoError(t, err)
		assert.Equal(t, session.Scopes, loaded.Scopes)

		require.ErrorIs(t, loaded.RequirePublicationScopes(), ErrInsufficientPublicationScope)
		var refusal *PublicationScopeError
		require.ErrorAs(t, loaded.RequirePublicationScopes(), &refusal)
		assert.Equal(t, PublicationScopes(), refusal.Missing)
		assert.Equal(t, int32(0), outbound.calls.Load())
		assert.Equal(t, stored, store.raw(item))
	})

	t.Run("refresh-keeps-the-granted-scope-set", func(t *testing.T) {
		_, client, store := newFakeOAuth(t)
		identity, err := client.Discover(context.Background(), testHandle)
		require.NoError(t, err)
		session := legacyScopeSession(t)
		session.DID = identity.DID
		session.Handle = identity.Handle
		session.Issuer = identity.Issuer
		session.TokenEndpoint = identity.TokenEndpoint
		require.NoError(t, client.saveSession(context.Background(), session))

		refreshed, refreshedIdentity, err := client.Refresh(context.Background(), testHandle, session)
		require.NoError(t, err)
		assert.Equal(t, identity.DID, refreshedIdentity.DID)
		assert.Equal(t, session.Scopes, refreshed.Scopes)
		require.ErrorIs(t, refreshed.RequirePublicationScopes(), ErrInsufficientPublicationScope)
		stored, err := client.LoadSession(context.Background(), identity.DID)
		require.NoError(t, err)
		assert.Equal(t, session.Scopes, stored.Scopes)
		assert.NotEmpty(t, store.raw(sessionItemName(client.ClientID, identity.DID)))
	})
}

func legacyScopeSession(t *testing.T) *Session {
	t.Helper()
	key, err := marshalPrivateKey(generateTestKey(t))
	require.NoError(t, err)
	legacy := make([]string, 0, len(VaultScopes()))
	for _, scope := range VaultScopes() {
		if scope == "repo:"+publication.HeadNSID || scope == "repo:"+publication.SnapshotNSID {
			continue
		}
		legacy = append(legacy, scope)
	}
	return &Session{
		DID:           testDID,
		Handle:        testHandle,
		Issuer:        "https://bsky.social",
		TokenEndpoint: "https://bsky.social/token",
		Scopes:        legacy,
		State:         SessionStateUsable,
		AccessToken: NewSecret(
			"legacy-access-token-shape",
		),
		RefreshToken:   NewSecret("refresh-token-shape"),
		DPoPPrivateKey: key,
	}
}

type countingRoundTripper struct {
	calls atomic.Int32
}

func (c *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("synthetic outbound transport is unreachable")
}

func TestAtprotoScopeGrantExactRequiredAndRequestedRules(t *testing.T) {
	requested := []string{"atproto", "repo:systems.lamb.dottie.vaultHead", "blob:application/octet-stream"}
	if err := ValidateScopes(
		requested,
		[]string{"atproto", "repo:systems.lamb.dottie.vaultHead"},
		requested,
	); err != nil {
		require.NoError(t, err, "exact grant rejected: %v", err)
	}
	if err := ValidateScopes(
		requested,
		[]string{"atproto", "repo:systems.lamb.dottie.vaultHead"},
		[]string{"repo:systems.lamb.dottie.vaultHead"},
	); err == nil {
		require.Error(t, err, "missing required scope was accepted")
	} else {
		if scopeError, ok := errors.AsType[*ScopeError](err); !ok {
			require.ErrorAs(t, err, &scopeError, "missing scope error type = %T", err)
		}
	}
	if err := ValidateScopes(
		requested,
		[]string{"atproto"},
		append(requested, "repo:com.example.unrequested"),
	); err == nil {
		require.Error(t, err, "unrequested scope was accepted")
	}
}

func TestAtprotoScopeGrammarRejectsOpaqueOrMalformedScopes(t *testing.T) {
	for _, value := range []string{"", "repo:one.two", "repo:9one.two.three", "blob:not-a-media-type", "openid", "atproto atproto"} {
		if _, err := ParseScopes(value); err == nil {
			assert.Error(t, err, "invalid scope list %q was accepted", value)
		}
	}
	parsed, err := ParseScopes("blob:application/octet-stream repo:com.example.settings atproto")
	if err != nil || len(parsed) != 3 || parsed[0] != "atproto" {
		require.False(t, err != nil || len(parsed) != 3 || parsed[0] != "atproto", "ParseScopes = %#v, %v", parsed, err)
	}
}
