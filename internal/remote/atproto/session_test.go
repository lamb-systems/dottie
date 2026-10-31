package atproto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionEnvelopeReloadAndRefreshPersistsRotatedRefreshToken(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	key := generateTestKey(t)
	privateKey, err := marshalPrivateKey(key)
	if err != nil {
		require.NoError(t, err)
	}
	session := &Session{
		DID:            testDID,
		Issuer:         "https://bsky.social",
		TokenEndpoint:  "https://bsky.social/token",
		Scopes:         []string{"atproto", "repo:com.example.settings"},
		AccessToken:    NewSecret("old-access-token-shape"),
		RefreshToken:   NewSecret("old-refresh-token-shape"),
		DPoPPrivateKey: privateKey,
	}
	if err := client.SaveSession(context.Background(), session); err != nil {
		require.NoError(t, err)
	}
	clientID := client.ClientID
	restarted, err := NewClient(clientID, store,
		WithHTTPClient(client.HTTPClient),
		WithClock(func() time.Time { return time.Unix(1_700_000_123, 0) }),
		WithRandom(&counterReader{}),
	)
	if err != nil {
		require.NoError(t, err)
	}
	loaded, err := restarted.LoadSession(context.Background(), testDID)
	if err != nil {
		require.NoError(t, err)
	}
	if loaded.AccessToken.Reveal() != "" || loaded.RefreshToken.Reveal() != "old-refresh-token-shape" {
		require.False(t, loaded.AccessToken.Reveal() != "" || loaded.RefreshToken.Reveal() != "old-refresh-token-shape", "restart did not load the one-item refresh session: %#v", loaded)
	}
	fake.tokenRefresh = "rotated-refresh-token-shape"
	fake.tokenAccess = "rotated-access-token-shape"
	refreshed, err := restarted.Refresh(context.Background(), testHandle, loaded)
	if err != nil {
		require.NoError(t, err)
	}
	if refreshed.RefreshToken.Reveal() != "rotated-refresh-token-shape" || refreshed.AccessToken.Reveal() != "rotated-access-token-shape" {
		require.False(t, refreshed.RefreshToken.Reveal() != "rotated-refresh-token-shape" || refreshed.AccessToken.Reveal() != "rotated-access-token-shape", "refresh response did not replace the rotated tokens")
	}
	reloaded, err := restarted.LoadSession(context.Background(), testDID)
	if err != nil {
		require.NoError(t, err)
	}
	if reloaded.RefreshToken.Reveal() != "rotated-refresh-token-shape" {
		require.Equal(t, "rotated-refresh-token-shape", reloaded.RefreshToken.Reveal(), "rotated refresh token did not survive the restart boundary")
	}
	envelope := store.raw(sessionItemName(clientID, testDID))
	if strings.Contains(string(envelope), "rotated-access-token-shape") {
		require.NotContains(t, string(envelope), "rotated-access-token-shape", "access token was persisted in the session envelope")
	}
	var persisted sessionEnvelope
	if err := json.Unmarshal(envelope, &persisted); err != nil || persisted.RefreshToken != "rotated-refresh-token-shape" {
		require.False(t, err != nil || persisted.RefreshToken != "rotated-refresh-token-shape", "invalid atomic session envelope: %+v, %v", persisted, err)
	}
}

func TestLoadSessionRejectsPartialAndWrongVersionEnvelopes(t *testing.T) {
	_, client, store := newFakeOAuth(t)
	name := sessionItemName(client.ClientID, testDID)
	for _, encoded := range []string{
		`{"version":1,"did":"` + testDID + `"}`,
		`{"version":2,"did":"` + testDID + `","issuer":"https://bsky.social","token_endpoint":"https://bsky.social/token","scopes":["atproto"],"refresh_token":"refresh","dpop_private_key":"not-a-key"}`,
	} {
		if err := store.Save(context.Background(), name, []byte(encoded)); err != nil {
			require.NoError(t, err)
		}
		if _, err := client.LoadSession(context.Background(), testDID); err != ErrSessionUnavailable {
			require.ErrorIs(t, err, ErrSessionUnavailable, "LoadSession error = %v, want forced re-login", err)
		}
	}
}

func TestRefreshRejectsChangedIssuerOrTokenEndpoint(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	key, err := marshalPrivateKey(generateTestKey(t))
	if err != nil {
		require.NoError(t, err)
	}
	session := &Session{DID: testDID, Issuer: "https://other.example", TokenEndpoint: "https://bsky.social/token", Scopes: []string{"atproto"}, RefreshToken: NewSecret("refresh"), DPoPPrivateKey: key}
	if _, err := client.Refresh(context.Background(), testHandle, session); err == nil {
		require.Error(t, err, "refresh accepted a changed issuer")
	}
	session.Issuer = fake.metadataIssuer
	session.TokenEndpoint = "https://other.example/token"
	if _, err := client.Refresh(context.Background(), testHandle, session); err == nil {
		require.Error(t, err, "refresh accepted a changed token endpoint")
	}
	if fake.tokenRequests != 0 {
		require.Equal(t, 0, fake.tokenRequests, "changed discovery caused %d credential-bearing requests", fake.tokenRequests)
	}
}

func TestNoTokenMaterialIsWrittenUnderStateCacheOrConfig(t *testing.T) {
	_, client, _ := newFakeOAuth(t)
	key, err := marshalPrivateKey(generateTestKey(t))
	if err != nil {
		require.NoError(t, err)
	}
	session := &Session{DID: testDID, Issuer: "https://bsky.social", TokenEndpoint: "https://bsky.social/token", Scopes: []string{"atproto"}, AccessToken: NewSecret("access-token-shaped-value"), RefreshToken: NewSecret("refresh-token-shaped-value"), DPoPPrivateKey: key}
	if err := client.SaveSession(context.Background(), session); err != nil {
		require.NoError(t, err)
	}
	root := t.TempDir()
	for _, name := range []string{"state", "cache", "config"} {
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			require.NoError(t, err)
		}
		if err := filepath.WalkDir(path, func(file string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			contents, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			for _, secret := range []string{"access-token-shaped-value", "refresh-token-shaped-value", key.Reveal()} {
				if strings.Contains(string(contents), secret) {
					return fmt.Errorf("secret material found under %s", name)
				}
			}
			return nil
		}); err != nil {
			require.NoError(t, err)
		}
	}
}

func TestSecretRedactionFormattingAndJSONMatrix(t *testing.T) {
	record := struct {
		Code       Secret `json:"code"`
		Access     Secret `json:"access"`
		Refresh    Secret `json:"refresh"`
		PrivateKey Secret `json:"private_key"`
	}{Code: NewSecret("authorization-code-secret"), Access: NewSecret("access-token-secret"), Refresh: NewSecret("refresh-token-secret"), PrivateKey: NewSecret("private-key-secret")}
	for _, format := range []string{"%v", "%+v", "%s", "%q", "%#v"} {
		output := fmt.Sprintf(format, record)
		if !strings.Contains(output, redactionMarker) {
			assert.Contains(t, output, redactionMarker, "format %s omitted redaction marker: %s", format, output)
		}
		for _, raw := range []string{"authorization-code-secret", "access-token-secret", "refresh-token-secret", "private-key-secret"} {
			if strings.Contains(output, raw) {
				assert.NotContains(t, output, raw, "format %s leaked %s", format, raw)
			}
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		require.NoError(t, err)
	}
	if strings.Count(string(encoded), redactionMarker) != 4 || strings.Contains(string(encoded), "private-key-secret") {
		require.False(t, strings.Count(string(encoded), redactionMarker) != 4 || strings.Contains(string(encoded), "private-key-secret"), "JSON did not structurally redact secrets: %s", encoded)
	}
	text, err := record.Code.MarshalText()
	if err != nil || string(text) != redactionMarker {
		require.False(t, err != nil || string(text) != redactionMarker, "MarshalText = %q, %v", text, err)
	}
}

func TestSessionKeyNameBindsClientAndDID(t *testing.T) {
	left := sessionItemName("https://dottie.example/client", testDID)
	rightClient := sessionItemName("https://other.example/client", testDID)
	rightDID := sessionItemName("https://dottie.example/client", "did:plc:zyxwvutsrqponmlkjihgfe00")
	if left == rightClient || left == rightDID {
		require.False(t, left == rightClient || left == rightDID, "keyring item name does not bind both client id and DID")
	}
	digest := sha256.Sum256([]byte("https://dottie.example/client\x00" + testDID))
	if left != "session:"+base64.RawURLEncoding.EncodeToString(digest[:]) {
		require.Equal(t, "session:"+base64.RawURLEncoding.EncodeToString(digest[:]), left, "unexpected item name derivation: %q", left)
	}
}
