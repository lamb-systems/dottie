package atproto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDPoPWireHeaderClaimsFixedSignatureAndJWK(t *testing.T) {
	key := generateTestKey(t)
	now := time.Unix(1_700_000_123, 987654321)
	proof, err := makeDPoPProof(key, "get", "https://resource.example/path?secret=query#fragment", now, &counterReader{}, Secret{}, "")
	if err != nil {
		require.NoError(t, err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		require.Len(t, parts, 3, "proof has %d JWS segments", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		require.NoError(t, err)
	}
	var header dpopHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		require.NoError(t, err)
	}
	if header.Typ != "dpop+jwt" || header.Alg != "ES256" || header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" {
		require.False(t, header.Typ != "dpop+jwt" || header.Alg != "ES256" || header.JWK.Kty != "EC" || header.JWK.Crv != "P-256", "unexpected DPoP header: %+v", header)
	}
	claims, err := readClaims(proof)
	if err != nil {
		require.NoError(t, err)
	}
	if claims.JTI == "" || claims.HTM != "GET" || claims.HTU != "https://resource.example/path" || claims.IAT != now.Unix() || claims.ATH != "" {
		require.False(t, claims.JTI == "" || claims.HTM != "GET" || claims.HTU != "https://resource.example/path" || claims.IAT != now.Unix() || claims.ATH != "", "unexpected DPoP claims: %+v", claims)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		require.False(t, err != nil || len(signature) != 64, "ES256 signature must be fixed-width R||S: len=%d err=%v", len(signature), err)
	}
	public, err := decodePublicJWK(header.JWK)
	if err != nil {
		require.NoError(t, err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		require.True(t, ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])), "DPoP signature did not verify")
	}
	if public.X.Cmp(key.X) != 0 || public.Y.Cmp(key.Y) != 0 {
		require.False(t, public.X.Cmp(key.X) != 0 || public.Y.Cmp(key.Y) != 0, "JWK round-trip changed the P-256 public key")
	}
}

func TestDPoPResourceProofCarriesATHAndOmitsQuery(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	privateKey := generateTestKey(t)
	encoded, err := marshalPrivateKey(privateKey)
	if err != nil {
		require.NoError(t, err)
	}
	session := &Session{DID: testDID, Issuer: "https://bsky.social", TokenEndpoint: "https://bsky.social/token", Scopes: []string{"atproto"}, AccessToken: NewSecret("resource-access-secret"), RefreshToken: NewSecret("refresh-secret"), DPoPPrivateKey: encoded}
	response, err := client.DoResource(context.Background(), session, http.MethodGet, "https://bsky.social/resource?private=query", nil, nil)
	if err != nil {
		require.NoError(t, err)
	}
	_ = response.Body.Close()
	claims, err := readClaims(fake.resourceProof)
	if err != nil {
		require.NoError(t, err)
	}
	digest := sha256.Sum256([]byte("resource-access-secret"))
	if claims.ATH != base64.RawURLEncoding.EncodeToString(digest[:]) || claims.HTU != "https://bsky.social/resource" {
		require.False(t, claims.ATH != base64.RawURLEncoding.EncodeToString(digest[:]) || claims.HTU != "https://bsky.social/resource", "resource proof claims = %+v", claims)
	}
	if fake.resourceAuth != "DPoP resource-access-secret" {
		require.Equal(t, "DPoP resource-access-secret", fake.resourceAuth, "resource request was not DPoP-authorized")
	}
}

func TestDPoPNonceIsOriginScopedAndRetriesOnceWithFreshJTI(t *testing.T) {
	var requests atomic.Int32
	var exhaust atomic.Bool
	var proofsMu sync.Mutex
	var proofs []dpopClaims
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		proof, err := readClaims(request.Header.Get("DPoP"))
		if err != nil {
			http.Error(writer, "invalid proof", http.StatusBadRequest)
			return
		}
		proofsMu.Lock()
		proofs = append(proofs, proof)
		proofsMu.Unlock()
		count := requests.Add(1)
		if count == 1 || exhaust.Load() {
			writer.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			writer.Header().Set("DPoP-Nonce", "origin-nonce")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	client, err := NewClient("https://dottie.example/client", newMemoryStore(),
		WithHTTPClient(&http.Client{Transport: &rewriteTransport{server: serverURL, transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}),
		WithClock(func() time.Time { return time.Unix(1_700_000_123, 0) }), WithRandom(&counterReader{}))
	if err != nil {
		require.NoError(t, err)
	}
	key := generateTestKey(t)
	response, err := client.doDPoP(context.Background(), http.MethodPost, "https://issuer.example/nonce", strings.NewReader("x"), 1, "text/plain", nil, key, Secret{})
	if err != nil {
		require.NoError(t, err)
	}
	_ = response.Body.Close()
	if requests.Load() != 2 || len(proofs) != 2 {
		require.False(t, requests.Load() != 2 || len(proofs) != 2, "nonce challenge produced %d requests and %d proofs", requests.Load(), len(proofs))
	}
	if proofs[0].JTI == proofs[1].JTI || proofs[1].Nonce != "origin-nonce" {
		require.False(t, proofs[0].JTI == proofs[1].JTI || proofs[1].Nonce != "origin-nonce", "retry did not use a fresh jti and challenged nonce: %#v", proofs)
	}

	exhaust.Store(true)
	requests.Store(0)
	client.nonceMu.Lock()
	client.nonces = make(map[string]string)
	client.nonceMu.Unlock()
	err = client.postFormDPoP(context.Background(), "https://issuer.example/nonce", url.Values{"grant_type": {"refresh_token"}}, key, &struct{}{})
	if err == nil || requests.Load() != 2 {
		require.False(t, err == nil || requests.Load() != 2, "second nonce challenge was not surfaced after one retry: requests=%d error=%v", requests.Load(), err)
	}
}

func TestCredentialRequestDoesNotFollowRedirect(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.redirectToken = true
	response, err := client.doDPoP(context.Background(), http.MethodPost, "https://bsky.social/token", strings.NewReader("grant_type=authorization_code"), int64(len("grant_type=authorization_code")), "application/x-www-form-urlencoded", nil, generateTestKey(t), Secret{})
	if err != nil {
		require.NoError(t, err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound || fake.followedRedirect != 0 {
		require.False(t, response.StatusCode != http.StatusFound || fake.followedRedirect != 0, "credential-bearing request followed redirect: status=%d follow-count=%d", response.StatusCode, fake.followedRedirect)
	}
}

func TestDPoPRejectsNonHTTPSAndBadKey(t *testing.T) {
	fixed := time.Unix(1_700_000_123, 0)
	if _, err := makeDPoPProof(generateTestKey(t), "GET", "http://resource.example/path", fixed, &counterReader{}, Secret{}, ""); err == nil {
		require.Error(t, err, "DPoP accepted an HTTP target")
	}
	if _, err := makeDPoPProof(nil, "GET", "https://resource.example/path", fixed, &counterReader{}, Secret{}, ""); err == nil {
		require.Error(t, err, "DPoP accepted an absent key")
	}
}

func readClaims(proof string) (dpopClaims, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return dpopClaims{}, errors.New("invalid proof")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return dpopClaims{}, err
	}
	var claims dpopClaims
	err = json.Unmarshal(payload, &claims)
	return claims, err
}

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), &counterReader{})
	if err != nil {
		require.NoError(t, err)
	}
	return key
}

func TestDPoPNonceChallengeFromErrorBodyIsRetried(t *testing.T) {
	var requests atomic.Int32
	var proofsMu sync.Mutex
	var proofs []dpopClaims
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		proof, err := readClaims(request.Header.Get("DPoP"))
		if err != nil {
			http.Error(writer, "invalid proof", http.StatusBadRequest)
			return
		}
		proofsMu.Lock()
		proofs = append(proofs, proof)
		proofsMu.Unlock()
		if requests.Add(1) == 1 {
			writer.Header().Set("DPoP-Nonce", "body-nonce")
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}`))
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	client, err := NewClient("https://dottie.example/client", newMemoryStore(),
		WithHTTPClient(&http.Client{Transport: &rewriteTransport{server: serverURL, transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}),
		WithClock(func() time.Time { return time.Unix(1_700_000_123, 0) }), WithRandom(&counterReader{}))
	if err != nil {
		require.NoError(t, err)
	}
	response, err := client.doDPoP(context.Background(), http.MethodPost, "https://issuer.example/par", strings.NewReader("x"), 1, "text/plain", nil, generateTestKey(t), Secret{})
	if err != nil {
		require.NoError(t, err)
	}
	_ = response.Body.Close()
	if requests.Load() != 2 || len(proofs) != 2 {
		require.False(t, requests.Load() != 2 || len(proofs) != 2, "body-signalled nonce challenge produced %d requests and %d proofs", requests.Load(), len(proofs))
	}
	if proofs[1].Nonce != "body-nonce" || proofs[0].JTI == proofs[1].JTI {
		require.False(t, proofs[1].Nonce != "body-nonce" || proofs[0].JTI == proofs[1].JTI, "retry did not carry the body-signalled nonce with a fresh jti: %#v", proofs)
	}
}
