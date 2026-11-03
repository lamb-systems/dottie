package atproto

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testDID = "did:plc:abcdefghijklmnopqrstuvwx"
const testHandle = "alice.example"

const (
	handleHost = "alice.example"
	didHost    = "plc.directory"
	pdsHost    = "shard.example"
	issuerHost = "bsky.social"
)

type fakeOAuth struct {
	server                 *httptest.Server
	mu                     sync.Mutex
	did                    string
	documentID             string
	handleStatus           int
	alsoKnown              []string
	serviceID              string
	pds                    string
	resource               string
	resourceStatus         int
	authorizationServer    string
	metadataIssuer         string
	authorizationEndpoint  string
	tokenEndpoint          string
	parEndpoint            string
	revocationEndpoint     string
	parStatus              int
	parValues              url.Values
	tokenValues            url.Values
	tokenSub               string
	tokenScope             string
	tokenRefresh           string
	tokenAccess            string
	checkVerifier          bool
	redirectToken          bool
	tokenRequests          int
	tokenStatus            int
	tokenErrorBody         string
	presentedRefreshTokens []string
	rejectRefreshReuse     bool
	usedRefreshTokens      map[string]bool
	pendingAtToken         bool
	pendingCheck           func() bool
	revocationResponses    []fakeResourceResponse
	revocationRequests     []fakeRevocationRequest
	resourceProof          string
	resourceAuth           string
	resourceResponses      []fakeResourceResponse
	resourceRequests       []fakeResourceRequest
	afterResourceRequest   func(int)
	followedRedirect       int
}

type fakeResourceResponse struct {
	status int
	header http.Header
	body   string
}

type fakeResourceRequest struct {
	host          string
	authorization string
	proof         string
}

type fakeRevocationRequest struct {
	form          url.Values
	authorization string
	proof         string
}

type rewriteTransport struct {
	server    *url.URL
	transport *http.Transport
}

func (r *rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	original := *request.URL
	copy.Header = request.Header.Clone()
	copy.Header.Set("X-Original-Host", original.Host)
	copy.URL.Scheme = r.server.Scheme
	copy.URL.Host = r.server.Host
	copy.Host = original.Host
	return r.transport.RoundTrip(copy)
}

type counterReader struct {
	mu sync.Mutex
	n  byte
}

func (r *counterReader) Read(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range buffer {
		buffer[index] = r.n
		r.n++
	}
	return len(buffer), nil
}

type memoryStore struct {
	mu        sync.Mutex
	items     map[string][]byte
	saveHook  func(string, []byte) error
	loadErr   error
	deleteErr error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{items: make(map[string][]byte)}
}

func (s *memoryStore) Save(_ context.Context, name string, payload []byte) error {
	s.mu.Lock()
	hook := s.saveHook
	s.mu.Unlock()
	if hook != nil {
		if err := hook(name, append([]byte(nil), payload...)); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[name] = append([]byte(nil), payload...)
	return nil
}

func (s *memoryStore) Load(_ context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	payload, ok := s.items[name]
	if !ok {
		return nil, errorsNewNotFound{}
	}
	return append([]byte(nil), payload...), nil
}

type errorsNewNotFound struct{}

func (errorsNewNotFound) Error() string { return "not found" }

func (s *memoryStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.items, name)
	return nil
}

func (s *memoryStore) raw(name string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.items[name]...)
}

func newFakeOAuth(t *testing.T) (*fakeOAuth, *Client, *memoryStore) {
	t.Helper()
	fake := &fakeOAuth{
		did:                   testDID,
		documentID:            testDID,
		alsoKnown:             []string{"at://" + testHandle},
		serviceID:             testDID + "#atproto_pds",
		pds:                   "https://" + pdsHost,
		resource:              "https://" + pdsHost,
		authorizationServer:   "https://" + issuerHost,
		metadataIssuer:        "https://" + issuerHost,
		authorizationEndpoint: "https://" + issuerHost + "/authorize",
		tokenEndpoint:         "https://" + issuerHost + "/token",
		parEndpoint:           "https://" + issuerHost + "/par",
		revocationEndpoint:    "https://" + issuerHost + "/revoke",
		tokenSub:              testDID,
		tokenScope:            "",
		tokenRefresh:          "refresh-secret-value",
		tokenAccess:           "access-secret-value",
		usedRefreshTokens:     make(map[string]bool),
	}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(fake.serveHTTP))
	t.Cleanup(fake.server.Close)
	serverURL, err := url.Parse(fake.server.URL)
	if err != nil {
		require.NoError(t, err)
	}
	store := newMemoryStore()
	client, err := NewClient("https://dottie.example/client-metadata.json", store,
		WithHTTPClient(&http.Client{Transport: &rewriteTransport{server: serverURL, transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}),
		WithClock(func() time.Time { return time.Unix(1_700_000_123, 987654321) }),
		WithRandom(&counterReader{}),
		WithTXTLookup(func(context.Context, string) ([]string, error) { return nil, errorsNewNotFound{} }),
	)
	if err != nil {
		require.NoError(t, err)
	}
	return fake, client, store
}

func (f *fakeOAuth) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	host := request.Header.Get("X-Original-Host")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case host == handleHost && request.URL.Path == "/.well-known/did.json":
		writeJSON(writer, didDocument{ID: f.documentID, AlsoKnownAs: f.alsoKnown, Service: []didService{{ID: f.serviceID, Type: "AtprotoPersonalDataServer", ServiceEndpoint: f.pds}}})
	case host == handleHost && request.URL.Path == "/.well-known/atproto-did":
		if f.handleStatus != 0 {
			http.Error(writer, "not found", f.handleStatus)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, f.did)
	case host == didHost && strings.HasPrefix(request.URL.Path, "/did:"):
		writeJSON(writer, didDocument{ID: f.documentID, AlsoKnownAs: f.alsoKnown, Service: []didService{{ID: f.serviceID, Type: "AtprotoPersonalDataServer", ServiceEndpoint: f.pds}}})
	case hostMatchesURL(host, f.pds) && request.URL.Path == "/.well-known/oauth-protected-resource":
		status := f.resourceStatus
		if status != 0 {
			http.Error(writer, "missing", status)
			return
		}
		writeJSON(writer, protectedResource{Resource: f.resource, AuthorizationServers: []string{f.authorizationServer}})
	case host == issuerHost && request.URL.Path == "/.well-known/oauth-authorization-server":
		writeJSON(writer, authorizationMetadata{Issuer: f.metadataIssuer, AuthorizationEndpoint: f.authorizationEndpoint, TokenEndpoint: f.tokenEndpoint, PARSEndpoint: f.parEndpoint, RevocationEndpoint: f.revocationEndpoint, ScopesSupported: VaultScopes()})
	case host == issuerHost && request.URL.Path == "/par":
		_ = request.ParseForm()
		f.parValues = request.Form
		if f.parStatus != 0 {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(f.parStatus)
			_, _ = io.WriteString(writer, `{"error":"invalid_request"}`)
			return
		}
		writeJSON(writer, parResponse{RequestURI: "urn:example:request:123", ExpiresIn: 60})
	case host == issuerHost && request.URL.Path == "/token":
		f.tokenRequests++
		if f.pendingCheck != nil {
			f.pendingAtToken = f.pendingCheck()
		}
		if f.redirectToken {
			http.Redirect(writer, request, "https://"+issuerHost+"/should-not-follow", http.StatusFound)
			return
		}
		_ = request.ParseForm()
		f.tokenValues = request.Form
		if request.Form.Get("grant_type") == "refresh_token" {
			refresh := request.Form.Get("refresh_token")
			f.presentedRefreshTokens = append(f.presentedRefreshTokens, refresh)
			if f.rejectRefreshReuse && f.usedRefreshTokens[refresh] {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(writer, `{"error":"invalid_grant"}`)
				return
			}
			f.usedRefreshTokens[refresh] = true
		}
		if f.checkVerifier {
			digest := sha256Sum(request.Form.Get("code_verifier"))
			if digest != f.parValues.Get("code_challenge") {
				http.Error(writer, "invalid verifier", http.StatusBadRequest)
				return
			}
		}
		if f.tokenErrorBody != "" {
			status := f.tokenStatus
			if status == 0 {
				status = http.StatusBadRequest
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(status)
			_, _ = io.WriteString(writer, f.tokenErrorBody)
			return
		}
		status := f.tokenStatus
		if status != 0 {
			writer.WriteHeader(status)
			return
		}
		writeJSON(writer, tokenResponse{AccessToken: f.tokenAccess, RefreshToken: f.tokenRefresh, TokenType: "DPoP", Scope: f.tokenScope, Sub: f.tokenSub})
	case host == issuerHost && request.URL.Path == "/resource":
		f.resourceProof = request.Header.Get("DPoP")
		f.resourceAuth = request.Header.Get("Authorization")
		writer.WriteHeader(http.StatusNoContent)
	case hostMatchesURL(host, f.pds) && request.URL.Path == "/resource":
		f.resourceProof = request.Header.Get("DPoP")
		f.resourceAuth = request.Header.Get("Authorization")
		f.resourceRequests = append(f.resourceRequests, fakeResourceRequest{host: host, authorization: f.resourceAuth, proof: f.resourceProof})
		index := len(f.resourceRequests) - 1
		var configured fakeResourceResponse
		if index < len(f.resourceResponses) {
			configured = f.resourceResponses[index]
		}
		if f.afterResourceRequest != nil {
			f.afterResourceRequest(index)
		}
		for name, values := range configured.header {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		status := configured.status
		if status == 0 {
			status = http.StatusNoContent
		}
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, configured.body)
	case host == issuerHost && request.URL.Path == "/revoke":
		_ = request.ParseForm()
		f.revocationRequests = append(f.revocationRequests, fakeRevocationRequest{form: request.Form, authorization: request.Header.Get("Authorization"), proof: request.Header.Get("DPoP")})
		index := len(f.revocationRequests) - 1
		var configured fakeResourceResponse
		if index < len(f.revocationResponses) {
			configured = f.revocationResponses[index]
		}
		for name, values := range configured.header {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		status := configured.status
		if status == 0 {
			status = http.StatusNoContent
		}
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, configured.body)
	case host == issuerHost && request.URL.Path == "/should-not-follow":
		f.followedRedirect++
		writer.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(writer, request)
	}
}

func hostMatchesURL(host, value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && strings.EqualFold(host, parsed.Host)
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func sha256Sum(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
