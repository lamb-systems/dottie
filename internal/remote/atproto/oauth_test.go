package atproto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBeginDerivesPKCEAndPinsActualLoopbackRedirect(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.checkVerifier = true
	flow, err := client.Begin(context.Background(), testHandle, []string{"atproto", "repo:com.example.settings"}, []string{"atproto"})
	if err != nil {
		require.NoError(t, err)
	}
	defer flow.Close()
	verifier := flow.CodeVerifier().Reveal()
	digest := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if fake.parValues.Get("code_challenge") != wantChallenge || fake.parValues.Get("code_challenge_method") != "S256" {
		require.False(t, fake.parValues.Get("code_challenge") != wantChallenge || fake.parValues.Get("code_challenge_method") != "S256", "PAR challenge does not derive from the retained verifier: %#v", fake.parValues)
	}
	if fake.parValues.Get("redirect_uri") != flow.RedirectURI() {
		require.Equal(t, flow.RedirectURI(), fake.parValues.Get("redirect_uri"), "PAR redirect URI %q differs from bound URI %q", fake.parValues.Get("redirect_uri"), flow.RedirectURI())
	}
	parsed, err := url.Parse(flow.RedirectURI())
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Path != "/callback" {
		require.False(t, err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Path != "/callback", "redirect URI is not the concrete loopback listener: %q, %v", flow.RedirectURI(), err)
	}
	authorization, err := url.Parse(flow.AuthorizationURL())
	if err != nil || authorization.Query().Get("request_uri") != "urn:example:request:123" {
		require.False(t, err != nil || authorization.Query().Get("request_uri") != "urn:example:request:123", "invalid PAR authorization URL: %q", flow.AuthorizationURL())
	}
	callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {"authorization-code-secret"}})
	session, err := flow.Wait(context.Background())
	if err != nil {
		require.NoError(t, err)
	}
	if session.DID != testDID || fake.tokenValues.Get("redirect_uri") != flow.RedirectURI() {
		require.False(t, session.DID != testDID || fake.tokenValues.Get("redirect_uri") != flow.RedirectURI(), "token exchange changed the redirect or identity: session=%+v token=%#v", session, fake.tokenValues)
	}
	if fake.tokenValues.Get("code_verifier") != verifier {
		require.Equal(t, verifier, fake.tokenValues.Get("code_verifier"), "token exchange did not use the retained verifier")
	}
}

func TestWrongPKCEVerifierFailsAtTokenExchange(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	fake.checkVerifier = true
	flow, err := client.Begin(context.Background(), testHandle, []string{"atproto"}, []string{"atproto"})
	if err != nil {
		require.NoError(t, err)
	}
	flow.verifier = NewSecret("deliberately-wrong-verifier")
	callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {"authorization-code-secret"}})
	if _, err := flow.Wait(context.Background()); err == nil {
		require.Error(t, err, "wrong verifier was accepted")
	}
	if len(store.items) != 0 {
		require.Len(t, store.items, 0, "wrong verifier created a stored session")
	}
	if fake.tokenRequests != 1 {
		require.Equal(t, 1, fake.tokenRequests, "token requests = %d, want one", fake.tokenRequests)
	}
}

func TestCallbackFailuresAreRejectedBeforeExchange(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		query  func(*Flow) url.Values
		cancel bool
	}{
		{name: "wrong state", path: "/callback", query: func(flow *Flow) url.Values {
			return url.Values{"state": {"wrong"}, "iss": {flow.identity.Issuer}, "code": {"code"}}
		}, cancel: true},
		{name: "missing code", path: "/callback", query: func(flow *Flow) url.Values { return url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}} }},
		{name: "access denied", path: "/callback", query: func(flow *Flow) url.Values {
			return url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "error": {"access_denied"}}
		}},
		{name: "wrong callback issuer", path: "/callback", query: func(flow *Flow) url.Values {
			return url.Values{"state": {flow.state}, "iss": {"https://wrong.example"}, "code": {"code"}}
		}},
		{name: "wrong path", path: "/wrong", query: func(flow *Flow) url.Values {
			return url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {"code"}}
		}, cancel: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake, client, _ := newFakeOAuth(t)
			flow, err := client.Begin(context.Background(), testHandle, []string{"atproto"}, []string{"atproto"})
			if err != nil {
				require.NoError(t, err)
			}
			defer flow.Close()
			callbackRequest(t, flow, test.path, test.query(flow))
			ctx := context.Background()
			cancel := func() {}
			if test.cancel {
				var cancelContext context.CancelFunc
				ctx, cancelContext = context.WithCancel(ctx)
				cancelContext()
				cancel = cancelContext
			}
			defer cancel()
			_, err = flow.Wait(ctx)
			if err == nil {
				require.Error(t, err, "invalid callback was accepted")
			}
			if fake.tokenRequests != 0 {
				require.Equal(t, 0, fake.tokenRequests, "callback failure reached the token endpoint %d times", fake.tokenRequests)
			}
		})
	}
}

func TestCallbackTimeoutDoesNotExchangeCode(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	flow, err := client.Begin(context.Background(), testHandle, []string{"atproto"}, []string{"atproto"})
	if err != nil {
		require.NoError(t, err)
	}
	defer flow.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if _, err := flow.Wait(ctx); err == nil || !strings.Contains(err.Error(), "timed out") {
		require.ErrorContains(t, err, "timed out", "Wait error = %v", err)
	}
	if fake.tokenRequests != 0 {
		require.Equal(t, 0, fake.tokenRequests, "callback timeout exchanged a code %d times", fake.tokenRequests)
	}
}

func TestTokenSubjectMismatchRejectedBeforeStorage(t *testing.T) {
	fake, client, store := newFakeOAuth(t)
	fake.tokenSub = "did:plc:zyxwvutsrqponmlkjihgfe00"
	flow, err := client.Begin(context.Background(), testHandle, []string{"atproto"}, []string{"atproto"})
	if err != nil {
		require.NoError(t, err)
	}
	defer flow.Close()
	callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {"authorization-code-secret"}})
	if _, err := flow.Wait(context.Background()); err == nil || !strings.Contains(err.Error(), "subject") {
		require.ErrorContains(t, err, "subject", "subject mismatch error = %v", err)
	}
	if len(store.items) != 0 {
		require.Len(t, store.items, 0, "subject mismatch stored a session")
	}
}

func TestCallbackStateComparisonAndSingleUse(t *testing.T) {
	if constantStateEqual("a", "b") || !constantStateEqual("same-state", "same-state") {
		require.False(t, constantStateEqual("a", "b") || !constantStateEqual("same-state", "same-state"), "state comparison returned an incorrect result")
	}
	_, client, _ := newFakeOAuth(t)
	flow, err := client.Begin(context.Background(), testHandle, []string{"atproto"}, []string{"atproto"})
	if err != nil {
		require.NoError(t, err)
	}
	callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {"code"}})
	if _, err := flow.Wait(context.Background()); err != nil {
		require.NoError(t, err)
	}
	if _, err := flow.Wait(context.Background()); err == nil {
		require.Error(t, err, "OAuth flow was reusable")
	}
}

func callbackFlow(t *testing.T, flow *Flow, query url.Values) {
	t.Helper()
	callbackRequest(t, flow, "/callback", query)
}

func callbackRequest(t *testing.T, flow *Flow, path string, query url.Values) {
	t.Helper()
	target := strings.TrimSuffix(flow.RedirectURI(), "/callback") + path + "?" + query.Encode()
	response, err := http.Get(target)
	if err != nil {
		require.NoError(t, err, "callback request: %v", err)
	}
	_ = response.Body.Close()
}

func TestFlowWaitConsumesOnceEvenOnError(t *testing.T) {
	_, client, _ := newFakeOAuth(t)
	flow, err := client.Begin(context.Background(), testHandle, []string{"atproto"}, []string{"atproto"})
	if err != nil {
		require.NoError(t, err)
	}
	callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {"bad-issuer"}, "code": {"code"}})
	if _, err := flow.Wait(context.Background()); err == nil {
		require.Error(t, err, "invalid issuer was accepted")
	}
	if _, err := flow.Wait(context.Background()); err == nil || errors.Is(err, context.Canceled) {
		require.False(t, err == nil || errors.Is(err, context.Canceled), "second Wait result = %v", err)
	}
}
