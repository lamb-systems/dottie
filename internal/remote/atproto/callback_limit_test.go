package atproto

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCallbackAttemptsAreBounded(t *testing.T) {
	_, client, _ := newFakeOAuth(t)
	client.callbackAttempts = 2
	flow, err := client.Begin(context.Background(), testHandle, []string{"atproto"}, []string{"atproto"})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	for attempt := 0; attempt < 2; attempt++ {
		callbackRequest(t, flow, "/callback", url.Values{"state": {"incorrect"}, "iss": {flow.identity.Issuer}, "code": {"code"}})
	}
	target := strings.TrimSuffix(flow.RedirectURI(), "/callback") + "/callback?state=incorrect&iss=" + url.QueryEscape(flow.identity.Issuer) + "&code=code"
	if response, err := http.Get(target); err == nil {
		_ = response.Body.Close()
	}
	if _, err := flow.Wait(context.Background()); err == nil || !strings.Contains(err.Error(), "attempt limit") {
		t.Fatalf("callback attempt exhaustion error = %v", err)
	}
}
