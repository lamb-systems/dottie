package atproto

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeGrantFailuresPreventSessionStorage(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		required  []string
		granted   string
	}{
		{name: "missing required", requested: []string{"atproto", "repo:com.example.settings"}, required: []string{"atproto", "repo:com.example.settings"}, granted: "atproto"},
		{name: "extra granted", requested: []string{"atproto"}, required: []string{"atproto"}, granted: "atproto repo:com.example.unrequested"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake, client, store := newFakeOAuth(t)
			fake.tokenScope = test.granted
			flow, err := client.Begin(context.Background(), testHandle, test.requested, test.required)
			if err != nil {
				require.NoError(t, err)
			}
			defer flow.Close()
			callbackFlow(t, flow, url.Values{"state": {flow.state}, "iss": {flow.identity.Issuer}, "code": {"scope-test-code"}})
			if _, err := flow.Wait(context.Background()); err == nil {
				require.Error(t, err, "invalid scope grant was accepted")
			}
			if len(store.items) != 0 {
				require.Len(t, store.items, 0, "invalid scope grant was stored")
			}
		})
	}
}
