package atproto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoverDIDWebUsesHTTPSWellKnownDocument(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.did = "did:web:alice.example"
	fake.documentID = fake.did
	fake.serviceID = fake.did + "#atproto_pds"
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		require.NoError(t, err)
	}
	if identity.DID != fake.did || identity.PDS != fake.pds {
		require.False(t, identity.DID != fake.did || identity.PDS != fake.pds, "did:web discovery result = %+v", identity)
	}
}
