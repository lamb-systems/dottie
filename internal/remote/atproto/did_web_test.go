package atproto

import (
	"context"
	"testing"
)

func TestDiscoverDIDWebUsesHTTPSWellKnownDocument(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.did = "did:web:alice.example"
	fake.documentID = fake.did
	fake.serviceID = fake.did + "#atproto_pds"
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != fake.did || identity.PDS != fake.pds {
		t.Fatalf("did:web discovery result = %+v", identity)
	}
}
