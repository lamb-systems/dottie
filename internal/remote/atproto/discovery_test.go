package atproto

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoverShardPDSToDifferentAuthorizationServer(t *testing.T) {
	_, client, _ := newFakeOAuth(t)
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		require.NoError(t, err)
	}
	if identity.DID != testDID || identity.PDS != "https://shard.example" || identity.Issuer != "https://bsky.social" {
		require.False(t, identity.DID != testDID || identity.PDS != "https://shard.example" || identity.Issuer != "https://bsky.social", "discovery result lost the sharded identity: %+v", identity)
	}
	if identity.PDS == identity.Issuer || identity.Handle == "" {
		require.False(t, identity.PDS == identity.Issuer || identity.Handle == "", "discovery incorrectly requires host equality: %+v", identity)
	}
}

func TestDiscoverRejectsIdentityAndResourceMismatches(t *testing.T) {
	tests := []struct {
		name   string
		stage  error
		mutate func(*fakeOAuth)
	}{
		{name: "did document id", stage: ErrDID, mutate: func(fake *fakeOAuth) { fake.documentID = "did:plc:zyxwvutsrqponmlkjihgfe00" }},
		{name: "handle claim", stage: ErrDID, mutate: func(fake *fakeOAuth) { fake.alsoKnown = []string{"at://other.example"} }},
		{name: "resource missing", stage: ErrResource, mutate: func(fake *fakeOAuth) { fake.resourceStatus = 404 }},
		{name: "resource not bound to PDS", stage: ErrResource, mutate: func(fake *fakeOAuth) { fake.resource = "https://other.example" }},
		{name: "metadata issuer", stage: ErrIssuer, mutate: func(fake *fakeOAuth) { fake.metadataIssuer = "https://other.example" }},
		{name: "unsupported DID", stage: ErrDID, mutate: func(fake *fakeOAuth) { fake.did = "did:example:unsupported" }},
		{name: "PDS must use HTTPS", stage: ErrPDS, mutate: func(fake *fakeOAuth) { fake.pds = "http://shard.example" }},
		{name: "authorization endpoint must use HTTPS", stage: ErrIssuer, mutate: func(fake *fakeOAuth) { fake.authorizationEndpoint = "http://bsky.social/authorize" }},
		{name: "token endpoint must use HTTPS", stage: ErrIssuer, mutate: func(fake *fakeOAuth) { fake.tokenEndpoint = "http://bsky.social/token" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake, client, _ := newFakeOAuth(t)
			test.mutate(fake)
			_, err := client.Discover(context.Background(), testHandle)
			if !errors.Is(err, test.stage) {
				require.ErrorIs(t, err, test.stage, "Discover error = %v, want stage %v", err, test.stage)
			}
		})
	}
}

func TestDiscoverAcceptsDIDQualifiedAndFragmentPDSServiceIDs(t *testing.T) {
	for _, serviceID := range []string{"#atproto_pds", testDID + "#atproto_pds"} {
		t.Run(serviceID, func(t *testing.T) {
			fake, client, _ := newFakeOAuth(t)
			fake.serviceID = serviceID
			if _, err := client.Discover(context.Background(), testHandle); err != nil {
				require.NoError(t, err)
			}
		})
	}
}

func TestDiscoverUsesAtprotoTXTFallback(t *testing.T) {
	fake, client, _ := newFakeOAuth(t)
	fake.handleStatus = 404
	client.lookupTXT = func(_ context.Context, name string) ([]string, error) {
		if name != "_atproto."+testHandle {
			require.Equal(t, "_atproto."+testHandle, name, "TXT lookup name = %q", name)
		}
		return []string{"did=" + testDID}, nil
	}
	identity, err := client.Discover(context.Background(), testHandle)
	if err != nil {
		require.NoError(t, err)
	}
	if identity.DID != testDID {
		require.Equal(t, testDID, identity.DID, "DID = %q", identity.DID)
	}
}

func TestValidateHTTPSURLRejectsHTTP(t *testing.T) {
	if _, err := validateHTTPSURL("http://auth.example/token"); err == nil {
		require.Error(t, err, "HTTP endpoint was accepted")
	}
}
