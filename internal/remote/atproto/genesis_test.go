package atproto

import (
	"context"
	"errors"
	"io"
	"net/url"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGenesisPreflightRepository(t *testing.T) (*atprototest.MemoryPDS, RevisionReader) {
	t.Helper()
	key, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(testDID, key)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	return pds, RevisionReader{
		Transport: pds, DIDDocumentID: testDID,
		VerificationMethods: []VerificationMethod{{
			ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
		}},
	}
}

func seedGenesisRecord(t *testing.T, pds *atprototest.MemoryPDS, collection, rkey string) {
	t.Helper()
	body := []byte(`{"repo":"` + testDID + `","swapCommit":"` + pds.CurrentRevision().CommitCID.String() + `","writes":[{"$type":"com.atproto.repo.applyWrites#create","collection":"` + collection + `","rkey":"` + rkey + `","value":{"$type":"` + collection + `","probe":"genesis"}}]}`)
	status, _, err := pds.Do(context.Background(), "POST", "com.atproto.repo.applyWrites", nil, body, "application/json")
	require.NoError(t, err)
	require.Equal(t, 200, status)
}

func TestGenesisPreflightAllowsRecordsFromOtherApplications(t *testing.T) {
	ctx := context.Background()
	pds, reader := newGenesisPreflightRepository(t)
	seedGenesisRecord(t, pds, "app.bsky.actor.profile", "self")
	seedGenesisRecord(t, pds, "com.example.thirdparty.note", "3foreignrecord")
	revision, err := reader.Read(ctx, testDID)
	require.NoError(t, err)
	require.Len(t, revision.Membership(), 2)
	assert.NoError(t, CheckNoDottiePublication(ctx, reader, pds, testDID))
}

func TestGenesisPreflightRefusesAnExistingV2Publication(t *testing.T) {
	for _, collection := range []string{publication.HeadNSID, publication.SnapshotNSID} {
		t.Run(collection, func(t *testing.T) {
			ctx := context.Background()
			pds, reader := newGenesisPreflightRepository(t)
			seedGenesisRecord(t, pds, "app.bsky.actor.profile", "self")
			seedGenesisRecord(t, pds, collection, "0000000000000001")
			err := CheckNoDottiePublication(ctx, reader, pds, testDID)
			require.ErrorIs(t, err, ErrDottiePublicationPresent)
			assert.NotErrorIs(t, err, ErrGenesisPreflightUnavailable)
		})
	}
}

func TestGenesisPreflightRefusesRetiredV1Collections(t *testing.T) {
	for _, collection := range []string{
		VaultHeadNSID, VaultControlNSID, VaultSnapshotNSID, VaultPolicyNSID,
		VaultCertificateNSID, VaultCheckpointNSID, VaultAttestationNSID,
	} {
		t.Run(collection, func(t *testing.T) {
			ctx := context.Background()
			pds, reader := newGenesisPreflightRepository(t)
			seedGenesisRecord(t, pds, collection, "self")
			err := CheckNoDottiePublication(ctx, reader, pds, testDID)
			require.ErrorIs(t, err, ErrDottiePublicationPresent)
			assert.NotErrorIs(t, err, ErrGenesisPreflightUnavailable)
		})
	}
}

type unavailableRevisionTransport struct{}

func (unavailableRevisionTransport) Do(context.Context, string, string, url.Values, []byte, string) (int, []byte, error) {
	return 0, nil, errors.New("synthetic revision transport failure")
}

func (unavailableRevisionTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("synthetic revision transport failure")
}

func TestGenesisPreflightRefusesAnUnreadableRepository(t *testing.T) {
	transport := unavailableRevisionTransport{}
	reader := RevisionReader{Transport: transport, DIDDocumentID: testDID}
	err := CheckNoDottiePublication(context.Background(), reader, transport, testDID)
	require.ErrorIs(t, err, ErrGenesisPreflightUnavailable)
	assert.NotErrorIs(t, err, ErrDottiePublicationPresent)
}
