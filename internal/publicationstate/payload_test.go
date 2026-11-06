package publicationstate

import (
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchingCIDMalformedPayloadCannotProduceProposalOrFloor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	malformed := []byte{0xa0, 0x01, 0x02}
	blobCID, err := publication.RawPayloadCID(malformed)
	require.NoError(t, err)
	record := publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: 0, Parent: []byte{}, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(malformed))}}
	record.PublicationID[15] = 0x71
	recordRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(recordRaw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: 0, SnapshotCID: recordCID, BlobCID: blobCID})
	require.NoError(t, err)
	observation := Observation{Origin: f.binding, SuppliedContext: SuppliedContext{RepositoryRevision: "malformed-payload-revision", RepositoryDigest: []byte{1, 2, 3}}, Head: head, Snapshots: []SnapshotBlock{{Key: "0000000000000000", Raw: recordRaw}}}
	store, _ := newStore(t, f)
	defer store.Close()
	_, err = store.RecordObservation(ctx, observation)
	require.NoError(t, err)
	proposal, err := store.Prepare(ctx, ModeFirstUse, observation, malformed)
	require.Error(t, err)
	assert.Equal(t, Proposal{}, proposal)
	_, present, loadErr := store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
}
