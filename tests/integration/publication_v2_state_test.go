package integration

import (
	"context"
	"os"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationV2StatePersistsOnlyAcceptedPositionEvidence(t *testing.T) {
	packed, err := vault.Pack(model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory}}}, Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic integration payload"), Mode: 0o600}}}})
	require.NoError(t, err)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	binding := publicationstate.Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx"}
	binding.Vault[0] = 0x52
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	recordBytes, err := publication.EncodeSnapshot(publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: [16]byte{0x31}, PublicationSeq: 0, Parent: []byte{}, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))}})
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(recordBytes)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: 0, SnapshotCID: recordCID, BlobCID: blobCID})
	require.NoError(t, err)
	observation := publicationstate.Observation{Origin: binding, SuppliedContext: publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}, Head: head, Snapshots: []publicationstate.SnapshotBlock{{Key: "0000000000000000", Raw: recordBytes}}}
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	proposal, err := store.Prepare(context.Background(), publicationstate.ModeFirstUse, observation, packed.Payload)
	require.NoError(t, err)
	floor, err := store.Accept(context.Background(), publicationstate.ModeFirstUse, proposal.StateToken, observation, packed.Payload, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), floor.Generation)
	require.NoError(t, store.Close())
	reopened, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	defer reopened.Close()
	loaded, present, err := reopened.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, floor, loaded)
	_, err = reopened.Prepare(context.Background(), publicationstate.ModeAdvance, observation, nil)
	assert.Error(t, err)
	page, err := reopened.History(context.Background(), 0, 1)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	require.Len(t, page.Records, 1)
	assert.Equal(t, recordBytes, page.Records[0].Raw)
}
