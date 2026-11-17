package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func publicationCandidateFixture(t *testing.T) (*Coordinator, platform.Paths, config.Config) {
	t.Helper()
	paths := materialTestPaths(t)
	require.NoError(t, os.MkdirAll(filepath.Join(paths.Home, "config"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(paths.Home, "config", "init.lua"), []byte("synthetic candidate payload"), 0o600))
	coordinator, err := NewCoordinator(Dependencies{State: openCoordinatorState(t), Paths: paths})
	require.NoError(t, err)
	configuration := config.Config{Version: config.Version, Targets: []config.Target{{
		ID: "files", Source: model.SourceFiles, Mode: config.BackupOnly,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}}}
	return coordinator, paths, configuration
}

func TestBuildPublicationSnapshotAndMaterialDescribeOneReviewedSnapshot(t *testing.T) {
	ctx := context.Background()
	coordinator, _, configuration := publicationCandidateFixture(t)
	binding := publicationstate.Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x41}}
	binding.Repository = "at://" + binding.AccountDID
	publicationID := [16]byte{0x51, 0x52}
	request := PublicationCandidateRequest{Configuration: configuration, PublicationID: publicationID}

	reviewed, err := coordinator.buildPublicationSnapshot(ctx, request)
	require.NoError(t, err)
	published, err := coordinator.buildPublicationSnapshot(ctx, request)
	require.NoError(t, err, "the second composition of the same request refused")
	reviewedPacked, err := vault.Pack(reviewed)
	require.NoError(t, err)
	publishedPacked, err := vault.Pack(published)
	require.NoError(t, err)
	assert.Equal(t, reviewedPacked.Payload, publishedPacked.Payload, "the published snapshot differs from the reviewed snapshot")
	assert.Len(t, reviewed.Targets, 1)
	require.Len(t, reviewed.Entries, 1)
	assert.Equal(t, []byte("synthetic candidate payload"), reviewed.Entries[0].File.Content)

	view := publicationstate.SuppliedRepositoryView{
		Origin: binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: materialTestContext(0),
	}
	candidate, blob, batch, err := buildPublicationMaterial(binding, reviewed, publicationstate.Floor{}, false, view, publicationID)
	require.NoError(t, err)
	assert.Equal(t, reviewedPacked.Payload, candidate.Payload, "the builder packed a different snapshot than the reviewed one")
	assert.Equal(t, uint64(len(reviewedPacked.Payload)), blob.Size)
	payloadCID, err := publication.RawPayloadCID(candidate.Payload)
	require.NoError(t, err)
	assert.Equal(t, payloadCID, blob.CID, "the returned blob reference is not the candidate payload reference")
	assert.Equal(t, view.SuppliedContext, batch.ExpectedContext, "the batch does not carry the supplied view context")
	assert.True(t, batch.HeadCreate)
	assert.Nil(t, batch.ExpectedPredecessor)

	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publicationID, record.PublicationID)
	decoded, err := publication.DecodePayload(candidate.Payload, record.Blob)
	require.NoError(t, err)
	decodedPacked, err := vault.Pack(decoded)
	require.NoError(t, err)
	assert.Equal(t, reviewedPacked.Payload, decodedPacked.Payload)
}

func TestBuildPublicationMaterialExtendsTheSuppliedFloor(t *testing.T) {
	ctx := context.Background()
	coordinator, _, configuration := publicationCandidateFixture(t)
	binding := publicationstate.Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x42}}
	binding.Repository = "at://" + binding.AccountDID
	snapshot, err := coordinator.buildPublicationSnapshot(ctx, PublicationCandidateRequest{Configuration: configuration, PublicationID: [16]byte{0x53}})
	require.NoError(t, err)
	predecessor, predecessorBlob, err := encodePublicationCandidate(binding, snapshot, publicationstate.Floor{}, false, [16]byte{0x53})
	require.NoError(t, err)
	predecessorCID, err := publication.RecordCID(predecessor.SnapshotRecord)
	require.NoError(t, err)
	floor := publicationstate.Floor{Sequence: 0, RecordCID: predecessorCID, BlobCID: predecessorBlob.CID, SnapshotKey: predecessor.SnapshotKey, Revision: 7, Generation: 2}
	view := publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: materialTestContext(1)}

	candidate, _, batch, err := buildPublicationMaterial(binding, snapshot, floor, true, view, [16]byte{0x53})
	require.NoError(t, err)
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), record.PublicationSeq)
	assert.Equal(t, floor.RecordCID, record.Parent)
	expectedKey, keyErr := publication.SequenceKey(1)
	require.NoError(t, keyErr)
	assert.Equal(t, expectedKey, candidate.SnapshotKey)
	assert.False(t, batch.HeadCreate)
	require.NotNil(t, batch.ExpectedPredecessor)
	assert.Equal(t, uint64(0), batch.ExpectedPredecessor.Sequence)
	assert.Equal(t, floor.RecordCID, batch.ExpectedPredecessor.CID)

	_, _, _, err = buildPublicationMaterial(binding, snapshot, floor, true, publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: materialTestContext(2)}, [16]byte{})
	require.Error(t, err, "the builder accepted a zero publication identity")
}

func TestPublicationSyncSnapshotKeepsTheDeclaredAppliedMode(t *testing.T) {
	for _, declared := range []uint32{0o600, 0o644} {
		floor := []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "niri.kdl", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("before"), Mode: 0o600}}}
		remote := []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "niri.kdl", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("after"), Mode: declared}}}
		local := []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "niri.kdl", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("after"), Mode: declared}}}

		composed := publicationSyncPostPullEntries(floor, remote, local)
		require.Len(t, composed, 1)
		require.NotNil(t, composed[0].File)
		assert.Equal(t, declared, composed[0].File.Mode)
		assert.Equal(t, []byte("after"), composed[0].File.Content)
	}
}

func TestBuildPublicationSnapshotUsesOnlyTheSuppliedBaseAndRemoteEntries(t *testing.T) {
	ctx := context.Background()
	coordinator, _, configuration := publicationCandidateFixture(t)
	base := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory}}}, Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic candidate payload"), Mode: 0o600}}}}
	request := PublicationCandidateRequest{Configuration: configuration, BaseSnapshot: base, RemoteSnapshot: base, PublicationID: [16]byte{0x54}}

	snapshot, err := coordinator.buildPublicationSnapshot(ctx, request)
	require.NoError(t, err)
	require.Len(t, snapshot.Entries, 1, "an unchanged base and remote produced a candidate entry set")
	assert.Equal(t, []byte("synthetic candidate payload"), snapshot.Entries[0].File.Content)

	_, err = coordinator.buildPublicationSnapshot(ctx, PublicationCandidateRequest{Configuration: configuration, PublicationID: [16]byte{}})
	require.ErrorIs(t, err, ErrPublicationCandidate)
	if _, err := coordinator.buildPublicationSnapshot(ctx, PublicationCandidateRequest{Configuration: config.Config{Version: config.Version}, PublicationID: [16]byte{0x55}}); err == nil {
		assert.Fail(t, "an empty target set produced a publication snapshot")
	}
}
