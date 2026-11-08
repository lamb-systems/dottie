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

func TestPublicationAttemptOfflineLifecycleUsesDurableCustody(t *testing.T) {
	ctx := context.Background()
	packed, err := vault.Pack(model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory}}}, Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic attempt integration payload"), Mode: 0o600}}}})
	require.NoError(t, err)
	binding := publicationstate.Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx"}
	binding.Vault[0] = 0x62
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	publicationID := [16]byte{0x31}
	snapshotBytes, err := publication.EncodeSnapshot(publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID, PublicationSeq: 0, Parent: []byte{}, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))}})
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotBytes)
	require.NoError(t, err)
	headBytes, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: 0, SnapshotCID: snapshotCID, BlobCID: blobCID})
	require.NoError(t, err)
	contextValue := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	view := publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: contextValue}
	candidate := publicationstate.CandidateInput{SnapshotKey: "0000000000000000", SnapshotRecord: snapshotBytes, HeadRecord: headBytes, Payload: packed.Payload}
	review := publicationstate.LocalReviewContext{SelectionDigest: [32]byte{1}, SelectionRevision: 1, ApprovalDigest: [32]byte{2}, ApprovalRevision: 1}
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	material, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, packed.Payload, material.Payload)

	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchUpload, view, review)
	require.NoError(t, err)
	upload, err := store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, packed.Payload, upload.Payload)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchSubmission, view, review)
	require.NoError(t, err)
	submission, err := store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	assert.True(t, submission.SnapshotCreateOnly)
	assert.True(t, submission.RequiresAtomicBatch)
	assert.True(t, submission.RequiresCreateExclude)

	current := publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: contextValue, Head: headBytes, Snapshots: []publicationstate.SnapshotBlock{{Key: candidate.SnapshotKey, Raw: snapshotBytes}}}
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.OutcomeCurrent, resolution.Outcome)
	finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	assert.Equal(t, snapshotCID, finalized.Floor.RecordCID)
	require.NoError(t, store.Close())

	reopened, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	defer reopened.Close()
	floor, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, finalized.Floor, floor)
	retained, err := reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, retained.Lifecycle)
	retainedCandidate, err := reopened.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, packed.Payload, retainedCandidate.Payload)
}
