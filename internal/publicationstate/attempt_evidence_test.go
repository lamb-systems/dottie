package publicationstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptLostFenceRequiresExactOccupiedKeyAndPredecessor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newStore(t, f)
	defer store.Close()
	floorObservation := f.observation(1)
	first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 1)
	view := attemptView(f, floorObservation, false)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)

	competingRecord, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	competingRecord.PublicationID[0] = 0x7f
	competingRecord.PublicationID[15] = 0x7e
	competingRaw, err := publication.EncodeSnapshot(competingRecord)
	require.NoError(t, err)
	competingCID, err := publication.RecordCID(competingRaw)
	require.NoError(t, err)
	competingHead, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: 1, SnapshotCID: competingCID, BlobCID: competingRecord.Blob.CID})
	require.NoError(t, err)
	competingView := SuppliedRepositoryView{Origin: f.binding, Scope: ViewScopeWholeRepository, SuppliedContext: cloneContext(view.SuppliedContext), Head: competingHead, Snapshots: []SnapshotBlock{f.blocks[0], {Key: f.blocks[1].Key, Raw: competingRaw}}}
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, competingView)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, resolution.Outcome)
	assert.NotEqual(t, candidate.SnapshotRecord, competingRaw)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, &competingView)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &competingView, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, retired.Outcome)
}

func TestPublicationAttemptCompetingGenesisUsesDifferentVaultOnlyForLostFence(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	otherVault := f.binding.Vault
	otherVault[0] ^= 0x20
	record := publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: otherVault, PublicationID: [16]byte{0x42}, PublicationSeq: 0, Parent: []byte{}, Blob: blobForCandidate(t, candidate)}
	otherRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	otherCID, err := publication.RecordCID(otherRaw)
	require.NoError(t, err)
	otherHead, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: otherVault, PublicationSeq: 0, SnapshotCID: otherCID, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	competing := SuppliedRepositoryView{Origin: f.binding, Scope: ViewScopeWholeRepository, SuppliedContext: cloneContext(empty.SuppliedContext), Head: otherHead, Snapshots: []SnapshotBlock{{Key: f.blocks[0].Key, Raw: otherRaw}}}
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, competing)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, resolution.Outcome)
	assert.False(t, bytes.Equal(record.Vault[:], f.binding.Vault[:]))
	_, err = store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, competing)
	require.Error(t, err)
}

func TestSuppliedViewRejectsGapsAndWrongPredecessorBeforeOutcomeMutation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newStore(t, f)
	defer store.Close()
	floorObservation := f.observation(1)
	first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 1)
	view := attemptView(f, floorObservation, false)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	before, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)

	gapped := attemptView(f, f.observation(2), false)
	gapped.Snapshots = gapped.Snapshots[1:]
	_, err = store.ResolveAttempt(ctx, attempt.ID, before.StateDigest, gapped)
	require.ErrorIs(t, err, ErrInvalid)
	wrongParent := f.blocks[1]
	record, err := publication.DecodeSnapshot(wrongParent.Raw)
	require.NoError(t, err)
	record.Parent = bytes.Clone(proposal.CandidateRecordCID)
	wrongRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	wrongCID, err := publication.RecordCID(wrongRaw)
	require.NoError(t, err)
	wrongHead, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: 1, SnapshotCID: wrongCID, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	bad := SuppliedRepositoryView{Origin: f.binding, Scope: ViewScopeWholeRepository, SuppliedContext: cloneContext(view.SuppliedContext), Head: wrongHead, Snapshots: []SnapshotBlock{f.blocks[0], {Key: f.blocks[1].Key, Raw: wrongRaw}}}
	_, err = store.ResolveAttempt(ctx, attempt.ID, before.StateDigest, bad)
	require.ErrorIs(t, err, ErrInvalid)
	after, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, before.StateDigest, after.StateDigest)
}

func TestAttemptReadbackRejectsStoredSuffixBeyondLineageLimit(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	positionLimits := DefaultLimits()
	positionLimits.MaxLineageLinks = 2
	store, directory := newStore(t, f, positionLimits)
	floorObservation := f.observation(1)
	first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 1)
	preflight := attemptView(f, floorObservation, false)
	review := attemptReview()
	attempt := createAndSubmitSuccessor(t, store, f, candidate, preflight, review)
	conflict := competingSuccessorWithOneDescendant(t, f, preflight, candidate)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, conflict)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, resolution.Outcome)
	firstConflict, present, err := store.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	var proof firstConflictWire
	require.NoError(t, strictJSON(firstConflict.Evidence, &proof))
	assert.Len(t, proof.Proof.Suffix, 2)

	lowerLimits := positionLimits
	lowerLimits.MaxLineageLinks = 1
	encodedLimits, err := encodeLimits(lowerLimits)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='limits'", encodedLimits)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	rejected, err := OpenWithLimits(directory, f.binding, lowerLimits)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
	assert.Nil(t, rejected)
}

func competingSuccessorWithOneDescendant(t *testing.T, f fixture, preflight SuppliedRepositoryView, candidate CandidateInput) SuppliedRepositoryView {
	t.Helper()
	occupant, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	occupant.PublicationID = [16]byte{0x7d}
	occupantRaw, err := publication.EncodeSnapshot(occupant)
	require.NoError(t, err)
	occupantCID, err := publication.RecordCID(occupantRaw)
	require.NoError(t, err)
	descendant, err := publication.DecodeSnapshot(f.blocks[2].Raw)
	require.NoError(t, err)
	descendant.Parent = bytes.Clone(occupantCID)
	descendantRaw, err := publication.EncodeSnapshot(descendant)
	require.NoError(t, err)
	descendantCID, err := publication.RecordCID(descendantRaw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: descendant.Vault, PublicationSeq: descendant.PublicationSeq, SnapshotCID: descendantCID, BlobCID: descendant.Blob.CID})
	require.NoError(t, err)
	blocks := []SnapshotBlock{cloneSnapshotBlocks(f.blocks[:1])[0], {Key: candidate.SnapshotKey, Raw: occupantRaw}, {Key: f.blocks[2].Key, Raw: descendantRaw}}
	return SuppliedRepositoryView{Origin: f.binding, Scope: preflight.Scope, SuppliedContext: cloneContext(preflight.SuppliedContext), Head: head, Snapshots: blocks}
}

func TestAttemptLineageLimitAppliesToResolveAndDirectAbandon(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	limits := DefaultLimits()
	limits.MaxLineageLinks = 1
	store, directory := openAttemptStoreWithLimits(t, f, limits)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	oneLink := attemptView(f, f.observation(2), false)
	twoLinks := attemptView(f, f.observation(3), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	beforeResolve := readAttemptLogicalRows(t, store)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, twoLinks)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonRecordSet)
	assert.Equal(t, AttemptResolution{}, resolution)
	assert.Equal(t, beforeResolve, readAttemptLogicalRows(t, store))

	resolution, err = store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, oneLink)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSuperseded, resolution.Outcome)
	var proof attemptEvidenceWire
	require.NoError(t, strictJSON(resolution.Evidence, &proof))
	assert.Len(t, proof.Suffix, 2)
	beforeAbandon := readAttemptLogicalRows(t, store)
	proposal, err := store.PrepareAbandon(ctx, attempt.ID, &twoLinks)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonRecordSet)
	assert.Equal(t, AbandonProposal{}, proposal)
	assert.Equal(t, beforeAbandon, readAttemptLogicalRows(t, store))
	proposal, err = store.PrepareAbandon(ctx, attempt.ID, &oneLink)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, proposal.StateToken, &twoLinks, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonRecordSet)
	assert.Equal(t, Attempt{}, retired)
	assert.Equal(t, beforeAbandon, readAttemptLogicalRows(t, store))

	retired, err = store.AbandonAttempt(ctx, attempt.ID, proposal.StateToken, &oneLink, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	assert.Equal(t, OutcomeSuperseded, retired.Outcome)
	payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
	beforePayload, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	reopened, err := OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	defer reopened.Close()
	stored, err := reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, stored.Lifecycle)
	assert.Equal(t, OutcomeSuperseded, stored.Outcome)
	afterPayload, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	assert.Equal(t, beforePayload, afterPayload)
}
