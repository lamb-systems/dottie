package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errMaterialTestBatchShape     = errors.New("material transport: unsupported batch shape")
	errMaterialTestStaleContext   = errors.New("material transport: stale expected context")
	errMaterialTestCreateConflict = errors.New("material transport: snapshot create conflict")
	errMaterialTestHeadExists     = errors.New("material transport: head already exists")
	errMaterialTestPredecessor    = errors.New("material transport: expected predecessor does not match the committed head")
	errMaterialTestPayloadMissing = errors.New("material transport: referenced payload was never uploaded")
	errMaterialTestRecordMismatch = errors.New("material transport: record bytes do not hash to the expected snapshot cid")
	errMaterialTestBeforeCommit   = errors.New("material transport: failed before commit")
	errMaterialTestCommitUnknown  = errors.New("material transport: committed but the response was lost")
	errMaterialTestUploadRejected = errors.New("material transport: upload rejected")
)

type materialTestTransport struct {
	mu               sync.Mutex
	binding          publicationstate.Binding
	scope            publicationstate.ViewScope
	context          publicationstate.SuppliedContext
	contextSeq       int
	blocks           map[string][]byte
	head             []byte
	blobs            map[string][]byte
	uploads          int
	applies          int
	applied          []MaterialWriteBatch
	uploadErr        error
	uploadCID        []byte
	writeOnUpload    bool
	failBeforeCommit bool
	commitThenFail   bool
}

func newMaterialTestTransport(binding publicationstate.Binding) *materialTestTransport {
	return &materialTestTransport{
		binding: binding, scope: publicationstate.ViewScopeWholeRepository,
		context: materialTestContext(0), blocks: map[string][]byte{}, blobs: map[string][]byte{},
	}
}

func materialTestContext(sequence int) publicationstate.SuppliedContext {
	return publicationstate.SuppliedContext{
		RepositoryRevision: fmt.Sprintf("synthetic-revision-%d", sequence),
		RepositoryDigest:   []byte{byte(sequence + 1), 0x5a},
	}
}

func (transport *materialTestTransport) UploadPayload(ctx context.Context, payload []byte) (publication.BlobReference, error) {
	if err := ctx.Err(); err != nil {
		return publication.BlobReference{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploads++
	if transport.uploadErr != nil {
		return publication.BlobReference{}, transport.uploadErr
	}
	cid, err := publication.RawPayloadCID(payload)
	if err != nil {
		return publication.BlobReference{}, err
	}
	transport.blobs[string(cid)] = bytes.Clone(payload)
	if transport.writeOnUpload {
		transport.advanceContextLocked()
	}
	if len(transport.uploadCID) != 0 {
		return publication.BlobReference{CID: bytes.Clone(transport.uploadCID), Size: uint64(len(payload))}, nil
	}
	return publication.BlobReference{CID: cid, Size: uint64(len(payload))}, nil
}

func (transport *materialTestTransport) ApplyWrites(ctx context.Context, batch MaterialWriteBatch) (MaterialWriteOutcome, error) {
	if err := ctx.Err(); err != nil {
		return MaterialWriteOutcome{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.applies++
	transport.applied = append(transport.applied, cloneMaterialWriteBatch(batch))
	if transport.failBeforeCommit {
		return MaterialWriteOutcome{}, errMaterialTestBeforeCommit
	}
	if err := transport.checkMaterialBatch(batch); err != nil {
		return MaterialWriteOutcome{}, err
	}
	transport.blocks[batch.SnapshotKey] = bytes.Clone(batch.SnapshotRecord)
	transport.head = bytes.Clone(batch.HeadRecord)
	transport.advanceContextLocked()
	if transport.commitThenFail {
		return MaterialWriteOutcome{}, errMaterialTestCommitUnknown
	}
	return MaterialWriteOutcome{Committed: true}, nil
}

func (transport *materialTestTransport) ReadView(ctx context.Context) (publicationstate.SuppliedRepositoryView, error) {
	if err := ctx.Err(); err != nil {
		return publicationstate.SuppliedRepositoryView{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	keys := make([]string, 0, len(transport.blocks))
	for key := range transport.blocks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	view := publicationstate.SuppliedRepositoryView{
		Origin: transport.binding, Scope: transport.scope,
		SuppliedContext: cloneMaterialContext(transport.context), Head: bytes.Clone(transport.head),
		Snapshots: make([]publicationstate.SnapshotBlock, 0, len(keys)),
	}
	for _, key := range keys {
		view.Snapshots = append(view.Snapshots, publicationstate.SnapshotBlock{Key: key, Raw: bytes.Clone(transport.blocks[key])})
	}
	return view, nil
}

func (transport *materialTestTransport) checkMaterialBatch(batch MaterialWriteBatch) error {
	if batch.SnapshotCollection != publication.SnapshotNSID || batch.HeadCollection != publication.HeadNSID || batch.HeadKey != materialHeadKey || !batch.SnapshotCreateOnly || !batch.RequiresAtomicBatch || !batch.RequiresCreateExclude || batch.RequiresPolicyCheck != (transport.binding.Backend == publicationstate.BackendSpaces) {
		return errMaterialTestBatchShape
	}
	if !sameMaterialContext(batch.ExpectedContext, transport.context) {
		return errMaterialTestStaleContext
	}
	snapshot, err := publication.DecodeSnapshot(batch.SnapshotRecord)
	if err != nil || snapshot.Vault != transport.binding.Vault {
		return errMaterialTestBatchShape
	}
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	if err != nil || key != batch.SnapshotKey {
		return errMaterialTestBatchShape
	}
	cid, err := publication.RecordCID(batch.SnapshotRecord)
	if err != nil || !bytes.Equal(cid, batch.ExpectedSnapshotCID) {
		return errMaterialTestRecordMismatch
	}
	payload, uploaded := transport.blobs[string(snapshot.Blob.CID)]
	if !uploaded {
		return errMaterialTestPayloadMissing
	}
	if uint64(len(payload)) != snapshot.Blob.Size {
		return errMaterialTestBatchShape
	}
	if err := publication.VerifyHeadBinding(batch.HeadRecord, batch.SnapshotRecord, batch.SnapshotKey); err != nil {
		return errMaterialTestBatchShape
	}
	head, err := publication.DecodeHead(batch.HeadRecord)
	if err != nil || head.Vault != transport.binding.Vault || head.PublicationSeq != snapshot.PublicationSeq || !bytes.Equal(head.SnapshotCID, cid) {
		return errMaterialTestBatchShape
	}
	if batch.HeadCreate {
		if len(transport.head) != 0 {
			return errMaterialTestHeadExists
		}
		if batch.ExpectedPredecessor != nil {
			return errMaterialTestPredecessor
		}
	} else {
		if batch.ExpectedPredecessor == nil || len(transport.head) == 0 {
			return errMaterialTestPredecessor
		}
		committed, err := publication.DecodeHead(transport.head)
		if err != nil || committed.PublicationSeq != batch.ExpectedPredecessor.Sequence || !bytes.Equal(committed.SnapshotCID, batch.ExpectedPredecessor.CID) {
			return errMaterialTestPredecessor
		}
		if snapshot.PublicationSeq != batch.ExpectedPredecessor.Sequence+1 || !bytes.Equal(snapshot.Parent, batch.ExpectedPredecessor.CID) {
			return errMaterialTestPredecessor
		}
		if _, ok := transport.blocks[batch.ExpectedPredecessor.Key]; !ok {
			return errMaterialTestPredecessor
		}
	}
	if _, exists := transport.blocks[batch.SnapshotKey]; exists {
		return errMaterialTestCreateConflict
	}
	return nil
}

func (transport *materialTestTransport) advanceContextLocked() {
	transport.contextSeq++
	transport.context = materialTestContext(transport.contextSeq)
}

func (transport *materialTestTransport) advanceContext() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.advanceContextLocked()
}

func (transport *materialTestTransport) installSnapshot(t *testing.T, raw []byte) {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.installSnapshotLocked(t, raw, true)
	transport.advanceContextLocked()
}

func (transport *materialTestTransport) installSnapshotQuietly(t *testing.T, raw []byte, head bool) {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.installSnapshotLocked(t, raw, head)
}

func (transport *materialTestTransport) installSnapshotLocked(t *testing.T, raw []byte, head bool) {
	t.Helper()
	snapshot, err := publication.DecodeSnapshot(raw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	require.NoError(t, err)
	transport.blocks[key] = bytes.Clone(raw)
	if !head {
		return
	}
	snapshotCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	encoded, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: snapshot.Vault, PublicationSeq: snapshot.PublicationSeq,
		SnapshotCID: snapshotCID, BlobCID: snapshot.Blob.CID,
	})
	require.NoError(t, err)
	transport.head = encoded
}

func (transport *materialTestTransport) committed(key string) []byte {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return bytes.Clone(transport.blocks[key])
}

func (transport *materialTestTransport) committedHead() []byte {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return bytes.Clone(transport.head)
}

func (transport *materialTestTransport) applyCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.applies
}

func (transport *materialTestTransport) uploadCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.uploads
}

func (transport *materialTestTransport) setUploadError(err error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploadErr = err
}

func (transport *materialTestTransport) setUploadCID(cid []byte) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploadCID = bytes.Clone(cid)
}

func (transport *materialTestTransport) setWriteOnUpload() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.writeOnUpload = true
}

func (transport *materialTestTransport) setFailBeforeCommit() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.failBeforeCommit = true
}

func (transport *materialTestTransport) setCommitThenFail() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.commitThenFail = true
}

type materialPublishFixture struct {
	binding       publicationstate.Binding
	store         *publicationstate.Store
	transport     *materialTestTransport
	coordinator   *Coordinator
	snapshot      model.Snapshot
	publicationID [16]byte
	review        publicationstate.LocalReviewContext
}

func newMaterialPublishFixture(t *testing.T) *materialPublishFixture {
	t.Helper()
	binding := publicationstate.Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x41, 0x52, 0x63}}
	binding.Repository = "at://" + binding.AccountDID
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	coordinator, err := NewCoordinator(Dependencies{State: openCoordinatorState(t)})
	require.NoError(t, err)
	return &materialPublishFixture{
		binding: binding, store: store, transport: newMaterialTestTransport(binding), coordinator: coordinator,
		snapshot: materialTestSnapshot("synthetic genesis payload"), publicationID: [16]byte{0x25, 0x71},
		review: publicationstate.LocalReviewContext{SelectionDigest: [32]byte{1}, SelectionRevision: 1, ApprovalDigest: [32]byte{2}, ApprovalRevision: 1},
	}
}

func materialTestSnapshot(content string) model.Snapshot {
	return model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
		Entries: []model.Entry{{
			TargetID: "files",
			File:     &model.FileEntry{Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte(content), Mode: 0o600},
		}},
	}
}

func materialTestCandidate(t *testing.T, binding publicationstate.Binding, publicationID [16]byte, sequence uint64, parent, payload []byte) publicationstate.CandidateInput {
	t.Helper()
	blobCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	snapshotRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID,
		PublicationSeq: sequence, Parent: parent, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(payload))},
	})
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotRecord)
	require.NoError(t, err)
	headRecord, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: sequence,
		SnapshotCID: snapshotCID, BlobCID: blobCID,
	})
	require.NoError(t, err)
	return publicationstate.CandidateInput{SnapshotKey: key, SnapshotRecord: snapshotRecord, HeadRecord: headRecord, Payload: payload}
}

func (fixture *materialPublishFixture) request() MaterialPublishRequest {
	return MaterialPublishRequest{
		Store: fixture.store, Transport: fixture.transport, Binding: fixture.binding,
		Snapshot: fixture.snapshot, PublicationID: fixture.publicationID, Review: fixture.review,
	}
}

func (fixture *materialPublishFixture) prepare(t *testing.T) MaterialPublishProposal {
	t.Helper()
	proposal, err := fixture.coordinator.PreparePublishMaterial(context.Background(), fixture.request())
	require.NoError(t, err)
	return proposal
}

func (fixture *materialPublishFixture) publish(t *testing.T) (MaterialPublishProposal, MaterialPublishResult) {
	t.Helper()
	proposal := fixture.prepare(t)
	result, err := fixture.coordinator.PublishMaterial(context.Background(), proposal, proposal.Confirmation)
	require.NoError(t, err)
	return proposal, result
}

func requireMaterialRefusal(t *testing.T, err error, stage, reason string) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublishMaterial)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, stage, classified.Stage())
	assert.Equal(t, reason, classified.Reason())
}

func requireMaterialStoreRefusal(t *testing.T, err error, class error, reason publicationstate.Reason) {
	t.Helper()
	require.ErrorIs(t, err, class)
	var refused *publicationstate.Error
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, reason, refused.Reason())
}

func materialBatchTamperCases() []struct {
	name   string
	tamper func(*MaterialWriteBatch)
} {
	flip := func(data []byte) []byte {
		cloned := bytes.Clone(data)
		cloned[0] ^= 0xff
		return cloned
	}
	return []struct {
		name   string
		tamper func(*MaterialWriteBatch)
	}{
		{"snapshot-collection", func(batch *MaterialWriteBatch) { batch.SnapshotCollection = publication.HeadNSID }},
		{"snapshot-key", func(batch *MaterialWriteBatch) { batch.SnapshotKey = "0000000000000001" }},
		{"snapshot-record", func(batch *MaterialWriteBatch) {
			batch.SnapshotRecord = append(bytes.Clone(batch.SnapshotRecord), 0x00)
		}},
		{"expected-snapshot-cid", func(batch *MaterialWriteBatch) { batch.ExpectedSnapshotCID = flip(batch.ExpectedSnapshotCID) }},
		{"snapshot-create-only", func(batch *MaterialWriteBatch) { batch.SnapshotCreateOnly = false }},
		{"head-collection", func(batch *MaterialWriteBatch) { batch.HeadCollection = publication.SnapshotNSID }},
		{"head-key", func(batch *MaterialWriteBatch) { batch.HeadKey = "other" }},
		{"head-record", func(batch *MaterialWriteBatch) { batch.HeadRecord = append(bytes.Clone(batch.HeadRecord), 0x00) }},
		{"head-create", func(batch *MaterialWriteBatch) { batch.HeadCreate = !batch.HeadCreate }},
		{"expected-predecessor", func(batch *MaterialWriteBatch) {
			batch.ExpectedPredecessor = &publicationstate.RecordReference{Key: batch.SnapshotKey, CID: bytes.Clone(batch.ExpectedSnapshotCID), Sequence: 0}
		}},
		{"expected-context", func(batch *MaterialWriteBatch) {
			batch.ExpectedContext.RepositoryRevision = "synthetic-revision-forged"
		}},
		{"requires-atomic-batch", func(batch *MaterialWriteBatch) { batch.RequiresAtomicBatch = false }},
		{"requires-create-exclude", func(batch *MaterialWriteBatch) { batch.RequiresCreateExclude = false }},
		{"requires-policy-check", func(batch *MaterialWriteBatch) { batch.RequiresPolicyCheck = !batch.RequiresPolicyCheck }},
	}
}

func TestPublishMaterialGenesisCommitsFloorAndRetiresAttempt(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	proposal, result := fixture.publish(t)

	assert.Equal(t, publicationstate.OutcomeCurrent, result.Outcome)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, result.Attempt.Lifecycle)
	assert.Equal(t, uint64(1), result.Floor.Revision)
	assert.Equal(t, uint64(0), result.Floor.Sequence)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, result.Floor.RecordCID)
	assert.Equal(t, proposal.Blob.CID, result.Floor.BlobCID)
	assert.Equal(t, proposal.Batch.HeadRecord, result.Floor.Head)
	assert.Equal(t, proposal.Batch.SnapshotRecord, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Equal(t, proposal.Batch.HeadRecord, fixture.transport.committedHead())
	assert.Equal(t, 1, fixture.transport.uploadCount())
	assert.Equal(t, 1, fixture.transport.applyCount())

	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, result.Floor, floor)
	_, hasActive, err := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, hasActive)
	retained, err := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, retained.Lifecycle)

	decoded, err := publication.DecodePayload(packed.Payload, proposal.Blob)
	require.NoError(t, err)
	require.Len(t, decoded.Entries, 1)
	assert.Equal(t, []byte("synthetic genesis payload"), decoded.Entries[0].File.Content)
}

func TestPublishMaterialSuccessorExtendsCapturedFloor(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	genesisProposal, genesis := fixture.publish(t)

	fixture.publicationID = [16]byte{0x25, 0x72}
	fixture.snapshot = materialTestSnapshot("synthetic successor payload")
	proposal := fixture.prepare(t)
	assert.False(t, proposal.Batch.HeadCreate)
	require.NotNil(t, proposal.Batch.ExpectedPredecessor)
	assert.Equal(t, publicationstate.RecordReference{Key: genesisProposal.Batch.SnapshotKey, CID: genesis.Floor.RecordCID, Sequence: 0}, *proposal.Batch.ExpectedPredecessor)

	result, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), result.Floor.Revision)
	assert.Equal(t, uint64(1), result.Floor.Sequence)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, result.Floor.RecordCID)
	record, err := publication.DecodeSnapshot(proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, genesis.Floor.RecordCID, record.Parent)
	assert.Equal(t, genesisProposal.Batch.SnapshotRecord, fixture.transport.committed(genesisProposal.Batch.SnapshotKey))
	assert.Equal(t, proposal.Batch.HeadRecord, fixture.transport.committedHead())
}

func TestPublishMaterialRefusesRejectedUpload(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setUploadError(errMaterialTestUploadRejected)
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "upload", "upload_failed")
	assert.Equal(t, 0, fixture.transport.applyCount())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptUploadStarted, attempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeNotSubmitted, attempt.Outcome)
	retained, readErr := fixture.store.ReadCandidate(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, readErr)
	assert.Equal(t, proposal.Candidate.Payload, retained.Payload)
}

func TestPublishMaterialRefusesApplyFailureBeforeCommit(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setFailBeforeCommit()
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Equal(t, 1, fixture.transport.applyCount())
	assert.Nil(t, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Nil(t, fixture.transport.committedHead())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, attempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeUnresolved, attempt.Outcome)
}

func TestPublishMaterialSurvivesCommittedResponseLoss(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setCommitThenFail()
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Equal(t, 1, fixture.transport.applyCount())
	assert.Equal(t, proposal.Batch.SnapshotRecord, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Equal(t, proposal.Batch.HeadRecord, fixture.transport.committedHead())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	pending, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, pending.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeUnresolved, pending.Outcome)

	view, viewErr := fixture.transport.ReadView(ctx)
	require.NoError(t, viewErr)
	loaded, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	resolution, resolveErr := fixture.store.ResolveAttempt(ctx, proposal.Proposal.AttemptID, loaded.StateDigest, view)
	require.NoError(t, resolveErr)
	assert.Equal(t, publicationstate.OutcomeCurrent, resolution.Outcome)
	finalization, finalizeErr := fixture.store.FinalizeAttempt(ctx, proposal.Proposal.AttemptID, resolution.Attempt.StateDigest, view)
	require.NoError(t, finalizeErr)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, finalization.Floor.RecordCID)
	assert.Equal(t, 1, fixture.transport.applyCount())
}

func TestPublishMaterialRefusesBlobReferenceMismatch(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	other, err := publication.RawPayloadCID([]byte("synthetic unrelated payload"))
	require.NoError(t, err)
	fixture.transport.setUploadCID(other)
	proposal := fixture.prepare(t)

	_, publishErr := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, publishErr, "upload", "blob_mismatch")
	assert.Equal(t, 0, fixture.transport.applyCount())
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptUploadStarted, attempt.Lifecycle)
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
}

func TestPublishMaterialRefusesConfirmationMismatch(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	wrong := proposal.Confirmation
	wrong[0] ^= 0xff

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, wrong)
	requireMaterialRefusal(t, err, "consent", "confirmation_mismatch")
	_, zeroErr := fixture.coordinator.PublishMaterial(ctx, proposal, [32]byte{})
	requireMaterialRefusal(t, zeroErr, "consent", "confirmation_mismatch")
	_, hasActive, activeErr := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, activeErr)
	assert.False(t, hasActive)
	_, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.Error(t, loadErr)
	assert.Equal(t, 0, fixture.transport.uploadCount())
	assert.Equal(t, 0, fixture.transport.applyCount())
}

func TestPublishMaterialRefusesStaleProposal(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	view, err := fixture.transport.ReadView(ctx)
	require.NoError(t, err)
	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	otherCandidate := materialTestCandidate(t, fixture.binding, [16]byte{0x30}, 0, nil, packed.Payload)
	otherProposal, err := fixture.store.PrepareAttempt(ctx, otherCandidate, view, fixture.review)
	require.NoError(t, err)
	otherAttempt, err := fixture.store.CreateAttempt(ctx, otherProposal.StateToken, otherCandidate, view, fixture.review, otherProposal.Confirmation)
	require.NoError(t, err)
	abandonProposal, err := fixture.store.PrepareAbandon(ctx, otherAttempt.ID, nil)
	require.NoError(t, err)
	_, err = fixture.store.AbandonAttempt(ctx, otherAttempt.ID, abandonProposal.StateToken, nil, abandonProposal.Confirmation)
	require.NoError(t, err)

	_, publishErr := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialStoreRefusal(t, publishErr, publicationstate.ErrConsent, publicationstate.ReasonStale)
	assert.Equal(t, 0, fixture.transport.uploadCount())
	assert.Equal(t, 0, fixture.transport.applyCount())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
}

func TestPublishMaterialRefusesTamperedBatch(t *testing.T) {
	ctx := context.Background()
	for _, testCase := range materialBatchTamperCases() {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newMaterialPublishFixture(t)
			proposal := fixture.prepare(t)
			testCase.tamper(&proposal.Batch)

			_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
			requireMaterialRefusal(t, err, "batch", "batch_invalid")
			_, hasActive, activeErr := fixture.store.ActiveAttempt(ctx)
			require.NoError(t, activeErr)
			assert.False(t, hasActive)
			assert.Equal(t, 0, fixture.transport.uploadCount())
			assert.Equal(t, 0, fixture.transport.applyCount())
		})
	}
}

func TestPublishMaterialRefusesStaleObservation(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	stale := fixture.prepare(t)
	fixture.transport.advanceContext()
	observed, observedErr := fixture.transport.ReadView(ctx)
	require.NoError(t, observedErr)
	assert.False(t, sameMaterialContext(stale.Batch.ExpectedContext, observed.SuppliedContext))

	_, err := fixture.coordinator.PublishMaterial(ctx, stale, stale.Confirmation)
	requireMaterialRefusal(t, err, "view", "observation_stale")
	_, hasActive, activeErr := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, activeErr)
	assert.False(t, hasActive)
	assert.Equal(t, 0, fixture.transport.uploadCount())
	assert.Equal(t, 0, fixture.transport.applyCount())

	fresh, freshResult := fixture.publish(t)
	assert.NotEqual(t, stale.Batch.ExpectedContext.RepositoryRevision, fresh.Batch.ExpectedContext.RepositoryRevision)
	assert.True(t, sameMaterialContext(fresh.Batch.ExpectedContext, observed.SuppliedContext))
	assert.Equal(t, fresh.Batch.ExpectedSnapshotCID, freshResult.Floor.RecordCID)
	assert.Equal(t, 1, fixture.transport.applyCount())
}

func TestPublishMaterialRefusesStaleContextRejection(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setWriteOnUpload()
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Equal(t, 1, fixture.transport.applyCount())
	assert.Nil(t, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Nil(t, fixture.transport.committedHead())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	pending, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, pending.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeUnresolved, pending.Outcome)

	_, replayErr := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, replayErr, "view", "observation_stale")
	assert.Equal(t, 1, fixture.transport.applyCount())
	_, freshErr := fixture.coordinator.PreparePublishMaterial(ctx, fixture.request())
	requireMaterialStoreRefusal(t, freshErr, publicationstate.ErrConsent, publicationstate.ReasonActiveAttempt)
}

func TestPublishMaterialRefusesLostFenceResolution(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setFailBeforeCommit()
	proposal := fixture.prepare(t)
	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")

	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	competitor := materialTestCandidate(t, fixture.binding, [16]byte{0x40}, 0, nil, packed.Payload)
	fixture.transport.installSnapshot(t, competitor.SnapshotRecord)

	view, viewErr := fixture.transport.ReadView(ctx)
	require.NoError(t, viewErr)
	loaded, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	resolution, resolveErr := fixture.store.ResolveAttempt(ctx, proposal.Proposal.AttemptID, loaded.StateDigest, view)
	require.NoError(t, resolveErr)
	assert.Equal(t, publicationstate.OutcomeLostFence, resolution.Outcome)
	_, finalizeErr := fixture.store.FinalizeAttempt(ctx, proposal.Proposal.AttemptID, resolution.Attempt.StateDigest, view)
	requireMaterialStoreRefusal(t, finalizeErr, publicationstate.ErrContinuity, publicationstate.ReasonSubmittedUnknown)
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)

	evidence, recorded, evidenceErr := fixture.store.ReadFirstConflict(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, evidenceErr)
	require.True(t, recorded)
	assert.Equal(t, competitor.SnapshotRecord, evidence.HeadRecord)
	assert.Equal(t, uint64(0), evidence.HeadSequence)
}

func TestPublishMaterialRefusesObsoleteTokens(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	attempt, err := fixture.store.CreateAttempt(ctx, proposal.Proposal.StateToken, proposal.Candidate, proposal.View, proposal.Review, proposal.Confirmation)
	require.NoError(t, err)
	preDispatch, err := fixture.store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)

	uploadProposal, err := fixture.store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchUpload, proposal.View, proposal.Review)
	require.NoError(t, err)
	_, wrongDomainUpload := fixture.store.BeginUpload(ctx, attempt.ID, attempt.StateDigest, proposal.View, proposal.Review, uploadProposal.Confirmation)
	requireMaterialStoreRefusal(t, wrongDomainUpload, publicationstate.ErrConsent, publicationstate.ReasonStale)
	_, err = fixture.store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, proposal.View, proposal.Review, uploadProposal.Confirmation)
	require.NoError(t, err)
	_, reusedErr := fixture.store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, proposal.View, proposal.Review, uploadProposal.Confirmation)
	requireMaterialStoreRefusal(t, reusedErr, publicationstate.ErrConsent, publicationstate.ReasonStale)

	submissionProposal, err := fixture.store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchSubmission, proposal.View, proposal.Review)
	require.NoError(t, err)
	_, err = fixture.store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, proposal.View, proposal.Review, submissionProposal.Confirmation)
	require.NoError(t, err)
	postSubmission, err := fixture.store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.NotEqual(t, preDispatch.StateDigest, postSubmission.StateDigest)

	view, viewErr := fixture.transport.ReadView(ctx)
	require.NoError(t, viewErr)
	_, wrongDomainResolve := fixture.store.ResolveAttempt(ctx, attempt.ID, uploadProposal.StateToken, view)
	requireMaterialStoreRefusal(t, wrongDomainResolve, publicationstate.ErrConsent, publicationstate.ReasonStale)
	_, obsoleteErr := fixture.store.ResolveAttempt(ctx, attempt.ID, preDispatch.StateDigest, view)
	requireMaterialStoreRefusal(t, obsoleteErr, publicationstate.ErrConsent, publicationstate.ReasonStale)
	_, currentErr := fixture.store.ResolveAttempt(ctx, attempt.ID, postSubmission.StateDigest, view)
	require.NoError(t, currentErr)
}

type materialCancelingTransport struct {
	MaterialTransport
	cancel context.CancelFunc
}

func (transport materialCancelingTransport) ApplyWrites(context.Context, MaterialWriteBatch) (MaterialWriteOutcome, error) {
	transport.cancel()
	return MaterialWriteOutcome{}, errMaterialTestBeforeCommit
}

func TestPublishMaterialKeepsSubmissionAmbiguityAfterCancellation(t *testing.T) {
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proposal.Transport = materialCancelingTransport{MaterialTransport: fixture.transport, cancel: cancel}

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Nil(t, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Nil(t, fixture.transport.committedHead())
}

func TestPublishMaterialBatchMatchesSubmissionMaterial(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	attempt, err := fixture.store.CreateAttempt(ctx, proposal.Proposal.StateToken, proposal.Candidate, proposal.View, proposal.Review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := fixture.store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchUpload, proposal.View, proposal.Review)
	require.NoError(t, err)
	_, err = fixture.store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, proposal.View, proposal.Review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := fixture.store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchSubmission, proposal.View, proposal.Review)
	require.NoError(t, err)
	submission, err := fixture.store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, proposal.View, proposal.Review, submissionProposal.Confirmation)
	require.NoError(t, err)

	material := materialWriteBatchFromSubmission(submission)
	assert.True(t, sameMaterialWriteBatch(proposal.Batch, material))
	assert.Nil(t, material.ExpectedPredecessor)
	for _, testCase := range materialBatchTamperCases() {
		t.Run(testCase.name, func(t *testing.T) {
			tampered := cloneMaterialWriteBatch(material)
			testCase.tamper(&tampered)
			assert.False(t, sameMaterialWriteBatch(proposal.Batch, tampered))
		})
	}
}

func TestPublishMaterialTransportEnforcesConditionalBatch(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)

	_, err := fixture.transport.ApplyWrites(ctx, proposal.Batch)
	require.ErrorIs(t, err, errMaterialTestPayloadMissing)
	assert.Nil(t, fixture.transport.committedHead())

	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)

	competing := materialTestCandidate(t, fixture.binding, [16]byte{0x41}, 0, nil, packed.Payload)
	fixture.transport.installSnapshotQuietly(t, competing.SnapshotRecord, false)
	_, err = fixture.transport.ApplyWrites(ctx, proposal.Batch)
	require.ErrorIs(t, err, errMaterialTestCreateConflict, "the transport accepted a create-only snapshot that already exists")
	assert.Nil(t, fixture.transport.committedHead())

	fixture = newMaterialPublishFixture(t)
	proposal = fixture.prepare(t)
	packed, err = vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)
	head := materialTestCandidate(t, fixture.binding, [16]byte{0x42}, 0, nil, packed.Payload)
	fixture.transport.installSnapshotQuietly(t, head.SnapshotRecord, true)
	_, err = fixture.transport.ApplyWrites(ctx, proposal.Batch)
	require.ErrorIs(t, err, errMaterialTestHeadExists, "the transport accepted a head create against an existing head")
	assert.Equal(t, head.SnapshotRecord, fixture.transport.committed(head.SnapshotKey))

	fixture = newMaterialPublishFixture(t)
	proposal = fixture.prepare(t)
	packed, err = vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)
	fixture.transport.advanceContext()
	_, err = fixture.transport.ApplyWrites(ctx, proposal.Batch)
	require.ErrorIs(t, err, errMaterialTestStaleContext, "the transport accepted a batch with a stale expected context")
	assert.Nil(t, fixture.transport.committedHead())

	fixture = newMaterialPublishFixture(t)
	proposal = fixture.prepare(t)
	packed, err = vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)
	different := materialTestSnapshot("synthetic competing payload")
	differentPacked, err := vault.Pack(different)
	require.NoError(t, err)
	other := materialTestCandidate(t, fixture.binding, [16]byte{0x43}, 0, nil, differentPacked.Payload)
	forged := cloneMaterialWriteBatch(proposal.Batch)
	forged.SnapshotRecord = other.SnapshotRecord
	_, err = fixture.transport.ApplyWrites(ctx, forged)
	require.ErrorIs(t, err, errMaterialTestRecordMismatch, "the transport accepted record bytes that do not hash to the expected snapshot cid")
	assert.Nil(t, fixture.transport.committedHead())
}
