package service

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

type memoryProposalStore struct {
	mu      sync.Mutex
	records map[[16]byte]PublicationProposalRecord
}

func newMemoryProposalStore() *memoryProposalStore {
	return &memoryProposalStore{records: map[[16]byte]PublicationProposalRecord{}}
}

func (store *memoryProposalStore) List(context.Context) ([]PublicationProposalRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]PublicationProposalRecord, 0, len(store.records))
	for _, record := range store.records {
		records = append(records, record)
	}
	return records, nil
}

func (store *memoryProposalStore) Issue(_ context.Context, record PublicationProposalRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[record.PublicationID] = record
	return nil
}

func (store *memoryProposalStore) Consume(_ context.Context, publicationID [16]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[publicationID]
	if !found {
		return ErrPublicationProposalAbsent
	}
	record.Consumed = true
	store.records[publicationID] = record
	return nil
}

func (store *memoryProposalStore) Delete(_ context.Context, publicationID [16]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.records, publicationID)
	return nil
}

func (store *memoryProposalStore) has(publicationID [16]byte) (PublicationProposalRecord, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[publicationID]
	return record, found
}

type stubAcceptedSource struct {
	mu       sync.Mutex
	payload  publication.Payload
	snapshot model.Snapshot
	err      error
	calls    int
}

func (source *stubAcceptedSource) ReadAcceptedPayload(context.Context) (AcceptedPublication, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	if source.err != nil {
		return AcceptedPublication{}, source.err
	}
	if source.payload.Form != "" {
		return AcceptedPublication{Payload: source.payload}, nil
	}
	return AcceptedPublication{
		Payload: publication.Payload{
			Form: publication.PayloadFormPacked, Snapshot: clonePublicationSnapshot(source.snapshot),
		},
	}, nil
}

func (source *stubAcceptedSource) setPayload(payload publication.Payload) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.payload = payload
}

func (source *stubAcceptedSource) set(snapshot model.Snapshot) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.snapshot = snapshot
}

type publicationPushFixture struct {
	binding       publicationstate.Binding
	store         *publicationstate.Store
	directory     string
	transport     *materialTestTransport
	coordinator   *Coordinator
	paths         platform.Paths
	configuration config.Config
	reviews       *materialReviewSource
	records       *memoryProposalStore
	reader        *stubAcceptedSource
	publicationID [16]byte
}

func newPublicationPushFixture(t *testing.T) *publicationPushFixture {
	t.Helper()
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x61},
	}
	binding.Repository = "at://" + binding.AccountDID
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	paths := materialTestPaths(t)
	require.NoError(t, os.MkdirAll(filepath.Join(paths.Home, "config"), 0o700))
	require.NoError(
		t,
		os.WriteFile(filepath.Join(paths.Home, "config", "init.lua"), []byte("synthetic push payload"), 0o600),
	)
	coordinator, err := NewCoordinator(Dependencies{State: openCoordinatorState(t), Paths: paths})
	require.NoError(t, err)
	review := publicationstate.LocalReviewContext{
		SelectionDigest:   [32]byte{0x71},
		SelectionRevision: 1,
		ApprovalDigest:    [32]byte{0x72},
		ApprovalRevision:  1,
	}
	fixture := &publicationPushFixture{
		binding: binding, store: store, directory: directory,
		transport: newMaterialTestTransport(binding), coordinator: coordinator,
		paths: paths, reviews: newMaterialReviewSource(review), records: newMemoryProposalStore(),
		reader: &stubAcceptedSource{}, publicationID: [16]byte{0x73, 0x74},
		configuration: config.Config{Version: config.Version, Targets: []config.Target{{
			ID: "files", Source: model.SourceFiles, Mode: config.BackupOnly,
			Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}}},
	}
	t.Cleanup(func() { _ = fixture.store.Close() })
	return fixture
}

func (fixture *publicationPushFixture) reopenStore(t *testing.T) {
	t.Helper()
	require.NoError(t, fixture.store.Close())
	reopened, err := publicationstate.Open(fixture.directory, fixture.binding)
	require.NoError(t, err)
	fixture.store = reopened
}

func (fixture *publicationPushFixture) request(
	publicationID [16]byte,
	record *PublicationProposalRecord,
) PublicationPushRequest {
	return PublicationPushRequest{
		Store: fixture.store, Transport: fixture.transport, Reader: fixture.reader, Records: fixture.records,
		Binding: fixture.binding, Configuration: fixture.configuration, Reviews: fixture.reviews,
		PublicationID: publicationID, Record: record,
	}
}

func (fixture *publicationPushFixture) publish(t *testing.T) PublicationPushPreparation {
	t.Helper()
	ctx := context.Background()
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.False(t, preparation.NoOp)
	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.NoError(t, err)
	return preparation
}

func TestPreparePublicationPushIssuesOneRetainedRecordAndReprintsTheSameConfirmation(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.True(t, preparation.Issued)
	assert.False(t, preparation.Present)
	assert.Equal(t, fixture.publicationID, preparation.Proposal.PublicationID)
	assert.Equal(t, preparation.Proposal.Confirmation, preparation.Record.Confirmation)
	assert.Equal(t, publicationstate.AttemptPrepared, preparation.Record.Lifecycle)
	assert.False(t, preparation.Record.Consumed)
	assert.Equal(t, fixture.binding, preparation.Record.Binding)
	assert.Equal(t, preparation.Proposal.Proposal.CapturedGeneration, preparation.Record.Generation)
	assert.Equal(t, preparation.Proposal.Proposal.CandidateRecordCID, preparation.Record.CandidateRecordCID)
	assert.Equal(t, uint64(1), preparation.Record.Version)
	record, found := fixture.records.has(fixture.publicationID)
	require.True(t, found)
	assert.Equal(t, preparation.Record, record)
	assert.Equal(t, 0, fixture.transport.uploadCount(), "a review-only preparation uploaded a payload")
	assert.Zero(t, fixture.transport.sendCount(), "a review-only preparation dispatched writes")

	retained := record
	reattached, err := fixture.coordinator.PreparePublicationPush(
		ctx,
		fixture.request(fixture.publicationID, &retained),
	)
	require.NoError(t, err)
	assert.False(t, reattached.Issued)
	assert.Equal(
		t,
		preparation.Proposal.Confirmation,
		reattached.Proposal.Confirmation,
		"reattachment recomputed a different confirmation",
	)
	assert.Zero(t, fixture.transport.uploadCount(), "reattachment uploaded a payload")
}

func TestConfirmPublicationPushPublishesOnceAndDeletesTheRetainedRecord(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)

	result, err := fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.OutcomeCurrent, result.Outcome)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, result.Attempt.Lifecycle)
	assert.Equal(t, uint64(1), result.Floor.Revision)
	assert.Equal(t, 1, fixture.transport.uploadCount())
	assert.Equal(t, 1, fixture.transport.sendCount())
	_, found := fixture.records.has(fixture.publicationID)
	assert.False(t, found, "the retained record survived a terminal publication")

	require.NoError(t, fixture.records.Issue(ctx, preparation.Record))
	replayed, err := fixture.coordinator.PreparePublicationPush(
		ctx,
		fixture.request(fixture.publicationID, &preparation.Record),
	)
	require.ErrorIs(t, err, ErrPublicationProposalStale, "a retired attempt identity was not refused as stale")
	assert.Empty(t, replayed.Proposal.Confirmation)
	assert.Equal(t, 1, fixture.transport.sendCount())
	consumed, found := fixture.records.has(fixture.publicationID)
	require.True(t, found)
	assert.True(t, consumed.Consumed, "the stale record was not marked consumed")
}

func TestPreparePublicationPushRefusesAConsumedRecordWithoutDispatch(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.NoError(t, fixture.records.Consume(ctx, fixture.publicationID))

	consumed := preparation.Record
	consumed.Consumed = true
	_, err = fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, &consumed))
	require.ErrorIs(t, err, ErrPublicationProposalConsumed)
	assert.Zero(t, fixture.transport.uploadCount())
	assert.Zero(t, fixture.transport.sendCount())
	record, found := fixture.records.has(fixture.publicationID)
	require.True(t, found)
	assert.True(t, record.Consumed)
	assert.Equal(t, preparation.Proposal.Confirmation, record.Confirmation, "the consumed record was rewritten")
}

func TestPreparePublicationPushSurfacesAnActiveAttemptAndRefusesAbandonmentPastSubmission(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	fixture.transport.setFailBeforeCommit()
	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.Error(t, err)

	_, err = fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x76}, nil))
	require.ErrorIs(t, err, ErrPublicationProposalActive)
	_, err = fixture.coordinator.AbandonPublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.ErrorIs(t, err, ErrPublicationProposalUnresolved)
	active, has, activeErr := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, activeErr)
	require.True(t, has)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, active.Lifecycle, "the unresolved attempt was abandoned")
}

func TestConfirmPublicationPushCleansUpAPreSubmissionFailure(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	fixture.transport.setPrepareError(errMaterialTestBatchShape)
	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.Error(t, err)

	_, has, activeErr := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, activeErr)
	assert.False(t, has, "a pre-submission failure left a stranded active attempt")
	_, found := fixture.records.has(fixture.publicationID)
	assert.False(t, found, "a pre-submission failure left the retained record behind")
	assert.Equal(t, 0, fixture.transport.sendCount())
}
func TestAbandonPublicationPushWithoutAnAttemptOnlyConsumesTheRecord(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	_, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)

	attempt, err := fixture.coordinator.AbandonPublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, [16]byte{}, attempt.ID)
	_, found := fixture.records.has(fixture.publicationID)
	assert.False(t, found)
}

func TestPreparePublicationPushReportsAnUnchangedCandidateAsNoOp(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)

	setManifestReaderFromAccepted(t, fixture)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x77, 0x78}, nil))
	require.NoError(t, err)
	assert.True(t, preparation.NoOp)
	assert.False(t, preparation.Issued)
	assert.Equal(t, uint64(1), preparation.Floor.Revision)
	assert.Equal(t, 1, fixture.transport.uploadCount(), "a no-op preparation uploaded a payload")
	assert.Equal(t, 1, fixture.transport.sendCount(), "a no-op preparation dispatched writes")
}

func TestPublicationProposalRecordVerificationRefusesIncompleteRecords(t *testing.T) {
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(
		context.Background(),
		fixture.request(fixture.publicationID, nil),
	)
	require.NoError(t, err)
	record := preparation.Record
	require.NoError(t, VerifyPublicationProposalRecord(record))

	cases := map[string]func(*PublicationProposalRecord){
		"version":           func(r *PublicationProposalRecord) { r.Version = 0 },
		"publication id":    func(r *PublicationProposalRecord) { r.PublicationID = [16]byte{} },
		"confirmation":      func(r *PublicationProposalRecord) { r.Confirmation = [32]byte{} },
		"selection digest":  func(r *PublicationProposalRecord) { r.Review.SelectionDigest = [32]byte{} },
		"approval revision": func(r *PublicationProposalRecord) { r.Review.ApprovalRevision = 0 },
		"binding":           func(r *PublicationProposalRecord) { r.Binding = publicationstate.Binding{} },
		"candidate record":  func(r *PublicationProposalRecord) { r.CandidateRecordCID = nil },
		"form":              func(r *PublicationProposalRecord) { r.Form = "archive" },
		"entry count":       func(r *PublicationProposalRecord) { r.CandidateEntryCount = 0 },
		"entry digest":      func(r *PublicationProposalRecord) { r.CandidateEntryDigest = [32]byte{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := record
			mutate(&tampered)
			assert.ErrorIs(t, VerifyPublicationProposalRecord(tampered), ErrPublicationProposal)
		})
	}
}

func TestPublicationProposalRecordCarriesNoPayloadBytes(t *testing.T) {
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(
		context.Background(),
		fixture.request(fixture.publicationID, nil),
	)
	require.NoError(t, err)
	record := preparation.Record
	assert.Equal(t, fixture.binding.Vault, record.Binding.Vault)
	assert.NotEmpty(t, record.CandidateRecordCID)
	assert.Empty(t, record.CandidatePayloadCID)
	assert.Equal(t, publication.PayloadFormManifest, record.Form)
	assert.Equal(t, 1, record.CandidateEntryCount)
	assert.NotEqual(t, [32]byte{}, record.CandidateEntryDigest)
	assert.Equal(t, 1, preparation.Targets)
	assert.Equal(t, 1, preparation.Entries)
}

func TestPreparePublicationPushBindsOneConfirmationToTheReviewAndCandidate(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	first, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x79, 0x7a}, nil))
	require.NoError(t, err)
	second, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x7b, 0x7c}, nil))
	require.NoError(t, err)
	assert.NotEqual(
		t,
		first.Proposal.Confirmation,
		second.Proposal.Confirmation,
		"a different publication identity reproduced the same confirmation",
	)

	fixture.reviews.set(
		publicationstate.LocalReviewContext{
			SelectionDigest:   [32]byte{0x7d},
			SelectionRevision: 2,
			ApprovalDigest:    [32]byte{0x7e},
			ApprovalRevision:  2,
		},
		config.Token{0x7f},
	)
	third, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x7b, 0x7c}, nil))
	require.NoError(t, err)
	assert.NotEqual(
		t,
		second.Proposal.Confirmation,
		third.Proposal.Confirmation,
		"a changed review identity reproduced the same confirmation",
	)

	require.NoError(
		t,
		os.WriteFile(
			filepath.Join(fixture.paths.Home, "config", "init.lua"),
			[]byte("changed candidate payload"),
			0o600,
		),
	)
	fourth, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x7b, 0x7c}, nil))
	require.NoError(t, err)
	assert.NotEqual(
		t,
		third.Proposal.Confirmation,
		fourth.Proposal.Confirmation,
		"a changed candidate reproduced the same confirmation",
	)

	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request([16]byte{0x7b, 0x7c}, nil),
		fourth,
		third.Proposal.Confirmation,
	)
	require.ErrorIs(t, err, ErrPublicationProposalStale)
	assert.Zero(t, fixture.transport.sendCount(), "a stale confirmation dispatched writes")
}
