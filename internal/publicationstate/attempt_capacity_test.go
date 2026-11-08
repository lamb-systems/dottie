package publicationstate

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptReservesStandaloneHistoryEvidenceCapacity(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	candidate := attemptCandidate(f, 1)
	floorObservation := f.observation(1)
	view := attemptView(f, floorObservation, false)
	review := attemptReview()
	feasible := func(historyBytes uint64) bool {
		limits := DefaultLimits()
		limits.HistoryEvidenceBytes = historyBytes
		store, _ := newStore(t, f, limits)
		defer store.Close()
		first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
		if err != nil {
			return false
		}
		if _, err := store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation); err != nil {
			return false
		}
		_, err = store.PrepareAttempt(ctx, candidate, view, review)
		return err == nil
	}

	low, high := uint64(1), uint64(1<<20)
	require.True(t, feasible(high))
	for low < high {
		middle := low + (high-low)/2
		if feasible(middle) {
			high = middle
		} else {
			low = middle + 1
		}
	}
	bound := low
	require.Greater(t, bound, uint64(1))

	underLimits := DefaultLimits()
	underLimits.HistoryEvidenceBytes = bound - 1
	under, _ := newStore(t, f, underLimits)
	first, err := under.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = under.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err, "the already accepted first-use event must fit the reduced standalone history limit")
	_, err = under.PrepareAttempt(ctx, candidate, view, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	_, statErr := os.Stat(filepath.Join(under.directory, payloadDirectoryName))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	var attempts int
	require.NoError(t, under.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
	assert.Equal(t, 0, attempts)
	require.NoError(t, under.Close())

	exactLimits := DefaultLimits()
	exactLimits.HistoryEvidenceBytes = bound
	exact, exactDirectory := newStore(t, f, exactLimits)
	first, err = exact.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = exact.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	proposal, err := exact.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := exact.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	require.NoError(t, exact.Close())

	reopened, err := OpenWithLimits(exactDirectory, f.binding, exactLimits)
	require.NoError(t, err)
	defer reopened.Close()
	uploadProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	_, err = reopened.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = reopened.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	current := attemptView(f, f.observation(2), false)
	active, present, err := reopened.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)
	resolved, err := reopened.ResolveAttempt(ctx, active.ID, active.StateDigest, current)
	require.NoError(t, err)
	finalized, err := reopened.FinalizeAttempt(ctx, active.ID, resolved.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), finalized.Floor.Sequence)
}

func TestPublicationAttemptTightMetadataLimitCompletesAfterReopen(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	limits := DefaultAttemptLimits()
	expectedReservation := uint64(limits.CoreBytes) + uint64(limits.LifecycleEvents)*limits.EventBytes + 3*limits.EvidenceSlotBytes + 3*32
	limits.MetadataBytes = expectedReservation
	options := DefaultOpenOptions()
	options.AttemptLimits = limits
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, expectedReservation, store.attemptReservationSize())
	var reservation int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT metadata_bytes FROM attempt_reservations WHERE attempt_id=?", attempt.ID[:]).Scan(&reservation))
	assert.Equal(t, int64(expectedReservation), reservation)
	assertAttemptLogicalBytesExact(t, store, attempt.ID)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, empty, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, empty, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, empty, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	assertAttemptLogicalBytesExact(t, store, attempt.ID)
	require.NoError(t, store.Close())
	reopened, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	defer reopened.Close()
	loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assertAttemptLogicalBytesExact(t, reopened, attempt.ID)
	finalized, err := reopened.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	assertAttemptLogicalBytesExact(t, reopened, attempt.ID)
}

func TestPublicationAttemptRejectsTooFewLifecycleEventsBeforeCustody(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	for _, eventLimit := range []uint32{1, 3, 7} {
		t.Run(strconv.FormatUint(uint64(eventLimit), 10), func(t *testing.T) {
			limits := DefaultAttemptLimits()
			limits.LifecycleEvents = eventLimit
			options := DefaultOpenOptions()
			options.AttemptLimits = limits
			directory := t.TempDir()
			require.NoError(t, os.Chmod(directory, 0o700))
			store, err := OpenWithOptions(directory, f.binding, options)
			require.NoError(t, err)
			defer store.Close()
			_, present, err := store.Load(ctx)
			require.NoError(t, err)
			assert.False(t, present)
			proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
			requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
			assert.Equal(t, AttemptProposal{}, proposal)
			attempt, err := store.CreateAttempt(ctx, [32]byte{}, candidate, view, review, [32]byte{})
			requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
			assert.Equal(t, Attempt{}, attempt)
			assertNoAttemptCustodyMutation(t, store, directory)
		})
	}

	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	limits := DefaultAttemptLimits()
	limits.LifecycleEvents = 8
	options := DefaultOpenOptions()
	options.AttemptLimits = limits
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	defer store.Close()
	attempt, preflight, review := createSuccessorAttempt(t, store, f)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, preflight, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	repeatUpload, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, repeatUpload.StateToken, preflight, review, repeatUpload.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, preflight, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	absent, err := store.ResolveAttempt(ctx, attempt.ID, stateDigestForAttempt(t, store, attempt.ID), preflight)
	require.NoError(t, err)
	assert.Equal(t, OutcomeAbsentUnresolved, absent.Outcome)
	currentView := attemptView(f, f.observation(2), false)
	current, err := store.ResolveAttempt(ctx, attempt.ID, absent.Attempt.StateDigest, currentView)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, current.Outcome)
	supersededView := attemptView(f, f.observation(3), false)
	superseded, err := store.ResolveAttempt(ctx, attempt.ID, current.Attempt.StateDigest, supersededView)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSuperseded, superseded.Outcome)
	fork := forkGenesisObservation(t, f)
	replacement, err := store.Prepare(ctx, ModeReplaceFloor, fork, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeReplaceFloor, replacement.StateToken, fork, f.payload, replacement.Confirmation)
	require.NoError(t, err)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, &supersededView)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &supersededView, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	assert.Equal(t, OutcomeSuperseded, retired.Outcome)
	var events int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_events WHERE attempt_id=?", attempt.ID[:]).Scan(&events))
	assert.Equal(t, 8, events)
}

func TestPublicationAttemptRejectsOversizeCreatedEventBeforeCustody(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()

	options := DefaultOpenOptions()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	probe, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	proposal, err := probe.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := probe.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	var bodyLength, digestLength int64
	require.NoError(t, probe.conn.QueryRowContext(ctx, "SELECT length(body),length(digest) FROM attempt_events WHERE attempt_id=? AND ordinal=1", attempt.ID[:]).Scan(&bodyLength, &digestLength))
	createdEventBytes := uint64(bodyLength + digestLength)
	var coreBytes []byte
	require.NoError(t, probe.conn.QueryRowContext(ctx, "SELECT core FROM publication_attempts WHERE attempt_id=?", attempt.ID[:]).Scan(&coreBytes))
	require.NoError(t, probe.Close())

	for _, eventLimit := range []uint64{1, createdEventBytes - 1} {
		t.Run(strconv.FormatUint(eventLimit, 10), func(t *testing.T) {
			attemptLimits := DefaultAttemptLimits()
			attemptLimits.EventBytes = eventLimit
			options := DefaultOpenOptions()
			options.AttemptLimits = attemptLimits
			stateDirectory := t.TempDir()
			require.NoError(t, os.Chmod(stateDirectory, 0o700))
			store, err := OpenWithOptions(stateDirectory, f.binding, options)
			require.NoError(t, err)
			defer store.Close()
			err = store.checkAttemptCreatedEvent(coreBytes, attempt.ID, attempt.MutationRevision, StageAttempt)
			requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
			_, err = store.PrepareAttempt(ctx, candidate, view, review)
			requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
			attempt, err := store.CreateAttempt(ctx, [32]byte{}, candidate, view, review, [32]byte{})
			requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
			assert.Equal(t, Attempt{}, attempt)
			assertNoAttemptCustodyMutation(t, store, stateDirectory)
		})
	}

	exactLimits := DefaultAttemptLimits()
	exactLimits.EventBytes = createdEventBytes
	exactOptions := DefaultOpenOptions()
	exactOptions.AttemptLimits = exactLimits
	exactDirectory := t.TempDir()
	require.NoError(t, os.Chmod(exactDirectory, 0o700))
	exact, err := OpenWithOptions(exactDirectory, f.binding, exactOptions)
	require.NoError(t, err)
	defer exact.Close()
	require.NoError(t, exact.checkAttemptCreatedEvent(coreBytes, attempt.ID, attempt.MutationRevision, StageAttempt))
	_, err = exact.PrepareAttempt(ctx, candidate, view, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assertNoAttemptCustodyMutation(t, exact, exactDirectory)
}

func TestPublicationAttemptSubmissionEventAdmissionCoversEscapedContext(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	limits := DefaultLimits()
	limits.SuppliedContextBytes = 4096
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	probe, _ := openAttemptStoreWithLimits(t, f, limits)
	bound := independentSubmissionEventAdmissionBound(t, probe, candidate, view, review)
	require.Greater(t, bound, uint64(1))
	require.LessOrEqual(t, bound, DefaultAttemptLimits().EventBytes)
	require.NoError(t, probe.Close())

	underLimits := DefaultAttemptLimits()
	underLimits.EventBytes = bound - 1
	under, underDirectory := openAttemptStoreWithAttemptLimits(t, f, limits, underLimits)
	_, err := under.PrepareAttempt(ctx, candidate, view, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	result, err := under.CreateAttempt(ctx, [32]byte{}, candidate, view, review, [32]byte{})
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, Attempt{}, result)
	assertNoAttemptCustodyMutation(t, under, underDirectory)
	require.NoError(t, under.Close())

	exactLimits := DefaultAttemptLimits()
	exactLimits.EventBytes = bound
	exact, _ := openAttemptStoreWithAttemptLimits(t, f, limits, exactLimits)
	defer exact.Close()
	proposal, err := exact.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := exact.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	_, err = exact.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	escapedView := cloneSuppliedView(view)
	escapedView.SuppliedContext.RepositoryRevision = strings.Repeat("\x01", 128)
	submissionProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, escapedView, review)
	require.NoError(t, err)
	_, err = exact.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, escapedView, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	loaded, err := exact.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
	var eventBody, eventDigest []byte
	require.NoError(t, exact.conn.QueryRowContext(ctx, "SELECT body,digest FROM attempt_events WHERE attempt_id=? AND kind='may-have-submitted'", attempt.ID[:]).Scan(&eventBody, &eventDigest))
	assert.LessOrEqual(t, uint64(len(eventBody)+len(eventDigest)), bound)
	var event attemptEventWire
	require.NoError(t, strictJSON(eventBody, &event))
	var evidence attemptEvidenceWire
	require.NoError(t, strictJSON(event.Evidence, &evidence))
	assert.Equal(t, escapedView.SuppliedContext.RepositoryRevision, evidence.Context.RepositoryRevision)
}

func TestPublicationAttemptCurrentRetirementEvidenceSlotAdmissionBoundary(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	limits := DefaultLimits()
	limits.SuppliedContextBytes = 512
	candidate := attemptCandidate(f, 0)
	preflight := attemptView(f, f.observation(1), true)
	review := attemptReview()
	probe, _ := openAttemptStoreWithLimits(t, f, limits)
	bound := independentCurrentRetirementEvidenceSlotBound(t, probe, candidate, preflight, review)
	firstConflictBound := independentFirstConflictEvidenceSlotBound(t, probe, candidate, preflight, review)
	if firstConflictBound > bound {
		bound = firstConflictBound
	}
	require.Greater(t, bound, uint64(1))
	require.LessOrEqual(t, bound, DefaultAttemptLimits().EvidenceSlotBytes)
	require.NoError(t, probe.Close())

	underLimits := DefaultAttemptLimits()
	underLimits.EvidenceSlotBytes = bound - 1
	under, underDirectory := openAttemptStoreWithAttemptLimits(t, f, limits, underLimits)
	_, err := under.PrepareAttempt(ctx, candidate, preflight, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	result, err := under.CreateAttempt(ctx, [32]byte{}, candidate, preflight, review, [32]byte{})
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, Attempt{}, result)
	assertNoAttemptCustodyMutation(t, under, underDirectory)
	require.NoError(t, under.Close())

	exactLimits := DefaultAttemptLimits()
	exactLimits.EvidenceSlotBytes = bound
	exact, exactDirectory := openAttemptStoreWithAttemptLimits(t, f, limits, exactLimits)
	proposal, err := exact.PrepareAttempt(ctx, candidate, preflight, review)
	require.NoError(t, err)
	attempt, err := exact.CreateAttempt(ctx, proposal.StateToken, candidate, preflight, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	_, err = exact.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, preflight, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
	require.NoError(t, err)
	_, err = exact.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, preflight, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	current := attemptView(f, f.observation(1), false)
	loaded, err := exact.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := exact.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, resolution.Outcome)
	abandon, err := exact.PrepareAbandon(ctx, attempt.ID, &current)
	require.NoError(t, err)
	retired, err := exact.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &current, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	require.NoError(t, exact.Close())
	reopened, err := OpenWithOptions(exactDirectory, f.binding, attemptOpenOptions(limits, exactLimits))
	require.NoError(t, err)
	defer reopened.Close()
	stored, err := reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, stored.Lifecycle)
	page, err := reopened.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	var outcome, retirement bool
	for _, evidence := range page.Evidence {
		outcome = outcome || evidence.Role == "outcome"
		retirement = retirement || evidence.Role == "retirement"
	}
	assert.True(t, outcome)
	assert.True(t, retirement)
}

func TestPublicationAttemptAdmissionRejectsProspectiveLineageLimitBeforeCustody(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	limits := DefaultLimits()
	limits.MaxLineageLinks = 1
	store, directory := openAttemptStoreWithLimits(t, f, limits)
	defer store.Close()
	floorObservation := f.observation(2)
	first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	preflight := attemptView(f, floorObservation, false)
	_, err = validateSuppliedRepositoryView(preflight, f.binding, limits, false)
	require.NoError(t, err, "the two-record preflight view uses one permitted link")
	candidate := attemptCandidate(f, 2)
	review := attemptReview()
	before := readAttemptLogicalRows(t, store)
	proposal, err := store.PrepareAttempt(ctx, candidate, preflight, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, AttemptProposal{}, proposal)
	result, err := store.CreateAttempt(ctx, [32]byte{}, candidate, preflight, review, [32]byte{})
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, Attempt{}, result)
	assert.Equal(t, before, readAttemptLogicalRows(t, store))
	assertNoAttemptCustodyMutation(t, store, directory)
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, uint64(1), floor.Sequence)
}

func TestPublicationAttemptMaxBlobConflictFitsGuaranteedEvidenceSlot(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	positionLimits := DefaultLimits()
	positionLimits.MaxLineageLinks = 1
	candidate := attemptCandidate(f, 1)
	floorObservation := f.observation(1)
	preflight := attemptView(f, floorObservation, false)
	preflight.SuppliedContext.RepositoryRevision = strings.Repeat("\x01", 1024)
	preflight.SuppliedContext.RepositoryDigest = bytes.Repeat([]byte{0xa5}, 128)
	review := attemptReview()

	probe, _ := openAttemptStoreWithLimits(t, f, positionLimits)
	first, err := probe.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = probe.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	slot := independentFirstConflictEvidenceSlotBound(t, probe, candidate, preflight, review)
	require.Greater(t, slot, uint64(1))
	require.LessOrEqual(t, slot, DefaultAttemptLimits().EvidenceSlotBytes)
	require.NoError(t, probe.Close())

	attemptLimits := DefaultAttemptLimits()
	attemptLimits.EvidenceSlotBytes = slot
	attemptLimits.EvidenceBytes = 3 * (slot + 32)
	store, directory := openAttemptStoreWithAttemptLimits(t, f, positionLimits, attemptLimits)
	t.Cleanup(func() { _ = store.Close() })
	first, err = store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	proposal, err := store.PrepareAttempt(ctx, candidate, preflight, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, preflight, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, preflight, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, preflight, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	conflict := maxBlobCompetingSuccessorView(t, f, preflight, candidate)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, &conflict)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &conflict, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	assert.Equal(t, OutcomeLostFence, retired.Outcome)
	firstConflict, present, err := store.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, conflict.Head, firstConflict.Head)
	assert.Equal(t, conflict.Snapshots[1].Raw, firstConflict.HeadRecord)
	assert.Equal(t, uint64(1), firstConflict.HeadSequence)
	assert.LessOrEqual(t, uint64(len(firstConflict.Evidence)), slot)
	require.NoError(t, store.Close())

	reopened, err := OpenWithOptions(directory, f.binding, attemptOpenOptions(positionLimits, attemptLimits))
	require.NoError(t, err)
	defer reopened.Close()
	stored, present, err := reopened.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, firstConflict.ID, stored.ID)
	assert.Equal(t, firstConflict.Evidence, stored.Evidence)
}

func maxBlobCompetingSuccessorView(t *testing.T, f fixture, preflight SuppliedRepositoryView, candidate CandidateInput) SuppliedRepositoryView {
	t.Helper()
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	record.PublicationID[15] ^= 0x40
	if allZero(record.PublicationID[:]) {
		record.PublicationID[0] = 1
	}
	record.Blob.Size = publication.MaxBlobBytes
	occupant, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	occupantCID, err := publication.RecordCID(occupant)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: record.Vault, PublicationSeq: record.PublicationSeq, SnapshotCID: occupantCID, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	return SuppliedRepositoryView{Origin: f.binding, Scope: preflight.Scope, SuppliedContext: cloneContext(preflight.SuppliedContext), Head: head, Snapshots: []SnapshotBlock{cloneSnapshotBlocks(f.blocks[:1])[0], {Key: candidate.SnapshotKey, Raw: occupant}}}
}

func TestPublicationAttemptEvidenceAdmissionAggregateBoundary(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	positionLimits := DefaultLimits()
	positionLimits.SuppliedContextBytes = 512
	candidate := attemptCandidate(f, 0)
	preflight := attemptView(f, f.observation(1), true)
	review := attemptReview()
	slot := uint64(4096)
	reservation := 3*slot + 3*32

	underLimits := DefaultAttemptLimits()
	underLimits.EvidenceSlotBytes = slot
	underLimits.EvidenceBytes = reservation - 1
	under, underDirectory := openAttemptStoreWithAttemptLimits(t, f, positionLimits, underLimits)
	_, present, err := under.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	_, err = under.PrepareAttempt(ctx, candidate, preflight, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	result, err := under.CreateAttempt(ctx, [32]byte{}, candidate, preflight, review, [32]byte{})
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, Attempt{}, result)
	assertNoAttemptCustodyMutation(t, under, underDirectory)
	require.NoError(t, under.Close())

	exactLimits := DefaultAttemptLimits()
	exactLimits.EvidenceSlotBytes = slot
	exactLimits.EvidenceBytes = reservation
	exact, exactDirectory := openAttemptStoreWithAttemptLimits(t, f, positionLimits, exactLimits)
	proposal, err := exact.PrepareAttempt(ctx, candidate, preflight, review)
	require.NoError(t, err)
	attempt, err := exact.CreateAttempt(ctx, proposal.StateToken, candidate, preflight, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	_, err = exact.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, preflight, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
	require.NoError(t, err)
	_, err = exact.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, preflight, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	current := attemptView(f, f.observation(1), false)
	loaded, err := exact.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := exact.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, resolution.Outcome)
	abandon, err := exact.PrepareAbandon(ctx, attempt.ID, &current)
	require.NoError(t, err)
	retired, err := exact.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &current, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	require.NoError(t, exact.Close())
	reopened, err := OpenWithOptions(exactDirectory, f.binding, attemptOpenOptions(positionLimits, exactLimits))
	require.NoError(t, err)
	defer reopened.Close()
	stored, err := reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, stored.Lifecycle)
	page, err := reopened.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	var outcome, retirement bool
	for _, evidence := range page.Evidence {
		outcome = outcome || evidence.Role == "outcome"
		retirement = retirement || evidence.Role == "retirement"
	}
	assert.True(t, outcome)
	assert.True(t, retirement)
	var evidenceBytes int64
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence").Scan(&evidenceBytes))
	assert.LessOrEqual(t, evidenceBytes, int64(exactLimits.EvidenceBytes))
}

func TestPublicationAttemptEvidenceAdmissionIncludesRetiredEvidence(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	positionLimits := DefaultLimits()
	positionLimits.SuppliedContextBytes = 512
	firstCandidate := attemptCandidate(f, 0)
	secondCandidate := candidateWithPublicationID(t, firstCandidate, [16]byte{0x77})
	preflight := attemptView(f, f.observation(1), true)
	review := attemptReview()
	retirementBody, err := encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "retirement", AttemptedKey: firstCandidate.SnapshotKey, AttemptedRecord: bytes.Clone(firstCandidate.SnapshotRecord), Outcome: string(OutcomeNotSubmitted)})
	require.NoError(t, err)
	priorEvidenceBytes := uint64(len(retirementBody) + 32)
	slot := uint64(4096)
	reservation := 3 * (slot + 32)

	for _, testCase := range []struct {
		name   string
		margin uint64
	}{
		{name: "one-byte-short", margin: 1},
		{name: "exact", margin: 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			attemptLimits := DefaultAttemptLimits()
			attemptLimits.EvidenceSlotBytes = slot
			attemptLimits.EvidenceBytes = priorEvidenceBytes + reservation - testCase.margin
			store, directory := openAttemptStoreWithAttemptLimits(t, f, positionLimits, attemptLimits)
			t.Cleanup(func() { _ = store.Close() })
			firstProposal, err := store.PrepareAttempt(ctx, firstCandidate, preflight, review)
			require.NoError(t, err)
			first, err := store.CreateAttempt(ctx, firstProposal.StateToken, firstCandidate, preflight, review, firstProposal.Confirmation)
			require.NoError(t, err)
			abandon, err := store.PrepareAbandon(ctx, first.ID, nil)
			require.NoError(t, err)
			_, err = store.AbandonAttempt(ctx, first.ID, abandon.StateToken, nil, abandon.Confirmation)
			require.NoError(t, err)
			var existingBytes int64
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence").Scan(&existingBytes))
			assert.Equal(t, int64(priorEvidenceBytes), existingBytes)

			proposal, err := store.PrepareAttempt(ctx, secondCandidate, preflight, review)
			if testCase.margin != 0 {
				requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
				result, err := store.CreateAttempt(ctx, [32]byte{}, secondCandidate, preflight, review, [32]byte{})
				requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
				assert.Equal(t, Attempt{}, result)
				var attempts int
				require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
				assert.Equal(t, 1, attempts)
				var active int
				require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM active_publication_attempt").Scan(&active))
				assert.Zero(t, active)
			} else {
				require.NoError(t, err)
				second, err := store.CreateAttempt(ctx, proposal.StateToken, secondCandidate, preflight, review, proposal.Confirmation)
				require.NoError(t, err)
				require.NoError(t, store.Close())
				reopened, err := OpenWithOptions(directory, f.binding, attemptOpenOptions(positionLimits, attemptLimits))
				require.NoError(t, err)
				defer reopened.Close()
				loaded, err := reopened.LoadAttempt(ctx, second.ID)
				require.NoError(t, err)
				assert.Equal(t, AttemptPrepared, loaded.Lifecycle)
			}
			if testCase.margin != 0 {
				assertNoAdditionalAttemptRows(t, store, directory, 1)
				require.NoError(t, store.Close())
			}
		})
	}
}

func independentSubmissionEventAdmissionBound(t *testing.T, store *Store, candidate CandidateInput, view SuppliedRepositoryView, review LocalReviewContext) uint64 {
	t.Helper()
	state, err := store.readState(context.Background(), store.conn, StageAttempt)
	require.NoError(t, err)
	validated, err := store.validateAttemptInput(context.Background(), candidate, view, review, state, StageAttempt)
	require.NoError(t, err)
	contextBytes, err := canonicalJSON(contextToWire(validated.view.input.SuppliedContext))
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(contextBytes)), uint64(store.limits.SuppliedContextBytes))
	submission, err := encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "submission", Scope: string(validated.view.input.Scope), ViewDigest: bytes.Clone(validated.view.digest[:]), Origin: bindingToWire(validated.view.input.Origin), Context: contextToWire(validated.view.input.SuppliedContext), Head: bytes.Clone(validated.view.input.Head), AttemptedKey: validated.key, AttemptedRecord: bytes.Clone(validated.snapshotRaw), PredecessorRecord: candidatePredecessorRaw(validated), Outcome: string(OutcomeUnresolved)})
	require.NoError(t, err)
	maxEvidence := uint64(len(submission)) + uint64(store.limits.SuppliedContextBytes) - uint64(len(contextBytes))
	kind := "outcome-observed-absent-unresolved"
	for _, candidateKind := range []string{"created", "upload-started", "may-have-submitted", "blocked-floor-replaced", "retired-success", "retired-abandoned", "outcome-observed-absent-unresolved", "outcome-observed-current", "outcome-committed-superseded", "outcome-lost-fence", "outcome-unresolved", "outcome-not-submitted"} {
		if len(candidateKind) > len(kind) {
			kind = candidateKind
		}
	}
	body, digest, err := makeAttemptEvent(validated.id, store.attemptLimits.LifecycleEvents, kind, make([]byte, 32), make([]byte, int(maxEvidence)), [32]byte{})
	require.NoError(t, err)
	return uint64(len(body) + len(digest))
}

func independentCurrentRetirementEvidenceSlotBound(t *testing.T, store *Store, candidate CandidateInput, view SuppliedRepositoryView, review LocalReviewContext) uint64 {
	t.Helper()
	state, err := store.readState(context.Background(), store.conn, StageAttempt)
	require.NoError(t, err)
	validated, err := store.validateAttemptInput(context.Background(), candidate, view, review, state, StageAttempt)
	require.NoError(t, err)
	contextBytes, err := canonicalJSON(contextToWire(validated.view.input.SuppliedContext))
	require.NoError(t, err)
	currentViewInput := cloneSuppliedView(validated.view.input)
	currentViewInput.Snapshots = append(currentViewInput.Snapshots, SnapshotBlock{Key: validated.key, Raw: bytes.Clone(validated.snapshotRaw)})
	currentViewInput.Head = bytes.Clone(validated.headRaw)
	currentView, err := validateSuppliedRepositoryView(currentViewInput, store.binding, store.limits, false)
	require.NoError(t, err)
	proof, err := encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "retirement", Scope: string(currentView.input.Scope), ViewDigest: bytes.Clone(currentView.digest[:]), Origin: bindingToWire(currentView.input.Origin), Context: contextToWire(currentView.input.SuppliedContext), Head: bytes.Clone(currentView.input.Head), AttemptedKey: validated.key, AttemptedRecord: bytes.Clone(validated.snapshotRaw), PredecessorRecord: candidatePredecessorRaw(validated), Suffix: []SnapshotBlock{{Key: validated.key, Raw: bytes.Clone(validated.snapshotRaw)}}, Outcome: string(OutcomeCurrent)})
	require.NoError(t, err)
	return uint64(len(proof)) + uint64(store.limits.SuppliedContextBytes) - uint64(len(contextBytes))
}

func independentFirstConflictEvidenceSlotBound(t *testing.T, store *Store, candidate CandidateInput, view SuppliedRepositoryView, review LocalReviewContext) uint64 {
	t.Helper()
	state, err := store.readState(context.Background(), store.conn, StageAttempt)
	require.NoError(t, err)
	validated, err := store.validateAttemptInput(context.Background(), candidate, view, review, state, StageAttempt)
	require.NoError(t, err)
	contextBytes, err := canonicalJSON(contextToWire(validated.view.input.SuppliedContext))
	require.NoError(t, err)
	occupant := validated.snapshot
	occupant.Blob.Size = publication.MaxBlobBytes
	occupant.PublicationID[15] ^= 1
	if allZero(occupant.PublicationID[:]) {
		occupant.PublicationID[0] = 1
	}
	occupantRaw, err := publication.EncodeSnapshot(occupant)
	require.NoError(t, err)
	occupantCID, err := publication.RecordCID(occupantRaw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: occupant.Vault, PublicationSeq: occupant.PublicationSeq, SnapshotCID: occupantCID, BlobCID: bytes.Clone(occupant.Blob.CID)})
	require.NoError(t, err)
	proof := attemptEvidenceWire{Version: 1, Role: "outcome", Scope: string(validated.view.input.Scope), ViewDigest: make([]byte, 32), Origin: bindingToWire(validated.view.input.Origin), Context: contextToWire(validated.view.input.SuppliedContext), Head: head, AttemptedKey: validated.key, AttemptedRecord: occupantRaw, PredecessorRecord: candidatePredecessorRaw(validated), Suffix: []SnapshotBlock{{Key: validated.key, Raw: occupantRaw}}, Outcome: string(OutcomeLostFence)}
	wire := firstConflictWire{Version: 1, AttemptID: bytes.Clone(validated.id[:]), CoreDigest: make([]byte, 32), EventOrdinal: store.attemptLimits.LifecycleEvents, MutationRevision: ^uint64(0) >> 1, EventStateDigest: make([]byte, 32), Blocked: "blocked-floor-replaced", Proof: proof}
	encoded, err := canonicalJSON(wire)
	require.NoError(t, err)
	return uint64(len(encoded)) + uint64(store.limits.SuppliedContextBytes) - uint64(len(contextBytes))
}

func openAttemptStoreWithAttemptLimits(t *testing.T, f fixture, limits Limits, attemptLimits AttemptLimits) (*Store, string) {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	options := attemptOpenOptions(limits, attemptLimits)
	store, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	return store, directory
}

func attemptOpenOptions(limits Limits, attemptLimits AttemptLimits) OpenOptions {
	options := DefaultOpenOptions()
	options.PositionLimits = limits
	options.AttemptLimits = attemptLimits
	return options
}

func assertNoAdditionalAttemptRows(t *testing.T, store *Store, directory string, count int) {
	t.Helper()
	var attempts, active, objects int
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM active_publication_attempt").Scan(&active))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	assert.Equal(t, count, attempts)
	assert.Zero(t, active)
	assert.Equal(t, 1, objects)
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func assertNoAttemptCustodyMutation(t *testing.T, store *Store, directory string) {
	t.Helper()
	var attempts, objects, active int
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM active_publication_attempt").Scan(&active))
	assert.Equal(t, 0, attempts)
	assert.Equal(t, 0, objects)
	assert.Equal(t, 0, active)
	_, err := os.Stat(filepath.Join(directory, payloadDirectoryName))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func stateDigestForAttempt(t *testing.T, store *Store, id [16]byte) [32]byte {
	t.Helper()
	attempt, err := store.LoadAttempt(context.Background(), id)
	require.NoError(t, err)
	return attempt.StateDigest
}

func TestPublicationAttemptHistoryReserveCoversEscapedFinalContext(t *testing.T) {
	for _, kind := range []string{"genesis", "successor"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			if kind == "successor" {
				f.appendRecord(t, 1)
			}
			baseStore, _ := newStore(t, f)
			var preflight SuppliedRepositoryView
			var floorObservation Observation
			candidateSequence := uint64(0)
			if kind == "successor" {
				floorObservation = f.observation(1)
				first, err := baseStore.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
				require.NoError(t, err)
				_, err = baseStore.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
				require.NoError(t, err)
				preflight = attemptView(f, floorObservation, false)
				candidateSequence = 1
			} else {
				floorObservation = f.observation(1)
				preflight = attemptView(f, floorObservation, true)
			}
			candidate := attemptCandidate(f, candidateSequence)
			review := attemptReview()
			bound := independentFinalizationHistoryBound(t, baseStore, candidate, preflight, review)
			assert.Greater(t, bound, uint64(1))
			require.NoError(t, baseStore.Close())

			underLimits := DefaultLimits()
			underLimits.HistoryEvidenceBytes = bound - 1
			under, underDirectory := openAttemptStoreWithLimits(t, f, underLimits)
			if kind == "successor" {
				first, err := under.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
				require.NoError(t, err)
				_, err = under.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
				require.NoError(t, err)
			}
			_, err := under.PrepareAttempt(ctx, candidate, preflight, review)
			requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
			assertNoAttemptCustodyMutation(t, under, underDirectory)
			require.NoError(t, under.Close())

			exactLimits := DefaultLimits()
			exactLimits.HistoryEvidenceBytes = bound
			exact, exactDirectory := openAttemptStoreWithLimits(t, f, exactLimits)
			if kind == "successor" {
				first, err := exact.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
				require.NoError(t, err)
				_, err = exact.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
				require.NoError(t, err)
			}
			proposal, err := exact.PrepareAttempt(ctx, candidate, preflight, review)
			require.NoError(t, err)
			attempt, err := exact.CreateAttempt(ctx, proposal.StateToken, candidate, preflight, review, proposal.Confirmation)
			require.NoError(t, err)
			uploadProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
			require.NoError(t, err)
			_, err = exact.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, preflight, review, uploadProposal.Confirmation)
			require.NoError(t, err)
			submissionProposal, err := exact.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
			require.NoError(t, err)
			_, err = exact.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, preflight, review, submissionProposal.Confirmation)
			require.NoError(t, err)
			require.NoError(t, exact.Close())

			reopened, err := OpenWithLimits(exactDirectory, f.binding, exactLimits)
			require.NoError(t, err)
			defer reopened.Close()
			escapedContext := preflight.SuppliedContext
			escapedContext.RepositoryRevision = strings.Repeat("\x01", 1024)
			finalView := attemptView(f, f.observation(int(candidateSequence+1)), false)
			finalView.SuppliedContext = escapedContext
			loaded, err := reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			resolution, err := reopened.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, finalView)
			require.NoError(t, err)
			finalized, err := reopened.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, finalView)
			require.NoError(t, err)
			assert.Equal(t, candidateSequence, finalized.Floor.Sequence)
		})
	}
}

func TestLoweredContextLimitAdmitsFeasibleAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	limits := DefaultLimits()
	limits.SuppliedContextBytes = 256
	store, _ := openAttemptStoreWithLimits(t, f, limits)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
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
	finalView := attemptView(f, f.observation(1), false)
	finalView.SuppliedContext.RepositoryRevision = "short-final"
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, finalView)
	require.NoError(t, err)
	finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, finalView)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), finalized.Floor.Sequence)

	invalidDirectory := t.TempDir()
	require.NoError(t, os.Chmod(invalidDirectory, 0o700))
	invalid, err := OpenWithLimits(invalidDirectory, f.binding, limits)
	require.NoError(t, err)
	defer invalid.Close()
	tooLong := attemptView(f, f.observation(1), true)
	tooLong.SuppliedContext.RepositoryRevision = strings.Repeat("x", 256)
	_, err = invalid.PrepareAttempt(ctx, candidate, tooLong, review)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonContext)
	_, statErr := os.Stat(filepath.Join(invalidDirectory, payloadDirectoryName))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func openAttemptStoreWithLimits(t *testing.T, f fixture, limits Limits) (*Store, string) {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	return store, directory
}

func independentFinalizationHistoryBound(t *testing.T, store *Store, candidate CandidateInput, view SuppliedRepositoryView, review LocalReviewContext) uint64 {
	t.Helper()
	ctx := context.Background()
	state, err := store.readState(ctx, store.conn, StageAttempt)
	require.NoError(t, err)
	validatedCandidate, err := store.validateAttemptInput(ctx, candidate, view, review, state, StageAttempt)
	require.NoError(t, err)
	finalViewInput := cloneSuppliedView(view)
	finalViewInput.Snapshots = append(finalViewInput.Snapshots, SnapshotBlock{Key: validatedCandidate.key, Raw: bytes.Clone(validatedCandidate.snapshotRaw)})
	finalViewInput.Head = bytes.Clone(validatedCandidate.headRaw)
	finalView, err := validateSuppliedRepositoryView(finalViewInput, store.binding, store.limits, false)
	require.NoError(t, err)
	observation := repositoryViewToObservation(finalView)
	validatedObservation, err := validateObservation(observation, store.binding, store.limits)
	require.NoError(t, err)
	mode := ModeAdvance
	trace := resolvedTrace{refs: []RecordReference{cloneReference(validatedObservation.candidate.ref)}, records: []validatedRecord{cloneValidatedRecord(validatedObservation.candidate)}, stop: "joined"}
	if state.floor == nil {
		mode = ModeFirstUse
		trace.stop = "first_use"
	} else {
		trace.refs = append(trace.refs, RecordReference{Key: state.floor.SnapshotKey, CID: bytes.Clone(state.floor.RecordCID), Sequence: state.floor.Sequence})
		require.NotNil(t, validatedCandidate.predecessor)
		trace.records = append(trace.records, cloneValidatedRecord(*validatedCandidate.predecessor))
	}
	floor := buildFloor(store.databaseID, store.binding, validatedObservation, state, trace, mode)
	body := oracleJSON(t, oracleEvent{Version: 1, Mode: string(mode), Reason: string(trace.reason), OldFloor: oracleFloorFrom(state.floor), NewFloor: oracleCoreFrom(floor), Trace: oracleRefs(trace.refs), Stop: trace.stop, ObservationDigest: bytes.Clone(validatedObservation.observationDigest[:]), SuppliedSetDigest: bytes.Clone(validatedObservation.setDigest[:])})
	contextWire := oracleJSON(t, oracleCtx(validatedObservation.context))
	require.LessOrEqual(t, len(contextWire), int(store.limits.SuppliedContextBytes))
	bound := uint64(len(body) + 32 + 8)
	seen := make(map[string]bool)
	for _, record := range trace.records {
		if seen[string(record.ref.CID)] {
			continue
		}
		seen[string(record.ref.CID)] = true
		bound += uint64(len(record.raw) + len(record.ref.CID) + len(record.ref.Key) + 8)
	}
	if state.floor != nil && !seen[string(state.floor.RecordCID)] {
		anchor, err := store.loadRecordByCID(ctx, store.conn, state.floor.RecordCID, state.floor.SnapshotKey, state.floor.Sequence, StageAttempt)
		require.NoError(t, err)
		bound += uint64(len(anchor.raw) + len(anchor.ref.CID) + len(anchor.ref.Key) + 8)
	}
	return bound + uint64(store.limits.SuppliedContextBytes) - uint64(len(contextWire))
}

func TestPublicationAttemptValidOrphanReuseAtExactCustodyLimit(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	candidate := attemptCandidate(f, 0)
	attemptLimits := DefaultAttemptLimits()
	attemptLimits.CustodyBytes = uint64(len(candidate.Payload))
	attemptLimits.ManagedObjects = 1
	options := DefaultOpenOptions()
	options.AttemptLimits = attemptLimits
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	payloadDirectory := filepath.Join(directory, payloadDirectoryName)
	require.NoError(t, os.Mkdir(payloadDirectory, 0o700))
	payloadPath := filepath.Join(payloadDirectory, payloadBasename(candidate.Payload))
	require.NoError(t, os.WriteFile(payloadPath, candidate.Payload, 0o600))
	store, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	defer store.Close()
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, proposal.AttemptID, attempt.ID)
	stored, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, stored)
	var objects int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	assert.Equal(t, 1, objects)
}

func TestPublicationAttemptOrphanReuseEnforcesCompletedUnionBytes(t *testing.T) {
	ctx := context.Background()
	for _, caseValue := range []struct {
		name   string
		refuse bool
	}{
		{"exact", false},
		{"one-byte-over", true},
	} {
		t.Run(caseValue.name, func(t *testing.T) {
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			candidate := attemptCandidate(f, 0)
			other := packFixtureContent(t, candidate.Payload, []byte("second orphan bytes"))
			otherCID, err := publication.RawPayloadCID(other)
			require.NoError(t, err)
			otherName := payloadBasename(other)
			otherSize := uint64(len(other))
			custodyLimit := uint64(len(candidate.Payload))
			if caseValue.refuse {
				custodyLimit += otherSize - 1
			} else {
				custodyLimit += otherSize
			}
			attemptLimits := DefaultAttemptLimits()
			attemptLimits.CustodyBytes = custodyLimit
			attemptLimits.ManagedObjects = 2
			options := DefaultOpenOptions()
			options.AttemptLimits = attemptLimits
			directory := t.TempDir()
			require.NoError(t, os.Chmod(directory, 0o700))
			store, err := OpenWithOptions(directory, f.binding, options)
			require.NoError(t, err)
			defer store.Close()
			view := attemptView(f, f.observation(1), true)
			review := attemptReview()
			proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
			require.NoError(t, err)
			payloadDirectory := filepath.Join(directory, payloadDirectoryName)
			require.NoError(t, os.Mkdir(payloadDirectory, 0o700))
			candidateName := payloadBasename(candidate.Payload)
			candidatePath := filepath.Join(payloadDirectory, candidateName)
			require.NoError(t, os.WriteFile(candidatePath, candidate.Payload, 0o600))
			otherPath := filepath.Join(payloadDirectory, otherName)
			require.NoError(t, os.WriteFile(otherPath, other, 0o600))
			_, err = store.conn.ExecContext(ctx, "INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?)", otherCID, int64(otherSize), otherName, int64(otherSize))
			require.NoError(t, err)
			beforeCandidate, err := os.ReadFile(candidatePath)
			require.NoError(t, err)
			beforeRows := readAttemptLogicalRows(t, store)
			beforeEntries, err := os.ReadDir(payloadDirectory)
			require.NoError(t, err)
			beforeNames := directoryEntryNames(beforeEntries)
			_, err = store.PrepareAttempt(ctx, candidate, view, review)
			if caseValue.refuse {
				requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
				_, err = store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
				requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
				assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
				afterEntries, err := os.ReadDir(payloadDirectory)
				require.NoError(t, err)
				assert.Equal(t, beforeNames, directoryEntryNames(afterEntries))
			} else {
				require.NoError(t, err)
				attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
				require.NoError(t, err)
				assert.Equal(t, proposal.AttemptID, attempt.ID)
			}
			afterCandidate, err := os.ReadFile(candidatePath)
			require.NoError(t, err)
			assert.Equal(t, beforeCandidate, afterCandidate)
			otherAfter, err := os.ReadFile(otherPath)
			require.NoError(t, err)
			assert.Equal(t, other, otherAfter)
		})
	}
}

func TestPublicationAttemptCataloguedMissingObjectCountsTowardUnionLimit(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	candidate := attemptCandidate(f, 0)
	other := packFixtureContent(t, candidate.Payload, []byte("catalogued missing bytes"))
	otherCID, err := publication.RawPayloadCID(other)
	require.NoError(t, err)
	otherName := payloadBasename(other)
	otherSize := int64(len(other))
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	for _, objectLimit := range []uint32{1, 2} {
		t.Run(strconv.FormatUint(uint64(objectLimit), 10), func(t *testing.T) {
			attemptLimits := DefaultAttemptLimits()
			attemptLimits.ManagedObjects = objectLimit
			attemptLimits.CustodyBytes = uint64(len(candidate.Payload) + len(other) + 1)
			options := DefaultOpenOptions()
			options.AttemptLimits = attemptLimits
			directory := t.TempDir()
			require.NoError(t, os.Chmod(directory, 0o700))
			store, err := OpenWithOptions(directory, f.binding, options)
			require.NoError(t, err)
			defer store.Close()
			proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
			require.NoError(t, err)
			payloadDirectory := filepath.Join(directory, payloadDirectoryName)
			require.NoError(t, os.Mkdir(payloadDirectory, 0o700))
			candidatePath := filepath.Join(payloadDirectory, payloadBasename(candidate.Payload))
			otherPath := filepath.Join(payloadDirectory, otherName)
			require.NoError(t, os.WriteFile(candidatePath, candidate.Payload, 0o600))
			_, err = store.conn.ExecContext(ctx, "INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?)", otherCID, otherSize, otherName, otherSize)
			require.NoError(t, err)
			beforeRows := readAttemptLogicalRows(t, store)
			beforeFile, err := os.ReadFile(candidatePath)
			require.NoError(t, err)
			beforeNames := directoryEntryNames(mustReadDir(t, payloadDirectory))
			_, err = store.PrepareAttempt(ctx, candidate, view, review)
			if objectLimit == 1 {
				requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
				result, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
				requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
				assert.Equal(t, Attempt{}, result)
				assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
				assert.Equal(t, beforeNames, directoryEntryNames(mustReadDir(t, payloadDirectory)))
			} else {
				require.NoError(t, err)
				result, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
				require.NoError(t, err)
				assert.Equal(t, proposal.AttemptID, result.ID)
			}
			afterFile, err := os.ReadFile(candidatePath)
			require.NoError(t, err)
			assert.Equal(t, beforeFile, afterFile)
			_, missingErr := os.Stat(otherPath)
			assert.ErrorIs(t, missingErr, os.ErrNotExist)
		})
	}
}

func directoryEntryNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}

func mustReadDir(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	require.NoError(t, err)
	return entries
}

func TestAttemptCustodyInventoryFailureBlocksIntakeButNotInspection(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	attemptLimits := DefaultAttemptLimits()
	attemptLimits.ManagedObjects = 1
	options := DefaultOpenOptions()
	options.AttemptLimits = attemptLimits
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	_, err = store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	require.NoError(t, err)
	unknown := filepath.Join(directory, payloadDirectoryName, "unexpected-object")
	require.NoError(t, os.WriteFile(unknown, []byte("sentinel"), 0o600))
	second := candidateWithPublicationID(t, candidate, [16]byte{0x55})
	_, err = store.PrepareAttempt(ctx, second, view, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, loaded.Lifecycle)
	page, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.Len(t, page.Attempts, 1)
	data, err := os.ReadFile(unknown)
	require.NoError(t, err)
	assert.Equal(t, []byte("sentinel"), data)
	require.NoError(t, os.Remove(unknown))
	payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
	require.NoError(t, os.Remove(payloadPath))
	missingCatalogCandidate := candidateWithPublicationID(t, candidate, [16]byte{0x56})
	missingProposal, err := store.PrepareAttempt(ctx, missingCatalogCandidate, view, review)
	require.NoError(t, err)
	_, err = store.CreateAttempt(ctx, missingProposal.StateToken, missingCatalogCandidate, view, review, missingProposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateMissing)
	_, statErr := os.Stat(payloadPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	var active int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM active_publication_attempt").Scan(&active))
	assert.Equal(t, 0, active)
	differentPayload := packFixtureContent(t, candidate.Payload, []byte("different retained candidate bytes"))
	different := candidateWithPayload(t, candidate, f.binding, differentPayload)
	_, err = store.PrepareAttempt(ctx, different, view, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	_, statErr = os.Stat(payloadPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	loaded, err = store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, loaded.Lifecycle)
}

func TestPublicationAttemptEvidenceLogicalBytesTrackReplacementExactly(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)

	shortView := cloneSuppliedView(empty)
	shortView.SuppliedContext.RepositoryRevision = "short"
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	first, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, shortView)
	require.NoError(t, err)
	assert.Equal(t, OutcomeAbsentUnresolved, first.Outcome)
	assertAttemptLogicalBytesExact(t, store, attempt.ID)
	shortBytes := attemptLogicalBytes(t, store, attempt.ID)

	longView := cloneSuppliedView(shortView)
	longView.SuppliedContext.RepositoryRevision = strings.Repeat("r", 900)
	loaded, err = store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	second, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, longView)
	require.NoError(t, err)
	assert.Equal(t, OutcomeAbsentUnresolved, second.Outcome)
	assertAttemptLogicalBytesExact(t, store, attempt.ID)
	longBytes := attemptLogicalBytes(t, store, attempt.ID)
	assert.Greater(t, longBytes, shortBytes)

	loaded, err = store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	third, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, shortView)
	require.NoError(t, err)
	assert.Equal(t, OutcomeAbsentUnresolved, third.Outcome)
	assertAttemptLogicalBytesExact(t, store, attempt.ID)
	assert.Equal(t, shortBytes, attemptLogicalBytes(t, store, attempt.ID))
	var eventCount int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_events WHERE attempt_id=?", attempt.ID[:]).Scan(&eventCount))
	assert.Equal(t, 4, eventCount)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assertAttemptLogicalBytesExact(t, reopened, attempt.ID)
	current := attemptView(f, f.observation(1), false)
	resolution, err := reopened.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	finalized, err := reopened.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
}

func attemptLogicalBytes(t *testing.T, store *Store, id [16]byte) uint64 {
	t.Helper()
	var logical int64
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT logical_bytes FROM publication_attempts WHERE attempt_id=?", id[:]).Scan(&logical))
	require.GreaterOrEqual(t, logical, int64(0))
	return uint64(logical)
}

func assertAttemptLogicalBytesExact(t *testing.T, store *Store, id [16]byte) {
	t.Helper()
	var actual, coreBytes, eventBytes, evidenceBytes int64
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT logical_bytes FROM publication_attempts WHERE attempt_id=?", id[:]).Scan(&actual))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT length(core) FROM publication_attempts WHERE attempt_id=?", id[:]).Scan(&coreBytes))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_events WHERE attempt_id=?", id[:]).Scan(&eventBytes))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COALESCE(SUM(length(body)+length(digest)),0) FROM attempt_evidence WHERE attempt_id=?", id[:]).Scan(&evidenceBytes))
	assert.Equal(t, coreBytes+eventBytes+evidenceBytes, actual)
}

func TestPublicationAttemptSequence4078CurrentProofExcludesPrehistory(t *testing.T) {
	lowFixture := newFixture(t, BackendPublicRepo)
	lowFixture.appendRecord(t, 0)
	lowFixture.appendRecord(t, 1)
	lowFixture.appendRecord(t, 2)
	low := createCurrentProofRun(t, lowFixture, singleSequenceObservation(t, lowFixture, 1), 2)
	t.Cleanup(func() { _ = low.store.Close() })

	highFixture := newFixture(t, BackendPublicRepo)
	for sequence := uint64(0); sequence <= 4079; sequence++ {
		highFixture.appendRecord(t, sequence)
	}
	high := createCurrentProofRun(t, highFixture, singleSequenceObservation(t, highFixture, 4077), 4078)
	t.Cleanup(func() { _ = high.store.Close() })

	assert.Equal(t, 3, len(low.current.Snapshots))
	assert.Equal(t, 4079, len(high.current.Snapshots))
	require.Len(t, low.proof.Suffix, 1)
	require.Len(t, high.proof.Suffix, 1)
	assert.Equal(t, low.proof.Scope, high.proof.Scope)
	assert.Equal(t, low.proof.Origin, high.proof.Origin)
	assert.Equal(t, low.proof.Context, high.proof.Context)
	assert.Len(t, low.proof.AttemptedKey, publication.SequenceKeyLength)
	assert.Len(t, high.proof.AttemptedKey, publication.SequenceKeyLength)
	assert.Equal(t, low.proof.Outcome, high.proof.Outcome)
	assert.Len(t, low.proof.ViewDigest, 32)
	assert.Len(t, high.proof.ViewDigest, 32)
	assert.Equal(t, low.candidate.SnapshotRecord, low.proof.Suffix[0].Raw)
	assert.Equal(t, high.candidate.SnapshotRecord, high.proof.Suffix[0].Raw)
	assert.Equal(t, low.predecessor, low.proof.PredecessorRecord)
	assert.Equal(t, high.predecessor, high.proof.PredecessorRecord)
	assert.Equal(t, 2, len(high.proof.Head)-len(low.proof.Head))
	assert.Equal(t, 2, len(high.proof.AttemptedRecord)-len(low.proof.AttemptedRecord))
	assert.Equal(t, 2, len(high.proof.PredecessorRecord)-len(low.proof.PredecessorRecord))
	assert.Len(t, low.proof.Suffix[0].Key, publication.SequenceKeyLength)
	assert.Len(t, high.proof.Suffix[0].Key, publication.SequenceKeyLength)

	lowOracle := currentOutcomeOracle(t, low)
	highOracle := currentOutcomeOracle(t, high)
	assert.Equal(t, lowOracle, low.resolution.Evidence)
	assert.Equal(t, highOracle, high.resolution.Evidence)
	base64WidthDelta := func(highBytes, lowBytes []byte) int {
		return base64.StdEncoding.EncodedLen(len(highBytes)) - base64.StdEncoding.EncodedLen(len(lowBytes))
	}
	expectedDelta := base64WidthDelta(high.proof.Head, low.proof.Head) +
		base64WidthDelta(high.proof.AttemptedRecord, low.proof.AttemptedRecord) +
		base64WidthDelta(high.proof.PredecessorRecord, low.proof.PredecessorRecord) +
		base64WidthDelta(high.proof.Suffix[0].Raw, low.proof.Suffix[0].Raw)
	assert.Equal(t, expectedDelta, len(highOracle)-len(lowOracle))
	assert.Equal(t, expectedDelta, len(high.resolution.Evidence)-len(low.resolution.Evidence))

	finalized, err := high.store.FinalizeAttempt(context.Background(), high.attempt.ID, high.resolution.Attempt.StateDigest, high.current)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	assert.Equal(t, uint64(4078), finalized.Floor.Sequence)

	candidate := attemptCandidate(highFixture, 4079)
	preflight := attemptView(highFixture, highFixture.observation(4079), false)
	review := attemptReview()
	beforeRows := readAttemptLogicalRows(t, high.store)
	beforeFiles := payloadDirectorySnapshot(t, high.directory)
	proposal, err := high.store.PrepareAttempt(context.Background(), candidate, preflight, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, AttemptProposal{}, proposal)
	result, err := high.store.CreateAttempt(context.Background(), [32]byte{}, candidate, preflight, review, [32]byte{})
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, Attempt{}, result)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, high.store))
	assert.Equal(t, beforeFiles, payloadDirectorySnapshot(t, high.directory))
	assertNoAdditionalAttemptRows(t, high.store, high.directory, 1)
}

type currentProofRun struct {
	store       *Store
	directory   string
	attempt     Attempt
	candidate   CandidateInput
	current     SuppliedRepositoryView
	predecessor []byte
	resolution  AttemptResolution
	proof       attemptEvidenceWire
}

func createCurrentProofRun(t *testing.T, f fixture, floorObservation Observation, sequence uint64) currentProofRun {
	t.Helper()
	ctx := context.Background()
	store, directory := newStore(t, f)
	first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	var acceptedRecords int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM accepted_records").Scan(&acceptedRecords))
	require.Equal(t, 1, acceptedRecords, "the synthetic high-sequence prehistory is held in memory, not persisted as thousands of accepted points")

	preflight := attemptView(f, f.observation(int(sequence)), false)
	candidate := attemptCandidate(f, sequence)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, preflight, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, preflight, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, preflight, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, preflight, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	current := attemptView(f, f.observation(int(sequence+1)), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, resolution.Outcome)
	var acceptedAfterResolve int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM accepted_records").Scan(&acceptedAfterResolve))
	assert.Equal(t, 1, acceptedAfterResolve)
	var storedOutcome []byte
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body FROM attempt_evidence WHERE attempt_id=? AND role='outcome'", attempt.ID[:]).Scan(&storedOutcome))
	assert.Equal(t, resolution.Evidence, storedOutcome)
	var proof attemptEvidenceWire
	require.NoError(t, strictJSON(storedOutcome, &proof))
	predecessor := bytes.Clone(f.blocks[sequence-1].Raw)
	return currentProofRun{store: store, directory: directory, attempt: attempt, candidate: candidate, current: current, predecessor: predecessor, resolution: resolution, proof: proof}
}

func singleSequenceObservation(t *testing.T, f fixture, sequence uint64) Observation {
	t.Helper()
	block := f.blocks[sequence]
	record, err := publication.DecodeSnapshot(block.Raw)
	require.NoError(t, err)
	cid, err := publication.RecordCID(block.Raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: record.Vault, PublicationSeq: sequence, SnapshotCID: cid, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	context := f.observation(1).SuppliedContext
	return Observation{Origin: f.binding, SuppliedContext: context, Head: head, Snapshots: []SnapshotBlock{{Key: block.Key, Raw: bytes.Clone(block.Raw)}}}
}

func currentOutcomeOracle(t *testing.T, run currentProofRun) []byte {
	t.Helper()
	return oracleCanonicalJSON(t, wireOracleEvidence{Version: 1, Role: "outcome", Scope: string(run.current.Scope), ViewDigest: bytes.Clone(run.resolution.ViewDigest[:]), Origin: wireVectorBinding(run.current.Origin), Context: wireVectorContext(run.current.SuppliedContext), Head: bytes.Clone(run.current.Head), AttemptedKey: run.candidate.SnapshotKey, AttemptedRecord: bytes.Clone(run.candidate.SnapshotRecord), PredecessorRecord: bytes.Clone(run.predecessor), Suffix: []wireOracleSnapshot{{Key: run.candidate.SnapshotKey, Raw: bytes.Clone(run.candidate.SnapshotRecord)}}, Outcome: string(OutcomeCurrent)})
}

func payloadDirectorySnapshot(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, payloadDirectoryName, entry.Name()))
		require.NoError(t, err)
		files[entry.Name()] = data
	}
	return files
}
