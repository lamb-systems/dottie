package publicationstate

import (
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrdinaryAcceptRefusesExactActiveGenesisAndSuccessor(t *testing.T) {
	ctx := context.Background()
	t.Run("genesis", func(t *testing.T) {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		defer store.Close()
		observation := f.observation(1)
		position, err := store.Prepare(ctx, ModeFirstUse, observation, f.payload)
		require.NoError(t, err)
		candidate := attemptCandidate(f, 0)
		view := attemptView(f, observation, true)
		review := attemptReview()
		attemptProposal, err := store.PrepareAttempt(ctx, candidate, view, review)
		require.NoError(t, err)
		_, err = store.CreateAttempt(ctx, attemptProposal.StateToken, candidate, view, review, attemptProposal.Confirmation)
		require.NoError(t, err)
		position, err = store.Prepare(ctx, ModeFirstUse, observation, f.payload)
		require.NoError(t, err)
		before := readLogicalRows(t, store.conn)
		floor, present, err := store.Load(ctx)
		require.NoError(t, err)
		assert.False(t, present)
		result, err := store.Accept(ctx, ModeFirstUse, position.StateToken, observation, f.payload, position.Confirmation)
		requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonActiveAttempt)
		assert.Equal(t, Floor{}, result)
		after, present, err := store.Load(ctx)
		require.NoError(t, err)
		assert.False(t, present)
		assert.Equal(t, floor, after)
		assert.Equal(t, before, readLogicalRows(t, store.conn))
	})

	t.Run("successor", func(t *testing.T) {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		f.appendRecord(t, 1)
		store, _ := newStore(t, f)
		defer store.Close()
		genesis := f.observation(1)
		first, err := store.Prepare(ctx, ModeFirstUse, genesis, f.payload)
		require.NoError(t, err)
		_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, genesis, f.payload, first.Confirmation)
		require.NoError(t, err)
		observation := f.observation(2)
		position, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
		require.NoError(t, err)
		candidate := attemptCandidate(f, 1)
		view := attemptView(f, genesis, false)
		review := attemptReview()
		attemptProposal, err := store.PrepareAttempt(ctx, candidate, view, review)
		require.NoError(t, err)
		_, err = store.CreateAttempt(ctx, attemptProposal.StateToken, candidate, view, review, attemptProposal.Confirmation)
		require.NoError(t, err)
		position, err = store.Prepare(ctx, ModeAdvance, observation, f.payload)
		require.NoError(t, err)
		before := readLogicalRows(t, store.conn)
		oldFloor, present, err := store.Load(ctx)
		require.NoError(t, err)
		require.True(t, present)
		result, err := store.Accept(ctx, ModeAdvance, position.StateToken, observation, f.payload, [32]byte{})
		requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonActiveAttempt)
		assert.Equal(t, Floor{}, result)
		after, present, err := store.Load(ctx)
		require.NoError(t, err)
		assert.True(t, present)
		assert.Equal(t, oldFloor, after)
		assert.Equal(t, before, readLogicalRows(t, store.conn))
	})
}

func TestOrdinaryAcceptanceOfDifferentPositionPreservesAttemptButInvalidatesDispatch(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	for sequence := uint64(0); sequence < 3; sequence++ {
		f.appendRecord(t, sequence)
	}
	store, _ := newStore(t, f)
	defer store.Close()
	genesis := f.observation(1)
	first, err := store.Prepare(ctx, ModeFirstUse, genesis, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, genesis, f.payload, first.Confirmation)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 1)
	view := attemptView(f, genesis, false)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	remote := f.observation(3)
	advance, err := store.Prepare(ctx, ModeAdvance, remote, f.payload)
	require.NoError(t, err)
	floor, err := store.Accept(ctx, ModeAdvance, advance.StateToken, remote, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), floor.Sequence)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Empty(t, loaded.Blocked)
	_, err = store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	requireErrorMetadata(t, err, ErrContinuity, StageDispatch, ReasonStale)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	_, err = store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	require.NoError(t, err)
}

func TestPublicationAttemptFloorReplacementBlocksAtomically(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newStore(t, f)
	defer store.Close()
	genesis := f.observation(1)
	first, err := store.Prepare(ctx, ModeFirstUse, genesis, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, genesis, f.payload, first.Confirmation)
	require.NoError(t, err)
	fork := forkGenesisObservation(t, f)
	staleReplacement, err := store.Prepare(ctx, ModeReplaceFloor, fork, f.payload)
	require.NoError(t, err)

	candidate := attemptCandidate(f, 1)
	view := attemptView(f, genesis, false)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	beforeStaleAccept, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	_, err = store.Accept(ctx, ModeReplaceFloor, staleReplacement.StateToken, fork, f.payload, staleReplacement.Confirmation)
	requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonStale)
	afterStaleAccept, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, beforeStaleAccept, afterStaleAccept)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)

	replacement, err := store.Prepare(ctx, ModeReplaceFloor, fork, f.payload)
	require.NoError(t, err)
	floor, err := store.Accept(ctx, ModeReplaceFloor, replacement.StateToken, fork, f.payload, replacement.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), floor.Generation)
	blocked, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, "blocked-floor-replaced", blocked.Blocked)
	assert.Equal(t, AttemptPrepared, blocked.Lifecycle)
	material, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, material.Payload)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	requireErrorMetadata(t, err, ErrContinuity, StageDispatch, ReasonFloorReplaced)

	backProposal, err := store.Prepare(ctx, ModeReplaceFloor, genesis, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeReplaceFloor, backProposal.StateToken, genesis, f.payload, backProposal.Confirmation)
	require.NoError(t, err)
	stillBlocked, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, "blocked-floor-replaced", stillBlocked.Blocked)
	assert.Equal(t, attempt.SnapshotRecordCID, stillBlocked.SnapshotRecordCID)
}

func TestPublicationAttemptFloorReplacementAbortIsAtomic(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	attempt, view, review := createSuccessorAttempt(t, store, f)
	beforeFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	beforeAttempt, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	beforeEvents, err := queryAttemptEvents(t, store, attempt.ID)
	require.NoError(t, err)
	fork := forkGenesisObservation(t, f)
	replacement, err := store.Prepare(ctx, ModeReplaceFloor, fork, f.payload)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "CREATE TEMP TRIGGER abort_attempt_block BEFORE UPDATE ON main.publication_attempts WHEN NEW.blocked='blocked-floor-replaced' BEGIN SELECT RAISE(ABORT,'private-canary-attempt-block'); END")
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeReplaceFloor, replacement.StateToken, fork, f.payload, replacement.Confirmation)
	require.ErrorIs(t, err, ErrStorage)
	assert.NotContains(t, err.Error(), "private-canary-attempt-block")
	afterFloor, present, loadErr := store.Load(ctx)
	require.NoError(t, loadErr)
	assert.True(t, present)
	assert.Equal(t, beforeFloor, afterFloor)
	afterAttempt, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, beforeAttempt.StateDigest, afterAttempt.StateDigest)
	assert.Empty(t, afterAttempt.Blocked)
	afterEvents, err := queryAttemptEvents(t, store, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, beforeEvents, afterEvents)
	_, err = store.conn.ExecContext(ctx, "DROP TRIGGER abort_attempt_block")
	require.NoError(t, err)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	loaded, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, beforeFloor, loaded)
	loadedAttempt, err := reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Empty(t, loadedAttempt.Blocked)
	_, err = reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
}

func TestPublicationAttemptFloorReplacementWriteFailuresRollbackAllRows(t *testing.T) {
	triggers := []struct {
		name string
		ddl  string
	}{
		{"accepted-record", "CREATE TEMP TRIGGER fail_replace_record BEFORE INSERT ON main.accepted_records BEGIN SELECT RAISE(ABORT,'replace-record-canary'); END"},
		{"accepted-event", "CREATE TEMP TRIGGER fail_replace_event BEFORE INSERT ON main.accepted_events BEGIN SELECT RAISE(ABORT,'replace-event-canary'); END"},
		{"floor", "CREATE TEMP TRIGGER fail_replace_floor BEFORE UPDATE ON main.active_floor BEGIN SELECT RAISE(ABORT,'replace-floor-canary'); END"},
		{"revision", "CREATE TEMP TRIGGER fail_replace_revision BEFORE UPDATE ON main.store_meta WHEN NEW.key='revision' BEGIN SELECT RAISE(ABORT,'replace-revision-canary'); END"},
		{"block-event", "CREATE TEMP TRIGGER fail_replace_block_event BEFORE INSERT ON main.attempt_events WHEN NEW.kind='blocked-floor-replaced' BEGIN SELECT RAISE(ABORT,'replace-block-event-canary'); END"},
		{"attempt-state", "CREATE TEMP TRIGGER fail_replace_attempt BEFORE UPDATE ON main.publication_attempts WHEN NEW.blocked='blocked-floor-replaced' BEGIN SELECT RAISE(ABORT,'replace-attempt-canary'); END"},
		{"reservation", "CREATE TEMP TRIGGER fail_replace_reservation BEFORE UPDATE ON main.attempt_reservations BEGIN SELECT RAISE(ABORT,'replace-reservation-canary'); END"},
	}
	for _, fault := range triggers {
		t.Run(fault.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			f.appendRecord(t, 1)
			store, directory := newStore(t, f)
			attempt, _, _ := createSuccessorAttempt(t, store, f)
			before := readAttemptLogicalRows(t, store)
			fork := forkGenesisObservation(t, f)
			replacement, err := store.Prepare(ctx, ModeReplaceFloor, fork, f.payload)
			require.NoError(t, err)
			_, err = store.conn.ExecContext(ctx, fault.ddl)
			require.NoError(t, err)
			_, err = store.Accept(ctx, ModeReplaceFloor, replacement.StateToken, fork, f.payload, replacement.Confirmation)
			require.ErrorIs(t, err, ErrStorage)
			assert.NotContains(t, err.Error(), "-canary")
			assert.Equal(t, before, readAttemptLogicalRows(t, store))
			require.NoError(t, store.Close())
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			assert.Equal(t, before, readAttemptLogicalRows(t, reopened))
			loaded, present, err := reopened.Load(ctx)
			require.NoError(t, err)
			assert.True(t, present)
			assert.Equal(t, uint64(0), loaded.Sequence)
			retained, err := reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Empty(t, retained.Blocked)
			material, err := reopened.ReadCandidate(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, f.blocks[1].Raw, material.SnapshotRecord)
		})
	}
}

func TestActiveAttemptSuccessReserveDoesNotBlockFloorReplacement(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	limits := DefaultLimits()
	limits.AcceptedEventCount = 2
	store, _ := newStore(t, f, limits)
	defer store.Close()
	attempt, _, _ := createSuccessorAttempt(t, store, f)
	fork := forkGenesisObservation(t, f)
	replacement, err := store.Prepare(ctx, ModeReplaceFloor, fork, f.payload)
	require.NoError(t, err)
	floor, err := store.Accept(ctx, ModeReplaceFloor, replacement.StateToken, fork, f.payload, replacement.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), floor.Sequence)
	blocked, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, "blocked-floor-replaced", blocked.Blocked)
	var acceptedEventReserve int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT accepted_events FROM attempt_reservations WHERE attempt_id=?", attempt.ID[:]).Scan(&acceptedEventReserve))
	assert.Equal(t, int64(0), acceptedEventReserve)
}

func createSuccessorAttempt(t *testing.T, store *Store, f fixture) (Attempt, SuppliedRepositoryView, LocalReviewContext) {
	t.Helper()
	ctx := context.Background()
	genesis := f.observation(1)
	first, err := store.Prepare(ctx, ModeFirstUse, genesis, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, genesis, f.payload, first.Confirmation)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 1)
	view := attemptView(f, genesis, false)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	return attempt, view, review
}

func forkGenesisObservation(t *testing.T, f fixture) Observation {
	t.Helper()
	record, err := publication.DecodeSnapshot(f.blocks[0].Raw)
	require.NoError(t, err)
	record.PublicationID[0] = 0x7f
	record.PublicationID[15] = 0x7e
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: 0, SnapshotCID: cid, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	observation := f.observation(1)
	observation.Head = head
	observation.Snapshots = []SnapshotBlock{{Key: f.blocks[0].Key, Raw: raw}}
	return observation
}

func queryAttemptEvents(t *testing.T, store *Store, id [16]byte) ([][]any, error) {
	t.Helper()
	rows, err := store.conn.QueryContext(context.Background(), "SELECT ordinal,kind,body,digest FROM attempt_events WHERE attempt_id=? ORDER BY ordinal", id[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events [][]any
	for rows.Next() {
		var ordinal, kind, body, digest any
		if err := rows.Scan(&ordinal, &kind, &body, &digest); err != nil {
			return nil, err
		}
		events = append(events, []any{ordinal, kind, body, digest})
	}
	return events, rows.Err()
}
