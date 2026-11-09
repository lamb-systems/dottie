package publicationstate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReadAcceptedMaterialFinalizedOwnerSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendSpaces)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	require.Equal(t, AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	expectedFloor := cloneFloor(finalized.Floor)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	before := acceptedMaterialObservedState(t, reopened, attempt.ID)
	beforeRows := readAttemptLogicalRows(t, reopened)
	material, err := reopened.ReadAcceptedMaterial(ctx, f.binding, expectedFloor)
	require.NoError(t, err)
	require.Equal(t, expectedFloor, material.Floor)
	require.Equal(t, candidate.SnapshotRecord, material.SnapshotRecord)
	require.Equal(t, candidate.Payload, material.Payload)
	assert.Equal(t, expectedFloor.DatabaseID, material.Floor.DatabaseID)
	assert.Equal(t, expectedFloor.Generation, material.Floor.Generation)
	require.NotNil(t, material.Floor.SuppliedContext.Policy)

	material.Floor.AnchorCID[0] ^= 0xff
	material.Floor.Head[0] ^= 0xff
	material.Floor.RecordCID[0] ^= 0xff
	material.Floor.BlobCID[0] ^= 0xff
	material.Floor.SuppliedContext.RepositoryDigest[0] ^= 0xff
	material.Floor.SuppliedContext.Policy.Identity[0] ^= 0xff
	material.SnapshotRecord[0] ^= 0xff
	material.Payload[0] ^= 0xff

	again, err := reopened.ReadAcceptedMaterial(ctx, f.binding, expectedFloor)
	require.NoError(t, err)
	assert.Equal(t, expectedFloor, again.Floor)
	assert.Equal(t, candidate.SnapshotRecord, again.SnapshotRecord)
	assert.Equal(t, candidate.Payload, again.Payload)
	after := acceptedMaterialObservedState(t, reopened, attempt.ID)
	assert.Equal(t, before, after)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, reopened))
}

func TestPublicationReadAcceptedMaterialPositionOnlyAcceptanceIsNotRetained(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	observation := f.observation(1)
	proposal, err := store.Prepare(ctx, ModeFirstUse, observation, f.payload)
	require.NoError(t, err)
	floor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	_, _, err = store.Load(ctx)
	require.NoError(t, err)
	beforeRows := readAttemptLogicalRows(t, store)
	beforeFloor, beforeHistory := acceptedMaterialPositionState(t, store)

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	assert.Equal(t, AcceptedMaterial{}, material)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
	afterFloor, afterHistory := acceptedMaterialPositionState(t, store)
	assert.Equal(t, beforeFloor, afterFloor)
	assert.Equal(t, beforeHistory, afterHistory)
	var retained int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retained))
	assert.Zero(t, retained)
	assert.NoError(t, assertPayloadDirectoryAbsent(directory))
}

func TestPublicationReadAcceptedMaterialRequiresExistingFloorAndValidContext(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	store, directory := newStore(t, f)
	defer store.Close()

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, Floor{})
	requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonFirstUseRequired)
	assert.Equal(t, AcceptedMaterial{}, material)
	assert.NoError(t, assertPayloadDirectoryAbsent(directory))

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	material, err = store.ReadAcceptedMaterial(canceled, f.binding, Floor{})
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonCanceled)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, AcceptedMaterial{}, material)

	material, err = store.ReadAcceptedMaterial(nil, f.binding, Floor{})
	requireErrorMetadata(t, err, ErrInvalid, StageReadAcceptedMaterial, ReasonContext)
	assert.Equal(t, AcceptedMaterial{}, material)

	require.NoError(t, store.Close())
	material, err = store.ReadAcceptedMaterial(ctx, f.binding, Floor{})
	requireErrorMetadata(t, err, ErrClosed, StageReadAcceptedMaterial, ReasonClosed)
	assert.Equal(t, AcceptedMaterial{}, material)
}

func TestPublicationReadAcceptedMaterialRequiresIndependentBindingAndCompleteFloor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendSpaces)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	defer store.Close()

	wrongBinding := f.binding
	wrongBinding.Vault[0] ^= 0xff
	require.NoError(t, validateBinding(wrongBinding))
	require.NotEqual(t, f.binding, wrongBinding)
	material, err := store.ReadAcceptedMaterial(ctx, wrongBinding, finalized.Floor)
	assert.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrInvalid, StageReadAcceptedMaterial, ReasonBinding)

	require.NotEmpty(t, finalized.Floor.AnchorCID)
	require.NotEmpty(t, finalized.Floor.Head)
	require.NotEmpty(t, finalized.Floor.RecordCID)
	require.NotEmpty(t, finalized.Floor.BlobCID)
	require.NotEmpty(t, finalized.Floor.SuppliedContext.RepositoryDigest)
	require.NotNil(t, finalized.Floor.SuppliedContext.Policy)
	require.NotEmpty(t, finalized.Floor.SuppliedContext.Policy.Identity)

	mutations := []struct {
		name   string
		mutate func(*Floor)
	}{
		{"database-id", func(floor *Floor) { floor.DatabaseID[0] ^= 0xff }},
		{"generation", func(floor *Floor) { floor.Generation++ }},
		{"revision", func(floor *Floor) { floor.Revision++ }},
		{"provenance", func(floor *Floor) { floor.Provenance = ProvenanceReplace }},
		{"anchor", func(floor *Floor) { floor.AnchorCID[0] ^= 0xff }},
		{"head", func(floor *Floor) { floor.Head[0] ^= 0xff }},
		{"publication-id", func(floor *Floor) { floor.PublicationID[0] ^= 0xff }},
		{"record-cid", func(floor *Floor) { floor.RecordCID[0] ^= 0xff }},
		{"blob-cid", func(floor *Floor) { floor.BlobCID[0] ^= 0xff }},
		{"blob-size", func(floor *Floor) { floor.BlobSize++ }},
		{"observation-digest", func(floor *Floor) { floor.ObservationDigest[0] ^= 0xff }},
		{"accepted-event-digest", func(floor *Floor) { floor.AcceptedEventDigest[0] ^= 0xff }},
		{"repository-context", func(floor *Floor) { floor.SuppliedContext.RepositoryDigest[0] ^= 0xff }},
		{"policy-context", func(floor *Floor) { floor.SuppliedContext.Policy.Identity[0] ^= 0xff }},
		{"repository-revision", func(floor *Floor) { floor.SuppliedContext.RepositoryRevision += "x" }},
		{"policy-revision", func(floor *Floor) { floor.SuppliedContext.Policy.Revision += "x" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			expected := cloneFloor(finalized.Floor)
			test.mutate(&expected)
			material, err := store.ReadAcceptedMaterial(ctx, f.binding, expected)
			assert.Equal(t, AcceptedMaterial{}, material)
			requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonStale)
		})
	}

	material, err = store.ReadAcceptedMaterial(ctx, f.binding, Floor{})
	requireErrorMetadata(t, err, ErrInvalid, StageReadAcceptedMaterial, ReasonBinding)
	assert.Equal(t, AcceptedMaterial{}, material)
	malformedFloor := cloneFloor(finalized.Floor)
	malformedFloor.SnapshotKey = ""
	material, err = store.ReadAcceptedMaterial(ctx, f.binding, malformedFloor)
	requireErrorMetadata(t, err, ErrInvalid, StageReadAcceptedMaterial, ReasonRecordSet)
	assert.Equal(t, AcceptedMaterial{}, material)
	assert.NoError(t, assertPayloadDirectoryPresent(directory))
}

func TestPublicationReadAcceptedMaterialFencedUntilExplicitReadback(t *testing.T) {
	for _, mode := range []string{"commit-then-error", "rollback-then-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendSpaces)
			f.appendRecord(t, 0)
			store, _ := newStore(t, f)
			defer store.Close()
			candidate := attemptCandidate(f, 0)
			empty := attemptView(f, f.observation(1), true)
			review := attemptReview()
			attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
			current := attemptView(f, f.observation(1), false)
			loaded, err := store.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
			require.NoError(t, err)
			if mode == "rollback-then-error" {
				installDeferredAttemptCommitFailure(t, store, "CREATE TEMP TRIGGER fail_material_finalize_commit AFTER INSERT ON main.retained_publications BEGIN INSERT INTO attempt_commit_child(id) VALUES(1); END")
			}
			var prospective Floor
			var captureErr error
			store.commitTransaction = func(tx *sql.Tx) error {
				prospective, captureErr = acceptedMaterialFloorInTransaction(tx)
				if captureErr != nil {
					return captureErr
				}
				if err := tx.Commit(); err != nil {
					return err
				}
				if mode == "commit-then-error" {
					return errors.New("commit canary")
				}
				return nil
			}
			if mode == "rollback-then-error" {
				store.commitTransaction = func(tx *sql.Tx) error {
					prospective, captureErr = acceptedMaterialFloorInTransaction(tx)
					if captureErr != nil {
						return captureErr
					}
					return tx.Commit()
				}
			}

			finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
			requireErrorMetadata(t, err, ErrStorage, StageFinalize, ReasonCommitUnknown)
			assert.Equal(t, Finalization{}, finalized)
			assert.NoError(t, captureErr)
			assert.NotEqual(t, Floor{}, prospective)
			assert.True(t, store.needsReadback)

			material, err := store.ReadAcceptedMaterial(ctx, f.binding, prospective)
			requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonCommitUnknown)
			assert.Equal(t, AcceptedMaterial{}, material)
			assert.True(t, store.needsReadback)

			floor, present, err := store.Load(ctx)
			require.NoError(t, err)
			assert.False(t, store.needsReadback)
			if mode == "commit-then-error" {
				assert.True(t, present)
				assert.Equal(t, prospective, floor)
				material, err = store.ReadAcceptedMaterial(ctx, f.binding, prospective)
				require.NoError(t, err)
				assert.Equal(t, candidate.SnapshotRecord, material.SnapshotRecord)
				assert.Equal(t, candidate.Payload, material.Payload)
			} else {
				assert.False(t, present)
				assert.Equal(t, Floor{}, floor)
				material, err = store.ReadAcceptedMaterial(ctx, f.binding, Floor{})
				requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonFirstUseRequired)
				assert.Equal(t, AcceptedMaterial{}, material)
			}
		})
	}
}

type acceptedMaterialState struct {
	Floor          Floor
	HasFloor       bool
	History        HistoryPage
	Attempt        Attempt
	AttemptHistory AttemptPage
	Candidate      CandidateMaterial
}

func acceptedMaterialObservedState(t *testing.T, store *Store, attemptID [16]byte) acceptedMaterialState {
	t.Helper()
	ctx := context.Background()
	floor, hasFloor, err := store.Load(ctx)
	require.NoError(t, err)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	attempt, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	candidate, err := store.ReadCandidate(ctx, attemptID)
	require.NoError(t, err)
	return acceptedMaterialState{Floor: floor, HasFloor: hasFloor, History: history, Attempt: attempt, AttemptHistory: attemptHistory, Candidate: candidate}
}

func acceptedMaterialPositionState(t *testing.T, store *Store) (Floor, HistoryPage) {
	t.Helper()
	floor, present, err := store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	history, err := store.History(context.Background(), 0, 10)
	require.NoError(t, err)
	return floor, history
}

func acceptedMaterialFloorInTransaction(tx *sql.Tx) (Floor, error) {
	var encoded []byte
	if err := tx.QueryRowContext(context.Background(), "SELECT floor FROM active_floor WHERE singleton=1").Scan(&encoded); err != nil {
		return Floor{}, err
	}
	return decodeFloor(encoded)
}

func assertPayloadDirectoryAbsent(directory string) error {
	_, err := os.Stat(filepath.Join(directory, payloadDirectoryName))
	if err == nil {
		return errors.New("payload directory exists")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func assertPayloadDirectoryPresent(directory string) error {
	info, err := os.Stat(filepath.Join(directory, payloadDirectoryName))
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("payload path is not a directory")
	}
	return nil
}
