package publicationstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenRequiresExplicitPositionSchemaUpgradeAndPreservesHistory(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	observation := f.observation(1)
	_, err := store.RecordObservation(ctx, observation)
	require.NoError(t, err)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	historyBefore, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	databaseID := store.databaseID
	positionLimits := store.limits
	require.NoError(t, downgradeAttemptSchemaForTest(t, store))
	require.NoError(t, store.Close())

	_, err = Open(directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
	readOnly, err := sql.Open("sqlite", dbDSN(directory+"/publication.db", true))
	require.NoError(t, err)
	var version int
	require.NoError(t, readOnly.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
	assert.Equal(t, 1, version)
	require.NoError(t, readOnly.Close())

	options := DefaultOpenOptions()
	options.PositionLimits = positionLimits
	options.UpgradeFromPositions = true
	upgraded, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	defer upgraded.Close()
	assert.Equal(t, databaseID, upgraded.databaseID)
	loaded, present, err := upgraded.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, floor, loaded)
	historyAfter, err := upgraded.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, historyBefore, historyAfter)
	var cached int
	require.NoError(t, upgraded.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM cache_observations").Scan(&cached))
	assert.Equal(t, 1, cached)
	require.NoError(t, checkSchema(ctx, upgraded.conn))
	var upgradedVersion int
	require.NoError(t, upgraded.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&upgradedVersion))
	assert.Equal(t, 2, upgradedVersion)

	floorObservation := f.observation(1)
	candidate := attemptCandidate(f, 1)
	view := attemptView(f, floorObservation, false)
	review := attemptReview()
	attemptProposal, err := upgraded.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := upgraded.CreateAttempt(ctx, attemptProposal.StateToken, candidate, view, review, attemptProposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := upgraded.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	_, err = upgraded.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := upgraded.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = upgraded.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	current := attemptView(f, f.observation(2), false)
	active, present, err := upgraded.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)
	resolution, err := upgraded.ResolveAttempt(ctx, active.ID, active.StateDigest, current)
	require.NoError(t, err)
	finalized, err := upgraded.FinalizeAttempt(ctx, active.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), finalized.Floor.Sequence)
	var retained int
	require.NoError(t, upgraded.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retained))
	assert.Equal(t, 1, retained)
	var oldFloorRetained int
	require.NoError(t, upgraded.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE sequence=0").Scan(&oldFloorRetained))
	assert.Equal(t, 0, oldFloorRetained)
	fullHistory, err := upgraded.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, fullHistory.Events, 2)
	assert.Equal(t, historyBefore.Events[0], fullHistory.Events[0])
}

func TestPublicationStateUpgradeFromBaselineSchemaOneFixturePreservesRawRows(t *testing.T) {
	ctx := context.Background()
	fixtureDirectory := filepath.Join("testdata", "positions-v1")
	fixtureAssets := map[string]string{
		"schema1-baseline.db":          "f628f1905531fa7036497ee6a986eb7cce53affd43158452e32c342d5861363f",
		"schema1-baseline-rows.json":   "d295459410ab996ca597027699d5e9f6e146ae107524744e717a017ca81814d9",
		"schema1-baseline-payload.bin": "fbb1e20533b38f9977557cc443c6dba1785ba09a52dc401f57f371a67e302744",
	}
	assets := make(map[string][]byte, len(fixtureAssets))
	for name, expectedHash := range fixtureAssets {
		data, err := os.ReadFile(filepath.Join(fixtureDirectory, name))
		require.NoError(t, err)
		digest := sha256.Sum256(data)
		assert.Equal(t, expectedHash, hex.EncodeToString(digest[:]))
		assets[name] = bytes.Clone(data)
	}
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	for name, data := range assets {
		target := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(target, data, 0o600))
	}
	baselineRowsBytes, err := os.ReadFile(filepath.Join(root, "schema1-baseline-rows.json"))
	require.NoError(t, err)
	var baselineRows map[string]string
	require.NoError(t, json.Unmarshal(baselineRowsBytes, &baselineRows))
	require.Len(t, baselineRows, 6)
	payloadFixture, err := os.ReadFile(filepath.Join(root, "schema1-baseline-payload.bin"))
	require.NoError(t, err)

	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	require.Equal(t, payloadFixture, f.payload)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	databasePath := filepath.Join(directory, "publication.db")
	require.NoError(t, os.WriteFile(databasePath, assets["schema1-baseline.db"], 0o600))

	_, err = Open(directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
	readOnly, err := sql.Open("sqlite", dbDSN(databasePath, true))
	require.NoError(t, err)
	readOnlyConn, err := readOnly.Conn(ctx)
	require.NoError(t, err)
	var version int
	require.NoError(t, readOnlyConn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
	assert.Equal(t, 1, version)
	assert.Equal(t, baselineRows, readLogicalRows(t, readOnlyConn))
	require.NoError(t, readOnlyConn.Close())
	require.NoError(t, readOnly.Close())

	options := DefaultOpenOptions()
	options.UpgradeFromPositions = true
	upgraded, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	baselineMetadata := schema1Metadata(t, baselineRows["store_meta"])
	expectedDatabaseID, err := base64.StdEncoding.DecodeString(baselineMetadata["database_id"])
	require.NoError(t, err)
	assert.Equal(t, expectedDatabaseID, upgraded.databaseID[:])
	assert.Equal(t, DefaultLimits(), upgraded.limits)
	loaded, present, err := upgraded.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, uint64(1), loaded.Sequence)
	assert.Equal(t, uint64(2), loaded.Revision)
	assert.Equal(t, uint64(1), loaded.Generation)
	assertSchema1PositionRowsUnchanged(t, baselineRows, readLogicalRows(t, upgraded.conn))
	assertSchema1OldMetadataUnchanged(t, baselineRows, readLogicalRows(t, upgraded.conn))
	require.NoError(t, checkSchema(ctx, upgraded.conn))
	require.NoError(t, upgraded.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	floor, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, uint64(1), floor.Sequence)
	assertSchema1PositionRowsUnchanged(t, baselineRows, readLogicalRows(t, reopened.conn))
	assertSchema1OldMetadataUnchanged(t, baselineRows, readLogicalRows(t, reopened.conn))

	candidate := attemptCandidate(f, 2)
	candidate.Payload = bytes.Clone(payloadFixture)
	preflight := attemptView(f, f.observation(2), false)
	review := attemptReview()
	proposal, err := reopened.PrepareAttempt(ctx, candidate, preflight, review)
	require.NoError(t, err)
	attempt, err := reopened.CreateAttempt(ctx, proposal.StateToken, candidate, preflight, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	upload, err := reopened.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, preflight, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, payloadFixture, upload.Payload)
	submissionProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
	require.NoError(t, err)
	_, err = reopened.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, preflight, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	current := attemptView(f, f.observation(3), false)
	loadedAttempt, err := reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := reopened.ResolveAttempt(ctx, attempt.ID, loadedAttempt.StateDigest, current)
	require.NoError(t, err)
	finalized, err := reopened.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), finalized.Floor.Sequence)
	assert.Equal(t, uint64(3), finalized.Floor.Revision)

	var retainedRows, payloadObjects, oldRetained int
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retainedRows))
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&payloadObjects))
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE sequence<2").Scan(&oldRetained))
	assert.Equal(t, 1, retainedRows)
	assert.Equal(t, 1, payloadObjects)
	assert.Zero(t, oldRetained)
	var retainedRecord, retainedBlob []byte
	var retainedSequence, retainedSize int64
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT record_cid,sequence,blob_cid,size FROM retained_publications").Scan(&retainedRecord, &retainedSequence, &retainedBlob, &retainedSize))
	assert.Equal(t, attempt.SnapshotRecordCID, retainedRecord)
	assert.Equal(t, int64(2), retainedSequence)
	assert.Equal(t, attempt.BlobCID, retainedBlob)
	assert.Equal(t, int64(attempt.BlobSize), retainedSize)
	var payloadCID []byte
	var payloadSize int64
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT blob_cid,size FROM payload_objects").Scan(&payloadCID, &payloadSize))
	assert.Equal(t, attempt.BlobCID, payloadCID)
	assert.Equal(t, int64(attempt.BlobSize), payloadSize)
	var payloadReferences int
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&payloadReferences))
	assert.Zero(t, payloadReferences)
	assertSchema1OldRowsStillPresent(t, baselineRows, readLogicalRows(t, reopened.conn))
	assertSchema1StableMetadataAfterAdvance(t, baselineRows, readLogicalRows(t, reopened.conn))
	require.NoError(t, reopened.Close())

	finalStore, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer finalStore.Close()
	finalFloor, present, err := finalStore.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, uint64(2), finalFloor.Sequence)
	assert.Equal(t, uint64(3), finalFloor.Revision)
	assertSchema1OldRowsStillPresent(t, baselineRows, readLogicalRows(t, finalStore.conn))

	original, err := os.ReadFile(filepath.Join(fixtureDirectory, "schema1-baseline.db"))
	require.NoError(t, err)
	originalHash := sha256.Sum256(original)
	assert.Equal(t, fixtureAssets["schema1-baseline.db"], hex.EncodeToString(originalHash[:]))
}

func assertSchema1PositionRowsUnchanged(t *testing.T, expected, actual map[string]string) {
	t.Helper()
	for table, rows := range expected {
		if table == "store_meta" {
			continue
		}
		assert.Equal(t, rows, actual[table], table)
	}
}

func schema1Metadata(t *testing.T, rows string) map[string]string {
	t.Helper()
	var entries [][]string
	require.NoError(t, json.Unmarshal([]byte(rows), &entries))
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		require.Len(t, entry, 2)
		values[entry[0]] = entry[1]
	}
	return values
}

func assertSchema1OldMetadataUnchanged(t *testing.T, expected, actual map[string]string) {
	t.Helper()
	want := schema1Metadata(t, expected["store_meta"])
	got := schema1Metadata(t, actual["store_meta"])
	for _, key := range []string{"binding", "database_id", "generation", "limits", "revision"} {
		assert.Equal(t, want[key], got[key], key)
	}
}

func assertSchema1StableMetadataAfterAdvance(t *testing.T, expected, actual map[string]string) {
	t.Helper()
	want := schema1Metadata(t, expected["store_meta"])
	got := schema1Metadata(t, actual["store_meta"])
	for _, key := range []string{"binding", "database_id", "generation", "limits"} {
		assert.Equal(t, want[key], got[key], key)
	}
}

func assertSchema1OldRowsStillPresent(t *testing.T, expected, actual map[string]string) {
	t.Helper()
	for _, table := range []string{"accepted_records", "accepted_events"} {
		var oldRows, currentRows [][]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(expected[table]), &oldRows))
		require.NoError(t, json.Unmarshal([]byte(actual[table]), &currentRows))
		byFirstColumn := make(map[string][]json.RawMessage, len(currentRows))
		for _, row := range currentRows {
			require.NotEmpty(t, row)
			byFirstColumn[string(row[0])] = row
		}
		for _, oldRow := range oldRows {
			require.NotEmpty(t, oldRow)
			assert.Equal(t, oldRow, byFirstColumn[string(oldRow[0])], table)
		}
	}
	for _, table := range []string{"cache_records", "cache_observations"} {
		assert.Equal(t, expected[table], actual[table], table)
	}
}

func TestPublicationStateUpgradeAbortsEverySchemaStageWithoutLosingPositions(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	_, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	positionLimits := store.limits
	before, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.NoError(t, downgradeAttemptSchemaForTest(t, store))
	require.NoError(t, store.Close())

	options := DefaultOpenOptions()
	options.PositionLimits = positionLimits
	options.UpgradeFromPositions = true
	stages := len(attemptSchemaStatements) + 4
	for failAt := 1; failAt <= stages; failAt++ {
		options.upgradeFault = func(stage int) error {
			if stage == failAt {
				return errors.New("upgrade fault canary")
			}
			return nil
		}
		_, err := OpenWithOptions(directory, f.binding, options)
		requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
		check, err := sql.Open("sqlite", dbDSN(directory+"/publication.db", true))
		require.NoError(t, err)
		var version int
		require.NoError(t, check.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
		assert.Equal(t, 1, version)
		var attemptTables int
		require.NoError(t, check.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE name='publication_attempts'").Scan(&attemptTables))
		assert.Equal(t, 0, attemptTables)
		var eventCount int
		require.NoError(t, check.QueryRowContext(ctx, "SELECT COUNT(*) FROM accepted_events").Scan(&eventCount))
		assert.Equal(t, len(before.Events), eventCount)
		require.NoError(t, check.Close())
	}
	options.upgradeFault = nil
	upgraded, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	defer upgraded.Close()
	after, err := upgraded.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestPublicationStateUpgradeCommitUnknownReadbackRecognizesCommittedSchema(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.NoError(t, downgradeAttemptSchemaForTest(t, store))
	require.NoError(t, store.Close())
	options := DefaultOpenOptions()
	options.UpgradeFromPositions = true
	options.upgradeCommit = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("upgrade commit canary")
	}
	_, err = OpenWithOptions(directory, f.binding, options)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	loaded, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, floor, loaded)
	after, err := reopened.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, history, after)
}

func downgradeAttemptSchemaForTest(t *testing.T, store *Store) error {
	t.Helper()
	ctx := context.Background()
	for _, table := range []string{"active_publication_attempt", "pending_genesis", "retained_publications", "attempt_payload_refs", "attempt_reservations", "attempt_evidence", "attempt_events", "payload_objects", "publication_attempts"} {
		if _, err := store.conn.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			return err
		}
	}
	if _, err := store.conn.ExecContext(ctx, "DELETE FROM store_meta WHERE key IN ('attempt_limits','attempt_mutation_revision')"); err != nil {
		return err
	}
	_, err := store.conn.ExecContext(ctx, "PRAGMA user_version=1")
	return err
}
