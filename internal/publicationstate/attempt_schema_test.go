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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenRequiresExplicitPositionSchemaUpgradeAndPreservesHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
	directory := filepath.Dir(databasePath)
	source := attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows)

	refused, err := Open(directory, f.binding)
	if refused != nil {
		t.Cleanup(func() { assert.NoError(t, refused.Close()) })
	}
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
	require.Nil(t, refused)
	require.Equal(t, source, attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows))

	expectedStages := make([]int, 0, len(attemptSchemaStatements)+5)
	for stage := 1; stage <= len(attemptSchemaStatements)+5; stage++ {
		expectedStages = append(expectedStages, stage)
	}
	stages := make([]int, 0, len(attemptSchemaStatements)+5)
	commits := 0
	options := DefaultOpenOptions()
	options.UpgradeFromPositions = true
	options.UpgradeFromAttempts = true
	options.upgradeFault = func(stage int) error {
		stages = append(stages, stage)
		return nil
	}
	options.upgradeCommit = func(tx *sql.Tx) error {
		commits++
		return tx.Commit()
	}
	upgraded, err := OpenWithOptions(directory, f.binding, options)
	if upgraded != nil {
		t.Cleanup(func() { assert.NoError(t, upgraded.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, 1, commits)
	require.Equal(t, expectedStages, stages)
	attemptSchemaRequireCurrent3(t, ctx, upgraded, f, source)
	require.NoError(t, upgraded.Close())

	reopened, err := Open(directory, f.binding)
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	attemptSchemaRequireCurrent3(t, ctx, reopened, f, source)

	candidate := attemptCandidate(f, 2)
	predecessorView := attemptView(f, f.observation(2), false)
	review := attemptReview()
	proposal, err := reopened.PrepareAttempt(ctx, candidate, predecessorView, review)
	require.NoError(t, err)
	attempt, err := reopened.CreateAttempt(ctx, proposal.StateToken, candidate, predecessorView, review, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptPrepared, attempt.Lifecycle)
	uploadProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, predecessorView, review)
	require.NoError(t, err)
	upload, err := reopened.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, predecessorView, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, f.payload, upload.Payload)
	submissionProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, predecessorView, review)
	require.NoError(t, err)
	_, err = reopened.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, predecessorView, review, submissionProposal.Confirmation)
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

	var retainedRows, payloadObjects, oldRetained, reservations, payloadReferences int
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retainedRows))
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&payloadObjects))
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE sequence<2").Scan(&oldRetained))
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_reservations").Scan(&reservations))
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&payloadReferences))
	assert.Equal(t, 1, retainedRows)
	assert.Equal(t, 1, payloadObjects)
	assert.Zero(t, oldRetained)
	assert.Zero(t, reservations)
	assert.Zero(t, payloadReferences)
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
	_, present, err := reopened.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, present)

	full, err := reopened.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, full.Events, 3)
	assert.Equal(t, source.history.Events, full.Events[:2])
	assert.False(t, full.HasMore)
	assert.Equal(t, uint64(3), full.NextRevision)
	require.GreaterOrEqual(t, len(full.Records), len(source.history.Records))
	assert.Equal(t, source.history.Records, full.Records[:len(source.history.Records)])
	rows := readLogicalRows(t, reopened.conn)
	assertSchema1OldRowsStillPresent(t, source.rows, rows)
	assertSchema1StableMetadataAfterAdvance(t, source.rows, rows)
	require.NoError(t, reopened.Close())

	final, err := Open(directory, f.binding)
	if final != nil {
		t.Cleanup(func() { assert.NoError(t, final.Close()) })
	}
	require.NoError(t, err)
	finalFloor, present, err := final.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, uint64(2), finalFloor.Sequence)
	require.Equal(t, uint64(3), finalFloor.Revision)
	require.Equal(t, finalized.Floor, finalFloor)
	finalHistory, err := final.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Equal(t, full, finalHistory)
	require.Equal(t, 3, final.schemaVersion)
	require.NoError(t, checkSchema(ctx, final.conn))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, final.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, final.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	assertSchema1OldRowsStillPresent(t, source.rows, readLogicalRows(t, final.conn))
	assert.Equal(t, source.payload, attemptSchemaCompanionPayload(t, final.directory))
	require.NoError(t, final.Close())
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
	options.UpgradeFromAttempts = true
	upgraded, err := OpenWithOptions(directory, f.binding, options)
	if upgraded != nil {
		t.Cleanup(func() { assert.NoError(t, upgraded.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, 3, upgraded.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, upgraded.conn))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, upgraded.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, upgraded.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
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
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, 3, reopened.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, reopened.conn))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, reopened.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, reopened.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
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
	if finalStore != nil {
		t.Cleanup(func() { assert.NoError(t, finalStore.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, 3, finalStore.schemaVersion)
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, finalStore.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, finalStore.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
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
	stages := len(attemptSchemaStatements) + 5
	require.Equal(t, 16, stages)
	for failAt := 1; failAt <= stages; failAt++ {
		t.Run(fmt.Sprintf("fail at %d", failAt), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			t.Cleanup(cancel)
			f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
			directory := filepath.Dir(databasePath)
			source := attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows)
			canary := fmt.Errorf("b7a2 upgrade fault canary %d", failAt)
			recorder := newPublicationOpenRecorder()
			recorder.canary = canary
			expectedReached := make([]int, 0, failAt)
			for stage := 1; stage <= failAt; stage++ {
				expectedReached = append(expectedReached, stage)
			}
			reached := make([]int, 0, failAt)
			commits := 0
			options := DefaultOpenOptions()
			options.UpgradeFromPositions = true
			options.UpgradeFromAttempts = true
			options.openFault = recorder.openFault
			options.upgradeFault = func(stage int) error {
				require.NoError(t, recorder.upgradeFault(stage))
				reached = append(reached, stage)
				if stage == failAt {
					return canary
				}
				return nil
			}
			options.upgradeCommit = func(tx *sql.Tx) error {
				commits++
				return recorder.commit(tx)
			}
			fd0 := publicationOpenFD0(t)
			refused, err := OpenWithOptions(directory, f.binding, options)
			if refused != nil {
				t.Cleanup(func() { assert.NoError(t, refused.Close()) })
			}
			incomingMaterialPublicRollbackRequireFailed(t, refused, err, recorder, expectedReached, canary, directory, fd0)
			require.Zero(t, commits)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
			require.Nil(t, refused)
			require.Equal(t, expectedReached, reached)
			require.NotContains(t, err.Error(), canary.Error())
			require.NotContains(t, fmt.Sprintf("%+v", err), canary.Error())
			require.NotErrorIs(t, err, canary)

			require.Equal(t, source, attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows))

			options.upgradeFault = nil
			options.openFault = nil
			options.upgradeCommit = func(tx *sql.Tx) error {
				commits++
				return tx.Commit()
			}
			commits = 0
			upgraded, err := OpenWithOptions(directory, f.binding, options)
			if upgraded != nil {
				t.Cleanup(func() { assert.NoError(t, upgraded.Close()) })
			}
			require.NoError(t, err)
			require.Equal(t, 1, commits)
			attemptSchemaRequireCurrent3(t, ctx, upgraded, f, source)
			require.NoError(t, upgraded.Close())
		})
	}
}

func TestPublicationStateUpgradeCommitUnknownReadbackRecognizesCommittedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
	directory := filepath.Dir(databasePath)
	source := attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows)
	canary := errors.New("b7a2 upgrade commit canary")
	commits := 0
	options := DefaultOpenOptions()
	options.UpgradeFromPositions = true
	options.UpgradeFromAttempts = true
	options.upgradeCommit = func(tx *sql.Tx) error {
		commits++
		require.NoError(t, tx.Commit())
		return canary
	}
	refused, err := OpenWithOptions(directory, f.binding, options)
	if refused != nil {
		t.Cleanup(func() { assert.NoError(t, refused.Close()) })
	}
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	require.Nil(t, refused)
	require.Equal(t, 1, commits)
	require.NotContains(t, err.Error(), canary.Error())
	require.NotContains(t, fmt.Sprintf("%+v", err), canary.Error())
	require.NotErrorIs(t, err, canary)

	lock, err := platform.LockFile(filepath.Join(directory, "publication.db.lock"))
	if lock != nil {
		t.Cleanup(func() { assert.NoError(t, lock.Close()) })
	}
	require.NoError(t, err)
	require.NoError(t, lock.Close())
	reopened, err := Open(directory, f.binding)
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	attemptSchemaRequireCurrent3(t, ctx, reopened, f, source)
	require.NoError(t, reopened.Close())

	final, err := Open(directory, f.binding)
	if final != nil {
		t.Cleanup(func() { assert.NoError(t, final.Close()) })
	}
	require.NoError(t, err)
	attemptSchemaRequireCurrent3(t, ctx, final, f, source)
	require.NoError(t, final.Close())
}

type attemptSchemaFixtureSnapshot struct {
	rows     map[string]string
	typed    map[string][][]any
	metadata map[string][]byte
	objects  map[string]incomingMaterialUpgradeFixtureObject
	state    stateSnapshot
	history  HistoryPage
	payload  []byte
}

func attemptSchemaFixtureSnapshotV1(t *testing.T, ctx context.Context, f fixture, databasePath string, companionRows map[string]string) attemptSchemaFixtureSnapshot {
	t.Helper()
	conn, closeConn := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	require.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	var appID int
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID))
	require.Equal(t, applicationID, appID)
	rows := readLogicalRows(t, conn)
	require.Equal(t, companionRows, rows)
	typed := incomingMaterialUpgradeV1Rows(t, ctx, conn)
	require.Len(t, typed, 6)
	require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(typed))
	require.Len(t, typed["store_meta"], 5)
	require.Len(t, typed["cache_records"], 3)
	require.Len(t, typed["cache_observations"], 1)
	require.Len(t, typed["accepted_records"], 2)
	require.Len(t, typed["accepted_events"], 2)
	require.Len(t, typed["active_floor"], 1)
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
	require.Len(t, metadata, 5)
	source, err := readIncomingMaterialUpgradeSource(ctx, conn, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
	require.NoError(t, err)
	require.Equal(t, 1, source.version)
	require.Equal(t, f.binding, source.binding)
	require.Equal(t, DefaultLimits(), source.limits)
	require.Equal(t, DefaultAttemptLimits(), source.attemptLimits)
	require.Equal(t, metadata, source.metadata)
	state, err := readStateForUpgrade(ctx, conn, f.binding, DefaultLimits())
	require.NoError(t, err)
	require.NotNil(t, state.floor)
	require.Equal(t, uint64(1), state.floor.Sequence)
	require.Equal(t, uint64(2), state.floor.Revision)
	require.Equal(t, uint64(1), state.floor.Generation)
	require.Equal(t, uint64(2), state.revision)
	require.Equal(t, uint64(1), state.generation)
	require.Equal(t, metadata["database_id"], state.floor.DatabaseID[:])
	require.Equal(t, uint64Bytes(2), metadata["revision"])
	require.Equal(t, uint64Bytes(1), metadata["generation"])
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, conn)
	counts := incomingMaterialUpgradeFixtureObjectCounts(t, objects)
	require.Equal(t, 6, counts.tables)
	require.Equal(t, 0, counts.namedIndexes)
	require.Equal(t, 4, counts.autoIndexes)
	require.Len(t, objects, 10)
	for name := range objects {
		require.NotContains(t, name, "attempt")
	}
	require.NotContains(t, objects, "accepted_material_refs")
	payload := attemptSchemaCompanionPayload(t, filepath.Dir(databasePath))
	require.Equal(t, f.payload, payload)
	payloadCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	reference := publication.BlobReference{CID: payloadCID, Size: uint64(len(payload))}
	require.NoError(t, publication.VerifyPayload(payload, reference))
	decoded, err := publication.DecodePayload(payload, reference)
	require.NoError(t, err)
	require.NotEmpty(t, decoded.Entries)
	view := &Store{binding: f.binding, limits: DefaultLimits(), databaseID: state.floor.DatabaseID, schemaVersion: 1, rootFD: -1, payloadFD: -1, conn: conn}
	history, err := view.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, history.Events, 2)
	require.Len(t, history.Records, 2)
	require.False(t, history.HasMore)
	require.Equal(t, uint64(2), history.NextRevision)
	require.Equal(t, uint64(1), history.Events[0].Revision)
	require.Equal(t, uint64(2), history.Events[1].Revision)
	require.Equal(t, uint64(1), history.Events[1].NewFloor.Sequence)
	accepted := make(map[string][]any, len(typed["accepted_records"]))
	for _, row := range typed["accepted_records"] {
		require.Len(t, row, 5)
		cid, ok := row[0].([]byte)
		require.True(t, ok)
		accepted[string(cid)] = row
	}
	for _, evidence := range history.Records {
		row, present := accepted[string(evidence.Reference.CID)]
		require.True(t, present)
		require.Equal(t, row[3], evidence.Raw)
		sequence, ok := row[2].(int64)
		require.True(t, ok)
		require.Equal(t, uint64(sequence), evidence.Reference.Sequence)
	}
	closeConn(t)
	return attemptSchemaFixtureSnapshot{rows: rows, typed: typed, metadata: metadata, objects: objects, state: state, history: history, payload: payload}
}

func attemptSchemaCompanionPayload(t *testing.T, directory string) []byte {
	t.Helper()
	name := "schema1-baseline-payload.bin"
	state := incomingMaterialUpgradeFixturePayloadState(t, filepath.Join(directory, name))
	require.Equal(t, incomingMaterialUpgradeFixtureHashes[name], state.sha256, name)
	require.Equal(t, incomingMaterialUpgradeFixtureSizes[name], state.size, name)
	require.NotEmpty(t, state.bytes)
	return state.bytes
}

func attemptSchemaRequireCurrent3(t *testing.T, ctx context.Context, store *Store, f fixture, source attemptSchemaFixtureSnapshot) {
	t.Helper()
	require.NotNil(t, store)
	require.False(t, store.closed)
	require.Equal(t, 3, store.schemaVersion)
	require.Equal(t, f.binding, store.binding)
	require.Equal(t, DefaultLimits(), store.limits)
	require.Equal(t, DefaultAttemptLimits(), store.attemptLimits)
	require.NoError(t, checkSchema(ctx, store.conn))
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
	var appID int
	require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID))
	require.Equal(t, applicationID, appID)
	destination := incomingMaterialUpgradeSource{version: 1, binding: f.binding, limits: DefaultLimits(), attemptLimits: DefaultAttemptLimits(), metadata: source.metadata}
	require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, store.conn, destination))
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
	require.Len(t, metadata, 7)
	for key, value := range source.metadata {
		require.Equal(t, value, metadata[key], key)
	}
	wanted, err := encodeAttemptLimits(DefaultAttemptLimits())
	require.NoError(t, err)
	require.Equal(t, wanted, metadata["attempt_limits"])
	require.Equal(t, uint64Bytes(0), metadata["attempt_mutation_revision"])
	require.Equal(t, source.metadata["database_id"], store.databaseID[:])
	rows := readLogicalRows(t, store.conn)
	assertSchema1PositionRowsUnchanged(t, source.rows, rows)
	assertSchema1OldMetadataUnchanged(t, source.rows, rows)
	typed := incomingMaterialUpgradeV1Rows(t, ctx, store.conn)
	require.Len(t, typed, 6)
	require.Len(t, typed["store_meta"], 7)
	for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
		require.Equal(t, source.typed[table], typed[table], table)
	}
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, uint64(1), floor.Sequence)
	require.Equal(t, uint64(2), floor.Revision)
	require.Equal(t, uint64(1), floor.Generation)
	require.Equal(t, *source.state.floor, floor)
	require.Equal(t, uint64(0), store.attemptMutationRevision)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Equal(t, uint64(2), history.NextRevision)
	require.Equal(t, source.history, history)
	for _, table := range incomingMaterialUpgradeFixtureAttemptTables {
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM "+table), table)
	}
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	namedObjects, definitions, err := readSchemaObjects(ctx, store.conn)
	require.NoError(t, err)
	require.Equal(t, expectedSchemaV3Objects(), namedObjects)
	inventory, err := schemaInventoryForVersion(3)
	require.NoError(t, err)
	require.Len(t, inventory.statements, 18)
	for _, statement := range inventory.statements {
		require.Equal(t, statement, strings.TrimSpace(definitions[statementTableName(statement)]))
	}
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, store.conn)
	objectCounts := incomingMaterialUpgradeFixtureObjectCounts(t, objects)
	require.Equal(t, 16, objectCounts.tables)
	require.Equal(t, 2, objectCounts.namedIndexes)
	require.Equal(t, 14, objectCounts.autoIndexes)
	require.Len(t, objects, 32)
	additions, autoIndexAdditions := incomingMaterialUpgradeFixtureObjectAdditions(t, source.objects, objects)
	expectedAdditions := append([]string{"accepted_material_refs"}, incomingMaterialUpgradeFixtureAttemptTables...)
	expectedAdditions = append(expectedAdditions, incomingMaterialUpgradeFixtureAttemptIndexes...)
	sort.Strings(expectedAdditions)
	require.Equal(t, expectedAdditions, additions)
	require.Equal(t, 10, autoIndexAdditions)
	for _, statement := range attemptSchemaStatements {
		require.Equal(t, statement, objects[statementTableName(statement)].sql, statementTableName(statement))
	}
	require.Equal(t, incomingMaterialSchemaStatement, objects["accepted_material_refs"].sql)
	require.Equal(t, -1, store.payloadFD)
	_, err = os.Lstat(filepath.Join(store.directory, payloadDirectoryName))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Equal(t, source.payload, attemptSchemaCompanionPayload(t, store.directory))
}
