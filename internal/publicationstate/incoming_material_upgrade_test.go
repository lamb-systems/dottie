package publicationstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

var incomingMaterialUpgradeFixtureHashes = map[string]string{
	"schema1-baseline.db":          "f628f1905531fa7036497ee6a986eb7cce53affd43158452e32c342d5861363f",
	"schema1-baseline-rows.json":   "d295459410ab996ca597027699d5e9f6e146ae107524744e717a017ca81814d9",
	"schema1-baseline-payload.bin": "fbb1e20533b38f9977557cc443c6dba1785ba09a52dc401f57f371a67e302744",
}

var incomingMaterialUpgradeFixtureNames = []string{
	"schema1-baseline.db",
	"schema1-baseline-rows.json",
	"schema1-baseline-payload.bin",
}

var incomingMaterialUpgradeFixtureSizes = map[string]int64{
	"schema1-baseline.db":          49152,
	"schema1-baseline-rows.json":   16685,
	"schema1-baseline-payload.bin": 3072,
}

var incomingMaterialUpgradeCopyNames = map[string]string{
	"schema1-baseline.db":          "publication.db",
	"schema1-baseline-rows.json":   "schema1-baseline-rows.json",
	"schema1-baseline-payload.bin": "schema1-baseline-payload.bin",
}

func TestIncomingMaterialUpgradeSourceValidation(t *testing.T) {
	t.Run("genuine positions v1", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
		db, err := sql.Open("sqlite", dbDSN(databasePath, true))
		require.NoError(t, err)
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		t.Cleanup(func() { assert.NoError(t, db.Close()) })
		conn, err := db.Conn(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, conn.Close()) })
		var version int
		require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
		require.Equal(t, 1, version)
		require.Equal(t, companionRows, readLogicalRows(t, conn))
		stored := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
		require.Len(t, stored, 5)

		recorder := &incomingMaterialUpgradeRecorder{source: conn}
		snapshot, err := readIncomingMaterialUpgradeSource(ctx, recorder, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		assert.Equal(t, 1, snapshot.version)
		assert.Equal(t, f.binding, snapshot.binding)
		assert.Equal(t, DefaultLimits(), snapshot.limits)
		assert.Equal(t, DefaultAttemptLimits(), snapshot.attemptLimits)
		require.Equal(t, stored, snapshot.metadata)
		assert.Equal(t, uint64Bytes(2), snapshot.metadata["revision"])
		assert.Equal(t, uint64Bytes(1), snapshot.metadata["generation"])
		expectedDatabaseID, err := base64.StdEncoding.DecodeString(schema1Metadata(t, companionRows["store_meta"])["database_id"])
		require.NoError(t, err)
		assert.Equal(t, expectedDatabaseID, snapshot.metadata["database_id"])
		for _, identity := range recorder.identities() {
			assert.NotContains(t, strings.ToLower(identity), "attempt")
			require.NotContains(t, strings.ToLower(identity), "accepted_material_refs")
		}

		refused, err := readIncomingMaterialUpgradeSource(ctx, conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)

		tx, err := conn.BeginTx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				assert.NoError(t, err)
			}
		})
		transactionSnapshot, err := readIncomingMaterialUpgradeSource(ctx, tx, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		assert.Equal(t, snapshot.metadata, transactionSnapshot.metadata)
		assert.Equal(t, snapshot.binding, transactionSnapshot.binding)
		require.NoError(t, tx.Rollback())
		require.Equal(t, companionRows, readLogicalRows(t, conn))
	})

	t.Run("empty source two unit store", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newSchema2UnitStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		require.Equal(t, 2, store.schemaVersion)
		beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		beforeState, err := store.readState(ctx, store.conn, StageOpen)
		require.NoError(t, err)
		stored := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, stored, 7)

		recorder := &incomingMaterialUpgradeRecorder{source: store.conn}
		snapshot, err := readIncomingMaterialUpgradeSource(ctx, recorder, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		assert.Equal(t, 2, snapshot.version)
		require.Equal(t, stored, snapshot.metadata)
		assert.Equal(t, uint64Bytes(0), snapshot.metadata["revision"])
		assert.Equal(t, uint64Bytes(0), snapshot.metadata["generation"])
		assert.Equal(t, uint64Bytes(0), snapshot.metadata["attempt_mutation_revision"])
		assert.Equal(t, store.databaseID[:], snapshot.metadata["database_id"])
		var incomingRefs int64
		require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE name='accepted_material_refs'").Scan(&incomingRefs))
		assert.Zero(t, incomingRefs)
		recorder.requireQueryContaining(t, "FROM publication_attempts")
		recorder.requireQueryContaining(t, "FROM accepted_events")
		recorder.requireQueryContaining(t, "FROM accepted_records")
		for _, identity := range recorder.identities() {
			require.NotContains(t, strings.ToLower(identity), "accepted_material_refs")
		}

		afterRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		assert.Equal(t, beforeRows, afterRows)
		afterState, err := store.readState(ctx, store.conn, StageOpen)
		require.NoError(t, err)
		assert.Equal(t, beforeState, afterState)
		assert.Equal(t, uint64(0), store.attemptMutationRevision)
		assert.Equal(t, stored, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
	})

	t.Run("populated source two unit store", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		f.appendRecord(t, 1)
		store, _ := newSchema2UnitStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		genesis, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
		require.Equal(t, uint64(1), finalized.Floor.Revision)
		require.Equal(t, genesis.ID, finalized.Attempt.ID)
		predecessorView := attemptView(f, f.observation(1), false)
		successorCandidate := attemptCandidate(f, 1)
		successorReview := attemptReview()
		proposal, err := store.PrepareAttempt(ctx, successorCandidate, predecessorView, successorReview)
		require.NoError(t, err)
		successor, err := store.CreateAttempt(ctx, proposal.StateToken, successorCandidate, predecessorView, successorReview, proposal.Confirmation)
		require.NoError(t, err)
		require.Equal(t, AttemptPrepared, successor.Lifecycle)
		require.Equal(t, int64(2), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM publication_attempts"))
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM active_publication_attempt"))
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications"))
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_payload_refs"))
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_reservations"))
		require.GreaterOrEqual(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_events"), int64(2))
		require.GreaterOrEqual(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_evidence"), int64(1))
		require.GreaterOrEqual(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"), int64(1))

		beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		beforeState, err := store.readState(ctx, store.conn, StageOpen)
		require.NoError(t, err)
		beforeMutation := store.attemptMutationRevision
		stored := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)

		tx, err := store.conn.BeginTx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				assert.NoError(t, err)
			}
		})
		recorder := &incomingMaterialUpgradeRecorder{source: tx}
		snapshot, err := readIncomingMaterialUpgradeSource(ctx, recorder, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		directSnapshot, err := readIncomingMaterialUpgradeSource(ctx, tx, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		assert.Equal(t, snapshot, directSnapshot)
		require.Equal(t, stored, snapshot.metadata)
		for _, fragment := range []string{
			"FROM publication_attempts",
			"FROM attempt_events",
			"FROM attempt_evidence",
			"FROM attempt_payload_refs",
			"FROM attempt_reservations",
			"FROM retained_publications",
			"FROM payload_objects",
			"FROM accepted_events",
			"FROM accepted_records",
		} {
			recorder.requireQueryContaining(t, fragment)
		}
		recorder.requireQueryArgument(t, "FROM publication_attempts WHERE attempt_id=?", genesis.ID[:])
		recorder.requireQueryArgument(t, "FROM publication_attempts WHERE attempt_id=?", successor.ID[:])
		for _, identity := range recorder.identities() {
			require.NotContains(t, strings.ToLower(identity), "accepted_material_refs")
		}
		recorder.requireQueryArgument(t, "FROM attempt_payload_refs WHERE attempt_id=?", successor.ID[:])
		require.NoError(t, tx.Rollback())

		afterRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		assert.Equal(t, beforeRows, afterRows)
		afterState, err := store.readState(ctx, store.conn, StageOpen)
		require.NoError(t, err)
		assert.Equal(t, beforeState, afterState)
		assert.Equal(t, beforeMutation, store.attemptMutationRevision)
		assert.Equal(t, stored, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
	})

	t.Run("shape and context refusals", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newSchema2UnitStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		var nilContext context.Context
		refused, err := readIncomingMaterialUpgradeSource(nilContext, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonContext)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
		canceledContext, cancelRun := context.WithCancel(ctx)
		cancelRun()
		refused, err = readIncomingMaterialUpgradeSource(canceledContext, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.ErrorIs(t, err, context.Canceled)
		requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCanceled)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
		expiredContext, expire := context.WithDeadline(ctx, time.Now().Add(-time.Second))
		defer expire()
		refused, err = readIncomingMaterialUpgradeSource(expiredContext, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.ErrorIs(t, err, context.DeadlineExceeded)
		requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCanceled)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)

		for _, version := range []int{0, 3} {
			refused, err = readIncomingMaterialUpgradeSource(ctx, store.conn, version, f.binding, DefaultLimits(), DefaultAttemptLimits())
			requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
			assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
		}
		refused, err = readIncomingMaterialUpgradeSource(ctx, store.conn, 2, Binding{}, DefaultLimits(), DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
		refused, err = readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, Limits{}, DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonLimits)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
		refused, err = readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), AttemptLimits{})
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonLimits)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)

		refusals := []struct {
			name       string
			statements []string
		}{
			{name: "application id", statements: []string{"PRAGMA application_id=0"}},
			{name: "future user version", statements: []string{"PRAGMA user_version=4"}},
			{name: "extra named object", statements: []string{"CREATE INDEX incoming_material_upgrade_probe ON store_meta(key)"}},
			{name: "missing named index", statements: []string{"DROP INDEX payload_objects_basename"}},
			{name: "extra metadata key", statements: []string{"INSERT INTO store_meta(key,value) VALUES('incoming_material_upgrade_probe',x'00')"}},
		}
		for _, refusal := range refusals {
			t.Run(refusal.name, func(t *testing.T) {
				tx := incomingMaterialUpgradeTransaction(t, ctx, store)
				for _, statement := range refusal.statements {
					_, err := tx.ExecContext(ctx, statement)
					require.NoError(t, err)
				}
				refused, err := readIncomingMaterialUpgradeSource(ctx, tx, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
				requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
				assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
				require.NoError(t, tx.Rollback())
			})
		}

		foreignPath := filepath.Join(t.TempDir(), "foreign.db")
		foreignDB, err := sql.Open("sqlite", dbDSN(foreignPath, false))
		require.NoError(t, err)
		foreignDB.SetMaxOpenConns(1)
		foreignDB.SetMaxIdleConns(1)
		t.Cleanup(func() { assert.NoError(t, foreignDB.Close()) })
		foreignConn, err := foreignDB.Conn(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, foreignConn.Close()) })
		_, err = foreignConn.ExecContext(ctx, "CREATE TABLE foreign_probe(id INTEGER PRIMARY KEY)")
		require.NoError(t, err)
		refused, err = readIncomingMaterialUpgradeSource(ctx, foreignConn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
	})

	t.Run("binding and limit mismatch", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		loweredAttemptLimits := DefaultAttemptLimits()
		loweredAttemptLimits.HistoricalAttempts = 1000
		store, _ := newSchema2UnitStoreWithLimits(t, f, DefaultLimits(), loweredAttemptLimits)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		other := newFixture(t, BackendSpaces)
		other.appendRecord(t, 0)
		refused, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, other.binding, DefaultLimits(), loweredAttemptLimits)
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)

		loweredLimits := DefaultLimits()
		loweredLimits.MaxLineageLinks = loweredLimits.MaxLineageLinks - 1
		require.NoError(t, validateLimits(loweredLimits))
		refused, err = readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, loweredLimits, loweredAttemptLimits)
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonLimits)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)

		refused, err = readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonLimits)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)

		snapshot, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), loweredAttemptLimits)
		require.NoError(t, err)
		require.Len(t, snapshot.metadata, 7)
		detached := incomingMaterialUpgradeCloneSource(snapshot)
		snapshot.metadata["binding"][0] ^= 0xff
		snapshot.metadata["database_id"][0] ^= 0xff
		snapshot.metadata["revision"] = []byte{0}
		delete(snapshot.metadata, "generation")
		second, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), loweredAttemptLimits)
		require.NoError(t, err)
		require.Len(t, second.metadata, 7)
		assert.Equal(t, detached, second)
		assert.NotEqual(t, detached, snapshot)
		storedAfter := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, storedAfter, 7)
		assert.Equal(t, detached.metadata["binding"], storedAfter["binding"])
		assert.Equal(t, detached.metadata["database_id"], storedAfter["database_id"])
		assert.Equal(t, detached.metadata["revision"], storedAfter["revision"])
		assert.Equal(t, detached.metadata["generation"], storedAfter["generation"])
	})

	t.Run("stored metadata corruption", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newSchema2UnitStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		stored := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, stored, 7)
		bindingSpaced := incomingMaterialUpgradeSpaceAfterFirstColon(t, stored["binding"])
		limitsSpaced := incomingMaterialUpgradeSpaceAfterFirstColon(t, stored["limits"])
		attemptLimitsSpaced := incomingMaterialUpgradeSpaceAfterFirstColon(t, stored["attempt_limits"])
		var canonicalBinding, spacedBinding bindingWire
		require.NoError(t, json.Unmarshal(stored["binding"], &canonicalBinding))
		require.NoError(t, json.Unmarshal(bindingSpaced, &spacedBinding))
		require.Equal(t, canonicalBinding, spacedBinding)
		require.NotEqual(t, stored["binding"], bindingSpaced)
		var canonicalLimits, spacedLimits limitsWire
		require.NoError(t, json.Unmarshal(stored["limits"], &canonicalLimits))
		require.NoError(t, json.Unmarshal(limitsSpaced, &spacedLimits))
		require.Equal(t, canonicalLimits, spacedLimits)
		require.NotEqual(t, stored["limits"], limitsSpaced)
		var canonicalAttemptLimits, spacedAttemptLimits attemptLimitsWire
		require.NoError(t, json.Unmarshal(stored["attempt_limits"], &canonicalAttemptLimits))
		require.NoError(t, json.Unmarshal(attemptLimitsSpaced, &spacedAttemptLimits))
		require.Equal(t, canonicalAttemptLimits, spacedAttemptLimits)
		require.NotEqual(t, stored["attempt_limits"], attemptLimitsSpaced)
		overflow := make([]byte, 8)
		binary.BigEndian.PutUint64(overflow, 1<<63)

		corruptions := []struct {
			name       string
			key        string
			statement  string
			args       []any
			wantType   string
			wantLength int64
			wantClass  error
			wantReason Reason
		}{
			{name: "database id short", key: "database_id", statement: "UPDATE store_meta SET value=? WHERE key='database_id'", args: []any{make([]byte, 31)}, wantType: "blob", wantLength: 31, wantClass: ErrSchema, wantReason: ReasonCorrupt},
			{name: "database id zero", key: "database_id", statement: "UPDATE store_meta SET value=? WHERE key='database_id'", args: []any{make([]byte, 32)}, wantType: "blob", wantLength: 32, wantClass: ErrSchema, wantReason: ReasonCorrupt},
			{name: "database id text", key: "database_id", statement: "UPDATE store_meta SET value='not-a-database-id' WHERE key='database_id'", wantType: "text", wantLength: int64(len("not-a-database-id")), wantClass: ErrSchema, wantReason: ReasonCorrupt},
			{name: "revision too long", key: "revision", statement: "UPDATE store_meta SET value=? WHERE key='revision'", args: []any{make([]byte, 9)}, wantType: "blob", wantLength: 9, wantClass: ErrSchema, wantReason: ReasonCorrupt},
			{name: "revision above max sequence", key: "revision", statement: "UPDATE store_meta SET value=? WHERE key='revision'", args: []any{uint64Bytes(publication.MaxSequence + 1)}, wantType: "blob", wantLength: 8, wantClass: ErrSchema, wantReason: ReasonCorrupt},
			{name: "generation text", key: "generation", statement: "UPDATE store_meta SET value='generation' WHERE key='generation'", wantType: "text", wantLength: int64(len("generation")), wantClass: ErrSchema, wantReason: ReasonCorrupt},
			{name: "mutation overflow", key: "attempt_mutation_revision", statement: "UPDATE store_meta SET value=? WHERE key='attempt_mutation_revision'", args: []any{overflow}, wantType: "blob", wantLength: 8, wantClass: ErrSchema, wantReason: ReasonCorrupt},
			{name: "noncanonical binding", key: "binding", statement: "UPDATE store_meta SET value=? WHERE key='binding'", args: []any{bindingSpaced}, wantType: "blob", wantLength: int64(len(bindingSpaced)), wantClass: ErrInvalid, wantReason: ReasonBinding},
			{name: "noncanonical position limits", key: "limits", statement: "UPDATE store_meta SET value=? WHERE key='limits'", args: []any{limitsSpaced}, wantType: "blob", wantLength: int64(len(limitsSpaced)), wantClass: ErrInvalid, wantReason: ReasonLimits},
			{name: "noncanonical attempt limits", key: "attempt_limits", statement: "UPDATE store_meta SET value=? WHERE key='attempt_limits'", args: []any{attemptLimitsSpaced}, wantType: "blob", wantLength: int64(len(attemptLimitsSpaced)), wantClass: ErrInvalid, wantReason: ReasonLimits},
		}
		for _, corruption := range corruptions {
			t.Run(corruption.name, func(t *testing.T) {
				tx := incomingMaterialUpgradeTransaction(t, ctx, store)
				_, err := tx.ExecContext(ctx, corruption.statement, corruption.args...)
				require.NoError(t, err)
				incomingMaterialUpgradeRequireStoredShape(t, ctx, tx, corruption.key, corruption.wantType, corruption.wantLength)
				refused, err := readIncomingMaterialUpgradeSource(ctx, tx, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
				requireErrorMetadata(t, err, corruption.wantClass, StageOpen, corruption.wantReason)
				assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
				require.NoError(t, tx.Rollback())
			})
		}
		_, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		assert.Equal(t, stored, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
	})

	t.Run("uncommitted source changes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		f.appendRecord(t, 1)
		store, _ := newSchema2UnitStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		genesis, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
		require.Equal(t, uint64(1), finalized.Floor.Revision)
		require.Equal(t, genesis.ID, finalized.Attempt.ID)
		predecessorView := attemptView(f, f.observation(1), false)
		successorCandidate := attemptCandidate(f, 1)
		successorReview := attemptReview()
		proposal, err := store.PrepareAttempt(ctx, successorCandidate, predecessorView, successorReview)
		require.NoError(t, err)
		successor, err := store.CreateAttempt(ctx, proposal.StateToken, successorCandidate, predecessorView, successorReview, proposal.Confirmation)
		require.NoError(t, err)
		require.Equal(t, AttemptPrepared, successor.Lifecycle)
		require.Positive(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))

		eventTx := incomingMaterialUpgradeTransaction(t, ctx, store)
		_, err = readIncomingMaterialUpgradeSource(ctx, eventTx, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		_, err = eventTx.ExecContext(ctx, "UPDATE accepted_events SET digest=zeroblob(32) WHERE revision=1")
		require.NoError(t, err)
		var digestType string
		var digestLength int64
		require.NoError(t, eventTx.QueryRowContext(ctx, "SELECT typeof(digest),length(CAST(digest AS BLOB)) FROM accepted_events WHERE revision=1").Scan(&digestType, &digestLength))
		require.Equal(t, "blob", digestType)
		require.Equal(t, int64(32), digestLength)
		refused, err := readIncomingMaterialUpgradeSource(ctx, eventTx, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
		require.NoError(t, eventTx.Rollback())

		attemptTx := incomingMaterialUpgradeTransaction(t, ctx, store)
		_, err = readIncomingMaterialUpgradeSource(ctx, attemptTx, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		_, err = attemptTx.ExecContext(ctx, "UPDATE publication_attempts SET state_digest=zeroblob(32) WHERE attempt_id=?", successor.ID[:])
		require.NoError(t, err)
		require.NoError(t, attemptTx.QueryRowContext(ctx, "SELECT typeof(state_digest),length(CAST(state_digest AS BLOB)) FROM publication_attempts WHERE attempt_id=?", successor.ID[:]).Scan(&digestType, &digestLength))
		require.Equal(t, "blob", digestType)
		require.Equal(t, int64(32), digestLength)
		refused, err = readIncomingMaterialUpgradeSource(ctx, attemptTx, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		assert.Equal(t, incomingMaterialUpgradeSource{}, refused)
		require.NoError(t, attemptTx.Rollback())

		_, err = readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
	})
}

func incomingMaterialUpgradeCopyV1(t *testing.T) (fixture, string, map[string]string) {
	t.Helper()
	source := filepath.Join("testdata", "positions-v1")
	original := make(map[string][]byte, len(incomingMaterialUpgradeFixtureNames))
	available := make(map[string]bool, len(incomingMaterialUpgradeFixtureNames))
	t.Cleanup(func() {
		for _, name := range incomingMaterialUpgradeFixtureNames {
			data, err := os.ReadFile(filepath.Join(source, name))
			if !assert.NoError(t, err, name) {
				continue
			}
			digest := sha256.Sum256(data)
			assert.Equal(t, incomingMaterialUpgradeFixtureHashes[name], hex.EncodeToString(digest[:]), name)
			if available[name] {
				assert.Equal(t, original[name], data, name)
			}
		}
	})
	for _, name := range incomingMaterialUpgradeFixtureNames {
		data := incomingMaterialUpgradeReadPinned(t, filepath.Join(source, name), incomingMaterialUpgradeFixtureSizes[name])
		digest := sha256.Sum256(data)
		require.Equal(t, incomingMaterialUpgradeFixtureHashes[name], hex.EncodeToString(digest[:]), name)
		original[name] = data
		available[name] = true
	}

	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	var directoryStat unix.Stat_t
	require.NoError(t, unix.Lstat(directory, &directoryStat))
	require.Equal(t, uint32(unix.S_IFDIR), directoryStat.Mode&unix.S_IFMT)
	require.Equal(t, uint32(0o700), directoryStat.Mode&0o777)
	require.Equal(t, uint32(os.Getuid()), directoryStat.Uid)

	for _, name := range incomingMaterialUpgradeFixtureNames {
		incomingMaterialUpgradeWriteExclusive(t, filepath.Join(directory, incomingMaterialUpgradeCopyNames[name]), original[name])
	}
	for _, name := range incomingMaterialUpgradeFixtureNames {
		copied := filepath.Join(directory, incomingMaterialUpgradeCopyNames[name])
		var copiedStat unix.Stat_t
		require.NoError(t, unix.Lstat(copied, &copiedStat))
		require.Equal(t, uint32(unix.S_IFREG), copiedStat.Mode&unix.S_IFMT)
		require.Equal(t, uint32(0o600), copiedStat.Mode&0o777)
		require.Equal(t, uint32(os.Getuid()), copiedStat.Uid)
		require.Equal(t, uint64(1), copiedStat.Nlink)
		require.Equal(t, incomingMaterialUpgradeFixtureSizes[name], copiedStat.Size)
		copiedBytes, err := os.ReadFile(copied)
		require.NoError(t, err)
		digest := sha256.Sum256(copiedBytes)
		require.Equal(t, incomingMaterialUpgradeFixtureHashes[name], hex.EncodeToString(digest[:]), name)
		require.Equal(t, original[name], copiedBytes, name)
	}

	companionBytes, err := os.ReadFile(filepath.Join(directory, "schema1-baseline-rows.json"))
	require.NoError(t, err)
	var companionRows map[string]string
	require.NoError(t, json.Unmarshal(companionBytes, &companionRows))
	require.Len(t, companionRows, 6)

	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	require.Equal(t, original["schema1-baseline-payload.bin"], f.payload)
	return f, filepath.Join(directory, "publication.db"), companionRows
}

func incomingMaterialUpgradeReadPinned(t *testing.T, path string, size int64) []byte {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	closed := false
	defer func() {
		if !closed {
			assert.NoError(t, unix.Close(fd))
		}
	}()
	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(fd, &stat))
	require.Equal(t, uint32(unix.S_IFREG), stat.Mode&unix.S_IFMT)
	require.Equal(t, uint64(1), stat.Nlink)
	require.Equal(t, size, stat.Size)
	data := make([]byte, size)
	offset := 0
	for offset < len(data) {
		count, readErr := unix.Read(fd, data[offset:])
		require.NoError(t, readErr)
		require.Positive(t, count)
		offset += count
	}
	require.NoError(t, unix.Close(fd))
	closed = true
	return data
}

func incomingMaterialUpgradeWriteExclusive(t *testing.T, path string, data []byte) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	require.NoError(t, err)
	closed := false
	defer func() {
		if !closed {
			assert.NoError(t, unix.Close(fd))
		}
	}()
	remaining := data
	for len(remaining) > 0 {
		count, writeErr := unix.Write(fd, remaining)
		require.NoError(t, writeErr)
		require.Positive(t, count)
		remaining = remaining[count:]
	}
	require.NoError(t, unix.Fsync(fd))
	require.NoError(t, unix.Close(fd))
	closed = true
}

type incomingMaterialUpgradeRecordedQuery struct {
	query string
	args  []any
}

type incomingMaterialUpgradeRecorder struct {
	source  queryer
	queries []incomingMaterialUpgradeRecordedQuery
}

func (r *incomingMaterialUpgradeRecorder) record(query string, args []any) {
	cloned := make([]any, len(args))
	for index, arg := range args {
		if data, ok := arg.([]byte); ok {
			cloned[index] = bytes.Clone(data)
			continue
		}
		cloned[index] = arg
	}
	r.queries = append(r.queries, incomingMaterialUpgradeRecordedQuery{query: query, args: cloned})
}

func (r *incomingMaterialUpgradeRecorder) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	r.record(query, args)
	return r.source.QueryContext(ctx, query, args...)
}

func (r *incomingMaterialUpgradeRecorder) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	r.record(query, args)
	return r.source.QueryRowContext(ctx, query, args...)
}

func (r *incomingMaterialUpgradeRecorder) identities() []string {
	seen := make(map[string]struct{}, len(r.queries))
	identities := make([]string, 0, len(r.queries))
	for _, recorded := range r.queries {
		if _, present := seen[recorded.query]; present {
			continue
		}
		seen[recorded.query] = struct{}{}
		identities = append(identities, recorded.query)
	}
	return identities
}

func (r *incomingMaterialUpgradeRecorder) requireQueryContaining(t *testing.T, fragment string) {
	t.Helper()
	for _, identity := range r.identities() {
		if strings.Contains(identity, fragment) {
			return
		}
	}
	require.FailNowf(t, "missing routed query", "%q not observed in %v", fragment, r.identities())
}

func (r *incomingMaterialUpgradeRecorder) requireQueryArgument(t *testing.T, fragment string, wanted []byte) {
	t.Helper()
	for _, recorded := range r.queries {
		if !strings.Contains(recorded.query, fragment) {
			continue
		}
		for _, arg := range recorded.args {
			if data, ok := arg.([]byte); ok && bytes.Equal(data, wanted) {
				return
			}
		}
	}
	require.FailNowf(t, "missing routed argument", "%x not observed for %q", wanted, fragment)
}

func incomingMaterialUpgradeCloneSource(source incomingMaterialUpgradeSource) incomingMaterialUpgradeSource {
	cloned := incomingMaterialUpgradeSource{version: source.version, binding: source.binding, limits: source.limits, attemptLimits: source.attemptLimits, metadata: make(map[string][]byte, len(source.metadata))}
	for key, value := range source.metadata {
		cloned.metadata[key] = bytes.Clone(value)
	}
	return cloned
}

func incomingMaterialUpgradeStoredMetadata(t *testing.T, ctx context.Context, q queryer) map[string][]byte {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT key,value FROM store_meta ORDER BY key")
	require.NoError(t, err)
	keys := make([]string, 0, 7)
	values := make([][]byte, 0, 7)
	var scanErr error
	for rows.Next() {
		var key string
		var value []byte
		if scanErr = rows.Scan(&key, &value); scanErr != nil {
			break
		}
		keys = append(keys, key)
		values = append(values, bytes.Clone(value))
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, rowsErr)
	require.NoError(t, closeErr)
	metadata := make(map[string][]byte, len(keys))
	for index, key := range keys {
		metadata[key] = values[index]
	}
	return metadata
}

func incomingMaterialUpgradeTransaction(t *testing.T, ctx context.Context, store *Store) *sql.Tx {
	t.Helper()
	tx, err := store.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			assert.NoError(t, err)
		}
	})
	return tx
}

func incomingMaterialUpgradeCount(t *testing.T, ctx context.Context, q queryer, query string, args ...any) int64 {
	t.Helper()
	value, err := queryInt64(ctx, q, query, args...)
	require.NoError(t, err)
	return value
}

func incomingMaterialUpgradeRequireStoredShape(t *testing.T, ctx context.Context, q queryer, key, wantType string, wantLength int64) {
	t.Helper()
	var storedType string
	var storedLength int64
	require.NoError(t, q.QueryRowContext(ctx, "SELECT typeof(value),length(CAST(value AS BLOB)) FROM store_meta WHERE key=?", key).Scan(&storedType, &storedLength))
	require.Equal(t, wantType, storedType)
	require.Equal(t, wantLength, storedLength)
}

func incomingMaterialUpgradeSpaceAfterFirstColon(t *testing.T, canonical []byte) []byte {
	t.Helper()
	index := bytes.IndexByte(canonical, ':')
	require.Greater(t, index, 0)
	spaced := make([]byte, 0, len(canonical)+1)
	spaced = append(spaced, canonical[:index+1]...)
	spaced = append(spaced, ' ')
	spaced = append(spaced, canonical[index+1:]...)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(spaced, &decoded))
	return spaced
}

func incomingMaterialUpgradeCopiedSource(t *testing.T, ctx context.Context) (fixture, *sql.Conn, map[string]string) {
	t.Helper()
	f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
	db, err := sql.Open("sqlite", dbDSN(databasePath, false))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { assert.NoError(t, db.Close()) })
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	require.NoError(t, configureConnection(ctx, conn))
	return f, conn, companionRows
}

func incomingMaterialUpgradeTx(t *testing.T, ctx context.Context, conn *sql.Conn) *sql.Tx {
	t.Helper()
	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			assert.NoError(t, err)
		}
	})
	return tx
}

func incomingMaterialUpgradeV1Rows(t *testing.T, ctx context.Context, q queryer) map[string][][]any {
	t.Helper()
	tables := []struct {
		name    string
		orderBy string
	}{
		{"store_meta", "key"},
		{"cache_records", "cid"},
		{"cache_observations", "observation_id"},
		{"accepted_records", "cid"},
		{"accepted_events", "revision"},
		{"active_floor", "singleton"},
	}
	result := make(map[string][][]any, len(tables))
	for _, table := range tables {
		rows, err := q.QueryContext(ctx, "SELECT * FROM "+table.name+" ORDER BY "+table.orderBy)
		require.NoError(t, err)
		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			require.NoError(t, err)
		}
		tableRows := make([][]any, 0)
		var scanErr error
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(values))
			for index := range values {
				destinations[index] = &values[index]
			}
			if scanErr = rows.Scan(destinations...); scanErr != nil {
				break
			}
			tableRows = append(tableRows, values)
		}
		rowsErr := rows.Err()
		closeErr := rows.Close()
		require.NoError(t, scanErr)
		require.NoError(t, rowsErr)
		require.NoError(t, closeErr)
		result[table.name] = tableRows
	}
	return result
}

func incomingMaterialUpgradeUserVersion(t *testing.T, ctx context.Context, q queryer) int {
	t.Helper()
	var version int
	require.NoError(t, q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
	return version
}

func incomingMaterialUpgradeIncomingTableRows(t *testing.T, ctx context.Context, q queryer) int64 {
	t.Helper()
	return incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM sqlite_master WHERE name='accepted_material_refs'")
}

func incomingMaterialUpgradePopulatedSource(t *testing.T, ctx context.Context) (fixture, *Store, Attempt, Finalization) {
	t.Helper()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	genesis, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
	require.Equal(t, uint64(1), finalized.Floor.Revision)
	require.Equal(t, genesis.ID, finalized.Attempt.ID)
	predecessorView := attemptView(f, f.observation(1), false)
	successorCandidate := attemptCandidate(f, 1)
	successorReview := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, successorCandidate, predecessorView, successorReview)
	require.NoError(t, err)
	successor, err := store.CreateAttempt(ctx, proposal.StateToken, successorCandidate, predecessorView, successorReview, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptPrepared, successor.Lifecycle)
	require.Equal(t, int64(2), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM publication_attempts"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM active_publication_attempt"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_payload_refs"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_reservations"))
	require.GreaterOrEqual(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_events"), int64(2))
	require.GreaterOrEqual(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_evidence"), int64(1))
	require.GreaterOrEqual(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"), int64(1))
	return f, store, genesis, finalized
}

func TestIncomingMaterialUpgradeTransactionCore(t *testing.T) {
	t.Run("genuine positions v1", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, conn, companionRows := incomingMaterialUpgradeCopiedSource(t, ctx)
		require.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, conn))
		require.NoError(t, checkSchemaVersion(ctx, conn, 1))
		require.Equal(t, companionRows, readLogicalRows(t, conn))
		beforeRows := incomingMaterialUpgradeV1Rows(t, ctx, conn)
		beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
		require.Len(t, beforeMetadata, 5)
		source, err := readIncomingMaterialUpgradeSource(ctx, conn, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)

		tx := incomingMaterialUpgradeTx(t, ctx, conn)
		var points []int
		require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
			points = append(points, point)
			return nil
		}))
		assert.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, points)
		assert.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
		afterMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, tx)
		require.Len(t, afterMetadata, 7)
		for _, key := range []string{"binding", "database_id", "generation", "limits", "revision"} {
			assert.Equal(t, beforeMetadata[key], afterMetadata[key], key)
		}
		wantedAttemptLimits, err := encodeAttemptLimits(DefaultAttemptLimits())
		require.NoError(t, err)
		assert.Equal(t, wantedAttemptLimits, afterMetadata["attempt_limits"])
		assert.Equal(t, uint64Bytes(0), afterMetadata["attempt_mutation_revision"])
		require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, tx))
		assert.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
		assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		afterRows := incomingMaterialUpgradeV1Rows(t, ctx, tx)
		for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
			assert.Equal(t, beforeRows[table], afterRows[table], table)
		}
		for _, table := range []string{"publication_attempts", "active_publication_attempt", "pending_genesis", "attempt_events", "attempt_evidence", "payload_objects", "attempt_payload_refs", "retained_publications", "attempt_reservations"} {
			assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM "+table), table)
		}
		require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, source))
		require.NoError(t, tx.Rollback())
		assert.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, conn))
		require.NoError(t, checkSchemaVersion(ctx, conn, 1))
		assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, conn))
		assert.Equal(t, beforeRows, incomingMaterialUpgradeV1Rows(t, ctx, conn))
		assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, conn))
		assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM sqlite_master WHERE name='publication_attempts'"))
	})

	t.Run("populated source two unit store", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, beforeMetadata, 7)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)

		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		var points []int
		require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
			points = append(points, point)
			return nil
		}))
		assert.Equal(t, []int{13, 14, 15}, points)
		assert.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
		assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, tx))
		afterRows, err := sharedCustodyLogicalRows(ctx, tx)
		require.NoError(t, err)
		assert.Equal(t, beforeRows, afterRows)
		require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, tx))
		assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, source))
		require.NoError(t, tx.Rollback())
		assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
		assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
		restoredRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		assert.Equal(t, beforeRows, restoredRows)
		assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	})
}

func TestIncomingMaterialUpgradeSourceAuditFence(t *testing.T) {
	t.Run("source two uncommitted audit corruption", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		_, err = tx.ExecContext(ctx, "UPDATE accepted_events SET digest=zeroblob(32) WHERE revision=1")
		require.NoError(t, err)
		var digestType string
		var digestLength int64
		require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(digest),length(CAST(digest AS BLOB)) FROM accepted_events WHERE revision=1").Scan(&digestType, &digestLength))
		require.Equal(t, "blob", digestType)
		require.Equal(t, int64(32), digestLength)
		var points []int
		err = migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
			points = append(points, point)
			return nil
		})
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		assert.Empty(t, points)
		assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, tx))
		assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
		require.NoError(t, tx.Rollback())
		restoredRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		assert.Equal(t, beforeRows, restoredRows)
	})

	t.Run("stale expected snapshot", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, beforeMetadata, 7)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		stale := incomingMaterialUpgradeCloneSource(source)
		stale.metadata["revision"] = uint64Bytes(3)
		require.NotEqual(t, source.metadata["revision"], stale.metadata["revision"])
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		var points []int
		err = migrateIncomingMaterialTx(ctx, tx, stale, func(point int) error {
			points = append(points, point)
			return nil
		})
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		assert.Empty(t, points)
		assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, tx))
		assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
		require.NoError(t, tx.Rollback())
		assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
	})

	t.Run("source one uncommitted audit corruption", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, conn, _ := incomingMaterialUpgradeCopiedSource(t, ctx)
		beforeRows := incomingMaterialUpgradeV1Rows(t, ctx, conn)
		source, err := readIncomingMaterialUpgradeSource(ctx, conn, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, conn)
		_, err = tx.ExecContext(ctx, "UPDATE accepted_events SET digest=zeroblob(32) WHERE revision=2")
		require.NoError(t, err)
		var digestType string
		var digestLength int64
		require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(digest),length(CAST(digest AS BLOB)) FROM accepted_events WHERE revision=2").Scan(&digestType, &digestLength))
		require.Equal(t, "blob", digestType)
		require.Equal(t, int64(32), digestLength)
		var points []int
		err = migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
			points = append(points, point)
			return nil
		})
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		assert.Empty(t, points)
		assert.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, tx))
		assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM sqlite_master WHERE name='publication_attempts'"))
		require.NoError(t, tx.Rollback())
		assert.Equal(t, beforeRows, incomingMaterialUpgradeV1Rows(t, ctx, conn))
	})

	t.Run("expected snapshot key set", func(t *testing.T) {
		t.Run("source one", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			t.Cleanup(cancel)
			f, conn, _ := incomingMaterialUpgradeCopiedSource(t, ctx)
			beforeRows := incomingMaterialUpgradeV1Rows(t, ctx, conn)
			beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
			source, err := readIncomingMaterialUpgradeSource(ctx, conn, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
			require.NoError(t, err)
			require.Len(t, source.metadata, 5)
			expected := incomingMaterialUpgradeCloneSource(source)
			delete(expected.metadata, "revision")
			expected.metadata["unexpected_empty_metadata"] = []byte{}
			require.Len(t, expected.metadata, 5)
			_, present := expected.metadata["revision"]
			require.False(t, present)
			unknown, present := expected.metadata["unexpected_empty_metadata"]
			require.True(t, present)
			require.NotNil(t, unknown)
			require.Empty(t, unknown)
			_, present = source.metadata["unexpected_empty_metadata"]
			require.False(t, present)

			tx := incomingMaterialUpgradeTx(t, ctx, conn)
			var points []int
			err = migrateIncomingMaterialTx(ctx, tx, expected, func(point int) error {
				points = append(points, point)
				return nil
			})
			requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
			assert.Empty(t, points)
			assert.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, tx))
			assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
			assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM sqlite_master WHERE name='publication_attempts'"))
			require.NoError(t, tx.Rollback())
			assert.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, conn))
			assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, conn))
			assert.Equal(t, beforeRows, incomingMaterialUpgradeV1Rows(t, ctx, conn))
		})

		t.Run("source two", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			t.Cleanup(cancel)
			f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
			beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
			require.NoError(t, err)
			beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
			source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
			require.NoError(t, err)
			require.Len(t, source.metadata, 7)
			expected := incomingMaterialUpgradeCloneSource(source)
			delete(expected.metadata, "revision")
			expected.metadata["unexpected_empty_metadata"] = []byte{}
			require.Len(t, expected.metadata, 7)
			_, present := expected.metadata["revision"]
			require.False(t, present)
			unknown, present := expected.metadata["unexpected_empty_metadata"]
			require.True(t, present)
			require.NotNil(t, unknown)
			require.Empty(t, unknown)
			_, present = source.metadata["unexpected_empty_metadata"]
			require.False(t, present)

			tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
			var points []int
			err = migrateIncomingMaterialTx(ctx, tx, expected, func(point int) error {
				points = append(points, point)
				return nil
			})
			requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
			assert.Empty(t, points)
			assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, tx))
			assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
			require.NoError(t, tx.Rollback())
			assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
			assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
			restoredRows, err := sharedCustodyLogicalRows(ctx, store.conn)
			require.NoError(t, err)
			assert.Equal(t, beforeRows, restoredRows)
		})
	})
}

func TestIncomingMaterialUpgradeValidationUsesQueryer(t *testing.T) {
	t.Run("populated destination", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, nil))
		recorder := &incomingMaterialUpgradeRecorder{source: tx}
		require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, recorder, source))
		require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, source))
		for _, fragment := range []string{
			"PRAGMA application_id",
			"PRAGMA user_version",
			"SELECT name,type,sql FROM sqlite_master",
			"SELECT key FROM store_meta",
			"FROM accepted_events",
			"FROM accepted_records",
			"FROM publication_attempts",
			"FROM attempt_events",
			"FROM attempt_evidence",
			"FROM attempt_payload_refs",
			"FROM attempt_reservations",
			"FROM retained_publications",
			"FROM payload_objects",
			"FROM accepted_material_refs",
		} {
			recorder.requireQueryContaining(t, fragment)
		}
		require.NoError(t, tx.Rollback())
	})

	t.Run("populated duplicate role", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, finalized := incomingMaterialUpgradePopulatedSource(t, ctx)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, nil))
		_, err = tx.ExecContext(ctx, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", int64(finalized.Floor.Revision), finalized.Floor.RecordCID, finalized.Floor.BlobCID)
		require.NoError(t, err)
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		var revisionType, recordType, blobType string
		require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(accepted_revision),typeof(record_cid),typeof(blob_cid) FROM accepted_material_refs").Scan(&revisionType, &recordType, &blobType))
		require.Equal(t, "integer", revisionType)
		require.Equal(t, "blob", recordType)
		require.Equal(t, "blob", blobType)
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
		recorder := &incomingMaterialUpgradeRecorder{source: tx}
		err = checkIncomingMaterialUpgradeDestination(ctx, recorder, source)
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		for _, fragment := range []string{"FROM publication_attempts", "FROM attempt_events", "FROM accepted_material_refs", "FROM retained_publications WHERE accepted_revision=?"} {
			recorder.requireQueryContaining(t, fragment)
		}
		require.NoError(t, tx.Rollback())
	})
}

func TestIncomingMaterialUpgradeDestinationValidation(t *testing.T) {
	t.Run("extra named index", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		var points []int
		err = migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
			points = append(points, point)
			if point == incomingMaterialUpgradeUserVersionFault {
				_, execErr := tx.ExecContext(ctx, "CREATE INDEX incoming_material_upgrade_extra ON store_meta(key)")
				require.NoError(t, execErr)
				require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
				destinationMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, tx)
				require.Len(t, destinationMetadata, 7)
				require.Equal(t, source.metadata, destinationMetadata)
				require.NoError(t, compareMetadata(ctx, tx, source.binding, source.limits))
				require.NoError(t, checkAttemptMetadata(ctx, tx, source.attemptLimits))
				require.Equal(t, beforeRows, incomingMaterialUpgradeFixtureTypedRows(t, ctx, tx))
				databaseIDBytes := destinationMetadata["database_id"]
				require.Len(t, databaseIDBytes, 32)
				require.False(t, allZero(databaseIDBytes))
				mutationBytes := destinationMetadata["attempt_mutation_revision"]
				require.Len(t, mutationBytes, 8)
				var databaseID [32]byte
				copy(databaseID[:], databaseIDBytes)
				destinationStore := &Store{binding: source.binding, limits: source.limits, attemptLimits: source.attemptLimits, databaseID: databaseID, schemaVersion: 3}
				destinationStore.attemptMutationRevision = binary.BigEndian.Uint64(mutationBytes)
				_, stateErr := destinationStore.readState(ctx, tx, StageOpen)
				require.NoError(t, stateErr)
				incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
				require.NoError(t, destinationStore.checkIncomingMaterialRefs(ctx, tx, StageOpen))
				require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
			}
			return nil
		})
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
		assert.Equal(t, []int{13, 14}, points)
		assert.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM sqlite_master WHERE name='incoming_material_upgrade_extra'"))
		assert.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
		require.NoError(t, tx.Rollback())
		assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM sqlite_master WHERE name='incoming_material_upgrade_extra'"))
		restoredRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		assert.Equal(t, beforeRows, restoredRows)
	})

	t.Run("changed old metadata", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, beforeMetadata, 7)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		var points []int
		err = migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
			points = append(points, point)
			if point == incomingMaterialUpgradeUserVersionFault {
				_, execErr := tx.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='revision'", uint64Bytes(3))
				require.NoError(t, execErr)
			}
			return nil
		})
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		assert.Equal(t, []int{13, 14}, points)
		var changed []byte
		require.NoError(t, tx.QueryRowContext(ctx, "SELECT value FROM store_meta WHERE key='revision'").Scan(&changed))
		require.Equal(t, uint64Bytes(3), changed)
		require.NoError(t, tx.Rollback())
		restoredMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, restoredMetadata, 7)
		assert.Equal(t, beforeMetadata["revision"], restoredMetadata["revision"])
	})

	t.Run("old audit corruption", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		var points []int
		err = migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
			points = append(points, point)
			if point == incomingMaterialUpgradeUserVersionFault {
				_, execErr := tx.ExecContext(ctx, "UPDATE accepted_events SET digest=zeroblob(32) WHERE revision=1")
				require.NoError(t, execErr)
			}
			return nil
		})
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		assert.Equal(t, []int{13, 14}, points)
		var digestType string
		var digestLength int64
		require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(digest),length(CAST(digest AS BLOB)) FROM accepted_events WHERE revision=1").Scan(&digestType, &digestLength))
		require.Equal(t, "blob", digestType)
		require.Equal(t, int64(32), digestLength)
		require.NoError(t, tx.Rollback())
		restoredRows, err := sharedCustodyLogicalRows(ctx, store.conn)
		require.NoError(t, err)
		assert.Equal(t, beforeRows, restoredRows)
	})

	t.Run("invalid source", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		invalidVersion := incomingMaterialUpgradeCloneSource(source)
		invalidVersion.version = 3
		var points []int
		err = migrateIncomingMaterialTx(ctx, tx, invalidVersion, func(point int) error {
			points = append(points, point)
			return nil
		})
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
		assert.Empty(t, points)
		requireErrorMetadata(t, checkIncomingMaterialUpgradeDestination(ctx, tx, invalidVersion), ErrSchema, StageOpen, ReasonSchema)
		invalidBinding := incomingMaterialUpgradeCloneSource(source)
		invalidBinding.binding = Binding{}
		requireErrorMetadata(t, migrateIncomingMaterialTx(ctx, tx, invalidBinding, nil), ErrInvalid, StageOpen, ReasonBinding)
		requireErrorMetadata(t, checkIncomingMaterialUpgradeDestination(ctx, tx, invalidBinding), ErrInvalid, StageOpen, ReasonBinding)
		invalidLimits := incomingMaterialUpgradeCloneSource(source)
		invalidLimits.limits = Limits{}
		requireErrorMetadata(t, migrateIncomingMaterialTx(ctx, tx, invalidLimits, nil), ErrInvalid, StageOpen, ReasonLimits)
		requireErrorMetadata(t, checkIncomingMaterialUpgradeDestination(ctx, tx, invalidLimits), ErrInvalid, StageOpen, ReasonLimits)
		malformed := incomingMaterialUpgradeCloneSource(source)
		delete(malformed.metadata, "revision")
		requireErrorMetadata(t, migrateIncomingMaterialTx(ctx, tx, malformed, nil), ErrSchema, StageOpen, ReasonCorrupt)
		requireErrorMetadata(t, checkIncomingMaterialUpgradeDestination(ctx, tx, malformed), ErrSchema, StageOpen, ReasonCorrupt)
		require.NoError(t, tx.Rollback())
	})
}

func TestIncomingMaterialUpgradeCallsB5BeforeCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	f, store, _, finalized := incomingMaterialUpgradePopulatedSource(t, ctx)
	beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
	require.NoError(t, err)
	beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
	require.Len(t, beforeMetadata, 7)
	source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
	require.NoError(t, err)
	tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
	var points []int
	err = migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
		points = append(points, point)
		if point == incomingMaterialUpgradeUserVersionFault {
			_, execErr := tx.ExecContext(ctx, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", int64(finalized.Floor.Revision), finalized.Floor.RecordCID, finalized.Floor.BlobCID)
			require.NoError(t, execErr)
		}
		return nil
	})
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
	require.Equal(t, []int{13, 14}, points)
	require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, tx))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	var revisionType, recordType, blobType string
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(accepted_revision),typeof(record_cid),typeof(blob_cid) FROM accepted_material_refs").Scan(&revisionType, &recordType, &blobType))
	require.Equal(t, "integer", revisionType)
	require.Equal(t, "blob", recordType)
	require.Equal(t, "blob", blobType)
	incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
	destinationMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, tx)
	require.Len(t, destinationMetadata, 7)
	var databaseID [32]byte
	require.Len(t, destinationMetadata["database_id"], 32)
	require.False(t, allZero(destinationMetadata["database_id"]))
	require.Len(t, destinationMetadata["attempt_mutation_revision"], 8)
	copy(databaseID[:], destinationMetadata["database_id"])
	oldGraph := &Store{binding: source.binding, limits: source.limits, attemptLimits: source.attemptLimits, databaseID: databaseID, schemaVersion: 2}
	oldGraph.attemptMutationRevision = binary.BigEndian.Uint64(destinationMetadata["attempt_mutation_revision"])
	_, err = oldGraph.readState(ctx, tx, StageOpen)
	require.NoError(t, err)
	destinationStore := &Store{binding: source.binding, limits: source.limits, attemptLimits: source.attemptLimits, databaseID: databaseID, schemaVersion: 3}
	destinationStore.attemptMutationRevision = oldGraph.attemptMutationRevision
	refused, err := destinationStore.readState(ctx, tx, StageOpen)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
	require.Equal(t, stateSnapshot{}, refused)
	requireErrorMetadata(t, destinationStore.checkIncomingMaterialRefs(ctx, tx, StageOpen), ErrSchema, StageOpen, ReasonCorrupt)
	require.NoError(t, tx.Rollback())
	assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
	restoredRows, err := sharedCustodyLogicalRows(ctx, store.conn)
	require.NoError(t, err)
	assert.Equal(t, beforeRows, restoredRows)
}

func TestIncomingMaterialUpgradeRollbackAtEveryWritePoint(t *testing.T) {
	t.Run("source one", func(t *testing.T) {
		for point := 1; point <= 15; point++ {
			t.Run(fmt.Sprintf("point %d", point), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				t.Cleanup(cancel)
				f, conn, _ := incomingMaterialUpgradeCopiedSource(t, ctx)
				beforeRows := incomingMaterialUpgradeV1Rows(t, ctx, conn)
				beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
				require.Len(t, beforeMetadata, 5)
				source, err := readIncomingMaterialUpgradeSource(ctx, conn, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
				require.NoError(t, err)
				tx := incomingMaterialUpgradeTx(t, ctx, conn)
				canary := errors.New("injected interval failure")
				var points []int
				err = migrateIncomingMaterialTx(ctx, tx, source, func(reached int) error {
					points = append(points, reached)
					if reached == point {
						return canary
					}
					return nil
				})
				requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
				require.NotErrorIs(t, err, canary)
				expectedPoints := make([]int, 0, point)
				for reached := 1; reached <= point; reached++ {
					expectedPoints = append(expectedPoints, reached)
				}
				require.Equal(t, expectedPoints, points)
				if point >= incomingMaterialUpgradeAttemptMetadataFault {
					require.Len(t, incomingMaterialUpgradeStoredMetadata(t, ctx, tx), 7)
				} else {
					require.Len(t, incomingMaterialUpgradeStoredMetadata(t, ctx, tx), 5)
				}
				if point >= incomingMaterialUpgradeIncomingTableFault {
					assert.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
				} else {
					assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
				}
				if point >= incomingMaterialUpgradeUserVersionFault {
					assert.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
				} else {
					assert.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, tx))
				}
				require.NoError(t, tx.Rollback())
				assert.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, conn))
				require.NoError(t, checkSchemaVersion(ctx, conn, 1))
				assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, conn))
				assert.Equal(t, beforeRows, incomingMaterialUpgradeV1Rows(t, ctx, conn))
				assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, conn))
				assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM sqlite_master WHERE name='publication_attempts'"))
			})
		}
	})

	t.Run("source two", func(t *testing.T) {
		for _, point := range []int{13, 14, 15} {
			t.Run(fmt.Sprintf("point %d", point), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				t.Cleanup(cancel)
				f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
				beforeRows, err := sharedCustodyLogicalRows(ctx, store.conn)
				require.NoError(t, err)
				beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
				require.Len(t, beforeMetadata, 7)
				source, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, DefaultLimits(), DefaultAttemptLimits())
				require.NoError(t, err)
				tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
				canary := errors.New("injected interval failure")
				var points []int
				err = migrateIncomingMaterialTx(ctx, tx, source, func(reached int) error {
					points = append(points, reached)
					if reached == point {
						return canary
					}
					return nil
				})
				requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
				require.NotErrorIs(t, err, canary)
				expectedPoints := []int{13}
				if point >= incomingMaterialUpgradeUserVersionFault {
					expectedPoints = append(expectedPoints, 14)
				}
				if point >= incomingMaterialUpgradeDestinationFault {
					expectedPoints = append(expectedPoints, 15)
				}
				require.Equal(t, expectedPoints, points)
				assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, tx))
				assert.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
				if point >= incomingMaterialUpgradeUserVersionFault {
					assert.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
				} else {
					assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, tx))
				}
				require.NoError(t, tx.Rollback())
				assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
				assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn))
				restoredRows, err := sharedCustodyLogicalRows(ctx, store.conn)
				require.NoError(t, err)
				assert.Equal(t, beforeRows, restoredRows)
				assert.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
			})
		}
	})
}
