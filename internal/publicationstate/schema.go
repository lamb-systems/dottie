package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

var attemptSchemaStatements = []string{
	"CREATE TABLE publication_attempts (attempt_id BLOB PRIMARY KEY NOT NULL, core BLOB NOT NULL, lifecycle TEXT NOT NULL, outcome TEXT NOT NULL, blocked TEXT NOT NULL, state_digest BLOB NOT NULL, mutation_revision INTEGER NOT NULL, created_order INTEGER NOT NULL, logical_bytes INTEGER NOT NULL, terminal_evidence BLOB, retirement_evidence BLOB)",
	"CREATE TABLE active_publication_attempt (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1), attempt_id BLOB NOT NULL REFERENCES publication_attempts(attempt_id))",
	"CREATE TABLE pending_genesis (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1), attempt_id BLOB NOT NULL UNIQUE REFERENCES publication_attempts(attempt_id), vault BLOB NOT NULL)",
	"CREATE TABLE attempt_events (attempt_id BLOB NOT NULL REFERENCES publication_attempts(attempt_id), ordinal INTEGER NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(attempt_id, ordinal))",
	"CREATE TABLE attempt_evidence (attempt_id BLOB NOT NULL REFERENCES publication_attempts(attempt_id), role TEXT NOT NULL, body BLOB NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(attempt_id, role))",
	"CREATE TABLE payload_objects (blob_cid BLOB PRIMARY KEY NOT NULL, size INTEGER NOT NULL, basename TEXT NOT NULL UNIQUE, logical_bytes INTEGER NOT NULL)",
	"CREATE TABLE attempt_payload_refs (attempt_id BLOB PRIMARY KEY NOT NULL REFERENCES publication_attempts(attempt_id), blob_cid BLOB NOT NULL REFERENCES payload_objects(blob_cid))",
	"CREATE TABLE retained_publications (record_cid BLOB PRIMARY KEY NOT NULL, attempt_id BLOB NOT NULL UNIQUE REFERENCES publication_attempts(attempt_id), sequence INTEGER NOT NULL, blob_cid BLOB NOT NULL REFERENCES payload_objects(blob_cid), size INTEGER NOT NULL, accepted_revision INTEGER NOT NULL)",
	"CREATE TABLE attempt_reservations (attempt_id BLOB PRIMARY KEY NOT NULL REFERENCES publication_attempts(attempt_id), metadata_bytes INTEGER NOT NULL, accepted_bytes INTEGER NOT NULL, accepted_records INTEGER NOT NULL, accepted_events INTEGER NOT NULL, retained_points INTEGER NOT NULL)",
	"CREATE INDEX publication_attempts_order ON publication_attempts(created_order, attempt_id)",
	"CREATE INDEX payload_objects_basename ON payload_objects(basename)",
}

var attemptSchemaObjects = map[string]string{
	"publication_attempts":       "table",
	"active_publication_attempt": "table",
	"pending_genesis":            "table",
	"attempt_events":             "table",
	"attempt_evidence":           "table",
	"payload_objects":            "table",
	"attempt_payload_refs":       "table",
	"retained_publications":      "table",
	"attempt_reservations":       "table",
	"publication_attempts_order": "index",
	"payload_objects_basename":   "index",
}

func currentSchemaStatements() []string {
	statements := make([]string, 0, len(schemaStatements)+len(attemptSchemaStatements))
	statements = append(statements, schemaStatements...)
	statements = append(statements, attemptSchemaStatements...)
	return statements
}

func currentSchemaObjects() map[string]string {
	objects := make(map[string]string, len(schemaObjects)+len(attemptSchemaObjects))
	for name, kind := range schemaObjects {
		objects[name] = kind
	}
	for name, kind := range attemptSchemaObjects {
		objects[name] = kind
	}
	return objects
}

type schemaReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func checkSchemaVersion(ctx context.Context, conn schemaReader, version int) error {
	var appID, actual int
	if err := conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&actual); err != nil {
		return err
	}
	if appID != applicationID || actual != version {
		return errSchemaMismatch
	}
	objects, definitions, err := readSchemaObjects(ctx, conn)
	if err != nil {
		return err
	}
	wantedObjects := schemaObjects
	statements := schemaStatements
	metadata := []string{"binding", "database_id", "generation", "limits", "revision"}
	if version == 2 {
		wantedObjects = currentSchemaObjects()
		statements = currentSchemaStatements()
		metadata = []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"}
	}
	if !sameObjects(objects, wantedObjects) {
		return errSchemaMismatch
	}
	for _, statement := range statements {
		if strings.TrimSpace(definitions[statementTableName(statement)]) != statement {
			return errSchemaMismatch
		}
	}
	keys, err := readMetadataKeys(ctx, conn)
	if err != nil {
		return err
	}
	if !equalStrings(keys, metadata) {
		return errSchemaMismatch
	}
	return nil
}

func readSchemaObjects(ctx context.Context, conn schemaReader) (map[string]string, map[string]string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT name,type,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name")
	if err != nil {
		return nil, nil, err
	}
	objects := map[string]string{}
	definitions := map[string]string{}
	for rows.Next() {
		var name, kind, definition string
		if err := rows.Scan(&name, &kind, &definition); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		objects[name] = kind
		definitions[name] = definition
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	return objects, definitions, nil
}

func readMetadataKeys(ctx context.Context, conn schemaReader) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT key FROM store_meta ORDER BY key")
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, 7)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return keys, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func readStateForUpgrade(ctx context.Context, conn *sql.Conn, binding Binding, limits Limits) (stateSnapshot, error) {
	databaseID, err := readValueBounded(ctx, conn, "database_id", 32)
	if err != nil || len(databaseID) != 32 {
		return stateSnapshot{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	var id [32]byte
	copy(id[:], databaseID)
	if allZero(id[:]) {
		return stateSnapshot{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	store := &Store{binding: binding, limits: limits, databaseID: id, schemaVersion: 1}
	return store.readState(ctx, conn, StageOpen)
}

func upgradeSchema(ctx context.Context, conn *sql.Conn, limits AttemptLimits, rootFD int, fault func(int) error, commitHook func(*sql.Tx) error) error {
	encodedLimits, err := encodeAttemptLimits(limits)
	if err != nil {
		return classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	stage := 0
	for _, statement := range attemptSchemaStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
		stage++
		if fault != nil {
			if err := fault(stage); err != nil {
				return storageFailure(ctx, StageOpen, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO store_meta(key,value) VALUES ('attempt_limits',?),('attempt_mutation_revision',?)", encodedLimits, uint64Bytes(0)); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	stage++
	if fault != nil {
		if err := fault(stage); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
	}
	var fkRows *sql.Rows
	fkRows, err = tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	if fkRows.Next() {
		_ = fkRows.Close()
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	if err := fkRows.Err(); err != nil {
		_ = fkRows.Close()
		return storageFailure(ctx, StageOpen, err)
	}
	if err := fkRows.Close(); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	stage++
	if fault != nil {
		if err := fault(stage); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	if err := checkSchemaVersion(ctx, tx, 2); err != nil {
		return schemaOrStorageError(ctx, StageOpen, err)
	}
	if err := checkAttemptMetadata(ctx, tx, limits); err != nil {
		return err
	}
	stage++
	if fault != nil {
		if err := fault(stage); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
	}
	if err := unix.Fsync(rootFD); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	stage++
	if fault != nil {
		if err := fault(stage); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
	}
	commit := commitHook
	if commit == nil {
		commit = func(tx *sql.Tx) error { return tx.Commit() }
	}
	if err := commit(tx); err != nil {
		_ = tx.Rollback()
		return classified(ErrStorage, StageOpen, ReasonCommitUnknown)
	}
	rollback = false
	return nil
}

func checkAttemptMetadata(ctx context.Context, conn interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, limits AttemptLimits) error {
	stored, err := readValueBounded(ctx, conn, "attempt_limits", 16384)
	if err != nil {
		return storedOrQueryError(ctx, StageOpen, err)
	}
	wanted, err := encodeAttemptLimits(limits)
	if err != nil {
		return classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	if !bytes.Equal(stored, wanted) {
		return classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	revision, err := readValueBounded(ctx, conn, "attempt_mutation_revision", 8)
	if err != nil || len(revision) != 8 {
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	if binary.BigEndian.Uint64(revision) > uint64(^uint64(0)>>1) {
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	return nil
}

var _ = errors.Is
