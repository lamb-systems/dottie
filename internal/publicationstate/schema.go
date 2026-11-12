package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"strings"
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

type schemaInventory struct {
	statements   []string
	objects      map[string]string
	metadataKeys []string
}

func schemaInventoryForVersion(version int) (schemaInventory, error) {
	switch version {
	case 1:
		return schemaInventory{
			statements:   append([]string(nil), schemaV1Statements...),
			objects:      cloneSchemaObjects(schemaV1Objects),
			metadataKeys: []string{"binding", "database_id", "generation", "limits", "revision"},
		}, nil
	case 2:
		statements := make([]string, 0, len(schemaV1Statements)+len(attemptSchemaStatements))
		statements = append(statements, schemaV1Statements...)
		statements = append(statements, attemptSchemaStatements...)
		objects := make(map[string]string, len(schemaV1Objects)+len(attemptSchemaObjects))
		for name, kind := range schemaV1Objects {
			objects[name] = kind
		}
		for name, kind := range attemptSchemaObjects {
			objects[name] = kind
		}
		return schemaInventory{
			statements:   statements,
			objects:      objects,
			metadataKeys: []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"},
		}, nil
	case 3:
		base, err := schemaInventoryForVersion(2)
		if err != nil {
			return schemaInventory{}, err
		}
		statements := append(append([]string(nil), base.statements...), incomingMaterialSchemaStatement)
		objects := cloneSchemaObjects(base.objects)
		objects[statementTableName(incomingMaterialSchemaStatement)] = "table"
		return schemaInventory{
			statements:   statements,
			objects:      objects,
			metadataKeys: append([]string(nil), base.metadataKeys...),
		}, nil
	default:
		return schemaInventory{}, errSchemaMismatch
	}
}

func cloneSchemaObjects(objects map[string]string) map[string]string {
	cloned := make(map[string]string, len(objects))
	for name, kind := range objects {
		cloned[name] = kind
	}
	return cloned
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
	inventory, err := schemaInventoryForVersion(version)
	if err != nil {
		return err
	}
	if !sameObjects(objects, inventory.objects) {
		return errSchemaMismatch
	}
	for _, statement := range inventory.statements {
		if strings.TrimSpace(definitions[statementTableName(statement)]) != statement {
			return errSchemaMismatch
		}
	}
	keys, err := readMetadataKeys(ctx, conn)
	if err != nil {
		return err
	}
	if !equalStrings(keys, inventory.metadataKeys) {
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

func readStateForUpgrade(ctx context.Context, conn queryer, binding Binding, limits Limits) (stateSnapshot, error) {
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
