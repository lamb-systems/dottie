package main

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publicationstate"
)

const generatorPreflightDID = "did:plc:abcdefghijklmnopqrstuvwx"

func generatorPreflightBinding() publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: generatorPreflightDID,
		Backend:    publicationstate.BackendPublicRepo,
		Repository: "at://" + generatorPreflightDID,
	}
	binding.Vault[0] = 1
	return binding
}

func generatorPreflightAttemptID() []byte {
	attemptID := make([]byte, 16)
	attemptID[15] = 1
	return attemptID
}

func generatorPreflightSource(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.OpenWithOptions(
		directory,
		generatorPreflightBinding(),
		publicationstate.DefaultOpenOptions(),
	)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	databasePath := filepath.Join(directory, "publication.db")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: databasePath}).String())
	require.NoError(t, err)
	_, err = db.ExecContext(
		context.Background(),
		"INSERT INTO publication_attempts(attempt_id,core,lifecycle,outcome,blocked,state_digest,mutation_revision,created_order,logical_bytes) VALUES(?,?,?,?,?,?,?,?,?)",
		generatorPreflightAttemptID(),
		[]byte("core"),
		"prepared",
		"not-submitted",
		"",
		make([]byte, 32),
		int64(0),
		int64(1),
		int64(4),
	)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	return databasePath
}

func generatorPreflightRetainedRow(
	t *testing.T,
	databasePath string,
	statement string,
	args ...any,
) {
	t.Helper()
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: databasePath}).String())
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), statement, args...)
	require.NoError(t, err)
	require.NoError(t, db.Close())
}

func generatorPreflightManifestRow(t *testing.T, databasePath string) {
	t.Helper()
	cid := make([]byte, 36)
	cid[0] = 0x01
	generatorPreflightRetainedRow(t,
		databasePath,
		"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'manifest',NULL,NULL,?,1)",
		cid,
		generatorPreflightAttemptID(),
		[]byte("manifest"),
	)
}

func generatorPreflightSchema2Statements(t *testing.T) []string {
	t.Helper()
	statements, err := loadSchema2Statements()
	require.NoError(t, err)
	return statements
}

func TestSchema2RebuildRefusesManifestRetainedRows(t *testing.T) {
	databasePath := generatorPreflightSource(t)
	generatorPreflightManifestRow(t, databasePath)
	_, err := rebuildSchema2(databasePath, generatorPreflightSchema2Statements(t), func(rowInventory) error { return nil })
	require.ErrorIs(t, err, errUnrepresentableRetainedPublication)
	_, statErr := os.Stat(databasePath + ".schema2")
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestSchema2RebuildRefusesManifestRetainedRowsBeforeDestinationCreation(t *testing.T) {
	databasePath := generatorPreflightSource(t)
	generatorPreflightManifestRow(t, databasePath)
	sentinelPath := databasePath + ".schema2"
	sentinel := []byte("pre-existing schema-2 destination sentinel")
	require.NoError(t, os.WriteFile(sentinelPath, sentinel, 0o600))
	_, err := rebuildSchema2(databasePath, generatorPreflightSchema2Statements(t), func(rowInventory) error { return nil })
	require.ErrorIs(t, err, errUnrepresentableRetainedPublication)
	unchanged, err := os.ReadFile(sentinelPath)
	require.NoError(t, err)
	assert.Equal(t, sentinel, unchanged)
}

func TestSchema2RebuildAcceptsPackedRetainedRows(t *testing.T) {
	databasePath := generatorPreflightSource(t)
	cid := make([]byte, 36)
	cid[0] = 0x01
	generatorPreflightRetainedRow(t,
		databasePath,
		"INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,1,'entry.payload',1)",
		cid,
	)
	generatorPreflightRetainedRow(t,
		databasePath,
		"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'packed',?,1,NULL,1)",
		cid,
		generatorPreflightAttemptID(),
		cid,
	)
	statements, err := loadSchema2Statements()
	require.NoError(t, err)
	_, err = rebuildSchema2(databasePath, statements, func(rowInventory) error { return nil })
	require.NoError(t, err)
	db, closeDatabase, err := openImmutableDatabase(databasePath)
	require.NoError(t, err)
	defer closeDatabase()
	var userVersion int64
	require.NoError(t, db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&userVersion))
	assert.Equal(t, int64(schema2Version), userVersion)
	var rows int64
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM retained_publications").Scan(&rows))
	assert.Equal(t, int64(1), rows)
}

func TestSchema3AcceptedMaterialSpecMatchesTheLiveSchema(t *testing.T) {
	databasePath := generatorPreflightSource(t)
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: databasePath}).String())
	require.NoError(t, err)
	var stored string
	require.NoError(t, db.QueryRowContext(
		context.Background(),
		"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
		schema3AcceptedMaterialRefsSpec.Name,
	).Scan(&stored))
	require.NoError(t, db.Close())
	assert.Equal(t, schema3AcceptedMaterialRefsSpec.DDL, strings.TrimSpace(stored))
}
