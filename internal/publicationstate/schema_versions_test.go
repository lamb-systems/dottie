package publicationstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaInventoriesMatchFrozenGoldens(t *testing.T) {
	v1, err := schemaInventoryForVersion(1)
	require.NoError(t, err)
	v2, err := schemaInventoryForVersion(2)
	require.NoError(t, err)

	assertSchemaInventoryGolden(t, v1, 6, map[string]string{
		"store_meta":         "table",
		"cache_records":      "table",
		"cache_observations": "table",
		"accepted_records":   "table",
		"accepted_events":    "table",
		"active_floor":       "table",
	}, []string{"binding", "database_id", "generation", "limits", "revision"}, "7d3cb30f9344c9e994a6ba4f9f92cd4a58ca75ab5f6c9ecbf7c9a976caf38b89")
	assertSchemaInventoryGolden(t, v2, 17, map[string]string{
		"store_meta":                 "table",
		"cache_records":              "table",
		"cache_observations":         "table",
		"accepted_records":           "table",
		"accepted_events":            "table",
		"active_floor":               "table",
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
	}, []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"}, "32277ef36c51acb9115f9ece47c2917bd4f75ad9e4e8f1fa8f687f3b1d711ad3")
	assert.NotEqual(t, v1.statements, v2.statements)
	assert.NotEqual(t, v1.objects, v2.objects)
	assert.NotEqual(t, v1.metadataKeys, v2.metadataKeys)
}

func TestSchemaInventoryCollectionsAreDetached(t *testing.T) {
	v1, err := schemaInventoryForVersion(1)
	require.NoError(t, err)
	v2, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	require.Len(t, v1.statements, 6)
	require.Len(t, v1.metadataKeys, 5)
	require.Contains(t, v1.objects, "store_meta")
	require.Len(t, v2.statements, 17)
	require.Len(t, v2.metadataKeys, 7)
	require.Contains(t, v2.objects, "payload_objects")

	v1.statements[0] = "mutated v1 statement"
	v1.metadataKeys[0] = "mutated v1 key"
	v1.objects["store_meta"] = "index"
	delete(v1.objects, "cache_records")
	assertSchemaInventoryGolden(t, v2, 17, expectedSchemaV2Objects(), expectedSchemaV2MetadataKeys(), "32277ef36c51acb9115f9ece47c2917bd4f75ad9e4e8f1fa8f687f3b1d711ad3")

	freshV1, err := schemaInventoryForVersion(1)
	require.NoError(t, err)
	assertSchemaInventoryGolden(t, freshV1, 6, expectedSchemaV1Objects(), expectedSchemaV1MetadataKeys(), "7d3cb30f9344c9e994a6ba4f9f92cd4a58ca75ab5f6c9ecbf7c9a976caf38b89")

	v2.statements[0] = "mutated v2 statement"
	v2.metadataKeys[0] = "mutated v2 key"
	v2.objects["publication_attempts_order"] = "table"
	delete(v2.objects, "payload_objects_basename")
	assertSchemaInventoryGolden(t, freshV1, 6, expectedSchemaV1Objects(), expectedSchemaV1MetadataKeys(), "7d3cb30f9344c9e994a6ba4f9f92cd4a58ca75ab5f6c9ecbf7c9a976caf38b89")

	freshV2, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	assertSchemaInventoryGolden(t, freshV2, 17, expectedSchemaV2Objects(), expectedSchemaV2MetadataKeys(), "32277ef36c51acb9115f9ece47c2917bd4f75ad9e4e8f1fa8f687f3b1d711ad3")
}

func TestSchemaInventoryRejectsUnsupportedVersions(t *testing.T) {
	for _, version := range []int{-1, 0, 4, int(^uint(0) >> 1)} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			inventory, err := schemaInventoryForVersion(version)
			assert.Equal(t, schemaInventory{}, inventory)
			require.ErrorIs(t, err, errSchemaMismatch)
		})
	}
}

func TestSchema3StoreCreationAndRecognition(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	store, directory := newStore(t, f)
	if store != nil {
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
	}
	require.NotNil(t, store)
	require.Equal(t, 3, store.schemaVersion)
	require.NoError(t, checkSchema(ctx, store.conn))
	createdObjects, _, err := readSchemaObjects(ctx, store.conn)
	require.NoError(t, err)
	require.Equal(t, expectedSchemaV3Objects(), createdObjects)
	require.Len(t, createdObjects, 18)
	createdKeys, err := readMetadataKeys(ctx, store.conn)
	require.NoError(t, err)
	require.Len(t, createdKeys, 7)
	require.Equal(t, expectedSchemaV2MetadataKeys(), createdKeys)
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))

	var version int
	require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
	require.Equal(t, 3, version)
	probe, err := probeSchema(filepath.Join(directory, "publication.db"), f.binding, store.limits, store.attemptLimits)
	require.NoError(t, err)
	require.True(t, probe.recognized)
	require.False(t, probe.initial)
	require.Equal(t, 3, probe.version)

	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	require.NotNil(t, reopened)
	require.Equal(t, 3, reopened.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, reopened.conn))
	require.NoError(t, checkSchema(ctx, reopened.conn))
	reopenedObjects, _, err := readSchemaObjects(ctx, reopened.conn)
	require.NoError(t, err)
	require.Len(t, reopenedObjects, 18)
	require.Equal(t, expectedSchemaV3Objects(), reopenedObjects)
	reopenedKeys, err := readMetadataKeys(ctx, reopened.conn)
	require.NoError(t, err)
	require.Len(t, reopenedKeys, 7)
	require.Equal(t, expectedSchemaV2MetadataKeys(), reopenedKeys)
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, reopened.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, reopened.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.NoError(t, reopened.Close())
}

func TestOpenRefusesUnsupportedSchemaVersion(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	store, directory := newStore(t, f)
	require.NotNil(t, store)
	defer func() { assert.NoError(t, store.Close()) }()

	beforeObjects, beforeDefinitions, err := readSchemaObjects(ctx, store.conn)
	require.NoError(t, err)
	beforeRows := readAttemptLogicalRows(t, store)
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	_, err = store.conn.ExecContext(ctx, "PRAGMA user_version=4")
	require.NoError(t, err)
	require.NoError(t, store.Close())

	opened, err := Open(directory, f.binding)
	if opened != nil {
		assert.NoError(t, opened.Close())
	}
	require.Nil(t, opened)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)

	readOnly, err := sql.Open("sqlite", dbDSN(filepath.Join(directory, "publication.db"), true))
	require.NoError(t, err)
	defer func() { assert.NoError(t, readOnly.Close()) }()
	readOnlyConn, err := readOnly.Conn(ctx)
	require.NoError(t, err)
	defer func() { assert.NoError(t, readOnlyConn.Close()) }()

	var version int
	require.NoError(t, readOnlyConn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
	assert.Equal(t, 4, version)
	objects, definitions, err := readSchemaObjects(ctx, readOnlyConn)
	require.NoError(t, err)
	assert.Equal(t, beforeObjects, objects)
	assert.Equal(t, beforeDefinitions, definitions)
	afterRows := readAttemptLogicalRows(t, &Store{conn: readOnlyConn})
	assert.Equal(t, beforeRows, afterRows)
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, readOnlyConn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, readOnlyConn, "SELECT COUNT(*) FROM accepted_material_refs"))
}

func assertSchemaInventoryGolden(t *testing.T, inventory schemaInventory, statementCount int, expectedObjects map[string]string, expectedMetadataKeys []string, expectedStatementDigest string) {
	t.Helper()
	require.Len(t, inventory.statements, statementCount)
	require.Len(t, inventory.objects, len(expectedObjects))
	require.Len(t, inventory.metadataKeys, len(expectedMetadataKeys))
	assert.Equal(t, expectedObjects, inventory.objects)
	assert.Equal(t, expectedMetadataKeys, inventory.metadataKeys)
	digest := sha256.Sum256([]byte(strings.Join(inventory.statements, "\x00") + "\x00"))
	assert.Equal(t, expectedStatementDigest, hex.EncodeToString(digest[:]))
}

func expectedSchemaV1Objects() map[string]string {
	return map[string]string{
		"store_meta":         "table",
		"cache_records":      "table",
		"cache_observations": "table",
		"accepted_records":   "table",
		"accepted_events":    "table",
		"active_floor":       "table",
	}
}

func expectedSchemaV1MetadataKeys() []string {
	return []string{"binding", "database_id", "generation", "limits", "revision"}
}

func expectedSchemaV2Objects() map[string]string {
	return map[string]string{
		"store_meta":                 "table",
		"cache_records":              "table",
		"cache_observations":         "table",
		"accepted_records":           "table",
		"accepted_events":            "table",
		"active_floor":               "table",
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
}

func expectedSchemaV2MetadataKeys() []string {
	return []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"}
}

func expectedSchemaV3Objects() map[string]string {
	objects := expectedSchemaV2Objects()
	objects["accepted_material_refs"] = "table"
	return objects
}

func TestSchema3InventoryCompositionAndDetachment(t *testing.T) {
	ctx := context.Background()
	v3, err := schemaInventoryForVersion(3)
	require.NoError(t, err)
	require.Len(t, v3.statements, 18)
	require.Len(t, v3.objects, 18)
	require.Len(t, v3.metadataKeys, 7)
	freshV2, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	require.Len(t, freshV2.statements, 17)
	require.Len(t, freshV2.objects, 17)
	require.Len(t, freshV2.metadataKeys, 7)
	assertSchemaInventoryGolden(t, freshV2, 17, expectedSchemaV2Objects(), expectedSchemaV2MetadataKeys(), "32277ef36c51acb9115f9ece47c2917bd4f75ad9e4e8f1fa8f687f3b1d711ad3")
	expectedV2Statements := append([]string(nil), freshV2.statements...)
	require.Equal(t, freshV2.statements, v3.statements[:17])
	require.Equal(t, incomingMaterialSchemaStatement, v3.statements[17])
	require.Equal(t, incomingMaterialExpectedSchemaStatement, v3.statements[17])
	require.Equal(t, expectedSchemaV2MetadataKeys(), v3.metadataKeys)
	require.Equal(t, expectedSchemaV3Objects(), v3.objects)

	v3.statements[0] = "mutated v3 old-prefix statement"
	v3.statements[17] = "mutated v3 statement"
	v3.metadataKeys[0] = "mutated v3 key"
	v3.objects["accepted_material_refs"] = "index"
	delete(v3.objects, "store_meta")
	assertSchemaInventoryGolden(t, freshV2, 17, expectedSchemaV2Objects(), expectedSchemaV2MetadataKeys(), "32277ef36c51acb9115f9ece47c2917bd4f75ad9e4e8f1fa8f687f3b1d711ad3")
	require.Equal(t, expectedV2Statements, freshV2.statements)
	require.Equal(t, expectedSchemaV2Objects(), freshV2.objects)
	require.Equal(t, expectedSchemaV2MetadataKeys(), freshV2.metadataKeys)
	isolated, err := schemaInventoryForVersion(3)
	require.NoError(t, err)
	require.Len(t, isolated.statements, 18)
	require.Len(t, isolated.objects, 18)
	require.Len(t, isolated.metadataKeys, 7)
	require.Equal(t, expectedV2Statements, isolated.statements[:17])
	require.Equal(t, expectedSchemaV3Objects(), isolated.objects)
	require.Equal(t, incomingMaterialSchemaStatement, isolated.statements[17])
	require.Equal(t, incomingMaterialExpectedSchemaStatement, isolated.statements[17])
	require.Equal(t, expectedSchemaV2MetadataKeys(), isolated.metadataKeys)
	freshV1, err := schemaInventoryForVersion(1)
	require.NoError(t, err)
	assertSchemaInventoryGolden(t, freshV1, 6, expectedSchemaV1Objects(), expectedSchemaV1MetadataKeys(), "7d3cb30f9344c9e994a6ba4f9f92cd4a58ca75ab5f6c9ecbf7c9a976caf38b89")
	restoredV2, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	assertSchemaInventoryGolden(t, restoredV2, 17, expectedSchemaV2Objects(), expectedSchemaV2MetadataKeys(), "32277ef36c51acb9115f9ece47c2917bd4f75ad9e4e8f1fa8f687f3b1d711ad3")
	require.Equal(t, expectedV2Statements, restoredV2.statements)

	restoredV2.statements[0] = "mutated independent v2 statement"
	restoredV2.metadataKeys[0] = "mutated independent v2 key"
	restoredV2.objects["store_meta"] = "index"
	require.Len(t, isolated.statements, 18)
	require.Len(t, isolated.objects, 18)
	require.Len(t, isolated.metadataKeys, 7)
	require.Equal(t, expectedV2Statements, isolated.statements[:17])
	require.Equal(t, incomingMaterialExpectedSchemaStatement, isolated.statements[17])
	require.Equal(t, expectedSchemaV2MetadataKeys(), isolated.metadataKeys)
	require.Equal(t, expectedSchemaV3Objects(), isolated.objects)
	composed, err := schemaInventoryForVersion(3)
	require.NoError(t, err)
	require.Len(t, composed.statements, 18)
	require.Len(t, composed.objects, 18)
	require.Len(t, composed.metadataKeys, 7)
	againV2, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	assertSchemaInventoryGolden(t, againV2, 17, expectedSchemaV2Objects(), expectedSchemaV2MetadataKeys(), "32277ef36c51acb9115f9ece47c2917bd4f75ad9e4e8f1fa8f687f3b1d711ad3")
	require.Equal(t, expectedV2Statements, againV2.statements)
	require.Equal(t, againV2.statements, composed.statements[:17])
	require.Equal(t, expectedV2Statements, composed.statements[:17])
	require.Equal(t, incomingMaterialExpectedSchemaStatement, composed.statements[17])
	require.Equal(t, againV2.metadataKeys, composed.metadataKeys)
	require.Equal(t, expectedSchemaV2MetadataKeys(), composed.metadataKeys)
	require.Equal(t, expectedSchemaV3Objects(), composed.objects)

	f := newFixture(t, BackendPublicRepo)
	store, _ := newStore(t, f)
	if store != nil {
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
	}
	require.NotNil(t, store)
	require.Equal(t, 3, store.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
	require.NoError(t, checkSchema(ctx, store.conn))
	require.NoError(t, checkSchemaVersion(ctx, store.conn, 3))
	require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, store.conn))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.NoError(t, store.Close())
}
