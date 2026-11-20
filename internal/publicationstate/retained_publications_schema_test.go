package publicationstate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

func retainedPublicationsSixColumnRows(t *testing.T, ctx context.Context, q queryer) [][]any {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT record_cid,attempt_id,sequence,blob_cid,size,accepted_revision FROM retained_publications ORDER BY record_cid")
	require.NoError(t, err)
	result := make([][]any, 0)
	for rows.Next() {
		values := make([]any, 6)
		destinations := make([]any, len(values))
		for index := range values {
			destinations[index] = &values[index]
		}
		require.NoError(t, rows.Scan(destinations...))
		result = append(result, values)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	return result
}

func TestRetainedPublicationsSchema3Constraints(t *testing.T) {
	ctx := context.Background()
	f := manifestFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	attempt := stageManifestAttempt(t, store, f, f.view(), attemptReview())
	require.Len(t, attempt.Manifest.Entries, 3)
	cid, err := publication.RawPayloadCID(f.entries[0].Content)
	require.NoError(t, err)
	size := int64(len(f.entries[0].Content))
	manifest, err := encodeRetainedManifest(attempt.Manifest)
	require.NoError(t, err)
	recordCID := attempt.SnapshotRecordCID
	attemptID := attempt.ID[:]

	insert := func(t *testing.T, statement string, args ...any) error {
		t.Helper()
		_, err := store.conn.ExecContext(ctx, statement, args...)
		return err
	}
	reset := func(t *testing.T) {
		t.Helper()
		require.NoError(t, insert(t, "DELETE FROM retained_publications"))
	}

	t.Run("packed default form", func(t *testing.T) {
		reset(t)
		require.NoError(t, insert(
			t,
			"INSERT INTO retained_publications(record_cid,attempt_id,sequence,blob_cid,size,accepted_revision) VALUES(?,?,0,?,?,1)",
			recordCID,
			attemptID,
			cid,
			size,
		))
		var form string
		var manifestValue any
		require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT form,manifest FROM retained_publications").Scan(&form, &manifestValue))
		assert.Equal(t, string(PayloadFormPacked), form)
		assert.Nil(t, manifestValue)
	})

	t.Run("packed explicit form", func(t *testing.T) {
		reset(t)
		require.NoError(t, insert(
			t,
			"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'packed',?,?,NULL,1)",
			recordCID,
			attemptID,
			cid,
			size,
		))
	})

	t.Run("manifest form", func(t *testing.T) {
		reset(t)
		require.NoError(t, insert(
			t,
			"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'manifest',NULL,NULL,?,1)",
			recordCID,
			attemptID,
			manifest,
		))
	})

	refusals := []struct {
		name      string
		statement string
		args      []any
	}{
		{
			name:      "packed form with a manifest",
			statement: "INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'packed',?,?,?,1)",
			args:      []any{recordCID, attemptID, cid, size, manifest},
		},
		{
			name:      "packed form without packed bytes",
			statement: "INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'packed',NULL,NULL,NULL,1)",
			args:      []any{recordCID, attemptID},
		},
		{
			name:      "packed form without a size",
			statement: "INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'packed',?,NULL,NULL,1)",
			args:      []any{recordCID, attemptID, cid},
		},
		{
			name:      "manifest form with packed bytes",
			statement: "INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'manifest',?,?,?,1)",
			args:      []any{recordCID, attemptID, cid, size, manifest},
		},
		{
			name:      "manifest form with a size",
			statement: "INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'manifest',NULL,?,?,1)",
			args:      []any{recordCID, attemptID, size, manifest},
		},
		{
			name:      "manifest form without a manifest",
			statement: "INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'manifest',NULL,NULL,NULL,1)",
			args:      []any{recordCID, attemptID},
		},
		{
			name:      "unknown form",
			statement: "INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,0,'hybrid',NULL,NULL,?,1)",
			args:      []any{recordCID, attemptID, manifest},
		},
	}
	for _, refusal := range refusals {
		t.Run(refusal.name, func(t *testing.T) {
			reset(t)
			require.Error(t, insert(t, refusal.statement, refusal.args...))
			var count int64
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&count))
			assert.Zero(t, count)
		})
	}
}

func TestRetainedPublicationsUpgradeRebuildsTheSchema3Table(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	t.Run("committed upgrade", func(t *testing.T) {
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		require.Equal(t, 2, store.schemaVersion)
		before := retainedPublicationsSixColumnRows(t, ctx, store.conn)
		require.Len(t, before, 1)
		source, err := readIncomingMaterialUpgradeSource(
			ctx,
			store.conn,
			2,
			f.binding,
			DefaultLimits(),
			DefaultAttemptLimits(),
		)
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, nil))
		require.NoError(t, tx.Commit())
		directory := store.directory
		require.NoError(t, store.Close())

		reopened, err := Open(directory, f.binding)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		require.Equal(t, 3, reopened.schemaVersion)
		require.NoError(t, checkSchemaVersion(ctx, reopened.conn, 3))
		require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, reopened.conn))
		objects, definitions, err := readSchemaObjects(ctx, reopened.conn)
		require.NoError(t, err)
		assert.Equal(t, "table", objects["retained_publications"])
		assert.Equal(t, schema3RetainedPublicationsStatement, strings.TrimSpace(definitions["retained_publications"]))
		assert.NotContains(t, objects, retainedPublicationsSchema2ScratchTable)
		assert.Equal(t, before, retainedPublicationsSixColumnRows(t, ctx, reopened.conn))
		incomingMaterialUpgradeFixtureRequirePackedRetained(t, ctx, reopened.conn)
		assert.Zero(t, incomingMaterialUpgradeCount(t, ctx, reopened.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, reopened.conn)
	})

	t.Run("rolled back upgrade", func(t *testing.T) {
		f, store, _, _ := incomingMaterialUpgradePopulatedSource(t, ctx)
		before := retainedPublicationsSixColumnRows(t, ctx, store.conn)
		require.Len(t, before, 1)
		source, err := readIncomingMaterialUpgradeSource(
			ctx,
			store.conn,
			2,
			f.binding,
			DefaultLimits(),
			DefaultAttemptLimits(),
		)
		require.NoError(t, err)
		tx := incomingMaterialUpgradeTx(t, ctx, store.conn)
		require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, nil))
		require.NoError(t, tx.Rollback())
		objects, definitions, err := readSchemaObjects(ctx, store.conn)
		require.NoError(t, err)
		assert.Equal(t, incomingMaterialUpgradeFixtureSchema2RetainedDDL(), strings.TrimSpace(definitions["retained_publications"]))
		assert.NotContains(t, objects, retainedPublicationsSchema2ScratchTable)
		assert.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
		require.NoError(t, checkSchemaVersion(ctx, store.conn, 2))
		assert.Equal(t, before, retainedPublicationsSixColumnRows(t, ctx, store.conn))
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, store.conn)
	})
}
