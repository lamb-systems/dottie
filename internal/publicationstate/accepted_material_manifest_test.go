package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/lamb-systems/dottie/internal/publication"
)

type manifestMaterialFile struct {
	path    string
	mode    uint32
	content string
}

func manifestMaterialFiles(t *testing.T, files ...manifestMaterialFile) []manifestMaterialFile {
	t.Helper()
	sorted := slices.Clone(files)
	slices.SortFunc(sorted, func(left, right manifestMaterialFile) int {
		return strings.Compare(left.path, right.path)
	})
	for index, file := range sorted {
		require.NotEmpty(t, file.path)
		require.NotEmpty(t, file.content)
		if index > 0 {
			require.NotEqual(t, sorted[index-1].path, file.path)
		}
		mode := file.mode
		if mode == 0 {
			mode = 0o600
		}
		require.Contains(t, []uint32{0o600, 0o644}, mode)
		sorted[index].mode = mode
	}
	return sorted
}

func manifestMaterialBlock(
	t *testing.T,
	binding Binding,
	sequence uint64,
	parent []byte,
	files []manifestMaterialFile,
) SnapshotBlock {
	t.Helper()
	entries := make([]publication.SnapshotEntry, 0, len(files))
	for _, file := range files {
		cid, err := publication.RawPayloadCID([]byte(file.content))
		require.NoError(t, err)
		entries = append(entries, publication.SnapshotEntry{
			Path: file.path,
			Mode: file.mode,
			Size: uint64(len(file.content)),
			Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{
				CID:      cid,
				Size:     uint64(len(file.content)),
				MIMEType: publication.BlobMIMEType,
			},
		})
	}
	record := publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: sequence,
		Parent:         parent,
		Entries:        entries,
	}
	binary.BigEndian.PutUint64(record.PublicationID[8:], sequence+1)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return SnapshotBlock{Key: key, Raw: raw}
}

func manifestMaterialChain(
	t *testing.T,
	binding Binding,
	sequences int,
	filesPerSequence [][]manifestMaterialFile,
) []SnapshotBlock {
	t.Helper()
	require.Equal(t, sequences, len(filesPerSequence))
	blocks := make([]SnapshotBlock, 0, sequences)
	for index := range sequences {
		var parent []byte
		if index > 0 {
			cid, err := publication.RecordCID(blocks[index-1].Raw)
			require.NoError(t, err)
			parent = cid
		}
		blocks = append(blocks, manifestMaterialBlock(t, binding, uint64(index), parent, filesPerSequence[index]))
	}
	return blocks
}

func manifestMaterialObservation(t *testing.T, binding Binding, blocks ...SnapshotBlock) Observation {
	t.Helper()
	require.NotEmpty(t, blocks)
	terminal := blocks[len(blocks)-1]
	record, err := publication.DecodeSnapshot(terminal.Raw)
	require.NoError(t, err)
	cid, err := publication.RecordCID(terminal.Raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: record.PublicationSeq,
		SnapshotCID:    cid,
	})
	require.NoError(t, err)
	snapshots := make([]SnapshotBlock, 0, len(blocks))
	for _, block := range blocks {
		snapshots = append(snapshots, SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)})
	}
	return Observation{
		Origin:          binding,
		SuppliedContext: SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}},
		Head:            head,
		Snapshots:       snapshots,
	}
}

func manifestMaterialInput(files []manifestMaterialFile) MaterialInput {
	entries := make([]publication.PayloadEntry, 0, len(files))
	for _, file := range files {
		entries = append(entries, publication.PayloadEntry{
			Path:    file.path,
			Mode:    file.mode,
			Size:    uint64(len(file.content)),
			Content: []byte(file.content),
		})
	}
	return MaterialInput{Entries: entries}
}

func manifestMaterialAccept(
	t *testing.T,
	store *Store,
	mode Mode,
	observation Observation,
	input MaterialInput,
) Floor {
	t.Helper()
	ctx := context.Background()
	proposal, err := store.PrepareMaterial(ctx, mode, observation, input)
	require.NoError(t, err)
	confirmation := proposal.Confirmation
	if mode == ModeAdvance {
		confirmation = [32]byte{}
	}
	floor, err := store.AcceptMaterialInput(ctx, mode, proposal.StateToken, observation, input, confirmation)
	require.NoError(t, err)
	return floor
}

func TestAcceptedMaterialSchemaFormUnionConstraints(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.AcceptMaterial(
		ctx,
		ModeFirstUse,
		proposal.StateToken,
		observation,
		f.payload,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	manifestBytes, err := encodeRetainedManifest(&ManifestPayload{Entries: []PayloadEntryReference{{
		Path: "init.lua", CID: floor.BlobCID, Size: floor.BlobSize,
	}}})
	require.NoError(t, err)

	revision := int64(floor.Revision)
	const unionConstraint = "CHECK constraint failed: (form = 'packed' AND blob_cid IS NOT NULL AND manifest IS NULL)"
	invalid := []struct {
		name       string
		statement  string
		args       []any
		constraint string
	}{
		{
			name:       "form null",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,NULL,?,NULL)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID},
			constraint: "NOT NULL constraint failed: accepted_material_refs.form",
		},
		{
			name:       "form outside the union",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'bogus',?,NULL)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID},
			constraint: "CHECK constraint failed: form IN ('packed','manifest')",
		},
		{
			name:       "packed with a manifest",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'packed',?,?)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID, manifestBytes},
			constraint: unionConstraint,
		},
		{
			name:       "packed without a blob",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'packed',NULL,NULL)",
			args:       []any{revision, floor.RecordCID},
			constraint: unionConstraint,
		},
		{
			name:       "packed with a manifest and no blob",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'packed',NULL,?)",
			args:       []any{revision, floor.RecordCID, manifestBytes},
			constraint: unionConstraint,
		},
		{
			name:       "manifest with a blob",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'manifest',?,?)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID, manifestBytes},
			constraint: unionConstraint,
		},
		{
			name:       "manifest without a manifest",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'manifest',NULL,NULL)",
			args:       []any{revision, floor.RecordCID},
			constraint: unionConstraint,
		},
	}
	tx, txContext := incomingMaterialTransaction(t, store, false)
	_, err = tx.ExecContext(txContext, "DELETE FROM accepted_material_refs")
	require.NoError(t, err)
	require.Equal(t, int64(1), b8Count(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events"))
	require.NotZero(t, b8Count(t, txContext, tx, "SELECT COUNT(*) FROM accepted_records"))
	require.Equal(t, int64(1), b8Count(t, txContext, tx, "SELECT COUNT(*) FROM payload_objects"))
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := tx.ExecContext(txContext, "SAVEPOINT refused_ref")
			require.NoError(t, err)
			_, execErr := tx.ExecContext(txContext, test.statement, test.args...)
			require.Error(t, execErr)
			assert.Contains(t, execErr.Error(), test.constraint)
			_, err = tx.ExecContext(txContext, "ROLLBACK TO refused_ref")
			require.NoError(t, err)
			_, err = tx.ExecContext(txContext, "RELEASE refused_ref")
			require.NoError(t, err)
			require.Zero(t, b8Count(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		})
	}
	_, err = tx.ExecContext(
		txContext,
		"INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)",
		revision,
		floor.RecordCID,
		floor.BlobCID,
	)
	require.NoError(t, err)
	var form string
	require.NoError(t, tx.QueryRowContext(
		txContext,
		"SELECT form FROM accepted_material_refs WHERE accepted_revision=?",
		revision,
	).Scan(&form))
	assert.Equal(t, string(PayloadFormPacked), form)
	incomingMaterialRollback(t, txContext, store, tx)
}

func TestAcceptedMaterialManifestRefAuditRefusals(t *testing.T) {
	newManifest := func(t *testing.T) (*Store, Floor) {
		t.Helper()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/init.lua", content: "synthetic audit alpha"},
			manifestMaterialFile{path: "config/plugins.lua", content: "synthetic audit beta"},
		)
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, files),
		)
		floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
		require.NotNil(t, floor.Manifest)
		require.Len(t, floor.Manifest.Entries, 2)
		return store, floor
	}
	newPacked := func(t *testing.T) (*Store, Floor) {
		t.Helper()
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		observation := f.observation(1)
		proposal := prepareFirstUse(t, store, observation, f.payload)
		floor, err := store.AcceptMaterial(
			ctx,
			ModeFirstUse,
			proposal.StateToken,
			observation,
			f.payload,
			proposal.Confirmation,
		)
		require.NoError(t, err)
		require.Nil(t, floor.Manifest)
		require.NotEmpty(t, floor.BlobCID)
		return store, floor
	}
	cases := []struct {
		name   string
		setup  func(t *testing.T) (*Store, Floor)
		mutate func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor)
		detail func(t *testing.T, store *Store, ctx context.Context, tx *sql.Tx, floor Floor)
	}{
		{
			name:  "manifest rewritten to a different canonical manifest",
			setup: newManifest,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				other, err := encodeRetainedManifest(&ManifestPayload{Entries: []PayloadEntryReference{{
					Path: floor.Manifest.Entries[0].Path,
					CID:  floor.Manifest.Entries[0].CID,
					Size: floor.Manifest.Entries[0].Size,
				}}})
				require.NoError(t, err)
				expected, err := encodeRetainedManifest(floor.Manifest)
				require.NoError(t, err)
				require.NotEqual(t, expected, other)
				_, err = tx.ExecContext(
					ctx,
					"UPDATE accepted_material_refs SET manifest=? WHERE accepted_revision=?",
					other,
					int64(floor.Revision),
				)
				require.NoError(t, err)
				require.Zero(t, b8Count(
					t,
					ctx,
					tx,
					"SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=? AND manifest=?",
					int64(floor.Revision),
					expected,
				))
			},
		},
		{
			name:  "manifest ref form flipped to packed",
			setup: newManifest,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				_, err := tx.ExecContext(
					ctx,
					"UPDATE accepted_material_refs SET form='packed',blob_cid=?,manifest=NULL WHERE accepted_revision=?",
					floor.Manifest.Entries[1].CID,
					int64(floor.Revision),
				)
				require.NoError(t, err)
			},
		},
		{
			name:  "packed ref form flipped to manifest",
			setup: newPacked,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				manifestBytes, err := encodeRetainedManifest(&ManifestPayload{Entries: []PayloadEntryReference{{
					Path: "init.lua",
					CID:  floor.BlobCID,
					Size: floor.BlobSize,
				}}})
				require.NoError(t, err)
				_, err = tx.ExecContext(
					ctx,
					"UPDATE accepted_material_refs SET form='manifest',blob_cid=NULL,manifest=? WHERE accepted_revision=?",
					manifestBytes,
					int64(floor.Revision),
				)
				require.NoError(t, err)
			},
		},
		{
			name:  "manifest entry catalog row removed",
			setup: newManifest,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				result, err := tx.ExecContext(
					ctx,
					"DELETE FROM payload_objects WHERE blob_cid=?",
					floor.Manifest.Entries[1].CID,
				)
				require.NoError(t, err)
				deleted, err := result.RowsAffected()
				require.NoError(t, err)
				require.Equal(t, int64(1), deleted)
			},
			detail: func(t *testing.T, store *Store, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				requireErrorMetadata(
					t,
					store.checkIncomingManifestCatalog(
						ctx,
						tx,
						floor.Manifest,
						StageLoad,
						make(manifestCatalogCache),
					),
					ErrSchema,
					StageLoad,
					ReasonCorrupt,
				)
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store, floor := test.setup(t)
			tx, txContext := incomingMaterialTransaction(t, store, false)
			test.mutate(t, txContext, tx, floor)
			incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
			_, err := store.readState(txContext, tx, StageLoad)
			requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
			if test.detail != nil {
				test.detail(t, store, txContext, tx, floor)
			}
			incomingMaterialRollback(t, txContext, store, tx)
		})
	}
}

func TestSchema3MigrationCreatesAcceptedMaterialManifestUnion(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	unit, directory := newSchema2UnitStore(t, f)
	require.NoError(t, unit.Close())
	options := DefaultOpenOptions()
	options.UpgradeFromAttempts = true
	migrated, err := OpenWithOptions(directory, f.binding, options)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, migrated.Close()) })
	require.Equal(t, 3, migrated.schemaVersion)
	var storedSQL string
	require.NoError(t, migrated.conn.QueryRowContext(
		ctx,
		"SELECT sql FROM sqlite_master WHERE type='table' AND name='accepted_material_refs'",
	).Scan(&storedSQL))
	assert.Equal(t, incomingMaterialSchemaStatement, strings.TrimSpace(storedSQL))
	rows, err := migrated.conn.QueryContext(ctx, "PRAGMA table_info(accepted_material_refs)")
	require.NoError(t, err)
	columns := make([]string, 0, 5)
	for rows.Next() {
		var index, notNull, primary int64
		var name, kind string
		var defaultValue any
		require.NoError(t, rows.Scan(&index, &name, &kind, &notNull, &defaultValue, &primary))
		columns = append(columns, name)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	assert.Equal(t, []string{"accepted_revision", "record_cid", "form", "blob_cid", "manifest"}, columns)
	require.NoError(t, checkSchemaVersion(ctx, migrated.conn, 3))
}

func TestReadAcceptedMaterialFinalizedManifest(t *testing.T) {
	ctx := context.Background()
	manifestFixtureValue := manifestFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: manifestFixtureValue.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	review := attemptReview()
	submitted := submitManifestAttempt(t, store, manifestFixtureValue, manifestFixtureValue.view(), review)
	finalized, err := store.FinalizeAttempt(
		ctx,
		submitted.ID,
		submitted.StateDigest,
		manifestFixtureValue.currentView(),
	)
	require.NoError(t, err)

	material, err := store.ReadAcceptedMaterial(ctx, manifestFixtureValue.binding, finalized.Floor)
	require.NoError(t, err)
	assert.Equal(t, finalized.Floor, material.Floor)
	assert.Equal(t, manifestFixtureValue.raw, material.SnapshotRecord)
	assert.Empty(t, material.Payload)
	require.Len(t, material.Entries, len(manifestFixtureValue.entries))
	for index, entry := range manifestFixtureValue.entries {
		assert.Equal(t, entry.Path, material.Entries[index].Path)
		assert.Equal(t, entry.Mode, material.Entries[index].Mode)
		assert.Equal(t, entry.Content, material.Entries[index].Content)
	}
	for _, entry := range manifestFixtureValue.entries {
		_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName, payloadBasename(entry.Content)))
		assert.NoError(t, statErr)
	}
}

func TestReadAcceptedMaterialIncomingManifest(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/init.lua", content: "synthetic manifest init"},
		manifestMaterialFile{path: "config/plugins.lua", mode: 0o644, content: "synthetic manifest plugins"},
	)
	block := manifestMaterialBlock(t, f.binding, 0, nil, files)
	observation := manifestMaterialObservation(t, f.binding, block)
	floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
	require.NotNil(t, floor.Manifest)
	assert.Empty(t, floor.BlobCID)
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs WHERE form='manifest'"))

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	assert.Equal(t, floor, material.Floor)
	assert.Equal(t, block.Raw, material.SnapshotRecord)
	assert.Empty(t, material.Payload)
	require.Len(t, material.Entries, 2)
	assert.Equal(t, "config/init.lua", material.Entries[0].Path)
	assert.Equal(t, uint32(0o600), material.Entries[0].Mode)
	assert.Equal(t, []byte("synthetic manifest init"), material.Entries[0].Content)
	assert.Equal(t, "config/plugins.lua", material.Entries[1].Path)
	assert.Equal(t, uint32(0o644), material.Entries[1].Mode)
	assert.Equal(t, []byte("synthetic manifest plugins"), material.Entries[1].Content)
	for _, file := range files {
		_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(file.content))))
		assert.NoError(t, statErr)
	}
}

func TestReadAcceptedMaterialManifestRecordAboveThePackedCeiling(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := make([]manifestMaterialFile, 0, 8)
	for index := range 8 {
		files = append(files, manifestMaterialFile{
			path:    strings.Repeat(string(rune('a'+index)), 1024),
			content: "synthetic oversized manifest entry " + string(rune('a'+index)),
		})
	}
	sorted := manifestMaterialFiles(t, files...)
	block := manifestMaterialBlock(t, f.binding, 0, nil, sorted)
	require.Greater(t, len(block.Raw), publication.MaxRecordBytes)
	require.LessOrEqual(t, len(block.Raw), publication.MaxManifestRecordBytes)
	observation := manifestMaterialObservation(t, f.binding, block)
	floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(sorted))
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	require.Len(t, material.Entries, len(sorted))
	for index, file := range sorted {
		assert.Equal(t, file.path, material.Entries[index].Path)
		assert.Equal(t, []byte(file.content), material.Entries[index].Content)
	}
}

func TestReadAcceptedMaterialManifestOwnerSelection(t *testing.T) {
	t.Run("neither owner", func(t *testing.T) {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := manifestMaterialFiles(t, manifestMaterialFile{path: "init.lua", content: "synthetic manifest material"})
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, files),
		)
		floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
		tx, txContext := incomingMaterialTransaction(t, store, false)
		_, err := tx.ExecContext(txContext, "DELETE FROM accepted_material_refs WHERE accepted_revision=?", int64(floor.Revision))
		require.NoError(t, err)
		owner, err := store.acceptedMaterialOwner(txContext, tx, floor, StageAccept)
		requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonMaterialNotRetained)
		assert.Equal(t, materialOwnership{}, owner)
		assert.Positive(t, b8Count(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events"))
		incomingMaterialRollback(t, txContext, store, tx)
	})

	t.Run("both owners", func(t *testing.T) {
		f := newFixture(t, BackendSpaces)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		candidate := attemptCandidate(f, 0)
		_, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, candidate)
		tx, txContext := incomingMaterialTransaction(t, store, false)
		_, err := tx.ExecContext(
			txContext,
			"INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,manifest) VALUES(?,?,'packed',?,NULL)",
			int64(finalized.Floor.Revision),
			finalized.Floor.RecordCID,
			finalized.Floor.BlobCID,
		)
		require.NoError(t, err)
		owner, err := store.acceptedMaterialOwner(txContext, tx, finalized.Floor, StageAccept)
		requireErrorMetadata(t, err, ErrSchema, StageAccept, ReasonCorrupt)
		assert.Equal(t, materialOwnership{}, owner)
		incomingMaterialRollback(t, txContext, store, tx)
	})
}

func TestReadAcceptedMaterialManifestSharedCIDReturnsEachSnapshotMode(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/private.lua", mode: 0o600, content: "synthetic shared manifest content"},
		manifestMaterialFile{path: "config/shared.lua", mode: 0o644, content: "synthetic shared manifest content"},
	)
	observation := manifestMaterialObservation(
		t,
		f.binding,
		manifestMaterialBlock(t, f.binding, 0, nil, files),
	)
	floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
	require.NotNil(t, floor.Manifest)
	require.Len(t, floor.Manifest.Entries, 2)
	assert.Equal(t, floor.Manifest.Entries[0].CID, floor.Manifest.Entries[1].CID)
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	require.Len(t, material.Entries, 2)
	assert.Equal(t, uint32(0o600), material.Entries[0].Mode)
	assert.Equal(t, uint32(0o644), material.Entries[1].Mode)
	assert.Equal(t, material.Entries[0].Content, material.Entries[1].Content)
}

func TestReadAcceptedMaterialManifestRefusesDamagedSelectedFiles(t *testing.T) {
	newStoreWithManifest := func(t *testing.T) (*Store, Floor, string, []manifestMaterialFile) {
		t.Helper()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/init.lua", content: "synthetic first selected entry"},
			manifestMaterialFile{path: "config/plugins.lua", content: "synthetic second selected entry"},
		)
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, files),
		)
		floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
		return store, floor, directory, files
	}

	t.Run("missing", func(t *testing.T) {
		store, floor, directory, files := newStoreWithManifest(t)
		require.NoError(t, os.Remove(filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(files[1].content)))))
		material, err := store.ReadAcceptedMaterial(context.Background(), store.binding, floor)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialMissing)
	})

	t.Run("corrupt", func(t *testing.T) {
		store, floor, directory, files := newStoreWithManifest(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(files[1].content)))
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(files[1].content)), 0o600))
		material, err := store.ReadAcceptedMaterial(context.Background(), store.binding, floor)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialCorrupt)
	})

	t.Run("unsafe", func(t *testing.T) {
		store, floor, directory, files := newStoreWithManifest(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(files[1].content)))
		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Symlink(
			filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(files[0].content))),
			path,
		))
		material, err := store.ReadAcceptedMaterial(context.Background(), store.binding, floor)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialUnsafe)
		var stat unix.Stat_t
		require.NoError(t, unix.Lstat(path, &stat))
		assert.Equal(t, uint32(unix.S_IFLNK), stat.Mode&unix.S_IFMT)
	})
}
