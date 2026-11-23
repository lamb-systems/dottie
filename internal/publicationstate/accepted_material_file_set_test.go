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

type fileSetMaterialFile struct {
	path    string
	mode    uint32
	content string
}

func fileSetMaterialFiles(t *testing.T, files ...fileSetMaterialFile) []fileSetMaterialFile {
	t.Helper()
	sorted := slices.Clone(files)
	slices.SortFunc(sorted, func(left, right fileSetMaterialFile) int {
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

func fileSetMaterialBlock(
	t *testing.T,
	binding Binding,
	sequence uint64,
	parent []byte,
	files []fileSetMaterialFile,
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
		Targets:        fileSetTestTargets(),
	}
	binary.BigEndian.PutUint64(record.PublicationID[8:], sequence+1)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return SnapshotBlock{Key: key, Raw: raw}
}

func fileSetMaterialChain(
	t *testing.T,
	binding Binding,
	sequences int,
	filesPerSequence [][]fileSetMaterialFile,
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
		blocks = append(blocks, fileSetMaterialBlock(t, binding, uint64(index), parent, filesPerSequence[index]))
	}
	return blocks
}

func fileSetMaterialObservation(t *testing.T, binding Binding, blocks ...SnapshotBlock) Observation {
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

func fileSetMaterialInput(files []fileSetMaterialFile) MaterialInput {
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

func fileSetMaterialAccept(
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
	fileSetBytes, err := encodeRetainedFileSet(&FileSetPayload{Entries: []PayloadEntryReference{{
		Path: "init.lua", CID: floor.BlobCID, Size: floor.BlobSize,
	}}})
	require.NoError(t, err)

	revision := int64(floor.Revision)
	const unionConstraint = "CHECK constraint failed: (form = 'packed' AND blob_cid IS NOT NULL AND file_set IS NULL)"
	invalid := []struct {
		name       string
		statement  string
		args       []any
		constraint string
	}{
		{
			name:       "form null",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,NULL,?,NULL)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID},
			constraint: "NOT NULL constraint failed: accepted_material_refs.form",
		},
		{
			name:       "form outside the union",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,'bogus',?,NULL)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID},
			constraint: "CHECK constraint failed: form IN ('packed','file_set')",
		},
		{
			name:       "packed with a file-set",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,'packed',?,?)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID, fileSetBytes},
			constraint: unionConstraint,
		},
		{
			name:       "packed without a blob",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,'packed',NULL,NULL)",
			args:       []any{revision, floor.RecordCID},
			constraint: unionConstraint,
		},
		{
			name:       "packed with a file-set and no blob",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,'packed',NULL,?)",
			args:       []any{revision, floor.RecordCID, fileSetBytes},
			constraint: unionConstraint,
		},
		{
			name:       "file-set with a blob",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,'file_set',?,?)",
			args:       []any{revision, floor.RecordCID, floor.BlobCID, fileSetBytes},
			constraint: unionConstraint,
		},
		{
			name:       "file-set without a file-set",
			statement:  "INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,'file_set',NULL,NULL)",
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

func TestAcceptedMaterialFileSetRefAuditRefusals(t *testing.T) {
	newFileSet := func(t *testing.T) (*Store, Floor) {
		t.Helper()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := fileSetMaterialFiles(t,
			fileSetMaterialFile{path: "config/init.lua", content: "synthetic audit alpha"},
			fileSetMaterialFile{path: "config/plugins.lua", content: "synthetic audit beta"},
		)
		observation := fileSetMaterialObservation(
			t,
			f.binding,
			fileSetMaterialBlock(t, f.binding, 0, nil, files),
		)
		floor := fileSetMaterialAccept(t, store, ModeFirstUse, observation, fileSetMaterialInput(files))
		require.NotNil(t, floor.FileSet)
		require.Len(t, floor.FileSet.Entries, 2)
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
		require.Nil(t, floor.FileSet)
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
			name:  "file-set rewritten to a different canonical file-set",
			setup: newFileSet,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				other, err := encodeRetainedFileSet(&FileSetPayload{Entries: []PayloadEntryReference{{
					Path: floor.FileSet.Entries[0].Path,
					CID:  floor.FileSet.Entries[0].CID,
					Size: floor.FileSet.Entries[0].Size,
				}}})
				require.NoError(t, err)
				expected, err := encodeRetainedFileSet(floor.FileSet)
				require.NoError(t, err)
				require.NotEqual(t, expected, other)
				_, err = tx.ExecContext(
					ctx,
					"UPDATE accepted_material_refs SET file_set=? WHERE accepted_revision=?",
					other,
					int64(floor.Revision),
				)
				require.NoError(t, err)
				require.Zero(t, b8Count(
					t,
					ctx,
					tx,
					"SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=? AND file_set=?",
					int64(floor.Revision),
					expected,
				))
			},
		},
		{
			name:  "file-set ref form flipped to packed",
			setup: newFileSet,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				_, err := tx.ExecContext(
					ctx,
					"UPDATE accepted_material_refs SET form='packed',blob_cid=?,file_set=NULL WHERE accepted_revision=?",
					floor.FileSet.Entries[1].CID,
					int64(floor.Revision),
				)
				require.NoError(t, err)
			},
		},
		{
			name:  "packed ref form flipped to file-set",
			setup: newPacked,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				fileSetBytes, err := encodeRetainedFileSet(&FileSetPayload{Entries: []PayloadEntryReference{{
					Path: "init.lua",
					CID:  floor.BlobCID,
					Size: floor.BlobSize,
				}}})
				require.NoError(t, err)
				_, err = tx.ExecContext(
					ctx,
					"UPDATE accepted_material_refs SET form='file_set',blob_cid=NULL,file_set=? WHERE accepted_revision=?",
					fileSetBytes,
					int64(floor.Revision),
				)
				require.NoError(t, err)
			},
		},
		{
			name:  "file-set entry catalog row removed",
			setup: newFileSet,
			mutate: func(t *testing.T, ctx context.Context, tx *sql.Tx, floor Floor) {
				t.Helper()
				result, err := tx.ExecContext(
					ctx,
					"DELETE FROM payload_objects WHERE blob_cid=?",
					floor.FileSet.Entries[1].CID,
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
					store.checkIncomingFileSetCatalog(
						ctx,
						tx,
						floor.FileSet,
						StageLoad,
						make(fileSetCatalogCache),
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

func TestSchema3MigrationCreatesAcceptedMaterialFileSetUnion(t *testing.T) {
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
	assert.Equal(t, []string{"accepted_revision", "record_cid", "form", "blob_cid", "file_set"}, columns)
	require.NoError(t, checkSchemaVersion(ctx, migrated.conn, 3))
}

func TestReadAcceptedMaterialFinalizedFileSet(t *testing.T) {
	ctx := context.Background()
	fileSetFixtureValue := fileSetFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: fileSetFixtureValue.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	review := attemptReview()
	submitted := submitFileSetAttempt(t, store, fileSetFixtureValue, fileSetFixtureValue.view(), review)
	finalized, err := store.FinalizeAttempt(
		ctx,
		submitted.ID,
		submitted.StateDigest,
		fileSetFixtureValue.currentView(),
	)
	require.NoError(t, err)

	material, err := store.ReadAcceptedMaterial(ctx, fileSetFixtureValue.binding, finalized.Floor)
	require.NoError(t, err)
	assert.Equal(t, finalized.Floor, material.Floor)
	assert.Equal(t, fileSetFixtureValue.raw, material.SnapshotRecord)
	assert.Empty(t, material.Payload)
	require.Len(t, material.Entries, len(fileSetFixtureValue.entries))
	for index, entry := range fileSetFixtureValue.entries {
		assert.Equal(t, entry.Path, material.Entries[index].Path)
		assert.Equal(t, entry.Mode, material.Entries[index].Mode)
		assert.Equal(t, entry.Content, material.Entries[index].Content)
	}
	for _, entry := range fileSetFixtureValue.entries {
		_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName, payloadBasename(entry.Content)))
		assert.NoError(t, statErr)
	}
}

func TestReadAcceptedMaterialIncomingFileSet(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := fileSetMaterialFiles(t,
		fileSetMaterialFile{path: "config/init.lua", content: "synthetic file-set init"},
		fileSetMaterialFile{path: "config/plugins.lua", mode: 0o644, content: "synthetic file-set plugins"},
	)
	block := fileSetMaterialBlock(t, f.binding, 0, nil, files)
	observation := fileSetMaterialObservation(t, f.binding, block)
	floor := fileSetMaterialAccept(t, store, ModeFirstUse, observation, fileSetMaterialInput(files))
	require.NotNil(t, floor.FileSet)
	assert.Empty(t, floor.BlobCID)
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs WHERE form='file_set'"))

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	assert.Equal(t, floor, material.Floor)
	assert.Equal(t, block.Raw, material.SnapshotRecord)
	assert.Empty(t, material.Payload)
	require.Len(t, material.Entries, 2)
	assert.Equal(t, "config/init.lua", material.Entries[0].Path)
	assert.Equal(t, uint32(0o600), material.Entries[0].Mode)
	assert.Equal(t, []byte("synthetic file-set init"), material.Entries[0].Content)
	assert.Equal(t, "config/plugins.lua", material.Entries[1].Path)
	assert.Equal(t, uint32(0o644), material.Entries[1].Mode)
	assert.Equal(t, []byte("synthetic file-set plugins"), material.Entries[1].Content)
	for _, file := range files {
		_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(file.content))))
		assert.NoError(t, statErr)
	}
}

func TestReadAcceptedMaterialFileSetRecordAboveThePackedCeiling(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := make([]fileSetMaterialFile, 0, 8)
	for index := range 8 {
		files = append(files, fileSetMaterialFile{
			path:    strings.Repeat(string(rune('a'+index)), 1024),
			content: "synthetic oversized file-set entry " + string(rune('a'+index)),
		})
	}
	sorted := fileSetMaterialFiles(t, files...)
	block := fileSetMaterialBlock(t, f.binding, 0, nil, sorted)
	require.Greater(t, len(block.Raw), publication.MaxRecordBytes)
	require.LessOrEqual(t, len(block.Raw), publication.MaxFileSetRecordBytes)
	observation := fileSetMaterialObservation(t, f.binding, block)
	floor := fileSetMaterialAccept(t, store, ModeFirstUse, observation, fileSetMaterialInput(sorted))
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	require.Len(t, material.Entries, len(sorted))
	for index, file := range sorted {
		assert.Equal(t, file.path, material.Entries[index].Path)
		assert.Equal(t, []byte(file.content), material.Entries[index].Content)
	}
}

func TestReadAcceptedMaterialFileSetOwnerSelection(t *testing.T) {
	t.Run("neither owner", func(t *testing.T) {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := fileSetMaterialFiles(t, fileSetMaterialFile{path: "init.lua", content: "synthetic file-set material"})
		observation := fileSetMaterialObservation(
			t,
			f.binding,
			fileSetMaterialBlock(t, f.binding, 0, nil, files),
		)
		floor := fileSetMaterialAccept(t, store, ModeFirstUse, observation, fileSetMaterialInput(files))
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
			"INSERT INTO accepted_material_refs(accepted_revision,record_cid,form,blob_cid,file_set) VALUES(?,?,'packed',?,NULL)",
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

func TestReadAcceptedMaterialFileSetSharedCIDReturnsEachSnapshotMode(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := fileSetMaterialFiles(t,
		fileSetMaterialFile{path: "config/private.lua", mode: 0o600, content: "synthetic shared file-set content"},
		fileSetMaterialFile{path: "config/shared.lua", mode: 0o644, content: "synthetic shared file-set content"},
	)
	observation := fileSetMaterialObservation(
		t,
		f.binding,
		fileSetMaterialBlock(t, f.binding, 0, nil, files),
	)
	floor := fileSetMaterialAccept(t, store, ModeFirstUse, observation, fileSetMaterialInput(files))
	require.NotNil(t, floor.FileSet)
	require.Len(t, floor.FileSet.Entries, 2)
	assert.Equal(t, floor.FileSet.Entries[0].CID, floor.FileSet.Entries[1].CID)
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	require.Len(t, material.Entries, 2)
	assert.Equal(t, uint32(0o600), material.Entries[0].Mode)
	assert.Equal(t, uint32(0o644), material.Entries[1].Mode)
	assert.Equal(t, material.Entries[0].Content, material.Entries[1].Content)
}

func TestReadAcceptedMaterialFileSetRefusesDamagedSelectedFiles(t *testing.T) {
	newStoreWithFileSet := func(t *testing.T) (*Store, Floor, string, []fileSetMaterialFile) {
		t.Helper()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := fileSetMaterialFiles(t,
			fileSetMaterialFile{path: "config/init.lua", content: "synthetic first selected entry"},
			fileSetMaterialFile{path: "config/plugins.lua", content: "synthetic second selected entry"},
		)
		observation := fileSetMaterialObservation(
			t,
			f.binding,
			fileSetMaterialBlock(t, f.binding, 0, nil, files),
		)
		floor := fileSetMaterialAccept(t, store, ModeFirstUse, observation, fileSetMaterialInput(files))
		return store, floor, directory, files
	}

	t.Run("missing", func(t *testing.T) {
		store, floor, directory, files := newStoreWithFileSet(t)
		require.NoError(t, os.Remove(filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(files[1].content)))))
		material, err := store.ReadAcceptedMaterial(context.Background(), store.binding, floor)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialMissing)
	})

	t.Run("corrupt", func(t *testing.T) {
		store, floor, directory, files := newStoreWithFileSet(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(files[1].content)))
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(files[1].content)), 0o600))
		material, err := store.ReadAcceptedMaterial(context.Background(), store.binding, floor)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialCorrupt)
	})

	t.Run("unsafe", func(t *testing.T) {
		store, floor, directory, files := newStoreWithFileSet(t)
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
