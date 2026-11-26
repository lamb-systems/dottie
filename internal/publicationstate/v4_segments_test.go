package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/vault"
)

func v4TableColumns(t *testing.T, store *Store, table string) map[string]string {
	t.Helper()
	rows, err := store.conn.QueryContext(context.Background(), "PRAGMA table_info("+table+")")
	require.NoError(t, err)
	defer func() { assert.NoError(t, rows.Close()) }()
	columns := make(map[string]string)
	for rows.Next() {
		var index, notNull, primary int64
		var name, kind string
		var defaultValue any
		require.NoError(t, rows.Scan(&index, &name, &kind, &notNull, &defaultValue, &primary))
		columns[name] = kind
	}
	require.NoError(t, rows.Err())
	return columns
}

func TestV4StoreSchemaShape(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	store, _ := newStore(t, f)
	defer func() { assert.NoError(t, store.Close()) }()
	ctx := context.Background()

	var version int
	require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
	assert.Equal(t, 4, version)

	assert.Equal(t,
		map[string]string{
			"record_cid": "BLOB", "attempt_id": "BLOB", "sequence": "INTEGER",
			"segments": "BLOB", "accepted_revision": "INTEGER",
		},
		v4TableColumns(t, store, "retained_publications"),
	)
	assert.Equal(t,
		map[string]string{
			"attempt_id": "BLOB", "ordinal": "INTEGER", "blob_cid": "BLOB",
		},
		v4TableColumns(t, store, "attempt_payload_refs"),
	)
	assert.Equal(t,
		map[string]string{
			"accepted_revision": "INTEGER", "record_cid": "BLOB", "segments": "BLOB",
		},
		v4TableColumns(t, store, "accepted_material_refs"),
	)
	assert.Len(t, schema4AttemptSchemaStatements, len(attemptSchemaStatements))
	assert.NotContains(t, schema4RetainedPublicationsStatement, "file_set")
	assert.Contains(t, schema4RetainedPublicationsStatement, "segments BLOB NOT NULL")
}

func TestV4RefusesAnOlderUserVersion(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	store, directory := newStore(t, f)
	require.NoError(t, store.Close())

	databasePath := filepath.Join(directory, "publication.db")
	conn, err := sql.Open("sqlite", dbDSN(databasePath, false))
	require.NoError(t, err)
	_, err = conn.ExecContext(context.Background(), "PRAGMA user_version=3")
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	_, err = Open(directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
}

func v4SettingsTarget() model.Target {
	return model.Target{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
}

func v4EntriesTarget() model.Target {
	return model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "dotfiles", Kind: model.SelectionDirectory},
	}
}

func v4PackedTarget() model.Target {
	return model.Target{
		ID: "config", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootXDGConfig, Path: "app", Kind: model.SelectionDirectory},
	}
}

func TestFloorCarriesMixedSegments(t *testing.T) {
	settings := []publication.SnapshotSetting{{
		SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "color-scheme",
		State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "prefer-dark"},
	}}
	summaries := []SegmentSummary{
		{TargetID: "config", Form: PayloadFormPacked, BlobCID: []byte{0x01, 0x55, 0x12}, BlobSize: 128},
		{TargetID: "desktop", Form: PayloadFormSettings, Settings: publication.SettingsDigest(settings)},
		{TargetID: "files", Form: PayloadFormFileSet, Entries: []PayloadEntryReference{
			{Path: "init.lua", CID: []byte{0x01, 0x55, 0x12}, Size: 4},
		}},
	}
	floor := Floor{
		DatabaseID: [32]byte{1}, Revision: 1, Generation: 1, Provenance: ProvenanceFirst,
		AnchorCID: []byte{2}, Binding: Binding{AccountDID: testDID, Repository: "at://" + testDID},
		Head: []byte{3}, SnapshotKey: "0000000000000000", RecordCID: []byte{4},
		Segments: summaries,
	}
	encoded, err := encodeFloor(floor)
	require.NoError(t, err)
	decoded, err := decodeFloor(encoded)
	require.NoError(t, err)
	assert.Equal(t, summaries, decoded.Segments)
	assert.NoError(t, validateFloorPayload(decoded))
	require.NoError(t, validateSegmentSummaries(summaries))

	for _, invalid := range [][]SegmentSummary{
		{},
		{{TargetID: "a", Form: PayloadFormPacked}},
		{{TargetID: "a", Form: PayloadFormSettings}},
	} {
		require.Error(t, validateSegmentSummaries(invalid))
	}
}

func TestRecordCarriesPerTargetSegments(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)

	contents := map[string][]byte{"init.lua": []byte("vim.opt.number = true\n")}
	entryEntries, err := publication.SnapshotEntries(model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{v4EntriesTarget()},
		Entries: []model.Entry{{
			TargetID: "files",
			File: &model.FileEntry{
				Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
				Content: contents["init.lua"], Mode: 0o600,
			},
		}},
	})
	require.NoError(t, err)
	packedSnapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{v4PackedTarget()},
		Entries: []model.Entry{{
			TargetID: "config",
			File: &model.FileEntry{
				Path: "settings.json", State: model.FilePresent, Kind: model.FileRegular,
				Content: []byte(`{"theme":"dark"}`), Mode: 0o644,
			},
		}},
	}
	packed, err := vault.Pack(packedSnapshot)
	require.NoError(t, err)
	packedCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	settings := []publication.SnapshotSetting{{
		SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "color-scheme",
		State: model.SettingPresent,
		Value: &model.VariantValue{Type: "s", Text: "prefer-dark"},
	}}
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion,
		Vault:         f.binding.Vault,
		PublicationID: [16]byte{1},
		Segments: []publication.SnapshotSegment{
			{Target: v4PackedTarget(), Form: publication.SegmentFormPacked,
				Blob: publication.BlobReference{CID: packedCID, Size: uint64(len(packed.Payload)), MIMEType: publication.SnapshotBlobMIMEType}},
			{Target: v4SettingsTarget(), Form: publication.SegmentFormSettings, Settings: settings},
			{Target: v4EntriesTarget(), Form: publication.SegmentFormEntries, Entries: entryEntries},
		},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, SnapshotCID: recordCID,
	})
	require.NoError(t, err)

	summary := summariesOfRecord(record.Segments)
	require.Len(t, summary, 3)
	assert.Equal(t, "config", summary[0].TargetID)
	assert.Equal(t, PayloadFormPacked, summary[0].Form)
	assert.Equal(t, "desktop", summary[1].TargetID)
	assert.Equal(t, PayloadFormSettings, summary[1].Form)
	assert.Equal(t, "files", summary[2].TargetID)
	assert.Equal(t, PayloadFormFileSet, summary[2].Form)

	encodedFloor, err := encodeFloor(Floor{
		DatabaseID: [32]byte{1}, Revision: 1, Generation: 1, Provenance: ProvenanceFirst,
		AnchorCID: bytes.Clone(recordCID), Binding: f.binding,
		SuppliedContext: SuppliedContext{RepositoryRevision: "r", RepositoryDigest: []byte{1, 2}},
		Head:            head, SnapshotKey: key, RecordCID: recordCID, Segments: summary,
	})
	require.NoError(t, err)
	decodedFloor, err := decodeFloor(encodedFloor)
	require.NoError(t, err)
	assert.Equal(t, summary, decodedFloor.Segments)
	assert.Equal(t, summariesOfRecord(record.Segments), decodedFloor.Segments)

	_ = contents
}

func TestCandidateSettingsOnlyCarriesNoPayload(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	store, _ := newStore(t, f)
	defer func() { assert.NoError(t, store.Close()) }()
	ctx := context.Background()

	settings := []publication.SnapshotSetting{{
		SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "color-scheme",
		State: model.SettingReset,
	}}
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion,
		Vault:         f.binding.Vault,
		PublicationID: [16]byte{2},
		Segments: []publication.SnapshotSegment{
			{Target: v4SettingsTarget(), Form: publication.SegmentFormSettings, Settings: settings},
		},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, SnapshotCID: recordCID,
	})
	require.NoError(t, err)
	observation := Observation{
		Origin: f.binding, SuppliedContext: SuppliedContext{RepositoryRevision: "r", RepositoryDigest: []byte{1}},
		Head: head, Snapshots: []SnapshotBlock{{Key: key, Raw: raw}},
	}
	candidate := CandidateInput{
		SnapshotKey: key, SnapshotRecord: raw, HeadRecord: head,
		Segments: []CandidateSegment{{
			TargetID: "desktop", Form: PayloadFormSettings, SettingsDigest: publication.SettingsDigest(settings),
		}},
		Payloads: [][]byte{nil},
	}
	review := attemptReview()
	emptyView := attemptView(f, observation, true)
	proposal, err := store.PrepareAttempt(ctx, candidate, emptyView, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, emptyView, review, proposal.Confirmation)
	require.NoError(t, err)
	require.Len(t, attempt.Segments, 1)
	assert.Equal(t, PayloadFormSettings, attempt.Segments[0].Form)

	dispatch, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, emptyView, review)
	require.NoError(t, err)
	upload, err := store.BeginUpload(ctx, attempt.ID, dispatch.StateToken, emptyView, review, dispatch.Confirmation)
	require.NoError(t, err)
	assert.Empty(t, uploadPayload(upload))
	assert.Empty(t, upload.Entries)
}
