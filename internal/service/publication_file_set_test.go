package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func TestPreparePublicationPushSelectsFileSetForASoleSingleFileTarget(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.False(t, preparation.NoOp)
	assert.Equal(t, publication.PayloadFormFileSet, preparation.Form)
	assert.Equal(t, publication.PayloadFormFileSet, preparation.Proposal.Form)
	assert.Equal(t, 1, preparation.Targets)
	assert.Equal(t, 1, preparation.Entries)
	assert.Empty(t, proposalPackedBlob(preparation.Proposal).CID)
	assert.Empty(t, proposalPackedPayload(preparation.Proposal))

	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, record.PayloadForm())
	require.Len(t, recordFileSetEntries(record), 1)
	assert.Equal(t, "init.lua", recordFileSetEntries(record)[0].Path)
	assert.Equal(t, uint32(0o600), recordFileSetEntries(record)[0].Mode)
	assert.Equal(t, uint64(len("synthetic push payload")), recordFileSetEntries(record)[0].Size)

	require.Len(t, preparation.Proposal.Candidate.Entries, 1)
	assert.Equal(t, "init.lua", preparation.Proposal.Candidate.Entries[0].Path)
	assert.Equal(t, uint32(0o600), preparation.Proposal.Candidate.Entries[0].Mode)
	assert.Equal(t, []byte("synthetic push payload"), preparation.Proposal.Candidate.Entries[0].Content)
}

func TestFileSetPublicationNoOpUsesTheSoleSingleFileEntry(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)
	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormFileSet, first.Form)
	setFileSetReaderFromAccepted(t, fixture)

	unchanged, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x76, 0x01}, nil))
	require.NoError(t, err)
	assert.True(t, unchanged.NoOp)
	assert.Equal(t, publication.PayloadFormFileSet, unchanged.Form)

	require.NoError(t, os.Chmod(filepath.Join(fixture.paths.Home, "config", "init.lua"), 0o644))
	changed, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x76, 0x02}, nil))
	require.NoError(t, err)
	assert.False(t, changed.NoOp)
	assert.Equal(t, publication.PayloadFormFileSet, changed.Form)
	record, err := publication.DecodeSnapshot(changed.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, recordFileSetEntries(record), 1)
	assert.Equal(t, "init.lua", recordFileSetEntries(record)[0].Path)
	assert.Equal(t, uint32(0o644), recordFileSetEntries(record)[0].Mode)
}

func TestFileSetAcceptedMaterialProjectsTheSoleSingleFileEntry(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.binding, floor)
	require.NoError(t, err)
	require.Len(t, acceptedEntriesOf(material), 1)
	assert.Equal(t, "init.lua", acceptedEntriesOf(material)[0].Path)

	snapshot, form, err := acceptedPublicationSnapshot(material, fixture.configuration)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, form)
	require.Len(t, snapshot.Entries, 1)
	assert.Equal(t, model.SelectionFile, snapshot.Targets[0].Root.Kind)
	assert.Equal(t, ".", snapshot.Entries[0].File.Path)
	assert.Equal(t, uint32(0o600), snapshot.Entries[0].File.Mode)
	assert.Equal(t, []byte("synthetic push payload"), snapshot.Entries[0].File.Content)
	require.NotNil(t, floorFileSet(floor))
	assert.Empty(t, floorPackedBlob(floor).CID)
}

func TestPreparePublicationPushSelectsFileSetForAnEligibleDirectory(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.False(t, preparation.NoOp)
	assert.Equal(t, publication.PayloadFormFileSet, preparation.Form)
	assert.Equal(t, publication.PayloadFormFileSet, preparation.Proposal.Form)
	assert.Equal(t, 1, preparation.Targets)
	assert.Equal(t, 1, preparation.Entries)
	assert.Empty(t, proposalPackedBlob(preparation.Proposal).CID)
	assert.Empty(t, proposalPackedPayload(preparation.Proposal))
	require.Len(t, preparation.Proposal.Candidate.Entries, 1)

	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, record.PayloadForm())
	require.Len(t, recordFileSetEntries(record), 1)
	assert.Equal(t, "init.lua", recordFileSetEntries(record)[0].Path)
	assert.Equal(t, uint32(0o600), recordFileSetEntries(record)[0].Mode)
	assert.Equal(t, uint64(len("synthetic push payload")), recordFileSetEntries(record)[0].Size)

	head, err := publication.DecodeHead(preparation.Proposal.Batch.HeadRecord)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), head.PublicationSeq)
	assert.NotContains(t, string(preparation.Proposal.Batch.HeadRecord), "blobCid")
	summaries, err := publicationstate.DecodeSegmentSummaries(preparation.Record.Segments)
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, publicationstate.PayloadFormFileSet, summaries[0].Form)
	require.Len(t, summaries[0].Entries, 1)
	assert.Empty(t, summaries[0].BlobCID)
	assert.NotEqual(t, [32]byte{}, preparation.Record.PayloadsDigest)
}

func TestFileSetPublicationNoOpUsesTheExactOrderedEntrySetIncludingMode(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	setFileSetReaderFromAccepted(t, fixture)

	unchanged, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x01}, nil))
	require.NoError(t, err)
	assert.True(t, unchanged.NoOp)
	assert.Equal(t, publication.PayloadFormFileSet, unchanged.Form)

	require.NoError(t, os.Chmod(filepath.Join(fixture.paths.Home, "config", "init.lua"), 0o644))
	changed, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x02}, nil))
	require.NoError(t, err)
	assert.False(t, changed.NoOp)
	assert.Equal(t, publication.PayloadFormFileSet, changed.Form)
	record, err := publication.DecodeSnapshot(changed.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, recordFileSetEntries(record), 1)
	assert.Equal(t, uint32(0o644), recordFileSetEntries(record)[0].Mode)
}

func TestPreparePublicationPushKeepsNestedFilesInTheFileSet(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "config", "lua"), 0o755))
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "config", "lua", "options.lua"), []byte("options"), 0o600),
	)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, preparation.Form)
	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, record.PayloadForm())
	require.Len(t, recordFileSetEntries(record), 2)
	assert.Equal(t, "init.lua", recordFileSetEntries(record)[0].Path)
	assert.Equal(t, "lua/options.lua", recordFileSetEntries(record)[1].Path)
	assert.Empty(t, proposalPackedPayload(preparation.Proposal))
	assert.Empty(t, proposalPackedBlob(preparation.Proposal).CID)
}

func TestPreparePublicationPushFallsBackToPackedForUnsupportedFiles(t *testing.T) {
	cases := map[string]func(t *testing.T, fixture *publicationPushFixture){
		"empty file": func(t *testing.T, fixture *publicationPushFixture) {
			require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "config", "init.lua"), nil, 0o600))
		},
		"executable mode": func(t *testing.T, fixture *publicationPushFixture) {
			require.NoError(t, os.Chmod(filepath.Join(fixture.paths.Home, "config", "init.lua"), 0o755))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newPublicationPushFixture(t)
			mutate(t, fixture)
			preparation, err := fixture.coordinator.PreparePublicationPush(
				context.Background(),
				fixture.request(fixture.publicationID, nil),
			)
			require.NoError(t, err)
			assert.Equal(t, publication.PayloadFormPacked, preparation.Form)
			assert.NotEmpty(t, proposalPackedPayload(preparation.Proposal))
		})
	}
}

func TestPreparePublicationPushFallsBackToPackedForAnUnsupportedSingleFile(t *testing.T) {
	cases := map[string]func(t *testing.T, fixture *publicationPushFixture){
		"empty file": func(t *testing.T, fixture *publicationPushFixture) {
			require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "config", "init.lua"), nil, 0o600))
		},
		"executable mode": func(t *testing.T, fixture *publicationPushFixture) {
			require.NoError(t, os.Chmod(filepath.Join(fixture.paths.Home, "config", "init.lua"), 0o755))
		},
		"unrepresentable basename": func(t *testing.T, fixture *publicationPushFixture) {
			require.NoError(t, os.Rename(
				filepath.Join(fixture.paths.Home, "config", "init.lua"),
				filepath.Join(fixture.paths.Home, "config", "c:notes"),
			))
			fixture.configuration.Targets[0].Root.Path = "config/c:notes"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := singleFilePushFixture(t)
			mutate(t, fixture)
			preparation, err := fixture.coordinator.PreparePublicationPush(
				context.Background(),
				fixture.request(fixture.publicationID, nil),
			)
			require.NoError(t, err)
			assert.Equal(t, publication.PayloadFormPacked, preparation.Form)
			assert.NotEmpty(t, proposalPackedPayload(preparation.Proposal))
			record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
			require.NoError(t, err)
			assert.Equal(t, publication.PayloadFormPacked, record.PayloadForm())
		})
	}
}

func singleFilePushFixture(t *testing.T) *publicationPushFixture {
	t.Helper()
	fixture := newPublicationPushFixture(t)
	fixture.configuration.Targets[0].Root.Path = "config/init.lua"
	fixture.configuration.Targets[0].Root.Kind = model.SelectionFile
	return fixture
}

func TestPreparePublicationPushFallsBackToPackedForADirectoryWithoutFiles(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	empty := filepath.Join(fixture.paths.Home, "config", "empty")
	require.NoError(t, os.Mkdir(empty, 0o755))

	packed, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, packed.Form)
	assert.NotEmpty(t, proposalPackedPayload(packed.Proposal))

	require.NoError(t, os.WriteFile(filepath.Join(empty, "kept.lua"), []byte("kept"), 0o600))
	fileSet, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x03}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, fileSet.Form)
	record, err := publication.DecodeSnapshot(fileSet.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, recordFileSetEntries(record), 2)
	assert.Equal(
		t,
		[]string{"empty/kept.lua", "init.lua"},
		[]string{recordFileSetEntries(record)[0].Path, recordFileSetEntries(record)[1].Path},
	)
}

func TestPreparePublicationPushPublishesOneSegmentPerTarget(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "other"), 0o700))
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{
		ID: "other", Source: model.SourceFiles, Mode: config.BackupOnly,
		Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	})

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormMixed, preparation.Form)
	assert.Equal(t, 2, preparation.Targets)

	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 2)
	assert.Equal(t, "files", record.Segments[0].Target.ID)
	assert.Equal(t, publication.SegmentFormEntries, record.Segments[0].Form)
	require.Len(t, record.Segments[0].Entries, 1)
	assert.Equal(t, "other", record.Segments[1].Target.ID)
	assert.Equal(t, publication.SegmentFormPacked, record.Segments[1].Form)
}

func TestPreparePublicationPushFallsBackToPackedWhenTheAcceptedFileSetLosesAFile(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "config", "extra.lua"), []byte("extra"), 0o600),
	)
	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormFileSet, first.Form)

	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "extra.lua")))
	second, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x03}, nil))
	require.NoError(t, err)
	assert.False(t, second.NoOp)
	assert.Equal(t, publication.PayloadFormPacked, second.Form)
	record, err := publication.DecodeSnapshot(second.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, record.PayloadForm())
}

func TestPreparePublicationPushFallsBackToPackedWhenTheLastFileSetFileIsDeleted(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormFileSet, first.Form)

	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "init.lua")))
	second, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x04}, nil))
	require.NoError(t, err)
	assert.False(t, second.NoOp)
	assert.Equal(t, publication.PayloadFormPacked, second.Form)
}

func TestPreparePublicationPushKeepsTheAcceptedBaseOnItsOwnTarget(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	setFileSetReaderFromAccepted(t, fixture)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "other"), 0o700))
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{
		ID: "other", Source: model.SourceFiles, Mode: config.BackupOnly,
		Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	})

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x05}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormMixed, preparation.Form)

	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 2)
	assert.Equal(t, "files", record.Segments[0].Target.ID)
	assert.Equal(t, publication.SegmentFormEntries, record.Segments[0].Form)
	require.Len(t, record.Segments[0].Entries, 1)
	assert.Equal(t, "init.lua", record.Segments[0].Entries[0].Path)
	assert.Equal(t, "other", record.Segments[1].Target.ID)
	assert.Equal(t, publication.SegmentFormPacked, record.Segments[1].Form)
}

func TestFileSetPublicationRecordJSONCarriesNoContent(t *testing.T) {
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(
		context.Background(),
		fixture.request(fixture.publicationID, nil),
	)
	require.NoError(t, err)
	encoded, err := publication.RecordToJSON(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"path":"init.lua"`)
	assert.Contains(t, string(encoded), `"mode":384`)
	assert.Contains(t, string(encoded), `"size":22`)
	assert.NotContains(t, string(encoded), "synthetic push payload")
	assert.NotContains(t, string(encoded), publication.SnapshotBlobMIMEType)
}

func TestFileSetAcceptedMaterialRoundTripThroughProjection(t *testing.T) {
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(context.Background(), fixture.binding, floor)
	require.NoError(t, err)
	snapshot, form, err := acceptedPublicationSnapshot(material, fixture.configuration)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, form)
	require.Len(t, snapshot.Entries, 1)
	assert.Equal(t, "init.lua", snapshot.Entries[0].File.Path)
	assert.Equal(t, []byte("synthetic push payload"), snapshot.Entries[0].File.Content)
	require.True(t, floorFileSet(floor) != nil)
	assert.Empty(t, floorPackedBlob(floor).CID)
}

func TestFileSetProjectionSynthesizesParentDirectoriesAt0755(t *testing.T) {
	portable := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	snapshot, err := fileSetProjection(portable, []publication.PayloadEntry{{
		Path: "lua/config/options.lua", Mode: 0o644, Size: 7, Content: []byte("options"),
	}})
	require.NoError(t, err)
	require.Len(t, snapshot.Entries, 3)
	byPath := map[string]model.FileEntry{}
	for _, entry := range snapshot.Entries {
		byPath[entry.File.Path] = *entry.File
	}
	assert.Equal(t, model.FileDirectory, byPath["lua"].Kind)
	assert.Equal(t, uint32(0o755), byPath["lua"].Mode)
	assert.Equal(t, model.FileDirectory, byPath["lua/config"].Kind)
	assert.Equal(t, model.FileRegular, byPath["lua/config/options.lua"].Kind)
}

func TestFileSetProjectionMapsASingleFileEntryToTheRootEntry(t *testing.T) {
	portable := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config/init.lua", Kind: model.SelectionFile},
	}
	snapshot, err := fileSetProjection(portable, []publication.PayloadEntry{{
		Path: "init.lua", Mode: 0o600, Size: 4, Content: []byte("init"),
	}})
	require.NoError(t, err)
	require.Len(t, snapshot.Entries, 1)
	assert.Equal(t, model.SelectionFile, snapshot.Targets[0].Root.Kind)
	assert.Equal(t, ".", snapshot.Entries[0].File.Path)
	assert.Equal(t, model.FileRegular, snapshot.Entries[0].File.Kind)
	assert.Equal(t, model.FilePresent, snapshot.Entries[0].File.State)
	assert.Equal(t, uint32(0o600), snapshot.Entries[0].File.Mode)
	assert.Equal(t, []byte("init"), snapshot.Entries[0].File.Content)

	_, err = fileSetProjection(portable, []publication.PayloadEntry{
		{Path: "init.lua", Mode: 0o600, Size: 4, Content: []byte("init")},
		{Path: "other.lua", Mode: 0o600, Size: 5, Content: []byte("other")},
	})
	require.ErrorIs(t, err, publication.ErrInvalidRecord)

	_, err = fileSetProjection(portable, []publication.PayloadEntry{{
		Path: ".", Mode: 0o600, Size: 4, Content: []byte("init"),
	}})
	require.ErrorIs(t, err, publication.ErrInvalidRecord)
}

func TestFileSetPublicationTargetAcceptsBothFilesSelectionKinds(t *testing.T) {
	configuration := config.Config{
		Version: config.Version,
		Targets: []config.Target{{
			ID: "files", Source: model.SourceFiles,
			Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
	}
	_, portable, err := fileSetPublicationTarget(configuration)
	require.NoError(t, err)
	assert.Equal(t, model.SelectionDirectory, portable.Root.Kind)

	configuration.Targets[0].Root = &config.Root{
		Base: model.RootHome, Path: "config/init.lua", Kind: model.SelectionFile,
	}
	_, portable, err = fileSetPublicationTarget(configuration)
	require.NoError(t, err)
	assert.Equal(t, model.SelectionFile, portable.Root.Kind)
	assert.Equal(t, "config/init.lua", portable.Root.Path)

	configuration.Targets[0].Root.Kind = ""
	_, _, err = fileSetPublicationTarget(configuration)
	require.ErrorIs(t, err, ErrFileSetTarget)
}

func setFileSetReaderFromAccepted(t *testing.T, fixture *publicationPushFixture) {
	t.Helper()
	floor, present, err := fixture.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(context.Background(), fixture.binding, floor)
	require.NoError(t, err)
	entries := make([]publication.PayloadEntry, 0, len(acceptedEntriesOf(material)))
	for _, entry := range acceptedEntriesOf(material) {
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: uint64(len(entry.Content)), Content: entry.Content,
		})
	}
	snapshot, form, err := acceptedPublicationSnapshot(material, fixture.configuration)
	require.NoError(t, err)
	fixture.reader.setPayload(publication.Payload{Form: form, Snapshot: snapshot, Entries: entries})
}

func TestFileSetUploadFailureIsAbandonedByTheConfirmationWrapper(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "config", "extra.lua"), []byte("extra"), 0o600),
	)
	fixture.transport.uploadFailAt = 2

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.Equal(t, publication.PayloadFormFileSet, preparation.Form)
	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.Error(t, err)
	assert.Equal(t, 2, fixture.transport.uploadCount())

	_, active, err := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, active, "an upload-started file-set attempt was left active")
	_, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present, "a failed file-set upload advanced the accepted floor")
	_, retained := fixture.records.has(fixture.publicationID)
	assert.False(t, retained, "a failed file-set upload retained its proposal")

	retry, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x06}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, retry.Form)
}

func TestFileSetAmbiguousSubmissionStaysUnresolvedThroughConfirmation(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.transport.commitThenFail = true

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.Error(t, err)
	active, present, err := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, active.Lifecycle)
	_, retained := fixture.records.has(fixture.publicationID)
	assert.True(t, retained, "an ambiguous file-set submission deleted its proposal")

	_, err = fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x07}, nil))
	require.ErrorIs(t, err, ErrPublicationProposalActive)
	assert.Equal(t, 1, fixture.transport.uploadCount(), "a retry uploaded after an ambiguous submission")
}

func TestFileSetAcceptedPreviewAndBaseUseTheSoleDirectoryTarget(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.binding, floor)
	require.NoError(t, err)
	entries := make([]publication.PayloadEntry, 0, len(acceptedEntriesOf(material)))
	for _, entry := range acceptedEntriesOf(material) {
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: uint64(len(entry.Content)), Content: entry.Content,
		})
	}
	local, err := NewPublicationLocalContext(fixture.paths, LocalFilesCapture{}, nil)
	require.NoError(t, err)
	request := PublicationReconciliationRequest{
		Store: fixture.store, Binding: fixture.binding, ExpectedFloor: floor,
		SnapshotRecord: material.SnapshotRecord, Entries: entries,
		Configuration: fixture.configuration, TargetID: "files", Local: local,
	}
	base, err := EstablishLocalReconciliationBase(ctx, request)
	require.NoError(t, err)
	assert.NotNil(t, base)
	preview, disposition, err := PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.Zero(t, preview.UnresolvedEntries)
	require.Len(t, preview.Targets, 1)
	require.Len(t, preview.Targets[0].Entries, 1)
	assert.Equal(t, "init.lua", preview.Targets[0].Entries[0].Key.FilePath)

	fixture.reopenStore(t)
	request.Store = fixture.store
	reopened, disposition, err := PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.Equal(t, preview.Targets, reopened.Targets)
}

func TestFileSetAcceptedPreviewAndBaseUseTheSoleSingleFileTarget(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.binding, floor)
	require.NoError(t, err)
	entries := make([]publication.PayloadEntry, 0, len(acceptedEntriesOf(material)))
	for _, entry := range acceptedEntriesOf(material) {
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: uint64(len(entry.Content)), Content: entry.Content,
		})
	}
	local, err := NewPublicationLocalContext(fixture.paths, LocalFilesCapture{}, nil)
	require.NoError(t, err)
	request := PublicationReconciliationRequest{
		Store: fixture.store, Binding: fixture.binding, ExpectedFloor: floor,
		SnapshotRecord: material.SnapshotRecord, Entries: entries,
		Configuration: fixture.configuration, TargetID: "files", Local: local,
	}
	base, err := EstablishLocalReconciliationBase(ctx, request)
	require.NoError(t, err)
	assert.NotNil(t, base)
	preview, disposition, err := PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.Zero(t, preview.UnresolvedEntries)
	require.Len(t, preview.Targets, 1)
	require.Len(t, preview.Targets[0].Entries, 1)
	assert.Equal(t, ".", preview.Targets[0].Entries[0].Key.FilePath)

	fixture.reopenStore(t)
	request.Store = fixture.store
	reopened, disposition, err := PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.Equal(t, preview.Targets, reopened.Targets)
}

func TestSelectPublicationFormCrossesFormsWithoutChangingTargetIdentity(t *testing.T) {
	portable := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	configuration := config.Config{Version: config.Version, Targets: []config.Target{{
		ID: "files", Source: model.SourceFiles,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}}}
	base := model.Snapshot{
		Version: model.SnapshotVersion, Targets: []model.Target{portable},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{
			Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
			Content: []byte("alpha"), Mode: 0o600,
		}}},
	}
	eligible := model.Snapshot{
		Version: model.SnapshotVersion, Targets: []model.Target{portable},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{
			Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
			Content: []byte("beta"), Mode: 0o600,
		}}},
	}
	form, fileSet, err := selectPublicationForm(configuration, eligible, base)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, form)
	assert.Equal(t, portable, fileSet.Targets[0])

	packedCandidate := model.Snapshot{
		Version: model.SnapshotVersion, Targets: []model.Target{portable},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{
			Path: "empty.lua", State: model.FilePresent, Kind: model.FileRegular,
			Content: []byte{}, Mode: 0o600,
		}}},
	}
	form, snapshot, err := selectPublicationForm(configuration, packedCandidate, base)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, form)
	assert.Equal(t, packedCandidate, snapshot)
}

func TestFileSetPublicationNoOpComparesTheWholeSegmentTarget(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	setFileSetReaderFromAccepted(t, fixture)

	unchanged, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x76, 0x11}, nil))
	require.NoError(t, err)
	require.True(t, unchanged.NoOp)

	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)

	require.NoError(t, os.Rename(
		filepath.Join(fixture.paths.Home, "config"),
		filepath.Join(fixture.paths.Home, "renamed"),
	))
	fixture.configuration.Targets[0].Root.Path = "renamed"
	_, err = fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x76, 0x12}, nil))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPublicationRebind)
	assert.Contains(t, err.Error(), "home:config")
	assert.Contains(t, err.Error(), "home:renamed")

	after, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, floor.RecordCID, after.RecordCID, "a refused rebind published a record")
	assert.Equal(t, floor.Revision, after.Revision)
}

func TestPreparePublicationPushAcceptsATargetTheAcceptedPositionDoesNotName(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	setFileSetReaderFromAccepted(t, fixture)
	require.NoError(t, os.MkdirAll(filepath.Join(fixture.paths.Home, "extra"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "extra", "kept.conf"), []byte("kept"), 0o600))
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{
		ID: "extra", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "extra", Kind: model.SelectionDirectory},
	})

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x76, 0x13}, nil))
	require.NoError(t, err)
	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 2)
	assert.Equal(t, "extra", record.Segments[0].Target.ID)
	assert.Equal(t, "files", record.Segments[1].Target.ID)
}

func TestPreparePublicationPushFallsBackToPackedForACarriedDirectoryMode(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	nested := filepath.Join(fixture.paths.Home, "config", "nested")
	require.NoError(t, os.Mkdir(nested, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "app.conf"), []byte("synthetic nested"), 0o600))

	packed, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, packed.Form)

	require.NoError(t, os.Chmod(nested, 0o755))
	fileSet, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x12}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, fileSet.Form)
	record, err := publication.DecodeSnapshot(fileSet.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, recordFileSetEntries(record), 2)
	assert.Equal(t, "init.lua", recordFileSetEntries(record)[0].Path)
	assert.Equal(t, "nested/app.conf", recordFileSetEntries(record)[1].Path)
}

func TestPreparePublicationPushKeepsDeletionScopedToItsTarget(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "other"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "other", "kept.conf"), []byte("kept"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "config", "extra.lua"), []byte("extra"), 0o600))
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{
		ID: "other", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	})

	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormMixed, first.Form)
	setFileSetReaderFromAccepted(t, fixture)

	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "extra.lua")))
	second, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x21}, nil))
	require.NoError(t, err)
	assert.False(t, second.NoOp)
	record, err := publication.DecodeSnapshot(second.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 2)
	assert.Equal(t, "files", record.Segments[0].Target.ID)
	assert.Equal(t, publication.SegmentFormPacked, record.Segments[0].Form, "a deletion did not keep its target packed")
	assert.Equal(t, "other", record.Segments[1].Target.ID)
	assert.Equal(t, publication.SegmentFormEntries, record.Segments[1].Form, "a deletion demoted a sibling target")
}

func TestPreparePublicationPushPacksADeletionAgainstAPackedAcceptance(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	for _, name := range []string{"second.conf", "third.conf"} {
		require.NoError(
			t,
			os.WriteFile(filepath.Join(fixture.paths.Home, "config", name), []byte("synthetic "+name), 0o600),
		)
	}
	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormFileSet, first.Form)
	setFileSetReaderFromAccepted(t, fixture)

	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "third.conf")))
	secondRequest := fixture.request([16]byte{0x77, 0x01}, nil)
	second, err := fixture.coordinator.PreparePublicationPush(ctx, secondRequest)
	require.NoError(t, err)
	require.Equal(t, publication.PayloadFormPacked, second.Form, "a deletion against an entries base was not packed")
	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx, secondRequest, second, second.Proposal.Confirmation,
	)
	require.NoError(t, err)
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Len(t, floor.Segments, 1)
	require.Equal(t, publicationstate.PayloadFormPacked, floor.Segments[0].Form,
		"the packed successor was not the accepted position")
	setFileSetReaderFromAccepted(t, fixture)

	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "second.conf")))
	third, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x77, 0x02}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, third.Form,
		"a deletion against a packed accepted position left the target eligible for the entries form")
}

func TestPreparePublicationPushDoesNotPackADeletionWithoutAnAcceptedPosition(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	for _, name := range []string{"second.conf", "third.conf"} {
		require.NoError(
			t,
			os.WriteFile(filepath.Join(fixture.paths.Home, "config", name), []byte("synthetic "+name), 0o600),
		)
	}
	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "third.conf")))

	preparation, err := fixture.coordinator.PreparePublicationPush(
		ctx,
		fixture.request([16]byte{0x77, 0x03}, nil),
	)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, preparation.Form,
		"a first publication has no accepted position to delete from")
}

func newPackedDeletionReceiver(
	t *testing.T,
	localContent []byte,
) (PublicationApplyRequest, string) {
	t.Helper()
	ctx := context.Background()
	source := newPublicationPushFixture(t)
	second := []byte("synthetic second payload")
	require.NoError(t, os.WriteFile(filepath.Join(source.paths.Home, "config", "second.conf"), second, 0o600))
	first := source.publish(t)
	require.Equal(t, publication.PayloadFormFileSet, first.Form)
	setFileSetReaderFromAccepted(t, source)
	require.NoError(t, os.Remove(filepath.Join(source.paths.Home, "config", "second.conf")))
	successor, err := source.coordinator.PreparePublicationPush(ctx, source.request([16]byte{0x78, 0x01}, nil))
	require.NoError(t, err)
	require.Equal(t, publication.PayloadFormPacked, successor.Form,
		"the deletion was not published packed against a packed acceptance")
	floor, present, err := source.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	acceptedMaterial, err := source.store.ReadAcceptedMaterial(ctx, source.binding, floor)
	require.NoError(t, err)
	base, _, err := acceptedPublicationSnapshot(acceptedMaterial, source.configuration)
	require.NoError(t, err)
	require.Len(t, base.Entries, 2)
	record, err := publication.DecodeSnapshot(successor.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 1)
	remote, err := publication.DecodeSegmentPayload(proposalPackedPayload(successor.Proposal), record.Segments[0])
	require.NoError(t, err)

	target := newPublicationApplyFixture(t)
	root := filepath.Join(target.paths.Home, "config")
	require.NoError(t, os.Mkdir(root, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "second.conf"), localContent, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "init.lua"), []byte("synthetic push payload"), 0o600))
	applyTarget := config.Target{
		ID: "files", Source: model.SourceFiles,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	target.configuration = config.Config{Version: config.Version, Targets: []config.Target{applyTarget}}
	return PublicationApplyRequest{
		Journal: target.journal, Vault: target.vault, FloorRevision: target.floor,
		Configuration: target.configuration, BaseSnapshot: base, RemoteSnapshot: remote,
		Roots: map[string]string{"files": root}, Local: target.local,
	}, root
}

func TestPackedDeletionFromAnotherMachineRemovesTheLocalFile(t *testing.T) {
	second := []byte("synthetic second payload")
	request, root := newPackedDeletionReceiver(t, second)
	plan, err := PlanPublicationApply(context.Background(), request)
	require.NoError(t, err)
	deletes := 0
	for _, entry := range plan.Entries {
		if entry.Operation == PublicationApplyDelete {
			deletes++
		}
	}
	require.Equal(t, 1, deletes, "a packed deletion did not plan a local delete")

	report, err := ApplyPublication(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Applied)
	_, statErr := os.Lstat(filepath.Join(root, "second.conf"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "the deleted file survived the apply")
	kept, err := os.ReadFile(filepath.Join(root, "init.lua"))
	require.NoError(t, err)
	assert.Equal(t, "synthetic push payload", string(kept))
}

func TestPackedDeletionFromAnotherMachineRefusesADivergentLocalEdit(t *testing.T) {
	request, root := newPackedDeletionReceiver(t, []byte("edited on the second machine"))
	_, err := PlanPublicationApply(context.Background(), request)
	requirePublicationApplyRefusal(t, err, "apply-plan", "plan_conflict")

	content, readErr := os.ReadFile(filepath.Join(root, "second.conf"))
	require.NoError(t, readErr)
	assert.Equal(t, "edited on the second machine", string(content), "a refused plan mutated the file")
}

func TestPreparePublicationPushReturnsASingleFileTargetToTheEntriesForm(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	path := filepath.Join(fixture.paths.Home, "config", "init.lua")
	require.NoError(t, os.Chmod(path, 0o755))
	fixture.configuration.Targets[0].Root = &config.Root{
		Base: model.RootHome, Path: "config/init.lua", Kind: model.SelectionFile,
	}

	packed := fixture.publish(t)
	require.Equal(t, publication.PayloadFormPacked, packed.Form, "an unusual mode did not pack the target")
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, publicationstate.PayloadFormPacked, floor.Segments[0].Form)
	setFileSetReaderFromAccepted(t, fixture)

	require.NoError(t, os.Chmod(path, 0o600))
	eligible, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x79, 0x01}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, eligible.Form,
		"a single-file target compared the packed path dot against its basename and stayed packed")
	record, err := publication.DecodeSnapshot(eligible.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 1)
	require.Len(t, record.Segments[0].Entries, 1)
	assert.Equal(t, "init.lua", record.Segments[0].Entries[0].Path)
}
