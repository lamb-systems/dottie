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

func TestPreparePublicationPushSelectsManifestForASoleSingleFileTarget(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.False(t, preparation.NoOp)
	assert.Equal(t, publication.PayloadFormManifest, preparation.Form)
	assert.Equal(t, publication.PayloadFormManifest, preparation.Proposal.Form)
	assert.Equal(t, 1, preparation.Targets)
	assert.Equal(t, 1, preparation.Entries)
	assert.Empty(t, preparation.Proposal.Blob.CID)
	assert.Empty(t, preparation.Proposal.Candidate.Payload)

	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, record.PayloadForm())
	require.Len(t, record.Entries, 1)
	assert.Equal(t, "init.lua", record.Entries[0].Path)
	assert.Equal(t, uint32(0o600), record.Entries[0].Mode)
	assert.Equal(t, uint64(len("synthetic push payload")), record.Entries[0].Size)

	require.Len(t, preparation.Proposal.Candidate.Entries, 1)
	assert.Equal(t, "init.lua", preparation.Proposal.Candidate.Entries[0].Path)
	assert.Equal(t, uint32(0o600), preparation.Proposal.Candidate.Entries[0].Mode)
	assert.Equal(t, []byte("synthetic push payload"), preparation.Proposal.Candidate.Entries[0].Content)
}

func TestManifestPublicationNoOpUsesTheSoleSingleFileEntry(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)
	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormManifest, first.Form)
	setManifestReaderFromAccepted(t, fixture)

	unchanged, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x76, 0x01}, nil))
	require.NoError(t, err)
	assert.True(t, unchanged.NoOp)
	assert.Equal(t, publication.PayloadFormManifest, unchanged.Form)

	require.NoError(t, os.Chmod(filepath.Join(fixture.paths.Home, "config", "init.lua"), 0o644))
	changed, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x76, 0x02}, nil))
	require.NoError(t, err)
	assert.False(t, changed.NoOp)
	assert.Equal(t, publication.PayloadFormManifest, changed.Form)
	record, err := publication.DecodeSnapshot(changed.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Entries, 1)
	assert.Equal(t, "init.lua", record.Entries[0].Path)
	assert.Equal(t, uint32(0o644), record.Entries[0].Mode)
}

func TestManifestAcceptedMaterialProjectsTheSoleSingleFileEntry(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.binding, floor)
	require.NoError(t, err)
	require.Len(t, material.Entries, 1)
	assert.Equal(t, "init.lua", material.Entries[0].Path)

	snapshot, form, err := acceptedPublicationSnapshot(material, fixture.configuration)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, form)
	require.Len(t, snapshot.Entries, 1)
	assert.Equal(t, model.SelectionFile, snapshot.Targets[0].Root.Kind)
	assert.Equal(t, ".", snapshot.Entries[0].File.Path)
	assert.Equal(t, uint32(0o600), snapshot.Entries[0].File.Mode)
	assert.Equal(t, []byte("synthetic push payload"), snapshot.Entries[0].File.Content)
	require.NotNil(t, floor.Manifest)
	assert.Empty(t, floor.BlobCID)
}

func TestPreparePublicationPushSelectsManifestForAnEligibleDirectory(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.False(t, preparation.NoOp)
	assert.Equal(t, publication.PayloadFormManifest, preparation.Form)
	assert.Equal(t, publication.PayloadFormManifest, preparation.Proposal.Form)
	assert.Equal(t, 1, preparation.Targets)
	assert.Equal(t, 1, preparation.Entries)
	assert.Empty(t, preparation.Proposal.Blob.CID)
	assert.Empty(t, preparation.Proposal.Candidate.Payload)
	require.Len(t, preparation.Proposal.Candidate.Entries, 1)

	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, record.PayloadForm())
	require.Len(t, record.Entries, 1)
	assert.Equal(t, "init.lua", record.Entries[0].Path)
	assert.Equal(t, uint32(0o600), record.Entries[0].Mode)
	assert.Equal(t, uint64(len("synthetic push payload")), record.Entries[0].Size)

	head, err := publication.DecodeHead(preparation.Proposal.Batch.HeadRecord)
	require.NoError(t, err)
	assert.Empty(t, head.BlobCID)
	assert.NotEmpty(t, preparation.Record.CandidateEntryDigest)
	assert.Equal(t, 1, preparation.Record.CandidateEntryCount)
	assert.Empty(t, preparation.Record.CandidatePayloadCID)
}

func TestManifestPublicationNoOpUsesTheExactOrderedEntrySetIncludingMode(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	setManifestReaderFromAccepted(t, fixture)

	unchanged, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x01}, nil))
	require.NoError(t, err)
	assert.True(t, unchanged.NoOp)
	assert.Equal(t, publication.PayloadFormManifest, unchanged.Form)

	require.NoError(t, os.Chmod(filepath.Join(fixture.paths.Home, "config", "init.lua"), 0o644))
	changed, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x02}, nil))
	require.NoError(t, err)
	assert.False(t, changed.NoOp)
	assert.Equal(t, publication.PayloadFormManifest, changed.Form)
	record, err := publication.DecodeSnapshot(changed.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Entries, 1)
	assert.Equal(t, uint32(0o644), record.Entries[0].Mode)
}

func TestPreparePublicationPushKeepsNestedFilesInTheManifest(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "config", "lua"), 0o755))
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "config", "lua", "options.lua"), []byte("options"), 0o600),
	)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, preparation.Form)
	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, record.PayloadForm())
	require.Len(t, record.Entries, 2)
	assert.Equal(t, "init.lua", record.Entries[0].Path)
	assert.Equal(t, "lua/options.lua", record.Entries[1].Path)
	assert.Empty(t, preparation.Proposal.Candidate.Payload)
	assert.Empty(t, preparation.Proposal.Blob.CID)
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
			assert.NotEmpty(t, preparation.Proposal.Candidate.Payload)
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
			assert.NotEmpty(t, preparation.Proposal.Candidate.Payload)
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
	require.NoError(t, os.Mkdir(empty, 0o700))

	packed, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, packed.Form)
	assert.NotEmpty(t, packed.Proposal.Candidate.Payload)

	require.NoError(t, os.WriteFile(filepath.Join(empty, "kept.lua"), []byte("kept"), 0o600))
	manifest, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x03}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, manifest.Form)
	record, err := publication.DecodeSnapshot(manifest.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Entries, 2)
	assert.Equal(
		t,
		[]string{"empty/kept.lua", "init.lua"},
		[]string{record.Entries[0].Path, record.Entries[1].Path},
	)
}

func TestPreparePublicationPushFallsBackToPackedForMultipleTargets(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "other"), 0o700))
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{
		ID: "other", Source: model.SourceFiles, Mode: config.BackupOnly,
		Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	})

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, preparation.Form)
	assert.Equal(t, 2, preparation.Targets)
}

func TestPreparePublicationPushFallsBackToPackedWhenTheAcceptedManifestLosesAFile(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "config", "extra.lua"), []byte("extra"), 0o600),
	)
	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormManifest, first.Form)

	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "extra.lua")))
	second, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x03}, nil))
	require.NoError(t, err)
	assert.False(t, second.NoOp)
	assert.Equal(t, publication.PayloadFormPacked, second.Form)
	record, err := publication.DecodeSnapshot(second.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, record.PayloadForm())
}

func TestPreparePublicationPushFallsBackToPackedWhenTheLastManifestFileIsDeleted(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	first := fixture.publish(t)
	require.Equal(t, publication.PayloadFormManifest, first.Form)

	require.NoError(t, os.Remove(filepath.Join(fixture.paths.Home, "config", "init.lua")))
	second, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x04}, nil))
	require.NoError(t, err)
	assert.False(t, second.NoOp)
	assert.Equal(t, publication.PayloadFormPacked, second.Form)
}

func TestPreparePublicationPushRefusesToMapAManifestBaseToMultipleTargets(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "other"), 0o700))
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{
		ID: "other", Source: model.SourceFiles, Mode: config.BackupOnly,
		Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	})

	before := fixture.transport.uploadCount()
	_, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x05}, nil))
	require.ErrorIs(t, err, ErrManifestTarget)
	assert.Equal(t, before, fixture.transport.uploadCount(), "a refused manifest mapping uploaded a payload")
}

func TestManifestPublicationRecordJSONCarriesNoContent(t *testing.T) {
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

func TestManifestAcceptedMaterialRoundTripThroughProjection(t *testing.T) {
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(context.Background(), fixture.binding, floor)
	require.NoError(t, err)
	snapshot, form, err := acceptedPublicationSnapshot(material, fixture.configuration)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, form)
	require.Len(t, snapshot.Entries, 1)
	assert.Equal(t, "init.lua", snapshot.Entries[0].File.Path)
	assert.Equal(t, []byte("synthetic push payload"), snapshot.Entries[0].File.Content)
	require.True(t, floor.Manifest != nil)
	assert.Empty(t, floor.BlobCID)
}

func TestManifestProjectionSynthesizesParentDirectoriesAt0755(t *testing.T) {
	portable := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	snapshot, err := manifestProjection(portable, []publication.PayloadEntry{{
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

func TestManifestProjectionMapsASingleFileEntryToTheRootEntry(t *testing.T) {
	portable := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config/init.lua", Kind: model.SelectionFile},
	}
	snapshot, err := manifestProjection(portable, []publication.PayloadEntry{{
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

	_, err = manifestProjection(portable, []publication.PayloadEntry{
		{Path: "init.lua", Mode: 0o600, Size: 4, Content: []byte("init")},
		{Path: "other.lua", Mode: 0o600, Size: 5, Content: []byte("other")},
	})
	require.ErrorIs(t, err, publication.ErrInvalidRecord)

	_, err = manifestProjection(portable, []publication.PayloadEntry{{
		Path: ".", Mode: 0o600, Size: 4, Content: []byte("init"),
	}})
	require.ErrorIs(t, err, publication.ErrInvalidRecord)
}

func TestManifestPublicationTargetAcceptsBothFilesSelectionKinds(t *testing.T) {
	configuration := config.Config{
		Version: config.Version,
		Targets: []config.Target{{
			ID: "files", Source: model.SourceFiles,
			Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
	}
	_, portable, err := manifestPublicationTarget(configuration)
	require.NoError(t, err)
	assert.Equal(t, model.SelectionDirectory, portable.Root.Kind)

	configuration.Targets[0].Root = &config.Root{
		Base: model.RootHome, Path: "config/init.lua", Kind: model.SelectionFile,
	}
	_, portable, err = manifestPublicationTarget(configuration)
	require.NoError(t, err)
	assert.Equal(t, model.SelectionFile, portable.Root.Kind)
	assert.Equal(t, "config/init.lua", portable.Root.Path)

	configuration.Targets[0].Root.Kind = ""
	_, _, err = manifestPublicationTarget(configuration)
	require.ErrorIs(t, err, ErrManifestTarget)
}

func setManifestReaderFromAccepted(t *testing.T, fixture *publicationPushFixture) {
	t.Helper()
	floor, present, err := fixture.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(context.Background(), fixture.binding, floor)
	require.NoError(t, err)
	entries := make([]publication.PayloadEntry, 0, len(material.Entries))
	for _, entry := range material.Entries {
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: uint64(len(entry.Content)), Content: entry.Content,
		})
	}
	fixture.reader.setPayload(publication.Payload{Form: publication.PayloadFormManifest, Entries: entries})
}

func TestManifestUploadFailureIsAbandonedByTheConfirmationWrapper(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "config", "extra.lua"), []byte("extra"), 0o600),
	)
	fixture.transport.uploadFailAt = 2

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	require.Equal(t, publication.PayloadFormManifest, preparation.Form)
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
	assert.False(t, active, "an upload-started manifest attempt was left active")
	_, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present, "a failed manifest upload advanced the accepted floor")
	_, retained := fixture.records.has(fixture.publicationID)
	assert.False(t, retained, "a failed manifest upload retained its proposal")

	retry, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x06}, nil))
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, retry.Form)
}

func TestManifestAmbiguousSubmissionStaysUnresolvedThroughConfirmation(t *testing.T) {
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
	assert.True(t, retained, "an ambiguous manifest submission deleted its proposal")

	_, err = fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x07}, nil))
	require.ErrorIs(t, err, ErrPublicationProposalActive)
	assert.Equal(t, 1, fixture.transport.uploadCount(), "a retry uploaded after an ambiguous submission")
}

func TestManifestAcceptedPreviewAndBaseUseTheSoleDirectoryTarget(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.binding, floor)
	require.NoError(t, err)
	entries := make([]publication.PayloadEntry, 0, len(material.Entries))
	for _, entry := range material.Entries {
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

func TestManifestAcceptedPreviewAndBaseUseTheSoleSingleFileTarget(t *testing.T) {
	ctx := context.Background()
	fixture := singleFilePushFixture(t)
	fixture.publish(t)
	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	material, err := fixture.store.ReadAcceptedMaterial(ctx, fixture.binding, floor)
	require.NoError(t, err)
	entries := make([]publication.PayloadEntry, 0, len(material.Entries))
	for _, entry := range material.Entries {
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
	form, manifest, err := selectPublicationForm(configuration, eligible, base)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, form)
	assert.Equal(t, portable, manifest.Targets[0])

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
