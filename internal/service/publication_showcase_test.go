package service

import (
	"context"
	"errors"
	"fmt"
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

type showcaseServiceFile struct {
	path    string
	mode    uint32
	content []byte
}

type showcaseServicePublication struct {
	document publication.SnapshotRecord
	raw      []byte
	block    publicationstate.SnapshotBlock
	head     []byte
}

func newShowcaseServicePublication(
	t *testing.T,
	vault [32]byte,
	publicationID [16]byte,
	files ...showcaseServiceFile,
) showcaseServicePublication {
	t.Helper()
	entries := make([]publication.SnapshotEntry, 0, len(files))
	for _, file := range files {
		blobCID, err := publication.RawPayloadCID(file.content)
		require.NoError(t, err)
		entries = append(entries, publication.SnapshotEntry{
			Path: file.path, Mode: file.mode, Size: uint64(len(file.content)),
			Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{
				CID: blobCID, Size: uint64(len(file.content)), MIMEType: publication.BlobMIMEType,
			},
		})
	}
	document := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: vault, PublicationID: publicationID,
		Entries: entries,
	}
	raw, err := publication.EncodeSnapshot(document)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: vault,
		SnapshotCID: mustShowcaseRecordCID(t, raw),
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	return showcaseServicePublication{
		document: document, raw: raw,
		block: publicationstate.SnapshotBlock{Key: key, Raw: raw}, head: head,
	}
}

func showcaseServiceFiles() []showcaseServiceFile {
	return []showcaseServiceFile{
		{path: "init.lua", mode: 0o600, content: []byte("synthetic showcase init")},
		{path: "lua/config/options.lua", mode: 0o644, content: []byte("synthetic showcase options")},
	}
}

func showcaseServiceObservation(
	t *testing.T,
	binding publicationstate.Binding,
	context publicationstate.SuppliedContext,
) publicationstate.Observation {
	t.Helper()
	showcase := newShowcaseServicePublication(t, binding.Vault, [16]byte{0x25, 0x72}, showcaseServiceFiles()...)
	return publicationstate.Observation{
		Origin: binding, SuppliedContext: context, Head: showcase.head,
		Snapshots: []publicationstate.SnapshotBlock{showcase.block},
	}
}

func mustShowcaseRecordCID(t *testing.T, raw []byte) []byte {
	t.Helper()
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	return cid
}

func requireShowcaseRefusal(t *testing.T, err error, want error) {
	t.Helper()
	require.ErrorIs(t, err, want)
	require.ErrorIs(t, err, publication.ErrShowcasePayload)
	var refusal *publication.ShowcasePayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, publication.ShowcaseReasonPackedRequired, refusal.Reason)
}

func TestStagePublicationAcceptRefusesAShowcaseObservation(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	observation := showcaseServiceObservation(t, fixture.binding, fixture.context)

	proposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding,
		Observation: observation, Payload: []byte("packed payload for a showcase observation"),
	})
	assert.Equal(t, PublicationAcceptProposal{}, proposal)
	requireShowcaseRefusal(t, err, ErrPublicationAccept)
	assertPublicationAcceptFailure(t, err, "accept-input", "payload_form")
}

func TestAcceptPublicationRefusesAShowcaseObservation(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	observation := showcaseServiceObservation(t, fixture.binding, fixture.context)

	floor, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: publicationstate.ModeFirstUse,
		Observation: observation, Payload: []byte("packed payload for a showcase observation"),
	})
	assert.Equal(t, publicationstate.Floor{}, floor)
	requireShowcaseRefusal(t, err, ErrPublicationAccept)
	assertPublicationAcceptFailure(t, err, "accept-input", "payload_form")
}

func TestPreparePublicationPushRefusesAShowcaseAcceptedPublication(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.reader.setPayload(publication.Payload{
		Form: publication.PayloadFormShowcase,
		Entries: []publication.PayloadEntry{{
			Path: "init.lua", Mode: 0o600, Size: 20, Content: []byte("synthetic showcase init"),
		}},
	})

	preparation, err := fixture.coordinator.PreparePublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
	)
	assert.Equal(t, PublicationPushPreparation{}, preparation)
	requireShowcaseRefusal(t, err, publication.ErrShowcasePayload)
	assert.Empty(t, fixture.records.records, "a refused push issued a retained record")
	assert.Zero(t, fixture.transport.sendCount(), "a refused push dispatched writes")
}

func TestMaterialWriteBatchRefusesAShowcaseCandidate(t *testing.T) {
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo,
		Vault: [32]byte{0x61},
	}
	binding.Repository = "at://" + binding.AccountDID
	showcase := newShowcaseServicePublication(t, binding.Vault, [16]byte{0x25, 0x73}, showcaseServiceFiles()...)

	batch, err := newMaterialWriteBatch(
		binding,
		nil,
		publicationstate.SuppliedRepositoryView{},
		publicationstate.CandidateInput{
			SnapshotKey: showcase.block.Key, SnapshotRecord: showcase.raw, HeadRecord: showcase.head,
			Payload: []byte("packed payload for a showcase candidate"),
		},
	)
	assert.Equal(t, MaterialWriteBatch{}, batch)
	requireShowcaseRefusal(t, err, publication.ErrShowcasePayload)
}

func newShowcasePushFixture(t *testing.T) *publicationPushFixture {
	t.Helper()
	fixture := newPublicationPushFixture(t)
	fixture.configuration.Targets[0].Showcase = true
	return fixture
}

func requireShowcasePlanRefusal(t *testing.T, err error) *showcasePublicationError {
	t.Helper()
	require.ErrorIs(t, err, ErrShowcasePublication)
	refusal, ok := errors.AsType[*showcasePublicationError](err)
	require.True(t, ok, "showcase refusal is not typed")
	return refusal
}

func requireNoShowcaseWorkStaged(t *testing.T, fixture *publicationPushFixture) {
	t.Helper()
	ctx := context.Background()
	assert.Zero(t, fixture.transport.uploadCount(), "upload count")
	assert.Zero(t, fixture.transport.prepareCount(), "prepared write count")
	assert.Zero(t, fixture.transport.sendCount(), "sent write count")
	_, active, err := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, active, "showcase refusal staged an attempt")
	_, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present, "showcase refusal staged a floor")
	_, issued := fixture.records.has(fixture.publicationID)
	assert.False(t, issued, "showcase refusal retained a proposal")
}

func TestShowcasePublicationPlanningRefusesASettingsEntryNamingIt(t *testing.T) {
	configuration := config.Config{
		Version: config.Version,
		Targets: []config.Target{
			{
				ID: "files", Source: model.SourceFiles, Mode: config.BackupOnly, Showcase: true,
				Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
			},
			{
				ID: "gnome", Source: model.SourceGNOME, Mode: config.BackupOnly,
				GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalPending},
			},
		},
	}
	require.NoError(t, configuration.Validate())
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{
			{
				ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
				Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
			},
			{ID: "gnome", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
		},
		Entries: []model.Entry{
			{TargetID: "files", File: &model.FileEntry{
				Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular,
				Content: []byte("synthetic showcase payload"), Mode: 0o600,
			}},
			{TargetID: "gnome", Setting: &model.SettingEntry{
				SchemaID: "org.gnome.desktop.interface",
				Path:     "/org/gnome/desktop/interface/",
				Key:      "color-scheme",
				State:    model.SettingPresent,
				Value:    &model.VariantValue{Type: "s", Text: "prefer-dark"},
			}},
		},
	}

	err := checkShowcasePublication(configuration, snapshot)
	assert.Contains(
		t,
		err.Error(),
		"gnome/gnome:org.gnome.desktop.interface:/org/gnome/desktop/interface/:color-scheme",
	)
	refusal := requireShowcasePlanRefusal(t, err)
	assert.Equal(t, model.EntryKey{
		TargetID: "gnome", Source: model.SourceGNOME, SchemaID: "org.gnome.desktop.interface",
		SettingsPath: "/org/gnome/desktop/interface/", SettingKey: "color-scheme",
	}, refusal.entry)
	assert.Equal(t, "entries.setting: unsupported", refusal.detail)
}

func TestShowcasePublicationPlanningRefusesAnEmptyManifest(t *testing.T) {
	configuration := config.Config{
		Version: config.Version,
		Targets: []config.Target{{
			ID: "files", Source: model.SourceFiles, Mode: config.BackupOnly, Showcase: true,
			Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
	}
	require.NoError(t, configuration.Validate())

	err := checkShowcasePublication(configuration, model.Snapshot{Version: model.SnapshotVersion})
	assert.Contains(t, err.Error(), "cannot be represented as a showcase manifest")
	refusal := requireShowcasePlanRefusal(t, err)
	assert.Equal(t, showcasePublicationReasonSnapshot, refusal.reason)
	assert.Equal(t, "entries: empty", refusal.detail)
	require.ErrorIs(t, err, publication.ErrShowcaseEntryUnsupported)
}

func TestPreparePublicationPushRefusesAShowcaseTargetWithADirectoryBeforeAnyUpload(t *testing.T) {
	ctx := context.Background()
	fixture := newShowcasePushFixture(t)
	require.NoError(t, os.MkdirAll(filepath.Join(fixture.paths.Home, "config", "lua"), 0o700))
	require.NoError(t, os.Chmod(filepath.Join(fixture.paths.Home, "config", "lua"), 0o700))
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "config", "lua", "options.lua"), []byte("options"), 0o600),
	)

	_, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	assert.Contains(t, err.Error(), "files/files:lua cannot be represented as a showcase entry")
	refusal := requireShowcasePlanRefusal(t, err)
	assert.Equal(t, model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "lua"}, refusal.entry)
	assert.Equal(t, "entries.directory: unsupported", refusal.detail)
	requireNoShowcaseWorkStaged(t, fixture)
}

func TestPreparePublicationPushRefusesAShowcaseTargetBeyondTheEntryLimit(t *testing.T) {
	ctx := context.Background()
	fixture := newShowcasePushFixture(t)
	for index := range publication.MaxSnapshotEntries {
		path := filepath.Join(fixture.paths.Home, "config", fmt.Sprintf("file-%03d.lua", index))
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("synthetic %d", index)), 0o600))
	}

	_, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	assert.Contains(t, err.Error(), "65 entries exceed the 64-entry limit of a showcase publication")
	refusal := requireShowcasePlanRefusal(t, err)
	assert.Equal(t, publication.MaxSnapshotEntries+1, refusal.count)
	assert.Equal(t, publication.MaxSnapshotEntries, refusal.limit)
	requireNoShowcaseWorkStaged(t, fixture)
}

func TestPreparePublicationPushRefusesToPackAShowcaseTarget(t *testing.T) {
	ctx := context.Background()
	fixture := newShowcasePushFixture(t)

	_, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	assert.Contains(t, err.Error(), "publishing a showcase payload is not available in this build")
	assert.NotContains(t, err.Error(), "packed")
	requireShowcasePlanRefusal(t, err)
	requireNoShowcaseWorkStaged(t, fixture)
}

func TestPreparePublicationPushKeepsPackingTargetsWithoutTheOptIn(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)

	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	assert.False(t, preparation.NoOp)
	assert.Equal(t, 1, preparation.Targets)
	assert.Equal(t, 1, preparation.Entries)
	record, err := publication.DecodeSnapshot(preparation.Proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormPacked, record.PayloadForm())
}
