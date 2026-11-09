package local_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const publicationReconcileTargetID = "synthetic-files"

var publicationReconcileInitial = []byte("source A initial settings\n")
var publicationReconcileSuccessor = []byte("source A successor settings\n")
var publicationReconcileSentinelA = []byte("source A local-only sentinel\n")
var publicationReconcileSentinelB = []byte("destination B local-only sentinel\n")

type publicationReconcileHome struct {
	paths    platform.Paths
	root     string
	selected string
	sentinel string
	local    *service.PublicationLocalContext
	pubStore *publicationstate.Store
	floor    publicationstate.Floor
	base     *service.PublicationReconciliationBase
}

type publicationReconcileMaterial struct {
	payload   []byte
	key       string
	record    []byte
	recordCID []byte
	head      []byte
}

func TestPublicationReconcileTwoHomeRegularFileApplyRollback(t *testing.T) {
	ctx := context.Background()
	target := config.Target{
		ID: publicationReconcileTargetID, Source: model.SourceFiles,
		Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory, Exclude: []string{"machine-only"}},
	}
	portable, err := target.Model()
	require.NoError(t, err)
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, configuration.Validate())

	homeA := newPublicationReconcileHome(t, publicationReconcileSentinelA)
	homeB := newPublicationReconcileHome(t, publicationReconcileSentinelB)
	writePublicationReconcileFile(t, filepath.Join(homeA.selected, "settings.ini"), publicationReconcileInitial, 0o600)
	writePublicationReconcileFile(t, filepath.Join(homeB.selected, "settings.ini"), publicationReconcileInitial, 0o600)

	initialEntries := capturePublicationReconcileSource(t, homeA, target, publicationReconcileInitial)
	initialSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: initialEntries}
	require.NoError(t, initialSnapshot.Validate())
	binding := publicationReconcileBinding()
	suppliedContext := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	initial := encodePublicationReconcileMaterial(t, binding, initialSnapshot, 0, nil, [16]byte{0x25, 0x71})

	initialObservation := publicationReconcileObservation(binding, suppliedContext, initial)
	homeA.floor = acceptPublicationReconcilePosition(t, homeA.pubStore, publicationstate.ModeFirstUse, initialObservation, initial.payload)
	homeB.floor = acceptPublicationReconcilePosition(t, homeB.pubStore, publicationstate.ModeFirstUse, initialObservation, initial.payload)
	require.NotEqual(t, [32]byte{}, homeA.floor.DatabaseID)
	require.NotEqual(t, [32]byte{}, homeB.floor.DatabaseID)
	assert.NotEqual(t, homeA.floor.DatabaseID, homeB.floor.DatabaseID)
	assert.Equal(t, binding, homeA.floor.Binding)
	assert.Equal(t, binding, homeB.floor.Binding)
	assert.Equal(t, initial.record, homeA.floorRecord(t, 1))
	assert.Equal(t, initial.record, homeB.floorRecord(t, 1))
	assert.Equal(t, initial.recordCID, homeA.floor.RecordCID)
	assert.Equal(t, initial.recordCID, homeB.floor.RecordCID)
	initialRecord, err := publication.DecodeSnapshot(initial.record)
	require.NoError(t, err)
	assert.Equal(t, initialRecord.Blob.CID, homeA.floor.BlobCID)
	assert.Equal(t, initialRecord.Blob.CID, homeB.floor.BlobCID)
	assert.Equal(t, initial.key, homeA.floor.SnapshotKey)
	assert.Equal(t, initial.key, homeB.floor.SnapshotKey)
	assert.Equal(t, uint64(len(initial.payload)), homeA.floor.BlobSize)
	assert.Equal(t, uint64(len(initial.payload)), homeB.floor.BlobSize)

	homeA.local = newPublicationReconcileContext(t, homeA.paths)
	homeB.local = newPublicationReconcileContext(t, homeB.paths)
	assert.NotSame(t, homeA.local, homeB.local)
	initialRequestA := publicationReconcileRequest(homeA, binding, initial, configuration, homeA.local)
	initialRequestB := publicationReconcileRequest(homeB, binding, initial, configuration, homeB.local)
	homeA.base, err = service.EstablishLocalReconciliationBase(ctx, initialRequestA)
	require.NoError(t, err)
	require.NotNil(t, homeA.base)
	homeB.base, err = service.EstablishLocalReconciliationBase(ctx, initialRequestB)
	require.NoError(t, err)
	require.NotNil(t, homeB.base)

	writePublicationReconcileFile(t, filepath.Join(homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	successorEntries := capturePublicationReconcileSource(t, homeA, target, publicationReconcileSuccessor)
	successorSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: successorEntries}
	require.NoError(t, successorSnapshot.Validate())
	successor := encodePublicationReconcileMaterial(t, binding, successorSnapshot, 1, initial.recordCID, [16]byte{0x25, 0x72})
	successorObservation := publicationReconcileObservation(binding, suppliedContext, successor, initial)
	previousDatabaseIDA := homeA.floor.DatabaseID
	previousDatabaseIDB := homeB.floor.DatabaseID
	previousGenerationA := homeA.floor.Generation
	previousGenerationB := homeB.floor.Generation
	homeA.floor = acceptPublicationReconcilePosition(t, homeA.pubStore, publicationstate.ModeAdvance, successorObservation, successor.payload)
	homeB.floor = acceptPublicationReconcilePosition(t, homeB.pubStore, publicationstate.ModeAdvance, successorObservation, successor.payload)
	assert.Equal(t, previousDatabaseIDA, homeA.floor.DatabaseID)
	assert.Equal(t, previousDatabaseIDB, homeB.floor.DatabaseID)
	assert.Equal(t, previousGenerationA, homeA.floor.Generation)
	assert.Equal(t, previousGenerationB, homeB.floor.Generation)
	assert.Equal(t, successor.record, homeA.floorRecord(t, 2))
	assert.Equal(t, successor.record, homeB.floorRecord(t, 2))
	assert.Equal(t, successor.recordCID, homeA.floor.RecordCID)
	assert.Equal(t, successor.recordCID, homeB.floor.RecordCID)
	successorRecord, err := publication.DecodeSnapshot(successor.record)
	require.NoError(t, err)
	assert.Equal(t, successorRecord.Blob.CID, homeA.floor.BlobCID)
	assert.Equal(t, successorRecord.Blob.CID, homeB.floor.BlobCID)
	assert.Equal(t, successor.key, homeA.floor.SnapshotKey)
	assert.Equal(t, successor.key, homeB.floor.SnapshotKey)
	assert.Equal(t, uint64(len(successor.payload)), homeA.floor.BlobSize)
	assert.Equal(t, uint64(len(successor.payload)), homeB.floor.BlobSize)

	requestA := publicationReconcileRequest(homeA, binding, successor, configuration, homeA.local)
	requestB := publicationReconcileRequest(homeB, binding, successor, configuration, homeB.local)
	previewA, dispositionA, err := service.PreviewPublicationTarget(ctx, requestA, homeA.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionA)
	assert.True(t, previewA.Complete)
	entryA := publicationReconcilePreviewEntry(t, previewA, "settings.ini")
	assert.Equal(t, syncengine.ActionUnchanged, entryA.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonEqual, entryA.Reason)
	assertPublicationReconcileNoSentinelPreview(t, previewA)
	assertPublicationReconcileFile(t, filepath.Join(homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileFile(t, homeA.sentinel, publicationReconcileSentinelA, 0o640)

	previewB, dispositionB, err := service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	assert.True(t, previewB.Complete)
	entryB := publicationReconcilePreviewEntry(t, previewB, "settings.ini")
	assert.Equal(t, syncengine.ActionDownload, entryB.DecisionAction)
	assert.Equal(t, syncengine.PreviewChange, entryB.Action)
	assert.Equal(t, syncengine.PreviewReasonRemoteChanged, entryB.Reason)
	assertPublicationReconcileNoSentinelPreview(t, previewB)
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "settings.ini"), publicationReconcileInitial, 0o600)
	assertPublicationReconcileFile(t, homeB.sentinel, publicationReconcileSentinelB, 0o640)

	stateStore, err := state.Open(homeB.paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, stateStore.Close()) })
	require.NoError(t, stateStore.PutTarget(ctx, state.TargetDescriptor{
		ID: publicationReconcileTargetID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		LogicalBase: model.RootHome, LogicalPath: "synthetic", Kind: model.SelectionDirectory,
		Mode: string(config.Review), CreatedAt: 1,
	}))
	journal, err := stateStore.JournalEntriesAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, journal)
	postimages := publicationReconcilePostimages(t, previewB, successor.record, successor.payload)
	require.Len(t, postimages, 1)
	require.Equal(t, publicationReconcileTargetID, postimages[0].TargetID)
	require.Equal(t, "settings.ini", postimages[0].Key)
	require.Equal(t, publicationReconcileSuccessor, postimages[0].Data)
	require.Equal(t, os.FileMode(0o600), postimages[0].Mode.Perm())
	require.NoError(t, syncengine.Apply(ctx, stateStore, syncengine.ApplyRequest{
		Preview: previewB, Roots: map[string]string{publicationReconcileTargetID: homeB.root},
		ModePolicy: syncengine.ModePolicy{Default: 0o600}, Content: postimages, Now: publicationReconcileClock,
	}))

	assertPublicationReconcileFile(t, filepath.Join(homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileFile(t, homeA.sentinel, publicationReconcileSentinelA, 0o640)
	assertPublicationReconcileFile(t, homeB.sentinel, publicationReconcileSentinelB, 0o640)
	previewB, dispositionB, err = service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	assert.True(t, previewB.Complete)
	entryB = publicationReconcilePreviewEntry(t, previewB, "settings.ini")
	assert.Equal(t, syncengine.ActionUnchanged, entryB.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonEqual, entryB.Reason)

	journal, err = stateStore.JournalEntriesAll(ctx)
	require.NoError(t, err)
	require.Len(t, journal, 1)
	appliedJournal := journal[0]
	assert.Equal(t, "replace", appliedJournal.Operation)
	assert.Equal(t, "applied", appliedJournal.State)
	assert.Equal(t, state.JournalStageVerified, appliedJournal.Stage)
	assert.Nil(t, appliedJournal.Retention)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, appliedJournal.Identity)
	assert.Equal(t, filepath.Clean(homeB.root), appliedJournal.RootPath)
	assert.Equal(t, "settings.ini", appliedJournal.DestinationPath)
	require.NotEmpty(t, appliedJournal.BackupRef)
	backup, err := stateStore.Payload(appliedJournal.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, publicationReconcileInitial, backup)
	pending, err := stateStore.PendingJournalEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)

	rollback, err := syncengine.RollbackApplied(ctx, stateStore, nil, publicationReconcileClock)
	require.NoError(t, err)
	require.Len(t, rollback.Entries, 1)
	assert.Equal(t, appliedJournal.ID, rollback.Entries[0].JournalID)
	assert.Equal(t, "rolled-back", rollback.Entries[0].Outcome)
	assert.Empty(t, rollback.Pruned)
	assertPublicationReconcileFile(t, filepath.Join(homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "settings.ini"), publicationReconcileInitial, 0o600)
	assertPublicationReconcileFile(t, homeA.sentinel, publicationReconcileSentinelA, 0o640)
	assertPublicationReconcileFile(t, homeB.sentinel, publicationReconcileSentinelB, 0o640)
	journal, err = stateStore.JournalEntriesAll(ctx)
	require.NoError(t, err)
	require.Len(t, journal, 1)
	rolledBackJournal := journal[0]
	assert.Equal(t, appliedJournal.ID, rolledBackJournal.ID)
	assert.Equal(t, "rolled-back", rolledBackJournal.State)
	assert.Equal(t, state.JournalStageRolledBack, rolledBackJournal.Stage)
	assert.Nil(t, rolledBackJournal.Retention)
	assert.Equal(t, appliedJournal.BackupRef, rolledBackJournal.BackupRef)
	pruned, err := stateStore.PruneJournalBackupIfEligible(ctx, rolledBackJournal.ID, publicationReconcileClock().Add(8*24*time.Hour))
	require.NoError(t, err)
	assert.False(t, pruned)
	backup, err = stateStore.Payload(rolledBackJournal.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, publicationReconcileInitial, backup)
	pending, err = stateStore.PendingJournalEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)

	previewB, dispositionB, err = service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	assert.True(t, previewB.Complete)
	entryB = publicationReconcilePreviewEntry(t, previewB, "settings.ini")
	assert.Equal(t, syncengine.ActionDownload, entryB.DecisionAction)
	assert.Equal(t, syncengine.PreviewChange, entryB.Action)
	assert.Equal(t, syncengine.PreviewReasonRemoteChanged, entryB.Reason)
}

func newPublicationReconcileHome(t *testing.T, sentinel []byte) *publicationReconcileHome {
	t.Helper()
	root := canonicalPublicationReconcileTempDir(t)
	home := filepath.Join(root, "home")
	paths := platform.Paths{
		Home: home, ConfigHome: filepath.Join(home, ".config"),
		StateHome: filepath.Join(home, ".local", "state"), CacheHome: filepath.Join(home, ".cache"),
		DataHome: filepath.Join(home, ".local", "share"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	selected := filepath.Join(paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(selected, 0o700))
	selected, err := filepath.EvalSymlinks(selected)
	require.NoError(t, err)
	sentinelPath := filepath.Join(selected, "machine-only")
	writePublicationReconcileFile(t, sentinelPath, sentinel, 0o640)

	publicationDirectory := filepath.Join(root, "publication-state")
	require.NoError(t, os.Mkdir(publicationDirectory, 0o700))
	store, err := publicationstate.Open(publicationDirectory, publicationReconcileBinding())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return &publicationReconcileHome{paths: paths, root: selected, selected: selected, sentinel: sentinelPath, pubStore: store}
}

func canonicalPublicationReconcileTempDir(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs(t.TempDir())
	require.NoError(t, err)
	resolved, err := filepath.EvalSymlinks(absolute)
	require.NoError(t, err)
	return filepath.Clean(resolved)
}

func newPublicationReconcileContext(t *testing.T, paths platform.Paths) *service.PublicationLocalContext {
	t.Helper()
	local, err := service.NewPublicationLocalContext(paths, nil, nil)
	require.NoError(t, err)
	return local
}

func publicationReconcileBinding() publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo,
		Repository: "at://did:plc:abcdefghijklmnopqrstuvwx", Vault: [32]byte{0x41, 0x52, 0x63},
	}
	return binding
}

func capturePublicationReconcileSource(t *testing.T, home *publicationReconcileHome, target config.Target, expected []byte) []model.Entry {
	t.Helper()
	captured, err := (service.LocalFilesCapture{}).Capture(context.Background(), target, home.selected)
	require.NoError(t, err)
	require.Len(t, captured.Observations, 1)
	observation := captured.Observations[0]
	require.Equal(t, model.ObservationPresent, observation.State)
	require.NotNil(t, observation.Entry)
	require.NotNil(t, observation.Entry.File)
	assert.Equal(t, "settings.ini", observation.Entry.File.Path)
	assert.Equal(t, model.FileRegular, observation.Entry.File.Kind)
	assert.Equal(t, expected, observation.Entry.File.Content)
	assert.Equal(t, uint32(0o600), observation.Entry.File.Mode)
	require.Len(t, captured.Skipped, 1)
	assert.Equal(t, "machine-only", captured.Skipped[0].Path)
	assert.Equal(t, files.SkipExcluded, captured.Skipped[0].Reason)
	entry := *observation.Entry
	entry.File.Content = bytes.Clone(observation.Entry.File.Content)
	return []model.Entry{entry}
}

func encodePublicationReconcileMaterial(t *testing.T, binding publicationstate.Binding, snapshot model.Snapshot, sequence uint64, parent []byte, publicationID [16]byte) publicationReconcileMaterial {
	t.Helper()
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	recordRaw, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID,
		PublicationSeq: sequence, Parent: bytes.Clone(parent),
		Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))},
	})
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(recordRaw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: sequence,
		SnapshotCID: recordCID, BlobCID: blobCID,
	})
	require.NoError(t, err)
	return publicationReconcileMaterial{payload: bytes.Clone(packed.Payload), key: key, record: recordRaw, recordCID: recordCID, head: head}
}

func publicationReconcileObservation(binding publicationstate.Binding, supplied publicationstate.SuppliedContext, current publicationReconcileMaterial, previous ...publicationReconcileMaterial) publicationstate.Observation {
	blocks := make([]publicationstate.SnapshotBlock, 0, len(previous)+1)
	for _, item := range previous {
		blocks = append(blocks, publicationstate.SnapshotBlock{Key: item.key, Raw: bytes.Clone(item.record)})
	}
	blocks = append(blocks, publicationstate.SnapshotBlock{Key: current.key, Raw: bytes.Clone(current.record)})
	return publicationstate.Observation{Origin: binding, SuppliedContext: supplied, Head: bytes.Clone(current.head), Snapshots: blocks}
}

func acceptPublicationReconcilePosition(t *testing.T, store *publicationstate.Store, mode publicationstate.Mode, observation publicationstate.Observation, payload []byte) publicationstate.Floor {
	t.Helper()
	proposal, err := store.Prepare(context.Background(), mode, observation, payload)
	require.NoError(t, err)
	floor, err := store.Accept(context.Background(), mode, proposal.StateToken, observation, payload, proposal.Confirmation)
	require.NoError(t, err)
	return floor
}

func publicationReconcileRequest(home *publicationReconcileHome, binding publicationstate.Binding, material publicationReconcileMaterial, configuration config.Config, local *service.PublicationLocalContext) service.PublicationReconciliationRequest {
	return service.PublicationReconciliationRequest{
		Store: home.pubStore, Binding: binding, ExpectedFloor: home.floor,
		SnapshotRecord: bytes.Clone(material.record), Payload: bytes.Clone(material.payload),
		Configuration: configuration, TargetID: publicationReconcileTargetID, Local: local,
	}
}

func publicationReconcilePreviewEntry(t *testing.T, preview syncengine.Preview, path string) syncengine.PreviewEntry {
	t.Helper()
	var matches []syncengine.PreviewEntry
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Key.TargetID == publicationReconcileTargetID && entry.Key.FilePath == path {
				matches = append(matches, entry)
			}
		}
	}
	require.Len(t, matches, 1)
	return matches[0]
}

func assertPublicationReconcileNoSentinelPreview(t *testing.T, preview syncengine.Preview) {
	t.Helper()
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			assert.NotEqual(t, "machine-only", entry.Key.FilePath)
		}
	}
}

func publicationReconcilePostimages(t *testing.T, preview syncengine.Preview, recordRaw, payload []byte) []syncengine.Postimage {
	t.Helper()
	record, err := publication.DecodeSnapshot(recordRaw)
	require.NoError(t, err)
	snapshot, err := publication.DecodePayload(payload, record.Blob)
	require.NoError(t, err)
	postimages := make([]syncengine.Postimage, 0, 1)
	for _, target := range preview.Targets {
		for _, previewEntry := range target.Entries {
			if previewEntry.Key.TargetID != publicationReconcileTargetID || previewEntry.Key.FilePath != "settings.ini" || previewEntry.DecisionAction != syncengine.ActionDownload {
				continue
			}
			var candidates []model.Entry
			for _, entry := range snapshot.Entries {
				if entry.Identity() == previewEntry.Key {
					candidates = append(candidates, entry)
				}
			}
			require.Len(t, candidates, 1)
			require.NotNil(t, candidates[0].File)
			require.Equal(t, model.FileRegular, candidates[0].File.Kind)
			require.Equal(t, publicationReconcileSuccessor, candidates[0].File.Content)
			require.Equal(t, uint32(0o600), candidates[0].File.Mode)
			digest := sha256.Sum256(candidates[0].File.Content)
			postimages = append(postimages, syncengine.Postimage{
				TargetID: previewEntry.Key.TargetID, Key: previewEntry.Key.FilePath,
				Data: bytes.Clone(candidates[0].File.Content), Digest: bytes.Clone(digest[:]), Mode: os.FileMode(candidates[0].File.Mode),
			})
		}
	}
	return postimages
}

func assertPublicationReconcileFile(t *testing.T, path string, expected []byte, mode os.FileMode) {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, expected, content)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, mode.Perm(), info.Mode().Perm())
}

func writePublicationReconcileFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, mode))
	require.NoError(t, os.Chmod(path, mode))
}

func publicationReconcileClock() time.Time {
	return time.Unix(100, 0)
}

func (home *publicationReconcileHome) floorRecord(t *testing.T, revision uint64) []byte {
	t.Helper()
	page, err := home.pubStore.History(context.Background(), revision-1, 1)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	for _, evidence := range page.Records {
		if evidence.Reference.Key == page.Events[0].NewFloor.SnapshotKey && bytes.Equal(evidence.Reference.CID, page.Events[0].NewFloor.RecordCID) {
			return bytes.Clone(evidence.Raw)
		}
	}
	require.FailNow(t, "accepted record must be present in public history")
	return nil
}
