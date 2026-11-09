package local_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReconcileRollbackPreservesNewerEdit(t *testing.T) {
	fixture := newPublicationReconcileRollbackFixture(t)
	require.NoError(t, syncengine.Apply(fixture.ctx, fixture.store, publicationReconcileRollbackApplyRequest(fixture, nil)))
	assertPublicationReconcileFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileRollbackNoAppliedBase(t, fixture)

	applied := publicationReconcileRollbackJournal(t, fixture)
	require.NotEmpty(t, applied.ID)
	assertPublicationReconcileRollbackRow(t, fixture, applied, applied.ID, "applied", state.JournalStageVerified)
	assertPublicationReconcileRollbackBackup(t, fixture, applied)

	newerEdit := []byte("destination B independent newer edit\n")
	writePublicationReconcileFile(t, fixture.destination, newerEdit, 0o600)
	assertPublicationReconcileFile(t, fixture.destination, newerEdit, 0o600)

	rollback, err := syncengine.RollbackApplied(fixture.ctx, fixture.store, nil, publicationReconcileClock)
	require.NoError(t, err)
	require.Len(t, rollback.Entries, 1)
	assert.Equal(t, "destination no longer matches intended postimage; left unchanged", rollback.Entries[0].Reason)
	assert.Empty(t, rollback.Pruned)
	assert.Equal(t, applied.ID, rollback.Entries[0].JournalID)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, rollback.Entries[0].Key)
	assert.Equal(t, "skipped-newer-edit", rollback.Entries[0].Outcome)

	skipped := publicationReconcileRollbackJournal(t, fixture)
	assertPublicationReconcileRollbackRow(t, fixture, skipped, applied.ID, "applied", state.JournalStageRollbackSkipped)
	assert.Equal(t, applied.BackupRef, skipped.BackupRef)
	assertPublicationReconcileRollbackBackup(t, fixture, skipped)
	assertPublicationReconcileFile(t, fixture.destination, newerEdit, 0o600)
	assertPublicationReconcileFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
	assertPublicationReconcileFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)

	preview, disposition, err := service.PreviewPublicationTarget(fixture.ctx, fixture.request, fixture.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, disposition)
	assert.False(t, preview.Complete)
	assert.Equal(t, 1, preview.UnresolvedEntries)
	require.Len(t, preview.Targets, 1)
	assert.Equal(t, publicationReconcileTargetID, preview.Targets[0].ID)
	require.Len(t, preview.Targets[0].Entries, 1)
	entry := preview.Targets[0].Entries[0]
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, entry.Key)
	assert.Equal(t, syncengine.PreviewStateConflict, entry.State)
	assert.Equal(t, syncengine.ActionConflict, entry.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonConflict, entry.Reason)
	assert.Equal(t, string(syncengine.ReasonDivergence), entry.Detail)
	assertPublicationReconcileNoSentinelPreview(t, preview)

	agedClock := func() time.Time {
		return time.Unix(applied.CreatedAt, 0).Add(state.JournalBackupRetention + time.Second)
	}
	repeated, err := syncengine.RollbackApplied(fixture.ctx, fixture.store, nil, agedClock)
	require.NoError(t, err)
	require.Len(t, repeated.Entries, 1)
	assert.Equal(t, "a previous rollback preserved a newer edit; this outcome is durable", repeated.Entries[0].Reason)
	assert.Equal(t, applied.ID, repeated.Entries[0].JournalID)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, repeated.Entries[0].Key)
	assert.Equal(t, "skipped-newer-edit", repeated.Entries[0].Outcome)
	assert.Empty(t, repeated.Pruned)

	repeatedJournal := publicationReconcileRollbackJournal(t, fixture)
	assertPublicationReconcileRollbackRow(t, fixture, repeatedJournal, applied.ID, "applied", state.JournalStageRollbackSkipped)
	assert.Equal(t, applied.BackupRef, repeatedJournal.BackupRef)
	assertPublicationReconcileRollbackBackup(t, fixture, repeatedJournal)
	assertPublicationReconcileFile(t, fixture.destination, newerEdit, 0o600)
	assertPublicationReconcileFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
	assertPublicationReconcileFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)
}

func TestPublicationReconcileIndeterminateApplyRetainsBackup(t *testing.T) {
	fixture := newPublicationReconcileRollbackFixture(t)
	fault := errors.New("synthetic post-rename fault")
	filesystem := &publicationReconcileRollbackRenameFS{
		base: files.DefaultApplyFileSystem(), destination: "settings.ini", fault: fault,
	}
	applyErr := syncengine.Apply(fixture.ctx, fixture.store, publicationReconcileRollbackApplyRequest(fixture, filesystem))
	assertPublicationReconcileRollbackNoAppliedBase(t, fixture)
	require.ErrorIs(t, applyErr, fault)
	var filesystemError *files.ApplyError
	require.ErrorAs(t, applyErr, &filesystemError)
	assert.Equal(t, files.ApplyStageRename, filesystemError.Stage)
	var partial *syncengine.PartialApplyError
	assert.False(t, errors.As(applyErr, &partial))
	require.True(t, filesystem.faultReturned)
	require.Len(t, filesystem.renames, 1)
	assert.Equal(t, "settings.ini", filesystem.renames[0].destination)
	assert.True(t, filesystem.renames[0].delegateSucceeded)
	assert.True(t, filesystem.renames[0].sentinelReturned)

	indeterminate := publicationReconcileRollbackJournal(t, fixture)
	require.NotEmpty(t, indeterminate.ID)
	assertPublicationReconcileRollbackRow(t, fixture, indeterminate, indeterminate.ID, "indeterminate", state.JournalStageIndeterminate)
	assertPublicationReconcileRollbackBackup(t, fixture, indeterminate)
	assertPublicationReconcileFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcileFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
	assertPublicationReconcileFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)
	pending, err := fixture.store.PendingJournalEntries(fixture.ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)

	rollback, err := syncengine.RollbackApplied(fixture.ctx, fixture.store, nil, publicationReconcileClock)
	require.NoError(t, err)
	assert.Empty(t, rollback.Entries)
	assert.Empty(t, rollback.Pruned)
	rolledBackJournal := publicationReconcileRollbackJournal(t, fixture)
	assertPublicationReconcileRollbackRow(t, fixture, rolledBackJournal, indeterminate.ID, "indeterminate", state.JournalStageIndeterminate)
	assert.Equal(t, indeterminate.BackupRef, rolledBackJournal.BackupRef)
	assertPublicationReconcileRollbackBackup(t, fixture, rolledBackJournal)
	assertPublicationReconcileFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)

	agedClock := time.Unix(indeterminate.CreatedAt, 0).Add(state.JournalBackupRetention + time.Second)
	pruned, err := fixture.store.PruneExpiredJournalBackups(fixture.ctx, agedClock)
	require.NoError(t, err)
	assert.Empty(t, pruned)
	prunedOne, err := fixture.store.PruneJournalBackupIfEligible(fixture.ctx, indeterminate.ID, agedClock)
	require.Error(t, err)
	assert.Equal(t, "journal backup can only be pruned after verified rollback or seven-day expiry of a verified apply", err.Error())
	assert.False(t, prunedOne)
	prunedJournal := publicationReconcileRollbackJournal(t, fixture)
	assertPublicationReconcileRollbackRow(t, fixture, prunedJournal, indeterminate.ID, "indeterminate", state.JournalStageIndeterminate)
	assert.Equal(t, indeterminate.BackupRef, prunedJournal.BackupRef)
	assertPublicationReconcileRollbackBackup(t, fixture, prunedJournal)
	assertPublicationReconcileFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)

	preview, disposition, err := service.PreviewPublicationTarget(fixture.ctx, fixture.request, fixture.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, disposition)
	assert.True(t, preview.Complete)
	require.Len(t, preview.Targets, 1)
	assert.Equal(t, publicationReconcileTargetID, preview.Targets[0].ID)
	require.Len(t, preview.Targets[0].Entries, 1)
	entry := preview.Targets[0].Entries[0]
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, entry.Key)
	assert.Equal(t, syncengine.ActionUnchanged, entry.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonEqual, entry.Reason)
	assertPublicationReconcileNoSentinelPreview(t, preview)

	finalJournal := publicationReconcileRollbackJournal(t, fixture)
	assertPublicationReconcileRollbackRow(t, fixture, finalJournal, indeterminate.ID, "indeterminate", state.JournalStageIndeterminate)
	assert.Equal(t, indeterminate.BackupRef, finalJournal.BackupRef)
	assertPublicationReconcileRollbackBackup(t, fixture, finalJournal)
	assertPublicationReconcileFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)
}

type publicationReconcileRollbackFixture struct {
	ctx         context.Context
	homeA       *publicationReconcileHome
	homeB       *publicationReconcileHome
	base        *service.PublicationReconciliationBase
	request     service.PublicationReconciliationRequest
	preview     syncengine.Preview
	postimages  []syncengine.Postimage
	store       *state.Store
	destination string
}

func newPublicationReconcileRollbackFixture(t *testing.T) *publicationReconcileRollbackFixture {
	t.Helper()
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
	for _, home := range []*publicationReconcileHome{homeA, homeB} {
		writePublicationReconcileFile(t, filepath.Join(home.selected, "settings.ini"), publicationReconcileInitial, 0o600)
	}
	initialEntriesA := capturePublicationReconcileSource(t, homeA, target, publicationReconcileInitial)
	initialEntriesB := capturePublicationReconcileSource(t, homeB, target, publicationReconcileInitial)
	assert.Equal(t, initialEntriesA, initialEntriesB)
	initialSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: initialEntriesA}
	require.NoError(t, initialSnapshot.Validate())
	binding := publicationReconcileBinding()
	suppliedContext := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	initial := encodePublicationReconcileMaterial(t, binding, initialSnapshot, 0, nil, [16]byte{0x25, 0x91})
	initialObservation := publicationReconcileObservation(binding, suppliedContext, initial)
	homeA.floor = acceptPublicationReconcilePosition(t, homeA.pubStore, publicationstate.ModeFirstUse, initialObservation, initial.payload)
	homeB.floor = acceptPublicationReconcilePosition(t, homeB.pubStore, publicationstate.ModeFirstUse, initialObservation, initial.payload)

	homeB.local = newPublicationReconcileContext(t, homeB.paths)
	initialRequest := publicationReconcileRequest(homeB, binding, initial, configuration, homeB.local)
	base, err := service.EstablishLocalReconciliationBase(ctx, initialRequest)
	require.NoError(t, err)
	require.NotNil(t, base)
	homeB.base = base

	writePublicationReconcileFile(t, filepath.Join(homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	successorEntries := capturePublicationReconcileSource(t, homeA, target, publicationReconcileSuccessor)
	successorSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: successorEntries}
	require.NoError(t, successorSnapshot.Validate())
	successor := encodePublicationReconcileMaterial(t, binding, successorSnapshot, 1, initial.recordCID, [16]byte{0x25, 0x92})
	successorObservation := publicationReconcileObservation(binding, suppliedContext, successor, initial)
	homeA.floor = acceptPublicationReconcilePosition(t, homeA.pubStore, publicationstate.ModeAdvance, successorObservation, successor.payload)
	homeB.floor = acceptPublicationReconcilePosition(t, homeB.pubStore, publicationstate.ModeAdvance, successorObservation, successor.payload)
	request := publicationReconcileRequest(homeB, binding, successor, configuration, homeB.local)
	preview, disposition, err := service.PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, disposition)
	assert.True(t, preview.Complete)
	require.Len(t, preview.Targets, 1)
	assert.Equal(t, publicationReconcileTargetID, preview.Targets[0].ID)
	require.Len(t, preview.Targets[0].Entries, 1)
	previewEntry := preview.Targets[0].Entries[0]
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "settings.ini"), publicationReconcileInitial, 0o600)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, previewEntry.Key)
	assert.Equal(t, syncengine.ActionDownload, previewEntry.DecisionAction)
	assert.Equal(t, syncengine.PreviewChange, previewEntry.Action)
	assert.Equal(t, syncengine.PreviewReasonRemoteChanged, previewEntry.Reason)
	postimages := publicationReconcilePostimages(t, preview, successor.record, successor.payload)
	require.Len(t, postimages, 1)
	assert.Equal(t, publicationReconcileTargetID, postimages[0].TargetID)
	assert.Equal(t, "settings.ini", postimages[0].Key)
	assert.Equal(t, publicationReconcileSuccessor, postimages[0].Data)
	assert.Equal(t, os.FileMode(0o600), postimages[0].Mode.Perm())

	store, err := state.Open(homeB.paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	require.NoError(t, store.PutTarget(ctx, state.TargetDescriptor{
		ID: publicationReconcileTargetID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		LogicalBase: model.RootHome, LogicalPath: "synthetic", Kind: model.SelectionDirectory,
		Mode: string(config.Review), CreatedAt: 1,
	}))
	bases, err := store.AppliedBase(ctx, publicationReconcileTargetID)
	require.NoError(t, err)
	assert.Empty(t, bases)
	journal, err := store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, journal)

	return &publicationReconcileRollbackFixture{
		ctx: ctx, homeA: homeA, homeB: homeB, base: base, request: request,
		preview: preview, postimages: postimages, store: store,
		destination: filepath.Join(homeB.root, "settings.ini"),
	}
}

func publicationReconcileRollbackApplyRequest(fixture *publicationReconcileRollbackFixture, filesystem files.ApplyFileSystem) syncengine.ApplyRequest {
	return syncengine.ApplyRequest{
		Preview: fixture.preview, Roots: map[string]string{publicationReconcileTargetID: fixture.homeB.root},
		ModePolicy: syncengine.ModePolicy{Default: 0o600}, Content: fixture.postimages,
		FileSystem: filesystem, Now: publicationReconcileClock,
	}
}

func assertPublicationReconcileRollbackNoAppliedBase(t *testing.T, fixture *publicationReconcileRollbackFixture) {
	t.Helper()
	bases, err := fixture.store.AppliedBase(fixture.ctx, publicationReconcileTargetID)
	require.NoError(t, err)
	assert.Empty(t, bases)
}

func publicationReconcileRollbackJournal(t *testing.T, fixture *publicationReconcileRollbackFixture) state.JournalEntry {
	t.Helper()
	journal, err := fixture.store.JournalEntriesAll(fixture.ctx)
	require.NoError(t, err)
	require.Len(t, journal, 1)
	return journal[0]
}

func assertPublicationReconcileRollbackRow(t *testing.T, fixture *publicationReconcileRollbackFixture, entry state.JournalEntry, id, expectedState, expectedStage string) {
	t.Helper()
	assert.Equal(t, id, entry.ID)
	assert.Equal(t, "replace", entry.Operation)
	assert.Equal(t, expectedState, entry.State)
	assert.Equal(t, expectedStage, entry.Stage)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, entry.Identity)
	assert.Equal(t, filepath.Clean(fixture.homeB.root), entry.RootPath)
	assert.Equal(t, "settings.ini", entry.DestinationPath)
	assert.Equal(t, state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", publicationReconcileInitial), entry.Preimage)
	assert.Equal(t, state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", publicationReconcileSuccessor), entry.Postimage)
	assert.Nil(t, entry.Retention)
	assert.NotEmpty(t, entry.BackupRef)
}

func assertPublicationReconcileRollbackBackup(t *testing.T, fixture *publicationReconcileRollbackFixture, entry state.JournalEntry) {
	t.Helper()
	backup, err := fixture.store.Payload(entry.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, publicationReconcileInitial, backup)
	assert.Equal(t, entry.Preimage.Size, int64(len(backup)))
}

type publicationReconcileRollbackRenameEvent struct {
	destination       string
	delegateSucceeded bool
	sentinelReturned  bool
}

type publicationReconcileRollbackRenameFS struct {
	base          files.ApplyFileSystem
	destination   string
	fault         error
	faultReturned bool
	renames       []publicationReconcileRollbackRenameEvent
}

func (filesystem *publicationReconcileRollbackRenameFS) Lstat(path string) (os.FileInfo, error) {
	return filesystem.base.Lstat(path)
}

func (filesystem *publicationReconcileRollbackRenameFS) OpenRoot(path string) (files.ApplyRoot, error) {
	root, err := filesystem.base.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &publicationReconcileRollbackRenameRoot{ApplyRoot: root, filesystem: filesystem}, nil
}

type publicationReconcileRollbackRenameRoot struct {
	files.ApplyRoot
	filesystem *publicationReconcileRollbackRenameFS
}

func (root *publicationReconcileRollbackRenameRoot) Rename(oldName, newName string) error {
	err := root.ApplyRoot.Rename(oldName, newName)
	event := publicationReconcileRollbackRenameEvent{destination: newName, delegateSucceeded: err == nil}
	if err == nil && newName == root.filesystem.destination && !root.filesystem.faultReturned {
		root.filesystem.faultReturned = true
		event.sentinelReturned = true
		root.filesystem.renames = append(root.filesystem.renames, event)
		return root.filesystem.fault
	}
	root.filesystem.renames = append(root.filesystem.renames, event)
	return err
}
