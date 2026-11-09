package local_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReconcileTwoHomePartialApplyKeepsOriginalBase(t *testing.T) {
	ctx := context.Background()
	const targetID = "synthetic-files"
	initial := map[string][]byte{
		"a.ini": []byte("source A initial alpha\n"),
		"b.ini": []byte("source A initial bravo\n"),
		"c.ini": []byte("source A initial charlie\n"),
	}
	successor := map[string][]byte{
		"a.ini": []byte("source A successor alpha\n"),
		"b.ini": []byte("source A successor bravo\n"),
		"c.ini": []byte("source A successor charlie\n"),
	}
	const independentEdit = "destination B independent c edit\n"
	const sentinelA = "source A excluded sentinel\n"
	const sentinelB = "destination B excluded sentinel\n"
	paths := []string{"a.ini", "b.ini", "c.ini"}
	target := config.Target{
		ID: targetID, Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory, Exclude: []string{"machine-only"}},
	}
	portable, err := target.Model()
	require.NoError(t, err)
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, configuration.Validate())

	homeA := newPublicationReconcileHome(t, []byte(sentinelA))
	homeB := newPublicationReconcileHome(t, []byte(sentinelB))
	for _, path := range paths {
		writePublicationReconcileFile(t, filepath.Join(homeA.selected, path), initial[path], 0o600)
		writePublicationReconcileFile(t, filepath.Join(homeB.selected, path), initial[path], 0o600)
	}

	initialEntriesA := capturePublicationPartialEntries(t, homeA, target, initial)
	initialEntriesB := capturePublicationPartialEntries(t, homeB, target, initial)
	initialSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: initialEntriesA}
	require.NoError(t, initialSnapshot.Validate())
	assert.Equal(t, initialEntriesA, initialEntriesB)
	binding := publicationReconcileBinding()
	suppliedContext := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	initialMaterial := encodePublicationReconcileMaterial(t, binding, initialSnapshot, 0, nil, [16]byte{0x25, 0x81})
	initialObservation := publicationReconcileObservation(binding, suppliedContext, initialMaterial)
	homeA.floor = acceptPublicationReconcilePosition(t, homeA.pubStore, publicationstate.ModeFirstUse, initialObservation, initialMaterial.payload)
	homeB.floor = acceptPublicationReconcilePosition(t, homeB.pubStore, publicationstate.ModeFirstUse, initialObservation, initialMaterial.payload)

	homeA.local = newPublicationReconcileContext(t, homeA.paths)
	homeB.local = newPublicationReconcileContext(t, homeB.paths)
	requestA := publicationReconcileRequest(homeA, binding, initialMaterial, configuration, homeA.local)
	requestB := publicationReconcileRequest(homeB, binding, initialMaterial, configuration, homeB.local)
	baseA, err := service.EstablishLocalReconciliationBase(ctx, requestA)
	require.NoError(t, err)
	require.NotNil(t, baseA)
	homeA.base = baseA
	baseB, err := service.EstablishLocalReconciliationBase(ctx, requestB)
	require.NoError(t, err)
	require.NotNil(t, baseB)
	homeB.base = baseB

	for _, path := range paths {
		writePublicationReconcileFile(t, filepath.Join(homeA.selected, path), successor[path], 0o600)
	}
	successorEntries := capturePublicationPartialEntries(t, homeA, target, successor)
	successorSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: successorEntries}
	require.NoError(t, successorSnapshot.Validate())
	successorMaterial := encodePublicationReconcileMaterial(t, binding, successorSnapshot, 1, initialMaterial.recordCID, [16]byte{0x25, 0x82})
	successorObservation := publicationReconcileObservation(binding, suppliedContext, successorMaterial, initialMaterial)
	for _, home := range []*publicationReconcileHome{homeA, homeB} {
		previousDatabaseID := home.floor.DatabaseID
		previousGeneration := home.floor.Generation
		home.floor = acceptPublicationReconcilePosition(t, home.pubStore, publicationstate.ModeAdvance, successorObservation, successorMaterial.payload)
		assert.Equal(t, previousDatabaseID, home.floor.DatabaseID)
		assert.Equal(t, previousGeneration, home.floor.Generation)
	}

	requestA = publicationReconcileRequest(homeA, binding, successorMaterial, configuration, homeA.local)
	requestB = publicationReconcileRequest(homeB, binding, successorMaterial, configuration, homeB.local)
	previewA, dispositionA, err := service.PreviewPublicationTarget(ctx, requestA, homeA.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionA)
	assert.True(t, previewA.Complete)
	assertPublicationPartialFiles(t, homeA, successor)
	assertPublicationReconcileFile(t, homeA.sentinel, []byte(sentinelA), 0o640)

	previewB, dispositionB, err := service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	require.True(t, previewB.Complete)
	require.Len(t, previewB.Targets, 1)
	require.Equal(t, targetID, previewB.Targets[0].ID)
	require.Len(t, previewB.Targets[0].Entries, len(paths))
	previewPaths := make([]string, 0, len(paths))
	for _, entry := range previewB.Targets[0].Entries {
		previewPaths = append(previewPaths, entry.Key.FilePath)
		assert.Equal(t, syncengine.ActionDownload, entry.DecisionAction)
		assert.Equal(t, syncengine.PreviewChange, entry.Action)
		assert.Equal(t, syncengine.PreviewReasonRemoteChanged, entry.Reason)
	}
	assert.Equal(t, paths, previewPaths)
	assertPublicationReconcileNoSentinelPreview(t, previewB)
	assertPublicationPartialFiles(t, homeB, initial)
	assertPublicationReconcileFile(t, homeB.sentinel, []byte(sentinelB), 0o640)
	postimages := publicationPartialPostimages(t, previewB, successorMaterial.record, successorMaterial.payload, successor, paths)
	require.Len(t, postimages, len(paths))

	stateStore, err := state.Open(homeB.paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, stateStore.Close()) })
	require.NoError(t, stateStore.PutTarget(ctx, state.TargetDescriptor{
		ID: targetID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		LogicalBase: model.RootHome, LogicalPath: "synthetic", Kind: model.SelectionDirectory,
		Mode: string(config.Review), CreatedAt: 1,
	}))
	bases, err := stateStore.AppliedBase(ctx, targetID)
	require.NoError(t, err)
	assert.Empty(t, bases)

	fault := errors.New("synthetic rename fault before b.ini mutation")
	filesystem := &publicationPartialApplyFS{
		base: files.DefaultApplyFileSystem(), failDestination: "b.ini", fault: fault,
	}
	applyErr := syncengine.Apply(ctx, stateStore, syncengine.ApplyRequest{
		Preview: previewB, Roots: map[string]string{targetID: homeB.root},
		ModePolicy: syncengine.ModePolicy{Default: 0o600}, Content: postimages,
		FileSystem: filesystem, Now: publicationReconcileClock,
	})
	require.ErrorIs(t, applyErr, fault)
	var partial *syncengine.PartialApplyError
	require.ErrorAs(t, applyErr, &partial)
	require.Len(t, partial.Applied, 1)
	assert.Equal(t, model.EntryKey{TargetID: targetID, Source: model.SourceFiles, FilePath: "a.ini"}, partial.Applied[0].Key)
	assert.Equal(t, "applied", partial.Applied[0].Outcome)
	assert.Equal(t, model.EntryKey{TargetID: targetID, Source: model.SourceFiles, FilePath: "b.ini"}, partial.Failed.Key)
	assert.Equal(t, "failed", partial.Failed.Outcome)
	require.True(t, filesystem.faulted)
	require.Equal(t, 1, filesystem.faultCount)
	require.Equal(t, []publicationPartialRenameEvent{
		{destination: "a.ini"},
		{destination: "b.ini", faulted: true},
	}, filesystem.renamed)
	directoryEntries, err := os.ReadDir(homeB.selected)
	require.NoError(t, err)
	directoryNames := make([]string, 0, len(directoryEntries))
	for _, entry := range directoryEntries {
		directoryNames = append(directoryNames, entry.Name())
	}
	require.Equal(t, []string{"a.ini", "b.ini", "c.ini", "machine-only"}, directoryNames)
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "a.ini"), successor["a.ini"], 0o600)
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "b.ini"), initial["b.ini"], 0o600)
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "c.ini"), initial["c.ini"], 0o600)
	assertPublicationPartialFiles(t, homeA, successor)
	assertPublicationReconcileFile(t, homeA.sentinel, []byte(sentinelA), 0o640)
	assertPublicationReconcileFile(t, homeB.sentinel, []byte(sentinelB), 0o640)
	bases, err = stateStore.AppliedBase(ctx, targetID)
	require.NoError(t, err)
	assert.Empty(t, bases)

	journal, err := stateStore.JournalEntriesAll(ctx)
	require.NoError(t, err)
	require.Len(t, journal, 2)
	journalByPath := make(map[string]state.JournalEntry, len(journal))
	for _, entry := range journal {
		journalByPath[entry.Identity.FilePath] = entry
	}
	appliedJournal, ok := journalByPath["a.ini"]
	require.True(t, ok)
	failedJournal, ok := journalByPath["b.ini"]
	require.True(t, ok)
	_, hasUnattemptedJournal := journalByPath["c.ini"]
	assert.False(t, hasUnattemptedJournal)
	assert.Equal(t, partial.Applied[0].JournalID, appliedJournal.ID)
	assert.Equal(t, partial.Applied[0].Key, appliedJournal.Identity)
	assert.Equal(t, "replace", appliedJournal.Operation)
	assert.Equal(t, "applied", appliedJournal.State)
	assert.Equal(t, state.JournalStageVerified, appliedJournal.Stage)
	assert.Nil(t, appliedJournal.Retention)
	assert.NotEmpty(t, appliedJournal.BackupRef)
	appliedBackup, err := stateStore.Payload(appliedJournal.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, initial["a.ini"], appliedBackup)
	assert.Equal(t, partial.Failed.JournalID, failedJournal.ID)
	assert.Equal(t, partial.Failed.Key, failedJournal.Identity)
	assert.Equal(t, "replace", failedJournal.Operation)
	assert.Equal(t, "failed", failedJournal.State)
	assert.Equal(t, state.JournalStageRename, failedJournal.Stage)
	assert.Nil(t, failedJournal.Retention)
	assert.NotEmpty(t, failedJournal.BackupRef)
	failedBackup, err := stateStore.Payload(failedJournal.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, initial["b.ini"], failedBackup)
	pending, err := stateStore.PendingJournalEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)

	previewB, dispositionB, err = service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	assertPublicationPartialClassifications(t, previewB, targetID, successor, initial, nil)

	newBase, err := service.EstablishLocalReconciliationBase(ctx, requestB)
	assert.Nil(t, newBase)
	assertPublicationPartialNotConverged(t, err)
	previewB, dispositionB, err = service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	assertPublicationPartialClassifications(t, previewB, targetID, successor, initial, nil)

	writePublicationReconcileFile(t, filepath.Join(homeB.selected, "c.ini"), []byte(independentEdit), 0o600)
	assertPublicationReconcileFile(t, filepath.Join(homeB.selected, "c.ini"), []byte(independentEdit), 0o600)
	previewB, dispositionB, err = service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	assertPublicationPartialClassifications(t, previewB, targetID, successor, initial, map[string]bool{"c.ini": true})
	newBase, err = service.EstablishLocalReconciliationBase(ctx, requestB)
	assert.Nil(t, newBase)
	assertPublicationPartialNotConverged(t, err)
	previewB, dispositionB, err = service.PreviewPublicationTarget(ctx, requestB, homeB.base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, dispositionB)
	assertPublicationPartialClassifications(t, previewB, targetID, successor, initial, map[string]bool{"c.ini": true})

	writePublicationReconcileFile(t, filepath.Join(homeB.selected, "b.ini"), successor["b.ini"], 0o600)
	writePublicationReconcileFile(t, filepath.Join(homeB.selected, "c.ini"), successor["c.ini"], 0o600)
	convergedBase, err := service.EstablishLocalReconciliationBase(ctx, requestB)
	require.NoError(t, err)
	require.NotNil(t, convergedBase)
	convergedPreview, convergedDisposition, err := service.PreviewPublicationTarget(ctx, requestB, convergedBase)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, convergedDisposition)
	require.True(t, convergedPreview.Complete)
	for _, path := range paths {
		entry := publicationReconcilePreviewEntry(t, convergedPreview, path)
		assert.Equal(t, syncengine.ActionUnchanged, entry.DecisionAction)
		assert.Equal(t, syncengine.PreviewReasonEqual, entry.Reason)
	}
	assertPublicationPartialFiles(t, homeB, successor)
	assertPublicationReconcileFile(t, homeB.sentinel, []byte(sentinelB), 0o640)
	journal, err = stateStore.JournalEntriesAll(ctx)
	require.NoError(t, err)
	require.Len(t, journal, 2)
	finalJournalByPath := make(map[string]state.JournalEntry, len(journal))
	for _, entry := range journal {
		_, duplicate := finalJournalByPath[entry.Identity.FilePath]
		require.False(t, duplicate)
		finalJournalByPath[entry.Identity.FilePath] = entry
	}
	finalAppliedJournal, ok := finalJournalByPath["a.ini"]
	require.True(t, ok)
	finalFailedJournal, ok := finalJournalByPath["b.ini"]
	require.True(t, ok)
	_, hasFinalUnattemptedJournal := finalJournalByPath["c.ini"]
	assert.False(t, hasFinalUnattemptedJournal)
	assert.Equal(t, appliedJournal, finalAppliedJournal)
	assert.Equal(t, failedJournal, finalFailedJournal)
	require.NotEmpty(t, finalFailedJournal.BackupRef)
	failedBackup, err = stateStore.Payload(finalFailedJournal.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, initial["b.ini"], failedBackup)
}

func capturePublicationPartialEntries(t *testing.T, home *publicationReconcileHome, target config.Target, expected map[string][]byte) []model.Entry {
	t.Helper()
	captured, err := (service.LocalFilesCapture{}).Capture(context.Background(), target, home.selected)
	require.NoError(t, err)
	require.Len(t, captured.Observations, len(expected))
	require.Len(t, captured.Skipped, 1)
	assert.Equal(t, "machine-only", captured.Skipped[0].Path)
	assert.Equal(t, files.SkipExcluded, captured.Skipped[0].Reason)
	entries := make([]model.Entry, 0, len(captured.Observations))
	observed := make(map[string]struct{}, len(captured.Observations))
	for _, observation := range captured.Observations {
		require.Equal(t, model.ObservationPresent, observation.State)
		require.NotNil(t, observation.Entry)
		entry := *observation.Entry
		require.NotNil(t, entry.File)
		require.Equal(t, model.FileRegular, entry.File.Kind)
		require.Equal(t, uint32(0o600), entry.File.Mode)
		expectedBytes, ok := expected[entry.File.Path]
		require.True(t, ok)
		assert.Equal(t, expectedBytes, entry.File.Content)
		_, duplicate := observed[entry.File.Path]
		assert.False(t, duplicate)
		observed[entry.File.Path] = struct{}{}
		entry.File.Content = bytes.Clone(entry.File.Content)
		entries = append(entries, entry)
	}
	assert.Len(t, observed, len(expected))
	sort.Slice(entries, func(i, j int) bool { return entries[i].File.Path < entries[j].File.Path })
	return entries
}

func publicationPartialPostimages(t *testing.T, preview syncengine.Preview, recordRaw, payload []byte, expected map[string][]byte, paths []string) []syncengine.Postimage {
	t.Helper()
	record, err := publication.DecodeSnapshot(recordRaw)
	require.NoError(t, err)
	snapshot, err := publication.DecodePayload(payload, record.Blob)
	require.NoError(t, err)
	require.Len(t, snapshot.Entries, len(paths))
	remote := make(map[model.EntryKey]model.Entry, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		identity := entry.Identity()
		_, duplicate := remote[identity]
		assert.False(t, duplicate)
		remote[identity] = entry
	}
	require.Len(t, preview.Targets, 1)
	require.Len(t, preview.Targets[0].Entries, len(paths))
	postimages := make([]syncengine.Postimage, 0, len(paths))
	for index, previewEntry := range preview.Targets[0].Entries {
		path := paths[index]
		expectedIdentity := model.EntryKey{TargetID: preview.Targets[0].ID, Source: model.SourceFiles, FilePath: path}
		require.Equal(t, expectedIdentity, previewEntry.Key)
		require.Equal(t, syncengine.ActionDownload, previewEntry.DecisionAction)
		remoteEntry, ok := remote[expectedIdentity]
		require.True(t, ok)
		require.NotNil(t, remoteEntry.File)
		require.Equal(t, model.FileRegular, remoteEntry.File.Kind)
		require.Equal(t, expected[path], remoteEntry.File.Content)
		require.Equal(t, uint32(0o600), remoteEntry.File.Mode)
		digest := sha256.Sum256(remoteEntry.File.Content)
		postimages = append(postimages, syncengine.Postimage{
			TargetID: expectedIdentity.TargetID, Key: expectedIdentity.FilePath,
			Data: bytes.Clone(remoteEntry.File.Content), Digest: bytes.Clone(digest[:]), Mode: os.FileMode(remoteEntry.File.Mode),
		})
	}
	assert.Len(t, remote, len(paths))
	return postimages
}

func assertPublicationPartialFiles(t *testing.T, home *publicationReconcileHome, expected map[string][]byte) {
	t.Helper()
	for path, content := range expected {
		assertPublicationReconcileFile(t, filepath.Join(home.selected, path), content, 0o600)
	}
}

func assertPublicationPartialClassifications(t *testing.T, preview syncengine.Preview, targetID string, successor, initial map[string][]byte, conflicts map[string]bool) {
	t.Helper()
	assert.Equal(t, len(conflicts) == 0, preview.Complete)
	require.Len(t, preview.Targets, 1)
	require.Equal(t, targetID, preview.Targets[0].ID)
	require.Len(t, preview.Targets[0].Entries, 3)
	for _, path := range []string{"a.ini", "b.ini", "c.ini"} {
		entry := publicationReconcilePreviewEntry(t, preview, path)
		switch {
		case path == "a.ini":
			assert.Equal(t, targetID, entry.Key.TargetID)
			assert.Equal(t, syncengine.ActionUnchanged, entry.DecisionAction)
			assert.Equal(t, syncengine.PreviewReasonEqual, entry.Reason)
		case conflicts[path]:
			assert.Equal(t, syncengine.PreviewStateConflict, entry.State)
			assert.Equal(t, syncengine.ActionConflict, entry.DecisionAction)
			assert.Equal(t, syncengine.PreviewReasonConflict, entry.Reason)
			assert.Equal(t, string(syncengine.ReasonDivergence), entry.Detail)
		default:
			assert.Equal(t, syncengine.ActionDownload, entry.DecisionAction)
			assert.Equal(t, syncengine.PreviewReasonRemoteChanged, entry.Reason)
		}
		assert.NotEqual(t, successor[path], initial[path])
	}
}

func assertPublicationPartialNotConverged(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, "base", classified.Stage())
	assert.Equal(t, "not_converged", classified.Reason())
}

type publicationPartialRenameEvent struct {
	destination string
	faulted     bool
}

type publicationPartialApplyFS struct {
	base            files.ApplyFileSystem
	failDestination string
	fault           error
	faulted         bool
	faultCount      int
	renamed         []publicationPartialRenameEvent
}

func (filesystem *publicationPartialApplyFS) Lstat(path string) (os.FileInfo, error) {
	return filesystem.base.Lstat(path)
}

func (filesystem *publicationPartialApplyFS) OpenRoot(path string) (files.ApplyRoot, error) {
	root, err := filesystem.base.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return publicationPartialApplyRoot{ApplyRoot: root, filesystem: filesystem}, nil
}

type publicationPartialApplyRoot struct {
	files.ApplyRoot
	filesystem *publicationPartialApplyFS
}

func (root publicationPartialApplyRoot) Rename(oldName, newName string) error {
	event := publicationPartialRenameEvent{destination: newName}
	if newName == root.filesystem.failDestination && root.filesystem.faultCount == 0 {
		root.filesystem.faulted = true
		root.filesystem.faultCount++
		event.faulted = true
		root.filesystem.renamed = append(root.filesystem.renamed, event)
		return root.filesystem.fault
	}
	root.filesystem.renamed = append(root.filesystem.renamed, event)
	return root.ApplyRoot.Rename(oldName, newName)
}
