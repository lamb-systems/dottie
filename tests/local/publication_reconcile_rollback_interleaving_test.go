package local_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReconcileRollbackSkipsEditBetweenObservations(t *testing.T) {
	t.Run("newer edit between observations is skipped before restore staging", func(t *testing.T) {
		fixture := newPublicationReconcileRollbackFixture(t)
		applied, rootIdentity := publicationReconcileRollbackInterleavingApply(t, fixture)
		newerEdit := []byte("destination B newer rollback interleaving edit\n")
		require.False(t, bytes.Equal(publicationReconcileInitial, newerEdit))
		require.False(t, bytes.Equal(publicationReconcileSuccessor, newerEdit))

		filesystem := &publicationReconcileRollbackInterleavingFS{
			delegate: files.DefaultApplyFileSystem(), selectedRoot: fixture.homeB.root,
			selectedFile: "settings.ini", armed: true,
			edit: func() error {
				if err := os.WriteFile(fixture.destination, newerEdit, 0o600); err != nil {
					return err
				}
				return os.Chmod(fixture.destination, 0o600)
			},
		}
		rollback, err := syncengine.RollbackApplied(fixture.ctx, fixture.store, filesystem, publicationReconcileClock)
		require.NoError(t, err)
		require.Equal(t, 1, filesystem.triggerCount)
		assert.Equal(t, 0, filesystem.triggerObservationIndex)
		assert.True(t, filesystem.triggerRootCloseSucceeded)
		assert.NoError(t, filesystem.callbackErr)
		assert.True(t, filesystem.callbackCompleted)

		require.Len(t, filesystem.observations, 2)
		first := filesystem.observations[0]
		second := filesystem.observations[1]
		assertPublicationReconcileRollbackInterleavingObservation(t, first, rootIdentity, publicationReconcileSuccessor)
		assertPublicationReconcileRollbackInterleavingObservation(t, second, rootIdentity, newerEdit)
		require.Equal(t, []string{
			"destination-root-lstat",
			"destination-root-lstat",
			"destination-root-lstat",
			"selected-path-stat-before-open",
			"selected-readonly-open",
			"selected-file-stat",
			"selected-read-eof",
			"selected-file-stat",
			"selected-path-stat-after-read",
			"selected-file-close",
			"selected-root-close",
			"newer-edit-trigger",
			"newer-edit-complete",
			"destination-root-lstat",
			"destination-root-lstat",
			"selected-path-stat-before-open",
			"selected-readonly-open",
			"selected-file-stat",
			"selected-read-eof",
			"selected-file-stat",
			"selected-path-stat-after-read",
			"selected-file-close",
			"selected-root-close",
			"destination-root-lstat",
		}, filesystem.events)
		assert.Empty(t, filesystem.mutatingOpens)
		assert.Empty(t, filesystem.writes)
		assert.Empty(t, filesystem.chmods)
		assert.Empty(t, filesystem.renames)
		assert.Empty(t, filesystem.removes)

		require.Len(t, rollback.Entries, 1)
		assert.Empty(t, rollback.Pruned)
		assert.Equal(t, applied.ID, rollback.Entries[0].JournalID)
		assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, rollback.Entries[0].Key)
		assert.Equal(t, "skipped-newer-edit", rollback.Entries[0].Outcome)
		assert.Equal(t, "destination changed before restore; left unchanged", rollback.Entries[0].Reason)

		skipped := publicationReconcileRollbackJournal(t, fixture)
		assertPublicationReconcileRollbackRow(t, fixture, skipped, applied.ID, "applied", state.JournalStageRollbackSkipped)
		assert.Equal(t, applied.BackupRef, skipped.BackupRef)
		assert.Nil(t, skipped.Retention)
		backup, err := fixture.store.Payload(skipped.BackupRef)
		require.NoError(t, err)
		assert.Equal(t, publicationReconcileInitial, backup)
		pending, err := fixture.store.PendingJournalEntries(fixture.ctx)
		require.NoError(t, err)
		assert.Empty(t, pending)
		bases, err := fixture.store.AppliedBase(fixture.ctx, publicationReconcileTargetID)
		require.NoError(t, err)
		assert.Empty(t, bases)

		assertPublicationReconcileFile(t, fixture.destination, newerEdit, 0o600)
		assertPublicationReconcileFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
		assertPublicationReconcileFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
		assertPublicationReconcileFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)
		assert.Equal(t, []string{"machine-only", "settings.ini"}, publicationReconcileRollbackInterleavingNames(t, fixture.homeB.root))
	})

	t.Run("unarmed rollback restores through the delegated filesystem", func(t *testing.T) {
		fixture := newPublicationReconcileRollbackFixture(t)
		applied, rootIdentity := publicationReconcileRollbackInterleavingApply(t, fixture)
		filesystem := &publicationReconcileRollbackInterleavingFS{
			delegate: files.DefaultApplyFileSystem(), selectedRoot: fixture.homeB.root,
			selectedFile: "settings.ini",
		}

		rollback, err := syncengine.RollbackApplied(fixture.ctx, fixture.store, filesystem, publicationReconcileClock)
		require.NoError(t, err)
		assert.Equal(t, 0, filesystem.triggerCount)
		assert.False(t, filesystem.callbackCompleted)
		assert.NoError(t, filesystem.callbackErr)
		require.Len(t, filesystem.observations, 4)
		for index, expected := range [][]byte{
			publicationReconcileSuccessor,
			publicationReconcileSuccessor,
			publicationReconcileSuccessor,
			publicationReconcileInitial,
		} {
			assertPublicationReconcileRollbackInterleavingObservation(t, filesystem.observations[index], rootIdentity, expected)
		}
		require.Len(t, filesystem.mutatingOpens, 1)
		assert.True(t, filesystem.mutatingOpens[0].flags&os.O_CREATE != 0)
		require.Len(t, filesystem.writes, 1)
		assert.Equal(t, len(publicationReconcileInitial), filesystem.writes[0].bytesWritten)
		require.Len(t, filesystem.chmods, 1)
		require.Len(t, filesystem.renames, 1)
		assert.True(t, filesystem.renames[0].delegateSucceeded)
		assert.Equal(t, "settings.ini", filesystem.renames[0].destination)
		assert.True(t, strings.HasPrefix(filesystem.renames[0].source, ".settings.ini.dottie-"))
		assert.Equal(t, filesystem.renames[0].source, filesystem.mutatingOpens[0].name)
		assert.Equal(t, filesystem.renames[0].source, filesystem.writes[0].name)
		assert.Equal(t, filesystem.renames[0].source, filesystem.chmods[0].name)
		assert.Equal(t, os.FileMode(0o600), filesystem.chmods[0].mode.Perm())
		assert.Empty(t, filesystem.removes)

		require.Len(t, rollback.Entries, 1)
		assert.Empty(t, rollback.Pruned)
		assert.Equal(t, applied.ID, rollback.Entries[0].JournalID)
		assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, rollback.Entries[0].Key)
		assert.Equal(t, "rolled-back", rollback.Entries[0].Outcome)
		assert.Equal(t, "backup restored and verified; backup retained for a retained recovery point", rollback.Entries[0].Reason)

		rolledBack := publicationReconcileRollbackJournal(t, fixture)
		assertPublicationReconcileRollbackRow(t, fixture, rolledBack, applied.ID, "rolled-back", state.JournalStageRolledBack)
		assert.Equal(t, applied.BackupRef, rolledBack.BackupRef)
		assert.Nil(t, rolledBack.Retention)
		backup, err := fixture.store.Payload(rolledBack.BackupRef)
		require.NoError(t, err)
		assert.Equal(t, publicationReconcileInitial, backup)
		pending, err := fixture.store.PendingJournalEntries(fixture.ctx)
		require.NoError(t, err)
		assert.Empty(t, pending)
		bases, err := fixture.store.AppliedBase(fixture.ctx, publicationReconcileTargetID)
		require.NoError(t, err)
		assert.Empty(t, bases)

		assertPublicationReconcileFile(t, fixture.destination, publicationReconcileInitial, 0o600)
		assertPublicationReconcileFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
		assertPublicationReconcileFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
		assertPublicationReconcileFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)
		assert.Equal(t, []string{"machine-only", "settings.ini"}, publicationReconcileRollbackInterleavingNames(t, fixture.homeB.root))
	})
}

func publicationReconcileRollbackInterleavingApply(t *testing.T, fixture *publicationReconcileRollbackFixture) (state.JournalEntry, publicationReconcileRollbackInterleavingIdentity) {
	t.Helper()
	require.True(t, fixture.preview.Complete)
	require.NoError(t, syncengine.Apply(fixture.ctx, fixture.store, publicationReconcileRollbackApplyRequest(fixture, nil)))
	assertPublicationReconcileFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)
	applied := publicationReconcileRollbackJournal(t, fixture)
	assertPublicationReconcileRollbackRow(t, fixture, applied, applied.ID, "applied", state.JournalStageVerified)
	assert.Equal(t, filepath.Clean(fixture.homeB.root), applied.RootPath)
	assert.Equal(t, "settings.ini", applied.DestinationPath)
	rootInfo, err := os.Lstat(fixture.homeB.root)
	require.NoError(t, err)
	rootIdentity, err := publicationReconcileRollbackInterleavingIdentityOf(rootInfo)
	require.NoError(t, err)
	assert.Equal(t, uint64(applied.RootDevice), rootIdentity.device)
	assert.Equal(t, uint64(applied.RootInode), rootIdentity.inode)
	backup, err := fixture.store.Payload(applied.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, publicationReconcileInitial, backup)
	pending, err := fixture.store.PendingJournalEntries(fixture.ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)
	bases, err := fixture.store.AppliedBase(fixture.ctx, publicationReconcileTargetID)
	require.NoError(t, err)
	assert.Empty(t, bases)
	return applied, rootIdentity
}

func assertPublicationReconcileRollbackInterleavingObservation(t *testing.T, observed publicationReconcileRollbackInterleavingObservation, rootIdentity publicationReconcileRollbackInterleavingIdentity, expected []byte) {
	t.Helper()
	assert.True(t, observed.coherent)
	assert.Equal(t, rootIdentity, observed.rootIdentity)
	assert.Equal(t, "settings.ini", observed.fileName)
	assert.Equal(t, syscall.O_RDONLY, observed.openFlags&syscall.O_ACCMODE)
	assert.Equal(t, os.FileMode(0), observed.openMode)
	assert.Equal(t, os.FileMode(0o600), observed.fileMode.Perm())
	assert.Equal(t, expected, observed.data)
}

func publicationReconcileRollbackInterleavingNames(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

type publicationReconcileRollbackInterleavingIdentity struct {
	device uint64
	inode  uint64
}

func publicationReconcileRollbackInterleavingIdentityOf(info os.FileInfo) (publicationReconcileRollbackInterleavingIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return publicationReconcileRollbackInterleavingIdentity{}, errors.New("rollback root identity is unavailable")
	}
	return publicationReconcileRollbackInterleavingIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

type publicationReconcileRollbackInterleavingObservation struct {
	rootIdentity publicationReconcileRollbackInterleavingIdentity
	fileName     string
	openFlags    int
	openMode     os.FileMode
	fileMode     os.FileMode
	data         []byte
	coherent     bool
}

type publicationReconcileRollbackInterleavingMutableObservation struct {
	rootIdentity publicationReconcileRollbackInterleavingIdentity
	fileName     string
	openFlags    int
	openMode     os.FileMode
	pathInfos    []os.FileInfo
	fileInfos    []os.FileInfo
	pathErrors   []error
	fileErrors   []error
	data         []byte
	readEOF      bool
	fileClosed   bool
	fileCloseErr error
	rootCloseErr error
}

type publicationReconcileRollbackInterleavingOpen struct {
	name  string
	flags int
}

type publicationReconcileRollbackInterleavingWrite struct {
	name         string
	bytesWritten int
}

type publicationReconcileRollbackInterleavingChmod struct {
	name string
	mode os.FileMode
}

type publicationReconcileRollbackInterleavingRename struct {
	source            string
	destination       string
	delegateSucceeded bool
}

type publicationReconcileRollbackInterleavingRemove struct {
	name              string
	delegateSucceeded bool
}

type publicationReconcileRollbackInterleavingFS struct {
	delegate                  files.ApplyFileSystem
	selectedRoot              string
	selectedFile              string
	armed                     bool
	edit                      func() error
	triggerCount              int
	triggerObservationIndex   int
	triggerRootCloseSucceeded bool
	callbackCompleted         bool
	callbackErr               error
	events                    []string
	observations              []publicationReconcileRollbackInterleavingObservation
	mutatingOpens             []publicationReconcileRollbackInterleavingOpen
	writes                    []publicationReconcileRollbackInterleavingWrite
	chmods                    []publicationReconcileRollbackInterleavingChmod
	renames                   []publicationReconcileRollbackInterleavingRename
	removes                   []publicationReconcileRollbackInterleavingRemove
}

func (filesystem *publicationReconcileRollbackInterleavingFS) Lstat(path string) (os.FileInfo, error) {
	if filepath.Clean(path) == filepath.Clean(filesystem.selectedRoot) {
		filesystem.events = append(filesystem.events, "destination-root-lstat")
	}
	return filesystem.delegate.Lstat(path)
}

func (filesystem *publicationReconcileRollbackInterleavingFS) OpenRoot(path string) (files.ApplyRoot, error) {
	rootInfo, err := filesystem.delegate.Lstat(path)
	if err != nil {
		return nil, err
	}
	rootIdentity, err := publicationReconcileRollbackInterleavingIdentityOf(rootInfo)
	if err != nil {
		return nil, err
	}
	root, err := filesystem.delegate.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &publicationReconcileRollbackInterleavingRoot{
		ApplyRoot: root, filesystem: filesystem, path: filepath.Clean(path), rootIdentity: rootIdentity,
	}, nil
}

type publicationReconcileRollbackInterleavingRoot struct {
	files.ApplyRoot
	filesystem    *publicationReconcileRollbackInterleavingFS
	path          string
	rootIdentity  publicationReconcileRollbackInterleavingIdentity
	observation   *publicationReconcileRollbackInterleavingMutableObservation
	pendingInfos  []os.FileInfo
	pendingErrors []error
	pathCount     int
}

func (root *publicationReconcileRollbackInterleavingRoot) Lstat(name string) (os.FileInfo, error) {
	info, err := root.ApplyRoot.Lstat(name)
	if root.path != root.filesystem.selectedRoot || name != root.filesystem.selectedFile {
		return info, err
	}
	if root.observation == nil {
		if err == nil {
			root.pendingInfos = append(root.pendingInfos, info)
		} else {
			root.pendingErrors = append(root.pendingErrors, err)
		}
		root.pathCount++
		if root.pathCount == 1 {
			root.filesystem.events = append(root.filesystem.events, "selected-path-stat-before-open")
		} else {
			root.filesystem.events = append(root.filesystem.events, "selected-path-stat-after-read")
		}
		return info, err
	}
	if err == nil {
		root.observation.pathInfos = append(root.observation.pathInfos, info)
		root.filesystem.events = append(root.filesystem.events, "selected-path-stat-after-read")
	} else {
		root.observation.pathErrors = append(root.observation.pathErrors, err)
	}
	return info, err
}

func (root *publicationReconcileRollbackInterleavingRoot) OpenFile(name string, flags int, mode os.FileMode) (files.ApplyFile, error) {
	mutating := flags&syscall.O_ACCMODE != syscall.O_RDONLY || flags&(os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0
	if mutating {
		root.filesystem.mutatingOpens = append(root.filesystem.mutatingOpens, publicationReconcileRollbackInterleavingOpen{name: name, flags: flags})
	}
	file, err := root.ApplyRoot.OpenFile(name, flags, mode)
	if err != nil {
		return nil, err
	}
	selected := root.path == root.filesystem.selectedRoot && name == root.filesystem.selectedFile
	readOnly := flags&syscall.O_ACCMODE == syscall.O_RDONLY
	if !selected || !readOnly {
		return &publicationReconcileRollbackInterleavingFile{ApplyFile: file, root: root, name: name}, nil
	}
	observation := &publicationReconcileRollbackInterleavingMutableObservation{
		rootIdentity: root.rootIdentity, fileName: name, openFlags: flags, openMode: mode,
		pathInfos:  append([]os.FileInfo(nil), root.pendingInfos...),
		pathErrors: append([]error(nil), root.pendingErrors...),
	}
	root.observation = observation
	root.filesystem.events = append(root.filesystem.events, "selected-readonly-open")
	return &publicationReconcileRollbackInterleavingFile{ApplyFile: file, root: root, observation: observation, name: name}, nil
}

func (root *publicationReconcileRollbackInterleavingRoot) Rename(oldName, newName string) error {
	index := len(root.filesystem.renames)
	root.filesystem.renames = append(root.filesystem.renames, publicationReconcileRollbackInterleavingRename{source: oldName, destination: newName})
	err := root.ApplyRoot.Rename(oldName, newName)
	root.filesystem.renames[index].delegateSucceeded = err == nil
	return err
}

func (root *publicationReconcileRollbackInterleavingRoot) Remove(name string) error {
	index := len(root.filesystem.removes)
	root.filesystem.removes = append(root.filesystem.removes, publicationReconcileRollbackInterleavingRemove{name: name})
	err := root.ApplyRoot.Remove(name)
	root.filesystem.removes[index].delegateSucceeded = err == nil
	return err
}

func (root *publicationReconcileRollbackInterleavingRoot) Close() error {
	err := root.ApplyRoot.Close()
	if root.observation == nil {
		return err
	}
	root.observation.rootCloseErr = err
	root.filesystem.events = append(root.filesystem.events, "selected-root-close")
	observed, coherent := root.observation.snapshot()
	observed.coherent = coherent
	root.filesystem.observations = append(root.filesystem.observations, observed)
	if err != nil || !coherent || !root.filesystem.armed || root.filesystem.triggerCount != 0 {
		return err
	}
	root.filesystem.triggerCount++
	root.filesystem.triggerObservationIndex = len(root.filesystem.observations) - 1
	root.filesystem.triggerRootCloseSucceeded = true
	root.filesystem.events = append(root.filesystem.events, "newer-edit-trigger")
	if root.filesystem.edit != nil {
		root.filesystem.callbackErr = root.filesystem.edit()
	}
	if root.filesystem.callbackErr != nil {
		return root.filesystem.callbackErr
	}
	root.filesystem.callbackCompleted = true
	root.filesystem.events = append(root.filesystem.events, "newer-edit-complete")
	return nil
}

type publicationReconcileRollbackInterleavingFile struct {
	files.ApplyFile
	root        *publicationReconcileRollbackInterleavingRoot
	observation *publicationReconcileRollbackInterleavingMutableObservation
	name        string
}

func (file *publicationReconcileRollbackInterleavingFile) Stat() (os.FileInfo, error) {
	info, err := file.ApplyFile.Stat()
	if file.observation != nil {
		if err == nil {
			file.observation.fileInfos = append(file.observation.fileInfos, info)
		} else {
			file.observation.fileErrors = append(file.observation.fileErrors, err)
		}
		file.root.filesystem.events = append(file.root.filesystem.events, "selected-file-stat")
	}
	return info, err
}

func (file *publicationReconcileRollbackInterleavingFile) Read(buffer []byte) (int, error) {
	read, err := file.ApplyFile.Read(buffer)
	if file.observation != nil {
		if read > 0 {
			file.observation.data = append(file.observation.data, buffer[:read]...)
		}
		if errors.Is(err, io.EOF) {
			file.observation.readEOF = true
			file.root.filesystem.events = append(file.root.filesystem.events, "selected-read-eof")
		} else if err != nil {
			file.observation.fileErrors = append(file.observation.fileErrors, err)
		}
	}
	return read, err
}

func (file *publicationReconcileRollbackInterleavingFile) Write(buffer []byte) (int, error) {
	index := len(file.root.filesystem.writes)
	file.root.filesystem.writes = append(file.root.filesystem.writes, publicationReconcileRollbackInterleavingWrite{name: file.name})
	written, err := file.ApplyFile.Write(buffer)
	file.root.filesystem.writes[index].bytesWritten = written
	return written, err
}

func (file *publicationReconcileRollbackInterleavingFile) Chmod(mode os.FileMode) error {
	file.root.filesystem.chmods = append(file.root.filesystem.chmods, publicationReconcileRollbackInterleavingChmod{name: file.name, mode: mode})
	return file.ApplyFile.Chmod(mode)
}

func (file *publicationReconcileRollbackInterleavingFile) Close() error {
	err := file.ApplyFile.Close()
	if file.observation != nil {
		file.observation.fileCloseErr = err
		file.observation.fileClosed = true
		file.root.filesystem.events = append(file.root.filesystem.events, "selected-file-close")
	}
	return err
}

func (file *publicationReconcileRollbackInterleavingFile) Sync() error {
	return file.ApplyFile.Sync()
}

func (observation *publicationReconcileRollbackInterleavingMutableObservation) snapshot() (publicationReconcileRollbackInterleavingObservation, bool) {
	result := publicationReconcileRollbackInterleavingObservation{
		rootIdentity: observation.rootIdentity, fileName: observation.fileName,
		openFlags: observation.openFlags, openMode: observation.openMode,
		data: append([]byte(nil), observation.data...),
	}
	if observation.rootCloseErr != nil || !observation.fileClosed || observation.fileCloseErr != nil || !observation.readEOF || len(observation.fileErrors) != 0 || len(observation.pathErrors) != 0 || len(observation.pathInfos) != 2 || len(observation.fileInfos) != 2 || observation.openFlags&syscall.O_ACCMODE != syscall.O_RDONLY || observation.openMode != 0 {
		return result, false
	}
	infos := []os.FileInfo{observation.pathInfos[0], observation.fileInfos[0], observation.fileInfos[1], observation.pathInfos[1]}
	for _, info := range infos {
		if !info.Mode().IsRegular() || !os.SameFile(infos[0], info) || infos[0].Size() != info.Size() || !infos[0].ModTime().Equal(info.ModTime()) {
			return result, false
		}
	}
	if int64(len(observation.data)) != infos[0].Size() {
		return result, false
	}
	result.fileMode = observation.fileInfos[0].Mode()
	return result, true
}
