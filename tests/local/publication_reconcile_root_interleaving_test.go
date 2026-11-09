package local_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReconcileApplyRefusesRootReplacementAfterPrepare(t *testing.T) {
	t.Run("armed replacement refuses before journaling", func(t *testing.T) {
		fixture := newPublicationReconcileRollbackFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		root := fixture.homeB.root
		heldRoot := root + "-held"
		replacementSentinel := []byte("destination B replacement-root sentinel\n")
		originalRootInfo, err := os.Lstat(root)
		require.NoError(t, err)
		originalIdentity, err := publicationReconcileRootInterleavingIdentityOf(originalRootInfo)
		require.NoError(t, err)
		_, err = os.Lstat(heldRoot)
		require.ErrorIs(t, err, os.ErrNotExist)

		filesystem := &publicationReconcileRootInterleavingFS{
			delegate: files.DefaultApplyFileSystem(), selectedRoot: root,
			selectedFile: "settings.ini", armed: true, ctx: ctx,
			replace: func() error {
				if err := os.Rename(root, heldRoot); err != nil {
					return err
				}
				if err := os.Mkdir(root, 0o700); err != nil {
					return err
				}
				if err := publicationReconcileRootInterleavingWrite(filepath.Join(root, "settings.ini"), publicationReconcileInitial, 0o600); err != nil {
					return err
				}
				return publicationReconcileRootInterleavingWrite(filepath.Join(root, "machine-only"), replacementSentinel, 0o640)
			},
		}
		require.True(t, fixture.preview.Complete)
		previewEntry := publicationReconcilePreviewEntry(t, fixture.preview, "settings.ini")
		require.Equal(t, syncengine.ActionDownload, previewEntry.DecisionAction)
		assert.Equal(t, syncengine.PreviewChange, previewEntry.Action)
		assertPublicationReconcileFile(t, filepath.Join(root, "settings.ini"), publicationReconcileInitial, 0o600)
		assertPublicationReconcileFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)
		publicationReconcileRootInterleavingAssertNoAppliedBase(t, ctx, fixture)
		beforePayloads := publicationReconcileRootInterleavingPayloadNames(t, fixture)
		require.Empty(t, beforePayloads)
		beforeUsage, err := fixture.store.JournalBackupUsage(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), beforeUsage.Bytes)
		assert.Empty(t, beforeUsage.Holders)
		beforeJournal, err := fixture.store.JournalEntriesAll(ctx)
		require.NoError(t, err)
		assert.Empty(t, beforeJournal)

		applyErr := syncengine.Apply(ctx, fixture.store, publicationReconcileRollbackApplyRequest(fixture, filesystem))
		require.Equal(t, 1, filesystem.triggerCount)
		require.NoError(t, filesystem.callbackErr)
		assert.Equal(t, 0, filesystem.triggerObservationIndex)
		assert.True(t, filesystem.triggerRootCloseSucceeded)
		assert.NoError(t, filesystem.contextErr)
		assert.False(t, filesystem.contextDone)
		require.GreaterOrEqual(t, len(filesystem.events), 9)
		assert.Equal(t, []string{
			"selected-path-stat-before-open",
			"selected-readonly-open",
			"selected-file-stat",
			"selected-read-eof",
			"selected-file-stat",
			"selected-path-stat-after-read",
			"selected-file-close",
			"selected-root-close",
			"root-replacement-trigger",
		}, filesystem.events[:9])
		require.Len(t, filesystem.observations, 2)
		firstObservation := filesystem.observations[0]
		assert.Equal(t, originalIdentity, firstObservation.rootIdentity)
		assert.Equal(t, publicationReconcileInitial, firstObservation.data)
		assert.Equal(t, os.FileMode(0o600), firstObservation.fileMode.Perm())
		assert.Equal(t, "settings.ini", firstObservation.fileName)
		assert.Equal(t, syscall.O_RDONLY, firstObservation.openFlags&syscall.O_ACCMODE)
		assert.Equal(t, os.FileMode(0), firstObservation.openMode)
		assert.True(t, firstObservation.coherent)

		heldInfo, err := os.Lstat(heldRoot)
		require.NoError(t, err)
		replacementInfo, err := os.Lstat(root)
		require.NoError(t, err)
		heldIdentity, err := publicationReconcileRootInterleavingIdentityOf(heldInfo)
		require.NoError(t, err)
		replacementIdentity, err := publicationReconcileRootInterleavingIdentityOf(replacementInfo)
		require.NoError(t, err)
		assert.True(t, os.SameFile(originalRootInfo, heldInfo))
		assert.Equal(t, originalIdentity, heldIdentity)
		assert.NotEqual(t, heldIdentity, replacementIdentity)
		assert.False(t, os.SameFile(heldInfo, replacementInfo))
		assertPublicationReconcileFile(t, filepath.Join(heldRoot, "settings.ini"), publicationReconcileInitial, 0o600)
		assertPublicationReconcileFile(t, filepath.Join(heldRoot, "machine-only"), publicationReconcileSentinelB, 0o640)
		assertPublicationReconcileFile(t, filepath.Join(root, "settings.ini"), publicationReconcileInitial, 0o600)
		assertPublicationReconcileFile(t, filepath.Join(root, "machine-only"), replacementSentinel, 0o640)
		secondObservation := filesystem.observations[1]
		assert.Equal(t, replacementIdentity, secondObservation.rootIdentity)
		assert.Equal(t, publicationReconcileInitial, secondObservation.data)
		assert.Equal(t, os.FileMode(0o600), secondObservation.fileMode.Perm())
		assert.True(t, secondObservation.coherent)

		require.EqualError(t, applyErr, "recheck destination root before apply: journal destination root identity changed")
		var partial *syncengine.PartialApplyError
		assert.False(t, errors.As(applyErr, &partial))
		journal, err := fixture.store.JournalEntriesAll(ctx)
		require.NoError(t, err)
		assert.Empty(t, journal)
		pending, err := fixture.store.PendingJournalEntries(ctx)
		require.NoError(t, err)
		assert.Empty(t, pending)
		usage, err := fixture.store.JournalBackupUsage(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), usage.Bytes)
		assert.Empty(t, usage.Holders)
		assert.Equal(t, beforePayloads, publicationReconcileRootInterleavingPayloadNames(t, fixture))
		publicationReconcileRootInterleavingAssertNoAppliedBase(t, ctx, fixture)
		assertPublicationReconcileFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
		assertPublicationReconcileFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
	})

	t.Run("unarmed Apply records the original root and backup", func(t *testing.T) {
		fixture := newPublicationReconcileRollbackFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		root := fixture.homeB.root
		rootInfo, err := os.Lstat(root)
		require.NoError(t, err)
		rootIdentity, err := publicationReconcileRootInterleavingIdentityOf(rootInfo)
		require.NoError(t, err)
		filesystem := &publicationReconcileRootInterleavingFS{
			delegate: files.DefaultApplyFileSystem(), selectedRoot: root,
			selectedFile: "settings.ini", ctx: ctx,
		}
		require.True(t, fixture.preview.Complete)
		previewEntry := publicationReconcilePreviewEntry(t, fixture.preview, "settings.ini")
		require.Equal(t, syncengine.ActionDownload, previewEntry.DecisionAction)
		assert.Equal(t, syncengine.PreviewChange, previewEntry.Action)
		publicationReconcileRootInterleavingAssertNoAppliedBase(t, ctx, fixture)
		beforePayloads := publicationReconcileRootInterleavingPayloadNames(t, fixture)
		require.Empty(t, beforePayloads)
		beforeUsage, err := fixture.store.JournalBackupUsage(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), beforeUsage.Bytes)
		assert.Empty(t, beforeUsage.Holders)

		require.NoError(t, syncengine.Apply(ctx, fixture.store, publicationReconcileRollbackApplyRequest(fixture, filesystem)))
		assert.Equal(t, 0, filesystem.triggerCount)
		assert.NoError(t, filesystem.callbackErr)
		assertPublicationReconcileFile(t, filepath.Join(root, "settings.ini"), publicationReconcileSuccessor, 0o600)
		assertPublicationReconcileFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)
		assertPublicationReconcileFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
		assertPublicationReconcileFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
		require.GreaterOrEqual(t, len(filesystem.observations), 4)
		assert.Equal(t, rootIdentity, filesystem.observations[0].rootIdentity)
		assert.Equal(t, publicationReconcileInitial, filesystem.observations[0].data)
		assert.Equal(t, publicationReconcileInitial, filesystem.observations[1].data)
		assert.Equal(t, publicationReconcileSuccessor, filesystem.observations[len(filesystem.observations)-1].data)
		for _, observation := range filesystem.observations {
			assert.True(t, observation.coherent)
			assert.Equal(t, rootIdentity, observation.rootIdentity)
		}

		journal, err := fixture.store.JournalEntriesAll(ctx)
		require.NoError(t, err)
		require.Len(t, journal, 1)
		entry := journal[0]
		assert.NotEmpty(t, entry.ID)
		assert.Equal(t, "replace", entry.Operation)
		assert.Equal(t, "applied", entry.State)
		assert.Equal(t, state.JournalStageVerified, entry.Stage)
		assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, entry.Identity)
		assert.Equal(t, filepath.Clean(root), entry.RootPath)
		assert.Equal(t, "settings.ini", entry.DestinationPath)
		assert.Equal(t, rootIdentity.device, uint64(entry.RootDevice))
		assert.Equal(t, rootIdentity.inode, uint64(entry.RootInode))
		assert.Equal(t, state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", publicationReconcileInitial), entry.Preimage)
		assert.Equal(t, state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", publicationReconcileSuccessor), entry.Postimage)
		assert.Nil(t, entry.Retention)
		assert.NotEmpty(t, entry.BackupRef)
		backup, err := fixture.store.Payload(entry.BackupRef)
		require.NoError(t, err)
		assert.Equal(t, publicationReconcileInitial, backup)
		usage, err := fixture.store.JournalBackupUsage(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(len(publicationReconcileInitial)), usage.Bytes)
		require.Len(t, usage.Holders, 1)
		assert.Equal(t, entry.BackupRef, usage.Holders[0].Reference)
		assert.Equal(t, int64(len(publicationReconcileInitial)), usage.Holders[0].Size)
		assert.Equal(t, []string{entry.ID}, usage.Holders[0].Entries)
		pending, err := fixture.store.PendingJournalEntries(ctx)
		require.NoError(t, err)
		assert.Empty(t, pending)
		publicationReconcileRootInterleavingAssertNoAppliedBase(t, ctx, fixture)
		assert.NotEmpty(t, publicationReconcileRootInterleavingPayloadNames(t, fixture))
	})
}

type publicationReconcileRootInterleavingIdentity struct {
	device uint64
	inode  uint64
}

func publicationReconcileRootInterleavingIdentityOf(info os.FileInfo) (publicationReconcileRootInterleavingIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return publicationReconcileRootInterleavingIdentity{}, errors.New("root identity is unavailable")
	}
	return publicationReconcileRootInterleavingIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

type publicationReconcileRootInterleavingObservation struct {
	rootIdentity publicationReconcileRootInterleavingIdentity
	fileName     string
	openFlags    int
	openMode     os.FileMode
	fileMode     os.FileMode
	data         []byte
	coherent     bool
}

type publicationReconcileRootInterleavingFS struct {
	delegate                  files.ApplyFileSystem
	selectedRoot              string
	selectedFile              string
	armed                     bool
	ctx                       context.Context
	replace                   func() error
	triggerCount              int
	triggerObservationIndex   int
	triggerRootCloseSucceeded bool
	callbackErr               error
	contextErr                error
	contextDone               bool
	events                    []string
	observations              []publicationReconcileRootInterleavingObservation
}

func (filesystem *publicationReconcileRootInterleavingFS) Lstat(path string) (os.FileInfo, error) {
	return filesystem.delegate.Lstat(path)
}

func (filesystem *publicationReconcileRootInterleavingFS) OpenRoot(path string) (files.ApplyRoot, error) {
	rootInfo, err := filesystem.delegate.Lstat(path)
	if err != nil {
		return nil, err
	}
	rootIdentity, err := publicationReconcileRootInterleavingIdentityOf(rootInfo)
	if err != nil {
		return nil, err
	}
	root, err := filesystem.delegate.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &publicationReconcileRootInterleavingRoot{
		ApplyRoot: root, filesystem: filesystem, path: filepath.Clean(path), rootIdentity: rootIdentity,
	}, nil
}

type publicationReconcileRootInterleavingRoot struct {
	files.ApplyRoot
	filesystem    *publicationReconcileRootInterleavingFS
	path          string
	rootIdentity  publicationReconcileRootInterleavingIdentity
	observation   *publicationReconcileRootInterleavingMutableObservation
	pendingInfos  []os.FileInfo
	pendingErrors []error
	pathCount     int
	otherActivity bool
}

type publicationReconcileRootInterleavingMutableObservation struct {
	rootIdentity publicationReconcileRootInterleavingIdentity
	fileName     string
	openFlags    int
	openMode     os.FileMode
	fileInfos    []os.FileInfo
	pathInfos    []os.FileInfo
	fileErrors   []error
	pathErrors   []error
	data         []byte
	readEOF      bool
	fileClosed   bool
	fileCloseErr error
	rootCloseErr error
}

func (root *publicationReconcileRootInterleavingRoot) Lstat(name string) (os.FileInfo, error) {
	info, err := root.ApplyRoot.Lstat(name)
	if root.path == root.filesystem.selectedRoot && name == root.filesystem.selectedFile {
		root.pathCount++
		if root.observation == nil {
			if err == nil {
				root.pendingInfos = append(root.pendingInfos, info)
			} else {
				root.pendingErrors = append(root.pendingErrors, err)
			}
			if root.pathCount == 1 {
				root.filesystem.events = append(root.filesystem.events, "selected-path-stat-before-open")
			} else {
				root.filesystem.events = append(root.filesystem.events, "selected-path-stat-after-read")
			}
		} else if err == nil {
			root.observation.pathInfos = append(root.observation.pathInfos, info)
			root.filesystem.events = append(root.filesystem.events, "selected-path-stat-after-read")
		} else {
			root.observation.pathErrors = append(root.observation.pathErrors, err)
		}
	}
	return info, err
}

func (root *publicationReconcileRootInterleavingRoot) OpenFile(name string, flags int, mode os.FileMode) (files.ApplyFile, error) {
	file, err := root.ApplyRoot.OpenFile(name, flags, mode)
	if err != nil {
		return nil, err
	}
	selected := root.path == root.filesystem.selectedRoot && name == root.filesystem.selectedFile
	readOnly := flags&syscall.O_ACCMODE == syscall.O_RDONLY
	if !selected || !readOnly {
		root.otherActivity = true
		return file, nil
	}
	observation := &publicationReconcileRootInterleavingMutableObservation{
		rootIdentity: root.rootIdentity, fileName: name, openFlags: flags, openMode: mode,
		pathInfos:  append([]os.FileInfo(nil), root.pendingInfos...),
		pathErrors: append([]error(nil), root.pendingErrors...),
	}
	root.observation = observation
	root.filesystem.events = append(root.filesystem.events, "selected-readonly-open")
	return &publicationReconcileRootInterleavingFile{ApplyFile: file, root: root, observation: observation}, nil
}

func (root *publicationReconcileRootInterleavingRoot) Rename(oldName, newName string) error {
	root.otherActivity = true
	return root.ApplyRoot.Rename(oldName, newName)
}

func (root *publicationReconcileRootInterleavingRoot) Remove(name string) error {
	root.otherActivity = true
	return root.ApplyRoot.Remove(name)
}

func (root *publicationReconcileRootInterleavingRoot) Close() error {
	err := root.ApplyRoot.Close()
	if root.observation == nil {
		return err
	}
	root.observation.rootCloseErr = err
	root.filesystem.events = append(root.filesystem.events, "selected-root-close")
	observation, coherent := root.observation.snapshot(root.otherActivity)
	if !coherent || err != nil {
		return err
	}
	root.filesystem.observations = append(root.filesystem.observations, observation)
	if root.filesystem.armed && root.filesystem.triggerCount == 0 {
		root.filesystem.triggerCount++
		root.filesystem.triggerObservationIndex = len(root.filesystem.observations) - 1
		root.filesystem.triggerRootCloseSucceeded = true
		if root.filesystem.ctx != nil {
			root.filesystem.contextErr = root.filesystem.ctx.Err()
			select {
			case <-root.filesystem.ctx.Done():
				root.filesystem.contextDone = true
			default:
			}
		}
		root.filesystem.events = append(root.filesystem.events, "root-replacement-trigger")
		if root.filesystem.replace != nil {
			root.filesystem.callbackErr = root.filesystem.replace()
		}
	}
	return err
}

type publicationReconcileRootInterleavingFile struct {
	files.ApplyFile
	root        *publicationReconcileRootInterleavingRoot
	observation *publicationReconcileRootInterleavingMutableObservation
}

func (file *publicationReconcileRootInterleavingFile) Stat() (os.FileInfo, error) {
	info, err := file.ApplyFile.Stat()
	if err == nil {
		file.observation.fileInfos = append(file.observation.fileInfos, info)
	} else {
		file.observation.fileErrors = append(file.observation.fileErrors, err)
	}
	file.root.filesystem.events = append(file.root.filesystem.events, "selected-file-stat")
	return info, err
}

func (file *publicationReconcileRootInterleavingFile) Read(buffer []byte) (int, error) {
	read, err := file.ApplyFile.Read(buffer)
	if read > 0 {
		file.observation.data = append(file.observation.data, buffer[:read]...)
	}
	if errors.Is(err, io.EOF) {
		file.observation.readEOF = true
		file.root.filesystem.events = append(file.root.filesystem.events, "selected-read-eof")
	} else if err != nil {
		file.observation.fileErrors = append(file.observation.fileErrors, err)
	}
	return read, err
}

func (file *publicationReconcileRootInterleavingFile) Close() error {
	err := file.ApplyFile.Close()
	file.observation.fileCloseErr = err
	file.observation.fileClosed = true
	file.root.filesystem.events = append(file.root.filesystem.events, "selected-file-close")
	return err
}

func (observation *publicationReconcileRootInterleavingMutableObservation) snapshot(otherActivity bool) (publicationReconcileRootInterleavingObservation, bool) {
	result := publicationReconcileRootInterleavingObservation{
		rootIdentity: observation.rootIdentity, fileName: observation.fileName,
		openFlags: observation.openFlags, openMode: observation.openMode,
		data: append([]byte(nil), observation.data...),
	}
	if otherActivity || observation.rootCloseErr != nil || !observation.fileClosed || observation.fileCloseErr != nil || !observation.readEOF || len(observation.fileErrors) != 0 || len(observation.pathErrors) != 0 || len(observation.pathInfos) != 2 || len(observation.fileInfos) != 2 || observation.openFlags&syscall.O_ACCMODE != syscall.O_RDONLY || observation.openMode != 0 {
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
	result.coherent = true
	return result, true
}

func publicationReconcileRootInterleavingWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func publicationReconcileRootInterleavingPayloadNames(t *testing.T, fixture *publicationReconcileRollbackFixture) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(fixture.homeB.paths.AppStateDir(), "payloads"))
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func publicationReconcileRootInterleavingAssertNoAppliedBase(t *testing.T, ctx context.Context, fixture *publicationReconcileRollbackFixture) {
	t.Helper()
	bases, err := fixture.store.AppliedBase(ctx, publicationReconcileTargetID)
	require.NoError(t, err)
	assert.Empty(t, bases)
}
