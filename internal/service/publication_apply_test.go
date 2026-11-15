package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publicationApplyFixture struct {
	paths         platform.Paths
	root          string
	journalPath   string
	target        config.Target
	portable      model.Target
	configuration config.Config
	journal       *publicationstate.Journal
	local         *PublicationLocalContext
	vault         [32]byte
	floor         uint64
}

func newPublicationApplyFixture(t *testing.T) publicationApplyFixture {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	paths := platform.Paths{
		Home:       home,
		ConfigHome: filepath.Join(home, ".config"),
		StateHome:  filepath.Join(home, ".state"),
		CacheHome:  filepath.Join(home, ".cache"),
		DataHome:   filepath.Join(home, ".data"),
	}
	for _, path := range []string{paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	require.NoError(t, os.Mkdir(filepath.Join(home, "applied"), 0o700))
	root := filepath.Join(home, "applied", "tree")
	require.NoError(t, os.Mkdir(root, 0o700))
	target := config.Target{ID: "applied-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "applied/tree", Kind: model.SelectionDirectory}}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	portable, err := target.Model()
	require.NoError(t, err)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	journal, err := publicationstate.OpenJournal(directory)
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	local, err := NewPublicationLocalContext(paths, LocalFilesCapture{}, nil)
	require.NoError(t, err)
	var vault [32]byte
	vault[0] = 9
	return publicationApplyFixture{
		paths: paths, root: root, journalPath: filepath.Join(directory, "journal.db"), target: target, portable: portable,
		configuration: configuration, journal: journal, local: local, vault: vault, floor: 1,
	}
}

func (fixture publicationApplyFixture) request(local *PublicationLocalContext, base, remote model.Snapshot) PublicationApplyRequest {
	return PublicationApplyRequest{
		Journal: fixture.journal, Vault: fixture.vault, FloorRevision: fixture.floor,
		Configuration: fixture.configuration, BaseSnapshot: base, RemoteSnapshot: remote,
		Roots: map[string]string{fixture.target.ID: fixture.root}, Local: local,
	}
}

func (fixture publicationApplyFixture) targetSnapshot(entries []model.Entry) model.Snapshot {
	return model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fixture.portable}, Entries: entries}
}

func (fixture publicationApplyFixture) emptySnapshot() model.Snapshot {
	return model.Snapshot{Version: model.SnapshotVersion}
}

func (fixture publicationApplyFixture) path(name string) string {
	return filepath.Join(fixture.root, name)
}

func (fixture publicationApplyFixture) write(t *testing.T, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(fixture.path(name), []byte(content), 0o600))
}

func (fixture publicationApplyFixture) read(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(fixture.path(name))
	require.NoError(t, err)
	return string(content)
}

func (fixture publicationApplyFixture) readOther(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

func (fixture publicationApplyFixture) resolutions(t *testing.T) []publicationstate.JournalResolution {
	t.Helper()
	resolutions, err := fixture.journal.ResolveInterrupted(context.Background(), func(entry publicationstate.JournalEntry) (publicationstate.ObservedFile, error) {
		return observePublicationApplyEntry(files.DefaultApplyFileSystem(), entry)
	})
	require.NoError(t, err)
	return resolutions
}

func (fixture publicationApplyFixture) assertNoJournalRows(t *testing.T) {
	t.Helper()
	count, err := fixture.journal.EntryCount(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func (fixture publicationApplyFixture) journalRowCount(t *testing.T) int64 {
	t.Helper()
	count, err := fixture.journal.EntryCount(context.Background())
	require.NoError(t, err)
	return count
}

func (fixture publicationApplyFixture) anchor(t *testing.T) publicationstate.JournalAnchor {
	t.Helper()
	info, err := os.Lstat(fixture.root)
	require.NoError(t, err)
	anchor, ok := publicationstate.NewJournalAnchor(fixture.root, info)
	require.True(t, ok)
	return anchor
}

func publicationApplyEntryFor(t *testing.T, report PublicationApplyReport, path string) PublicationApplyEntry {
	t.Helper()
	for _, entry := range report.Entries {
		if entry.Path == path {
			return entry
		}
	}
	require.FailNow(t, "apply entry not found")
	return PublicationApplyEntry{}
}

func requirePublicationApplyRefusal(t *testing.T, err error, stage, reason string) *publicationApplyError {
	t.Helper()
	var refused *publicationApplyError
	require.ErrorAs(t, err, &refused)
	require.ErrorIs(t, err, ErrPublicationApply)
	assert.Equal(t, stage, refused.Stage())
	assert.Equal(t, reason, refused.Reason())
	return refused
}

func TestApplyPublicationWritesChangesAndDeletes(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	fixture.write(t, "kept.ini", "kept")
	fixture.write(t, "removed.ini", "gone")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"changed.ini": "before", "kept.ini": "kept", "removed.ini": "gone",
	}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"changed.ini": "after", "kept.ini": "kept",
	}))

	report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	require.NoError(t, err)
	assert.Nil(t, report.Stopped)
	assert.Equal(t, 2, report.Applied)
	assert.Equal(t, 1, report.Unchanged)
	assert.Equal(t, uint64(len("after")), report.BytesWritten)
	require.Len(t, report.Entries, 3)
	assert.Equal(t, []string{"changed.ini", "kept.ini", "removed.ini"}, []string{report.Entries[0].Path, report.Entries[1].Path, report.Entries[2].Path})

	changed := publicationApplyEntryFor(t, report, "changed.ini")
	assert.Equal(t, PublicationApplyWrite, changed.Operation)
	assert.Equal(t, publicationstate.JournalStateApplied, changed.State)
	assert.NotZero(t, changed.Journal)
	assert.Equal(t, sha256.Sum256([]byte("after")), changed.Digest)
	assert.Equal(t, uint64(len("after")), changed.Size)
	assert.Equal(t, uint32(0o600), changed.Mode)
	require.NotNil(t, changed.Backup)
	backup, err := fixture.journal.BackupBytes(context.Background(), *changed.Backup)
	require.NoError(t, err)
	assert.Equal(t, "before", string(backup))

	removed := publicationApplyEntryFor(t, report, "removed.ini")
	assert.Equal(t, PublicationApplyDelete, removed.Operation)
	assert.Equal(t, publicationstate.JournalStateApplied, removed.State)
	assert.NotZero(t, removed.Journal)
	assert.Equal(t, publicationstate.ObservedFile{}, publicationstate.ObservedFile{Present: removed.Digest != ([32]byte{}), Digest: removed.Digest, Size: removed.Size})
	require.NotNil(t, removed.Backup)
	removedBackup, err := fixture.journal.BackupBytes(context.Background(), *removed.Backup)
	require.NoError(t, err)
	assert.Equal(t, "gone", string(removedBackup))

	kept := publicationApplyEntryFor(t, report, "kept.ini")
	assert.Equal(t, PublicationApplyUnchanged, kept.Operation)
	assert.Zero(t, kept.Journal)
	assert.Empty(t, kept.State)

	assert.Equal(t, "after", fixture.read(t, "changed.ini"))
	assert.Equal(t, "kept", fixture.read(t, "kept.ini"))
	_, err = os.Lstat(fixture.path("removed.ini"))
	require.ErrorIs(t, err, os.ErrNotExist)
	applied, err := os.Lstat(fixture.path("changed.ini"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), applied.Mode().Perm())
	assert.Empty(t, fixture.resolutions(t))
	assert.NoError(t, fixture.journal.CheckAdmission(context.Background(), fixture.floor))
}

func TestApplyPublicationLeavesUnchangedEntryWithoutJournalRow(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "same.ini", "same")
	before, err := os.Lstat(fixture.path("same.ini"))
	require.NoError(t, err)
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"same.ini": "same"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"same.ini": "same"}))

	report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	require.NoError(t, err)
	assert.Equal(t, 0, report.Applied)
	assert.Equal(t, 1, report.Unchanged)
	assert.Equal(t, uint64(0), report.BytesWritten)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, PublicationApplyUnchanged, report.Entries[0].Operation)
	assert.Zero(t, report.Entries[0].Journal)
	after, err := os.Lstat(fixture.path("same.ini"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after))
	fixture.assertNoJournalRows(t)
}

func TestApplyPublicationMarksMismatchedPostimageIndeterminateAndBlocksNextApply(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))

	request := fixture.request(fixture.local, base, remote)
	request.Barrier = func(phase PublicationApplyPhase, _ publicationstate.JournalEntry) error {
		if phase != PublicationApplyMutated {
			return nil
		}
		return os.WriteFile(fixture.path("changed.ini"), []byte("external"), 0o600)
	}
	report, err := ApplyPublication(context.Background(), request)
	require.Error(t, err)
	require.NotNil(t, report.Stopped)
	assert.Equal(t, PublicationApplyWrite, report.Stopped.Operation)
	assert.Equal(t, publicationstate.JournalStateIndeterminate, report.Stopped.State)
	assert.NotZero(t, report.Stopped.Journal)
	assert.Equal(t, 0, report.Applied)
	assert.Equal(t, "external", fixture.read(t, "changed.ini"))

	_, err = ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	refused := requirePublicationApplyRefusal(t, err, "apply-resolve", "journal_indeterminate")
	assert.Equal(t, report.Stopped.Journal, refused.entry)
	assert.Contains(t, err.Error(), fmt.Sprintf("journal entry %d", report.Stopped.Journal))
	assert.Equal(t, "external", fixture.read(t, "changed.ini"))
}

func TestApplyPublicationResumesAfterInterruptedJournaledEntry(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))

	stop := errors.New("synthetic stop before mutation")
	request := fixture.request(fixture.local, base, remote)
	request.Barrier = func(phase PublicationApplyPhase, _ publicationstate.JournalEntry) error {
		if phase == PublicationApplyJournaled {
			return stop
		}
		return nil
	}
	report, err := ApplyPublication(context.Background(), request)
	require.ErrorIs(t, err, stop)
	require.NotNil(t, report.Stopped)
	assert.Equal(t, publicationstate.JournalStatePending, report.Stopped.State)
	assert.Equal(t, 0, report.Applied)
	assert.Equal(t, "before", fixture.read(t, "changed.ini"))

	resolutions := fixture.resolutions(t)
	require.Len(t, resolutions, 1)
	assert.Equal(t, report.Stopped.Journal, resolutions[0].Entry)
	assert.Equal(t, publicationstate.JournalOutcomeFailed, resolutions[0].Outcome)

	report, err = ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	require.NoError(t, err)
	assert.Equal(t, 1, report.Applied)
	assert.Equal(t, 0, report.Unchanged)
	assert.Equal(t, "after", fixture.read(t, "changed.ini"))
}

func TestApplyPublicationResolvesInterruptedMutationWithoutRewriting(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))

	stop := errors.New("synthetic stop after mutation")
	request := fixture.request(fixture.local, base, remote)
	request.Barrier = func(phase PublicationApplyPhase, _ publicationstate.JournalEntry) error {
		if phase == PublicationApplyMutated {
			return stop
		}
		return nil
	}
	report, err := ApplyPublication(context.Background(), request)
	require.ErrorIs(t, err, stop)
	require.NotNil(t, report.Stopped)
	assert.Equal(t, publicationstate.JournalStatePending, report.Stopped.State)
	assert.Equal(t, "after", fixture.read(t, "changed.ini"))

	resolutions := fixture.resolutions(t)
	require.Len(t, resolutions, 1)
	assert.Equal(t, report.Stopped.Journal, resolutions[0].Entry)
	assert.Equal(t, publicationstate.JournalOutcomeApplied, resolutions[0].Outcome)

	mutated, err := os.Lstat(fixture.path("changed.ini"))
	require.NoError(t, err)
	report, err = ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	require.NoError(t, err)
	assert.Equal(t, 0, report.Applied)
	assert.Equal(t, 1, report.Unchanged)
	assert.Equal(t, uint64(0), report.BytesWritten)
	after, err := os.Lstat(fixture.path("changed.ini"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(mutated, after))
}

func TestApplyPublicationRefusesAdmissionWhileALiveRowExists(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "done")
	entry, err := fixture.journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: fixture.vault, Operation: "apply", DestinationDir: fixture.root, DestinationPath: "note.ini",
		Anchor: fixture.anchor(t), Postimage: publicationstate.ObservedJournalFile([]byte("done")), SeenFloorRevision: 2,
	})
	require.NoError(t, err)
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "done"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "next"}))

	report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	var blocked *publicationstate.JournalBlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, entry.Entry, blocked.Entry)
	assert.Equal(t, publicationstate.JournalStateApplied, blocked.State)
	assert.Equal(t, fixture.floor, blocked.FloorRevision)
	assert.Equal(t, 0, report.Applied)
	assert.Equal(t, "done", fixture.read(t, "note.ini"))
}

func TestApplyPublicationRefusesOversizedPostCaptureGrowthWithoutMutating(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "big.bin", "A")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"big.bin": "A"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"big.bin": "B"}))
	oversized := bytes.Repeat([]byte("x"), 8<<20+1)
	capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
		result, err := LocalFilesCapture{}.Capture(ctx, target, path)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(fixture.path("big.bin"), oversized, 0o600))
		return result, nil
	})
	local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
	require.NoError(t, err)

	report, err := ApplyPublication(context.Background(), fixture.request(local, base, remote))
	requirePublicationApplyRefusal(t, err, "apply-observe", "oversized")
	assert.Equal(t, 0, report.Applied)
	require.NotNil(t, report.Stopped)
	assert.Zero(t, report.Stopped.Journal)
	info, err := os.Lstat(fixture.path("big.bin"))
	require.NoError(t, err)
	assert.Equal(t, int64(len(oversized)), info.Size())
	fixture.assertNoJournalRows(t)
}

func TestApplyPublicationRefusesContainmentBeforeJournaling(t *testing.T) {
	t.Run("root mismatch", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		fixture.write(t, "moved.ini", "local")
		base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"moved.ini": "local"}))
		remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"moved.ini": "remote"}))
		elsewhere := filepath.Join(fixture.paths.Home, "elsewhere")
		require.NoError(t, os.Mkdir(elsewhere, 0o700))
		request := fixture.request(fixture.local, base, remote)
		request.Roots = map[string]string{fixture.target.ID: elsewhere}

		_, err := ApplyPublication(context.Background(), request)
		requirePublicationApplyRefusal(t, err, "apply-plan", "root_mismatch")
		assert.NoFileExists(t, filepath.Join(elsewhere, "moved.ini"))
		assert.Equal(t, "local", fixture.read(t, "moved.ini"))
		fixture.assertNoJournalRows(t)
	})

	t.Run("absent parent", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"nested/deep.ini": "remote"}))

		_, err := ApplyPublication(context.Background(), fixture.request(fixture.local, fixture.emptySnapshot(), remote))
		requirePublicationApplyRefusal(t, err, "apply-plan", "missing_parent")
		assert.NoFileExists(t, fixture.path("nested"))
		fixture.assertNoJournalRows(t)
	})

	t.Run("symlinked destination", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"linked.ini": "remote"}))
		outside := filepath.Join(fixture.paths.Home, "outside.ini")
		capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
			result, err := LocalFilesCapture{}.Capture(ctx, target, path)
			require.NoError(t, err)
			require.NoError(t, os.Symlink(outside, fixture.path("linked.ini")))
			return result, nil
		})
		local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
		require.NoError(t, err)

		report, err := ApplyPublication(context.Background(), fixture.request(local, fixture.emptySnapshot(), remote))
		requirePublicationApplyRefusal(t, err, "apply-observe", "destination_unreadable")
		assert.Equal(t, 0, report.Applied)
		linked, err := os.Lstat(fixture.path("linked.ini"))
		require.NoError(t, err)
		assert.NotZero(t, linked.Mode()&os.ModeSymlink)
		assert.NoFileExists(t, outside)
		fixture.assertNoJournalRows(t)
	})

	t.Run("escaping recorded destination", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		anchor := fixture.anchor(t)
		elsewhere := filepath.Join(fixture.paths.Home, "elsewhere")
		require.NoError(t, os.Mkdir(elsewhere, 0o700))

		assert.Error(t, publicationApplyContainment(anchor, fixture.root, "../outside.ini"))
		assert.Error(t, publicationApplyContainment(anchor, "/etc", "passwd"))
		assert.Error(t, publicationApplyContainment(anchor, fixture.root, "."))
		assert.Error(t, publicationApplyContainment(anchor, fixture.root, "/absolute.ini"))
		assert.Error(t, publicationApplyContainment(anchor, elsewhere, "inside.ini"))
		assert.NoError(t, publicationApplyContainment(anchor, fixture.root, "inside.ini"))
	})
}

func TestApplyPublicationLeavesInterruptedDeleteForResolution(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "removed.ini", "gone")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"removed.ini": "gone"}))
	remote := fixture.targetSnapshot(nil)

	stop := errors.New("synthetic stop after unlink")
	request := fixture.request(fixture.local, base, remote)
	request.Barrier = func(phase PublicationApplyPhase, _ publicationstate.JournalEntry) error {
		if phase == PublicationApplyMutated {
			return stop
		}
		return nil
	}
	report, err := ApplyPublication(context.Background(), request)
	require.ErrorIs(t, err, stop)
	require.NotNil(t, report.Stopped)
	assert.Equal(t, PublicationApplyDelete, report.Stopped.Operation)
	assert.Equal(t, publicationstate.JournalStatePending, report.Stopped.State)
	assert.NoFileExists(t, fixture.path("removed.ini"))

	resolutions := fixture.resolutions(t)
	require.Len(t, resolutions, 1)
	assert.Equal(t, report.Stopped.Journal, resolutions[0].Entry)
	assert.Equal(t, publicationstate.JournalOutcomeApplied, resolutions[0].Outcome)
	assert.NoFileExists(t, fixture.path("removed.ini"))
}

func TestApplyPublicationSkipsPlannedWorkThatIsAlreadySettled(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	fixture.write(t, "removed.ini", "gone")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"changed.ini": "before", "removed.ini": "gone",
	}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))
	capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
		result, err := LocalFilesCapture{}.Capture(ctx, target, path)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(fixture.path("changed.ini"), []byte("after"), 0o600))
		require.NoError(t, os.Remove(fixture.path("removed.ini")))
		return result, nil
	})
	local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
	require.NoError(t, err)

	report, err := ApplyPublication(context.Background(), fixture.request(local, base, remote))
	require.NoError(t, err)
	assert.Equal(t, 0, report.Applied)
	assert.Equal(t, 2, report.Unchanged)
	assert.Equal(t, uint64(0), report.BytesWritten)
	for _, entry := range report.Entries {
		assert.Equal(t, PublicationApplyUnchanged, entry.Operation)
		assert.Zero(t, entry.Journal)
	}
	assert.Equal(t, "after", fixture.read(t, "changed.ini"))
	assert.NoFileExists(t, fixture.path("removed.ini"))
	fixture.assertNoJournalRows(t)
}

func TestApplyPublicationRefusesInvalidRequests(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	base := fixture.targetSnapshot(nil)
	remote := fixture.targetSnapshot(nil)

	missingJournal := fixture.request(fixture.local, base, remote)
	missingJournal.Journal = nil
	_, err := ApplyPublication(context.Background(), missingJournal)
	requirePublicationApplyRefusal(t, err, "apply", "request_invalid")

	missingLocal := fixture.request(fixture.local, base, remote)
	missingLocal.Local = nil
	_, err = ApplyPublication(context.Background(), missingLocal)
	requirePublicationApplyRefusal(t, err, "apply", "request_invalid")

	missingRoots := fixture.request(fixture.local, base, remote)
	missingRoots.Roots = nil
	_, err = ApplyPublication(context.Background(), missingRoots)
	requirePublicationApplyRefusal(t, err, "apply", "request_invalid")

	emptyVault := fixture.request(fixture.local, base, remote)
	emptyVault.Vault = [32]byte{}
	_, err = ApplyPublication(context.Background(), emptyVault)
	requirePublicationApplyRefusal(t, err, "apply", "request_invalid")

	unsupportedEntry := fixture.request(fixture.local, base, fixture.targetSnapshot([]model.Entry{
		{TargetID: fixture.target.ID, File: &model.FileEntry{Path: "link.ini", State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: "shared/target.ini"}},
	}))
	_, err = ApplyPublication(context.Background(), unsupportedEntry)
	requirePublicationApplyRefusal(t, err, "apply-plan", "target_unsupported")

	fixture.assertNoJournalRows(t)
}

type publicationApplySwappingFileSystem struct {
	files.ApplyFileSystem
	at    int
	calls int
	swap  func()
}

func (swapping *publicationApplySwappingFileSystem) OpenRoot(path string) (files.ApplyRoot, error) {
	swapping.calls++
	if swapping.calls == swapping.at {
		swapping.swap()
	}
	return swapping.ApplyFileSystem.OpenRoot(path)
}

func publicationApplyReplaceRoot(t *testing.T, fixture publicationApplyFixture) string {
	t.Helper()
	moved := fixture.root + "-moved"
	require.NoError(t, os.Rename(fixture.root, moved))
	require.NoError(t, os.Mkdir(fixture.root, 0o700))
	return moved
}

func publicationApplySymlinkAncestor(t *testing.T, fixture publicationApplyFixture) (string, string) {
	t.Helper()
	ancestor := filepath.Join(fixture.paths.Home, "applied")
	moved := filepath.Join(fixture.paths.Home, "applied-moved")
	other := filepath.Join(fixture.paths.Home, "other")
	require.NoError(t, os.MkdirAll(filepath.Join(other, "tree"), 0o700))
	require.NoError(t, os.Rename(ancestor, moved))
	require.NoError(t, os.Symlink(other, ancestor))
	return filepath.Join(moved, "tree"), filepath.Join(other, "tree")
}

func publicationApplyJournalDatabase(t *testing.T, fixture publicationApplyFixture) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+fixture.journalPath)
	require.NoError(t, err)
	return db
}

func publicationApplyJournalState(t *testing.T, fixture publicationApplyFixture, entry int64) (string, string) {
	t.Helper()
	db := publicationApplyJournalDatabase(t, fixture)
	defer func() { require.NoError(t, db.Close()) }()
	var state, stage string
	require.NoError(t, db.QueryRow("SELECT state,stage FROM journal WHERE entry=?", entry).Scan(&state, &stage))
	return state, stage
}

func publicationApplyRewriteBackup(t *testing.T, fixture publicationApplyFixture, digest [32]byte, data []byte) {
	t.Helper()
	db := publicationApplyJournalDatabase(t, fixture)
	defer func() { require.NoError(t, db.Close()) }()
	_, err := db.Exec("UPDATE backups SET data=? WHERE digest=?", data, digest[:])
	require.NoError(t, err)
	var stored any
	require.NoError(t, db.QueryRow("SELECT data FROM backups WHERE digest=?", digest[:]).Scan(&stored))
	require.Equal(t, data, stored)
}

func TestApplyPublicationRefusesPostCaptureLocalChanges(t *testing.T) {
	cases := map[string]struct {
		local     map[string]string
		base      map[string]string
		remote    map[string]string
		inject    func(t *testing.T, fixture publicationApplyFixture)
		preserved map[string]string
	}{
		"small edit": {
			local:  map[string]string{"changed.ini": "before"},
			base:   map[string]string{"changed.ini": "before"},
			remote: map[string]string{"changed.ini": "after"},
			inject: func(t *testing.T, fixture publicationApplyFixture) {
				require.NoError(t, os.WriteFile(fixture.path("changed.ini"), []byte("user edit"), 0o600))
			},
			preserved: map[string]string{"changed.ini": "user edit"},
		},
		"newly created file": {
			local:  map[string]string{},
			base:   map[string]string{},
			remote: map[string]string{"created.ini": "remote"},
			inject: func(t *testing.T, fixture publicationApplyFixture) {
				require.NoError(t, os.WriteFile(fixture.path("created.ini"), []byte("user file"), 0o600))
			},
			preserved: map[string]string{"created.ini": "user file"},
		},
		"changed delete target": {
			local:  map[string]string{"removed.ini": "gone"},
			base:   map[string]string{"removed.ini": "gone"},
			remote: map[string]string{},
			inject: func(t *testing.T, fixture publicationApplyFixture) {
				require.NoError(t, os.WriteFile(fixture.path("removed.ini"), []byte("user edit"), 0o600))
			},
			preserved: map[string]string{"removed.ini": "user edit"},
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newPublicationApplyFixture(t)
			for path, content := range testCase.local {
				fixture.write(t, path, content)
			}
			base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, testCase.base))
			remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, testCase.remote))
			capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
				result, err := LocalFilesCapture{}.Capture(ctx, target, path)
				require.NoError(t, err)
				testCase.inject(t, fixture)
				return result, nil
			})
			local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
			require.NoError(t, err)

			report, err := ApplyPublication(context.Background(), fixture.request(local, base, remote))
			requirePublicationApplyRefusal(t, err, "apply-observe", "preimage_changed")
			assert.Equal(t, 0, report.Applied)
			require.NotNil(t, report.Stopped)
			assert.Zero(t, report.Stopped.Journal)
			for path, content := range testCase.preserved {
				assert.Equal(t, content, fixture.read(t, path))
			}
			fixture.assertNoJournalRows(t)
		})
	}
}

func TestApplyPublicationRefusesAncestorSwapBeforeMutation(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))
	other := filepath.Join(fixture.paths.Home, "other")
	require.NoError(t, os.MkdirAll(filepath.Join(other, "tree"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(other, "tree", "changed.ini"), []byte("before"), 0o600))
	moved := filepath.Join(fixture.paths.Home, "applied-moved")
	swapping := &publicationApplySwappingFileSystem{ApplyFileSystem: files.DefaultApplyFileSystem(), at: 2}
	swapping.swap = func() {
		require.NoError(t, os.Rename(filepath.Join(fixture.paths.Home, "applied"), moved))
		require.NoError(t, os.Symlink(other, filepath.Join(fixture.paths.Home, "applied")))
	}
	request := fixture.request(fixture.local, base, remote)
	request.FileSystem = swapping

	report, err := ApplyPublication(context.Background(), request)
	requirePublicationApplyRefusal(t, err, "apply-mutate", "containment_refused")
	assert.Equal(t, 2, swapping.calls)
	assert.Equal(t, 0, report.Applied)
	require.NotNil(t, report.Stopped)
	assert.Equal(t, publicationstate.JournalStateIndeterminate, report.Stopped.State)
	assert.Equal(t, "before", fixture.readOther(t, filepath.Join(other, "tree", "changed.ini")))
	assert.Equal(t, "before", fixture.readOther(t, filepath.Join(moved, "tree", "changed.ini")))
}

func TestApplyPublicationRefusesReplacedTargetBetweenEntries(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "a.ini", "before")
	fixture.write(t, "b.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"a.ini": "before", "b.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"a.ini": "after", "b.ini": "after"}))
	moved := fixture.root + "-moved"
	swapping := &publicationApplySwappingFileSystem{ApplyFileSystem: files.DefaultApplyFileSystem(), at: 4}
	swapping.swap = func() {
		require.NoError(t, os.Rename(fixture.root, moved))
		require.NoError(t, os.Mkdir(fixture.root, 0o700))
		require.NoError(t, os.WriteFile(fixture.path("b.ini"), []byte("before"), 0o600))
	}
	request := fixture.request(fixture.local, base, remote)
	request.FileSystem = swapping

	report, err := ApplyPublication(context.Background(), request)
	requirePublicationApplyRefusal(t, err, "apply-observe", "containment_refused")
	assert.Equal(t, 4, swapping.calls)
	assert.Equal(t, 1, report.Applied)
	require.NotNil(t, report.Stopped)
	assert.Equal(t, "b.ini", report.Stopped.Path)
	assert.Zero(t, report.Stopped.Journal)
	assert.Equal(t, "after", fixture.readOther(t, filepath.Join(moved, "a.ini")))
	assert.Equal(t, "before", fixture.readOther(t, filepath.Join(moved, "b.ini")))
	assert.Equal(t, "before", fixture.readOther(t, fixture.path("b.ini")))
	assert.Equal(t, int64(1), fixture.journalRowCount(t))
}

func TestApplyPublicationResolvesInterruptedAnchorMismatch(t *testing.T) {
	stopBeforeMutation := func(phase PublicationApplyPhase, _ publicationstate.JournalEntry) error {
		if phase == PublicationApplyJournaled {
			return errors.New("synthetic stop before mutation")
		}
		return nil
	}
	interrupt := func(t *testing.T, fixture publicationApplyFixture, base, remote model.Snapshot) int64 {
		t.Helper()
		request := fixture.request(fixture.local, base, remote)
		request.Barrier = stopBeforeMutation
		_, err := ApplyPublication(context.Background(), request)
		require.Error(t, err)
		require.Equal(t, int64(1), fixture.journalRowCount(t))
		return 1
	}
	requireBlocked := func(t *testing.T, fixture publicationApplyFixture, entry int64, state string) {
		t.Helper()
		require.ErrorIs(t, fixture.journal.CheckAdmission(context.Background(), 1000), publicationstate.ErrContinuity)
		read, stage := publicationApplyJournalState(t, fixture, entry)
		assert.Equal(t, state, read)
		assert.Equal(t, "apply-pending", stage)
	}

	t.Run("pending write replacement directory", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		fixture.write(t, "changed.ini", "before")
		base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
		remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))
		entry := interrupt(t, fixture, base, remote)
		moved := publicationApplyReplaceRoot(t, fixture)
		require.NoError(t, os.WriteFile(fixture.path("changed.ini"), []byte("after"), 0o600))

		_, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
		requirePublicationApplyRefusal(t, err, "apply-resolve", "journal_unobserved")
		requireBlocked(t, fixture, entry, "pending")
		assert.Equal(t, "before", fixture.readOther(t, filepath.Join(moved, "changed.ini")))
	})

	t.Run("pending write symlinked ancestor", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		fixture.write(t, "changed.ini", "before")
		base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
		remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))
		entry := interrupt(t, fixture, base, remote)
		movedTree, otherTree := publicationApplySymlinkAncestor(t, fixture)
		require.NoError(t, os.WriteFile(filepath.Join(otherTree, "changed.ini"), []byte("after"), 0o600))

		_, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
		requirePublicationApplyRefusal(t, err, "apply-resolve", "journal_unobserved")
		requireBlocked(t, fixture, entry, "pending")
		assert.Equal(t, "before", fixture.readOther(t, filepath.Join(movedTree, "changed.ini")))
		assert.Equal(t, "after", fixture.readOther(t, filepath.Join(otherTree, "changed.ini")))
	})

	t.Run("pending delete replacement directory", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		fixture.write(t, "removed.ini", "gone")
		base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"removed.ini": "gone"}))
		remote := fixture.targetSnapshot(nil)
		entry := interrupt(t, fixture, base, remote)
		moved := publicationApplyReplaceRoot(t, fixture)

		_, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
		requirePublicationApplyRefusal(t, err, "apply-resolve", "journal_unobserved")
		requireBlocked(t, fixture, entry, "pending")
		assert.Equal(t, "gone", fixture.readOther(t, filepath.Join(moved, "removed.ini")))
	})

	t.Run("pending delete symlinked ancestor", func(t *testing.T) {
		fixture := newPublicationApplyFixture(t)
		fixture.write(t, "removed.ini", "gone")
		base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"removed.ini": "gone"}))
		remote := fixture.targetSnapshot(nil)
		entry := interrupt(t, fixture, base, remote)
		movedTree, otherTree := publicationApplySymlinkAncestor(t, fixture)

		_, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
		requirePublicationApplyRefusal(t, err, "apply-resolve", "journal_unobserved")
		requireBlocked(t, fixture, entry, "pending")
		assert.Equal(t, "gone", fixture.readOther(t, filepath.Join(movedTree, "removed.ini")))
		assert.NoFileExists(t, filepath.Join(otherTree, "removed.ini"))
	})
}

func TestApplyPublicationRefusesWhileAnApplyLeaseIsHeld(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))
	lease, err := fixture.journal.AcquireApplyLease(context.Background())
	require.NoError(t, err)

	report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	requirePublicationApplyRefusal(t, err, "apply", "apply_lease_held")
	assert.Equal(t, 0, report.Applied)
	assert.Equal(t, "before", fixture.read(t, "changed.ini"))
	fixture.assertNoJournalRows(t)

	require.NoError(t, lease.Close())
	report, err = ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	require.NoError(t, err)
	assert.Equal(t, 1, report.Applied)
	assert.Equal(t, "after", fixture.read(t, "changed.ini"))
}

func TestApplyPublicationInterleavedInvocationCannotResolveTheLiveRow(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "changed.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))
	var nested error
	var nestedRows int64
	var nestedState string
	request := fixture.request(fixture.local, base, remote)
	request.Barrier = func(phase PublicationApplyPhase, journaled publicationstate.JournalEntry) error {
		if phase != PublicationApplyJournaled {
			return nil
		}
		nestedReport, nestedErr := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
		nested = nestedErr
		assert.Equal(t, 0, nestedReport.Applied)
		nestedRows = fixture.journalRowCount(t)
		nestedState, _ = publicationApplyJournalState(t, fixture, journaled.Entry)
		return nil
	}

	report, err := ApplyPublication(context.Background(), request)
	require.NoError(t, err)
	requirePublicationApplyRefusal(t, nested, "apply", "apply_lease_held")
	assert.Equal(t, int64(1), nestedRows)
	assert.Equal(t, "pending", nestedState)
	assert.Equal(t, 1, report.Applied)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, publicationstate.JournalStateApplied, report.Entries[0].State)
	assert.Equal(t, "after", fixture.read(t, "changed.ini"))
	state, stage := publicationApplyJournalState(t, fixture, report.Entries[0].Journal)
	assert.Equal(t, "applied", state)
	assert.Equal(t, "apply-complete", stage)
	require.NoError(t, fixture.journal.CheckAdmission(context.Background(), fixture.floor))
	assert.Equal(t, int64(1), fixture.journalRowCount(t))
}

func TestApplyPublicationRefusesReusingCorruptBackup(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "before"}))
	first := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "first"}))
	report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, first))
	require.NoError(t, err)
	backup := publicationApplyEntryFor(t, report, "note.ini").Backup
	require.NotNil(t, backup)
	require.Equal(t, int64(1), fixture.journalRowCount(t))

	fixture.write(t, "note.ini", "before")
	next := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "second"}))
	for name, data := range map[string][]byte{"truncated": []byte("befor"), "same length corrupt": []byte("bEfore")} {
		t.Run(name, func(t *testing.T) {
			publicationApplyRewriteBackup(t, fixture, *backup, data)
			_, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, next))
			require.ErrorIs(t, err, publicationstate.ErrSchema)
			var journalErr *publicationstate.Error
			require.ErrorAs(t, err, &journalErr)
			assert.Equal(t, publicationstate.StageJournal, journalErr.Stage())
			assert.Equal(t, publicationstate.ReasonCorrupt, journalErr.Reason())
			assert.Equal(t, "before", fixture.read(t, "note.ini"))
			assert.Equal(t, int64(1), fixture.journalRowCount(t))
		})
	}
}

func TestApplyPublicationRefusesBackupOnlySelection(t *testing.T) {
	cases := map[string]func(fixture *publicationApplyFixture){
		"target": func(fixture *publicationApplyFixture) {
			fixture.configuration.Targets[0].Mode = config.BackupOnly
		},
		"inherited": func(fixture *publicationApplyFixture) {
			fixture.configuration.Defaults.Mode = config.BackupOnly
		},
	}
	for name, apply := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newPublicationApplyFixture(t)
			apply(&fixture)
			fixture.write(t, "changed.ini", "before")
			fixture.write(t, "removed.ini", "gone")
			base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "before", "removed.ini": "gone"}))
			remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"changed.ini": "after"}))

			report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
			requirePublicationApplyRefusal(t, err, "apply-plan", "backup_only")
			assert.Equal(t, 0, report.Applied)
			assert.Equal(t, "before", fixture.read(t, "changed.ini"))
			assert.Equal(t, "gone", fixture.read(t, "removed.ini"))
			fixture.assertNoJournalRows(t)
		})
	}
}

func TestApplyPublicationJournalRowCountSeesTerminalRows(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "done")
	preimage := publicationstate.ObservedJournalFile([]byte("done"))
	entry, err := fixture.journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: fixture.vault, Operation: "apply", DestinationDir: fixture.root, DestinationPath: "note.ini",
		Anchor: fixture.anchor(t), Preimage: &preimage, PreimageBytes: []byte("done"),
		Postimage: publicationstate.ObservedJournalFile([]byte("next")), SeenFloorRevision: 2,
	})
	require.NoError(t, err)
	resolutions := fixture.resolutions(t)
	require.Len(t, resolutions, 1)
	assert.Equal(t, publicationstate.JournalOutcomeFailed, resolutions[0].Outcome)
	assert.Empty(t, fixture.resolutions(t))
	assert.NoError(t, fixture.journal.CheckAdmission(context.Background(), 0))
	assert.Equal(t, int64(1), fixture.journalRowCount(t))
	state, stage := publicationApplyJournalState(t, fixture, entry.Entry)
	assert.Equal(t, "failed", state)
	assert.Equal(t, "apply-failed", stage)
}

func publicationApplyModeEntry(targetID, path, content string, mode uint32) model.Entry {
	return model.Entry{TargetID: targetID, File: &model.FileEntry{Path: path, State: model.FilePresent, Kind: model.FileRegular, Content: []byte(content), Mode: mode}}
}

func TestApplyPublicationRefusesUnsupportedModeChanges(t *testing.T) {
	cases := map[string]struct {
		local      string
		localMode  os.FileMode
		base       string
		remote     string
		remoteMode uint32
	}{
		"mode only difference":               {local: "same", localMode: 0o600, base: "same", remote: "same", remoteMode: 0o644},
		"content and mode difference":        {local: "before", localMode: 0o600, base: "before", remote: "after", remoteMode: 0o644},
		"local mode is not the applied mode": {local: "same", localMode: 0o644, base: "same", remote: "same", remoteMode: 0o600},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newPublicationApplyFixture(t)
			fixture.write(t, "note.ini", testCase.local)
			require.NoError(t, os.Chmod(fixture.path("note.ini"), testCase.localMode))
			base := fixture.targetSnapshot([]model.Entry{publicationApplyModeEntry(fixture.target.ID, "note.ini", testCase.base, uint32(testCase.localMode))})
			remote := fixture.targetSnapshot([]model.Entry{publicationApplyModeEntry(fixture.target.ID, "note.ini", testCase.remote, testCase.remoteMode)})
			before, err := os.Lstat(fixture.path("note.ini"))
			require.NoError(t, err)

			plan, err := PlanPublicationApply(context.Background(), fixture.request(fixture.local, base, remote))
			requirePublicationApplyRefusal(t, err, "apply-plan", "mode_unsupported")
			assert.Empty(t, plan.Entries)

			report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
			requirePublicationApplyRefusal(t, err, "apply-plan", "mode_unsupported")
			assert.Equal(t, 0, report.Applied)
			assert.Nil(t, report.Stopped)
			after, err := os.Lstat(fixture.path("note.ini"))
			require.NoError(t, err)
			assert.True(t, os.SameFile(before, after))
			assert.Equal(t, testCase.localMode, after.Mode().Perm())
			assert.Equal(t, testCase.local, fixture.read(t, "note.ini"))
			fixture.assertNoJournalRows(t)
		})
	}
}

func TestApplyPublicationRefusesMixedPlanBeforeAnyMutation(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "supported.ini", "before")
	fixture.write(t, "unsupported.ini", "before")
	base := fixture.targetSnapshot([]model.Entry{
		publicationApplyModeEntry(fixture.target.ID, "supported.ini", "before", 0o600),
		publicationApplyModeEntry(fixture.target.ID, "unsupported.ini", "before", 0o600),
	})
	remote := fixture.targetSnapshot([]model.Entry{
		publicationApplyModeEntry(fixture.target.ID, "supported.ini", "after", 0o600),
		publicationApplyModeEntry(fixture.target.ID, "unsupported.ini", "after", 0o644),
	})

	report, err := ApplyPublication(context.Background(), fixture.request(fixture.local, base, remote))
	requirePublicationApplyRefusal(t, err, "apply-plan", "mode_unsupported")
	assert.Equal(t, 0, report.Applied)
	assert.Nil(t, report.Stopped)
	for _, name := range []string{"supported.ini", "unsupported.ini"} {
		assert.Equal(t, "before", fixture.read(t, name))
		info, err := os.Lstat(fixture.path(name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	fixture.assertNoJournalRows(t)
}

type publicationApplyCountingFileSystem struct {
	files.ApplyFileSystem
	growth int
	read   int64
}

type publicationApplyCountingRoot struct {
	files.ApplyRoot
	filesystem *publicationApplyCountingFileSystem
}

type publicationApplyCountingFile struct {
	files.ApplyFile
	filesystem *publicationApplyCountingFileSystem
}

func (f *publicationApplyCountingFileSystem) OpenRoot(path string) (files.ApplyRoot, error) {
	root, err := f.ApplyFileSystem.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &publicationApplyCountingRoot{ApplyRoot: root, filesystem: f}, nil
}

func (r *publicationApplyCountingRoot) OpenFile(name string, flag int, mode os.FileMode) (files.ApplyFile, error) {
	file, err := r.ApplyRoot.OpenFile(name, flag, mode)
	if err != nil {
		return nil, err
	}
	return &publicationApplyCountingFile{ApplyFile: file, filesystem: r.filesystem}, nil
}

func (f *publicationApplyCountingFile) Read(buffer []byte) (int, error) {
	read, err := f.ApplyFile.Read(buffer)
	f.filesystem.read += int64(read)
	if !errors.Is(err, io.EOF) {
		return read, err
	}
	if f.filesystem.growth == 0 {
		return read, err
	}
	extra := f.filesystem.growth
	if extra > len(buffer) {
		extra = len(buffer)
	}
	for index := 0; index < extra; index++ {
		buffer[index] = 'g'
	}
	f.filesystem.growth -= extra
	f.filesystem.read += int64(extra)
	return extra, nil
}

func (fixture publicationApplyFixture) writeSized(t *testing.T, name string, size int64) {
	t.Helper()
	require.NoError(t, os.WriteFile(fixture.path(name), nil, 0o600))
	require.NoError(t, os.Truncate(fixture.path(name), size))
}

func TestApplyPublicationRefusesOversizedPreimageWithoutReadingPastTheBound(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "big.bin", "A")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"big.bin": "A"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"big.bin": "B"}))
	counter := &publicationApplyCountingFileSystem{ApplyFileSystem: files.DefaultApplyFileSystem(), growth: 1 << 16}
	capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
		result, err := LocalFilesCapture{}.Capture(ctx, target, path)
		require.NoError(t, err)
		fixture.writeSized(t, "big.bin", publicationApplyMaxObservedBytes)
		return result, nil
	})
	local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
	require.NoError(t, err)
	request := fixture.request(local, base, remote)
	request.FileSystem = counter

	report, err := ApplyPublication(context.Background(), request)
	requirePublicationApplyRefusal(t, err, "apply-observe", "oversized")
	assert.Equal(t, publicationApplyMaxObservedBytes+1, counter.read)
	assert.Equal(t, 0, report.Applied)
	require.NotNil(t, report.Stopped)
	assert.Zero(t, report.Stopped.Journal)
	info, err := os.Lstat(fixture.path("big.bin"))
	require.NoError(t, err)
	assert.Equal(t, publicationApplyMaxObservedBytes, info.Size())
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	fixture.assertNoJournalRows(t)
}

func TestApplyPublicationRefusesOversizedPostimageWithoutReadingPastTheBound(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "after"}))
	counter := &publicationApplyCountingFileSystem{ApplyFileSystem: files.DefaultApplyFileSystem()}
	request := fixture.request(fixture.local, base, remote)
	request.FileSystem = counter
	request.Barrier = func(phase PublicationApplyPhase, _ publicationstate.JournalEntry) error {
		if phase != PublicationApplyMutated {
			return nil
		}
		fixture.writeSized(t, "note.ini", publicationApplyMaxObservedBytes)
		counter.read = 0
		counter.growth = 1 << 16
		return nil
	}

	report, err := ApplyPublication(context.Background(), request)
	requirePublicationApplyRefusal(t, err, "apply-observation", "oversized")
	assert.Equal(t, publicationApplyMaxObservedBytes+1, counter.read)
	assert.Equal(t, 0, report.Applied)
	require.NotNil(t, report.Stopped)
	assert.Equal(t, publicationstate.JournalStateIndeterminate, report.Stopped.State)
	assert.NotZero(t, report.Stopped.Journal)
}

func TestApplyPublicationRefusesOversizedRecoveryObservationWithoutReadingPastTheBound(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "before")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "after"}))
	stop := errors.New("synthetic stop before mutation")
	interrupted := fixture.request(fixture.local, base, remote)
	interrupted.Barrier = func(phase PublicationApplyPhase, _ publicationstate.JournalEntry) error {
		if phase == PublicationApplyJournaled {
			return stop
		}
		return nil
	}
	_, err := ApplyPublication(context.Background(), interrupted)
	require.ErrorIs(t, err, stop)
	require.Equal(t, int64(1), fixture.journalRowCount(t))

	fixture.writeSized(t, "note.ini", publicationApplyMaxObservedBytes)
	counter := &publicationApplyCountingFileSystem{ApplyFileSystem: files.DefaultApplyFileSystem(), growth: 1 << 16}
	recovery := fixture.request(fixture.local, base, remote)
	recovery.FileSystem = counter

	_, err = ApplyPublication(context.Background(), recovery)
	requirePublicationApplyRefusal(t, err, "apply-resolve", "journal_unobserved")
	assert.Equal(t, publicationApplyMaxObservedBytes+1, counter.read)
	require.ErrorIs(t, fixture.journal.CheckAdmission(context.Background(), 1000), publicationstate.ErrContinuity)
	assert.Equal(t, int64(1), fixture.journalRowCount(t))
}
