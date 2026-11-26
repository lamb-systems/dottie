package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/source/files"
)

func fileSetApplyUmask(t *testing.T) {
	t.Helper()
	previous := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(previous) })
}

func fileSetApplyRemote(t *testing.T, fixture publicationApplyFixture, entries ...publication.PayloadEntry) model.Snapshot {
	t.Helper()
	snapshot, err := ProjectFileSetSnapshot(fixture.portable, entries)
	require.NoError(t, err)
	return snapshot
}

func fileSetApplyEntry(path string, mode uint32, content string) publication.PayloadEntry {
	return publication.PayloadEntry{
		Path: path, Mode: mode, Size: uint64(len(content)), Content: []byte(content),
	}
}

func TestFileSetApplyCreatesMissingParentsFromAnEmptyTargetRoot(t *testing.T) {
	fileSetApplyUmask(t)
	fixture := newPublicationApplyFixture(t)
	remote := fileSetApplyRemote(
		t,
		fixture,
		fileSetApplyEntry("init.lua", 0o600, "synthetic file-set init"),
		fileSetApplyEntry("lua/config/options.lua", 0o644, "synthetic file-set options"),
	)
	request := fixture.request(fixture.local, fixture.emptySnapshot(), remote)
	request.FileSetTargets = []string{fixture.target.ID}

	plan, err := PlanPublicationApply(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, 4, plan.Changes)
	assert.Equal(t, []PublicationApplyPlanEntry{
		{
			TargetID: fixture.target.ID, Path: "init.lua", Operation: PublicationApplyWrite,
			Size: uint64(len("synthetic file-set init")),
		},
		{TargetID: fixture.target.ID, Path: "lua", Operation: PublicationApplyMkdir},
		{TargetID: fixture.target.ID, Path: "lua/config", Operation: PublicationApplyMkdir},
		{
			TargetID: fixture.target.ID, Path: "lua/config/options.lua", Operation: PublicationApplyWrite,
			Size: uint64(len("synthetic file-set options")),
		},
	}, plan.Entries)
	require.NoDirExists(t, fixture.path("lua"), "planning created a directory")

	report, err := ApplyPublication(context.Background(), request)
	require.NoError(t, err)
	assert.Nil(t, report.Stopped)
	assert.Equal(t, 4, report.Applied)
	assert.Zero(t, report.Unchanged)
	assert.Equal(
		t,
		uint64(len("synthetic file-set init")+len("synthetic file-set options")),
		report.BytesWritten,
	)

	for _, path := range []string{"lua", "lua/config"} {
		directory := publicationApplyEntryFor(t, report, path)
		assert.Equal(t, PublicationApplyMkdir, directory.Operation, path)
		assert.Equal(t, uint32(0o755), directory.Mode, path)
		assert.Zero(t, directory.Journal, path)
		info, err := os.Lstat(fixture.path(path))
		require.NoError(t, err)
		assert.True(t, info.IsDir(), path)
		assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), path)
	}

	assert.Equal(t, "synthetic file-set init", fixture.read(t, "init.lua"))
	assert.Equal(t, "synthetic file-set options", fixture.read(t, "lua/config/options.lua"))
	for path, want := range map[string]os.FileMode{"init.lua": 0o600, "lua/config/options.lua": 0o644} {
		info, err := os.Lstat(fixture.path(path))
		require.NoError(t, err)
		assert.Equal(t, want, info.Mode().Perm(), path)
		assert.NotZero(t, publicationApplyEntryFor(t, report, path).Journal, path)
	}

	assert.Equal(t, int64(2), fixture.journalRowCount(t), "a synthesized directory was journaled")
	assert.Empty(t, fixture.resolutions(t))
	assert.NoError(t, fixture.journal.CheckAdmission(context.Background(), fixture.floor))
}

func newFileSetApplySymlinkedParentRequest(
	t *testing.T,
) (publicationApplyFixture, PublicationApplyRequest, string) {
	t.Helper()
	fixture := newPublicationApplyFixture(t)
	remote := fileSetApplyRemote(t, fixture, fileSetApplyEntry("linked/app.conf", 0o600, "synthetic linked"))
	outside := filepath.Join(fixture.paths.Home, "outside")
	require.NoError(t, os.Mkdir(outside, 0o700))
	capture := publicationCapturePortFunc(
		func(ctx context.Context, target config.Target, path string) (files.Result, error) {
			result, err := LocalFilesCapture{}.Capture(ctx, target, path)
			require.NoError(t, err)
			if _, statErr := os.Lstat(fixture.path("linked")); errors.Is(statErr, os.ErrNotExist) {
				require.NoError(t, os.Symlink(outside, fixture.path("linked")))
			}
			return result, nil
		},
	)
	local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
	require.NoError(t, err)
	request := fixture.request(local, fixture.emptySnapshot(), remote)
	request.FileSetTargets = []string{fixture.target.ID}
	return fixture, request, outside
}

func TestFileSetApplyRefusesASymlinkedParentBeforeJournaling(t *testing.T) {
	t.Run("plan", func(t *testing.T) {
		fixture, request, outside := newFileSetApplySymlinkedParentRequest(t)

		_, err := PlanPublicationApply(context.Background(), request)
		requirePublicationApplyRefusal(t, err, "apply-plan", "missing_parent")
		assert.NoFileExists(t, filepath.Join(outside, "app.conf"))
		fixture.assertNoJournalRows(t)
	})

	t.Run("apply", func(t *testing.T) {
		fixture, request, outside := newFileSetApplySymlinkedParentRequest(t)

		_, err := ApplyPublication(context.Background(), request)
		requirePublicationApplyRefusal(t, err, "apply-plan", "missing_parent")
		assert.NoFileExists(t, filepath.Join(outside, "app.conf"))
		fixture.assertNoJournalRows(t)
	})
}

func TestFileSetApplyRefusesADirectoryDownloadInBackupOnly(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.configuration.Targets[0].Mode = config.BackupOnly
	remote := fileSetApplyRemote(t, fixture, fileSetApplyEntry("nested/app.conf", 0o600, "synthetic nested"))
	request := fixture.request(fixture.local, fixture.emptySnapshot(), remote)
	request.FileSetTargets = []string{fixture.target.ID}

	_, err := PlanPublicationApply(context.Background(), request)
	requirePublicationApplyRefusal(t, err, "apply-plan", "backup_only")
	_, err = ApplyPublication(context.Background(), request)
	requirePublicationApplyRefusal(t, err, "apply-plan", "backup_only")
	require.NoDirExists(t, fixture.path("nested"))
	fixture.assertNoJournalRows(t)
}
