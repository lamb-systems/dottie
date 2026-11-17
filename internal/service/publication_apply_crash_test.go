package service

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/files"
)

const (
	publicationApplyCrashHelperName = "TestApplyCrashHelper"
	publicationApplyCrashHomeEnv    = "DOTTIE_TEST_APPLY_CRASH_HOME"
	publicationApplyCrashJournalEnv = "DOTTIE_TEST_APPLY_CRASH_JOURNAL"
	publicationApplyCrashStageEnv   = "DOTTIE_TEST_APPLY_CRASH_STAGE"

	publicationApplyCrashWrittenStage = "written"
	publicationApplyCrashRenamedStage = "renamed"

	publicationApplyCrashTarget          = "changed.ini"
	publicationApplyCrashPreimage        = "before"
	publicationApplyCrashPostimage       = "after"
	publicationApplyCrashFloor           = uint64(1)
	publicationApplyCrashDeadline        = 30 * time.Second
	publicationApplyCrashJournalName     = "journal"
	publicationApplyCrashJournalDatabase = "journal.db"
)

var publicationApplyCrashVault = [32]byte{0x63, 0x72, 0x61, 0x73, 0x68}

type publicationApplyCrashCase struct {
	name        string
	state       publicationstate.JournalState
	stage       publicationstate.JournalStage
	destination string
	scratch     bool
	rewrite     bool
}

var publicationApplyCrashCases = []publicationApplyCrashCase{
	{
		name: string(publicationApplyHookJournaled), state: publicationstate.JournalStatePending,
		stage: publicationstate.JournalStageApplyPending, destination: publicationApplyCrashPreimage, rewrite: true,
	},
	{
		name:        publicationApplyCrashWrittenStage,
		state:       publicationstate.JournalStatePending,
		stage:       publicationstate.JournalStageApplyPending,
		destination: publicationApplyCrashPreimage,
		scratch:     true,
		rewrite:     true,
	},
	{
		name: publicationApplyCrashRenamedStage, state: publicationstate.JournalStatePending,
		stage: publicationstate.JournalStageApplyPending, destination: publicationApplyCrashPostimage,
	},
	{
		name: string(publicationApplyHookMutated), state: publicationstate.JournalStatePending,
		stage: publicationstate.JournalStageApplyPending, destination: publicationApplyCrashPostimage,
	},
	{
		name: string(publicationApplyHookCompleted), state: publicationstate.JournalStateApplied,
		stage: publicationstate.JournalStageApplyComplete, destination: publicationApplyCrashPostimage,
	},
}

type publicationApplyCrashFixture struct {
	paths             platform.Paths
	root              string
	journalDirectory  string
	positionDirectory string
	binding           publicationstate.Binding
	floorRecord       publicationstate.Floor
	target            config.Target
	portable          model.Target
	configuration     config.Config
	local             *PublicationLocalContext
	vault             [32]byte
	floor             uint64
}

type publicationApplyCrashRow struct {
	entry  int64
	state  publicationstate.JournalState
	stage  publicationstate.JournalStage
	backup *[32]byte
}

type publicationApplyCrashFileSystem struct {
	files.ApplyFileSystem

	killBeforeRename bool
	killAfterRename  bool
}

type publicationApplyCrashRoot struct {
	files.ApplyRoot

	crash publicationApplyCrashFileSystem
}

func (crash publicationApplyCrashFileSystem) OpenRoot(path string) (files.ApplyRoot, error) {
	root, err := crash.ApplyFileSystem.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return publicationApplyCrashRoot{ApplyRoot: root, crash: crash}, nil
}

func (root publicationApplyCrashRoot) Rename(oldname, newname string) error {
	if root.crash.killBeforeRename {
		publicationApplyCrashKill()
	}
	if err := root.ApplyRoot.Rename(oldname, newname); err != nil {
		return err
	}
	if root.crash.killAfterRename {
		publicationApplyCrashKill()
	}
	return nil
}

func publicationApplyCrashKill() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

func publicationApplyCrashFixtureAt(home, journalDirectory string) (publicationApplyCrashFixture, error) {
	paths := platform.Paths{
		Home:       home,
		ConfigHome: filepath.Join(home, ".config"),
		StateHome:  filepath.Join(home, ".state"),
		CacheHome:  filepath.Join(home, ".cache"),
		DataHome:   filepath.Join(home, ".data"),
	}
	target := config.Target{
		ID:     "crash-files",
		Source: model.SourceFiles,
		Root:   &config.Root{Base: model.RootHome, Path: "applied/tree", Kind: model.SelectionDirectory},
	}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	portable, err := target.Model()
	if err != nil {
		return publicationApplyCrashFixture{}, err
	}
	local, err := NewPublicationLocalContext(paths, LocalFilesCapture{}, nil)
	if err != nil {
		return publicationApplyCrashFixture{}, err
	}
	return publicationApplyCrashFixture{
		paths: paths, root: filepath.Join(home, "applied", "tree"), journalDirectory: journalDirectory,
		target: target, portable: portable, configuration: configuration, local: local,
		vault: publicationApplyCrashVault, floor: publicationApplyCrashFloor,
	}, nil
}

func newPublicationApplyCrashFixture(t *testing.T) publicationApplyCrashFixture {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	fixture, err := publicationApplyCrashFixtureAt(
		home,
		filepath.Join(home, ".state", publicationApplyCrashJournalName),
	)
	require.NoError(t, err)
	for _, path := range []string{fixture.paths.ConfigHome, fixture.paths.StateHome, fixture.paths.CacheHome, fixture.paths.DataHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	require.NoError(t, os.MkdirAll(fixture.root, 0o700))
	require.NoError(
		t,
		os.WriteFile(fixture.path(publicationApplyCrashTarget), []byte(publicationApplyCrashPreimage), 0o600),
	)
	require.NoError(t, os.Mkdir(fixture.journalDirectory, 0o700))
	journal, err := publicationstate.OpenJournal(fixture.journalDirectory)
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	position := newPublicationAcceptFixture(t)
	position.append(t, "synthetic crash position payload")
	proposal := position.stage(t, 0)
	fixture.floorRecord = position.accept(t, proposal, 0)
	require.Equal(t, publicationApplyCrashFloor, fixture.floorRecord.Revision)
	fixture.positionDirectory = position.directory
	fixture.binding = position.binding
	return fixture
}

func (fixture publicationApplyCrashFixture) path(name string) string {
	return filepath.Join(fixture.root, name)
}

func (fixture publicationApplyCrashFixture) read(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

func (fixture publicationApplyCrashFixture) snapshot(entries map[string]string) model.Snapshot {
	return model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fixture.portable},
		Entries: publicationPreviewFileEntries(fixture.target.ID, entries),
	}
}

func (fixture publicationApplyCrashFixture) request(journal *publicationstate.Journal) PublicationApplyRequest {
	return PublicationApplyRequest{
		Journal:       journal,
		Vault:         fixture.vault,
		FloorRevision: fixture.floor,
		Configuration: fixture.configuration,
		BaseSnapshot:  fixture.snapshot(map[string]string{publicationApplyCrashTarget: publicationApplyCrashPreimage}),
		RemoteSnapshot: fixture.snapshot(
			map[string]string{publicationApplyCrashTarget: publicationApplyCrashPostimage},
		),
		Roots: map[string]string{fixture.target.ID: fixture.root},
		Local: fixture.local,
	}
}

func (fixture publicationApplyCrashFixture) runCrashHelper(t *testing.T, stage string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), publicationApplyCrashDeadline)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+publicationApplyCrashHelperName+"$")
	command.Env = append(os.Environ(),
		publicationApplyCrashHomeEnv+"="+fixture.paths.Home,
		publicationApplyCrashJournalEnv+"="+fixture.journalDirectory,
		publicationApplyCrashStageEnv+"="+stage,
	)
	output, err := command.CombinedOutput()
	require.NoError(t, ctx.Err(), "crash helper %q hung: %s", stage, output)
	var exited *exec.ExitError
	require.ErrorAs(t, err, &exited, "crash helper %q did not die: %s", stage, output)
	status, ok := exited.Sys().(syscall.WaitStatus)
	require.True(t, ok, "crash helper %q reported no wait status: %s", stage, output)
	require.True(t, status.Signaled(), "crash helper %q exited instead of dying: %s", stage, output)
	assert.Equal(t, syscall.SIGKILL, status.Signal(), "crash helper %q was killed by another signal: %s", stage, output)
}

func (fixture publicationApplyCrashFixture) scratch(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(fixture.root)
	require.NoError(t, err)
	paths := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "."+publicationApplyCrashTarget+".dottie-") && strings.HasSuffix(name, ".tmp") {
			paths = append(paths, fixture.path(name))
		}
	}
	return paths
}

func (fixture publicationApplyCrashFixture) rows(t *testing.T) []publicationApplyCrashRow {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(fixture.journalDirectory, publicationApplyCrashJournalDatabase))
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	result, err := db.Query("SELECT entry,state,stage,backup_digest FROM journal ORDER BY entry")
	require.NoError(t, err)
	defer func() { require.NoError(t, result.Close()) }()
	rows := make([]publicationApplyCrashRow, 0)
	for result.Next() {
		var entry int64
		var state, stage string
		var backup any
		require.NoError(t, result.Scan(&entry, &state, &stage, &backup))
		row := publicationApplyCrashRow{
			entry: entry,
			state: publicationstate.JournalState(state),
			stage: publicationstate.JournalStage(stage),
		}
		if backup != nil {
			digest, ok := backup.([]byte)
			require.True(t, ok, "journal entry %d holds a non-blob backup digest", entry)
			require.Len(t, digest, 32)
			var value [32]byte
			copy(value[:], digest)
			row.backup = &value
		}
		rows = append(rows, row)
	}
	require.NoError(t, result.Err())
	return rows
}

func (fixture publicationApplyCrashFixture) assertFloorUnchanged(t *testing.T) {
	t.Helper()
	store, err := publicationstate.Open(fixture.positionDirectory, fixture.binding)
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	floor, present, err := store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, fixture.floorRecord.Revision, floor.Revision)
	assert.Equal(t, fixture.floorRecord.Generation, floor.Generation)
}

func TestApplyCrashHelper(t *testing.T) {
	stage := os.Getenv(publicationApplyCrashStageEnv)
	if stage == "" {
		t.Skip("the crash helper runs only as the re-executed child of the crash harness")
	}
	fixture, err := publicationApplyCrashFixtureAt(
		os.Getenv(publicationApplyCrashHomeEnv),
		os.Getenv(publicationApplyCrashJournalEnv),
	)
	require.NoError(t, err)
	journal, err := publicationstate.OpenJournal(fixture.journalDirectory)
	require.NoError(t, err)
	defer func() { _ = journal.Close() }()
	publicationApplyStageHook = func(reached publicationApplyHookStage) {
		if string(reached) == stage {
			publicationApplyCrashKill()
		}
	}
	request := fixture.request(journal)
	switch stage {
	case publicationApplyCrashWrittenStage:
		request.FileSystem = publicationApplyCrashFileSystem{
			ApplyFileSystem:  files.DefaultApplyFileSystem(),
			killBeforeRename: true,
		}
	case publicationApplyCrashRenamedStage:
		request.FileSystem = publicationApplyCrashFileSystem{
			ApplyFileSystem: files.DefaultApplyFileSystem(),
			killAfterRename: true,
		}
	}
	_, err = ApplyPublication(context.Background(), request)
	require.NoError(t, err)
}

func TestApplyCrashStagesLeaveARecoverableJournal(t *testing.T) {
	for _, testCase := range publicationApplyCrashCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newPublicationApplyCrashFixture(t)
			destination := fixture.path(publicationApplyCrashTarget)
			preimage, err := os.Lstat(destination)
			require.NoError(t, err)

			fixture.runCrashHelper(t, testCase.name)

			journal, err := publicationstate.OpenJournal(fixture.journalDirectory)
			require.NoError(t, err)
			defer func() { assert.NoError(t, journal.Close()) }()
			lease, err := journal.AcquireApplyLease(context.Background())
			require.NoError(t, err)
			require.NoError(t, lease.Close())

			rows := fixture.rows(t)
			require.Len(t, rows, 1)
			assert.Equal(t, testCase.state, rows[0].state)
			assert.Equal(t, testCase.stage, rows[0].stage)
			require.NotNil(t, rows[0].backup)
			backup, err := journal.BackupBytes(context.Background(), *rows[0].backup)
			require.NoError(t, err)
			assert.Equal(t, publicationApplyCrashPreimage, string(backup))

			assert.Equal(t, testCase.destination, fixture.read(t, destination))
			destinationInfo, err := os.Lstat(destination)
			require.NoError(t, err)
			assert.Equal(t, int64(len(testCase.destination)), destinationInfo.Size())
			if testCase.rewrite {
				assert.True(t, os.SameFile(preimage, destinationInfo))
			}
			scratch := fixture.scratch(t)
			if testCase.scratch {
				require.Len(t, scratch, 1)
				assert.Equal(t, publicationApplyCrashPostimage, fixture.read(t, scratch[0]))
			} else {
				assert.Empty(t, scratch)
			}

			fixture.assertFloorUnchanged(t)

			if testCase.scratch {
				_, err = ApplyPublication(context.Background(), fixture.request(journal))
				requirePublicationApplyRefusal(t, err, "apply-plan", "plan_unresolved")
				resolved := fixture.rows(t)
				require.Len(t, resolved, 1)
				assert.Equal(t, publicationstate.JournalStateFailed, resolved[0].state)
				assert.Equal(t, publicationstate.JournalStageApplyFailed, resolved[0].stage)
				for _, path := range scratch {
					require.NoError(t, os.Remove(path))
				}
			}

			before, err := os.Lstat(destination)
			require.NoError(t, err)
			report, err := ApplyPublication(context.Background(), fixture.request(journal))
			require.NoError(t, err)
			after, err := os.Lstat(destination)
			require.NoError(t, err)
			require.Len(t, report.Entries, 1)
			assert.Equal(t, publicationApplyCrashPostimage, fixture.read(t, destination))
			if testCase.rewrite {
				assert.Equal(t, PublicationApplyWrite, report.Entries[0].Operation)
				assert.Equal(t, publicationstate.JournalStateApplied, report.Entries[0].State)
				assert.Equal(t, 1, report.Applied)
				assert.Equal(t, 0, report.Unchanged)
				assert.Equal(t, uint64(len(publicationApplyCrashPostimage)), report.BytesWritten)
				assert.False(t, os.SameFile(preimage, after))
				assert.False(t, os.SameFile(before, after))
			} else {
				assert.Equal(t, PublicationApplyUnchanged, report.Entries[0].Operation)
				assert.Equal(t, publicationstate.JournalState(""), report.Entries[0].State)
				assert.Zero(t, report.Entries[0].Journal)
				assert.Equal(t, 0, report.Applied)
				assert.Equal(t, 1, report.Unchanged)
				assert.Equal(t, uint64(0), report.BytesWritten)
				assert.True(t, os.SameFile(before, after))
				assert.Equal(t, before.ModTime(), after.ModTime())
			}

			settled := fixture.rows(t)
			if testCase.rewrite {
				require.Len(t, settled, 2)
				assert.Equal(t, publicationstate.JournalStateFailed, settled[0].state)
				assert.Equal(t, publicationstate.JournalStageApplyFailed, settled[0].stage)
				assert.Equal(t, publicationstate.JournalStateApplied, settled[1].state)
				assert.Equal(t, publicationstate.JournalStageApplyComplete, settled[1].stage)
			} else {
				require.Len(t, settled, 1)
				assert.Equal(t, publicationstate.JournalStateApplied, settled[0].state)
				assert.Equal(t, publicationstate.JournalStageApplyComplete, settled[0].stage)
			}
			require.NoError(t, journal.CheckAdmission(context.Background(), fixture.floor))
			fixture.assertFloorUnchanged(t)
		})
	}
}
