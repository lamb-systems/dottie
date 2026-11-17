package config

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
)

func TestOpenSnapshotAbsentReturnsDefaultWithoutCreatingState(t *testing.T) {
	paths := testPaths(t)
	snapshot, err := OpenSnapshot(paths)
	require.NoError(t, err)
	assert.Equal(t, Default(), snapshot.Config, "absent snapshot config")
	assert.Equal(t, Token{}, snapshot.Token, "absent snapshot token")
	assert.Equal(t, selectionDigest(Default()), snapshot.Selection.Digest, "absent snapshot selection digest")
	assert.Equal(t, approvalDigest(Default()), snapshot.Approval.Digest, "absent snapshot approval digest")
	assert.Zero(t, snapshot.Selection.Revision, "absent snapshot selection revision")
	assert.Zero(t, snapshot.Approval.Revision, "absent snapshot approval revision")

	_, err = os.Lstat(paths.AppConfigDir())
	require.ErrorIs(t, err, os.ErrNotExist, "OpenSnapshot created the configuration directory")

	_, guard, err := AcquireReader(paths)
	require.NoError(t, err)
	guard.Release()
	guard.Release()
	_, err = os.Lstat(paths.AppConfigDir())
	assert.ErrorIs(t, err, os.ErrNotExist, "AcquireReader created the configuration directory")
}

func TestUpdateSetsFirstUseRevisions(t *testing.T) {
	paths := testPaths(t)
	snapshot, err := Update(paths, Token{}, func(c Config) (Config, error) { return c, nil })
	require.NoError(t, err)
	assert.Equal(t, uint64(1), snapshot.Selection.Revision, "first use selection revision")
	assert.Equal(t, uint64(1), snapshot.Approval.Revision, "first use approval revision")
	loaded, err := Load(paths)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), loaded.SelectionRevision, "persisted selection revision")
	assert.Equal(t, uint64(1), loaded.ApprovalRevision, "persisted approval revision")
}

func TestUpdateBumpsOnlyAffectedRevisions(t *testing.T) {
	paths := testPaths(t)
	seedConfig(t, paths, Default())

	added, err := updateWithCurrentToken(t, paths, func(c Config) (Config, error) {
		c.Targets = append(c.Targets, filesTarget("extra", model.RootHome, "extra", model.SelectionDirectory))
		return c, nil
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), added.Selection.Revision, "selection revision after a files target")
	assert.Equal(t, uint64(1), added.Approval.Revision, "approval revision after a files target")

	unchanged, err := updateWithCurrentToken(t, paths, func(c Config) (Config, error) { return c, nil })
	require.NoError(t, err)
	assert.Equal(t, uint64(2), unchanged.Selection.Revision, "unchanged update bumped the selection revision")
	assert.Equal(t, uint64(1), unchanged.Approval.Revision, "unchanged update bumped the approval revision")

	approved, err := updateWithCurrentToken(t, paths, func(c Config) (Config, error) {
		c.Targets = append(c.Targets, Target{ID: "desktop", Source: model.SourceGNOME, GNOMEPolicy: &GNOMEPolicy{
			Approval:      GNOMEApprovalApproved,
			Categories:    []string{"appearance"},
			MatrixVersion: 1,
			KeyDigest:     digestTestKey,
		}})
		return c, nil
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), approved.Selection.Revision, "selection revision after an approval")
	assert.Equal(t, uint64(2), approved.Approval.Revision, "approval revision after an approval")
}

func TestUpdateRefusesStaleTokenAndKeepsBytes(t *testing.T) {
	paths := testPaths(t)
	seedConfig(t, paths, Default())
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	before, err := os.ReadFile(configPath)
	require.NoError(t, err)
	stale, err := OpenSnapshot(paths)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, []byte("# unrelated rewrite\n"+string(before)), 0o600))
	after, err := os.ReadFile(configPath)
	require.NoError(t, err)

	_, err = Update(paths, stale.Token, func(c Config) (Config, error) {
		c.Defaults.Mode = AutoApply
		return c, nil
	})
	require.ErrorIs(t, err, ErrConfigStale, "update accepted a stale token")
	got, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, after, got, "refused update rewrote the file")
}

func TestUpdateMutationErrorWritesNothing(t *testing.T) {
	paths := testPaths(t)
	seedConfig(t, paths, Default())
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	before, err := os.ReadFile(configPath)
	require.NoError(t, err)
	snapshot, err := OpenSnapshot(paths)
	require.NoError(t, err)
	refused := errors.New("synthetic mutation refusal")

	_, err = Update(paths, snapshot.Token, func(c Config) (Config, error) {
		c.Defaults.Mode = AutoApply
		return c, refused
	})
	require.ErrorIs(t, err, refused)
	got, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, before, got, "refused mutation rewrote the file")
}

func TestUpdateRefusesInvalidMutationResult(t *testing.T) {
	paths := testPaths(t)
	seedConfig(t, paths, Default())
	snapshot, err := OpenSnapshot(paths)
	require.NoError(t, err)

	_, err = Update(paths, snapshot.Token, func(c Config) (Config, error) {
		c.Targets = append(c.Targets, Target{ID: "desktop", Source: model.SourceGNOME})
		return c, nil
	})
	require.Error(t, err, "update accepted an invalid configuration")
	loaded, err := Load(paths)
	require.NoError(t, err)
	assert.Empty(t, loaded.Targets, "invalid update reached the file")
}

func TestUpdateRefusesRevisionExhaustion(t *testing.T) {
	paths := testPaths(t)
	writeRawConfig(
		t,
		paths,
		"config_version = 2\nselection_revision = 9223372036854775807\napproval_revision = 9223372036854775807\n",
	)
	snapshot, err := OpenSnapshot(paths)
	require.NoError(t, err)
	require.Equal(t, uint64(math.MaxInt64), snapshot.Selection.Revision, "seed selection revision")

	unchanged, err := Update(paths, snapshot.Token, func(c Config) (Config, error) { return c, nil })
	require.NoError(t, err, "unchanged update refused at the revision ceiling")
	assert.Equal(t, uint64(math.MaxInt64), unchanged.Selection.Revision, "unchanged update moved the revision ceiling")

	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	before, err := os.ReadFile(configPath)
	require.NoError(t, err)
	current, err := OpenSnapshot(paths)
	require.NoError(t, err)
	_, err = Update(paths, current.Token, func(c Config) (Config, error) {
		c.Defaults.Mode = AutoApply
		return c, nil
	})
	require.ErrorIs(t, err, ErrConfigRevisionExhausted, "changed update wrapped an exhausted revision")
	got, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, before, got, "exhausted update rewrote the file")

	_, err = Update(paths, current.Token, func(c Config) (Config, error) {
		c.Defaults.Mode = AutoApply
		c.SelectionRevision = 1
		c.ApprovalRevision = 1
		return c, nil
	})
	require.ErrorIs(t, err, ErrConfigRevisionExhausted, "a mutation could rewind an exhausted revision")
}

func TestUpdateRefusesRevisionAboveSupportedRange(t *testing.T) {
	above := Config{Version: Version, SelectionRevision: math.MaxInt64 + 1}
	err := above.Validate()
	require.Error(t, err, "validation accepted a revision outside the supported range")
	assert.Contains(t, err.Error(), "revision", "revision range error")

	paths := testPaths(t)
	writeRawConfig(t, paths, "config_version = 2\nselection_revision = 18446744073709551615\n")
	_, err = OpenSnapshot(paths)
	require.Error(t, err, "load accepted a revision outside the supported range")
}

func TestUpdateCreatesLockFileAndPrivateDirectoryOnFirstWriteOnly(t *testing.T) {
	paths := testPaths(t)
	_, err := os.Lstat(paths.AppConfigDir())
	require.ErrorIs(t, err, os.ErrNotExist, "fixture configuration directory exists")

	seedConfig(t, paths, Default())
	directory, err := os.Stat(paths.AppConfigDir())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), directory.Mode().Perm(), "configuration directory mode")

	lockInfo, err := os.Stat(filepath.Join(paths.AppConfigDir(), LockFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), lockInfo.Mode().Perm(), "configuration lock mode")

	snapshot, err := OpenSnapshot(paths)
	require.NoError(t, err)
	_, err = Update(paths, snapshot.Token, func(c Config) (Config, error) {
		c.Defaults.Mode = BackupOnly
		return c, nil
	})
	require.NoError(t, err)
	again, err := os.Stat(filepath.Join(paths.AppConfigDir(), LockFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), again.Mode().Perm(), "configuration lock mode after a later write")
}

func TestAcquireReaderHoldsSharedLockAgainstWriters(t *testing.T) {
	paths := testPaths(t)
	seedConfig(t, paths, Default())
	snapshot, guard, err := AcquireReader(paths)
	require.NoError(t, err)
	require.NotNil(t, guard)
	assert.NotEqual(t, Token{}, snapshot.Token, "reader snapshot token")

	require.ErrorIs(t, probeExclusiveLock(paths), syscall.EWOULDBLOCK, "a shared reader did not block a writer")

	guard.Release()
	require.NoError(t, probeExclusiveLock(paths), "the released reader still blocked a writer")

	second, secondGuard, err := AcquireReader(paths)
	require.NoError(t, err)
	assert.Equal(t, snapshot, second, "shared readers disagree")
	secondGuard.Release()
}

func probeExclusiveLock(paths platform.Paths) error {
	file, err := os.OpenFile(filepath.Join(paths.AppConfigDir(), LockFileName), os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	locked := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
	return locked
}

func updateWithCurrentToken(t *testing.T, paths platform.Paths, mutate func(Config) (Config, error)) (Snapshot, error) {
	t.Helper()
	snapshot, err := OpenSnapshot(paths)
	require.NoError(t, err)
	return Update(paths, snapshot.Token, mutate)
}

func TestUpdateReportsDurabilityUncertainAfterCommit(t *testing.T) {
	paths := testPaths(t)
	seedConfig(t, paths, Default())
	original := syncDir
	syncDir = func(string) error { return errors.New("injected directory sync") }
	t.Cleanup(func() { syncDir = original })
	snapshot, err := OpenSnapshot(paths)
	require.NoError(t, err)

	_, err = Update(paths, snapshot.Token, func(c Config) (Config, error) {
		c.Defaults.Mode = AutoApply
		return c, nil
	})
	require.Error(t, err, "Update succeeded with an injected directory sync failure")
	assert.Contains(t, err.Error(), "durability uncertain", "post-commit error")
	loaded, err := Load(paths)
	require.NoError(t, err)
	assert.Equal(t, AutoApply, loaded.Defaults.Mode, "committed value not visible")
}
