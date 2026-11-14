package publicationstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func inspectionDirectoryEntries(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		require.NoError(t, err)
		names = append(names, fmt.Sprintf("%s=%d", entry.Name(), info.Size()))
	}
	return names
}

func inspectionFileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return sha256.Sum256(data)
}

func newInspectionStore(t *testing.T, backend Backend) (fixture, string, Floor) {
	t.Helper()
	f := newFixture(t, backend)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.Accept(context.Background(), ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	return f, directory, floor
}

func TestInspectDirectoryGuardsPrecedeStoreDecision(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	private := filepath.Join(t.TempDir(), "private")
	require.NoError(t, os.Mkdir(private, 0o700))
	openDirectory := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.Mkdir(openDirectory, 0o755))
	linkParent := t.TempDir()
	require.NoError(t, os.Symlink(private, filepath.Join(linkParent, "link")))
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name      string
		directory string
		class     error
		reason    Reason
	}{
		{name: "missing directory", directory: missing, class: ErrSchema, reason: ReasonPositionAbsent},
		{name: "non-private directory", directory: openDirectory, class: ErrStorage, reason: ReasonIO},
		{name: "symlinked directory", directory: filepath.Join(linkParent, "link"), class: ErrStorage, reason: ReasonIO},
		{name: "relative directory", directory: "relative/publication", class: ErrInvalid, reason: ReasonBinding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspection, err := Inspect(context.Background(), test.directory, f.binding)
			requireErrorMetadata(t, err, test.class, StageInspect, test.reason)
			assert.Equal(t, Inspection{}, inspection)
		})
	}
	assert.Empty(t, inspectionDirectoryEntries(t, private), "guard must not create a store in a private directory")
	assert.Empty(t, inspectionDirectoryEntries(t, openDirectory), "guard must not create a store in a non-private directory")
	_, err := os.Lstat(missing)
	assert.ErrorIs(t, err, os.ErrNotExist, "guard must not create the missing directory")
}

func TestInspectRefusesAbsentStoreWithoutCreatingIt(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	inspection, err := Inspect(context.Background(), directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonPositionAbsent)
	assert.Equal(t, Inspection{}, inspection)
	assert.Empty(t, inspectionDirectoryEntries(t, directory), "inspection created store files")
}

func TestInspectRefusesMissingDirectoryAsAbsentWithoutCreatingIt(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	parent := t.TempDir()
	directory := filepath.Join(parent, "publication-state")
	inspection, err := Inspect(context.Background(), directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonPositionAbsent)
	assert.Equal(t, Inspection{}, inspection)
	_, statErr := os.Lstat(directory)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "inspection created the store directory")
}

func TestInspectRefusesZeroByteDatabaseWithoutCreatingStore(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	databasePath := filepath.Join(directory, "publication.db")
	require.NoError(t, os.WriteFile(databasePath, nil, 0o600))
	inspection, err := Inspect(context.Background(), directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonPositionAbsent)
	assert.Equal(t, Inspection{}, inspection)
	info, err := os.Stat(databasePath)
	require.NoError(t, err)
	assert.Zero(t, info.Size(), "inspection wrote to the zero-byte database")
	assert.Equal(t, []string{"publication.db=0"}, inspectionDirectoryEntries(t, directory), "inspection created sidecars")
}

func TestInspectRefusesUncheckpointedWAL(t *testing.T) {
	f, directory, floor := newInspectionStore(t, BackendPublicRepo)
	databasePath := filepath.Join(directory, "publication.db")
	walPath := databasePath + "-wal"
	require.NoError(t, os.WriteFile(walPath, []byte("uncheckpointed frames canary"), 0o600))
	before := inspectionDirectoryEntries(t, directory)
	databaseDigest := inspectionFileDigest(t, databasePath)
	walDigest := inspectionFileDigest(t, walPath)
	inspection, err := Inspect(context.Background(), directory, f.binding)
	requireErrorMetadata(t, err, ErrStorage, StageInspect, ReasonIO)
	assert.Equal(t, Inspection{}, inspection)
	assert.NotEqual(t, Floor{}, floor)
	assert.Equal(t, before, inspectionDirectoryEntries(t, directory), "inspection changed the directory")
	assert.Equal(t, databaseDigest, inspectionFileDigest(t, databasePath), "inspection changed the database")
	assert.Equal(t, walDigest, inspectionFileDigest(t, walPath), "inspection changed the uncheckpointed WAL")
}

func TestInspectAcceptsEmptyWAL(t *testing.T) {
	f, directory, floor := newInspectionStore(t, BackendPublicRepo)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "publication.db-wal"), nil, 0o600))
	inspection, err := Inspect(context.Background(), directory, f.binding)
	require.NoError(t, err)
	assert.True(t, inspection.Present)
	assert.Equal(t, floor, inspection.Floor)
	info, err := os.Stat(filepath.Join(directory, "publication.db-wal"))
	require.NoError(t, err)
	assert.Zero(t, info.Size(), "inspection wrote to the empty WAL")
}

func TestInspectReportsAbsentFloorOnRecognizedStore(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	require.NoError(t, store.Close())
	before := inspectionDirectoryEntries(t, directory)
	inspection, err := Inspect(context.Background(), directory, f.binding)
	require.NoError(t, err)
	assert.False(t, inspection.Present)
	assert.Equal(t, zeroFloor(), inspection.Floor)
	assert.Equal(t, before, inspectionDirectoryEntries(t, directory), "inspection changed the directory")
}

func TestInspectReportsAcceptedFloorWithoutMutatingDirectory(t *testing.T) {
	f, directory, floor := newInspectionStore(t, BackendPublicRepo)
	databasePath := filepath.Join(directory, "publication.db")
	before := inspectionDirectoryEntries(t, directory)
	databaseDigest := inspectionFileDigest(t, databasePath)
	var databaseInfo os.FileInfo
	databaseInfo, err := os.Stat(databasePath)
	require.NoError(t, err)

	inspection, err := Inspect(context.Background(), directory, f.binding)
	require.NoError(t, err)
	assert.True(t, inspection.Present)
	assert.Equal(t, floor, inspection.Floor)

	assert.Equal(t, before, inspectionDirectoryEntries(t, directory), "inspection changed file names or sizes")
	assert.Equal(t, databaseDigest, inspectionFileDigest(t, databasePath), "inspection changed the database bytes")
	afterInfo, err := os.Stat(databasePath)
	require.NoError(t, err)
	assert.Equal(t, databaseInfo.ModTime(), afterInfo.ModTime(), "inspection changed the database modification time")
	assert.Equal(t, databaseInfo.Mode(), afterInfo.Mode(), "inspection changed the database mode")
}

func TestInspectRefusesForeignBinding(t *testing.T) {
	f, directory, floor := newInspectionStore(t, BackendPublicRepo)
	require.NotEqual(t, [32]byte{}, f.binding.Vault)
	foreign := f.binding
	foreign.Vault[0] ^= 0xff
	inspection, err := Inspect(context.Background(), directory, foreign)
	requireErrorMetadata(t, err, ErrInvalid, StageInspect, ReasonBinding)
	assert.Equal(t, Inspection{}, inspection)
	assert.Equal(t, 1, int(floor.Revision))

	inspection, err = Inspect(context.Background(), directory, Binding{})
	requireErrorMetadata(t, err, ErrInvalid, StageInspect, ReasonBinding)
	assert.Equal(t, Inspection{}, inspection)
}

func TestInspectProbeDoesNotExcludeOtherInspectors(t *testing.T) {
	f, directory, floor := newInspectionStore(t, BackendPublicRepo)
	inspection, err := Inspect(context.Background(), directory, f.binding)
	require.NoError(t, err)
	require.True(t, inspection.Present)
	assert.Equal(t, floor, inspection.Floor)

	results := make(chan error, 8)
	for index := 0; index < 8; index++ {
		go func() {
			_, inspectErr := Inspect(context.Background(), directory, f.binding)
			results <- inspectErr
		}()
	}
	for index := 0; index < 8; index++ {
		assert.NoError(t, <-results, "concurrent inspections must not observe each other as a lock holder")
	}
}

func TestInspectRefusesUnsafeDatabaseFile(t *testing.T) {
	f, directory, _ := newInspectionStore(t, BackendPublicRepo)
	databasePath := filepath.Join(directory, "publication.db")
	require.NoError(t, os.Chmod(databasePath, 0o644))
	inspection, err := Inspect(context.Background(), directory, f.binding)
	requireErrorMetadata(t, err, ErrStorage, StageInspect, ReasonIO)
	assert.Equal(t, Inspection{}, inspection)
}

func TestInspectRefusesUpgradeRequiredSchemas(t *testing.T) {
	t.Run("schema 1", func(t *testing.T) {
		f, databasePath, rows := incomingMaterialUpgradeCopyV1(t)
		require.NotEmpty(t, rows)
		directory := filepath.Dir(databasePath)
		before := inspectionDirectoryEntries(t, directory)
		digest := inspectionFileDigest(t, databasePath)
		inspection, err := Inspect(context.Background(), directory, f.binding)
		requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonUpgradeRequired)
		assert.Equal(t, Inspection{}, inspection)
		assert.Equal(t, before, inspectionDirectoryEntries(t, directory), "inspection changed the directory")
		assert.Equal(t, digest, inspectionFileDigest(t, databasePath), "inspection upgraded the schema-1 database")
	})
	t.Run("schema 2", func(t *testing.T) {
		assets := incomingMaterialUpgradeFixtureCopy(t)
		image := assets.manifest.requireImage(t, "mixed")
		binding, _, _ := incomingMaterialUpgradeFixtureBindingOptions(t, image)
		directory := filepath.Join(assets.root, "mixed")
		databasePath := filepath.Join(directory, "publication.db")
		before := inspectionDirectoryEntries(t, directory)
		digest := inspectionFileDigest(t, databasePath)
		inspection, err := Inspect(context.Background(), directory, binding)
		requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonUpgradeRequired)
		assert.Equal(t, Inspection{}, inspection)
		assert.Equal(t, before, inspectionDirectoryEntries(t, directory), "inspection changed the directory")
		assert.Equal(t, digest, inspectionFileDigest(t, databasePath), "inspection upgraded the schema-2 database")
	})
}

func TestInspectRefusesHeldWriterAndReleasesProbe(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	inspection, err := Inspect(context.Background(), directory, f.binding)
	requireErrorMetadata(t, err, ErrLocked, StageInspect, ReasonLocked)
	assert.Equal(t, Inspection{}, inspection)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err, "inspection kept the store lock")
	require.NoError(t, reopened.Close())
}

func TestInspectRefusesForeignSchema(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	databasePath := filepath.Join(directory, "publication.db")
	foreign, err := sql.Open("sqlite", dbDSN(databasePath, false))
	require.NoError(t, err)
	_, err = foreign.Exec("CREATE TABLE foreign_state(value TEXT NOT NULL)")
	require.NoError(t, err)
	var mode string
	require.NoError(t, foreign.QueryRow("PRAGMA journal_mode=DELETE").Scan(&mode))
	require.NoError(t, foreign.Close())
	require.NoError(t, os.Chmod(databasePath, 0o600))
	before := inspectionDirectoryEntries(t, directory)
	digest := inspectionFileDigest(t, databasePath)
	inspection, err := Inspect(context.Background(), directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonSchema)
	assert.Equal(t, Inspection{}, inspection)
	assert.Equal(t, before, inspectionDirectoryEntries(t, directory), "inspection changed the directory")
	assert.Equal(t, digest, inspectionFileDigest(t, databasePath), "inspection changed the foreign database")
}
