package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cliManifestFile struct {
	path    string
	mode    uint32
	content []byte
}

type cliManifestPublication struct {
	block publicationstate.SnapshotBlock
	head  []byte
	view  publicationstate.SuppliedRepositoryView
	floor publicationstate.Floor
}

func newCLIManifestPublication(t *testing.T, binding publicationstate.Binding) cliManifestPublication {
	t.Helper()
	files := []cliManifestFile{
		{path: "init.lua", mode: 0o600, content: []byte("synthetic manifest init")},
		{path: "lua/config/options.lua", mode: 0o644, content: []byte("synthetic manifest options")},
	}
	entries := make([]publication.SnapshotEntry, 0, len(files))
	for _, file := range files {
		blobCID, err := publication.RawPayloadCID(file.content)
		require.NoError(t, err)
		entries = append(entries, publication.SnapshotEntry{
			Path: file.path, Mode: file.mode, Size: uint64(len(file.content)),
			Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{
				CID: blobCID, Size: uint64(len(file.content)), MIMEType: publication.BlobMIMEType,
			},
		})
	}
	raw, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault,
		PublicationID: [16]byte{0x62, 0x31}, Entries: entries,
	})
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, SnapshotCID: recordCID,
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	view := publicationstate.SuppliedRepositoryView{
		Origin: binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{
			RepositoryRevision: "synthetic-manifest-revision", RepositoryDigest: []byte{0x71},
		},
		Head:      head,
		Snapshots: []publicationstate.SnapshotBlock{{Key: key, Raw: raw}},
	}
	floor := publicationstate.Floor{
		Revision: 1, Generation: 1, Binding: binding, RecordCID: recordCID, SnapshotKey: key,
	}
	return cliManifestPublication{block: view.Snapshots[0], head: head, view: view, floor: floor}
}

func pullTestManifestBinding() publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: pullTestDID, Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x62},
	}
	binding.Repository = "at://" + binding.AccountDID
	return binding
}

func manifestTestReader(manifest cliManifestPublication) *pullTestReader {
	return &pullTestReader{
		view: manifest.view,
		entries: map[string][]byte{
			string(mustCLIManifestCID(manifest.block.Raw, 0)): []byte("synthetic manifest init"),
			string(mustCLIManifestCID(manifest.block.Raw, 1)): []byte("synthetic manifest options"),
		},
	}
}

func mustCLIManifestCID(raw []byte, index int) []byte {
	record, err := publication.DecodeSnapshot(raw)
	if err != nil {
		panic(err)
	}
	return record.Entries[index].Blob.CID
}

func TestPullApplySnapshotsResolvesAManifestProviderPayload(t *testing.T) {
	binding := pullTestManifestBinding()
	manifest := newCLIManifestPublication(t, binding)
	reader := manifestTestReader(manifest)

	material, err := pullApplySnapshots(context.Background(), pullRemote{
		Reader: reader, Entry: reader.ReadEntry,
	}, manifest.view, manifest.floor, false)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, material.Form)
	require.Len(t, material.Entries, 2)
	assert.Equal(t, "init.lua", material.Entries[0].Path)
	assert.Equal(t, []byte("synthetic manifest init"), material.Entries[0].Content)
	assert.Empty(t, material.Payload)
}

func TestPullPositionComparisonAcceptsAManifestFloor(t *testing.T) {
	binding := pullTestManifestBinding()
	manifest := newCLIManifestPublication(t, binding)
	floor := manifest.floor
	record, err := publication.DecodeSnapshot(manifest.block.Raw)
	require.NoError(t, err)
	floor.Manifest = &publicationstate.ManifestPayload{}
	for _, entry := range record.Entries {
		floor.Manifest.Entries = append(floor.Manifest.Entries, publicationstate.PayloadEntryReference{
			Path: entry.Path, CID: entry.Blob.CID, Size: entry.Size,
		})
	}
	assert.Equal(t, pullFinding{Kind: pullFindingMatches}, comparePullPosition(floor, manifest.view))
	require.NoError(t, syncViewMatchesFloor(floor, manifest.view))
}

func TestPullAppliesANestedManifestOntoAFreshTarget(t *testing.T) {
	pullManifestUmask(t)
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	manifest := newCLIManifestPublication(t, fixture.binding)
	reader := manifestTestReader(manifest)
	record, err := publication.DecodeSnapshot(manifest.block.Raw)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormManifest, record.PayloadForm())
	require.Len(t, record.Entries, 2)
	require.Len(t, reader.entries, len(record.Entries), "the reader fixture did not supply every manifest entry")
	for _, entry := range record.Entries {
		require.Contains(t, reader.entries, string(entry.Blob.CID), entry.Path)
	}

	code, stdout, stderr := runPullManifestStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(t, stdout, "apply: changes=4 unchanged=0\n")
	assert.Contains(t, stdout, "apply: mkdir lua\n")
	assert.Contains(t, stdout, "apply: mkdir lua/config\n")
	assert.Contains(
		t,
		stdout,
		fmt.Sprintf("apply: write init.lua size=%d\n", len("synthetic manifest init")),
	)
	assert.Contains(
		t,
		stdout,
		fmt.Sprintf("apply: write lua/config/options.lua size=%d\n", len("synthetic manifest options")),
	)
	assert.Contains(t, stdout, "pull: plan only; nothing was applied; repeat with --confirm ")
	assert.NotContains(t, stdout, "pull: applied")
	token := pullTestConfirmation(t, stdout)
	require.NoDirExists(t, fixture.targetPath("lua"))
	require.NoFileExists(t, fixture.targetPath("init.lua"))
	assert.False(t, pullManifestFloorPresent(t, fixture), "the unconfirmed plan accepted a floor")

	fixture.configureRoot(t, "", "config-moved")
	code, stdout, stderr = runPullManifestStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr, "stale or bound to a different vault")
	assert.NotContains(t, stdout, "pull: applied")
	require.NoDirExists(t, filepath.Join(fixture.paths.Home, "config-moved", "lua"))
	require.NoFileExists(t, fixture.targetPath("init.lua"))
	assert.False(t, pullManifestFloorPresent(t, fixture), "a stale target root accepted a floor")
	fixture.configureRoot(t, "", "config")

	pullManifestConfigureRevision(t, fixture, 2)
	code, stdout, stderr = runPullManifestStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr, "stale or bound to a different vault")
	assert.NotContains(t, stdout, "pull: applied")
	require.NoDirExists(t, fixture.targetPath("lua"))
	require.NoFileExists(t, fixture.targetPath("init.lua"))
	assert.False(t, pullManifestFloorPresent(t, fixture), "a changed configuration revision accepted a floor")
	fixture.configureRoot(t, "", "config")

	code, stdout, stderr = runPullManifestStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 0, code, stderr)
	assert.Contains(
		t,
		stdout,
		fmt.Sprintf(
			"pull: applied changes=4 unchanged=0 bytes=%d\n",
			len("synthetic manifest init")+len("synthetic manifest options"),
		),
	)
	assert.Contains(t, stdout, "floor: revision=1 generation=1 sequence=0\n")

	for path, want := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"init.lua":               {content: "synthetic manifest init", mode: 0o600},
		"lua/config/options.lua": {content: "synthetic manifest options", mode: 0o644},
	} {
		content, err := os.ReadFile(fixture.targetPath(path))
		require.NoError(t, err)
		assert.Equal(t, want.content, string(content), path)
		info, err := os.Lstat(fixture.targetPath(path))
		require.NoError(t, err)
		assert.Equal(t, want.mode, info.Mode().Perm(), path)
	}
	for _, path := range []string{"lua", "lua/config"} {
		info, err := os.Lstat(fixture.targetPath(path))
		require.NoError(t, err)
		assert.True(t, info.IsDir(), path)
		assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), path)
	}
	assert.Equal(t, int64(2), pullManifestJournalRows(t, fixture), "a synthesized directory was journaled")
	accepted := fixture.acceptedFloor(t)
	require.NotNil(t, accepted.Manifest, "the accepted floor did not record the manifest payload")
	assert.Empty(t, accepted.BlobCID)
	assert.Zero(t, accepted.BlobSize)
	require.Len(t, accepted.Manifest.Entries, len(record.Entries))
	for index, entry := range record.Entries {
		assert.Equal(t, entry.Path, accepted.Manifest.Entries[index].Path)
		assert.Equal(t, entry.Size, accepted.Manifest.Entries[index].Size)
		assert.Equal(t, entry.Blob.CID, accepted.Manifest.Entries[index].CID)
	}
	store := fixture.openStore(t)
	material, err := store.ReadAcceptedMaterial(context.Background(), fixture.binding, accepted)
	require.NoError(t, err)
	require.Len(t, material.Entries, len(record.Entries))
	for index, entry := range material.Entries {
		assert.Equal(t, record.Entries[index].Path, entry.Path)
		assert.Equal(t, record.Entries[index].Mode, entry.Mode)
		assert.Equal(t, reader.entries[string(record.Entries[index].Blob.CID)], entry.Content)
	}
	assert.Empty(t, material.Payload, "a manifest floor retained a packed payload")
	require.NoError(t, store.Close())

	before := pullTestDirectoryState(t, fixture.paths.Home)
	code, stdout, stderr = runPullManifestStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "pull: matches\n", stdout)
	assert.Equal(t, before, pullTestDirectoryState(t, fixture.paths.Home), "a matching re-pull wrote a local file")
	assert.Equal(t, int64(2), pullManifestJournalRows(t, fixture), "a matching re-pull journaled an apply")
	assert.Equal(t, uint64(1), fixture.acceptedFloor(t).Revision)
}

func runPullManifestStep(
	t *testing.T,
	fixture *pullTestFixture,
	reader *pullTestReader,
	args ...string,
) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, args...)
	return code, stdout.String(), stderr.String()
}

func pullManifestFloorPresent(t *testing.T, fixture *pullTestFixture) bool {
	t.Helper()
	inspection, err := publicationstate.Inspect(
		context.Background(),
		fixture.paths.PublicationStateDir(),
		fixture.binding,
	)
	require.NoError(t, err)
	return inspection.Present
}

func pullManifestConfigureRevision(t *testing.T, fixture *pullTestFixture, revision uint64) {
	t.Helper()
	path := filepath.Join(fixture.paths.AppConfigDir(), config.FileName)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	header := fmt.Sprintf("selection_revision = %d\napproval_revision = %d\n", revision, revision)
	require.NoError(t, os.WriteFile(path, append([]byte(header), content...), 0o600))
}

func pullManifestJournalRows(t *testing.T, fixture *pullTestFixture) int64 {
	t.Helper()
	journal, err := publicationstate.OpenJournal(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, journal.Close()) }()
	count, err := journal.EntryCount(context.Background())
	require.NoError(t, err)
	return count
}

func pullManifestUmask(t *testing.T) {
	t.Helper()
	previous := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(previous) })
}

func TestSyncAcceptedSnapshotProjectsAManifestWithTheSoleTarget(t *testing.T) {
	binding := pullTestManifestBinding()
	manifest := newCLIManifestPublication(t, binding)
	record, err := publication.DecodeSnapshot(manifest.block.Raw)
	require.NoError(t, err)
	accepted := publicationstate.AcceptedMaterial{
		Floor: manifest.floor, SnapshotRecord: manifest.block.Raw,
	}
	for _, entry := range record.Entries {
		accepted.Entries = append(accepted.Entries, publicationstate.AcceptedMaterialEntry{
			Path: entry.Path, Mode: entry.Mode, Content: []byte("synthetic manifest " + entry.Path),
		})
	}
	configuration := config.Config{Version: config.Version, Targets: []config.Target{{
		ID: "files", Source: model.SourceFiles,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}}}
	snapshot, err := syncAcceptedSnapshot(accepted, configuration)
	require.NoError(t, err)
	require.Len(t, snapshot.Entries, 4)
	byPath := map[string]model.FileEntry{}
	for _, entry := range snapshot.Entries {
		byPath[entry.File.Path] = *entry.File
	}
	assert.Equal(t, model.FileDirectory, byPath["lua"].Kind)
	assert.Equal(t, model.FileDirectory, byPath["lua/config"].Kind)
	assert.Equal(t, []byte("synthetic manifest lua/config/options.lua"), byPath["lua/config/options.lua"].Content)
}

func TestPullRefusesAManifestWithoutASoleDirectoryTarget(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "other"), 0o700))
	configPath := filepath.Join(fixture.paths.AppConfigDir(), config.FileName)
	file, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = file.WriteString("\n[[targets]]\nid = \"other\"\nsource = \"files\"\n\n[targets.root]\nbase = \"home\"\npath = \"other\"\nkind = \"directory\"\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	manifest := newCLIManifestPublication(t, fixture.binding)
	reader := manifestTestReader(manifest)
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)

	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code, stderr.String())
	assert.Contains(t, stderr.String(), "manifest publication requires the sole local directory files target")
	assert.NotContains(t, stdout.String(), "confirmation:")

	_, err = os.Stat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
