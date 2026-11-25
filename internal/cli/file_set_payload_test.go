package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cliFileSetFile struct {
	path    string
	mode    uint32
	content []byte
}

type cliFileSetPublication struct {
	block publicationstate.SnapshotBlock
	head  []byte
	view  publicationstate.SuppliedRepositoryView
	floor publicationstate.Floor
}

func newCLIFileSetPublication(t *testing.T, binding publicationstate.Binding) cliFileSetPublication {
	t.Helper()
	files := []cliFileSetFile{
		{path: "init.lua", mode: 0o600, content: []byte("synthetic file-set init")},
		{path: "lua/config/options.lua", mode: 0o644, content: []byte("synthetic file-set options")},
	}
	block, head := cliFileSetBlock(t, binding, 0, nil, files)
	view := publicationstate.SuppliedRepositoryView{
		Origin: binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{
			RepositoryRevision: "synthetic-file-set-revision", RepositoryDigest: []byte{0x71},
		},
		Head:      head,
		Snapshots: []publicationstate.SnapshotBlock{block},
	}
	recordCID, err := publication.RecordCID(block.Raw)
	require.NoError(t, err)
	floor := publicationstate.Floor{
		Revision: 1, Generation: 1, Binding: binding, RecordCID: recordCID, SnapshotKey: block.Key,
	}
	return cliFileSetPublication{block: block, head: head, view: view, floor: floor}
}

func cliFileSetBlock(
	t *testing.T,
	binding publicationstate.Binding,
	sequence uint64,
	parent []byte,
	files []cliFileSetFile,
) (publicationstate.SnapshotBlock, []byte) {
	t.Helper()
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
		PublicationID: [16]byte{0x62, 0x31}, PublicationSeq: sequence, Parent: parent, Entries: entries,
		Targets: cliFileSetTargets(),
	})
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault,
		PublicationSeq: sequence, SnapshotCID: recordCID,
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return publicationstate.SnapshotBlock{Key: key, Raw: raw}, head
}

func cliFileSetTargets() []model.Target {
	return []model.Target{{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}}
}

func pullTestFileSetBinding() publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: pullTestDID, Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x62},
	}
	binding.Repository = "at://" + binding.AccountDID
	return binding
}

func fileSetTestReader(fileSet cliFileSetPublication) *pullTestReader {
	return &pullTestReader{
		view: fileSet.view,
		entries: map[string][]byte{
			string(mustCLIFileSetCID(fileSet.block.Raw, 0)): []byte("synthetic file-set init"),
			string(mustCLIFileSetCID(fileSet.block.Raw, 1)): []byte("synthetic file-set options"),
		},
	}
}

func mustCLIFileSetCID(raw []byte, index int) []byte {
	record, err := publication.DecodeSnapshot(raw)
	if err != nil {
		panic(err)
	}
	return record.Entries[index].Blob.CID
}

func TestPullApplySnapshotsResolvesAFileSetProviderPayload(t *testing.T) {
	binding := pullTestFileSetBinding()
	fileSet := newCLIFileSetPublication(t, binding)
	reader := fileSetTestReader(fileSet)

	material, err := pullApplySnapshots(context.Background(), pullRemote{
		Reader: reader, Entry: reader.ReadEntry,
	}, fileSet.view, fileSet.floor, false)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, material.Form)
	require.Len(t, material.Entries, 2)
	assert.Equal(t, "init.lua", material.Entries[0].Path)
	assert.Equal(t, []byte("synthetic file-set init"), material.Entries[0].Content)
	assert.Empty(t, material.Payload)
}

func TestPullPositionComparisonAcceptsAFileSetFloor(t *testing.T) {
	binding := pullTestFileSetBinding()
	fileSet := newCLIFileSetPublication(t, binding)
	floor := fileSet.floor
	record, err := publication.DecodeSnapshot(fileSet.block.Raw)
	require.NoError(t, err)
	floor.FileSet = &publicationstate.FileSetPayload{}
	for _, entry := range record.Entries {
		floor.FileSet.Entries = append(floor.FileSet.Entries, publicationstate.PayloadEntryReference{
			Path: entry.Path, CID: entry.Blob.CID, Size: entry.Size,
		})
	}
	assert.Equal(t, pullFinding{Kind: pullFindingMatches}, comparePullPosition(floor, fileSet.view))
	require.NoError(t, syncViewMatchesFloor(floor, fileSet.view))
}

func TestPullAppliesANestedFileSetOntoAFreshTarget(t *testing.T) {
	pullFileSetUmask(t)
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	fileSet := newCLIFileSetPublication(t, fixture.binding)
	reader := fileSetTestReader(fileSet)
	record, err := publication.DecodeSnapshot(fileSet.block.Raw)
	require.NoError(t, err)
	assert.Equal(t, publication.PayloadFormFileSet, record.PayloadForm())
	require.Len(t, record.Entries, 2)
	require.Len(t, reader.entries, len(record.Entries), "the reader fixture did not supply every file-set entry")
	for _, entry := range record.Entries {
		require.Contains(t, reader.entries, string(entry.Blob.CID), entry.Path)
	}

	code, stdout, stderr := runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(t, stdout, "apply: changes=4 unchanged=0\n")
	assert.Contains(t, stdout, "apply: mkdir lua\n")
	assert.Contains(t, stdout, "apply: mkdir lua/config\n")
	assert.Contains(
		t,
		stdout,
		fmt.Sprintf("apply: write init.lua size=%d\n", len("synthetic file-set init")),
	)
	assert.Contains(
		t,
		stdout,
		fmt.Sprintf("apply: write lua/config/options.lua size=%d\n", len("synthetic file-set options")),
	)
	assert.Contains(t, stdout, "pull: plan only; nothing was applied; repeat with --confirm ")
	assert.NotContains(t, stdout, "pull: applied")
	token := pullTestConfirmation(t, stdout)
	require.NoDirExists(t, fixture.targetPath("lua"))
	require.NoFileExists(t, fixture.targetPath("init.lua"))
	assert.False(t, pullFileSetFloorPresent(t, fixture), "the unconfirmed plan accepted a floor")

	fixture.configureRoot(t, "", "config-moved")
	code, stdout, stderr = runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr, "stale or bound to a different vault")
	assert.NotContains(t, stdout, "pull: applied")
	require.NoDirExists(t, filepath.Join(fixture.paths.Home, "config-moved", "lua"))
	require.NoFileExists(t, fixture.targetPath("init.lua"))
	assert.False(t, pullFileSetFloorPresent(t, fixture), "a stale target root accepted a floor")
	fixture.configureRoot(t, "", "config")

	pullFileSetConfigureRevision(t, fixture, 2)
	code, stdout, stderr = runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr, "stale or bound to a different vault")
	assert.NotContains(t, stdout, "pull: applied")
	require.NoDirExists(t, fixture.targetPath("lua"))
	require.NoFileExists(t, fixture.targetPath("init.lua"))
	assert.False(t, pullFileSetFloorPresent(t, fixture), "a changed configuration revision accepted a floor")
	fixture.configureRoot(t, "", "config")

	code, stdout, stderr = runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 0, code, stderr)
	assert.Contains(
		t,
		stdout,
		fmt.Sprintf(
			"pull: applied changes=4 unchanged=0 bytes=%d\n",
			len("synthetic file-set init")+len("synthetic file-set options"),
		),
	)
	assert.Contains(t, stdout, "floor: revision=1 generation=1 sequence=0\n")

	for path, want := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"init.lua":               {content: "synthetic file-set init", mode: 0o600},
		"lua/config/options.lua": {content: "synthetic file-set options", mode: 0o644},
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
	assert.Equal(t, int64(2), pullFileSetJournalRows(t, fixture), "a synthesized directory was journaled")
	accepted := fixture.acceptedFloor(t)
	require.NotNil(t, accepted.FileSet, "the accepted floor did not record the file-set payload")
	assert.Empty(t, accepted.BlobCID)
	assert.Zero(t, accepted.BlobSize)
	require.Len(t, accepted.FileSet.Entries, len(record.Entries))
	for index, entry := range record.Entries {
		assert.Equal(t, entry.Path, accepted.FileSet.Entries[index].Path)
		assert.Equal(t, entry.Size, accepted.FileSet.Entries[index].Size)
		assert.Equal(t, entry.Blob.CID, accepted.FileSet.Entries[index].CID)
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
	assert.Empty(t, material.Payload, "a file-set floor retained a packed payload")
	require.NoError(t, store.Close())

	before := pullTestDirectoryState(t, fixture.paths.Home)
	code, stdout, stderr = runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "pull: matches\n", stdout)
	assert.Equal(t, before, pullTestDirectoryState(t, fixture.paths.Home), "a matching re-pull wrote a local file")
	assert.Equal(t, int64(2), pullFileSetJournalRows(t, fixture), "a matching re-pull journaled an apply")
	assert.Equal(t, uint64(1), fixture.acceptedFloor(t).Revision)
}

func runPullFileSetStep(
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

func pullFileSetFloorPresent(t *testing.T, fixture *pullTestFixture) bool {
	t.Helper()
	inspection, err := publicationstate.Inspect(
		context.Background(),
		fixture.paths.PublicationStateDir(),
		fixture.binding,
	)
	require.NoError(t, err)
	return inspection.Present
}

func pullFileSetConfigureRevision(t *testing.T, fixture *pullTestFixture, revision uint64) {
	t.Helper()
	path := filepath.Join(fixture.paths.AppConfigDir(), config.FileName)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	header := fmt.Sprintf("selection_revision = %d\napproval_revision = %d\n", revision, revision)
	require.NoError(t, os.WriteFile(path, append([]byte(header), content...), 0o600))
}

func pullFileSetJournalRows(t *testing.T, fixture *pullTestFixture) int64 {
	t.Helper()
	journal, err := publicationstate.OpenJournal(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, journal.Close()) }()
	count, err := journal.EntryCount(context.Background())
	require.NoError(t, err)
	return count
}

func pullFileSetUmask(t *testing.T) {
	t.Helper()
	previous := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(previous) })
}

func TestSyncAcceptedSnapshotProjectsAFileSetWithTheSoleTarget(t *testing.T) {
	binding := pullTestFileSetBinding()
	fileSet := newCLIFileSetPublication(t, binding)
	record, err := publication.DecodeSnapshot(fileSet.block.Raw)
	require.NoError(t, err)
	accepted := publicationstate.AcceptedMaterial{
		Floor: fileSet.floor, SnapshotRecord: fileSet.block.Raw,
	}
	for _, entry := range record.Entries {
		accepted.Entries = append(accepted.Entries, publicationstate.AcceptedMaterialEntry{
			Path: entry.Path, Mode: entry.Mode, Content: []byte("synthetic file-set " + entry.Path),
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
	assert.Equal(t, []byte("synthetic file-set lua/config/options.lua"), byPath["lua/config/options.lua"].Content)
}

func TestPullRefusesAFileSetWithoutASoleFilesTarget(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "other"), 0o700))
	configPath := filepath.Join(fixture.paths.AppConfigDir(), config.FileName)
	file, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = file.WriteString("\n[[targets]]\nid = \"other\"\nsource = \"files\"\n\n[targets.root]\nbase = \"home\"\npath = \"other\"\nkind = \"directory\"\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	fileSet := newCLIFileSetPublication(t, fixture.binding)
	reader := fileSetTestReader(fileSet)
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)

	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code, stderr.String())
	assert.Contains(t, stderr.String(), "file-set publication requires the sole local files target")
	assert.NotContains(t, stdout.String(), "confirmation:")

	_, err = os.Stat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestPullAppliesASoleSingleFileFileSetOntoAFileTarget(t *testing.T) {
	pullFileSetUmask(t)
	fixture := newPullTestFixture(t)
	configurePullSingleFileTarget(t, fixture, "config/init.lua")
	accepted := []byte("synthetic single file v1")
	published := []byte("synthetic single file v2")
	require.NoError(t, os.WriteFile(fixture.targetPath("init.lua"), accepted, 0o600))

	firstBlock, firstHead := cliFileSetBlock(t, fixture.binding, 0, nil, []cliFileSetFile{
		{path: "init.lua", mode: 0o600, content: accepted},
	})
	firstCID, err := publication.RecordCID(firstBlock.Raw)
	require.NoError(t, err)
	secondBlock, secondHead := cliFileSetBlock(t, fixture.binding, 1, firstCID, []cliFileSetFile{
		{path: "published-elsewhere.lua", mode: 0o644, content: published},
	})
	context := publicationstate.SuppliedContext{
		RepositoryRevision: "synthetic-single-file-revision", RepositoryDigest: []byte{0x72},
	}
	entries := map[string][]byte{}
	for _, content := range [][]byte{accepted, published} {
		cid, err := publication.RawPayloadCID(content)
		require.NoError(t, err)
		entries[string(cid)] = content
	}
	acceptedView := publicationstate.SuppliedRepositoryView{
		Origin: fixture.binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: context, Head: firstHead,
		Snapshots: []publicationstate.SnapshotBlock{firstBlock},
	}
	movedView := publicationstate.SuppliedRepositoryView{
		Origin: fixture.binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: context, Head: secondHead,
		Snapshots: []publicationstate.SnapshotBlock{firstBlock, secondBlock},
	}
	firstReader := &pullTestReader{view: acceptedView, entries: entries}
	movedReader := &pullTestReader{view: movedView, entries: entries}

	code, stdout, stderr := runPullFileSetStep(t, fixture, firstReader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(
		t,
		stdout,
		"pull: reconciled changes=0 unchanged=1; the published position sequence=0 can be adopted without writing files",
	)
	assert.NotContains(t, stdout, "apply: write")
	token := pullTestConfirmation(t, stdout)
	code, stdout, stderr = runPullFileSetStep(
		t,
		fixture,
		firstReader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--confirm", token,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "floor: revision=1 generation=1 sequence=0\n")
	require.Equal(t, accepted, readPullSingleFile(t, fixture))

	code, stdout, stderr = runPullFileSetStep(t, fixture, movedReader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "apply: changes=1 unchanged=0\n")
	assert.Contains(t, stdout, fmt.Sprintf("apply: write . size=%d\n", len(published)))
	assert.NotContains(t, stdout, "apply: mkdir")
	token = pullTestConfirmation(t, stdout)
	code, stdout, stderr = runPullFileSetStep(
		t,
		fixture,
		movedReader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--confirm", token,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, fmt.Sprintf("pull: applied changes=1 unchanged=0 bytes=%d\n", len(published)))
	require.Equal(t, published, readPullSingleFile(t, fixture))
	info, err := os.Lstat(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	before := pullTestDirectoryState(t, fixture.paths.Home)
	code, stdout, stderr = runPullFileSetStep(t, fixture, movedReader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "pull: matches\n", stdout)
	assert.Equal(t, before, pullTestDirectoryState(t, fixture.paths.Home), "a matching re-pull wrote a local file")
	assert.Equal(t, uint64(2), fixture.acceptedFloor(t).Revision)
}

func configurePullSingleFileTarget(t *testing.T, fixture *pullTestFixture, path string) {
	t.Helper()
	directory := fixture.paths.AppConfigDir()
	require.NoError(t, os.MkdirAll(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o700))
	content := "config_version = 2\n\n[[targets]]\nid = \"files\"\nsource = \"files\"\n" +
		"\n[targets.root]\nbase = \"home\"\npath = \"" + path + "\"\nkind = \"file\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(directory, config.FileName), []byte(content), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(fixture.paths.Home, path)), 0o700))
}

func readPullSingleFile(t *testing.T, fixture *pullTestFixture) []byte {
	t.Helper()
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	return content
}

func TestPullAdoptsAFreshFileSetTargetOnConfirmation(t *testing.T) {
	pullFileSetUmask(t)
	fixture := newPullTestFixture(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(fixture.targetPath("init.lua")), 0o700))
	fileSet := newCLIFileSetPublication(t, fixture.binding)
	reader := fileSetTestReader(fileSet)

	code, stdout, stderr := runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "adopt: create target files (files:home/config, directory, mode review)\n")
	assert.Contains(t, stdout, "pull: adoption only; nothing local was read or changed; repeat with")
	assert.NotContains(t, stdout, "apply:")
	planned, err := config.Load(fixture.paths)
	require.NoError(t, err)
	assert.Empty(t, planned.Targets, "the unconfirmed adoption was written")
	_, statErr := os.Lstat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "the unconfirmed adoption wrote a target file")

	adoptionToken := pullTestConfirmation(t, stdout)
	code, stdout, stderr = runPullFileSetStep(
		t,
		fixture,
		reader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--confirm", adoptionToken,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "adopt: created target files (files:home/config, directory, mode review)\n")
	assert.Contains(t, stdout, "pull: plan only; nothing was applied; repeat with")
	adopted, err := config.Load(fixture.paths)
	require.NoError(t, err)
	require.Len(t, adopted.Targets, 1)
	target := adopted.Targets[0]
	assert.Equal(t, "files", target.ID)
	assert.Equal(t, model.SourceFiles, target.Source)
	assert.Equal(t, config.Review, target.Mode)
	require.NotNil(t, target.Root)
	assert.Equal(t, model.RootHome, target.Root.Base)
	assert.Equal(t, "config", target.Root.Path)
	assert.Equal(t, model.SelectionDirectory, target.Root.Kind)
	assert.Empty(t, target.Root.Exclude)
	_, statErr = os.Lstat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "the adoption run applied files")

	applyToken := pullTestConfirmation(t, stdout)
	code, stdout, stderr = runPullFileSetStep(
		t,
		fixture,
		reader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--confirm", applyToken,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, fmt.Sprintf("pull: applied changes=4 unchanged=0 bytes=%d\n",
		len("synthetic file-set init")+len("synthetic file-set options")))
	assert.Equal(t, []byte("synthetic file-set init"), readPullSingleFile(t, fixture))
	assert.Equal(t, uint64(1), fixture.acceptedFloor(t).Revision)

	code, stdout, stderr = runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "pull: matches\n", stdout)
}

func TestPullReadsNothingOutsideTheConfiguredTargetBeforeAdoption(t *testing.T) {
	fixture := newPullTestFixture(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(fixture.targetPath("init.lua")), 0o700))
	require.NoError(t, os.WriteFile(fixture.targetPath("init.lua"), []byte("local difference"), 0o600))
	fileSet := newCLIFileSetPublication(t, fixture.binding)
	reader := fileSetTestReader(fileSet)

	code, stdout, stderr := runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: adoption only; nothing local was read or changed; repeat with")
	assert.NotContains(t, stdout, "conflict")
	planned, err := config.Load(fixture.paths)
	require.NoError(t, err)
	assert.Empty(t, planned.Targets)

	adoptionToken := pullTestConfirmation(t, stdout)
	code, stdout, stderr = runPullFileSetStep(
		t,
		fixture,
		reader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--confirm", adoptionToken,
	)
	require.Equal(t, 3, code, stdout)
	assert.Contains(t, stderr, "conflict")
	refused, err := config.Load(fixture.paths)
	require.NoError(t, err)
	assert.Empty(t, refused.Targets, "a refused plan adopted the target")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, []byte("local difference"), content)
}

func TestPullAdoptsAFileSetTargetWhenLocalFilesAlreadyMatch(t *testing.T) {
	pullFileSetUmask(t)
	fixture := newPullTestFixture(t)
	require.NoError(t, os.MkdirAll(filepath.Join(fixture.paths.Home, "config", "lua", "config"), 0o755))
	require.NoError(t, os.WriteFile(fixture.targetPath("init.lua"), []byte("synthetic file-set init"), 0o600))
	require.NoError(t, os.WriteFile(fixture.targetPath("lua/config/options.lua"), []byte("synthetic file-set options"), 0o644))
	fileSet := newCLIFileSetPublication(t, fixture.binding)
	reader := fileSetTestReader(fileSet)

	code, stdout, stderr := runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: adoption only; nothing local was read or changed; repeat with")
	adoptionToken := pullTestConfirmation(t, stdout)

	code, stdout, stderr = runPullFileSetStep(
		t,
		fixture,
		reader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--confirm", adoptionToken,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "adopt: created target")
	assert.Contains(t, stdout, "pull: acceptance only; nothing was applied; repeat with")
	adopted, err := config.Load(fixture.paths)
	require.NoError(t, err)
	require.Len(t, adopted.Targets, 1)
	assert.Equal(t, "files", adopted.Targets[0].ID)

	acceptToken := pullTestConfirmation(t, stdout)
	code, stdout, stderr = runPullFileSetStep(
		t,
		fixture,
		reader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--confirm", acceptToken,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "floor: revision=1")
}

func TestPullRefusesToAdoptAFileSetTargetWhoseRootDoesNotExist(t *testing.T) {
	fixture := newPullTestFixture(t)
	fileSet := newCLIFileSetPublication(t, fixture.binding)
	reader := fileSetTestReader(fileSet)

	code, stdout, stderr := runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code, stdout)
	assert.Contains(t, stderr, "cannot be adopted")
	assert.NotContains(t, stdout, "confirmation:")
	planned, err := config.Load(fixture.paths)
	require.NoError(t, err)
	assert.Empty(t, planned.Targets)
}

func TestPullRefusesAFreshPackedPositionWithoutAnyAdoptableTarget(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code, stdout.String())
	assert.Contains(t, stderr.String(), "no target is configured")
}

func TestPullApplyAdoptionLeavesAConfiguredMachineAlone(t *testing.T) {
	configuration := config.Default()
	configuration.Targets = []config.Target{{
		ID: "settings", Source: model.SourceGNOME,
		GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalPending},
	}}
	sources := pullApplySources{Configuration: configuration}
	material := pullApplyMaterial{
		Form: publication.PayloadFormFileSet,
		Targets: []model.Target{{
			ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
	}
	got, adoption, _, err := pullApplyAdoption(sources, material, pullApplyPlanRequest{})
	require.NoError(t, err)
	assert.Nil(t, adoption)
	assert.Equal(t, configuration, got)
}

func TestPullAdoptsAPackedFilesTargetOnConfirmation(t *testing.T) {
	pullFileSetUmask(t)
	fixture := newPullTestFixture(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(fixture.targetPath("init.lua")), 0o700))
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	run := func(args ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := 0
		command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
		code = runPullForTest(command, &code, args...)
		return code, stdout.String(), stderr.String()
	}

	code, stdout, stderr := run("--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "adopt: create target files (files:home/config, directory, mode review)\n")
	assert.Contains(t, stdout, "pull: adoption only; nothing local was read or changed; repeat with")
	planned, err := config.Load(fixture.paths)
	require.NoError(t, err)
	assert.Empty(t, planned.Targets, "the unconfirmed adoption was written")

	adoptionToken := pullTestConfirmation(t, stdout)
	code, stdout, stderr = run("--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", adoptionToken)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "adopt: created target files (files:home/config, directory, mode review)\n")
	assert.Contains(t, stdout, "pull: plan only; nothing was applied; repeat with")
	adopted, err := config.Load(fixture.paths)
	require.NoError(t, err)
	require.Len(t, adopted.Targets, 1)
	assert.Equal(t, model.RootHome, adopted.Targets[0].Root.Base)
	assert.Equal(t, "config", adopted.Targets[0].Root.Path)
	_, statErr := os.Lstat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "the adoption run applied files")

	applyToken := pullTestConfirmation(t, stdout)
	code, stdout, stderr = run("--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", applyToken)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: applied changes=1 unchanged=0")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, pullTestBaseContent, string(content))
	assert.Equal(t, uint64(1), fixture.acceptedFloor(t).Revision)
}

func TestPullApplyAdoptionCarriesPackedFilesAndSettingsTargets(t *testing.T) {
	paths, _ := cliEnvironment(t)
	require.NoError(t, os.MkdirAll(filepath.Join(paths.Home, "config"), 0o700))
	absent, err := config.OpenSnapshot(paths)
	require.NoError(t, err)
	sources := pullApplySources{
		Paths:         paths,
		Configuration: config.Default(),
		Token:         absent.Token,
	}
	material := pullApplyMaterial{
		Form: publication.PayloadFormPacked,
		Targets: []model.Target{
			{
				ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
				Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
			},
			{
				ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion,
			},
		},
	}
	input := pullApplyPlanRequest{
		Settings: []pullSettingsSelection{{TargetID: "desktop", Categories: []string{"clock", "appearance"}}},
	}
	configuration, adoption, skipped, err := pullApplyAdoption(sources, material, input)
	require.NoError(t, err)
	assert.Empty(t, skipped)
	require.NotNil(t, adoption)
	require.Len(t, adoption.Targets, 2)
	require.Len(t, configuration.Targets, 2)

	files := configuration.Targets[0]
	assert.Equal(t, model.SourceFiles, files.Source)
	require.NotNil(t, files.Root)
	assert.Equal(t, model.RootHome, files.Root.Base)
	assert.Equal(t, "config", files.Root.Path)
	assert.Equal(t, config.Review, files.Mode)

	desktop := configuration.Targets[1]
	assert.Equal(t, "desktop", desktop.ID)
	assert.Equal(t, model.SourceGNOME, desktop.Source)
	assert.Equal(t, config.Review, desktop.Mode)
	require.NotNil(t, desktop.GNOMEPolicy)
	keys, err := matrix.SelectCategories([]string{"appearance", "clock"})
	require.NoError(t, err)
	digest, err := matrix.KeySetDigest(keys)
	require.NoError(t, err)
	assert.Equal(t, config.GNOMEApprovalApproved, desktop.GNOMEPolicy.Approval)
	assert.Equal(t, []string{"appearance", "clock"}, desktop.GNOMEPolicy.Categories)
	assert.Equal(t, matrix.Version, desktop.GNOMEPolicy.MatrixVersion)
	assert.Equal(t, hex.EncodeToString(digest[:]), desktop.GNOMEPolicy.KeyDigest)

	binding := pullTestFileSetBinding()
	token := pullAdoptionConfirmationToken(binding, 0, false, []byte{0x01}, 0, adoption)
	assert.Equal(t, token, pullAdoptionConfirmationToken(binding, 0, false, []byte{0x01}, 0, adoption))
	widened := pullApplyPlanRequest{
		Settings: []pullSettingsSelection{{TargetID: "desktop", Categories: []string{"appearance", "clock", "fonts"}}},
	}
	_, other, _, err := pullApplyAdoption(sources, material, widened)
	require.NoError(t, err)
	assert.NotEqual(
		t,
		token,
		pullAdoptionConfirmationToken(binding, 0, false, []byte{0x01}, 0, other),
		"the token does not bind the approved category set",
	)

	require.NoError(t, commitPullAdoption(context.Background(), paths, adoption))
	stored, err := config.Load(paths)
	require.NoError(t, err)
	require.Len(t, stored.Targets, 2)
}

func TestPullApplyAdoptionSkipsSettingsTargetsWithoutASelection(t *testing.T) {
	paths, _ := cliEnvironment(t)
	sources := pullApplySources{Paths: paths, Configuration: config.Default()}
	material := pullApplyMaterial{
		Form: publication.PayloadFormPacked,
		Targets: []model.Target{
			{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
		},
	}
	configuration, adoption, skipped, err := pullApplyAdoption(sources, material, pullApplyPlanRequest{})
	require.NoError(t, err)
	assert.Nil(t, adoption)
	assert.Equal(t, config.Default(), configuration)
	require.Len(t, skipped, 1)
	assert.Contains(t, skipped[0], "settings target desktop is not configured")
	assert.Contains(t, skipped[0], "--settings desktop=CATEGORY")
}

func TestPullApplyAdoptionLeavesAnIdenticalSettingsTargetAlone(t *testing.T) {
	paths, _ := cliEnvironment(t)
	policy, err := config.ApprovedGNOMEPolicy([]string{"appearance", "clock"})
	require.NoError(t, err)
	configured := config.Default()
	configured.Targets = []config.Target{{
		ID: "desktop", Source: model.SourceGNOME, GNOMEPolicy: &policy,
	}}
	sources := pullApplySources{Paths: paths, Configuration: configured}
	material := pullApplyMaterial{
		Form: publication.PayloadFormPacked,
		Targets: []model.Target{
			{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
		},
	}
	got, adoption, skipped, err := pullApplyAdoption(sources, material, pullApplyPlanRequest{
		Settings: []pullSettingsSelection{{TargetID: "desktop", Categories: []string{"clock", "appearance"}}},
	})
	require.NoError(t, err)
	assert.Nil(t, adoption)
	assert.Empty(t, skipped)
	assert.Equal(t, configured, got)

	_, _, _, err = pullApplyAdoption(sources, material, pullApplyPlanRequest{
		Settings: []pullSettingsSelection{{TargetID: "desktop", Categories: []string{"fonts"}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run dottie targets approve")
}

func TestPullSettingsSelectionsParseAndRejectDuplicates(t *testing.T) {
	selections, err := parsePullSettings([]string{"desktop=appearance,clock", "files=appearance"})
	require.NoError(t, err)
	assert.Equal(t, []pullSettingsSelection{
		{TargetID: "desktop", Categories: []string{"appearance", "clock"}},
		{TargetID: "files", Categories: []string{"appearance"}},
	}, selections)

	for _, value := range [][]string{
		{"desktop"},
		{"=appearance"},
		{"desktop="},
		{"desktop=appearance,"},
		{"desktop=appearance", "desktop=clock"},
	} {
		_, err := parsePullSettings(value)
		require.Error(t, err, "%v", value)
		assert.Contains(t, err.Error(), "usage:", "%v", value)
	}
}

func TestPullReportsSkippedPackedTargetsBeforeRefusing(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code, stdout.String())
	assert.Contains(t, stdout.String(), "skip: target files:home/config is not configured")
	assert.Contains(t, stderr.String(), "no target is configured")
}

func TestPullRefusesSettingsSelectionsOnAFileSetPosition(t *testing.T) {
	fixture := newPullTestFixture(t)
	fileSet := newCLIFileSetPublication(t, fixture.binding)
	reader := fileSetTestReader(fileSet)

	code, stdout, stderr := runPullFileSetStep(
		t,
		fixture,
		reader,
		"--did", pullTestDID,
		"--vault", pullTestVaultHex(),
		"--settings", "desktop=appearance",
	)
	require.Equal(t, 3, code, stdout)
	assert.Contains(t, stderr, "--settings applies to packed publications")
}

func TestPullApplyAdoptionRefusesSettingsTargetsThatAreNotPublished(t *testing.T) {
	paths, _ := cliEnvironment(t)
	policy, err := config.ApprovedGNOMEPolicy([]string{"appearance"})
	require.NoError(t, err)
	configured := config.Default()
	configured.Targets = []config.Target{{
		ID: "desktop", Source: model.SourceGNOME, GNOMEPolicy: &policy,
	}}
	sources := pullApplySources{Paths: paths, Configuration: configured}
	material := pullApplyMaterial{
		Form: publication.PayloadFormPacked,
		Targets: []model.Target{
			{
				ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
				Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
			},
		},
	}
	_, _, _, err = pullApplyAdoption(sources, material, pullApplyPlanRequest{
		Settings: []pullSettingsSelection{{TargetID: "desktop", Categories: []string{"appearance"}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "names no settings target desktop")
}

func TestPullApplyAdoptionRefusesARootOwnedByADifferentTargetID(t *testing.T) {
	paths, _ := cliEnvironment(t)
	require.NoError(t, os.MkdirAll(filepath.Join(paths.Home, "config"), 0o700))
	configured := config.Default()
	configured.Targets = []config.Target{{
		ID: "other", Source: model.SourceFiles,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}}
	sources := pullApplySources{Paths: paths, Configuration: configured}
	material := pullApplyMaterial{
		Form: publication.PayloadFormPacked,
		Targets: []model.Target{{
			ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
	}
	_, _, _, err := pullApplyAdoption(sources, material, pullApplyPlanRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shares its root with local target other")
}
