package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
)

func TestPullApplyPlansASameContentRenameAsADeleteAndAWrite(t *testing.T) {
	ctx := t.Context()
	binding := pullTestFileSetBinding()
	content := []byte("synthetic renamed content")
	first, firstHead := cliFileSetBlock(t, binding, 0, nil, []cliFileSetFile{
		{path: "before.lua", mode: 0o600, content: content},
	})
	firstCID, err := publication.RecordCID(first.Raw)
	require.NoError(t, err)
	second, secondHead := cliFileSetBlock(t, binding, 1, firstCID, []cliFileSetFile{
		{path: "after.lua", mode: 0o600, content: content},
	})
	_ = firstHead
	view := publicationstate.SuppliedRepositoryView{
		Origin: binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{
			RepositoryRevision: "synthetic-rename-revision", RepositoryDigest: []byte{0x72},
		},
		Head:      secondHead,
		Snapshots: []publicationstate.SnapshotBlock{first, second},
	}
	reader := &pullTestReader{
		view:    view,
		entries: map[string][]byte{string(mustCLIFileSetCID(second.Raw, 0)): content},
	}
	floor := publicationstate.Floor{
		Revision: 1, Generation: 1, Binding: binding,
		RecordCID: firstCID, SnapshotKey: first.Key,
		Segments: cliRecordSummaries(t, mustCLIFileSetRecord(t, first.Raw)),
	}

	material, err := pullApplySnapshots(ctx, pullRemote{
		Reader: reader, Entry: reader.ReadEntry,
	}, view, floor, true)
	require.NoError(t, err)
	require.Len(t, material.Entries, 1)
	assert.Equal(t, "after.lua", material.Entries[0].Path)

	baseEntries, ok, err := pullProjectionBaseEntries(material)
	require.NoError(t, err)
	require.True(t, ok)

	home, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(home, "config")
	require.NoError(t, os.Mkdir(root, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "before.lua"), content, 0o600))

	target := config.Target{
		ID: "files", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	configuration := config.Config{Version: config.Version, Targets: []config.Target{target}}
	portable, err := target.Model()
	require.NoError(t, err)
	remoteSnapshot, err := service.ProjectFileSetSnapshot(portable, material.Entries)
	require.NoError(t, err)
	baseSnapshot, err := service.ProjectFileSetSnapshot(portable, baseEntries)
	require.NoError(t, err)

	paths := platform.Paths{
		Home: home, ConfigHome: filepath.Join(home, ".config"), StateHome: filepath.Join(home, ".state"),
		CacheHome: filepath.Join(home, ".cache"), DataHome: filepath.Join(home, ".data"),
	}
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	journal, err := publicationstate.OpenJournal(directory)
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	local, err := service.NewPublicationLocalContext(paths, service.LocalFilesCapture{}, nil)
	require.NoError(t, err)
	var vault [32]byte
	vault[0] = 0x62

	plan, err := service.PlanPublicationApply(ctx, service.PublicationApplyRequest{
		Journal: journal, Vault: vault, FloorRevision: floor.Revision,
		Configuration: configuration, BaseSnapshot: baseSnapshot, RemoteSnapshot: remoteSnapshot,
		Roots: map[string]string{"files": root}, Local: local,
	})
	require.NoError(t, err)
	operations := make(map[string]service.PublicationApplyOperation, len(plan.Entries))
	for _, entry := range plan.Entries {
		operations[entry.Path] = entry.Operation
	}
	assert.Equal(t, service.PublicationApplyWrite, operations["after.lua"])
	assert.Equal(t, service.PublicationApplyDelete, operations["before.lua"])
	assert.Equal(t, 2, plan.Changes, "the projected rename was not planned as two changes")
}
