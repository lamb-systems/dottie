package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

func publicationJournalDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	return directory
}

func TestPullSettingsApplyRefusalBlocksAConfiguredPublishedSettingsTarget(t *testing.T) {
	policy, err := config.ApprovedGNOMEPolicy([]string{"appearance"})
	require.NoError(t, err)
	files := config.Target{
		ID: "files", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	settings := config.Target{
		ID: "desktop", Source: model.SourceGNOME, Mode: config.Review, GNOMEPolicy: &policy,
	}
	material := pullApplyMaterial{Targets: []model.Target{
		{
			ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		},
		{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
	}}
	filesOnly := config.Config{Version: config.Version, Targets: []config.Target{files}}
	require.NoError(t, pullSettingsApplyRefusal(pullApplyPlanRequest{}, filesOnly, material, pullApplySources{}))

	withSettings := config.Config{Version: config.Version, Targets: []config.Target{files, settings}}
	err = pullSettingsApplyRefusal(pullApplyPlanRequest{}, withSettings, material, pullApplySources{})
	require.Error(t, err)
	var exitErr urfave.ExitCoder
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 3, exitErr.ExitCode())
	assert.Contains(t, err.Error(), "desktop")
	assert.Contains(t, err.Error(), "cannot apply settings")

	require.NoError(t, pullSettingsApplyRefusal(
		pullApplyPlanRequest{}, withSettings, material,
		pullApplySources{Settings: &settingsTestBackendStub{}},
	))
}

func TestPullProjectionBaseEntriesRefusesAReplacedPublishedTarget(t *testing.T) {
	first := model.Target{
		ID: "first", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "first", Kind: model.SelectionDirectory},
	}
	second := model.Target{
		ID: "second", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "second", Kind: model.SelectionDirectory},
	}
	material := pullApplyMaterial{
		Targets: []model.Target{second},
		Base:    model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{first}},
	}
	input := pullApplyPlanRequest{Present: true}
	_, _, err := pullProjectionBaseEntries(input, material)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replaced target first with second")

	material.Targets = []model.Target{first}
	entries, ok, err := pullProjectionBaseEntries(input, material)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Empty(t, entries)

	material.Base = model.Snapshot{Version: model.SnapshotVersion}
	_, ok, err = pullProjectionBaseEntries(input, material)
	require.NoError(t, err)
	assert.False(t, ok, "a base without the published target was used as a predecessor")

	material.Base = model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{first}}
	moved := first
	moved.Root = &model.FileRoot{Base: model.RootHome, Path: "moved", Kind: model.SelectionDirectory}
	material.Base.Targets = []model.Target{moved}
	_, _, err = pullProjectionBaseEntries(input, material)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "different root")
}

func TestPullProjectionBaseEntriesSelectsTheHeadIdentityFromAMixedBase(t *testing.T) {
	first := model.Target{
		ID: "first", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "first", Kind: model.SelectionDirectory},
	}
	second := model.Target{
		ID: "second", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "second", Kind: model.SelectionDirectory},
	}
	material := pullApplyMaterial{
		Targets: []model.Target{second},
		Base: model.Snapshot{
			Version: model.SnapshotVersion,
			Targets: []model.Target{first, second},
			Entries: []model.Entry{
				{
					TargetID: "first",
					File: &model.FileEntry{
						Path: "kept.conf", State: model.FilePresent, Kind: model.FileRegular,
						Content: []byte("sentinel"), Mode: 0o600,
					},
				},
				{
					TargetID: "second",
					File: &model.FileEntry{
						Path: "second.conf", State: model.FilePresent, Kind: model.FileRegular,
						Content: []byte("second"), Mode: 0o600,
					},
				},
			},
		},
	}
	entries, ok, err := pullProjectionBaseEntries(pullApplyPlanRequest{Present: true}, material)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, entries, 1, "the predecessor came from the wrong target")
	assert.Equal(t, "second.conf", entries[0].Path)
}

func TestPullApplyJournalGuardSettlesAnInterruptedApply(t *testing.T) {
	directory := publicationJournalDirectory(t)
	root := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(root, 0o700))
	destination := filepath.Join(root, "note.ini")
	require.NoError(t, os.WriteFile(destination, []byte("done"), 0o600))
	info, err := os.Lstat(root)
	require.NoError(t, err)
	anchor, ok := publicationstate.NewJournalAnchor(root, info)
	require.True(t, ok)

	journal, err := publicationstate.OpenJournal(directory)
	require.NoError(t, err)
	postimage := publicationstate.ObservedJournalFile([]byte("done"))
	postimage.Mode = 0o600
	_, err = journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: [32]byte{0x31}, Operation: "apply", DestinationDir: root, DestinationPath: "note.ini",
		Anchor: anchor, Postimage: postimage,
	})
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	guard, err := openPullApplyJournalGuard(context.Background(), directory, "pull")
	require.NoError(t, err)
	resolved, err := guard.resolve(context.Background(), "pull", 0, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), resolved)
	guard.Close()

	live, err := publicationstate.LiveJournalRows(directory)
	require.NoError(t, err)
	assert.Equal(t, int64(0), live)
}

func TestPullApplyJournalGuardRefusesAnIndeterminateApply(t *testing.T) {
	directory := publicationJournalDirectory(t)
	root := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(root, 0o700))
	destination := filepath.Join(root, "note.ini")
	require.NoError(t, os.WriteFile(destination, []byte("third"), 0o600))
	info, err := os.Lstat(root)
	require.NoError(t, err)
	anchor, ok := publicationstate.NewJournalAnchor(root, info)
	require.True(t, ok)

	journal, err := publicationstate.OpenJournal(directory)
	require.NoError(t, err)
	preimage := publicationstate.ObservedJournalFile([]byte("before"))
	preimage.Mode = 0o600
	postimage := publicationstate.ObservedJournalFile([]byte("done"))
	postimage.Mode = 0o600
	_, err = journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: [32]byte{0x32}, Operation: "apply", DestinationDir: root, DestinationPath: "note.ini",
		Anchor: anchor, Preimage: &preimage, PreimageBytes: []byte("before"), Postimage: postimage,
	})
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	guard, err := openPullApplyJournalGuard(context.Background(), directory, "pull")
	require.NoError(t, err)
	defer guard.Close()
	_, err = guard.resolve(context.Background(), "pull", 0, nil)
	require.Error(t, err)
	var exitErr urfave.ExitCoder
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 4, exitErr.ExitCode())
	assert.Contains(t, err.Error(), "unresolved")

	live, liveErr := publicationstate.LiveJournalRows(directory)
	require.NoError(t, liveErr)
	assert.Equal(t, int64(1), live, "the unresolved row was retired")

	content, readErr := os.ReadFile(destination)
	require.NoError(t, readErr)
	assert.Equal(t, "third", string(content), "an indeterminate apply mutated the destination")
}

func TestPullApplyJournalGuardRefusesARowSeenAheadOfTheFloor(t *testing.T) {
	directory := publicationJournalDirectory(t)
	root := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(root, 0o700))
	destination := filepath.Join(root, "note.ini")
	require.NoError(t, os.WriteFile(destination, []byte("done"), 0o600))
	info, err := os.Lstat(root)
	require.NoError(t, err)
	anchor, ok := publicationstate.NewJournalAnchor(root, info)
	require.True(t, ok)

	journal, err := publicationstate.OpenJournal(directory)
	require.NoError(t, err)
	postimage := publicationstate.ObservedJournalFile([]byte("done"))
	postimage.Mode = 0o600
	_, err = journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: [32]byte{0x33}, Operation: "apply", DestinationDir: root, DestinationPath: "note.ini",
		Anchor: anchor, Postimage: postimage, SeenFloorRevision: 4,
	})
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	guard, err := openPullApplyJournalGuard(context.Background(), directory, "pull")
	require.NoError(t, err)
	defer guard.Close()
	_, err = guard.resolve(context.Background(), "pull", 2, nil)
	require.Error(t, err)
	var exitErr urfave.ExitCoder
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 4, exitErr.ExitCode())
	assert.Contains(t, err.Error(), "unresolved")
}

func TestPullApplyJournalGuardHoldsTheLeaseWhileTheFloorAdvances(t *testing.T) {
	directory := publicationJournalDirectory(t)
	first, err := openPullApplyJournalGuard(context.Background(), directory, "pull")
	require.NoError(t, err)
	_, err = openPullApplyJournalGuard(context.Background(), directory, "pull")
	require.Error(t, err, "a second run acquired the apply journal while the first held it")
	first.Close()

	second, err := openPullApplyJournalGuard(context.Background(), directory, "pull")
	require.NoError(t, err)
	second.Close()
}

func TestPullRefusesAnAcceptanceWhileAnApplyIsUnresolved(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	root := filepath.Join(fixture.paths.Home, "config")
	destination := filepath.Join(root, "init.lua")
	require.NoError(t, os.WriteFile(destination, []byte(pullTestBaseContent), 0o600))

	info, err := os.Lstat(root)
	require.NoError(t, err)
	anchor, ok := publicationstate.NewJournalAnchor(root, info)
	require.True(t, ok)
	stateDirectory := fixture.paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(stateDirectory, 0o700))
	require.NoError(t, os.Chmod(stateDirectory, 0o700))
	journal, err := publicationstate.OpenJournal(stateDirectory)
	require.NoError(t, err)
	preimage := publicationstate.ObservedJournalFile([]byte("before"))
	preimage.Mode = 0o600
	postimage := publicationstate.ObservedJournalFile([]byte("after"))
	postimage.Mode = 0o600
	interrupted := publicationstate.ObservedJournalFile([]byte(pullTestBaseContent))
	interrupted.Mode = 0o600
	require.NotEqual(t, interrupted.Digest, preimage.Digest)
	require.NotEqual(t, interrupted.Digest, postimage.Digest)
	_, err = journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: fixture.binding.Vault, Operation: "apply", DestinationDir: root, DestinationPath: "init.lua",
		Anchor: anchor, Preimage: &preimage, PreimageBytes: []byte("before"), Postimage: postimage,
	})
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	require.Contains(t, stdout.String(), "acceptance only")
	token := pullTestConfirmation(t, stdout.String())

	rows, err := publicationstate.LiveJournalRows(stateDirectory)
	require.NoError(t, err)
	assert.Equal(t, int64(1), rows, "the preview mutated the journal")

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 4, code, stdout.String())
	assert.Contains(t, stderr.String(), "an interrupted apply is unresolved")
	inspection, err := publicationstate.Inspect(
		context.Background(),
		fixture.paths.PublicationStateDir(),
		fixture.binding,
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present, "the floor advanced past an unresolved apply")

	content, err := os.ReadFile(destination)
	require.NoError(t, err)
	assert.Equal(t, pullTestBaseContent, string(content), "an unresolved apply was rewritten")
}

func TestPullRefusesAMixedPredecessorReplacedByASingleEntriesHead(t *testing.T) {
	first := model.Target{
		ID: "first", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}
	second := model.Target{
		ID: "second", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	}
	base := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{first, second},
		Entries: []model.Entry{
			{
				TargetID: "first",
				File: &model.FileEntry{
					Path: "sentinel.conf", State: model.FilePresent, Kind: model.FileRegular,
					Content: []byte("sentinel"), Mode: 0o600,
				},
			},
			{
				TargetID: "second",
				File: &model.FileEntry{
					Path: "second.conf", State: model.FilePresent, Kind: model.FileRegular,
					Content: []byte("second"), Mode: 0o600,
				},
			},
		},
	}
	material := pullApplyMaterial{
		Targets: []model.Target{second},
		Base:    base,
	}
	entries, ok, err := pullProjectionBaseEntries(pullApplyPlanRequest{Present: true}, material)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, entries, 1)
	assert.Equal(t, "second.conf", entries[0].Path, "the projection used the predecessor of another target")

	material.Targets = []model.Target{{
		ID: "replacement", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}}
	_, _, err = pullProjectionBaseEntries(pullApplyPlanRequest{Present: true}, material)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replaced target")
	assert.NotContains(t, err.Error(), "sentinel")
}

type settingsTestBackendStub struct{}

func (settingsTestBackendStub) Observe(
	context.Context,
	model.EntryKey,
) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{}, nil
}

func (settingsTestBackendStub) Canonicalize(
	context.Context,
	model.EntryKey,
	string,
	string,
) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{}, nil
}

func (settingsTestBackendStub) Set(context.Context, model.EntryKey, string, string) error {
	return nil
}

func (settingsTestBackendStub) Reset(context.Context, model.EntryKey) error { return nil }
