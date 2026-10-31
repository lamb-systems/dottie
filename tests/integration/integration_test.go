package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/preset"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/require"
)

func testPaths(t *testing.T) platform.Paths {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home:       filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "config"),
		StateHome:  filepath.Join(root, "state"),
		CacheHome:  filepath.Join(root, "cache"),
		DataHome:   filepath.Join(root, "data"),
	}
	for _, dir := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			require.NoError(t, err)
		}
	}
	return paths
}

func TestPresetCaptureSnapshotStateRoundTrip(t *testing.T) {
	paths := testPaths(t)
	ctx := context.Background()

	neovim, err := preset.Lookup("neovim")
	if err != nil {
		require.NoError(t, err, "lookup preset: %v", err)
	}
	proposed, err := preset.Materialize(neovim, config.Default(), paths)
	if err != nil {
		require.NoError(t, err, "materialize preset: %v", err)
	}
	if err := proposed.Validate(); err != nil {
		require.NoError(t, err, "materialized config is invalid: %v", err)
	}
	if len(proposed.Targets) != 1 {
		require.Len(t, proposed.Targets, 1, "expected one materialized target, got %d", len(proposed.Targets))
	}
	target := proposed.Targets[0]
	if target.Mode != "" {
		require.Equal(t, "", target.Mode, "materialization must not set a consent override, got %q", target.Mode)
	}

	root, err := target.ResolvedPath(paths)
	if err != nil {
		require.NoError(t, err, "resolve target: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "lua", "plugin"), 0o700); err != nil {
		require.NoError(t, err)
	}
	if err := os.WriteFile(filepath.Join(root, "init.lua"), []byte("vim.o.number = true\n"), 0o600); err != nil {
		require.NoError(t, err)
	}
	if err := os.WriteFile(filepath.Join(root, "lua", "plugin", "example.lua"), []byte("return {}\n"), 0o600); err != nil {
		require.NoError(t, err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		require.NoError(t, err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("excluded\n"), 0o600); err != nil {
		require.NoError(t, err)
	}

	captured, err := files.Capture(files.Root{
		TargetID: target.ID,
		Path:     root,
		Kind:     target.Root.Kind,
		Budget:   files.DefaultBudget(),
		Exclude:  target.Root.Exclude,
	})
	if err != nil {
		require.NoError(t, err, "capture: %v", err)
	}

	portableTarget, err := target.Model()
	if err != nil {
		require.NoError(t, err, "portable target: %v", err)
	}
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portableTarget}}
	for _, observation := range captured.Observations {
		if observation.State != model.ObservationPresent || observation.Entry == nil {
			continue
		}
		snapshot.Entries = append(snapshot.Entries, *observation.Entry)
	}
	if err := snapshot.Validate(); err != nil {
		require.NoError(t, err, "captured snapshot is invalid: %v", err)
	}
	if len(snapshot.Entries) == 0 {
		require.NotEmpty(t, snapshot.Entries, "capture produced no present entries")
	}
	var sawNested bool
	for _, entry := range snapshot.Entries {
		if entry.File == nil {
			continue
		}
		if entry.File.Path == ".git/config" {
			require.NotEqual(t, ".git/config", entry.File.Path, "preset exclude did not apply during capture")
		}
		if entry.File.Path == "lua/plugin/example.lua" && entry.File.Kind == model.FileRegular {
			sawNested = true
		}
	}
	if !sawNested {
		require.True(t, sawNested, "capture did not include a nested, non-excluded file")
	}

	blob, err := vault.Pack(snapshot)
	if err != nil {
		require.NoError(t, err, "pack: %v", err)
	}
	restored, err := vault.Unpack(blob)
	if err != nil {
		require.NoError(t, err, "unpack: %v", err)
	}
	if len(restored.Entries) != len(snapshot.Entries) || len(restored.Targets) != 1 || restored.Targets[0].ID != target.ID {
		require.Len(t, restored.Entries, len(snapshot.Entries), "unpack lost fidelity: %d/%d entries, %d targets", len(restored.Entries), len(snapshot.Entries), len(restored.Targets))
		require.Len(t, restored.Targets, 1, "unpack lost fidelity: %d/%d entries, %d targets", len(restored.Entries), len(snapshot.Entries), len(restored.Targets))
		require.Equal(t, target.ID, restored.Targets[0].ID, "unpack lost fidelity: %d/%d entries, %d targets", len(restored.Entries), len(snapshot.Entries), len(restored.Targets))
	}
	repacked, err := vault.Pack(restored)
	if err != nil {
		require.NoError(t, err, "repack restored snapshot: %v", err)
	}
	if !bytes.Equal(repacked.Payload, blob.Payload) {
		require.Equal(t, blob.Payload, repacked.Payload, "repacking the restored snapshot produced different bytes, so unpack changed the content")
	}
	var initContent string
	for _, entry := range restored.Entries {
		if entry.File != nil && entry.File.Path == "init.lua" && entry.File.Kind == model.FileRegular {
			initContent = string(entry.File.Content)
		}
	}
	if initContent != "vim.o.number = true\n" {
		require.Equal(t, "vim.o.number = true\n", initContent, "restored init.lua content = %q", initContent)
	}

	store, err := state.Open(paths)
	if err != nil {
		require.NoError(t, err, "open state: %v", err)
	}
	descriptor := state.TargetDescriptor{
		ID:            target.ID,
		Version:       1,
		Source:        target.Source,
		SourceVersion: model.SourceVersion,
		LogicalBase:   target.Root.Base,
		LogicalPath:   target.Root.Path,
		Kind:          target.Root.Kind,
		Mode:          "review",
		CreatedAt:     1,
	}
	if err := store.PutTarget(ctx, descriptor); err != nil {
		require.NoError(t, err, "put target: %v", err)
	}

	var baseEntry model.Entry
	for _, entry := range snapshot.Entries {
		if entry.File != nil && entry.File.Kind == model.FileRegular && entry.File.Path != "." {
			baseEntry = entry
			break
		}
	}
	if baseEntry.File == nil {
		require.NotNil(t, baseEntry.File, "no regular file entry to use as an applied base")
	}
	base, err := store.PutAppliedBase(ctx, state.BaseRecord{
		Identity:    baseEntry.Identity(),
		Fingerprint: state.NewFingerprint("present", baseEntry.File.Kind, baseEntry.File.Mode, baseEntry.File.LinkTarget, "", "", baseEntry.File.Content),
		RecordedAt:  2,
	}, baseEntry.File.Content)
	if err != nil {
		require.NoError(t, err, "put applied base: %v", err)
	}
	intent, err := store.AppendIntent(ctx, state.Intent{
		ID:        "intent-1",
		Identity:  baseEntry.Identity(),
		State:     "pending",
		Attempts:  0,
		CreatedAt: 3,
	}, []byte("pending payload"))
	if err != nil {
		require.NoError(t, err, "append intent: %v", err)
	}
	if err := store.Close(); err != nil {
		require.NoError(t, err, "close state: %v", err)
	}

	reopened, err := state.Open(paths)
	if err != nil {
		require.NoError(t, err, "reopen state: %v", err)
	}
	defer reopened.Close()
	bases, err := reopened.AppliedBase(ctx, target.ID)
	if err != nil {
		require.NoError(t, err, "read applied base: %v", err)
	}
	if len(bases) != 1 || bases[0].Fingerprint.Digest != base.Fingerprint.Digest {
		require.Len(t, bases, 1, "applied base did not survive restart: %+v", bases)
		require.Equal(t, base.Fingerprint.Digest, bases[0].Fingerprint.Digest, "applied base did not survive restart: %+v", bases)
	}
	basePayload, err := reopened.Payload(bases[0].PayloadRef)
	if err != nil {
		require.NoError(t, err, "base payload: %v", err)
	}
	if string(basePayload) != string(baseEntry.File.Content) {
		require.Equal(t, string(baseEntry.File.Content), string(basePayload), "base payload mismatch: %q", basePayload)
	}
	intents, err := reopened.Intents(ctx, target.ID)
	if err != nil {
		require.NoError(t, err, "read intents: %v", err)
	}
	if len(intents) != 1 || intents[0].ID != intent.ID {
		require.Len(t, intents, 1, "intent did not survive restart: %+v", intents)
		require.Equal(t, intent.ID, intents[0].ID, "intent did not survive restart: %+v", intents)
	}
	if err := os.RemoveAll(paths.AppCacheDir()); err != nil {
		require.NoError(t, err)
	}
	if _, err := reopened.Payload(intents[0].PayloadRef); err != nil {
		require.NoError(t, err, "intent payload must not depend on the cache: %v", err)
	}
}
