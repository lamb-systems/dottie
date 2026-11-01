package local_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type restoreGateFixture struct {
	base      string
	treeRoot  string
	targets   []model.Target
	roots     map[string]string
	excludes  map[string][]string
	localOnly model.EntryKey
	unsafe    model.EntryKey
	secret    string
}

type restoreGateCapture struct {
	observations []model.Observation
	entries      []model.Entry
	skips        map[string][]files.Skip
	covered      []string
}

type treeEntry struct {
	mode    os.FileMode
	kind    string
	content []byte
	link    string
}

func TestRestoreGateComposesLocalCapturePreviewApplyAndRollback(t *testing.T) {
	fixture := newRestoreGateFixture(t)
	store := openRestoreGateStore(t, fixture)
	originalTree := readRestoreGateTree(t, fixture.treeRoot)
	initial := captureRestoreGateTree(t, fixture)
	baseSnapshot := restoreGateSnapshot(t, fixture.targets, initial.entries)
	assertExcludedLocalIncludes(t, fixture, initial, baseSnapshot)

	remoteEntries := makeRestoreGateRemote(t, baseSnapshot.Entries)
	firstPlan, firstPreview := reconcileRestoreGate(t, fixture.targets, baseSnapshot.Entries, initial, remoteEntries)
	assertRestoreGateProperties(t, fixture, firstPlan, firstPreview)
	assertMissingRootRefusal(t, fixture, store, baseSnapshot.Entries, initial, remoteEntries, firstPreview, originalTree)
	assertUnsafeLinkRefusal(t, fixture, store, firstPreview, remoteEntries, originalTree)

	firstPostimages := restoreGatePostimages(t, firstPreview, remoteEntries)
	require.NoError(t, syncengine.Apply(context.Background(), store, restoreGateApplyRequest(fixture.roots, firstPreview, firstPostimages)), "first apply must apply the reviewed remote changes")
	firstApplied := captureRestoreGateTree(t, fixture)
	assert.Equal(t, restoreGateCanonicalEntries(t, remoteEntries), restoreGateCanonicalEntries(t, firstApplied.entries), "first apply verification must match the remote snapshot")
	assertRestoreGateConverged(t, fixture.targets, remoteEntries, firstApplied)

	firstRollback, err := syncengine.RollbackApplied(context.Background(), store, nil, restoreGateClock)
	require.NoError(t, err, "first rollback must complete")
	assert.Equal(t, countRestoreGateActions(firstPreview), len(firstRollback.Entries), "first rollback must report every applied file operation")
	for _, result := range firstRollback.Entries {
		assert.Equal(t, "rolled-back", result.Outcome, "first rollback must restore each operation")
	}
	assert.Equal(t, originalTree, readRestoreGateTree(t, fixture.treeRoot), "first rollback must restore the original tree byte-for-byte")

	secondStart := captureRestoreGateTree(t, fixture)
	secondPlan, secondPreview := reconcileRestoreGate(t, fixture.targets, baseSnapshot.Entries, secondStart, remoteEntries)
	assert.Equal(t, firstPlan, secondPlan, "second pass determinism must reproduce the same reconciliation plan")
	assert.Equal(t, firstPreview, secondPreview, "second pass determinism must reproduce the same preview actions and preimages")
	secondPostimages := restoreGatePostimages(t, secondPreview, remoteEntries)
	require.NoError(t, syncengine.Apply(context.Background(), store, restoreGateApplyRequest(fixture.roots, secondPreview, secondPostimages)), "second apply must apply the same reviewed changes")
	secondApplied := captureRestoreGateTree(t, fixture)
	assert.Equal(t, restoreGateCanonicalEntries(t, remoteEntries), restoreGateCanonicalEntries(t, secondApplied.entries), "second apply verification must match the remote snapshot")
	assertRestoreGateConverged(t, fixture.targets, remoteEntries, secondApplied)

	userEdit := []byte("user edit after apply\n")
	initPath := filepath.Join(fixture.roots["neovim"], "init.lua")
	writeRestoreGateFile(t, initPath, userEdit, 0o600)
	secondRollback, err := syncengine.RollbackApplied(context.Background(), store, nil, restoreGateClock)
	require.NoError(t, err, "second rollback must report and preserve the post-apply edit")
	var skipped *syncengine.JournalResult
	for index := range secondRollback.Entries {
		result := &secondRollback.Entries[index]
		if result.TargetID == "neovim" && result.FilePath == "init.lua" {
			skipped = result
			continue
		}
		assert.Equal(t, "rolled-back", result.Outcome, "second rollback must restore every unedited operation")
	}
	require.NotNil(t, skipped, "second rollback must report the edited init.lua operation")
	assert.Equal(t, "skipped-newer-edit", skipped.Outcome, "rollback must refuse to overwrite a newer user edit")
	assert.Contains(t, skipped.Reason, "left unchanged", "rollback refusal must name the preserved newer edit")
	assert.Equal(t, userEdit, readRestoreGateFile(t, initPath), "rollback must leave the newer user edit byte-for-byte untouched")
	assertTreeMatchesWithUserEdit(t, originalTree, readRestoreGateTree(t, fixture.treeRoot), "nvim/init.lua", userEdit)
	journal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	initJournal := restoreGateJournalEntry(t, journal, "neovim", "init.lua")
	assert.Equal(t, state.JournalStageRollbackSkipped, initJournal.Stage, "rollback refusal must be recorded in the journal")
	assert.Equal(t, "applied", initJournal.State, "a skipped newer edit must remain applied in the journal")

	t.Logf("restore gate: %d preview operations; new module, combined edits, rename, missing-root and unsafe-link refusals; first rollback restored the original tree; second rollback preserved a newer edit", countRestoreGateActions(firstPreview))
}

func TestRestoreGateRefusesLocalOnlyUploadAsLocalWrite(t *testing.T) {
	fixture := newRestoreGateFixture(t)
	store := openRestoreGateStore(t, fixture)
	baseline := captureRestoreGateTree(t, fixture)
	baseSnapshot := restoreGateSnapshot(t, fixture.targets, baseline.entries)
	localEdit := []byte("local-only edit that must survive\n")
	path := filepath.Join(fixture.roots["neovim"], "init.lua")
	writeRestoreGateFile(t, path, localEdit, 0o600)
	captured := captureRestoreGateTree(t, fixture)
	plan, preview := reconcileRestoreGate(t, fixture.targets, baseSnapshot.Entries, captured, baseSnapshot.Entries)

	var upload syncengine.Action
	for _, decision := range plan.Decisions {
		if decision.Key.TargetID == "neovim" && decision.Key.FilePath == "init.lua" {
			upload = decision.Action
		}
	}
	assert.Equal(t, syncengine.ActionUpload, upload, "a local-only edit must reconcile to upload")
	entry := restoreGatePreviewEntry(t, preview, model.EntryKey{TargetID: "neovim", Source: model.SourceFiles, FilePath: "init.lua"})
	assert.Equal(t, syncengine.ActionUpload, entry.DecisionAction, "preview must preserve the reconciler's upload action")
	remotePostimages := restoreGatePostimages(t, preview, baseSnapshot.Entries)
	applyErr := syncengine.Apply(context.Background(), store, restoreGateApplyRequest(fixture.roots, preview, remotePostimages))
	var notActionable *syncengine.NotActionableError
	require.ErrorAs(t, applyErr, &notActionable, "local apply must reject an outgoing upload")
	assert.ErrorIs(t, applyErr, syncengine.ErrNotActionable, "refusal must use the typed not-actionable error")
	assert.Equal(t, entry.Key, notActionable.Key, "refusal must name the upload entry")
	assert.Equal(t, syncengine.ActionUpload, notActionable.Action, "refusal must name the reconciler action")
	assert.Equal(t, localEdit, readRestoreGateFile(t, path), "refusing an upload must leave the local edit untouched")
	assert.Empty(t, restoreGateJournalEntries(t, store), "refusing an upload must not create a journal row")
}

func newRestoreGateFixture(t *testing.T) restoreGateFixture {
	t.Helper()
	base := t.TempDir()
	treeRoot := filepath.Join(base, "home", ".config")
	neovimRoot := filepath.Join(treeRoot, "nvim")
	workstationRoot := filepath.Join(treeRoot, "wm-custom")
	for _, directory := range []string{
		filepath.Join(neovimRoot, "lua", "plugins"),
		workstationRoot,
	} {
		require.NoError(t, os.MkdirAll(directory, 0o700), "synthetic configuration directories must be created")
	}
	writeRestoreGateFile(t, filepath.Join(neovimRoot, "init.lua"), []byte("dofile(\"lua/local.lua\")\nreturn require(\"core\")\n"), 0o600)
	writeRestoreGateFile(t, filepath.Join(neovimRoot, "lua", "core.lua"), []byte("return { enabled = true }\n"), 0o600)
	writeRestoreGateFile(t, filepath.Join(neovimRoot, "lua", "plugins", "old.lua"), []byte("return \"old-plugin\"\n"), 0o600)
	writeRestoreGateFile(t, filepath.Join(neovimRoot, "lua", "local.lua"), []byte("return { machine = \"local\" }\n"), 0o600)
	writeRestoreGateFile(t, filepath.Join(workstationRoot, "wm.conf"), []byte("include = local.conf\n"), 0o600)
	writeRestoreGateFile(t, filepath.Join(workstationRoot, "terminal.conf"), []byte("font = monospace 10\n"), 0o600)
	writeRestoreGateFile(t, filepath.Join(workstationRoot, "local.conf"), []byte("monitor = local-output\n"), 0o600)
	secret := filepath.Join(base, "outside", "monitor.conf")
	writeRestoreGateFile(t, secret, []byte("not captured\n"), 0o600)
	unsafePath := filepath.Join(workstationRoot, "external.conf")
	require.NoError(t, os.Symlink(secret, unsafePath), "synthetic escaping link must be created")

	targets := []model.Target{
		{ID: "neovim", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: ".config/nvim", Kind: model.SelectionDirectory}},
		{ID: "wm-custom", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: ".config/wm-custom", Kind: model.SelectionDirectory}},
	}
	return restoreGateFixture{
		base:     base,
		treeRoot: treeRoot,
		targets:  targets,
		roots: map[string]string{
			"neovim":    neovimRoot,
			"wm-custom": workstationRoot,
		},
		excludes:  map[string][]string{"wm-custom": {"local.conf"}},
		localOnly: model.EntryKey{TargetID: "wm-custom", Source: model.SourceFiles, FilePath: "local.conf"},
		unsafe:    model.EntryKey{TargetID: "wm-custom", Source: model.SourceFiles, FilePath: "external.conf"},
		secret:    secret,
	}
}

func openRestoreGateStore(t *testing.T, fixture restoreGateFixture) *state.Store {
	t.Helper()
	paths := platform.Paths{
		Home:      filepath.Join(fixture.base, "home"),
		StateHome: filepath.Join(fixture.base, "state"),
	}
	store, err := state.Open(paths)
	require.NoError(t, err, "temporary local state store must open")
	t.Cleanup(func() { _ = store.Close() })
	for _, target := range fixture.targets {
		require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{
			ID: target.ID, Version: 1, Source: target.Source, SourceVersion: target.SourceVersion,
			LogicalBase: target.Root.Base, LogicalPath: target.Root.Path, Kind: target.Root.Kind, Mode: "review", CreatedAt: 1,
		}), "synthetic target descriptor must be stored")
	}
	return store
}

func writeRestoreGateFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700), "synthetic file parent must exist")
	require.NoError(t, os.WriteFile(path, content, mode), "synthetic file must be written")
	require.NoError(t, os.Chmod(path, mode), "synthetic file mode must be deterministic")
}

func readRestoreGateFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err, "synthetic file must be readable")
	return content
}

func captureRestoreGateTree(t *testing.T, fixture restoreGateFixture) restoreGateCapture {
	t.Helper()
	capture := restoreGateCapture{skips: make(map[string][]files.Skip)}
	for _, target := range fixture.targets {
		result, err := files.Capture(files.Root{
			TargetID: target.ID,
			Path:     fixture.roots[target.ID],
			Kind:     target.Root.Kind,
			Exclude:  fixture.excludes[target.ID],
		})
		require.NoError(t, err, "capture must return observations for target %s", target.ID)
		capture.observations = append(capture.observations, result.Observations...)
		capture.skips[target.ID] = append(capture.skips[target.ID], result.Skipped...)
		targetCovered := true
		for _, observation := range result.Observations {
			if observation.State == model.ObservationUnknown {
				targetCovered = false
			}

			if observation.State == model.ObservationPresent {
				require.NotNil(t, observation.Entry, "present capture for %s must include an entry", observation.Identity.FilePath)
				capture.entries = append(capture.entries, *observation.Entry)
			}
		}
		if targetCovered {
			capture.covered = append(capture.covered, target.ID)
		}
	}
	capture.entries = restoreGateCanonicalEntries(t, capture.entries)
	sort.Slice(capture.observations, func(i, j int) bool {
		return restoreGateKeyLess(capture.observations[i].Identity, capture.observations[j].Identity)
	})
	return capture
}

func restoreGateSnapshot(t *testing.T, targets []model.Target, entries []model.Entry) model.Snapshot {
	t.Helper()
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: append([]model.Target(nil), targets...), Entries: restoreGateCanonicalEntries(t, entries)}
	require.NoError(t, snapshot.Validate(), "captured fixture must be a valid portable snapshot")
	return snapshot
}

func assertExcludedLocalIncludes(t *testing.T, fixture restoreGateFixture, capture restoreGateCapture, snapshot model.Snapshot) {
	t.Helper()
	assert.Contains(t, capture.skips["wm-custom"], files.Skip{Path: "local.conf", Reason: files.SkipExcluded, Detail: "local.conf"}, "local-only WM include must be explicitly excluded")
	assert.Contains(t, capture.skips["wm-custom"], files.Skip{Path: "external.conf", Reason: files.SkipExternalLink, Detail: fixture.secret}, "escaping WM link must be reported as skipped")
	assert.NotContains(t, restoreGateEntryKeys(snapshot.Entries), fixture.localOnly, "local-only WM include must be absent from the snapshot")
	assert.NotContains(t, restoreGateEntryKeys(snapshot.Entries), fixture.unsafe, "escaping link must be absent from the snapshot")
}

func makeRestoreGateRemote(t *testing.T, baseEntries []model.Entry) []model.Entry {
	t.Helper()
	remote := cloneRestoreGateEntries(baseEntries)
	setRestoreGateFile(t, remote, "neovim", "init.lua", []byte("dofile(\"lua/local.lua\")\nreturn require(\"core\").remote\n"), 0o600)
	setRestoreGateFile(t, remote, "wm-custom", "terminal.conf", []byte("font = monospace 12\n"), 0o600)
	removeRestoreGateFile(t, &remote, "neovim", "lua/plugins/old.lua")
	remote = append(remote,
		model.Entry{TargetID: "neovim", File: &model.FileEntry{Path: "lua/plugins/new-module.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("return { joined = true }\n"), Mode: 0o600}},
		model.Entry{TargetID: "neovim", File: &model.FileEntry{Path: "lua/plugins/renamed.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("return \"renamed-plugin\"\n"), Mode: 0o600}},
	)
	return restoreGateCanonicalEntries(t, remote)
}

func setRestoreGateFile(t *testing.T, entries []model.Entry, targetID, path string, content []byte, mode uint32) {
	t.Helper()
	for index := range entries {
		if entries[index].TargetID == targetID && entries[index].File != nil && entries[index].File.Path == path {
			entries[index].File.Content = append([]byte(nil), content...)
			entries[index].File.Mode = mode
			return
		}
	}
	require.FailNow(t, "remote file to edit was not captured", "%s/%s", targetID, path)
}

func removeRestoreGateFile(t *testing.T, entries *[]model.Entry, targetID, path string) {
	t.Helper()
	for index, entry := range *entries {
		if entry.TargetID == targetID && entry.File != nil && entry.File.Path == path {
			*entries = append((*entries)[:index], (*entries)[index+1:]...)
			return
		}
	}
	require.FailNow(t, "remote file to rename was not captured", "%s/%s", targetID, path)
}

func reconcileRestoreGate(t *testing.T, targets []model.Target, baseEntries []model.Entry, captured restoreGateCapture, remoteEntries []model.Entry) (syncengine.Plan, syncengine.Preview) {
	t.Helper()
	local := syncengine.LocalView{Coverage: append([]string(nil), captured.covered...)}
	for _, observation := range captured.observations {
		switch observation.State {
		case model.ObservationPresent:
			local.Entries = append(local.Entries, *observation.Entry)
		case model.ObservationUnknown:
			local.Unknown = append(local.Unknown, observation.Identity)
		case model.ObservationUntracked:
			local.Untracked = append(local.Untracked, observation.Identity)
		}
	}
	bindings := make([]syncengine.TargetBinding, 0, len(targets))
	for _, target := range targets {
		binding, err := syncengine.NewTargetBinding(target)
		require.NoError(t, err, "portable target binding must validate for %s", target.ID)
		bindings = append(bindings, binding)
	}
	plan, err := syncengine.Reconcile(syncengine.BaseView{Status: syncengine.BaseKnown, Entries: baseEntries}, local, remoteEntries, syncengine.Options{Bindings: bindings})
	require.NoError(t, err, "captured local tree and remote snapshot must reconcile")
	preview, err := syncengine.BuildPreview(plan, targets, captured.observations)
	require.NoError(t, err, "reconciled tree must produce a preview")
	return plan, preview
}

func assertRestoreGateProperties(t *testing.T, fixture restoreGateFixture, plan syncengine.Plan, preview syncengine.Preview) {
	t.Helper()
	newModule := restoreGatePreviewEntry(t, preview, model.EntryKey{TargetID: "neovim", Source: model.SourceFiles, FilePath: "lua/plugins/new-module.lua"})
	assert.Equal(t, syncengine.PreviewCreate, newModule.Action, "new module property: a new file must join as a create automatically")

	initEdit := restoreGatePreviewEntry(t, preview, model.EntryKey{TargetID: "neovim", Source: model.SourceFiles, FilePath: "init.lua"})
	terminalEdit := restoreGatePreviewEntry(t, preview, model.EntryKey{TargetID: "wm-custom", Source: model.SourceFiles, FilePath: "terminal.conf"})
	assert.Equal(t, syncengine.PreviewChange, initEdit.Action, "combined-edit property: Neovim edit must be part of the shared plan")
	assert.Equal(t, syncengine.PreviewChange, terminalEdit.Action, "combined-edit property: custom-root edit must be part of the same shared plan")
	assert.Equal(t, 2, countRestoreGateActionKind(preview, syncengine.PreviewChange), "combined-edit property: both edits must combine as changes in the same plan")

	oldName := restoreGatePreviewEntry(t, preview, model.EntryKey{TargetID: "neovim", Source: model.SourceFiles, FilePath: "lua/plugins/old.lua"})
	newName := restoreGatePreviewEntry(t, preview, model.EntryKey{TargetID: "neovim", Source: model.SourceFiles, FilePath: "lua/plugins/renamed.lua"})
	assert.Equal(t, syncengine.PreviewDelete, oldName.Action, "rename property: old path must be a delete")
	assert.Equal(t, syncengine.PreviewCreate, newName.Action, "rename property: new path must be a create")
	assert.NotEqual(t, syncengine.PreviewChange, oldName.Action, "rename property: rename must not silently overwrite the old path")
	assert.NotEqual(t, syncengine.PreviewChange, newName.Action, "rename property: rename must not silently overwrite the new path")

	assert.False(t, restoreGatePreviewHasKey(preview, fixture.localOnly), "local-only include property: excluded WM include must not enter the preview")
	assert.False(t, restoreGatePreviewHasKey(preview, fixture.unsafe), "unsafe-link property: skipped escaping link must not enter the preview")
	assert.Equal(t, 5, countRestoreGateActions(preview), "restore gate plan must contain two edits, one new module, and a delete/create rename")
	assert.Equal(t, 5, countRestoreGatePlanActions(plan), "reconciliation plan must contain the same five actionable paths")
}

func countRestoreGateActions(preview syncengine.Preview) int {
	count := 0
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Action != "" {
				count++
			}
		}
	}
	return count
}

func countRestoreGateActionKind(preview syncengine.Preview, action syncengine.PreviewAction) int {
	count := 0
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Action == action {
				count++
			}
		}
	}
	return count
}

func countRestoreGatePlanActions(plan syncengine.Plan) int {
	count := 0
	for _, decision := range plan.Decisions {
		if decision.Action == syncengine.ActionUpload || decision.Action == syncengine.ActionDownload || decision.Action == syncengine.ActionDeleteLocal || decision.Action == syncengine.ActionDeleteRemote {
			count++
		}
	}
	return count
}

func restoreGatePreviewEntry(t *testing.T, preview syncengine.Preview, key model.EntryKey) syncengine.PreviewEntry {
	t.Helper()
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Key == key {
				return entry
			}
		}
	}
	require.FailNow(t, "expected path was not represented in preview", "%s/%s", key.TargetID, key.FilePath)
	return syncengine.PreviewEntry{}
}

func restoreGatePreviewHasKey(preview syncengine.Preview, key model.EntryKey) bool {
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Key == key {
				return true
			}
		}
	}
	return false
}

func assertMissingRootRefusal(t *testing.T, fixture restoreGateFixture, store *state.Store, baseEntries []model.Entry, initial restoreGateCapture, remoteEntries []model.Entry, completePreview syncengine.Preview, originalTree map[string]treeEntry) {
	t.Helper()
	missingCapture, err := files.Capture(files.Root{TargetID: "wm-custom", Path: filepath.Join(fixture.base, "missing-wm-root"), Kind: model.SelectionDirectory})
	require.NoError(t, err, "missing root capture must return a named unknown observation")
	require.Len(t, missingCapture.Observations, 1, "missing root capture must report exactly the root observation")
	assert.Equal(t, model.ObservationUnknown, missingCapture.Observations[0].State, "missing root property: capture must not infer absence")
	assert.Equal(t, ".", missingCapture.Observations[0].Identity.FilePath, "missing root property: unknown reason must name the root path")

	uncertain := restoreGateCapture{observations: make([]model.Observation, 0, len(initial.observations)), covered: []string{"neovim"}}
	for _, observation := range initial.observations {
		if observation.Identity.TargetID != "wm-custom" {
			uncertain.observations = append(uncertain.observations, observation)
		}
	}
	uncertain.observations = append(uncertain.observations, missingCapture.Observations...)
	_, incomplete := reconcileRestoreGate(t, fixture.targets, baseEntries, uncertain, remoteEntries)
	rootDecision := restoreGatePreviewEntry(t, incomplete, model.EntryKey{TargetID: "wm-custom", Source: model.SourceFiles, FilePath: "."})
	assert.Equal(t, syncengine.PreviewStateUnknown, rootDecision.State, "missing root property: preview must name the unknown root")
	assert.Equal(t, syncengine.PreviewReasonUnknown, rootDecision.Reason, "missing root property: preview must report the unknown reason")
	assert.False(t, incomplete.Complete, "missing root property: incomplete coverage must prevent apply")

	firstTargetPath := filepath.Join(fixture.roots["neovim"], "init.lua")
	before := readRestoreGateFile(t, firstTargetPath)
	applyErr := syncengine.Apply(context.Background(), store, restoreGateApplyRequest(fixture.roots, incomplete, restoreGatePostimages(t, completePreview, remoteEntries)))
	var notActionable *syncengine.NotActionableError
	require.ErrorAs(t, applyErr, &notActionable, "missing root property: blocked entry must be non-actionable")
	assert.Equal(t, syncengine.ActionBlocked, notActionable.Action, "missing root property: refusal must name the blocked reconciler action")
	assert.Equal(t, before, readRestoreGateFile(t, firstTargetPath), "missing root property: refusal must not partially apply the valid Neovim change")
	assert.Equal(t, originalTree, readRestoreGateTree(t, fixture.treeRoot), "missing root property: refusal must leave the whole fixture unchanged")

	assert.Empty(t, restoreGateJournalEntries(t, store), "missing root refusal must not publish partial journal operations")
}

func assertUnsafeLinkRefusal(t *testing.T, fixture restoreGateFixture, store *state.Store, preview syncengine.Preview, remoteEntries []model.Entry, originalTree map[string]treeEntry) {
	t.Helper()
	badPreview := preview
	badPreview.Targets = append([]syncengine.PreviewTarget(nil), preview.Targets...)
	unsafeEntry := syncengine.PreviewEntry{Key: fixture.unsafe, Action: syncengine.PreviewCreate, DecisionAction: syncengine.ActionDownload}
	for index := range badPreview.Targets {
		badPreview.Targets[index].Entries = append([]syncengine.PreviewEntry(nil), badPreview.Targets[index].Entries...)
		if badPreview.Targets[index].ID == fixture.unsafe.TargetID {
			badPreview.Targets[index].Entries = append(badPreview.Targets[index].Entries, unsafeEntry)
		}
	}
	unsafeBytes := []byte("must not replace a link\n")
	digest := sha256.Sum256(unsafeBytes)
	content := restoreGatePostimages(t, preview, remoteEntries)
	content = append(content, syncengine.Postimage{TargetID: fixture.unsafe.TargetID, Key: fixture.unsafe.FilePath, Data: unsafeBytes, Digest: digest[:], Mode: 0o600})
	firstTargetPath := filepath.Join(fixture.roots["neovim"], "init.lua")
	before := readRestoreGateFile(t, firstTargetPath)
	applyErr := syncengine.Apply(context.Background(), store, restoreGateApplyRequest(fixture.roots, badPreview, content))
	var unsupported *syncengine.UnsupportedApplyEntryError
	require.True(t, errors.As(applyErr, &unsupported), "unsafe link property: a hand-constructed link operation must return a typed refusal")
	assert.Equal(t, fixture.unsafe, unsupported.Key, "unsafe link property: refusal must identify the escaping path")
	assert.Equal(t, "symbolic links are not applied", unsupported.Reason, "unsafe link property: refusal must name the symlink reason")
	assert.Equal(t, before, readRestoreGateFile(t, firstTargetPath), "unsafe link property: refusal must not partially apply earlier Neovim operations")
	linkTarget, err := os.Readlink(filepath.Join(fixture.roots[fixture.unsafe.TargetID], fixture.unsafe.FilePath))
	require.NoError(t, err, "unsafe link property: refusal must leave the link in place")
	assert.Equal(t, fixture.secret, linkTarget, "unsafe link property: refusal must not replace or follow the external link")
	assert.Equal(t, originalTree, readRestoreGateTree(t, fixture.treeRoot), "unsafe link refusal must leave the full fixture unchanged")
	assert.Empty(t, restoreGateJournalEntries(t, store), "unsafe link refusal must not journal a partial operation")
}

func restoreGatePostimages(t *testing.T, preview syncengine.Preview, remoteEntries []model.Entry) []syncengine.Postimage {
	t.Helper()
	remoteByKey := make(map[model.EntryKey]model.Entry, len(remoteEntries))
	for _, entry := range remoteEntries {
		remoteByKey[entry.Identity()] = entry
	}
	postimages := make([]syncengine.Postimage, 0)
	for _, target := range preview.Targets {
		for _, previewEntry := range target.Entries {
			if previewEntry.Action != syncengine.PreviewCreate && previewEntry.Action != syncengine.PreviewChange {
				continue
			}
			entry, exists := remoteByKey[previewEntry.Key]
			require.True(t, exists, "preview postimage source must exist for %s/%s", target.ID, previewEntry.Key.FilePath)
			require.NotNil(t, entry.File, "filesystem postimage must be a file entry")
			require.Equal(t, model.FileRegular, entry.File.Kind, "filesystem postimage must be a regular file")
			digest := sha256.Sum256(entry.File.Content)
			postimages = append(postimages, syncengine.Postimage{
				TargetID: previewEntry.Key.TargetID,
				Key:      previewEntry.Key.FilePath,
				Data:     append([]byte(nil), entry.File.Content...),
				Digest:   digest[:],
				Mode:     os.FileMode(entry.File.Mode),
			})
		}
	}
	return postimages
}

func restoreGateApplyRequest(roots map[string]string, preview syncengine.Preview, content []syncengine.Postimage) syncengine.ApplyRequest {
	return syncengine.ApplyRequest{
		Preview: preview, Roots: cloneRestoreGateRoots(roots), ModePolicy: syncengine.ModePolicy{Default: 0o600}, Content: content,
		Now: restoreGateClock,
	}
}

func restoreGateClock() time.Time {
	return time.Unix(100, 0)
}

func assertRestoreGateConverged(t *testing.T, targets []model.Target, remoteEntries []model.Entry, captured restoreGateCapture) {
	t.Helper()
	_, converged := reconcileRestoreGate(t, targets, remoteEntries, captured, remoteEntries)
	assert.True(t, converged.Complete, "convergence property: post-apply preview must be complete")
	assert.Equal(t, 0, countRestoreGateActions(converged), "convergence property: post-apply preview must have nothing to apply")
}

func restoreGateEntryKeys(entries []model.Entry) []model.EntryKey {
	keys := make([]model.EntryKey, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Identity())
	}
	return keys
}

func restoreGateCanonicalEntries(t *testing.T, entries []model.Entry) []model.Entry {
	t.Helper()
	canonical := cloneRestoreGateEntries(entries)
	sort.Slice(canonical, func(i, j int) bool {
		return restoreGateKeyLess(canonical[i].Identity(), canonical[j].Identity())
	})
	return canonical
}

func cloneRestoreGateEntries(entries []model.Entry) []model.Entry {
	cloned := make([]model.Entry, len(entries))
	for index, entry := range entries {
		cloned[index] = entry
		if entry.File != nil {
			file := *entry.File
			file.Content = append([]byte(nil), entry.File.Content...)
			cloned[index].File = &file
		}
		if entry.Setting != nil {
			setting := *entry.Setting
			if entry.Setting.Value != nil {
				value := *entry.Setting.Value
				setting.Value = &value
			}
			cloned[index].Setting = &setting
		}
	}
	return cloned
}

func restoreGateKeyLess(left, right model.EntryKey) bool {
	if left.TargetID != right.TargetID {
		return left.TargetID < right.TargetID
	}
	if left.Source != right.Source {
		return left.Source < right.Source
	}
	return left.FilePath < right.FilePath
}

func restoreGateJournalEntries(t *testing.T, store *state.Store) []state.JournalEntry {
	t.Helper()
	entries, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err, "journal entries must be readable")
	return entries
}

func restoreGateJournalEntry(t *testing.T, entries []state.JournalEntry, targetID, filePath string) state.JournalEntry {
	t.Helper()
	for _, entry := range entries {
		if entry.Identity.TargetID == targetID && entry.Identity.FilePath == filePath && entry.State == "applied" {
			return entry
		}
	}
	require.FailNow(t, "applied journal row for expected file was not found", "%s/%s", targetID, filePath)
	return state.JournalEntry{}
}

func cloneRestoreGateRoots(roots map[string]string) map[string]string {
	cloned := make(map[string]string, len(roots))
	for targetID, root := range roots {
		cloned[targetID] = root
	}
	return cloned
}

func readRestoreGateTree(t *testing.T, root string) map[string]treeEntry {
	t.Helper()
	tree := make(map[string]treeEntry)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		captured := treeEntry{mode: info.Mode().Perm()}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			captured.kind = "symlink"
			captured.link, err = os.Readlink(path)
		case info.IsDir():
			captured.kind = "directory"
		case info.Mode().IsRegular():
			captured.kind = "file"
			captured.content, err = os.ReadFile(path)
		default:
			return errors.New("fixture tree contains an unsupported entry")
		}
		if err != nil {
			return err
		}
		tree[filepath.ToSlash(relative)] = captured
		return nil
	})
	require.NoError(t, err, "synthetic tree must be readable for byte-for-byte comparison")
	return tree
}

func assertTreeMatchesWithUserEdit(t *testing.T, original, got map[string]treeEntry, editedPath string, editedBytes []byte) {
	t.Helper()
	expected := make(map[string]treeEntry, len(original))
	for path, entry := range original {
		expected[path] = entry
	}
	originalEntry, exists := expected[editedPath]
	require.True(t, exists, "edited path must be present in original tree")
	originalEntry.content = append([]byte(nil), editedBytes...)
	expected[editedPath] = originalEntry
	assert.Equal(t, expected, got, "second rollback must byte-match the original tree except for the deliberately preserved newer edit")
}
