package syncengine

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPreviewMapsActionsAndPackerSizes(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	baseChanged := regular("a-change", "old")
	baseDeleted := regular("b-delete", "old")
	baseDownloaded := regular("d-download", "before")
	localChanged := model.Entry{TargetID: "files", File: &model.FileEntry{Path: "a-change", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("new-content"), Mode: 0o640}}
	localCreated := model.Entry{TargetID: "files", File: &model.FileEntry{Path: "c-create", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("create"), Mode: 0o600}}
	remoteDownloaded := model.Entry{TargetID: "files", File: &model.FileEntry{Path: "d-download", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("remote-change"), Mode: 0o644}}
	remoteCreated := regular("e-download-create", "remote-create")
	base := BaseView{Status: BaseKnown, Entries: []model.Entry{baseDeleted, baseChanged, baseDownloaded}}
	local := LocalView{Entries: []model.Entry{localCreated, localChanged, baseDownloaded}, Coverage: []string{"files"}}
	remote := []model.Entry{baseChanged, baseDeleted, remoteDownloaded, remoteCreated}
	observations := []model.Observation{
		{State: model.ObservationPresent, Identity: localChanged.Identity(), Entry: &localChanged},
		{State: model.ObservationMissing, Identity: baseDeleted.Identity()},
		{State: model.ObservationPresent, Identity: localCreated.Identity(), Entry: &localCreated},
		{State: model.ObservationPresent, Identity: baseDownloaded.Identity(), Entry: &baseDownloaded},
		{State: model.ObservationMissing, Identity: remoteCreated.Identity()},
	}

	plan, err := Reconcile(base, local, remote, options)
	require.NoError(t, err)
	preview, err := BuildPreview(plan, targets, observations)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	require.Len(t, preview.Targets[0].Entries, 5)
	assert.Equal(t, []string{"a-change", "b-delete", "c-create", "d-download", "e-download-create"}, []string{
		preview.Targets[0].Entries[0].Key.FilePath,
		preview.Targets[0].Entries[1].Key.FilePath,
		preview.Targets[0].Entries[2].Key.FilePath,
		preview.Targets[0].Entries[3].Key.FilePath,
		preview.Targets[0].Entries[4].Key.FilePath,
	}, "entries are in deterministic path order")
	assert.Equal(t, PreviewChange, preview.Targets[0].Entries[0].Action, "changed input action")
	assert.Equal(t, PreviewDelete, preview.Targets[0].Entries[1].Action, "missing input action")
	assert.Equal(t, PreviewCreate, preview.Targets[0].Entries[2].Action, "new local input action")
	assert.Equal(t, PreviewChange, preview.Targets[0].Entries[3].Action, "changed remote input action")
	assert.Equal(t, PreviewCreate, preview.Targets[0].Entries[4].Action, "new remote input action")
	assert.Equal(t, PreviewStateMissing, preview.Targets[0].Entries[1].State, "missing state")
	assert.Equal(t, PreviewReasonMissing, preview.Targets[0].Entries[1].Reason, "missing reason")
	assert.Equal(t, int64(len(localChanged.File.Content)), preview.Targets[0].Entries[0].Size, "changed file size")
	assert.Equal(t, int64(0), preview.Targets[0].Entries[1].Size, "delete size")
	assert.Equal(t, int64(len(localCreated.File.Content)), preview.Targets[0].Entries[2].Size, "created file size")
	assert.Equal(t, int64(len(remoteDownloaded.File.Content)), preview.Targets[0].Entries[3].Size, "downloaded file size")
	assert.Equal(t, int64(len(remoteCreated.File.Content)), preview.Targets[0].Entries[4].Size, "downloaded create size")

	digest := sha256.Sum256(localChanged.File.Content)
	require.NotNil(t, preview.Targets[0].Entries[0].Preimage, "present file preimage")
	assert.Equal(t, hex.EncodeToString(digest[:]), preview.Targets[0].Entries[0].Preimage.Digest, "preimage digest")
	assert.Equal(t, localChanged.File.Mode, preview.Targets[0].Entries[0].Preimage.Mode, "preimage mode")
	require.NotNil(t, preview.Targets[0].Entries[2].Preimage, "created file preimage")
	assert.Equal(t, localCreated.File.Mode, preview.Targets[0].Entries[2].Preimage.Mode, "created preimage mode")
	require.NotNil(t, preview.Targets[0].Entries[3].Preimage, "downloaded file preimage")
	assert.Equal(t, baseDownloaded.File.Mode, preview.Targets[0].Entries[3].Preimage.Mode, "download preimage mode")
	assert.Nil(t, preview.Targets[0].Entries[1].Preimage, "missing observation has no preimage")
	assert.Nil(t, preview.Targets[0].Entries[4].Preimage, "download create has no observed preimage")

	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: targets, Entries: []model.Entry{localChanged, localCreated, remoteDownloaded, remoteCreated}}
	estimate, err := vault.Estimate(snapshot)
	require.NoError(t, err)
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	assert.Equal(t, estimate.PlaintextBytes, preview.TransferBytes, "transfer total follows packer accounting")
	assert.Equal(t, packed.PlaintextBytes, preview.TransferBytes, "transfer total matches packed transfer plaintext bytes")
	assert.Equal(t, estimate.PlaintextBytes, preview.ResultingSnapshotBytes, "resulting snapshot total follows packer accounting")
	assert.True(t, preview.Complete, "all entries have a resolved result")
	assert.Equal(t, 0, preview.UnresolvedEntries, "unresolved entry count")
}

func TestBuildPreviewSeparatesTransferAndResultingSnapshotSizes(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	baseChanged := regular("changed", "before")
	baseUnchanged := regular("unchanged", "keep-this-in-snapshot")
	baseDeleted := regular("deleted", "gone")
	localChanged := regular("changed", "new-transfer")
	localUnchanged := regular("unchanged", "keep-this-in-snapshot")
	base := BaseView{Status: BaseKnown, Entries: []model.Entry{baseChanged, baseUnchanged, baseDeleted}}
	local := LocalView{Entries: []model.Entry{localChanged, localUnchanged}, Coverage: []string{"files"}}
	remote := []model.Entry{baseChanged, baseUnchanged, baseDeleted}
	observations := []model.Observation{
		{State: model.ObservationPresent, Identity: localChanged.Identity(), Entry: &localChanged},
		{State: model.ObservationPresent, Identity: localUnchanged.Identity(), Entry: &localUnchanged},
		{State: model.ObservationMissing, Identity: baseDeleted.Identity()},
	}
	plan, err := Reconcile(base, local, remote, options)
	require.NoError(t, err)
	preview, err := BuildPreview(plan, targets, observations)
	require.NoError(t, err)
	require.Len(t, preview.Targets[0].Entries, 3)

	transferSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: targets, Entries: []model.Entry{localChanged}}
	resultSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: targets, Entries: []model.Entry{localChanged, localUnchanged}}
	transferEstimate, err := vault.Estimate(transferSnapshot)
	require.NoError(t, err)
	resultEstimate, err := vault.Estimate(resultSnapshot)
	require.NoError(t, err)
	packed, err := vault.Pack(resultSnapshot)
	require.NoError(t, err)
	assert.Equal(t, transferEstimate.PlaintextBytes, preview.TransferBytes, "transfer bytes match packer accounting")
	assert.Equal(t, resultEstimate.PlaintextBytes, preview.ResultingSnapshotBytes, "resulting snapshot bytes match packer accounting")
	assert.Equal(t, packed.PlaintextBytes, preview.ResultingSnapshotBytes, "resulting bytes match packed snapshot plaintext")
	assert.Equal(t, int64(len(localChanged.File.Content)), preview.Targets[0].Entries[0].Size, "changed file transfer size")
	assert.Equal(t, PreviewDelete, preview.Targets[0].Entries[1].Action, "delete entry ordering")
	assert.Equal(t, int64(0), preview.Targets[0].Entries[1].Size, "delete contributes no transfer size")
	assert.Equal(t, int64(0), preview.Targets[0].Entries[1].SnapshotBytes, "delete contributes no resulting snapshot bytes")
	assert.Equal(t, int64(0), preview.Targets[0].Entries[2].Size, "unchanged file has no transfer size")
	assert.Equal(t, int64(len(localUnchanged.File.Content)), preview.Targets[0].Entries[2].SnapshotBytes, "unchanged file contributes to resulting snapshot")
	assert.Equal(t, preview.TransferBytes+int64(len(localUnchanged.File.Content)), preview.ResultingSnapshotBytes, "the totals differ by unchanged payload")
	assert.True(t, preview.Complete, "resolved deletion and unchanged entries are complete")
	assert.Equal(t, 0, preview.UnresolvedEntries, "unresolved entry count")
}

func TestBuildPreviewPreservesUnknownAndMapsUntracked(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	unknownEntry := regular("a-unknown", "base")
	untrackedEntry := regular("b-untracked", "remote-data")
	base := BaseView{Status: BaseKnown, Entries: []model.Entry{unknownEntry, untrackedEntry}}
	local := LocalView{
		Unknown:   []model.EntryKey{unknownEntry.Identity()},
		Untracked: []model.EntryKey{untrackedEntry.Identity()},
		Coverage:  []string{"files"},
	}
	plan, err := Reconcile(base, local, []model.Entry{unknownEntry, untrackedEntry}, options)
	require.NoError(t, err)
	observations := []model.Observation{
		{State: model.ObservationUnknown, Identity: unknownEntry.Identity()},
		{State: model.ObservationUntracked, Identity: untrackedEntry.Identity()},
	}
	preview, err := BuildPreview(plan, targets, observations)
	require.NoError(t, err)
	require.Len(t, preview.Targets[0].Entries, 2)
	unknown := preview.Targets[0].Entries[0]
	assert.Equal(t, PreviewStateUnknown, unknown.State, "unknown remains a state")
	assert.Empty(t, unknown.Action, "unknown is not an action")
	assert.Equal(t, PreviewReasonUnknown, unknown.Reason, "unknown reason")
	assert.Nil(t, unknown.Preimage, "unknown has no preimage")
	untracked := preview.Targets[0].Entries[1]
	assert.Equal(t, PreviewCreate, untracked.Action, "untracked maps to create")
	assert.Equal(t, PreviewReasonUntracked, untracked.Reason, "untracked reason")
	assert.Nil(t, untracked.Preimage, "untracked observation has no preimage")
	assert.Equal(t, int64(len(untrackedEntry.File.Content)), untracked.Size, "create uses the explicit remote entry size")
	assert.False(t, preview.Complete, "unknown item makes resulting size incomplete")
	assert.Equal(t, 1, preview.UnresolvedEntries, "unknown unresolved count")
}

func TestBuildPreviewDistinguishesConflictFromMissing(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	baseConflict := regular("conflict", "base")
	baseMissing := regular("missing", "base")
	localConflict := regular("conflict", "local")
	remoteConflict := regular("conflict", "remote")
	base := BaseView{Status: BaseKnown, Entries: []model.Entry{baseConflict, baseMissing}}
	local := LocalView{Entries: []model.Entry{localConflict}, Coverage: []string{"files"}}
	remote := []model.Entry{remoteConflict, baseMissing}
	observations := []model.Observation{
		{State: model.ObservationPresent, Identity: localConflict.Identity(), Entry: &localConflict},
		{State: model.ObservationMissing, Identity: baseMissing.Identity()},
	}
	plan, err := Reconcile(base, local, remote, options)
	require.NoError(t, err)
	preview, err := BuildPreview(plan, targets, observations)
	require.NoError(t, err)
	require.Len(t, preview.Targets[0].Entries, 2)
	conflict := preview.Targets[0].Entries[0]
	assert.Equal(t, PreviewStateConflict, conflict.State, "conflict state")
	assert.Equal(t, PreviewReasonConflict, conflict.Reason, "conflict reason")
	assert.Empty(t, conflict.Action, "conflict is not an action")
	assert.Equal(t, string(ReasonDivergence), conflict.Detail, "conflict detail")
	missing := preview.Targets[0].Entries[1]
	assert.Equal(t, PreviewStateMissing, missing.State, "missing state")
	assert.Equal(t, PreviewReasonMissing, missing.Reason, "missing has its own reason code")
	assert.Equal(t, PreviewDelete, missing.Action, "missing remains a delete action")
	assert.NotEqual(t, conflict.Reason, missing.Reason, "conflict and missing reason codes differ")
	assert.False(t, preview.Complete, "conflict makes resulting size incomplete")
	assert.Equal(t, 1, preview.UnresolvedEntries, "conflict unresolved count")
}

func TestBuildPreviewIncludesMissingObservationWithoutDecision(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	key := model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "not-in-base"}
	plan, err := Reconcile(BaseView{Status: BaseMissing}, LocalView{}, nil, options)
	require.NoError(t, err)
	preview, err := BuildPreview(plan, targets, []model.Observation{{State: model.ObservationMissing, Identity: key}})
	require.NoError(t, err)
	require.Len(t, preview.Targets[0].Entries, 1)
	assert.Equal(t, key, preview.Targets[0].Entries[0].Key, "missing observation identity")
	assert.Equal(t, PreviewStateMissing, preview.Targets[0].Entries[0].State, "missing state")
	assert.Equal(t, PreviewReasonMissing, preview.Targets[0].Entries[0].Reason, "missing reason")
	assert.Equal(t, "unmatched", preview.Targets[0].Entries[0].Detail, "missing observation has no matching decision")
	assert.False(t, preview.Complete, "unmatched missing observation makes resulting size incomplete")
	assert.Equal(t, 1, preview.UnresolvedEntries, "missing unresolved count")
}

func TestBuildPreviewKeepsMissingDescendantUnknownBelowUnknownAncestor(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	root := model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "."}
	child := model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "child"}
	plan, err := Reconcile(BaseView{Status: BaseMissing}, LocalView{Unknown: []model.EntryKey{root}}, nil, options)
	require.NoError(t, err)
	observations := []model.Observation{
		{State: model.ObservationUnknown, Identity: root},
		{State: model.ObservationMissing, Identity: child},
	}
	preview, err := BuildPreview(plan, targets, observations)
	require.NoError(t, err)
	require.Len(t, preview.Targets[0].Entries, 2)
	assert.Equal(t, PreviewStateUnknown, preview.Targets[0].Entries[0].State, "unknown root state")
	assert.Equal(t, PreviewStateUnknown, preview.Targets[0].Entries[1].State, "unknown ancestor takes precedence over missing descendant")
	assert.Equal(t, PreviewReasonUnknown, preview.Targets[0].Entries[1].Reason, "blocked descendant reason")
	assert.False(t, preview.Complete, "unknown subtree makes resulting size incomplete")
	assert.Equal(t, 2, preview.UnresolvedEntries, "unknown and unmatched descendant count")
}

func TestBuildPreviewReportsEscapingSymlinkRisk(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	baseEntry := symlink("link", "inside")
	observed := symlink("link", "../../outside")
	plan, err := Reconcile(
		BaseView{Status: BaseKnown, Entries: []model.Entry{baseEntry}},
		LocalView{Entries: []model.Entry{observed}, Coverage: []string{"files"}},
		[]model.Entry{baseEntry},
		options,
	)
	require.NoError(t, err)
	observation := model.Observation{State: model.ObservationPresent, Identity: observed.Identity(), Entry: &observed}
	preview, err := BuildPreview(plan, targets, []model.Observation{observation})
	require.NoError(t, err)
	require.Len(t, preview.Targets[0].Entries, 1)
	assert.Equal(t, []PreviewReason{PreviewReasonEscapingSymlink}, preview.Targets[0].Entries[0].Risks, "escaping symlink risk")
}

func TestBuildPreviewDoesNotMutateViewsOrReconcilePlan(t *testing.T) {
	options := fileBinding(t)
	targets := []model.Target{options.Bindings[0].Target}
	baseEntry := regular("config", "base-content")
	localEntry := regular("config", "observed-content")
	base := BaseView{Status: BaseKnown, Entries: []model.Entry{baseEntry}}
	local := LocalView{Entries: []model.Entry{localEntry}, Coverage: []string{"files"}}
	remote := []model.Entry{baseEntry}
	observations := []model.Observation{{State: model.ObservationPresent, Identity: localEntry.Identity(), Entry: &localEntry}}
	plan, err := Reconcile(base, local, remote, options)
	require.NoError(t, err)
	before := struct {
		Base         BaseView
		Local        LocalView
		Remote       []model.Entry
		Targets      []model.Target
		Observations []model.Observation
		Plan         Plan
	}{base, local, remote, targets, observations, plan}

	_, err = BuildPreview(plan, targets, observations)
	require.NoError(t, err)
	after := struct {
		Base         BaseView
		Local        LocalView
		Remote       []model.Entry
		Targets      []model.Target
		Observations []model.Observation
		Plan         Plan
	}{base, local, remote, targets, observations, plan}
	assert.True(t, reflect.DeepEqual(before, after), "preview construction mutated its supplied views or reconcile result")
}

func TestBuildPreviewOrdersTargetsByID(t *testing.T) {
	first := model.Target{ID: "alpha", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	second := model.Target{ID: "beta", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	preview, err := BuildPreview(Plan{}, []model.Target{second, first}, nil)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 2)
	assert.Equal(t, []string{"alpha", "beta"}, []string{preview.Targets[0].ID, preview.Targets[1].ID}, "targets are sorted by ID")
}

func TestBuildPreviewRejectsObservationWithoutTarget(t *testing.T) {
	_, err := BuildPreview(Plan{}, nil, []model.Observation{{
		State:    model.ObservationMissing,
		Identity: model.EntryKey{TargetID: "missing-target", Source: model.SourceFiles, FilePath: "config"},
	}})
	require.Error(t, err, "observation without a target must be rejected")
}
