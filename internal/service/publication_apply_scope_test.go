package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func newPublicationApplySettingsTarget(t *testing.T) config.Target {
	t.Helper()
	policy, err := config.ApprovedGNOMEPolicy([]string{"appearance"})
	require.NoError(t, err)
	return config.Target{
		ID: "desktop", Source: model.SourceGNOME, Mode: config.Review, GNOMEPolicy: &policy,
	}
}

func TestPlanPublicationApplyIgnoresAConfiguredUnpublishedTarget(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.configuration.Targets = append(fixture.configuration.Targets, newPublicationApplySettingsTarget(t))
	fixture.write(t, "note.ini", "before")

	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "before"}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"note.ini": "content"}))
	request := fixture.request(fixture.local, base, remote)
	plan, err := PlanPublicationApply(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, 1, plan.Changes)
	require.Len(t, plan.Entries, 1)
	assert.Equal(t, fixture.target.ID, plan.Entries[0].TargetID)
}

func TestPlanPublicationApplyRefusesAPublishedTargetItCannotWrite(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	settings := newPublicationApplySettingsTarget(t)
	fixture.configuration.Targets = append(fixture.configuration.Targets, settings)

	remote := fixture.targetSnapshot(nil)
	portable, err := settings.Model()
	require.NoError(t, err)
	remote.Targets = append(remote.Targets, portable)

	_, err = PlanPublicationApply(context.Background(), fixture.request(fixture.local, fixture.emptySnapshot(), remote))
	requirePublicationApplyRefusal(t, err, "apply-plan", "target_unsupported")
}

func TestPlanPublicationApplyRefusesAPublishedRootMismatch(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "applied", "other"), 0o700))

	remote := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID: fixture.portable.ID, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "applied/other", Kind: model.SelectionDirectory},
		}},
	}
	_, err := PlanPublicationApply(context.Background(), fixture.request(fixture.local, fixture.emptySnapshot(), remote))
	requirePublicationApplyRefusal(t, err, "apply-plan", "root_mismatch")
}

func TestPlanPublicationApplyIgnoresBaseEntriesFromADifferentRoot(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	base := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID: fixture.portable.ID, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "applied/elsewhere", Kind: model.SelectionDirectory},
		}},
		Entries: publicationPreviewFileEntries(fixture.target.ID, map[string]string{"kept.ini": "local"}),
	}

	fixture.write(t, "kept.ini", "local")
	plan, err := PlanPublicationApply(
		context.Background(),
		fixture.request(
			fixture.local,
			base,
			fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{"kept.ini": "local"})),
		),
	)
	require.NoError(t, err)
	assert.Equal(t, 0, plan.Changes)
	for _, entry := range plan.Entries {
		assert.NotEqual(t, PublicationApplyDelete, entry.Operation, "a foreign base authorized a deletion")
	}

	require.NoError(t, os.WriteFile(fixture.path("sentinel.ini"), []byte("local"), 0o600))
	_, err = PlanPublicationApply(
		context.Background(),
		fixture.request(fixture.local, base, fixture.targetSnapshot(nil)),
	)
	requirePublicationApplyRefusal(t, err, "apply-plan", "plan_unresolved")
	fixture.assertNoJournalRows(t)
}

func TestPlanPublicationApplySkipsAnUnconfiguredPublishedTarget(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, "applied", "unused"), 0o700))

	remote := fixture.targetSnapshot(nil)
	remote.Targets = append(remote.Targets, model.Target{
		ID: "unconfigured", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "applied/unused", Kind: model.SelectionDirectory},
	})
	plan, err := PlanPublicationApply(context.Background(), fixture.request(fixture.local, fixture.emptySnapshot(), remote))
	require.NoError(t, err)
	assert.Equal(t, 0, plan.Changes)
	assert.Empty(t, plan.Entries)
}

func TestResolvePublicationApplyJournalReportsLiveAndUnsettledRows(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "done")
	postimage := publicationstate.ObservedJournalFile([]byte("done"))
	postimage.Mode = 0o600
	_, err := fixture.journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: fixture.vault, Operation: "apply", DestinationDir: fixture.root, DestinationPath: "note.ini",
		Anchor: fixture.anchor(t), Postimage: postimage, SeenFloorRevision: fixture.floor,
	})
	require.NoError(t, err)

	status, err := ResolvePublicationApplyJournal(context.Background(), fixture.journal, fixture.floor)
	require.NoError(t, err)
	assert.Equal(t, 1, status.Live)
	assert.Equal(t, 0, status.Unsettled)
	assert.False(t, status.Blocked)

	status, err = ResolvePublicationApplyJournal(context.Background(), fixture.journal, fixture.floor)
	require.NoError(t, err)
	assert.Equal(t, 0, status.Live, "a resolved row stayed live")
	assert.False(t, status.Blocked)

	fixture.write(t, "note.ini", "third")
	preimage := publicationstate.ObservedJournalFile([]byte("before"))
	preimage.Mode = 0o600
	_, err = fixture.journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: fixture.vault, Operation: "apply", DestinationDir: fixture.root, DestinationPath: "note.ini",
		Anchor: fixture.anchor(t), Preimage: &preimage, PreimageBytes: []byte("before"),
		Postimage: postimage, SeenFloorRevision: fixture.floor,
	})
	require.NoError(t, err)

	status, err = ResolvePublicationApplyJournal(context.Background(), fixture.journal, fixture.floor)
	require.NoError(t, err)
	assert.Equal(t, 1, status.Live)
	assert.Equal(t, 1, status.Unsettled)
	assert.True(t, status.Blocked)
}

func TestResolvePublicationApplyJournalRefusesAPendingRollback(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "after")
	preimage := publicationstate.ObservedJournalFile([]byte("before"))
	preimage.Mode = 0o600
	postimage := publicationstate.ObservedJournalFile([]byte("after"))
	postimage.Mode = 0o600
	entry, err := fixture.journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: fixture.vault, Operation: "apply", DestinationDir: fixture.root, DestinationPath: "note.ini",
		Anchor: fixture.anchor(t), Preimage: &preimage, PreimageBytes: []byte("before"), Postimage: postimage,
		SeenFloorRevision: fixture.floor,
	})
	require.NoError(t, err)
	require.NoError(t, fixture.journal.CompleteJournal(context.Background(), entry, postimage))
	require.NoError(t, fixture.journal.BeginRollback(context.Background(), entry))
	fixture.write(t, "note.ini", "in-between")

	status, err := ResolvePublicationApplyJournal(context.Background(), fixture.journal, fixture.floor)
	require.NoError(t, err)
	assert.Equal(t, 1, status.Live)
	assert.Equal(t, 1, status.Unsettled, "a live rollback was treated as settled")
	assert.True(t, status.Blocked)
}

func TestComposePublicationSyncSnapshotKeepsATargetTheRemoteOmits(t *testing.T) {
	fixture := newPublicationPushFixture(t)
	require.NoError(t, os.MkdirAll(filepath.Join(fixture.paths.Home, "other"), 0o700))
	require.NoError(
		t,
		os.WriteFile(filepath.Join(fixture.paths.Home, "other", "kept.conf"), []byte("kept"), 0o600),
	)
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{
		ID: "other", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	})
	filesPortable, err := fixture.configuration.Targets[0].Model()
	require.NoError(t, err)
	otherPortable, err := fixture.configuration.Targets[1].Model()
	require.NoError(t, err)

	floor := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{filesPortable, otherPortable},
		Entries: append(
			publicationPreviewFileEntries("files", map[string]string{"init.lua": "synthetic push payload"}),
			publicationPreviewFileEntries("other", map[string]string{"kept.conf": "kept"})...,
		),
	}
	remote := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{filesPortable},
		Entries: publicationPreviewFileEntries("files", map[string]string{"init.lua": "synthetic push payload"}),
	}
	snapshot, err := fixture.coordinator.ComposePublicationSyncSnapshot(
		context.Background(),
		PublicationSyncSnapshotRequest{
			Configuration:  fixture.configuration,
			FloorSnapshot:  floor,
			RemoteSnapshot: remote,
			PublicationID:  [16]byte{0x51, 0x01},
		},
	)
	require.NoError(t, err)
	entries, defined := publicationSnapshotTargetEntries(snapshot, "other")
	require.True(t, defined)
	require.Len(t, entries, 1, "the sync candidate dropped a target the pull does not touch")
	assert.Equal(t, "kept.conf", entries[0].File.Path)
}
