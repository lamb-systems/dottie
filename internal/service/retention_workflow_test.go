package service

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorRestoreJournalsMultipleBoundFileAndSettingOperations(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	settings := &retentionRestoreSettings{values: make(map[model.EntryKey]syncengine.SettingValue)}
	settingTarget := approvedGNOMETarget(t)
	settingTarget.ID = "desktop"
	settingTarget.Mode = config.Review
	refs, err := approvedSettings(ctx, settings, settingTarget)
	require.NoError(t, err)
	for _, key := range []string{"gtk-theme", "cursor-theme"} {
		var identity model.EntryKey
		for _, ref := range refs {
			if ref.Key == key {
				identity = model.EntryKey{TargetID: settingTarget.ID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}
				break
			}
		}
		require.NotEmpty(t, identity.SettingKey, "the approved synthetic appearance matrix must include %s", key)
		settings.values[identity] = syncengine.SettingValue{Present: true, Type: "s", Text: "'local-" + key + "'", Writable: true}
	}
	configuration := fixture.coordinator.deps.Config.(*memoryConfig)
	settingTarget.Mode = config.Review
	configuration.value.Targets = append(configuration.value.Targets, settingTarget)
	fixture.coordinator.deps.Settings = settings
	require.NoError(t, fixture.store.PutTarget(ctx, state.TargetDescriptor{
		ID: settingTarget.ID, Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion,
		Mode: string(config.Review), CreatedAt: 1,
	}))
	secondFile := filepath.Join(fixture.paths.Home, "selected", "other.toml")
	require.NoError(t, os.WriteFile(secondFile, []byte("second = 'local'\n"), 0o600))
	initial, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, initial.Status)

	fixture.publishRemoteSnapshot(t, func(snapshot *model.Snapshot) {
		for index := range snapshot.Entries {
			entry := &snapshot.Entries[index]
			if entry.File != nil {
				switch entry.File.Path {
				case "prefs.toml":
					entry.File.Content = []byte("theme = 'remote'\n")
				case "other.toml":
					entry.File.Content = []byte("second = 'remote'\n")
				}
			} else if entry.Setting != nil && (entry.Setting.Key == "gtk-theme" || entry.Setting.Key == "cursor-theme") {
				entry.Setting.Value = &model.VariantValue{Type: "s", Text: "'remote-" + entry.Setting.Key + "'"}
			}
		}
	})
	firstDevice, firstPublic := newAdminNewcomer(t, "multi-journal-epoch-one")
	firstEnrollment := enrollWithFixture(t, fixture, firstDevice, firstPublic)
	clone := retentionClone(t, fixture, firstEnrollment.EncodedBundle)
	_, err = clone.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	secondDevice, secondPublic := newAdminNewcomer(t, "multi-journal-epoch-two")
	secondTransition := coordinatorEnroll(t, clone, fixture, secondDevice, secondPublic, secondDevice.DeviceID)
	assert.Equal(t, StatusCommitted, secondTransition.Status)
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	_, err = fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)

	fileCandidate, err := fixture.coordinator.Preview(ctx, selection, fixture.target.ID)
	require.NoError(t, err)
	require.Len(t, fileCandidate.Actions, 2)
	fileReport, err := fixture.coordinator.Restore(ctx, RestoreRequest{Selection: selection, TargetID: fixture.target.ID, Confirm: fileCandidate.Digest})
	require.NoError(t, err, "both bound file journal entries must apply without an inventory refresh between them")
	assert.Len(t, fileReport.Applied, 2)

	checkpoint := mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault)
	boundary := state.RetentionRecoveryPoint{Epoch: checkpoint.Epoch, SnapshotCID: bytes.Clone(checkpoint.SnapshotCID), PolicyDigest: checkpoint.PolicyDigest, ControlCID: bytes.Clone(checkpoint.ControlCID)}
	pruneRequest := state.RetentionPruneRequest{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID, Boundary: boundary, Now: fixture.clock}
	_, err = fixture.store.PlanRetentionPrune(ctx, pruneRequest)
	assert.ErrorIs(t, err, state.ErrRetentionRecoveryPointInventoryUnknown, "pruning refuses while the restore's retained inventory is incomplete")
	_, err = fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err, "verified refresh completes the new backup inventory")
	_, err = fixture.store.PlanRetentionPrune(ctx, pruneRequest)
	require.NoError(t, err, "pruning can plan again after the refresh completes the inventory")

	settingCandidate, err := fixture.coordinator.Preview(ctx, selection, settingTarget.ID)
	require.NoError(t, err)
	require.Len(t, settingCandidate.Actions, 2)
	settingReport, err := fixture.coordinator.Restore(ctx, RestoreRequest{Selection: selection, TargetID: settingTarget.ID, Confirm: settingCandidate.Digest})
	require.NoError(t, err, "both bound setting journal entries must apply without an inventory refresh between them")
	assert.Len(t, settingReport.Applied, 2)

	journal, err := fixture.store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	var fileEntries, settingEntries []state.JournalEntry
	for _, entry := range journal {
		if entry.Identity.TargetID == fixture.target.ID {
			fileEntries = append(fileEntries, entry)
		}
		if entry.Identity.TargetID == settingTarget.ID {
			settingEntries = append(settingEntries, entry)
		}
	}
	require.Len(t, fileEntries, 2)
	require.Len(t, settingEntries, 2)
	require.NotNil(t, fileEntries[0].Retention)
	for _, entry := range append(fileEntries, settingEntries...) {
		require.NotNil(t, entry.Retention)
		assert.Equal(t, uint64(2), entry.Retention.Epoch)
		assert.Equal(t, fileEntries[0].Retention.SnapshotCID, entry.Retention.SnapshotCID)
	}
}

type retentionRestoreSettings struct {
	values map[model.EntryKey]syncengine.SettingValue
}

func (settings *retentionRestoreSettings) Resolve(_ context.Context, _, schemaID, _ string) (string, error) {
	if schemaID == "org.gnome.desktop.interface" {
		return "/org/gnome/desktop/interface/", nil
	}
	return "/org/gnome/desktop/calendar/", nil
}

func (settings *retentionRestoreSettings) Capture(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
	capture := SettingsCapture{}
	for _, ref := range refs {
		key := model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}
		value, exists := settings.values[key]
		if !exists || !value.Present {
			continue
		}
		capture.Entries = append(capture.Entries, model.Entry{TargetID: targetID, Setting: &model.SettingEntry{
			SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key, State: model.SettingPresent,
			Value: &model.VariantValue{Type: value.Type, Text: value.Text},
		}})
	}
	return capture, nil
}

func (settings *retentionRestoreSettings) Backend() syncengine.SettingsBackend { return settings }

func (settings *retentionRestoreSettings) Observe(_ context.Context, key model.EntryKey) (syncengine.SettingValue, error) {
	value, exists := settings.values[key]
	if !exists {
		return syncengine.SettingValue{Writable: true}, nil
	}
	value.Writable = true
	return value, nil
}

func (settings *retentionRestoreSettings) Canonicalize(_ context.Context, _ model.EntryKey, valueType, text string) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{Present: true, Type: valueType, Text: text, Writable: true}, nil
}

func (settings *retentionRestoreSettings) Set(_ context.Context, key model.EntryKey, valueType, text string) error {
	settings.values[key] = syncengine.SettingValue{Present: true, Type: valueType, Text: text, Writable: true}
	return nil
}

func (settings *retentionRestoreSettings) Reset(_ context.Context, key model.EntryKey) error {
	settings.values[key] = syncengine.SettingValue{Writable: true}
	return nil
}

func TestCoordinatorRetentionKeepsCheckpointSnapshotAndLatestLaterEpoch(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}

	firstRead, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, RetentionAdmissionUpdated, firstRead.Retention.Admission)
	assert.Equal(t, fixture.genesis.SnapshotCID, mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID).RecoveryPoints[0].SnapshotCID)

	newcomer, publicDevice := newAdminNewcomer(t, "retention-epoch-one")
	enrollment := enrollWithFixture(t, fixture, newcomer, publicDevice)
	require.Equal(t, RetentionAdmissionUpdated, enrollment.Retention.Admission)
	checkpoint := mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault)
	require.Equal(t, uint64(1), checkpoint.Epoch)
	checkpointPoint := state.RetentionRecoveryPoint{Epoch: checkpoint.Epoch, SnapshotCID: bytes.Clone(checkpoint.SnapshotCID), PolicyDigest: checkpoint.PolicyDigest, ControlCID: bytes.Clone(checkpoint.ControlCID)}

	require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'checkpoint-epoch-publication'\n"), 0o600))
	checkpointPublication, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, checkpointPublication.Status)
	require.Equal(t, uint64(1), checkpointPublication.PublicationCount)
	declaration := mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
	require.Len(t, declaration.RecoveryPoints, 1)
	assert.Equal(t, checkpointPoint, declaration.RecoveryPoints[0], "a later ordinary publication must not replace the exact checkpoint point")

	clone := retentionClone(t, fixture, enrollment.EncodedBundle)
	_, err = clone.Pull(ctx, selection)
	require.NoError(t, err)
	secondNewcomer, secondPublic := newAdminNewcomer(t, "retention-epoch-two")
	secondTransition := coordinatorEnroll(t, clone, fixture, secondNewcomer, secondPublic, "retention-epoch-two")
	assert.Equal(t, StatusCommitted, secondTransition.Status)

	liveRead, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, uint64(2), liveRead.Read.EpochSeq)
	require.Equal(t, RetentionAdmissionUpdated, liveRead.Retention.Admission)
	liveStartCID := bytes.Clone(liveRead.Read.Control.HeadSnapshotCID)
	require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'later-live-epoch-publication'\n"), 0o600))
	livePublication, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, livePublication.Status)
	require.Equal(t, uint64(1), livePublication.PublicationCount)
	assert.Equal(t, RetentionAdmissionUpdated, livePublication.Retention.Admission)

	declaration = mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
	require.Len(t, declaration.RecoveryPoints, 2)
	assert.Equal(t, checkpointPoint, declaration.RecoveryPoints[0])
	assert.Equal(t, uint64(2), declaration.RecoveryPoints[1].Epoch)
	assert.NotEqual(t, liveStartCID, declaration.RecoveryPoints[1].SnapshotCID, "later epoch point is the latest authenticated publication, not its epoch-start snapshot")
	assert.Equal(t, livePublication.HeadCID, declaration.RecoveryPoints[1].SnapshotCID)
	assert.Equal(t, RetentionFloorUnknown, livePublication.Retention.Floors.Status, "unclassified applied-base payload holdings must remain explicit")
	assert.True(t, livePublication.Retention.Floors.HasRecoveryFloor)
	assert.Equal(t, uint64(1), livePublication.Retention.Floors.RecoveryFloor)
}

func TestRetentionFloorReportSeparatesRecoveryAndConfidentialityFloors(t *testing.T) {
	inventory := state.RetentionInventory{
		Points: []state.RetentionInventoryPoint{
			{RetentionRecoveryPoint: state.RetentionRecoveryPoint{Epoch: 3}, InventoryComplete: true},
			{RetentionRecoveryPoint: state.RetentionRecoveryPoint{Epoch: 5}, InventoryComplete: false},
		},
		KnownMaterialEpochs: []uint64{1, 3, 5},
	}
	floors := retentionFloors(inventory, 2)
	assert.True(t, floors.HasRecoveryFloor)
	assert.Equal(t, uint64(3), floors.RecoveryFloor)
	assert.True(t, floors.HasConfidentialityFloor)
	assert.Equal(t, uint64(1), floors.ConfidentialityFloor, "an older protected backup remains in the confidentiality floor")
	assert.Equal(t, RetentionFloorBelowPolicy, floors.Status)
	assert.True(t, floors.BelowPolicy)

	inventory.UnknownHoldingReasons = []string{"legacy-unbound-journal-backup"}
	floors = retentionFloors(inventory, 0)
	assert.Equal(t, RetentionFloorUnknown, floors.Status)
	assert.True(t, floors.CompromisedForConfidentiality)
	assert.Equal(t, []string{"legacy-unbound-journal-backup"}, floors.UnknownHoldingReasons)
}

func TestCoordinatorRetentionCapRefusalKeepsPreviousCompleteDeclaration(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	first, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, RetentionAdmissionUpdated, first.Retention.Admission)
	assert.True(t, mustRetentionInventory(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID).Points[0].InventoryComplete)

	firstNewcomer, firstPublic := newAdminNewcomer(t, "retention-cap-one")
	firstEnrollment := enrollWithFixture(t, fixture, firstNewcomer, firstPublic)
	clone := retentionClone(t, fixture, firstEnrollment.EncodedBundle)
	_, err = clone.Pull(ctx, selection)
	require.NoError(t, err)

	var beforeCap state.RetentionDeclaration
	for index := 2; index <= 4; index++ {
		newcomer, public := newAdminNewcomer(t, "retention-cap-"+string(rune('0'+index)))
		transition := coordinatorEnroll(t, clone, fixture, newcomer, public, "retention-cap-"+string(rune('0'+index)))
		assert.Equal(t, StatusCommitted, transition.Status)
		if index < 4 {
			read, readErr := fixture.coordinator.Pull(ctx, selection)
			require.NoError(t, readErr)
			assert.Equal(t, RetentionAdmissionUpdated, read.Retention.Admission)
			if index == 3 {
				beforeCap = mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
			}
		}
	}
	atCapRead, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, RetentionAdmissionAtCap, atCapRead.Retention.Admission)
	assert.Equal(t, RetentionReasonPointCap, atCapRead.Retention.Reason)
	current := mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
	assert.Equal(t, beforeCap.RecoveryPoints, current.RecoveryPoints, "cap refusal preserves the old complete declaration")
	assert.Equal(t, 3, len(current.RecoveryPoints))
}

func TestCoordinatorPruneUsesCheckpointBoundaryAndPreservesProtectedMaterial(t *testing.T) {
	var oldBodyReference, oldReference string
	fixture := retentionPruneFixture(t, func(fixture *pushFixture) {
		ctx := context.Background()
		oldPoint := state.RetentionRecoveryPoint{Epoch: 0, SnapshotCID: bytes.Clone(fixture.genesis.SnapshotCID), PolicyDigest: fixture.genesis.PolicyDigest, ControlCID: bytes.Clone(fixture.genesis.ControlCID)}
		oldBody, err := fixture.store.Payload(mustPayloadRefFromCID(t, fixture, oldPoint.SnapshotCID))
		require.NoError(t, err)
		oldReference, err = fixture.store.PutRetentionMaterialPayload(ctx, []byte("cross-subject protected sentinel"))
		require.NoError(t, err)
		oldBodyReference, err = fixture.store.PutRetentionMaterialPayload(ctx, oldBody)
		require.NoError(t, err)
		require.NoError(t, fixture.store.SetRetentionRecoveryPointMaterial(ctx, fixture.genesis.Vault, fixture.device.DeviceID, oldPoint, []string{oldBodyReference, oldReference}, nil))

		otherVault := [32]byte{0xE2}
		otherBody := []byte("other subject's required recovery point")
		otherPoint := state.RetentionRecoveryPoint{Epoch: 7, SnapshotCID: rawVaultCID(otherBody), PolicyDigest: [32]byte{0x17}, ControlCID: rawVaultCID([]byte("other control"))}
		_, err = fixture.store.ReplaceRetentionDeclarationWithMaterials(ctx, state.RetentionDeclaration{
			Vault: otherVault, DeviceID: "other-device", PolicyDigest: otherPoint.PolicyDigest, RetentionFloor: otherPoint.Epoch, DeclaredAt: 1,
			RecoveryPoints: []state.RetentionRecoveryPoint{otherPoint},
		}, []state.RetentionRecoveryPointMaterials{{Point: otherPoint, Payloads: [][]byte{otherBody, []byte("cross-subject protected sentinel")}}})
		require.NoError(t, err)
	})
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	declaration := mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
	checkpointPoint := declaration.RecoveryPoints[0]
	checkpoint := mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault)
	require.Equal(t, checkpoint.Epoch, checkpointPoint.Epoch)
	require.NoError(t, fixture.store.PutTarget(ctx, state.TargetDescriptor{ID: "target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, Mode: "review", LogicalBase: model.RootHome, LogicalPath: "selected", Kind: model.SelectionDirectory, CreatedAt: 1}))
	backupBefore := []byte("protected retained backup")
	preimage := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", backupBefore)
	postimage := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("postimage"))
	journal, err := fixture.store.AppendJournal(ctx, state.JournalEntry{
		ID: "retained-bound-backup", Operation: "replace", State: "pending", Stage: state.JournalStagePending,
		Identity: stateFileIdentity("retained.toml"), Preimage: preimage, Postimage: postimage,
		Retention: &state.RetentionBinding{Vault: fixture.genesis.Vault, Epoch: checkpointPoint.Epoch, SnapshotCID: bytes.Clone(checkpointPoint.SnapshotCID), PolicyDigest: checkpointPoint.PolicyDigest, ControlCID: bytes.Clone(checkpointPoint.ControlCID)},
		CreatedAt: fixture.clock.Unix(),
	}, backupBefore)
	require.NoError(t, err)
	_, err = fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err, "verified read refreshes the bound backup into the complete inventory")

	plan, err := fixture.coordinator.PlanPrune(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, RetentionPrunePlanned, plan.Status)
	require.Equal(t, checkpointPoint, plan.Plan.Boundary)
	var eligibleOldBody, protectedCrossSubject *state.RetentionPruneCandidate
	for index := range plan.Plan.Candidates {
		candidate := &plan.Plan.Candidates[index]
		if candidate.Kind == state.RetentionPruneCandidatePayload && candidate.Reference == oldBodyReference {
			eligibleOldBody = candidate
		}
		if candidate.Kind == state.RetentionPruneCandidatePayload && candidate.Reference == oldReference {
			protectedCrossSubject = candidate
		}
	}
	require.NotNil(t, eligibleOldBody)
	assert.True(t, eligibleOldBody.Eligible)
	require.NotNil(t, protectedCrossSubject)
	assert.False(t, protectedCrossSubject.Eligible)
	assert.Contains(t, protectedCrossSubject.Reasons, "tied to a retained recovery point")

	unconfirmed, err := fixture.coordinator.ApplyPrune(ctx, selection, false)
	require.NoError(t, err)
	assert.Equal(t, RetentionPruneConfirmationRequired, unconfirmed.Status)
	assert.Equal(t, plan.Plan.PayloadReferences, unconfirmed.Plan.PayloadReferences)
	_, err = fixture.store.Payload(oldBodyReference)
	require.NoError(t, err, "missing confirmation does not delete payloads")

	applied, err := fixture.coordinator.ApplyPrune(ctx, selection, true)
	require.NoError(t, err)
	assert.Equal(t, RetentionPruneApplied, applied.Status)
	assert.Equal(t, []string{oldBodyReference}, applied.Report.DeletedPayloads)
	assert.Empty(t, applied.Report.PrunedBackupIDs)
	_, err = fixture.store.Payload(oldBodyReference)
	assert.Error(t, err)
	crossAfter, err := fixture.store.Payload(oldReference)
	require.NoError(t, err)
	assert.Equal(t, []byte("cross-subject protected sentinel"), crossAfter)
	backupAfter, err := fixture.store.Payload(journal.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, backupBefore, backupAfter)
	assert.Equal(t, RetentionFloorMeetsPolicy, applied.Floors.Status)
	assert.Equal(t, uint64(0), applied.Floors.ConfidentialityFloor)
}

func TestCoordinatorPlanPruneMapsLiveHeadAndIncompleteInventoryRefusals(t *testing.T) {
	fixture := newPushFixture(t)
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	read, err := fixture.coordinator.Pull(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, RetentionAdmissionUpdated, read.Retention.Admission)
	planned, err := fixture.coordinator.PlanPrune(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, RetentionPruneRefused, planned.Status)
	assert.Equal(t, RetentionPruneReasonLiveHead, planned.Reason, "live head equal to checkpoint is not later")

	advanced := retentionPruneFixture(t, nil)
	advancedSelection := VaultSelection{Vault: advanced.genesis.Vault, DeviceID: advanced.device.DeviceID}
	inventory := mustRetentionInventory(t, advanced.store, advanced.genesis.Vault, advanced.device.DeviceID)
	point := inventory.Points[0].RetentionRecoveryPoint
	entry := appendTestRetentionBackup(t, advanced.store, advanced.genesis.Vault, advanced.device.DeviceID, point)
	assert.NotEmpty(t, entry.BackupRef)
	checkpoint := mustVaultCheckpoint(t, advanced.store, advanced.genesis.Vault)
	incomplete, err := advanced.coordinator.planPruneAtHeldPosition(context.Background(), advancedSelection, TrustMaterial{
		Selection: advancedSelection, Anchor: advanced.genesis.Anchor, Checkpoint: checkpoint,
	}, 0)
	require.NoError(t, err)
	assert.Equal(t, RetentionPruneRefused, incomplete.Status)
	assert.Equal(t, RetentionPruneReasonIncomplete, incomplete.Reason)
}

func appendTestRetentionBackup(t *testing.T, store *state.Store, vaultID [32]byte, deviceID string, point state.RetentionRecoveryPoint) state.JournalEntry {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.PutTarget(ctx, state.TargetDescriptor{ID: "target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, Mode: "review", LogicalBase: model.RootHome, LogicalPath: "selected", Kind: model.SelectionDirectory, CreatedAt: 1}))
	before, after := []byte("before bound backup"), []byte("after bound backup")
	entry, err := store.AppendJournal(ctx, state.JournalEntry{
		ID: "incomplete-retention-backup", Operation: "replace", State: "pending", Stage: state.JournalStagePending,
		Identity:  stateFileIdentity("incomplete.toml"),
		Preimage:  state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", before),
		Postimage: state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", after),
		Retention: &state.RetentionBinding{Vault: vaultID, Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID)},
		CreatedAt: 1,
	}, before)
	require.NoError(t, err)
	return entry
}

func retentionPruneFixture(t *testing.T, beforeTransition func(*pushFixture)) *pushFixture {
	t.Helper()
	fixture := newPushFixture(t)
	ctx := context.Background()
	_, err := fixture.coordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	if beforeTransition != nil {
		beforeTransition(fixture)
	}
	first, public := newAdminNewcomer(t, "prune-epoch-one")
	enrollment := enrollWithFixture(t, fixture, first, public)
	clone := retentionClone(t, fixture, enrollment.EncodedBundle)
	_, err = clone.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	second, secondPublic := newAdminNewcomer(t, "prune-epoch-two")
	transition := coordinatorEnroll(t, clone, fixture, second, secondPublic, "prune-epoch-two")
	assert.Equal(t, StatusCommitted, transition.Status)
	_, err = fixture.coordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	return fixture
}

func retentionClone(t *testing.T, fixture *pushFixture, bundle []byte) *Coordinator {
	t.Helper()
	store, paths := openCoordinatorStateWithPaths(t)
	keys := &pushDeviceKeyring{devices: map[string]vault.DeviceMaterial{fixture.device.DeviceID: fixture.device}}
	clone := newNewcomerCoordinator(t, fixture, store, paths, keys)
	clone.deps.Publisher = &pushTestPublisher{io: fixture.provider.io}
	require.NoError(t, clone.ImportOnboarding(context.Background(), bundle, fixture.genesis.Vault, fixture.genesis.Anchor, fixture.device.DeviceID))
	return clone
}

func coordinatorEnroll(t *testing.T, coordinator *Coordinator, fixture *pushFixture, device vault.DeviceMaterial, public vault.PublicDeviceInput, deviceID string) AdministrativeResult {
	t.Helper()
	approval := vault.EnrollmentTranscriptFingerprint(fixture.genesis.Vault, public.DeviceID, public.KeyID, vault.RoleRestoreOnly, public.SigningPublicKey, public.RecipientPublicKey)
	result, err := coordinator.Enroll(context.Background(), EnrollRequest{
		Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, Device: public,
		Role: vault.RoleRestoreOnly, ApprovalFingerprint: approval, Kit: fixture.kit,
	})
	require.NoError(t, err)
	assert.NotNil(t, device.Recipient)
	assert.Equal(t, deviceID, public.DeviceID)
	return result
}

func mustRetentionDeclaration(t *testing.T, store *state.Store, vaultID [32]byte, deviceID string) state.RetentionDeclaration {
	t.Helper()
	declaration, err := store.RetentionDeclaration(context.Background(), vaultID, deviceID)
	require.NoError(t, err)
	return declaration
}

func mustRetentionInventory(t *testing.T, store *state.Store, vaultID [32]byte, deviceID string) state.RetentionInventory {
	t.Helper()
	inventory, err := store.RetentionInventory(context.Background(), vaultID, deviceID)
	require.NoError(t, err)
	return inventory
}

func mustPayloadRefFromCID(t *testing.T, fixture *pushFixture, snapshotCID []byte) string {
	t.Helper()
	inventory, err := fixture.store.RetentionInventory(context.Background(), fixture.genesis.Vault, fixture.device.DeviceID)
	require.NoError(t, err)
	for _, material := range inventory.Materials {
		if bytes.Equal(material.SnapshotCID, snapshotCID) && material.PayloadReference != "" {
			return material.PayloadReference
		}
	}
	t.Fatal("retention body reference is missing")
	return ""
}

func stateFileIdentity(path string) model.EntryKey {
	return model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: path}
}
