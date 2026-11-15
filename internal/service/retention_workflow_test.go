package service

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
