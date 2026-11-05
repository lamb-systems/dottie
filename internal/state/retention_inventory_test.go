package state

import (
	"bytes"
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetentionInventoryReportsDeclaredCompletenessAndEvictedMaterial(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{91}
	oldBody, currentBody := []byte("old retained snapshot body"), []byte("current retained snapshot body")
	oldPoint := testRetentionPoint(t, vaultID, 2, oldBody, [32]byte{7})
	currentPoint := testRetentionPoint(t, vaultID, 3, currentBody, [32]byte{8})
	declaration := testRetentionDeclaration(t, vaultID, currentPoint, 3, 10)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{oldPoint, currentPoint}
	_, err := store.ReplaceRetentionDeclarationWithMaterials(ctx, declaration, []RetentionRecoveryPointMaterials{
		{Point: oldPoint, Payloads: [][]byte{oldBody}},
		{Point: currentPoint, Payloads: [][]byte{currentBody}},
	})
	require.NoError(t, err)

	inventory, err := store.RetentionInventory(ctx, vaultID, declaration.DeviceID)
	require.NoError(t, err)
	require.Len(t, inventory.Points, 2)
	assert.True(t, inventory.Points[0].InventoryComplete)
	assert.True(t, inventory.Points[1].InventoryComplete)
	assert.Equal(t, []uint64{2, 3}, inventory.KnownMaterialEpochs)
	assert.Empty(t, inventory.UnknownHoldingReasons)

	declaration.RecoveryPoints = []RetentionRecoveryPoint{currentPoint}
	declaration.DeclaredAt++
	_, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	inventory, err = store.RetentionInventory(ctx, vaultID, declaration.DeviceID)
	require.NoError(t, err)
	require.Len(t, inventory.Points, 1)
	assert.Equal(t, currentPoint.Epoch, inventory.Points[0].Epoch)
	assert.True(t, inventory.Points[0].InventoryComplete)
	assert.Equal(t, []uint64{2, 3}, inventory.KnownMaterialEpochs, "material for the evicted point remains classified")
	assert.Contains(t, inventory.Materials, RetentionRecoveryMaterial{
		Epoch: oldPoint.Epoch, SnapshotCID: oldPoint.SnapshotCID,
		PayloadReference: mustPayloadReference(t, oldBody), InventoryComplete: true,
	})
}

func TestRetentionInventoryIncludesBoundBackupsAndFlagsUnboundAndOrphanedHoldings(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{92}
	pointBody := []byte("retained snapshot body")
	point := testRetentionPoint(t, vaultID, 4, pointBody, [32]byte{9})
	declaration := testRetentionDeclaration(t, vaultID, point, 4, 10)
	_, err := store.ReplaceRetentionDeclarationWithMaterials(ctx, declaration, []RetentionRecoveryPointMaterials{{Point: point, Payloads: [][]byte{pointBody}}})
	require.NoError(t, err)
	require.NoError(t, store.PutVaultSelection(ctx, VaultSelection{Vault: vaultID, DeviceID: declaration.DeviceID, RecordedAt: 1}))
	require.NoError(t, store.PutTarget(ctx, TargetDescriptor{ID: "target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, Mode: "review", LogicalBase: model.RootHome, LogicalPath: "selected", Kind: model.SelectionDirectory, CreatedAt: 1}))

	identity := fileIdentity("prefs.toml")
	preimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("after"))
	bound, err := store.AppendJournal(ctx, JournalEntry{
		ID: "bound-retention-backup", Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity: identity, Preimage: preimage, Postimage: postimage,
		Retention: &RetentionBinding{Vault: vaultID, Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID)},
		CreatedAt: 10,
	}, []byte("before"))
	require.NoError(t, err)
	_, err = store.AppendJournal(ctx, JournalEntry{
		ID: "legacy-backup", Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity: fileIdentity("legacy.toml"), Preimage: preimage, Postimage: postimage, CreatedAt: 11,
	}, []byte("before"))
	require.NoError(t, err)
	orphanReference, err := store.PutRetentionMaterialPayload(ctx, []byte("staged but never declared"))
	require.NoError(t, err)
	assert.NotEmpty(t, orphanReference)

	inventory, err := store.RetentionInventory(ctx, vaultID, declaration.DeviceID)
	require.NoError(t, err)
	require.Len(t, inventory.Points, 1)
	assert.False(t, inventory.Points[0].InventoryComplete, "journal append atomically demotes the point inventory")
	assert.Contains(t, inventory.KnownMaterialEpochs, uint64(4))
	assert.Contains(t, inventory.Materials, RetentionRecoveryMaterial{
		Epoch: point.Epoch, SnapshotCID: point.SnapshotCID,
		BackupReference: bound.BackupRef, InventoryComplete: true,
	})
	assert.Contains(t, inventory.UnknownHoldingReasons, "legacy-unbound-journal-backup")
	assert.Contains(t, inventory.UnknownHoldingReasons, "unclassified-payload-file")
}

func TestRetentionInventoryEmptyAndMissingMaterialHaveNoPositiveRecoveryFloor(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{93}
	inventory, err := store.RetentionInventory(ctx, vaultID, "device-a")
	require.NoError(t, err)
	assert.Empty(t, inventory.Points)
	assert.Empty(t, inventory.Materials)
	assert.Empty(t, inventory.KnownMaterialEpochs)
	assert.Empty(t, inventory.UnknownHoldingReasons)

	body := []byte("incomplete point body")
	point := testRetentionPoint(t, vaultID, 5, body, [32]byte{10})
	_, err = store.PutRetentionDeclaration(ctx, testRetentionDeclaration(t, vaultID, point, 5, 1))
	require.NoError(t, err)
	inventory, err = store.RetentionInventory(ctx, vaultID, "device-a")
	require.NoError(t, err)
	require.Len(t, inventory.Points, 1)
	assert.False(t, inventory.Points[0].InventoryComplete)
	assert.Empty(t, inventory.KnownMaterialEpochs, "an unmaterialized declaration is not surviving material")
}

func TestReplaceRetentionDeclarationWithMaterialsFailurePreservesCompleteDeclaration(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{94}
	firstBody, secondBody := []byte("first body"), []byte("second body")
	firstPoint := testRetentionPoint(t, vaultID, 1, firstBody, [32]byte{11})
	secondPoint := testRetentionPoint(t, vaultID, 2, secondBody, [32]byte{12})
	firstDeclaration := testRetentionDeclaration(t, vaultID, firstPoint, 1, 10)
	_, err := store.ReplaceRetentionDeclarationWithMaterials(ctx, firstDeclaration, []RetentionRecoveryPointMaterials{{Point: firstPoint, Payloads: [][]byte{firstBody}}})
	require.NoError(t, err)
	before, err := store.RetentionDeclaration(ctx, vaultID, firstDeclaration.DeviceID)
	require.NoError(t, err)
	beforeInventory, err := store.RetentionInventory(ctx, vaultID, firstDeclaration.DeviceID)
	require.NoError(t, err)
	require.True(t, beforeInventory.Points[0].InventoryComplete)

	missingBackup, _ := payloadReference([]byte("missing backup"))
	next := testRetentionDeclaration(t, vaultID, secondPoint, 2, 11)
	_, err = store.ReplaceRetentionDeclarationWithMaterials(ctx, next, []RetentionRecoveryPointMaterials{{
		Point: secondPoint, Payloads: [][]byte{secondBody}, BackupReferences: []string{missingBackup},
	}})
	require.Error(t, err)
	after, err := store.RetentionDeclaration(ctx, vaultID, firstDeclaration.DeviceID)
	require.NoError(t, err)
	assert.Equal(t, before.RecoveryPoints, after.RecoveryPoints)
	assert.Equal(t, before.DeclarationDigest, after.DeclarationDigest)
	afterInventory, err := store.RetentionInventory(ctx, vaultID, firstDeclaration.DeviceID)
	require.NoError(t, err)
	require.Len(t, afterInventory.Points, 1)
	assert.True(t, afterInventory.Points[0].InventoryComplete)
	assert.Equal(t, firstPoint.Epoch, afterInventory.Points[0].Epoch)
	_, err = store.Payload(mustPayloadReference(t, firstBody))
	require.NoError(t, err)
}

func mustPayloadReference(t *testing.T, data []byte) string {
	t.Helper()
	reference, _ := payloadReference(data)
	return reference
}
