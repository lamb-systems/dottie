package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetentionPruneBoundaryMustMatchDeclaredRecoveryPoint(t *testing.T) {
	for _, check := range []struct {
		name   string
		mutate func(*RetentionRecoveryPoint)
	}{
		{
			name: "epoch",
			mutate: func(boundary *RetentionRecoveryPoint) {
				boundary.Epoch++
			},
		},
		{
			name: "snapshot CID",
			mutate: func(boundary *RetentionRecoveryPoint) {
				boundary.SnapshotCID = []byte("different-snapshot")
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			store := openTestStore(t, testPaths(t))
			ctx := context.Background()
			vaultID := [32]byte{51}
			declaredBoundary := testRetentionPoint(t, vaultID, 2, []byte("declared-snapshot"), [32]byte{7})
			requestedBoundary := declaredBoundary
			check.mutate(&requestedBoundary)
			declaration := testRetentionDeclaration(t, vaultID, declaredBoundary, 2, 1_700_000_000)
			_, err := store.PutRetentionDeclaration(ctx, declaration)
			require.NoError(t, err)
			require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, requestedBoundary, declaration.PolicyDigest)))
			require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
				Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
			}))

			_, err = store.PlanRetentionPrune(ctx, RetentionPruneRequest{
				Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: requestedBoundary, Now: time.Now(),
			})
			assert.ErrorIs(t, err, ErrRetentionBoundaryNotVerified)
		})
	}
}

func TestRetentionPrunePlanRevalidatesPayloadDigestsAfterInventory(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{54}
	oldBody := []byte("evicted snapshot body")
	boundaryBody := []byte("retained snapshot body")
	oldPoint := testRetentionPoint(t, vaultID, 1, oldBody, [32]byte{7})
	boundary := testRetentionPoint(t, vaultID, 2, boundaryBody, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{oldPoint, boundary}
	declaration, err := store.ReplaceRetentionDeclarationWithMaterials(ctx, declaration, []RetentionRecoveryPointMaterials{
		{Point: oldPoint, Payloads: [][]byte{oldBody}},
		{Point: boundary, Payloads: [][]byte{boundaryBody}},
	})
	require.NoError(t, err)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	declaration, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
	}))

	inventory, err := store.RetentionInventory(ctx, vaultID, declaration.DeviceID)
	require.NoError(t, err)
	require.Len(t, inventory.Points, 1)
	require.True(t, inventory.Points[0].InventoryComplete)

	boundaryReference := mustPayloadReference(t, boundaryBody)
	boundaryName, err := payloadName(boundaryReference)
	require.NoError(t, err)
	boundaryPath := filepath.Join(store.payloadDir, boundaryName)
	require.NoError(t, os.Remove(boundaryPath))
	oldReference := mustPayloadReference(t, oldBody)
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}

	_, err = store.PlanRetentionPrune(ctx, request)
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = store.ApplyRetentionPrune(ctx, request, true)
	assert.ErrorIs(t, err, os.ErrNotExist)
	payload, err := store.Payload(oldReference)
	require.NoError(t, err, "refusal must not delete an evicted payload")
	assert.Equal(t, oldBody, payload)
	_, err = os.Stat(boundaryPath)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRetentionPruneBoundaryMustBeOldestRetainedRecoveryPoint(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{53}
	oldest := testRetentionPoint(t, vaultID, 2, []byte("oldest-snapshot"), [32]byte{7})
	newer := testRetentionPoint(t, vaultID, 3, []byte("newer-snapshot"), [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, oldest, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{oldest, newer}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, newer, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
	}))
	_, err = store.PlanRetentionPrune(ctx, RetentionPruneRequest{
		Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: newer, Now: time.Now(),
	})
	assert.ErrorIs(t, err, ErrRetentionBoundaryNewerThanFloor)
}

func TestRetentionPruneCheckpointMustMatchBoundaryEpochAndSnapshot(t *testing.T) {
	for _, check := range []struct {
		name       string
		checkpoint func(t *testing.T, vaultID [32]byte, boundary RetentionRecoveryPoint, digest [32]byte) VaultCheckpoint
	}{
		{
			name: "epoch",
			checkpoint: func(t *testing.T, vaultID [32]byte, boundary RetentionRecoveryPoint, digest [32]byte) VaultCheckpoint {
				boundary.Epoch++
				return testRetentionCheckpoint(t, vaultID, boundary, digest)
			},
		},
		{
			name: "snapshot CID",
			checkpoint: func(t *testing.T, vaultID [32]byte, boundary RetentionRecoveryPoint, digest [32]byte) VaultCheckpoint {
				boundary.SnapshotCID = []byte("other-checkpoint-snapshot")
				return testRetentionCheckpoint(t, vaultID, boundary, digest)
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			store := openTestStore(t, testPaths(t))
			ctx := context.Background()
			vaultID := [32]byte{52}
			boundary := testRetentionPoint(t, vaultID, 2, []byte("declared-snapshot"), [32]byte{7})
			declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
			_, err := store.PutRetentionDeclaration(ctx, declaration)
			require.NoError(t, err)
			require.NoError(t, store.PutVaultCheckpoint(ctx, check.checkpoint(t, vaultID, boundary, declaration.PolicyDigest)))
			require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
				Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
			}))

			_, err = store.PlanRetentionPrune(ctx, RetentionPruneRequest{
				Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now(),
			})
			assert.ErrorIs(t, err, ErrRetentionBoundaryNotVerified)
		})
	}
}
