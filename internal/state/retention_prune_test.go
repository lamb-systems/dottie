package state

import (
	"context"
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
			declaredBoundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("declared-snapshot")}
			requestedBoundary := declaredBoundary
			check.mutate(&requestedBoundary)
			declaration := testRetentionDeclaration(vaultID, declaredBoundary, 2, 1_700_000_000)
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

func TestRetentionPruneBoundaryMustBeOldestRetainedRecoveryPoint(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{53}
	oldest := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("oldest-snapshot")}
	newer := RetentionRecoveryPoint{Epoch: 3, SnapshotCID: []byte("newer-snapshot")}
	declaration := testRetentionDeclaration(vaultID, oldest, 2, 1_700_000_000)
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
			boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("declared-snapshot")}
			declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
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
