package service

import (
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorRevokeApprovalBindsAndConfirmsCurrentDevice(t *testing.T) {
	fixture := newPushFixture(t)
	newcomer, publicDevice := newAdminNewcomer(t, "approval-target")
	enrollment := enrollWithFixture(t, fixture, newcomer, publicDevice)
	require.Equal(t, StatusCommitted, enrollment.Status)
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	transcript, err := fixture.coordinator.RevokeApproval(context.Background(), selection, newcomer.DeviceID, fixture.kit)
	require.NoError(t, err)
	assert.Equal(t, fixture.genesis.Vault, transcript.Vault)
	assert.Equal(t, newcomer.DeviceID, transcript.DeviceID)
	assert.Equal(t, vault.RoleRestoreOnly, transcript.Role)
	assert.Equal(t, uint64(1), transcript.CurrentEpoch)
	assert.Equal(t, uint64(2), transcript.SuccessorEpoch)
	assert.NotEqual(t, [32]byte{}, transcript.SigningKeyFingerprint)
	assert.NotEqual(t, [32]byte{}, transcript.RecipientKeyFingerprint)
	assert.NotEqual(t, [32]byte{}, transcript.KitSigningKeyFingerprint)
	assert.NotEqual(t, [32]byte{}, transcript.ApprovalFingerprint)

	result, err := fixture.coordinator.Revoke(context.Background(), RevokeRequest{
		Selection: selection, DeviceID: newcomer.DeviceID, Kit: fixture.kit, ApprovalFingerprint: transcript.ApprovalFingerprint,
	})
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, result.Status)
	assert.Equal(t, uint64(2), mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault).Epoch)
}

func TestCoordinatorRevokeApprovalMismatchLeavesAdministrativeStateUnchanged(t *testing.T) {
	fixture := newPushFixture(t)
	newcomer, publicDevice := newAdminNewcomer(t, "approval-mismatch-target")
	enrollWithFixture(t, fixture, newcomer, publicDevice)
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	transcript, err := fixture.coordinator.RevokeApproval(context.Background(), selection, newcomer.DeviceID, fixture.kit)
	require.NoError(t, err)
	beforeRead, err := fixture.coordinator.Pull(context.Background(), selection)
	require.NoError(t, err)
	beforeCheckpoint := mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault)
	beforeSelections, err := fixture.store.VaultSelections(context.Background())
	require.NoError(t, err)
	beforeBases, err := fixture.store.AppliedBase(context.Background(), "files")
	require.NoError(t, err)
	wrong := transcript.ApprovalFingerprint
	wrong[0] ^= 0xff

	result, err := fixture.coordinator.Revoke(context.Background(), RevokeRequest{
		Selection: selection, DeviceID: newcomer.DeviceID, Kit: fixture.kit, ApprovalFingerprint: wrong,
	})
	var mismatch RevokeApprovalMismatchError
	require.ErrorAs(t, err, &mismatch)
	require.ErrorIs(t, err, ErrRevokeApprovalMismatch)
	assert.Equal(t, StatusRejected, result.Status)
	assert.Equal(t, beforeCheckpoint, mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault))
	afterSelections, err := fixture.store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Equal(t, beforeSelections, afterSelections)
	afterBases, err := fixture.store.AppliedBase(context.Background(), "files")
	require.NoError(t, err)
	assert.Equal(t, beforeBases, afterBases)
	afterRead, err := fixture.coordinator.Pull(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, beforeRead.Read.Revision.CommitCID(), afterRead.Read.Revision.CommitCID(), "mismatched approval must not write remote records")
}

func TestCoordinatorRevokeRejectsChangedTargetWithoutWriting(t *testing.T) {
	fixture := newPushFixture(t)
	newcomer, publicDevice := newAdminNewcomer(t, "approval-target-changed")
	enrollWithFixture(t, fixture, newcomer, publicDevice)
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	transcript, err := fixture.coordinator.RevokeApproval(context.Background(), selection, newcomer.DeviceID, fixture.kit)
	require.NoError(t, err)
	before, err := fixture.coordinator.Pull(context.Background(), selection)
	require.NoError(t, err)
	wrongDeviceFingerprint := transcript.ApprovalFingerprint
	wrongDeviceFingerprint[1] ^= 0x80
	_, err = fixture.coordinator.Revoke(context.Background(), RevokeRequest{
		Selection: selection, DeviceID: "another-device", Kit: fixture.kit, ApprovalFingerprint: wrongDeviceFingerprint,
	})
	require.ErrorIs(t, err, ErrRevokeApprovalMismatch)
	after, err := fixture.coordinator.Pull(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, before.Read.Revision.CommitCID(), after.Read.Revision.CommitCID())
	assert.Equal(t, uint64(1), mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault).Epoch)
}
