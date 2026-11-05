package service

import (
	"bytes"
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorPublishesOnlyLocalAttestationAndResolvesDuplicate(t *testing.T) {
	fixture := newPushFixture(t)
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	encoded, err := vault.BuildAttestation(vault.AttestationBuildRequest{
		VaultID: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor,
		State: vault.ControlEvidence{
			Policy: fixture.genesis.Policy, Control: fixture.genesis.Control,
			Certificates: [][]byte{fixture.genesis.Certificate},
		},
		SignerCertificate: fixture.genesis.Certificate, SigningKey: fixture.device.Signing,
		RetentionFloor: 0, RetainedRecoveryPoints: 1,
		RecoveryPoints: []vault.RetentionRecoveryPoint{{Epoch: 0, SnapshotCID: bytes.Clone(fixture.genesis.SnapshotCID)}},
	})
	require.NoError(t, err)

	first, err := fixture.coordinator.PublishAttestation(context.Background(), selection, encoded)
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, first.Status)
	assert.False(t, first.Idempotent)
	assert.NotEmpty(t, first.RKey)
	assert.NotEmpty(t, first.RecordCID)
	record, exists := fixture.pds.Record(atproto.VaultAttestationNSID, first.RKey)
	require.True(t, exists)
	decoded, err := atproto.DecodeRecord(record.Data)
	require.NoError(t, err)
	attestationRecord, ok := decoded.(atproto.AttestationRecord)
	require.True(t, ok)
	assert.Equal(t, int64(2), attestationRecord.SchemaVersion)
	assert.Equal(t, fixture.device.DeviceID, attestationRecord.DeviceID)
	assert.Equal(t, fixture.device.DeviceID, attestationRecord.SignerDeviceID)
	recordCID, exists := fixture.pds.RecordCID(atproto.VaultAttestationNSID, first.RKey)
	require.True(t, exists)
	assert.Equal(t, first.RecordCID, recordCID.String())

	second, err := fixture.coordinator.PublishAttestation(context.Background(), selection, encoded)
	require.NoError(t, err)
	assert.True(t, second.Idempotent)
	assert.Equal(t, first.RKey, second.RKey)
	assert.Equal(t, first.RecordCID, second.RecordCID)
	assert.Equal(t, first.CommitCID, second.CommitCID)

	tampered := bytes.Clone(encoded)
	tampered[len(tampered)-1] ^= 0x80
	refused, err := fixture.coordinator.PublishAttestation(context.Background(), selection, tampered)
	assert.ErrorIs(t, err, atproto.ErrBatchRejected)
	assert.Equal(t, AttestationPublicationResult{}, refused)
}

func TestCoordinatorBuildsAndPublishesCurrentRetentionAttestation(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}

	result, err := fixture.coordinator.PublishRetentionAttestation(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, result.Status)
	record, exists := fixture.pds.Record(atproto.VaultAttestationNSID, result.RKey)
	require.True(t, exists)
	verification := vault.AttestationVerificationRequest{
		VaultID: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor,
		State: vault.ControlEvidence{
			Policy: fixture.genesis.Policy, Control: fixture.genesis.Control,
			Certificates: [][]byte{fixture.genesis.Certificate},
		},
	}
	judgement, err := atproto.VerifyAttestationRecord(record.Data, verification)
	require.NoError(t, err)
	assert.Equal(t, vault.AttestationStatusMeetsPolicy, judgement.Status)

	inventory, err := fixture.store.RetentionInventory(ctx, fixture.genesis.Vault, fixture.device.DeviceID)
	require.NoError(t, err)
	floors := retentionFloors(inventory, 0)
	require.True(t, floors.HasConfidentialityFloor)
	assert.Equal(t, floors.ConfidentialityFloor, judgement.Attestation.RetentionFloor)
	expectedPoints := make([]vault.RetentionRecoveryPoint, len(inventory.Points))
	for index, point := range inventory.Points {
		require.True(t, point.InventoryComplete)
		expectedPoints[index] = vault.RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)}
	}
	assert.Equal(t, expectedPoints, judgement.Attestation.RecoveryPoints)
	assert.Equal(t, uint16(len(inventory.Points)), judgement.Attestation.RetainedRecoveryPoints)
}

func TestCoordinatorRefusesRetentionAttestationForUnknownLocalHoldings(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	claim, err := vault.BuildAttestation(vault.AttestationBuildRequest{
		VaultID: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor,
		State: vault.ControlEvidence{
			Policy: fixture.genesis.Policy, Control: fixture.genesis.Control,
			Certificates: [][]byte{fixture.genesis.Certificate},
		},
		SignerCertificate: fixture.genesis.Certificate, SigningKey: fixture.device.Signing,
		RetentionFloor: 0, RetainedRecoveryPoints: 1,
		RecoveryPoints: []vault.RetentionRecoveryPoint{{Epoch: 0, SnapshotCID: bytes.Clone(fixture.genesis.SnapshotCID)}},
	})
	require.NoError(t, err)
	_, err = fixture.store.PutRetentionMaterialPayload(ctx, []byte("legacy unclassified synthetic holding"))
	require.NoError(t, err)

	result, err := fixture.coordinator.PublishRetentionAttestation(ctx, selection)
	assert.ErrorIs(t, err, ErrAttestationInventoryIncomplete)
	assert.Equal(t, AttestationPublicationResult{}, result)
	legacyResult, legacyErr := fixture.coordinator.PublishAttestation(ctx, selection, claim)
	assert.ErrorIs(t, legacyErr, ErrAttestationInventoryIncomplete)
	assert.Equal(t, AttestationPublicationResult{}, legacyResult)
	for _, record := range fixture.pds.CurrentRevision().Records {
		assert.NotEqual(t, atproto.VaultAttestationNSID, record.Collection)
	}
	inventory, err := fixture.store.RetentionInventory(ctx, fixture.genesis.Vault, fixture.device.DeviceID)
	require.NoError(t, err)
	assert.NotEmpty(t, inventory.UnknownHoldingReasons)
}

func TestCoordinatorRejectsAttestationForDifferentLocalDevice(t *testing.T) {
	fixture := newPushFixture(t)
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	encoded, err := vault.BuildAttestation(vault.AttestationBuildRequest{
		VaultID: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor,
		State: vault.ControlEvidence{
			Policy: fixture.genesis.Policy, Control: fixture.genesis.Control,
			Certificates: [][]byte{fixture.genesis.Certificate},
		},
		SignerCertificate: fixture.genesis.Certificate, SigningKey: fixture.device.Signing,
		RetentionFloor: 0, RetainedRecoveryPoints: 0,
	})
	require.NoError(t, err)
	attestation, err := vault.DecodeAttestation(encoded)
	require.NoError(t, err)
	attestation.DeviceID = "other-device"
	encoded, err = vault.EncodeAttestation(attestation)
	require.NoError(t, err)

	result, err := fixture.coordinator.PublishAttestation(context.Background(), selection, encoded)
	assert.ErrorIs(t, err, atproto.ErrBatchRejected)
	assert.Equal(t, AttestationPublicationResult{}, result)
}
