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
