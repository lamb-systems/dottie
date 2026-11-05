package integration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func kitAuthorizesHeldCheckpoint(kit []byte, vaultID [32]byte, checkpoint state.VaultCheckpoint, evidence state.AuthenticatedPositionEvidence) error {
	policy, err := vault.DecodePolicy(evidence.Policy)
	if err != nil {
		return fmt.Errorf("held checkpoint policy could not be decoded: %w", err)
	}
	if policy.Vault != vaultID {
		return errors.New("held checkpoint policy belongs to a different vault")
	}
	if evidence.Vault != vaultID || evidence.Epoch != checkpoint.Epoch {
		return errors.New("held checkpoint evidence does not describe the held checkpoint")
	}
	fingerprint, err := vault.RecoveryKitPublicKeyFingerprint(kit, vaultID)
	if err != nil {
		return err
	}
	if policy.RecoveryAnchor != fingerprint {
		return errors.New("kit fingerprint does not match the policy recovery anchor")
	}
	if len(evidence.CheckpointPosition) == 0 {
		if checkpoint.Epoch != 0 {
			return errors.New("held checkpoint has no signed checkpoint object")
		}
		return nil
	}
	anchor, err := vault.RecoveryKitCheckpointAnchor(kit, vaultID, evidence.CheckpointPosition)
	if err != nil {
		return err
	}
	if anchor != checkpoint.Anchor {
		return errors.New("kit-signed checkpoint anchor differs from the held checkpoint")
	}
	return nil
}

func TestKitAuthorizesHeldCheckpoint(t *testing.T) {
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	device, _ := restoreMilestoneKitDevice(t)
	genesis := publicationAuditGenesis(t, kit, device)
	address := state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: genesis.ControlCID,
		ControlBytes: genesis.Control, SnapshotCID: genesis.SnapshotCID,
		Epoch: 0, PolicyDigest: genesis.PolicyDigest,
	}
	genesisEvidence := state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest, Policy: genesis.Policy,
		Control: genesis.Control, Head: genesis.Head, Certificates: [][]byte{genesis.Certificate},
	}
	require.NoError(t, kitAuthorizesHeldCheckpoint(kit, genesis.Vault, address, genesisEvidence))

	otherKit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	assert.Error(t, kitAuthorizesHeldCheckpoint(otherKit, genesis.Vault, address, genesisEvidence))
	clear(otherKit)

	wrongVault := genesis.Vault
	wrongVault[0] ^= 0xff
	assert.Error(t, kitAuthorizesHeldCheckpoint(kit, wrongVault, address, genesisEvidence))

	signed, err := vault.SignRecoveryKitCheckpoint(kit, genesis.Vault, genesis.Anchor, 1, genesis.PolicyDigest, genesis.ControlCID, genesis.SnapshotCID)
	require.NoError(t, err)
	successor := address
	successor.Epoch = 1
	successorEvidence := genesisEvidence
	successorEvidence.Epoch = 1
	successorEvidence.CheckpointPosition = signed
	require.NoError(t, kitAuthorizesHeldCheckpoint(kit, genesis.Vault, successor, successorEvidence))

	assert.Error(t, kitAuthorizesHeldCheckpoint(kit, genesis.Vault, address, successorEvidence))

	missingObject := successorEvidence
	missingObject.CheckpointPosition = nil
	assert.Error(t, kitAuthorizesHeldCheckpoint(kit, genesis.Vault, successor, missingObject))
}

func restoreMilestoneKitDevice(t *testing.T) (vault.DeviceMaterial, vault.PublicDeviceInput) {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	device := vault.DeviceMaterial{
		DeviceID:  "kit-anchor-device",
		KeyID:     bytes.Clone(signing.Public().(ed25519.PublicKey)),
		Signing:   signing,
		Recipient: recipient,
	}
	public := vault.PublicDeviceInput{
		DeviceID: device.DeviceID, KeyID: bytes.Clone(device.KeyID),
		SigningPublicKey:   bytes.Clone(signing.Public().(ed25519.PublicKey)),
		RecipientPublicKey: bytes.Clone(recipient.PublicKey().Bytes()),
	}
	return device, public
}
