package vault

import (
	"bytes"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComposeGenesisBindsCountZeroObjectsToCanonicalEmptySnapshot(t *testing.T) {
	kit := fixtureBytes(1, 32)
	root := DeviceMaterial{DeviceID: "genesis-root", KeyID: []byte("genesis-root-key"), Signing: fixedSigningKey(11), Recipient: fixedX25519Key(21)}
	genesis, err := ComposeGenesis(GenesisIntent{
		Kit: kit, VaultName: "genesis fixture", RootDevice: root, ContentKey: fixtureBytes(31, 32),
		Wraps:         []RecipientWrapInput{{KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(41, 32)), WrapNonce: [24]byte(fixtureBytes(51, 24))}},
		PublicationID: [16]byte(fixtureBytes(61, 16)), Nonce: [24]byte(fixtureBytes(71, 24)),
	})
	require.NoError(t, err)
	require.NoError(t, ValidateGenesis(genesis, kit))

	policy, err := DecodePolicy(genesis.Policy)
	require.NoError(t, err)
	control, err := DecodeControl(genesis.Control)
	require.NoError(t, err)
	head, err := DecodeHead(genesis.Head)
	require.NoError(t, err)
	checkpoint, err := DecodeCheckpoint(genesis.Checkpoint)
	require.NoError(t, err)
	envelope, err := DecodeEnvelope(genesis.Snapshot)
	require.NoError(t, err)
	assert.Zero(t, head.PublicationCount)
	assert.Empty(t, head.PrevHeadCID)
	assert.Equal(t, genesis.SnapshotCID, head.SnapshotCID)
	assert.Equal(t, genesis.SnapshotCID, head.BlobCID)
	assert.Equal(t, genesis.SnapshotCID, control.HeadSnapshotCID)
	assert.Equal(t, genesis.SnapshotCID, checkpoint.SnapshotCID)
	assert.Equal(t, genesis.ControlCID, checkpoint.ControlCID)
	assert.Empty(t, envelope.Parent)
	assert.Equal(t, policy.Vault, genesis.Vault)

	opened, err := Open(envelope, OpenRequest{
		Vault: genesis.Vault, EpochSeq: 0, PolicyDigest: genesis.PolicyDigest,
		Policy: genesis.Policy, Control: genesis.Control, TrustAnchor: genesis.Anchor,
		Certificates: [][]byte{genesis.Certificate}, DeviceKeyID: bytes.Clone(root.KeyID), DeviceKey: root.Recipient,
	})
	require.NoError(t, err)
	canonical, err := Pack(model.Snapshot{Version: model.SnapshotVersion})
	require.NoError(t, err)
	assert.Equal(t, canonical.Payload, opened)
}

func TestValidateGenesisRejectsMismatchedCheckpointAndHead(t *testing.T) {
	kit := fixtureBytes(2, 32)
	root := DeviceMaterial{DeviceID: "genesis-root", KeyID: []byte("genesis-root-key"), Signing: fixedSigningKey(12), Recipient: fixedX25519Key(22)}
	genesis, err := ComposeGenesis(GenesisIntent{
		Kit: kit, VaultName: "genesis hostile fixture", RootDevice: root, ContentKey: fixtureBytes(32, 32),
		Wraps:         []RecipientWrapInput{{KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(42, 32)), WrapNonce: [24]byte(fixtureBytes(52, 24))}},
		PublicationID: [16]byte(fixtureBytes(62, 16)), Nonce: [24]byte(fixtureBytes(72, 24)),
	})
	require.NoError(t, err)

	omittedCheckpoint := genesis
	omittedCheckpoint.Checkpoint = nil
	assert.Error(t, ValidateGenesis(omittedCheckpoint, kit))

	mismatchedCID := genesis
	mismatchedCID.Checkpoint = bytes.Clone(genesis.Checkpoint)
	mismatchedCID.Checkpoint[10] ^= 0xff
	assert.Error(t, ValidateGenesis(mismatchedCID, kit))

	mismatchedHead := genesis
	mismatchedHead.Head = bytes.Clone(genesis.Head)
	mismatchedHead.Head[10] ^= 0xff
	assert.Error(t, ValidateGenesis(mismatchedHead, kit))
}
