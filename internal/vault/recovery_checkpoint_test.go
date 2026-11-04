package vault

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryKitCheckpointAnchorBindsCheckpointVault(t *testing.T) {
	fixture := newDevicesFixture(t)
	anchor, err := RecoveryKitCheckpointAnchor(fixture.kit, fixture.bootstrap.Vault, fixture.bootstrap.Checkpoint)
	require.NoError(t, err)
	assert.Equal(t, fixture.bootstrap.Anchor, anchor)

	checkpoint, err := DecodeCheckpoint(fixture.bootstrap.Checkpoint)
	require.NoError(t, err)
	checkpoint.Vault[0] ^= 1
	altered := signRecoveryKitCheckpointForTest(t, fixture, checkpoint)
	_, err = RecoveryKitCheckpointAnchor(fixture.kit, fixture.bootstrap.Vault, altered)
	require.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "checkpoint vault")
}

func TestSignRecoveryKitCheckpointRoundTripsAdministrativePosition(t *testing.T) {
	fixture := newDevicesFixture(t)
	successorPolicy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	controlCID, err := rawCID(fixture.transition.Control)
	require.NoError(t, err)

	encoded, err := SignRecoveryKitCheckpoint(fixture.kit, fixture.bootstrap.Vault, fixture.bootstrap.Anchor, successorPolicy.EpochSeq,
		successorPolicyDigest(t, fixture.transition.Policy), controlCID, fixture.transition.SnapshotCID)
	require.NoError(t, err)
	publicKey, err := RecoveryKitSigningPublicKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	verified, err := VerifyCheckpoint(encoded, publicKey)
	require.NoError(t, err)
	assert.Equal(t, fixture.bootstrap.Vault, verified.Vault)
	assert.Equal(t, fixture.bootstrap.Anchor, verified.Anchor)
	assert.Equal(t, successorPolicy.EpochSeq, verified.EpochSeq)
	assert.Equal(t, successorPolicyDigest(t, fixture.transition.Policy), verified.PolicyDigest)
	assert.Equal(t, controlCID, verified.ControlCID)
	assert.Equal(t, fixture.transition.SnapshotCID, verified.SnapshotCID)
	assert.Equal(t, sha256.Sum256(publicKey), [32]byte(verified.Signer.KeyID))
}

func TestSignRecoveryKitCheckpointSignatureBindsAllPositionFields(t *testing.T) {
	fixture := newDevicesFixture(t)
	successorPolicy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	controlCID, err := rawCID(fixture.transition.Control)
	require.NoError(t, err)
	encoded, err := SignRecoveryKitCheckpoint(fixture.kit, fixture.bootstrap.Vault, fixture.bootstrap.Anchor, successorPolicy.EpochSeq,
		successorPolicyDigest(t, fixture.transition.Policy), controlCID, fixture.transition.SnapshotCID)
	require.NoError(t, err)
	publicKey, err := RecoveryKitSigningPublicKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	for _, test := range []struct {
		name   string
		mutate func(*Checkpoint)
	}{
		{"vault", func(value *Checkpoint) { value.Vault[0] ^= 1 }},
		{"anchor", func(value *Checkpoint) { value.Anchor[0] ^= 1 }},
		{"epoch", func(value *Checkpoint) { value.EpochSeq++ }},
		{"policy digest", func(value *Checkpoint) { value.PolicyDigest[0] ^= 1 }},
		{"control CID", func(value *Checkpoint) { value.ControlCID[0] ^= 1 }},
		{"snapshot CID", func(value *Checkpoint) { value.SnapshotCID[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed, err := DecodeCheckpoint(encoded)
			require.NoError(t, err)
			test.mutate(&changed)
			changedBytes, err := EncodeCheckpoint(changed)
			require.NoError(t, err)
			_, err = VerifyCheckpoint(changedBytes, publicKey)
			assert.ErrorIs(t, err, ErrSignature)
		})
	}
}

func TestSignRecoveryKitCheckpointRejectsInvalidInputsAndWrongKit(t *testing.T) {
	fixture := newDevicesFixture(t)
	successorPolicy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	controlCID, err := rawCID(fixture.transition.Control)
	require.NoError(t, err)
	digest := successorPolicyDigest(t, fixture.transition.Policy)

	for _, invalid := range [][]byte{nil, bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{1}, 33)} {
		_, err := SignRecoveryKitCheckpoint(invalid, fixture.bootstrap.Vault, fixture.bootstrap.Anchor, 1, digest, controlCID, fixture.transition.SnapshotCID)
		assert.ErrorIs(t, err, ErrFormat)
	}
	for _, epoch := range []uint64{0, ^uint64(0)} {
		_, err := SignRecoveryKitCheckpoint(fixture.kit, fixture.bootstrap.Vault, fixture.bootstrap.Anchor, epoch, digest, controlCID, fixture.transition.SnapshotCID)
		assert.ErrorIs(t, err, ErrTransitionEpoch)
	}
	_, err = SignRecoveryKitCheckpoint(fixture.kit, fixture.bootstrap.Vault, fixture.bootstrap.Anchor, successorPolicy.EpochSeq, digest, []byte("not-a-cid"), fixture.transition.SnapshotCID)
	assert.ErrorIs(t, err, ErrFormat)

	encoded, err := SignRecoveryKitCheckpoint(fixture.kit, fixture.bootstrap.Vault, fixture.bootstrap.Anchor, successorPolicy.EpochSeq, digest, controlCID, fixture.transition.SnapshotCID)
	require.NoError(t, err)
	otherKit := bytes.Repeat([]byte{0x91}, 32)
	otherPublic, err := RecoveryKitSigningPublicKey(otherKit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	_, err = VerifyCheckpoint(encoded, otherPublic)
	assert.ErrorIs(t, err, ErrAuthorization)

	altered, err := DecodeCheckpoint(encoded)
	require.NoError(t, err)
	altered.PolicyDigest[0] ^= 0x80
	alteredBytes, err := EncodeCheckpoint(altered)
	require.NoError(t, err)
	publicKey, err := RecoveryKitSigningPublicKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	_, err = VerifyCheckpoint(alteredBytes, publicKey)
	assert.ErrorIs(t, err, ErrSignature)
}

func TestVerifyCheckpointRequiresRecoveryKitSignerDeviceID(t *testing.T) {
	fixture := newDevicesFixture(t)
	kitPublic, err := RecoveryKitSigningPublicKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	_, err = VerifyCheckpoint(fixture.bootstrap.Checkpoint, kitPublic)
	require.NoError(t, err)

	checkpoint, err := DecodeCheckpoint(fixture.bootstrap.Checkpoint)
	require.NoError(t, err)
	checkpoint.Signer.DeviceID = "device-root"
	altered := signRecoveryKitCheckpointForTest(t, fixture, checkpoint)
	_, err = VerifyCheckpoint(altered, kitPublic)
	require.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "checkpoint kit signer")
}

func signRecoveryKitCheckpointForTest(t *testing.T, fixture devicesFixture, checkpoint Checkpoint) []byte {
	t.Helper()
	key, err := deriveKitSigningKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	return signCheckpointValue(t, checkpoint, key)
}

func successorPolicyDigest(t *testing.T, encoded []byte) [32]byte {
	t.Helper()
	digest, err := ComputePolicyDigest(encoded)
	require.NoError(t, err)
	return digest
}
