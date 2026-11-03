package vault

import (
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
	altered := signRecoveryKitCheckpoint(t, fixture, checkpoint)
	_, err = RecoveryKitCheckpointAnchor(fixture.kit, fixture.bootstrap.Vault, altered)
	require.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "checkpoint vault")
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
	altered := signRecoveryKitCheckpoint(t, fixture, checkpoint)
	_, err = VerifyCheckpoint(altered, kitPublic)
	require.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "checkpoint kit signer")
}

func signRecoveryKitCheckpoint(t *testing.T, fixture devicesFixture, checkpoint Checkpoint) []byte {
	t.Helper()
	key, err := deriveKitSigningKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	return signCheckpointValue(t, checkpoint, key)
}
