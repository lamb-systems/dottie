package vault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryKitRenderParseRoundTripAndGenerate(t *testing.T) {
	kit, err := GenerateRecoveryKit()
	require.NoError(t, err)
	require.Len(t, kit, 32)
	rendered, err := RenderRecoveryKit(kit)
	require.NoError(t, err)
	parsed, err := ParseRecoveryKit(rendered + " \n")
	require.NoError(t, err)
	assert.Equal(t, kit, parsed)
	assert.Contains(t, rendered, "-")
}

func TestRecoveryKitRejectsShortAndMalformedValues(t *testing.T) {
	_, err := RenderRecoveryKit(bytes.Repeat([]byte{1}, 31))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRecoveryKitLength)

	short, err := RenderRecoveryKit(bytes.Repeat([]byte{1}, 31))
	assert.Empty(t, short)
	assert.ErrorIs(t, err, ErrRecoveryKitLength)
	_, err = ParseRecoveryKit(short)
	assert.ErrorIs(t, err, ErrRecoveryKitEncoding)

	_, err = ParseRecoveryKit("AA")
	assert.ErrorIs(t, err, ErrRecoveryKitLength)
}

func TestRecoveryKitVaultDerivationAndCheckpointAnchor(t *testing.T) {
	kit := fixtureBytes(1, 32)
	vaultID, err := RecoveryKitVaultID(kit, "recovery-test")
	require.NoError(t, err)
	publicKey, err := RecoveryKitSigningPublicKey(kit, vaultID)
	require.NoError(t, err)
	repeated, err := RecoveryKitSigningPublicKey(kit, vaultID)
	require.NoError(t, err)
	assert.Equal(t, publicKey, repeated)

	root := DeviceMaterial{DeviceID: "recovery-root", KeyID: []byte("root-key"), Signing: fixedSigningKey(11), Recipient: fixedX25519Key(21)}
	boot, err := Bootstrap(kit, "recovery-test", root)
	require.NoError(t, err)
	assert.Equal(t, vaultID, boot.Vault)
	checkpointAnchor, err := RecoveryKitCheckpointAnchor(kit, vaultID, boot.Checkpoint)
	require.NoError(t, err)
	assert.Equal(t, boot.Anchor, checkpointAnchor)

	fingerprint, err := RecoveryKitPublicKeyFingerprint(kit, vaultID)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(publicKey), fingerprint)
}

func TestRecoveryKitWrongLengthIsTyped(t *testing.T) {
	_, err := RecoveryKitVaultID(make([]byte, 31), "vault")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFormat)
	_, err = ParseRecoveryKit("not-a-kit")
	assert.True(t, errors.Is(err, ErrRecoveryKitEncoding) || errors.Is(err, ErrRecoveryKitLength))
}
