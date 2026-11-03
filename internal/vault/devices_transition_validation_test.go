package vault

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTransitionRejectsAllCheckpointBearingTransitionKinds(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	revocation, err := PrepareTransition(predecessor, TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root,
		RevokeDeviceID: fixture.newDevice.DeviceID, ContentKey: fixtureBytes(31, 32),
		Recipients: [][]byte{bytes.Clone(predecessor.Certificates[0])},
		Wraps: []RecipientWrapInput{{
			KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(91, 32)),
			WrapNonce: [24]byte(fixtureBytes(123, 24)),
		}},
		Plaintext: []byte("synthetic state after revocation"), PublicationID: [16]byte(fixtureBytes(157, 16)),
		Nonce: [24]byte(fixtureBytes(173, 24)),
	})
	require.NoError(t, err)

	t.Run("valid enrollment without checkpoint", func(t *testing.T) {
		require.Empty(t, fixture.transition.Checkpoint)
		require.NoError(t, ValidateTransition(fixture.transition, fixture.predecessor))
	})
	t.Run("valid revocation without checkpoint", func(t *testing.T) {
		require.Empty(t, revocation.Checkpoint)
		require.NoError(t, ValidateTransition(revocation, predecessor))
	})
	t.Run("enrollment checkpoint", func(t *testing.T) {
		withCheckpoint := fixture.transition
		withCheckpoint.Checkpoint = bytes.Clone(fixture.bootstrap.Checkpoint)
		assert.ErrorIs(t, ValidateTransition(withCheckpoint, fixture.predecessor), ErrCheckpointAnchor)
	})
	t.Run("revocation checkpoint", func(t *testing.T) {
		withCheckpoint := revocation
		withCheckpoint.Checkpoint = bytes.Clone(fixture.bootstrap.Checkpoint)
		assert.ErrorIs(t, ValidateTransition(withCheckpoint, predecessor), ErrCheckpointAnchor)
	})
}
