package vault

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareRevocationAllowsRevokingReissuedCertificate(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor, firstControl := predecessorAfterReenrollment(t, fixture)
	targetCertificate, found := findCertificate(predecessor.Certificates, fixture.newDevice.DeviceID, fixture.newDevice.KeyID)
	require.True(t, found)
	assert.Equal(t, uint64(3), targetCertificate.CertEpoch)
	assert.Equal(t, uint64(1), firstControl.Revoked[0].CertEpoch)

	transition, err := PrepareTransition(predecessor, revocationIntent(fixture, predecessor, 61))
	require.NoError(t, err)
	control, err := DecodeControl(transition.Control)
	require.NoError(t, err)
	require.Len(t, control.Revoked, 2)
	assert.Equal(t, firstControl.Revoked[0], control.Revoked[0])
	assert.Equal(t, RevokedDevice{DeviceID: fixture.newDevice.DeviceID, CertEpoch: targetCertificate.CertEpoch}, control.Revoked[1])
}

func TestPrepareRevocationPreservesOlderRevocationHistory(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor, firstControl := predecessorAfterReenrollment(t, fixture)
	transition, err := PrepareTransition(predecessor, revocationIntent(fixture, predecessor, 61))
	require.NoError(t, err)
	control, err := DecodeControl(transition.Control)
	require.NoError(t, err)
	require.Len(t, control.Revoked, 2)
	assert.Equal(t, firstControl.Revoked, control.Revoked[:len(firstControl.Revoked)])
}

func TestPrepareRevocationRejectsSameCertificateEpoch(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	targetCertificate, found := findCertificate(predecessor.Certificates, fixture.newDevice.DeviceID, fixture.newDevice.KeyID)
	require.True(t, found)
	control, err := DecodeControl(predecessor.Control)
	require.NoError(t, err)
	control.Revoked = append(control.Revoked, RevokedDevice{DeviceID: targetCertificate.DeviceID, CertEpoch: targetCertificate.CertEpoch})
	predecessor.Control = signControlValue(t, control, fixture.root.Signing)
	predecessor.ControlCID, err = rawCID(predecessor.Control)
	require.NoError(t, err)

	_, err = PrepareTransition(predecessor, revocationIntent(fixture, predecessor, 31))
	require.ErrorIs(t, err, ErrRevokedDevice)
}

func TestPrepareRevocationRejectsPriorLaterCertificateEpoch(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	targetCertificate, found := findCertificate(predecessor.Certificates, fixture.newDevice.DeviceID, fixture.newDevice.KeyID)
	require.True(t, found)
	control, err := DecodeControl(predecessor.Control)
	require.NoError(t, err)
	control.Revoked = append(control.Revoked, RevokedDevice{DeviceID: targetCertificate.DeviceID, CertEpoch: targetCertificate.CertEpoch + 1})
	predecessor.Control = signControlValue(t, control, fixture.root.Signing)
	predecessor.ControlCID, err = rawCID(predecessor.Control)
	require.NoError(t, err)

	_, err = PrepareTransition(predecessor, revocationIntent(fixture, predecessor, 31))
	require.ErrorIs(t, err, ErrRevokedDevice)
}

func predecessorAfterReenrollment(t *testing.T, fixture devicesFixture) (Predecessor, Control) {
	t.Helper()
	firstPredecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	firstRevocation, err := PrepareTransition(firstPredecessor, revocationIntent(fixture, firstPredecessor, 31))
	require.NoError(t, err)
	firstControl, err := DecodeControl(firstRevocation.Control)
	require.NoError(t, err)
	afterFirstRevocation := predecessorAfterTransition(t, firstPredecessor, firstRevocation)

	enrollment, err := PrepareTransition(afterFirstRevocation, TransitionIntent{
		Kind: TransitionEnroll, Vault: fixture.bootstrap.Vault, Signer: fixture.root,
		NewDevice: &fixture.newDevice, RequestedRole: RolePublisher, ContentKey: fixtureBytes(41, 32),
		Recipients: cloneByteSlices(afterFirstRevocation.Certificates),
		Wraps: []RecipientWrapInput{
			{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(51, 32)), WrapNonce: [24]byte(fixtureBytes(83, 24))},
			{KeyID: bytes.Clone(fixture.newDevice.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(115, 32)), WrapNonce: [24]byte(fixtureBytes(147, 24))},
		},
		Plaintext: []byte("state after re-enrollment"), PublicationID: [16]byte(fixtureBytes(179, 16)), Nonce: [24]byte(fixtureBytes(195, 24)),
	})
	require.NoError(t, err)
	reissuedCertificate, err := DecodeCertificate(enrollment.Certificate)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), reissuedCertificate.CertEpoch)
	return predecessorAfterTransition(t, afterFirstRevocation, enrollment), firstControl
}

func revocationIntent(fixture devicesFixture, predecessor Predecessor, seed byte) TransitionIntent {
	return TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root,
		RevokeDeviceID: fixture.newDevice.DeviceID, ContentKey: fixtureBytes(seed, 32),
		Recipients: [][]byte{bytes.Clone(predecessor.Certificates[0])},
		Wraps: []RecipientWrapInput{{
			KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(seed+1, 32)),
			WrapNonce: [24]byte(fixtureBytes(seed+2, 24)),
		}},
		Plaintext: []byte("state after revocation"), PublicationID: [16]byte(fixtureBytes(seed+3, 16)),
		Nonce: [24]byte(fixtureBytes(seed+4, 24)),
	}
}

func TestValidatePublicationSignerRejectsRevokedCertificate(t *testing.T) {
	fixture, predecessor, _, _ := newPublicationTestFixture(t)
	policy, err := DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	control, err := DecodeControl(predecessor.Control)
	require.NoError(t, err)

	_, err = validatePublicationSigner(predecessor, policy, control, fixture.newDevice.DeviceID, fixture.newDevice.KeyID)
	require.NoError(t, err)

	certificate, found := findCertificate(predecessor.Certificates, fixture.newDevice.DeviceID, fixture.newDevice.KeyID)
	require.True(t, found)
	control.Revoked = append(control.Revoked, RevokedDevice{DeviceID: certificate.DeviceID, CertEpoch: certificate.CertEpoch})
	predecessor.Control = signControlValue(t, control, fixture.root.Signing)
	predecessor.ControlCID, err = rawCID(predecessor.Control)
	require.NoError(t, err)
	require.NoError(t, validatePredecessor(predecessor))
	control, err = DecodeControl(predecessor.Control)
	require.NoError(t, err)
	_, err = validatePublicationSigner(predecessor, policy, control, fixture.newDevice.DeviceID, fixture.newDevice.KeyID)
	require.ErrorIs(t, err, ErrPublicationAuthority)
}

func TestPrepareRevocationRejectsAlreadyRevokedCertificate(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	control, err := DecodeControl(predecessor.Control)
	require.NoError(t, err)
	control.Revoked = append(control.Revoked, RevokedDevice{DeviceID: fixture.newDevice.DeviceID, CertEpoch: predecessor.EpochSeq})
	predecessor.Control = signControlValue(t, control, fixture.root.Signing)
	predecessor.ControlCID, err = rawCID(predecessor.Control)
	require.NoError(t, err)
	require.NoError(t, validatePredecessor(predecessor))

	intent := TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root, RevokeDeviceID: fixture.newDevice.DeviceID,
		ContentKey: fixtureBytes(31, 32), Recipients: [][]byte{bytes.Clone(predecessor.Certificates[0])},
		Wraps: []RecipientWrapInput{{
			KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(91, 32)),
			WrapNonce: [24]byte(fixtureBytes(123, 24)),
		}},
		Plaintext: []byte("synthetic state after repeated revocation"), PublicationID: [16]byte(fixtureBytes(157, 16)),
		Nonce: [24]byte(fixtureBytes(173, 24)),
	}
	_, err = PrepareTransition(predecessor, intent)
	require.ErrorIs(t, err, ErrRevokedDevice)
}

func TestValidateRevocationDeltaAddedEntryMatchesTargetCertificate(t *testing.T) {
	fixture, predecessor, _, _ := newPublicationTestFixture(t)
	revocation, err := PrepareTransition(predecessor, TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root, RevokeDeviceID: fixture.newDevice.DeviceID,
		ContentKey: fixtureBytes(31, 32), Recipients: [][]byte{bytes.Clone(predecessor.Certificates[0])},
		Wraps: []RecipientWrapInput{{
			KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(91, 32)),
			WrapNonce: [24]byte(fixtureBytes(123, 24)),
		}},
		Plaintext: []byte("synthetic state after revocation"), PublicationID: [16]byte(fixtureBytes(157, 16)),
		Nonce: [24]byte(fixtureBytes(173, 24)),
	})
	require.NoError(t, err)
	require.NoError(t, ValidateTransition(revocation, predecessor))

	for _, mutate := range []struct {
		name string
		edit func(*RevokedDevice)
	}{
		{
			name: "device ID",
			edit: func(revoked *RevokedDevice) {
				revoked.DeviceID = "other-device"
			},
		},
		{
			name: "certificate epoch",
			edit: func(revoked *RevokedDevice) {
				revoked.CertEpoch++
			},
		},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			altered := revocation
			control, decodeErr := DecodeControl(altered.Control)
			require.NoError(t, decodeErr)
			require.NotEmpty(t, control.Revoked)
			mutate.edit(&control.Revoked[len(control.Revoked)-1])
			altered.Control = signControlValue(t, control, fixture.root.Signing)
			altered.Digest = ComputeTransitionDigest(altered)

			err := ValidateTransition(altered, predecessor)
			require.ErrorIs(t, err, ErrRevokedDevice)
		})
	}
}
