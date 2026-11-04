package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func publicEnrollmentIntentForFixture(fixture devicesFixture) PublicEnrollmentIntent {
	device := publicDeviceFromMaterial(fixture.newDevice)
	return PublicEnrollmentIntent{
		Vault: fixture.bootstrap.Vault, RootSigner: fixture.root, NewDevice: device, RequestedRole: fixture.intent.RequestedRole,
		ApprovalFingerprint: EnrollmentTranscriptFingerprint(fixture.bootstrap.Vault, device.DeviceID, device.KeyID, fixture.intent.RequestedRole, device.SigningPublicKey, device.RecipientPublicKey),
		ContentKey:          bytes.Clone(fixture.intent.ContentKey), Recipients: cloneByteSlices(fixture.intent.Recipients), Wraps: append([]RecipientWrapInput(nil), fixture.intent.Wraps...),
		Plaintext: bytes.Clone(fixture.intent.Plaintext), PublicationID: fixture.intent.PublicationID, Nonce: fixture.intent.Nonce,
	}
}

func TestPreparePublicEnrollmentUsesOnlyNewDevicePublicMaterial(t *testing.T) {
	fixture := newDevicesFixture(t)
	intent := publicEnrollmentIntentForFixture(fixture)
	transition, err := PreparePublicEnrollment(fixture.predecessor, intent)
	require.NoError(t, err)
	assert.Equal(t, fixture.transition, transition, "public-only enrollment prepares the same deterministic successor")
	assert.Empty(t, transition.Checkpoint, "enrollment does not include a checkpoint")
	assert.Equal(t, fixture.intent.Plaintext, openTransitionSnapshot(t, fixture, transition, fixture.newDevice), "the newcomer's private recipient key opens successor content")
	assert.NoError(t, ValidateTransition(transition, fixture.predecessor))
}

func TestPreparePublicEnrollmentRejectsInputsChangedAfterApproval(t *testing.T) {
	fixture := newDevicesFixture(t)
	changes := []struct {
		name     string
		expected error
		change   func(*PublicEnrollmentIntent)
	}{
		{"vault", ErrAuthorization, func(intent *PublicEnrollmentIntent) { intent.Vault[0] ^= 1 }},
		{"device id", ErrEnrollmentApproval, func(intent *PublicEnrollmentIntent) { intent.NewDevice.DeviceID = "other-device" }},
		{"key id", ErrEnrollmentApproval, func(intent *PublicEnrollmentIntent) { intent.NewDevice.KeyID[0] ^= 1 }},
		{"role", ErrEnrollmentApproval, func(intent *PublicEnrollmentIntent) { intent.RequestedRole = RoleRestoreOnly }},
		{"signing public key", ErrEnrollmentApproval, func(intent *PublicEnrollmentIntent) { intent.NewDevice.SigningPublicKey[0] ^= 1 }},
		{"recipient public key", ErrEnrollmentApproval, func(intent *PublicEnrollmentIntent) {
			intent.NewDevice.RecipientPublicKey = fixedX25519Key(91).PublicKey().Bytes()
		}},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			intent := publicEnrollmentIntentForFixture(fixture)
			change.change(&intent)
			_, err := PreparePublicEnrollment(fixture.predecessor, intent)
			assert.ErrorIs(t, err, change.expected)
		})
	}
}

func TestPreparePublicEnrollmentRejectsMalformedAndLowOrderRecipientKeys(t *testing.T) {
	fixture := newDevicesFixture(t)
	for _, test := range []struct {
		name   string
		change func(*PublicDeviceInput)
	}{
		{"wrong length", func(device *PublicDeviceInput) { device.RecipientPublicKey = []byte{1, 2, 3} }},
		{"low order", func(device *PublicDeviceInput) { device.RecipientPublicKey = make([]byte, 32) }},
		{"malformed signing key", func(device *PublicDeviceInput) { device.SigningPublicKey = []byte{1, 2, 3} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			intent := publicEnrollmentIntentForFixture(fixture)
			test.change(&intent.NewDevice)
			intent.ApprovalFingerprint = EnrollmentTranscriptFingerprint(intent.Vault, intent.NewDevice.DeviceID, intent.NewDevice.KeyID, intent.RequestedRole, intent.NewDevice.SigningPublicKey, intent.NewDevice.RecipientPublicKey)
			_, err := PreparePublicEnrollment(fixture.predecessor, intent)
			assert.Error(t, err)
		})
	}
}

func TestPreparePublicEnrollmentRejectsDuplicateIdentityAndRootRole(t *testing.T) {
	fixture := newDevicesFixture(t)
	for _, test := range []struct {
		name   string
		change func(*PublicEnrollmentIntent)
	}{
		{"duplicate device id", func(intent *PublicEnrollmentIntent) { intent.NewDevice.DeviceID = fixture.root.DeviceID }},
		{"duplicate key id", func(intent *PublicEnrollmentIntent) { intent.NewDevice.KeyID = bytes.Clone(fixture.root.KeyID) }},
		{"root role", func(intent *PublicEnrollmentIntent) { intent.RequestedRole = RoleRoot }},
	} {
		t.Run(test.name, func(t *testing.T) {
			intent := publicEnrollmentIntentForFixture(fixture)
			test.change(&intent)
			intent.ApprovalFingerprint = EnrollmentTranscriptFingerprint(intent.Vault, intent.NewDevice.DeviceID, intent.NewDevice.KeyID, intent.RequestedRole, intent.NewDevice.SigningPublicKey, intent.NewDevice.RecipientPublicKey)
			_, err := PreparePublicEnrollment(fixture.predecessor, intent)
			assert.Error(t, err)
		})
	}
}

func TestPreparePublicEnrollmentRejectsNonRootAdministratorAndWrongSigningKey(t *testing.T) {
	fixture := newDevicesFixture(t)
	intent := publicEnrollmentIntentForFixture(fixture)
	intent.RootSigner = fixture.newDevice
	_, err := PreparePublicEnrollment(fixture.predecessor, intent)
	assert.ErrorIs(t, err, ErrAuthorization)

	intent = publicEnrollmentIntentForFixture(fixture)
	intent.RootSigner.Signing = fixedSigningKey(77)
	_, err = PreparePublicEnrollment(fixture.predecessor, intent)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func TestPreparePublicEnrollmentRejectsInvalidPredecessorAndIncompleteRecipientSets(t *testing.T) {
	fixture := newDevicesFixture(t)
	intent := publicEnrollmentIntentForFixture(fixture)
	invalidPredecessor := fixture.predecessor
	invalidPredecessor.Control = []byte("not a control")
	_, err := PreparePublicEnrollment(invalidPredecessor, intent)
	assert.Error(t, err)

	wrongEpoch := fixture.predecessor
	wrongEpoch.EpochSeq++
	_, err = PreparePublicEnrollment(wrongEpoch, intent)
	assert.Error(t, err)

	cases := []struct {
		name   string
		change func(*PublicEnrollmentIntent)
	}{
		{"omitted recipient", func(intent *PublicEnrollmentIntent) { intent.Recipients = nil }},
		{"extra recipient", func(intent *PublicEnrollmentIntent) {
			intent.Recipients = append(intent.Recipients, bytes.Clone(intent.Recipients[0]))
		}},
		{"substituted recipient", func(intent *PublicEnrollmentIntent) { intent.Recipients[0] = []byte("substituted certificate") }},
		{"omitted wrap", func(intent *PublicEnrollmentIntent) { intent.Wraps = intent.Wraps[:1] }},
		{"extra wrap", func(intent *PublicEnrollmentIntent) {
			intent.Wraps = append(intent.Wraps, RecipientWrapInput{KeyID: []byte("extra-key")})
		}},
		{"substituted wrap", func(intent *PublicEnrollmentIntent) { intent.Wraps[0].KeyID = []byte("wrong-key") }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			intent := publicEnrollmentIntentForFixture(fixture)
			test.change(&intent)
			_, err := PreparePublicEnrollment(fixture.predecessor, intent)
			assert.Error(t, err)
		})
	}
}

func TestPreparePublicEnrollmentTransitionStillRejectsTamperedCertificateAndCheckpoint(t *testing.T) {
	fixture := newDevicesFixture(t)
	intent := publicEnrollmentIntentForFixture(fixture)
	transition, err := PreparePublicEnrollment(fixture.predecessor, intent)
	require.NoError(t, err)

	certificate, err := DecodeCertificate(transition.Certificate)
	require.NoError(t, err)
	certificate.Issuer = "changed-issuer"
	transition.Certificate = signCertificateValue(t, certificate, fixture.root.Signing)
	transition.Digest = ComputeTransitionDigest(transition)
	assert.ErrorIs(t, ValidateTransition(transition, fixture.predecessor), ErrCertificateAuthority)

	transition, err = PreparePublicEnrollment(fixture.predecessor, intent)
	require.NoError(t, err)
	transition.Checkpoint = bytes.Clone(fixture.bootstrap.Checkpoint)
	assert.ErrorIs(t, ValidateTransition(transition, fixture.predecessor), ErrCheckpointAnchor)
}

func TestPublicEnrollmentApprovalFingerprintBindsBothPublicKeys(t *testing.T) {
	fixture := newDevicesFixture(t)
	device := publicDeviceFromMaterial(fixture.newDevice)
	base := EnrollmentTranscriptFingerprint(fixture.bootstrap.Vault, device.DeviceID, device.KeyID, RolePublisher, device.SigningPublicKey, device.RecipientPublicKey)
	changedSigning := bytes.Clone(device.SigningPublicKey)
	changedSigning[0] ^= 1
	changedRecipient := bytes.Clone(device.RecipientPublicKey)
	changedRecipient[0] ^= 1
	assert.NotEqual(t, base, EnrollmentTranscriptFingerprint(fixture.bootstrap.Vault, device.DeviceID, device.KeyID, RolePublisher, changedSigning, device.RecipientPublicKey))
	assert.NotEqual(t, base, EnrollmentTranscriptFingerprint(fixture.bootstrap.Vault, device.DeviceID, device.KeyID, RolePublisher, device.SigningPublicKey, changedRecipient))
	assert.Len(t, device.SigningPublicKey, ed25519.PublicKeySize)
}
