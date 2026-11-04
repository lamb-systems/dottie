package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type attestationFixture struct {
	request AttestationBuildRequest
	verify  AttestationVerificationRequest
	key     ed25519.PrivateKey
}

func newAttestationFixture(t *testing.T) attestationFixture {
	t.Helper()
	base := newEnvelopeFixture(t)
	key := fixedSigningKey(77)
	certificate := Certificate{
		Vault: base.policy.Vault, DeviceID: "device-restore", KeyID: []byte("signer-restore"),
		SigningPublicKey:    [ed25519.PublicKeySize]byte(key.Public().(ed25519.PublicKey)),
		EncryptionPublicKey: [32]byte(fixedX25519Key(78).PublicKey().Bytes()), Role: RoleRestoreOnly, CertEpoch: base.policy.EpochSeq,
		Issuer: base.rootCertificate.DeviceID, Signer: Signer{DeviceID: base.rootCertificate.DeviceID, KeyID: bytes.Clone(base.rootCertificate.KeyID)},
	}
	certificateBytes := signCertificateValue(t, certificate, base.signingKey)
	policy := base.policy
	policy.Roles = append(policy.Roles, RoleBinding{DeviceID: certificate.DeviceID, Role: RoleRestoreOnly})
	policyBytes := signPolicyValue(t, policy, base.signingKey)
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	controlBytes := signControlValue(t, Control{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: policyDigest,
		Signer: Signer{DeviceID: base.rootCertificate.DeviceID, KeyID: bytes.Clone(base.rootCertificate.KeyID)},
	}, base.signingKey)
	state := ControlEvidence{
		Control: controlBytes, Policy: policyBytes,
		Certificates: [][]byte{bytes.Clone(base.rootCertificateBytes), bytes.Clone(certificateBytes)},
	}
	return attestationFixture{
		request: AttestationBuildRequest{
			VaultID: policy.Vault, TrustAnchor: base.trustAnchor, State: state,
			SignerCertificate: certificateBytes, SigningKey: key,
			RetentionFloor: policy.PolicyRetentionFloor - 1, RetainedRecoveryPoints: policy.RetainedRecoveryPoints,
			RecoveryPoints: []RetentionRecoveryPoint{
				{Epoch: 0, SnapshotCID: []byte("snapshot-zero")},
				{Epoch: policy.EpochSeq, SnapshotCID: []byte("snapshot-current-a")},
				{Epoch: policy.EpochSeq, SnapshotCID: []byte("snapshot-current-b")},
			},
		},
		verify: AttestationVerificationRequest{VaultID: policy.Vault, TrustAnchor: base.trustAnchor, State: state},
		key:    key,
	}
}

func TestBuildAndVerifyAttestationForRestoreOnlyDevice(t *testing.T) {
	fixture := newAttestationFixture(t)
	encoded, err := BuildAttestation(fixture.request)
	require.NoError(t, err)
	attestation, err := DecodeAttestation(encoded)
	require.NoError(t, err)
	assert.Equal(t, "device-restore", attestation.DeviceID)
	assert.Equal(t, attestation.DeviceID, attestation.Signer.DeviceID)
	assert.Equal(t, fixture.request.RetentionFloor, attestation.RetentionFloor)
	assert.Equal(t, fixture.request.RetainedRecoveryPoints, attestation.RetainedRecoveryPoints)

	certificate, err := DecodeCertificate(fixture.request.SignerCertificate)
	require.NoError(t, err)
	prefix, err := encodeAttestationPrefix(attestation)
	require.NoError(t, err)
	require.NoError(t, Verify(contextForPurpose(PurposeAttestation), objectSignaturePreimage(prefix), attestation.Signature[:], certificate.SigningPublicKey[:]))

	judgement, err := VerifyAttestation(encoded, fixture.verify)
	require.NoError(t, err)
	assert.Equal(t, AttestationStatusBelowPolicyFloor, judgement.Status)
	assert.True(t, judgement.CompromisedForConfidentiality)
	assert.Equal(t, fixture.request.RetentionFloor, judgement.Attestation.RetentionFloor)
}

func TestVerifyAttestationBindsToAuthenticatedState(t *testing.T) {
	fixture := newAttestationFixture(t)
	encoded, err := BuildAttestation(fixture.request)
	require.NoError(t, err)
	original, err := DecodeAttestation(encoded)
	require.NoError(t, err)
	for _, test := range []struct {
		name   string
		mutate func(*Attestation)
	}{
		{name: "vault", mutate: func(value *Attestation) { value.Vault[0] ^= 0x80 }},
		{name: "policy digest", mutate: func(value *Attestation) { value.PolicyDigest[0] ^= 0x80 }},
		{name: "control CID", mutate: func(value *Attestation) { value.ControlCID[0] ^= 0x80 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := original
			value.ControlCID = bytes.Clone(original.ControlCID)
			test.mutate(&value)
			forged := signAttestationValue(t, value, fixture.key)
			_, err := VerifyAttestation(forged, fixture.verify)
			assert.ErrorIs(t, err, ErrAuthorization)
		})
	}
}

func TestVerifyAttestationRefusesInvalidSignature(t *testing.T) {
	fixture := newAttestationFixture(t)
	encoded, err := BuildAttestation(fixture.request)
	require.NoError(t, err)
	encoded[len(encoded)-1] ^= 0x80

	_, err = VerifyAttestation(encoded, fixture.verify)
	assert.ErrorIs(t, err, ErrSignature)
}

func TestVerifyAttestationJoinsSignerToSubjectDevice(t *testing.T) {
	fixture := newAttestationFixture(t)
	encoded, err := BuildAttestation(fixture.request)
	require.NoError(t, err)
	attestation, err := DecodeAttestation(encoded)
	require.NoError(t, err)
	attestation.DeviceID = "other-device"
	encoded = signAttestationValue(t, attestation, fixture.key)

	_, err = VerifyAttestation(encoded, fixture.verify)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func TestVerifyAttestationRejectsSignerNotAuthorizedByCurrentPolicy(t *testing.T) {
	fixture := newAttestationFixture(t)
	policy, err := DecodePolicy(fixture.request.State.Policy)
	require.NoError(t, err)
	policy.Roles = policy.Roles[:len(policy.Roles)-1]
	policyBytes := signPolicyValue(t, policy, fixedSigningKey(11))
	digest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	control, err := DecodeControl(fixture.request.State.Control)
	require.NoError(t, err)
	control.PolicyDigest = digest
	controlBytes := signControlValue(t, control, fixedSigningKey(11))
	controlCID, err := rawCID(controlBytes)
	require.NoError(t, err)
	attestationBytes := signAttestationValue(t, Attestation{
		Vault: policy.Vault, DeviceID: "device-restore", PolicyDigest: digest,
		RetentionFloor: policy.PolicyRetentionFloor, RetainedRecoveryPoints: policy.RetainedRecoveryPoints,
		ControlCID: controlCID, Signer: Signer{DeviceID: "device-restore", KeyID: []byte("signer-restore")},
	}, fixture.key)
	state := fixture.verify
	state.State = ControlEvidence{
		Policy: policyBytes, Control: controlBytes, Certificates: fixture.request.State.Certificates,
	}

	_, err = VerifyAttestation(attestationBytes, state)
	assert.ErrorIs(t, err, ErrAuthorization)
}
