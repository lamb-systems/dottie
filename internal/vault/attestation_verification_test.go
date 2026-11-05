package vault

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyAttestationAtPolicyFloorMeetsPolicy(t *testing.T) {
	fixture := newAttestationFixture(t)
	policy, err := DecodePolicy(fixture.verify.State.Policy)
	require.NoError(t, err)
	fixture.request.RetentionFloor = policy.PolicyRetentionFloor
	encoded, err := BuildAttestation(fixture.request)
	require.NoError(t, err)

	judgement, err := VerifyAttestation(encoded, fixture.verify)
	require.NoError(t, err)
	assert.Equal(t, AttestationStatusMeetsPolicy, judgement.Status)
	assert.False(t, judgement.CompromisedForConfidentiality)
	assert.Equal(t, policy.PolicyRetentionFloor, judgement.Attestation.RetentionFloor)
}

func TestVerifyAttestationRefusesPolicyRoleCertificateRoleMismatch(t *testing.T) {
	fixture := newAttestationFixture(t)
	encoded, verification := buildAttestationWithVerificationEvidence(t, fixture, func(policy *Policy) {
		for index := range policy.Roles {
			if policy.Roles[index].DeviceID == "device-restore" {
				policy.Roles[index].Role = RolePublisher
			}
		}
	}, nil)
	fixture.request.State = verification.State
	_, buildErr := BuildAttestation(fixture.request)
	assert.ErrorIs(t, buildErr, ErrAuthorization)

	_, err := VerifyAttestation(encoded, verification)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func TestAttestationRefusesRevokedSigner(t *testing.T) {
	fixture := newAttestationFixture(t)
	certificate, err := DecodeCertificate(fixture.request.SignerCertificate)
	require.NoError(t, err)
	encoded, verification := buildAttestationWithVerificationEvidence(t, fixture, nil, func(control *Control) {
		control.Revoked = append(control.Revoked, RevokedDevice{DeviceID: certificate.DeviceID, CertEpoch: certificate.CertEpoch})
	})
	request := fixture.request
	request.State = verification.State
	_, buildErr := BuildAttestation(request)
	assert.ErrorIs(t, buildErr, ErrAuthorization)

	_, err = VerifyAttestation(encoded, verification)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func TestBuildAttestationRefusesUnknownEpochMaterialEvenAtZeroFloor(t *testing.T) {
	fixture := newAttestationFixture(t)
	fixture.request.RetentionFloor = 0
	fixture.request.UnknownEpochMaterial = true

	encoded, err := BuildAttestation(fixture.request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.Nil(t, encoded)
}

func TestBuildAttestationRequiresCertificateSigningKey(t *testing.T) {
	fixture := newAttestationFixture(t)
	fixture.request.SigningKey = fixedSigningKey(99)

	_, err := BuildAttestation(fixture.request)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func buildAttestationWithVerificationEvidence(t *testing.T, fixture attestationFixture, mutatePolicy func(*Policy), mutateControl func(*Control)) ([]byte, AttestationVerificationRequest) {
	t.Helper()
	policy, err := DecodePolicy(fixture.verify.State.Policy)
	require.NoError(t, err)
	if mutatePolicy != nil {
		mutatePolicy(&policy)
	}
	policyBytes := signPolicyValue(t, policy, fixedSigningKey(11))
	policy, err = DecodePolicy(policyBytes)
	require.NoError(t, err)
	digest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	control, err := DecodeControl(fixture.verify.State.Control)
	require.NoError(t, err)
	control.PolicyDigest = digest
	if mutateControl != nil {
		mutateControl(&control)
	}
	controlBytes := signControlValue(t, control, fixedSigningKey(11))
	controlCID, err := rawCID(controlBytes)
	require.NoError(t, err)
	certificate, err := DecodeCertificate(fixture.request.SignerCertificate)
	require.NoError(t, err)
	attestationBytes := signAttestationValue(t, Attestation{
		Vault: policy.Vault, DeviceID: certificate.DeviceID, PolicyDigest: digest,
		RetentionFloor: policy.PolicyRetentionFloor, RetainedRecoveryPoints: policy.RetainedRecoveryPoints,
		ControlCID: controlCID, Signer: Signer{DeviceID: certificate.DeviceID, KeyID: bytes.Clone(certificate.KeyID)},
	}, fixture.key)
	verification := fixture.verify
	verification.State = ControlEvidence{
		Control: controlBytes, Policy: policyBytes, Certificates: cloneByteSlices(fixture.verify.State.Certificates),
	}
	return attestationBytes, verification
}
