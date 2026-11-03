package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signTestEnvelope(t *testing.T, envelope Envelope, key ed25519.PrivateKey) Envelope {
	t.Helper()
	prefix, err := encodeEnvelopePrefix(envelope)
	require.NoError(t, err)
	signature, err := Sign(contextForPurpose(envelope.Purpose), append([]byte(preimageSig), prefix...), key)
	require.NoError(t, err)
	copy(envelope.Signature[:], signature)
	return envelope
}

func signedControlForOpenTest(t *testing.T, fixture envelopeFixture, mutate func(*Control), key ed25519.PrivateKey) []byte {
	t.Helper()
	control := Control{
		Vault: fixture.policy.Vault, EpochSeq: fixture.policy.EpochSeq,
		PolicyDigest: fixture.prepared.PolicyDigest,
		Signer:       Signer{DeviceID: fixture.rootCertificate.DeviceID, KeyID: bytes.Clone(fixture.rootCertificate.KeyID)},
	}
	if mutate != nil {
		mutate(&control)
	}
	return signControlValue(t, control, key)
}

func TestOpenRejectsEnvelopeVaultRequestMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	plaintext, err := Open(fixture.envelope, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	hostile := fixture.envelope
	hostile.Vault[0] ^= 1
	hostile = signTestEnvelope(t, hostile, fixture.publisherKey)
	plaintext, err = Open(hostile, fixture.openRequest)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "vault, epoch_seq, or policy_digest")
	assert.Nil(t, plaintext)
}

func TestOpenRejectsPolicyBytesDigestMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	plaintext, err := Open(fixture.envelope, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	policy := fixture.policy
	policy.MaxPublications--
	hostile := fixture.openRequest
	hostile.Policy = signPolicyValue(t, policy, fixture.signingKey)
	plaintext, err = Open(fixture.envelope, hostile)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "policy_digest")
	assert.Nil(t, plaintext)
}

func TestOpenRejectsPolicyVaultRequestMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	plaintext, err := Open(fixture.envelope, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	hostile := fixture.openRequest
	hostile.Vault[0] ^= 1
	plaintext, err = Open(fixture.envelope, hostile)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "policy vault")
	assert.Nil(t, plaintext)
}

func TestOpenRequiresRootPolicySigner(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	plaintext, err := Open(fixture.envelope, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	policy := fixture.policy
	policy.Signer = Signer{DeviceID: fixture.certificate.DeviceID, KeyID: bytes.Clone(fixture.certificate.KeyID)}
	policyBytes := signPolicyValue(t, policy, fixture.publisherKey)
	policyDigest := sha256.Sum256(append([]byte(preimagePolicy), policyBytes...))
	policy, err = DecodePolicy(policyBytes)
	require.NoError(t, err)
	prepared := fixture.prepared
	prepared.Policy = policy
	prepared.PolicyDigest = policyDigest
	envelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Policy = policyBytes
	request.PolicyDigest = policyDigest
	plaintext, err = Open(envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "policy signer")
	assert.Nil(t, plaintext)
}

func TestOpenRequiresRootControlSigner(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := fixture.openRequest
	request.Control = signedControlForOpenTest(t, fixture, nil, fixture.signingKey)
	plaintext, err := Open(fixture.envelope, request)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	request.Control = signedControlForOpenTest(t, fixture, nil, fixture.publisherKey)
	control, err := DecodeControl(request.Control)
	require.NoError(t, err)
	control.Signer = Signer{DeviceID: fixture.certificate.DeviceID, KeyID: bytes.Clone(fixture.certificate.KeyID)}
	request.Control = signControlValue(t, control, fixture.publisherKey)
	plaintext, err = Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "control signer")
	assert.Nil(t, plaintext)
}

func TestOpenRejectsControlVaultRequestMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := fixture.openRequest
	request.Control = signedControlForOpenTest(t, fixture, nil, fixture.signingKey)
	plaintext, err := Open(fixture.envelope, request)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	request.Control = signedControlForOpenTest(t, fixture, func(control *Control) { control.Vault[0] ^= 1 }, fixture.signingKey)
	plaintext, err = Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "control vault or epoch_seq")
	assert.Nil(t, plaintext)
}

func TestOpenRejectsControlEpochRequestMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := fixture.openRequest
	request.Control = signedControlForOpenTest(t, fixture, nil, fixture.signingKey)
	plaintext, err := Open(fixture.envelope, request)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	request.Control = signedControlForOpenTest(t, fixture, func(control *Control) { control.EpochSeq++ }, fixture.signingKey)
	plaintext, err = Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "control vault or epoch_seq")
	assert.Nil(t, plaintext)
}

func TestOpenRejectsControlPolicyDigestRequestMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := fixture.openRequest
	request.Control = signedControlForOpenTest(t, fixture, nil, fixture.signingKey)
	plaintext, err := Open(fixture.envelope, request)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	request.Control = signedControlForOpenTest(t, fixture, func(control *Control) { control.PolicyDigest[0] ^= 1 }, fixture.signingKey)
	plaintext, err = Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "control policy_digest")
	assert.Nil(t, plaintext)
}

func TestOpenRevocationMatchesCertificateDevice(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := fixture.openRequest
	request.Control = signedControlForOpenTest(t, fixture, nil, fixture.signingKey)
	plaintext, err := Open(fixture.envelope, request)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)

	request.Control = signedControlForOpenTest(t, fixture, func(control *Control) {
		control.Revoked = []RevokedDevice{{DeviceID: fixture.certificate.DeviceID, CertEpoch: fixture.certificate.CertEpoch}}
	}, fixture.signingKey)
	plaintext, err = Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "signer revocation")
	assert.Nil(t, plaintext)

	request.Control = signedControlForOpenTest(t, fixture, func(control *Control) {
		control.Revoked = []RevokedDevice{{DeviceID: "device-other", CertEpoch: fixture.certificate.CertEpoch}}
	}, fixture.signingKey)
	plaintext, err = Open(fixture.envelope, request)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)
}

func TestCertificateChainRequiresRequestedVault(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	leaf, err := DecodeCertificate(fixture.certificateBytes)
	require.NoError(t, err)
	require.NoError(t, verifyCertificateChain(leaf, fixture.openRequest, 1, make(map[string]bool)))

	leaf.Vault[0] ^= 1
	encoded := signCertificateValue(t, leaf, fixture.signingKey)
	leaf, err = DecodeCertificate(encoded)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Certificates = [][]byte{fixture.rootCertificateBytes, encoded}
	err = verifyCertificateChain(leaf, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "certificate chain")
}

func TestCertificateChainRequiresRootRole(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	root, err := DecodeCertificate(fixture.rootCertificateBytes)
	require.NoError(t, err)
	require.NoError(t, verifyCertificateChain(root, fixture.openRequest, 1, make(map[string]bool)))

	root.Role = RolePublisher
	encoded := signCertificateValue(t, root, fixture.signingKey)
	root, err = DecodeCertificate(encoded)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Certificates = [][]byte{encoded}
	err = verifyCertificateChain(root, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "root certificate")
}

func TestCertificateChainRequiresRootSignerDeviceIdentity(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	root, err := DecodeCertificate(fixture.rootCertificateBytes)
	require.NoError(t, err)
	require.NoError(t, verifyCertificateChain(root, fixture.openRequest, 1, make(map[string]bool)))

	root.Signer.DeviceID = "device-other"
	encoded := signCertificateValue(t, root, fixture.signingKey)
	root, err = DecodeCertificate(encoded)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Certificates = [][]byte{encoded}
	err = verifyCertificateChain(root, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "root certificate")
}

func TestCertificateChainRequiresRootSignerKeyIdentity(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	root, err := DecodeCertificate(fixture.rootCertificateBytes)
	require.NoError(t, err)
	require.NoError(t, verifyCertificateChain(root, fixture.openRequest, 1, make(map[string]bool)))

	root.Signer.KeyID = []byte("other-root-key")
	encoded := signCertificateValue(t, root, fixture.signingKey)
	root, err = DecodeCertificate(encoded)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Certificates = [][]byte{encoded}
	err = verifyCertificateChain(root, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "root certificate")
}

func TestCertificateChainRequiresLeafSignerDeviceToMatchIssuer(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	leaf, err := DecodeCertificate(fixture.certificateBytes)
	require.NoError(t, err)
	require.NoError(t, verifyCertificateChain(leaf, fixture.openRequest, 1, make(map[string]bool)))

	leaf.Signer.DeviceID = "device-other"
	encoded := signCertificateValue(t, leaf, fixture.signingKey)
	leaf, err = DecodeCertificate(encoded)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Certificates = [][]byte{fixture.rootCertificateBytes, encoded}
	err = verifyCertificateChain(leaf, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "certificate issuer")
}

func TestCertificateChainRequiresLeafSignerKeyToMatchIssuer(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	leaf, err := DecodeCertificate(fixture.certificateBytes)
	require.NoError(t, err)
	require.NoError(t, verifyCertificateChain(leaf, fixture.openRequest, 1, make(map[string]bool)))

	leaf.Signer.KeyID = []byte("other-root-key")
	encoded := signCertificateValue(t, leaf, fixture.signingKey)
	leaf, err = DecodeCertificate(encoded)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Certificates = [][]byte{fixture.rootCertificateBytes, encoded}
	err = verifyCertificateChain(leaf, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "certificate issuer")
}

func TestAuthorizedSignerRequiresPolicyRoleToMatchCertificate(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	certificate, err := authorizedSigner(fixture.envelope, fixture.openRequest, fixture.policy)
	require.NoError(t, err)
	assert.Equal(t, fixture.certificate.Role, certificate.Role)

	policy := fixture.policy
	for index := range policy.Roles {
		if policy.Roles[index].DeviceID == fixture.certificate.DeviceID {
			policy.Roles[index].Role = RoleRoot
		}
	}
	_, err = authorizedSigner(fixture.envelope, fixture.openRequest, policy)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "signer role")
}

func TestAuthorizedSignerRequiresPurposeAllowedForRole(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	certificate, err := authorizedSigner(fixture.envelope, fixture.openRequest, fixture.policy)
	require.NoError(t, err)
	assert.Equal(t, fixture.certificate.Role, certificate.Role)

	prepared := fixture.prepared
	prepared.Purpose = PurposeControl
	hostile, err := SealPrepared(prepared)
	require.NoError(t, err)
	_, err = authorizedSigner(hostile, fixture.openRequest, fixture.policy)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "signer role")
}

func TestSealAuthorizedRequiresCertificateVaultToMatchPolicy(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := SealRequest{
		Purpose: PurposeSnapshot, Vault: fixture.policy.Vault, PublicationID: fixture.prepared.PublicationID,
		EpochSeq: fixture.policy.EpochSeq, PolicyDigest: fixture.prepared.PolicyDigest,
		Parent: bytes.Clone(fixture.prepared.Parent), DeviceID: fixture.certificate.DeviceID,
		KeyID: bytes.Clone(fixture.certificate.KeyID), Plaintext: bytes.Clone(fixture.prepared.Plaintext),
		SigningKey: fixture.publisherKey,
		Recipients: []RecipientPublicKey{{KeyID: []byte("recipient-a"), PublicKey: fixture.recipientKey.PublicKey().Bytes()}},
	}
	_, err := SealAuthorized(request, fixture.certificate, fixture.policy)
	require.NoError(t, err)

	certificate := fixture.certificate
	certificate.Vault[0] ^= 1
	_, err = SealAuthorized(request, certificate, fixture.policy)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "seal vault")
}

func TestSealAuthorizedRequiresPolicyRoleToMatchCertificateRole(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := SealRequest{
		Purpose: PurposeSnapshot, Vault: fixture.policy.Vault, PublicationID: fixture.prepared.PublicationID,
		EpochSeq: fixture.policy.EpochSeq, PolicyDigest: fixture.prepared.PolicyDigest,
		Parent: bytes.Clone(fixture.prepared.Parent), DeviceID: fixture.certificate.DeviceID,
		KeyID: bytes.Clone(fixture.certificate.KeyID), Plaintext: bytes.Clone(fixture.prepared.Plaintext),
		SigningKey: fixture.publisherKey,
		Recipients: []RecipientPublicKey{{KeyID: []byte("recipient-a"), PublicKey: fixture.recipientKey.PublicKey().Bytes()}},
	}
	_, err := SealAuthorized(request, fixture.certificate, fixture.policy)
	require.NoError(t, err)

	policy := fixture.policy
	for index := range policy.Roles {
		if policy.Roles[index].DeviceID == fixture.certificate.DeviceID {
			policy.Roles[index].Role = RoleRoot
		}
	}
	_, err = SealAuthorized(request, fixture.certificate, policy)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "seal role")
}

func TestResolveTrustedCertificateRequiresRequestedKeyID(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	certificate, err := resolveTrustedCertificate(fixture.certificate.DeviceID, fixture.certificate.KeyID, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, fixture.certificate.KeyID, certificate.KeyID)

	certificate, err = resolveTrustedCertificate(fixture.certificate.DeviceID, []byte("different-key"), fixture.openRequest)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "signer certificate")
	assert.Equal(t, Certificate{}, certificate)
}

func TestOpenRejectsPolicySignerWithoutRoleBinding(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	policy := fixture.policy
	policy.Roles = []RoleBinding{{DeviceID: fixture.certificate.DeviceID, Role: RolePublisher}}
	policyBytes := signPolicyValue(t, policy, fixture.signingKey)
	policy, err := DecodePolicy(policyBytes)
	require.NoError(t, err)
	digest := sha256.Sum256(append([]byte(preimagePolicy), policyBytes...))
	prepared := fixture.prepared
	prepared.Policy = policy
	prepared.PolicyDigest = digest
	envelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Policy = policyBytes
	request.PolicyDigest = digest

	plaintext, err := Open(envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	assert.Nil(t, plaintext)
}

func TestAuthorizeControlRejectsSignerWithoutRoleBinding(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	policy := fixture.policy
	policy.Roles = []RoleBinding{{DeviceID: fixture.certificate.DeviceID, Role: RolePublisher}}
	control := Control{
		Vault: fixture.policy.Vault, EpochSeq: fixture.policy.EpochSeq, PolicyDigest: fixture.openRequest.PolicyDigest,
		Signer: Signer{DeviceID: fixture.rootCertificate.DeviceID, KeyID: bytes.Clone(fixture.rootCertificate.KeyID)},
	}
	request := fixture.openRequest
	request.Control = signControlValue(t, control, fixture.signingKey)

	_, err := authorizeControl(request, policy)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func TestOpenValidRecipientDoesNotNeedRedundantKeyIDComparison(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	plaintext, err := Open(fixture.envelope, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)
}
