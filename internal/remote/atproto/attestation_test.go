package atproto

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/lamb-systems/dottie/internal/vault"
)

type attestationRelayCapture struct {
	revision *Revision
	bytes    []byte
}

func (capture *attestationRelayCapture) CommitAttestation(_ context.Context, revision *Revision, signedBytes []byte) error {
	capture.revision = revision
	capture.bytes = bytes.Clone(signedBytes)
	return nil
}

func TestPrepareAndPublishAttestationFencedWritesOnlyAttestation(t *testing.T) {
	fixture := newReadFixture(t)
	attestation := vault.Attestation{
		Vault: fixture.request.Vault, DeviceID: "root", PolicyDigest: [32]byte(bytes.Repeat([]byte{1}, 32)),
		RetentionFloor: 1, RetainedRecoveryPoints: 3, ControlCID: readRawCID(t, []byte("control")),
		Signer: vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	signedBytes := signReadAttestation(t, attestation, fixtureSigningKey(11))
	write, err := PrepareAttestationRecordWrite("attest-one", signedBytes)
	require.NoError(t, err)
	assert.Equal(t, RecordCreate, write.Action)
	assert.Equal(t, VaultAttestationNSID, write.Collection)

	proof := makeProofFixture(t, 1)
	revision := &Revision{did: proofTestDID, commitCID: proof.root.String(), membership: map[RecordKey]string{}}
	transport := &proofTransport{
		doStatus: 200,
		doBody:   []byte(`{"commit":{"cid":"bafybeigdyrzt5sfp7udm7hu76uhy26nfjpy2ytma2if42f2qht6lmtkq3u"}}`),
	}
	_, err = PublishAttestationFenced(context.Background(), transport, revision, "attest-one", signedBytes)
	require.NoError(t, err)
	var input applyWritesInput
	require.NoError(t, json.Unmarshal(transport.requestBody, &input))
	require.Len(t, input.Writes, 1)
	var batchWrite struct {
		Collection string          `json:"collection"`
		RKey       string          `json:"rkey"`
		Value      json.RawMessage `json:"value"`
	}
	require.NoError(t, json.Unmarshal(input.Writes[0], &batchWrite))
	assert.Equal(t, VaultAttestationNSID, batchWrite.Collection)
	assert.Equal(t, "attest-one", batchWrite.RKey)
	assert.NotEqual(t, VaultControlNSID, batchWrite.Collection)
	assert.NotEqual(t, VaultHeadNSID, batchWrite.Collection)
	value, err := atdata.UnmarshalJSON(batchWrite.Value)
	require.NoError(t, err)
	record := value["signature"].(atdata.Bytes)
	assert.Equal(t, signedBytes[len(signedBytes)-64:], []byte(record))
}

func TestRelayAttestationPassesSignedBytesUnchanged(t *testing.T) {
	fixture := newReadFixture(t)
	attestation := vault.Attestation{
		Vault: fixture.request.Vault, DeviceID: "root", PolicyDigest: [32]byte(bytes.Repeat([]byte{2}, 32)),
		RetentionFloor: 1, RetainedRecoveryPoints: 3, ControlCID: readRawCID(t, []byte("control")),
		Signer: vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	signedBytes := signReadAttestation(t, attestation, fixtureSigningKey(11))
	proof := makeProofFixture(t, 1)
	revision := &Revision{did: proofTestDID, commitCID: proof.root.String(), membership: map[RecordKey]string{}}
	capture := &attestationRelayCapture{}

	require.NoError(t, RelayAttestation(context.Background(), capture, revision, signedBytes))
	assert.Same(t, revision, capture.revision)
	assert.Equal(t, signedBytes, capture.bytes)
}

func TestVerifyAttestationRecordSurfacesBelowPolicyFloorAndAuthenticatesSigner(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)
	policy.PolicyRetentionFloor = 2
	policyBytes := signReadPolicy(t, policy, fixtureSigningKey(11))
	digest, err := vault.ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	controlRecordValue, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	control := controlFromRecord(controlRecordValue.(ControlRecord))
	control.PolicyDigest = digest
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	certificates := make([][]byte, 0, len(fixture.records))
	for key, data := range fixture.records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		decoded, decodeErr := DecodeRecord(data)
		require.NoError(t, decodeErr)
		certificate, encodeErr := vault.EncodeCertificate(certificateFromRecord(decoded.(CertificateRecord)))
		require.NoError(t, encodeErr)
		certificates = append(certificates, certificate)
	}
	verification := vault.AttestationVerificationRequest{
		VaultID: fixture.request.Vault, TrustAnchor: fixture.request.TrustAnchor,
		State: vault.ControlEvidence{Policy: policyBytes, Control: controlBytes, Certificates: certificates},
	}
	attestation := vault.Attestation{
		Vault: policy.Vault, DeviceID: "root", PolicyDigest: digest,
		RetentionFloor: policy.PolicyRetentionFloor - 1, RetainedRecoveryPoints: policy.RetainedRecoveryPoints,
		ControlCID: readRawCID(t, controlBytes), Signer: vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	signedBytes := signReadAttestation(t, attestation, fixtureSigningKey(11))
	attestation, err = vault.DecodeAttestation(signedBytes)
	require.NoError(t, err)
	recordBytes, err := EncodeRecord(attestationRecordFromVault(attestation))
	require.NoError(t, err)
	decodedRecord, err := DecodeRecord(recordBytes)
	require.NoError(t, err)
	recordObject := decodedRecord.(AttestationRecord)
	reencoded, err := vault.EncodeAttestation(vault.Attestation{
		Vault: [32]byte(recordObject.Vault), DeviceID: recordObject.DeviceID, PolicyDigest: [32]byte(recordObject.PolicyDigest),
		RetentionFloor: recordObject.RetentionFloor, RetainedRecoveryPoints: recordObject.RetainedRecoveryPoints,
		ControlCID: recordObject.ControlCID, Signer: vault.Signer{DeviceID: recordObject.SignerDeviceID, KeyID: recordObject.SignerKeyID},
		Signature: [64]byte(recordObject.Signature),
	})
	require.NoError(t, err)
	assert.Equal(t, signedBytes, reencoded)

	judgement, err := VerifyAttestationRecord(recordBytes, verification)
	require.NoError(t, err)
	assert.Equal(t, vault.AttestationStatusBelowPolicyFloor, judgement.Status)
	assert.True(t, judgement.CompromisedForConfidentiality)
	assert.Equal(t, attestation.RetentionFloor, judgement.Attestation.RetentionFloor)

	attestation.DeviceID = "other-device"
	mismatchedSubject := signReadAttestation(t, attestation, fixtureSigningKey(11))
	mismatched, err := vault.DecodeAttestation(mismatchedSubject)
	require.NoError(t, err)
	mismatchedRecord, err := EncodeRecord(attestationRecordFromVault(mismatched))
	require.NoError(t, err)
	_, err = VerifyAttestationRecord(mismatchedRecord, verification)
	assert.ErrorIs(t, err, vault.ErrAuthorization)

	tampered := bytes.Clone(signedBytes)
	tampered[len(tampered)-1] ^= 0x80
	tamperedAttestation, err := vault.DecodeAttestation(tampered)
	require.NoError(t, err)
	tamperedRecord, err := EncodeRecord(attestationRecordFromVault(tamperedAttestation))
	require.NoError(t, err)
	_, err = VerifyAttestationRecord(tamperedRecord, verification)
	assert.ErrorIs(t, err, vault.ErrSignature)
}
