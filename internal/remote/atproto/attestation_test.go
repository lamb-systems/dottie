package atproto

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
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
	verification := readAttestationVerification(t, fixture)
	policy, err := vault.DecodePolicy(verification.State.Policy)
	require.NoError(t, err)
	attestation := vault.Attestation{
		Vault: fixture.request.Vault, DeviceID: "root", PolicyDigest: policyDigestBytes(t, verification.State.Policy),
		RetentionFloor: policy.PolicyRetentionFloor, RetainedRecoveryPoints: 0, ControlCID: readRawCID(t, verification.State.Control),
		Signer: vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	signedBytes := signReadAttestation(t, attestation, fixtureSigningKey(11))
	rkey, err := AttestationRecordRKey(signedBytes)
	require.NoError(t, err)
	write, err := PrepareAttestationRecordWrite(rkey, signedBytes)
	require.NoError(t, err)
	assert.Equal(t, RecordCreate, write.Action)
	assert.Equal(t, VaultAttestationNSID, write.Collection)

	proof := makeProofFixture(t, 1)
	revision := attestationContextRevision(t, verification, proof.root.String())
	transport := &proofTransport{
		doStatus: 200,
		doBody:   []byte(`{"commit":{"cid":"bafybeigdyrzt5sfp7udm7hu76uhy26nfjpy2ytma2if42f2qht6lmtkq3u"}}`),
	}
	_, err = PublishAttestationFenced(context.Background(), transport, revision, rkey, signedBytes, verification)
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
	assert.Equal(t, rkey, batchWrite.RKey)
	assert.NotEqual(t, VaultControlNSID, batchWrite.Collection)
	assert.NotEqual(t, VaultHeadNSID, batchWrite.Collection)
	value, err := atdata.UnmarshalJSON(batchWrite.Value)
	require.NoError(t, err)
	record := value["signature"].(atdata.Bytes)
	assert.Equal(t, signedBytes[len(signedBytes)-64:], []byte(record))
}

func TestRelayAttestationPassesSignedBytesUnchanged(t *testing.T) {
	fixture := newReadFixture(t)
	verification := readAttestationVerification(t, fixture)
	policy, err := vault.DecodePolicy(verification.State.Policy)
	require.NoError(t, err)
	attestation := vault.Attestation{
		Vault: fixture.request.Vault, DeviceID: "root", PolicyDigest: policyDigestBytes(t, verification.State.Policy),
		RetentionFloor: policy.PolicyRetentionFloor, ControlCID: readRawCID(t, verification.State.Control),
		Signer: vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	signedBytes := signReadAttestation(t, attestation, fixtureSigningKey(11))
	proof := makeProofFixture(t, 1)
	revision := &Revision{did: proofTestDID, commitCID: proof.root.String(), membership: map[RecordKey]string{}}
	capture := &attestationRelayCapture{}

	require.NoError(t, RelayAttestation(context.Background(), capture, revision, signedBytes, verification))
	assert.Same(t, revision, capture.revision)
	assert.Equal(t, signedBytes, capture.bytes)

	tampered := bytes.Clone(signedBytes)
	tampered[len(tampered)-1] ^= 0x80
	err = RelayAttestation(context.Background(), capture, revision, tampered, verification)
	assert.ErrorIs(t, err, ErrBatchRejected)
	assert.Equal(t, signedBytes, capture.bytes)

	wrongSubject, err := vault.DecodeAttestation(signedBytes)
	require.NoError(t, err)
	wrongSubject.DeviceID = "other-device"
	wrongSubjectBytes := signReadAttestation(t, wrongSubject, fixtureSigningKey(11))
	err = RelayAttestation(context.Background(), capture, revision, wrongSubjectBytes, verification)
	assert.ErrorIs(t, err, ErrBatchRejected)
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

func attestationContextRevision(t *testing.T, verification vault.AttestationVerificationRequest, commitCID string) *Revision {
	t.Helper()
	policy, err := vault.DecodePolicy(verification.State.Policy)
	require.NoError(t, err)
	control, err := vault.DecodeControl(verification.State.Control)
	require.NoError(t, err)
	records := map[RecordKey]ProvenRecord{}
	membership := map[RecordKey]string{}
	for key, value := range map[RecordKey]Record{
		{Collection: VaultPolicyNSID, RKey: "self"}:  toPolicyRecord(policy),
		{Collection: VaultControlNSID, RKey: "self"}: toControlRecord(control),
	} {
		data, encodeErr := EncodeRecord(value)
		require.NoError(t, encodeErr)
		encodedCID, cidErr := recordCID(data)
		require.NoError(t, cidErr)
		parsedCID, cidErr := cid.Cast(encodedCID)
		require.NoError(t, cidErr)
		membership[key] = parsedCID.String()
		records[key] = ProvenRecord{CID: parsedCID.String(), Data: data}
	}
	return &Revision{did: proofTestDID, commitCID: commitCID, membership: membership, records: records}
}

func readAttestationVerification(t *testing.T, fixture readFixture) vault.AttestationVerificationRequest {
	t.Helper()
	_, policyBytes, _ := fixturePolicyParts(t, fixture)
	controlRecord, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	controlBytes, err := vault.EncodeControl(controlFromRecord(controlRecord.(ControlRecord)))
	require.NoError(t, err)
	certificates := make([][]byte, 0)
	for key, data := range fixture.records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		record, decodeErr := DecodeRecord(data)
		require.NoError(t, decodeErr)
		certificate, encodeErr := vault.EncodeCertificate(certificateFromRecord(record.(CertificateRecord)))
		require.NoError(t, encodeErr)
		certificates = append(certificates, certificate)
	}
	return vault.AttestationVerificationRequest{
		VaultID: fixture.request.Vault, TrustAnchor: fixture.request.TrustAnchor,
		State: vault.ControlEvidence{Policy: policyBytes, Control: controlBytes, Certificates: certificates},
	}
}

func policyDigestBytes(t *testing.T, policy []byte) [32]byte {
	t.Helper()
	digest, err := vault.ComputePolicyDigest(policy)
	require.NoError(t, err)
	return digest
}
