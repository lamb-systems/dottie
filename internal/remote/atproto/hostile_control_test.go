package atproto

import (
	"bytes"
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestReaderRejectsInvalidPreviousControlRecordType(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.request.PreviousControl = []byte("not a control record")

	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlType)
}

func TestReaderRejectsInvalidPreviousControlSignature(t *testing.T) {
	fixture := newReadFixture(t)
	decoded, err := DecodeRecord(fixture.request.PreviousControl)
	require.NoError(t, err)
	record, ok := decoded.(ControlRecord)
	require.True(t, ok)
	record.Signature[0] ^= 0xff
	fixture.request.PreviousControl, err = EncodeRecord(record)
	require.NoError(t, err)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlSignature)
}

func TestReaderRejectsPreviousControlSignerMismatch(t *testing.T) {
	fixture := newReadFixture(t)
	genesisRecord, err := DecodeRecord(fixture.request.PreviousPolicy)
	require.NoError(t, err)
	genesisPolicy := policyFromRecord(genesisRecord.(PolicyRecord))
	genesisPolicy.Roles = []vault.RoleBinding{
		{DeviceID: "alternate-root", Role: vault.RoleRoot},
		{DeviceID: "root", Role: vault.RoleRoot},
	}
	genesisPolicyBytes := signReadPolicy(t, genesisPolicy, fixtureSigningKey(11))
	genesisDigest := readPolicyDigest(t, genesisPolicyBytes)
	genesisPolicyObject, err := vault.DecodePolicy(genesisPolicyBytes)
	require.NoError(t, err)
	genesisPolicyRecord, err := EncodeRecord(policyRecordFromObject(genesisPolicyObject))
	require.NoError(t, err)

	alternateRootSigning := fixtureSigningKey(61)
	alternateRootRecipient := readX25519Key(t, 62)
	alternateRootCert, _ := dualRootCertificate(
		t, fixture.request.Vault, "alternate-root", []byte("alternate-root-sign"), alternateRootSigning,
		alternateRootRecipient, 0, "root", []byte("root-sign"), fixtureSigningKey(11),
	)
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultCertificateNSID, RKey: "alternate-root"}, certificateRecordFromObject(mustReadCertificate(t, alternateRootCert)))

	successorPolicyRecord, successorPolicy, successorDigest := craftSuccessorPolicy(t, fixture, 1, genesisDigest)
	snapshotBytes, snapshot := sealSnapshotAtEpoch(t, fixture, successorPolicy, successorDigest, 1, nil, 0xD1, []byte("synthetic snapshot payload"))
	snapshotCID := readRawCID(t, snapshotBytes)
	genesisControl := vault.Control{
		Vault: fixture.request.Vault, EpochSeq: 0, PolicyDigest: genesisDigest,
		Signer: vault.Signer{DeviceID: "alternate-root", KeyID: []byte("alternate-root-sign")},
	}
	genesisControlBytes := signReadControl(t, genesisControl, alternateRootSigning)
	fixture.request.PreviousControl = encodeReadControlRecord(t, genesisControlBytes)
	fixture.request.PreviousPolicy = genesisPolicyRecord

	previousControlCID := readRawCID(t, genesisControlBytes)
	currentControl := craftControl(t, fixture, 1, successorDigest, snapshotCID, previousControlCID)
	currentHead := craftHead(t, fixture, 1, successorDigest, snapshotCID, nil, 1, publisherSigner(), fixtureSigningKey(12))
	fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}] = successorPolicyRecord
	installSnapshot(t, &fixture, snapshotBytes, snapshot, currentHead)
	installControl(t, &fixture, currentControl)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlSigner,
		"the valid predecessor control is signed by a root authorized in the predecessor policy but differs from that policy's signer")
}

func TestReaderRejectsPreviousControlEpochMismatch(t *testing.T) {
	fixture := newReadFixture(t)
	control := readControlObject(t, fixture.request.PreviousControl)
	control.EpochSeq = 9
	fixture.request.PreviousControl = encodeReadControlRecord(t, signReadControl(t, control, fixtureSigningKey(11)))

	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlEpoch)
}

func TestReaderRejectsPreviousControlPolicyDigestMismatch(t *testing.T) {
	fixture := newReadFixture(t)
	control := readControlObject(t, fixture.request.PreviousControl)
	control.PolicyDigest[0] ^= 0xff
	fixture.request.PreviousControl = encodeReadControlRecord(t, signReadControl(t, control, fixtureSigningKey(11)))

	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlPolicyDigest)
}

func TestReaderRejectsNonGenesisPolicyWithoutAncestry(t *testing.T) {
	fixture := newReadFixture(t)
	policyRecordBytes, policyObject, digest := craftSuccessorPolicy(t, fixture, 2, [32]byte{})
	snapshotBytes, snapshot := sealSnapshotAtEpoch(t, fixture, policyObject, digest, 2, nil, 0xD2, []byte("synthetic snapshot payload"))
	snapshotCID := readRawCID(t, snapshotBytes)
	currentControlObject := readControlObject(t, fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	currentControlCID := readRawCID(t, mustEncodeControl(t, currentControlObject))
	control := craftControl(t, fixture, 2, digest, snapshotCID, currentControlCID)
	head := craftHead(t, fixture, 2, digest, snapshotCID, nil, 1, publisherSigner(), fixtureSigningKey(12))
	fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}] = policyRecordBytes
	installSnapshot(t, &fixture, snapshotBytes, snapshot, head)
	installControl(t, &fixture, control)

	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrPolicyAncestry)
}

func TestReaderRejectsUnexpectedControlAtGenuineGenesis(t *testing.T) {
	fixture := newReadFixture(t)
	bootstrapControl := bytes.Clone(fixture.request.PreviousControl)
	installGenesisReadState(t, &fixture, nil, bootstrapControl)

	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadUnexpectedPrevious)
}

func TestReaderRejectsPredecessorAtGenesisControl(t *testing.T) {
	fixture := newReadFixture(t)
	bootstrapControl := bytes.Clone(fixture.request.PreviousControl)
	bootstrapObject := readControlObject(t, bootstrapControl)
	previousControlCID := readRawCID(t, mustEncodeControl(t, bootstrapObject))
	installGenesisReadState(t, &fixture, previousControlCID, bootstrapControl)

	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlLinkage)
}

func readControlObject(t *testing.T, recordBytes []byte) vault.Control {
	t.Helper()
	decoded, err := DecodeRecord(recordBytes)
	require.NoError(t, err)
	record, ok := decoded.(ControlRecord)
	require.True(t, ok)
	return controlFromRecord(record)
}

func mustEncodeControl(t *testing.T, control vault.Control) []byte {
	t.Helper()
	encoded, err := vault.EncodeControl(control)
	require.NoError(t, err)
	return encoded
}

func mustReadCertificate(t *testing.T, encoded []byte) vault.Certificate {
	t.Helper()
	certificate, err := vault.DecodeCertificate(encoded)
	require.NoError(t, err)
	return certificate
}

func installGenesisReadState(t *testing.T, fixture *readFixture, previousControlCID, suppliedPreviousControl []byte) {
	t.Helper()
	decoded, err := DecodeRecord(fixture.request.PreviousPolicy)
	require.NoError(t, err)
	policy := policyFromRecord(decoded.(PolicyRecord))
	policyBytes, err := vault.EncodePolicy(policy)
	require.NoError(t, err)
	policy, err = vault.DecodePolicy(policyBytes)
	require.NoError(t, err)
	policyDigest := readPolicyDigest(t, policyBytes)
	envelope, err := vault.SealPrepared(vault.PreparedSeal{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{0xD3}, 16)),
		EpochSeq: 0, PolicyDigest: policyDigest, DeviceID: "root", KeyID: []byte("root-sign"),
		Plaintext: []byte("synthetic genesis payload"), SigningKey: fixtureSigningKey(11),
		ContentKey: bytes.Repeat([]byte{0x5a}, 32), Nonce: [24]byte(bytes.Repeat([]byte{0x6b}, 24)),
		Recipients: preparedRecipientsForPolicy(t, policy, 81),
	})
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(11))
	snapshotCID := readRawCID(t, envelopeBytes)
	control := vault.Control{
		Vault: policy.Vault, EpochSeq: 0, PolicyDigest: policyDigest,
		HeadSnapshotCID: bytes.Clone(snapshotCID), PrevControlCID: bytes.Clone(previousControlCID), Signer: policy.Signer,
	}
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	controlRecord := encodeReadControlRecord(t, controlBytes)
	head := vault.Head{
		Vault: policy.Vault, EpochSeq: 0, PolicyDigest: policyDigest,
		SnapshotCID: bytes.Clone(snapshotCID), BlobCID: bytes.Clone(snapshotCID),
		Signer: policy.Signer,
	}
	headRecord := headRecordFromObject(mustDecodeHead(t, signReadHead(t, head, fixtureSigningKey(11))))
	fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}] = encodePolicyRecord(t, policy)
	fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}] = controlRecord
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, headRecord)
	fixture.records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}] = mustEncodeSnapshotRecord(t, snapshot)
	fixture.transport.blob = bytes.Clone(envelopeBytes)
	fixture.request.PreviousPolicy = nil
	fixture.request.PreviousControl = bytes.Clone(suppliedPreviousControl)
	fixture.request.DeviceKeyID = nil
	fixture.request.DeviceKey = nil
	replaceReadCAR(t, fixture, fixture.records)
}

func encodePolicyRecord(t *testing.T, policy vault.Policy) []byte {
	t.Helper()
	encoded, err := EncodeRecord(policyRecordFromObject(policy))
	require.NoError(t, err)
	return encoded
}

func mustDecodeHead(t *testing.T, encoded []byte) vault.Head {
	t.Helper()
	head, err := vault.DecodeHead(encoded)
	require.NoError(t, err)
	return head
}

func mustEncodeSnapshotRecord(t *testing.T, snapshot SnapshotRecord) []byte {
	t.Helper()
	encoded, err := EncodeRecord(snapshot)
	require.NoError(t, err)
	return encoded
}
