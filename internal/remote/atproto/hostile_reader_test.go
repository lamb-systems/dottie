package atproto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/lamb-systems/dottie/internal/vault"
)

type caseStatus string

const (
	statusExisting     caseStatus = "existing"
	statusNewRefusal   caseStatus = "new-refusal"
	statusKnownDefect  caseStatus = "known-defect"
	statusSeamBoundary caseStatus = "seam-boundary"
)

type matrixCase struct {
	id      string
	status  caseStatus
	test    string
	refusal string
}

type securityDefect struct {
	caseID      string
	finding     string
	owner       string
	contract    string
	observation string
}

var caseMatrix = []matrixCase{
	{id: "1a", status: statusNewRefusal, test: "TestReaderRefusesHeadEnvelopeParentMismatch", refusal: "TestExpectedRefusalReaderHeadEnvelopeParentLink"},
	{id: "3b", status: statusNewRefusal, test: "TestReaderRefusesExtraRecipientInMetadata", refusal: "TestExpectedRefusalReaderExtraRecipientInMetadata"},
	{id: "3c", status: statusNewRefusal, test: "TestReaderRefusesUnnamedRecipientSet", refusal: "TestExpectedRefusalReaderUnauthorizedWrap"},
	{id: "4", status: statusNewRefusal, test: "TestReaderRefusesUnrelatedPredecessorPolicy"},
	{id: "5a", status: statusExisting, test: "TestVaultReaderRejectsLowerCountOnAuthenticatedReread"},
	{id: "5b", status: statusNewRefusal, test: "TestReaderRefusesOlderSnapshotAtNextCount", refusal: "TestExpectedRefusalReaderOlderSnapshotAtNextCount"},
	{id: "5c", status: statusNewRefusal, test: "TestReaderRefusesCoherentForkBehindHead", refusal: "TestExpectedRefusalReaderCoherentForkBehindHead"},
	{id: "6a", status: statusExisting, test: "TestRevisionReaderRejectsMissingRecordBlock"},
	{id: "6b", status: statusNewRefusal, test: "TestReaderRefusesMissingSnapshotMembership"},
	{id: "7", status: statusNewRefusal, test: "TestReaderRefusesRestoreOnlySnapshotSigner"},
	{id: "8", status: statusNewRefusal, test: "TestReaderRefusesRevokedDeviceEnvelope"},
	{id: "9", status: statusSeamBoundary, test: "TestSeamBoundaryAttestationSignerUnauthenticated"},
	{id: "10", status: statusNewRefusal, test: "TestReaderRefusesHeadEnvelopeSignerMismatch", refusal: "TestExpectedRefusalReaderSplitHeadAndEnvelopeSigners"},
	{id: "11", status: statusNewRefusal, test: "TestReaderRefusesControlAncestry", refusal: "TestExpectedRefusalReaderControlAncestry"},
	{id: "16", status: statusNewRefusal, test: "TestReaderRefusesEpochMixedSnapshotObject"},
	{id: "17", status: statusNewRefusal, test: "TestReaderRefusesSuccessorPolicyFromUnauthorizedRoot"},
	{id: "18", status: statusNewRefusal, test: "TestReaderRefusesHeadAboveMaxPublications", refusal: "TestExpectedRefusalReaderHeadAboveMaxPublications"},
}

var knownSecurityDefects = []securityDefect{}

const hostilePackageName = "atproto"

var frozenCaseInventory = []string{"1a", "3b", "3c", "4", "5a", "5b", "5c", "6a", "6b", "7", "8", "9", "10", "11", "16", "17", "18"}

func testSourceFunctions(t *testing.T) map[string]bool {
	t.Helper()
	matches, err := filepath.Glob("*_test.go")
	require.NoError(t, err)
	pattern := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	functions := make(map[string]bool)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, group := range pattern.FindAllStringSubmatch(string(data), -1) {
			functions[group[1]] = true
		}
	}
	return functions
}

func testSourceFunctionsWithPrefix(t *testing.T, prefix string) map[string]bool {
	t.Helper()
	result := make(map[string]bool)
	for name := range testSourceFunctions(t) {
		if strings.HasPrefix(name, prefix) {
			result[name] = true
		}
	}
	return result
}

func TestCaseMatrixMatchesTests(t *testing.T) {
	functions := testSourceFunctions(t)
	matrixByID := make(map[string]matrixCase, len(caseMatrix))
	seen := make(map[string]bool, len(caseMatrix))
	for _, entry := range caseMatrix {
		require.False(t, seen[entry.id], "duplicate case id %s", entry.id)
		seen[entry.id] = true
		matrixByID[entry.id] = entry
		require.NotEmpty(t, entry.test, "case %s has no test name", entry.id)
		assert.True(t, functions[entry.test], "case %s names a test %q that does not exist", entry.id, entry.test)
	}
	frozen := make(map[string]bool, len(frozenCaseInventory))
	for _, id := range frozenCaseInventory {
		frozen[id] = true
		_, ok := matrixByID[id]
		assert.True(t, ok, "frozen inventory case %s is missing from the matrix", id)
	}
	for _, entry := range caseMatrix {
		assert.True(t, frozen[entry.id], "matrix case %s is not in the frozen inventory", entry.id)
	}
	for name := range testSourceFunctionsWithPrefix(t, "TestKnownDefect") {
		found := false
		for _, entry := range caseMatrix {
			if entry.test == name {
				found = true
				assert.Equal(t, statusKnownDefect, entry.status, "characterization test %q maps to a non-known-defect row %s", name, entry.id)
			}
		}
		assert.True(t, found, "characterization test %q is not registered in the case matrix", name)
	}
	registered := make(map[string]bool, len(knownSecurityDefects))
	for _, defect := range knownSecurityDefects {
		registered[defect.caseID] = true
		assert.Equal(t, "refuse", defect.contract, "defect %s contract", defect.caseID)
		assert.Equal(t, "accept", defect.observation, "defect %s observation", defect.caseID)
		assert.NotEmpty(t, defect.owner, "defect %s owner", defect.caseID)
		assert.NotEmpty(t, defect.finding, "defect %s finding id", defect.caseID)
	}
	for _, entry := range caseMatrix {
		if entry.status == statusKnownDefect {
			assert.True(t, registered[entry.id], "known-defect case %s is not in the registry", entry.id)
		} else {
			assert.False(t, registered[entry.id], "non-defect case %s is in the registry", entry.id)
		}
	}
}

var readRogueKeyID = []byte("rogue-recipient")

func fixturePolicyRecord(t *testing.T, fixture readFixture) PolicyRecord {
	t.Helper()
	decoded, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}])
	require.NoError(t, err)
	record, ok := decoded.(PolicyRecord)
	require.True(t, ok)
	return record
}

func fixturePolicyParts(t *testing.T, fixture readFixture) (vault.Policy, []byte, [32]byte) {
	t.Helper()
	policyBytes, err := vault.EncodePolicy(policyFromRecord(fixturePolicyRecord(t, fixture)))
	require.NoError(t, err)
	policy, err := vault.DecodePolicy(policyBytes)
	require.NoError(t, err)
	digest, err := vault.ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	return policy, policyBytes, digest
}

func fixturePublisherCertificate(t *testing.T, fixture readFixture) vault.Certificate {
	t.Helper()
	for key, data := range fixture.records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		decoded, err := DecodeRecord(data)
		require.NoError(t, err)
		record, ok := decoded.(CertificateRecord)
		require.True(t, ok)
		if record.DeviceID == "publisher" {
			return certificateFromRecord(record)
		}
	}
	require.FailNow(t, "publisher certificate not found")
	return vault.Certificate{}
}

func fixtureRecipientPublicKeys(policy vault.Policy) []vault.RecipientPublicKey {
	recipients := make([]vault.RecipientPublicKey, len(policy.Recipients))
	for index, recipient := range policy.Recipients {
		recipients[index] = vault.RecipientPublicKey{KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:])}
	}
	return recipients
}

func snapshotRecordForEnvelope(t *testing.T, envelope vault.Envelope, envelopeBytes []byte, signing ed25519.PrivateKey) SnapshotRecord {
	t.Helper()
	envelopeCID := readRawCID(t, envelopeBytes)
	parsed, err := cid.Cast(envelopeCID)
	require.NoError(t, err)
	digest := sha256Digest(envelope.Signature[:])
	snapshot := SnapshotRecord{
		SchemaVersion: 1, Vault: bytes.Clone(envelope.Vault[:]), PublicationID: bytes.Clone(envelope.PublicationID[:]),
		EpochSeq: envelope.EpochSeq, PolicyDigest: bytes.Clone(envelope.PolicyDigest[:]), Parent: bytes.Clone(envelope.Parent),
		Blob:           atdata.Blob{Ref: atdata.CIDLink(parsed), MimeType: "application/octet-stream", Size: int64(len(envelopeBytes))},
		SignerDeviceID: envelope.DeviceID, SignerKeyID: bytes.Clone(envelope.KeyID), EnvelopeSignatureDigest: digest[:],
	}
	signed, err := SignSnapshotRecord(snapshot, signing)
	require.NoError(t, err)
	return signed
}

func sealFixtureSnapshot(t *testing.T, fixture readFixture, parent []byte, publicationSeed byte, plaintext []byte) ([]byte, SnapshotRecord) {
	t.Helper()
	policy, _, digest := fixturePolicyParts(t, fixture)
	certificate := fixturePublisherCertificate(t, fixture)
	envelope, err := vault.SealAuthorized(vault.SealRequest{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{publicationSeed}, 16)),
		EpochSeq: policy.EpochSeq, PolicyDigest: digest, Parent: parent, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: plaintext, SigningKey: fixtureSigningKey(12), Recipients: fixtureRecipientPublicKeys(policy),
	}, certificate, policy)
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	return envelopeBytes, snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
}

func fixtureHeadObject(t *testing.T, fixture readFixture) vault.Head {
	t.Helper()
	decoded, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultHeadNSID, RKey: "self"}])
	require.NoError(t, err)
	record, ok := decoded.(HeadRecord)
	require.True(t, ok)
	return headFromRecord(record)
}

func signFixtureHead(t *testing.T, fixture readFixture, envelopeBytes []byte, count uint64, prevHeadCID []byte, signer vault.Signer, signing ed25519.PrivateKey) HeadRecord {
	t.Helper()
	head := fixtureHeadObject(t, fixture)
	envelopeCID := readRawCID(t, envelopeBytes)
	head.SnapshotCID = bytes.Clone(envelopeCID)
	head.BlobCID = bytes.Clone(envelopeCID)
	head.PublicationCount = count
	head.PrevHeadCID = bytes.Clone(prevHeadCID)
	head.Signer = vault.Signer{DeviceID: signer.DeviceID, KeyID: bytes.Clone(signer.KeyID)}
	headBytes := signReadHead(t, head, signing)
	decoded, err := vault.DecodeHead(headBytes)
	require.NoError(t, err)
	return headRecordFromObject(decoded)
}

func installSnapshot(t *testing.T, fixture *readFixture, envelopeBytes []byte, snapshot SnapshotRecord, head HeadRecord) {
	t.Helper()
	encoded, err := EncodeRecord(snapshot)
	require.NoError(t, err)
	fixture.records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}] = encoded
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, head)
	fixture.transport.blob = bytes.Clone(envelopeBytes)
	replaceReadCAR(t, fixture, fixture.records)
}

func fixtureSnapshotCID(t *testing.T, fixture readFixture) []byte {
	t.Helper()
	decoded, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}])
	require.NoError(t, err)
	snapshot, ok := decoded.(SnapshotRecord)
	require.True(t, ok)
	return cid.Cid(snapshot.Blob.Ref).Bytes()
}

func publisherSigner() vault.Signer {
	return vault.Signer{DeviceID: "publisher", KeyID: []byte("publisher-sign")}
}

func setControlHeadSnapshot(t *testing.T, fixture *readFixture, snapshotCID []byte) {
	t.Helper()
	decoded, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	control := controlFromRecord(decoded.(ControlRecord))
	control.HeadSnapshotCID = bytes.Clone(snapshotCID)
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	rebuilt, err := vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	installControl(t, fixture, controlRecordFromObject(rebuilt))
}

func buildGenuineChain(t *testing.T, fixture *readFixture, seed byte) (s0CID, s1CID []byte) {
	t.Helper()
	s0Envelope, s0Snapshot := sealFixtureSnapshot(t, *fixture, nil, seed, []byte("S0 epoch-start payload"))
	s0CID = readRawCID(t, s0Envelope)
	s0Head := signFixtureHead(t, *fixture, s0Envelope, 0, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, fixture, s0Envelope, s0Snapshot, s0Head)
	setControlHeadSnapshot(t, fixture, s0CID)
	r0, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err, "the genuine epoch-start snapshot S0 reads")
	require.Equal(t, []byte("S0 epoch-start payload"), r0.Plaintext)

	s1Envelope, s1Snapshot := sealFixtureSnapshot(t, *fixture, s0CID, seed+1, []byte("S1 payload"))
	s1CID = readRawCID(t, s1Envelope)
	s1Head := signFixtureHead(t, *fixture, s1Envelope, 1, s0CID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, fixture, s1Envelope, s1Snapshot, s1Head)
	r1, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err, "the genuine S1 reads and descends from S0")
	require.Equal(t, []byte("S1 payload"), r1.Plaintext)
	require.Equal(t, s0CID, r1.Envelope.Parent)
	require.Equal(t, s0CID, r1.Head.PrevHeadCID)
	return s0CID, s1CID
}

func policyRecordDigest(t *testing.T, recordBytes []byte) [32]byte {
	t.Helper()
	decoded, err := DecodeRecord(recordBytes)
	require.NoError(t, err)
	object, err := vault.EncodePolicy(policyFromRecord(decoded.(PolicyRecord)))
	require.NoError(t, err)
	digest, err := vault.ComputePolicyDigest(object)
	require.NoError(t, err)
	return digest
}

func craftSuccessorPolicy(t *testing.T, fixture readFixture, epoch uint64, prevPolicyDigest [32]byte) ([]byte, vault.Policy, [32]byte) {
	t.Helper()
	base, _, _ := fixturePolicyParts(t, fixture)
	base.EpochSeq = epoch
	base.PrevPolicyDigest = prevPolicyDigest
	encoded := signReadPolicy(t, base, fixtureSigningKey(11))
	object, err := vault.DecodePolicy(encoded)
	require.NoError(t, err)
	digest, err := vault.ComputePolicyDigest(encoded)
	require.NoError(t, err)
	recordBytes, err := EncodeRecord(policyRecordFromObject(object))
	require.NoError(t, err)
	return recordBytes, object, digest
}

func sealSnapshotAtEpoch(t *testing.T, fixture readFixture, policyObject vault.Policy, digest [32]byte, epoch uint64, parent []byte, seed byte, plaintext []byte) ([]byte, SnapshotRecord) {
	t.Helper()
	certificate := fixturePublisherCertificate(t, fixture)
	envelope, err := vault.SealAuthorized(vault.SealRequest{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{seed}, 16)),
		EpochSeq: epoch, PolicyDigest: digest, Parent: parent, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: plaintext, SigningKey: fixtureSigningKey(12), Recipients: fixtureRecipientPublicKeys(policyObject),
	}, certificate, policyObject)
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	return envelopeBytes, snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
}

func craftControl(t *testing.T, fixture readFixture, epoch uint64, digest [32]byte, headSnapshotCID, prevControlCID []byte) ControlRecord {
	t.Helper()
	decoded, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	control := controlFromRecord(decoded.(ControlRecord))
	control.EpochSeq = epoch
	control.PolicyDigest = digest
	control.HeadSnapshotCID = bytes.Clone(headSnapshotCID)
	control.PrevControlCID = bytes.Clone(prevControlCID)
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	rebuilt, err := vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	return controlRecordFromObject(rebuilt)
}

func craftHead(t *testing.T, fixture readFixture, epoch uint64, digest [32]byte, snapshotCID, prevHeadCID []byte, count uint64, signer vault.Signer, signing ed25519.PrivateKey) HeadRecord {
	t.Helper()
	head := vault.Head{
		Vault: fixture.request.Vault, EpochSeq: epoch, PolicyDigest: digest,
		SnapshotCID: bytes.Clone(snapshotCID), BlobCID: bytes.Clone(snapshotCID), PublicationCount: count,
		PrevHeadCID: bytes.Clone(prevHeadCID), Signer: vault.Signer{DeviceID: signer.DeviceID, KeyID: bytes.Clone(signer.KeyID)},
	}
	headBytes := signReadHead(t, head, signing)
	decoded, err := vault.DecodeHead(headBytes)
	require.NoError(t, err)
	return headRecordFromObject(decoded)
}

func fixtureCertificates(t *testing.T, fixture readFixture) map[string]storedCertificate {
	t.Helper()
	certificates := make(map[string]storedCertificate)
	for key, data := range fixture.records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		decoded, err := DecodeRecord(data)
		require.NoError(t, err)
		record := decoded.(CertificateRecord)
		object := certificateFromRecord(record)
		encoded, err := vault.EncodeCertificate(object)
		require.NoError(t, err)
		certificates[certificateIdentity(record.DeviceID, record.KeyID)] = storedCertificate{recordBytes: bytes.Clone(data), objectBytes: encoded, object: object}
	}
	return certificates
}

func signReadAttestation(t *testing.T, value vault.Attestation, key ed25519.PrivateKey) []byte {
	t.Helper()
	value.Signature = [ed25519.SignatureSize]byte{}
	unsigned, err := vault.EncodeAttestation(value)
	require.NoError(t, err)
	preimage := append([]byte("dottie/v1/sig"), unsigned[:len(unsigned)-ed25519.SignatureSize]...)
	signature, err := vault.Sign("dottie/v1/sig-attestation", preimage, key)
	require.NoError(t, err)
	copy(value.Signature[:], signature)
	encoded, err := vault.EncodeAttestation(value)
	require.NoError(t, err)
	return encoded
}

func verifyReadAttestationSignature(encoded, signature []byte, publicKey ed25519.PublicKey) error {
	preimage := append([]byte("dottie/v1/sig"), encoded[:len(encoded)-ed25519.SignatureSize]...)
	return vault.Verify("dottie/v1/sig-attestation", preimage, signature, publicKey)
}

func buildGenuineThirdPublication(t *testing.T, fixture *readFixture, s1CID []byte, seed byte) []byte {
	t.Helper()
	s2Envelope, s2Snapshot := sealFixtureSnapshot(t, *fixture, s1CID, seed, []byte("S2 payload"))
	s2CID := readRawCID(t, s2Envelope)
	s2Head := signFixtureHead(t, *fixture, s2Envelope, 2, s1CID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, fixture, s2Envelope, s2Snapshot, s2Head)
	s2Result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err, "the genuine S2 publication reads and descends from S1")
	require.Equal(t, []byte("S2 payload"), s2Result.Plaintext)
	require.Equal(t, s1CID, s2Result.Envelope.Parent)
	require.Equal(t, s1CID, s2Result.Head.PrevHeadCID)
	return s2CID
}

func TestReaderRefusesHeadEnvelopeParentMismatch(t *testing.T) {
	fixture := newReadFixture(t)
	s0CID, s1CID := buildGenuineChain(t, &fixture, 0xA0)
	s2CID := buildGenuineThirdPublication(t, &fixture, s1CID, 0xA2)

	s3Envelope, s3Snapshot := sealFixtureSnapshot(t, fixture, s2CID, 0xA3, []byte("hostile S3 payload"))
	s3Head := signFixtureHead(t, fixture, s3Envelope, 3, s1CID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, s3Envelope, s3Snapshot, s3Head)
	hostileEnvelope, err := vault.DecodeEnvelope(s3Envelope)
	require.NoError(t, err)
	assert.Equal(t, s2CID, hostileEnvelope.Parent, "hostile envelope Parent is S2")
	assert.Equal(t, s1CID, s3Head.PrevHeadCID, "hostile signed head PrevHeadCID is S1")
	assert.NotEqual(t, s0CID, s3Head.PrevHeadCID, "the hostile predecessor differs from control.HeadSnapshotCID S0")
	assert.NotEqual(t, s2CID, s3Head.PrevHeadCID, "the hostile predecessor differs from observed head S2")
	assert.NotEqual(t, hostileEnvelope.Parent, s3Head.PrevHeadCID,
		"the hostile input has Parent=S2 and PrevHeadCID=S1")

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadHeadEnvelopeLinkage,
		"the observed-store read refuses the Parent/PrevHeadCID mismatch")

	fixture.observationStore = newObservationStore(t)
	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadHeadEnvelopeLinkage,
		"the empty-store read refuses the Parent/PrevHeadCID mismatch")

	controlFixture := newReadFixture(t)
	_, controlS1 := buildGenuineChain(t, &controlFixture, 0xB0)
	controlS2 := buildGenuineThirdPublication(t, &controlFixture, controlS1, 0xB2)
	coherentEnvelope, coherentSnapshot := sealFixtureSnapshot(t, controlFixture, controlS2, 0xB3, []byte("coherent S3 payload"))
	coherentHead := signFixtureHead(t, controlFixture, coherentEnvelope, 3, controlS2, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, coherentEnvelope, coherentSnapshot, coherentHead)
	positive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "observed-store positive control reads coherent S3")
	assert.Equal(t, []byte("coherent S3 payload"), positive.Plaintext)
	assert.Equal(t, controlS2, positive.Envelope.Parent)
	assert.Equal(t, controlS2, positive.Head.PrevHeadCID)

	controlFixture.observationStore = newObservationStore(t)
	freshPositive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "fresh-store positive control reads coherent S3 on an empty observation store")
	assert.Equal(t, []byte("coherent S3 payload"), freshPositive.Plaintext)
	assert.Equal(t, controlS2, freshPositive.Envelope.Parent)
	assert.Equal(t, controlS2, freshPositive.Head.PrevHeadCID)
}

func TestReaderRefusesMissingSnapshotMembership(t *testing.T) {
	fixture := newReadFixture(t)
	delete(fixture.records, RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"})
	replaceReadCAR(t, &fixture, fixture.records)
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecordMissing)
	var readErr *ReadError
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, ReadStageRecord, readErr.Stage)
	assert.Zero(t, fixture.transport.blobCalls, "the reader must not fetch a blob when no snapshot record is present")
}

func installControl(t *testing.T, fixture *readFixture, control ControlRecord) {
	t.Helper()
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, control)
	replaceReadCAR(t, fixture, fixture.records)
}

func currentSnapshotRecord(t *testing.T, fixture readFixture) SnapshotRecord {
	t.Helper()
	decoded, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}])
	require.NoError(t, err)
	record, ok := decoded.(SnapshotRecord)
	require.True(t, ok)
	return record
}

func sealFixtureSnapshotExtraRecipient(t *testing.T, fixture readFixture, parent []byte, publicationSeed byte, plaintext []byte, extra vault.RecipientPublicKey) ([]byte, SnapshotRecord) {
	t.Helper()
	policy, _, digest := fixturePolicyParts(t, fixture)
	recipients := append(fixtureRecipientPublicKeys(policy), extra)
	preparedRecipients := make([]vault.PreparedRecipient, len(recipients))
	for index, recipient := range recipients {
		seed := byte(31 + index)
		preparedRecipients[index] = vault.PreparedRecipient{
			KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey),
			EphemeralPrivate: readX25519Key(t, seed).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{byte(0x33 + index)}, 24)),
		}
	}
	envelope, err := vault.SealPrepared(vault.PreparedSeal{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{publicationSeed}, 16)),
		EpochSeq: policy.EpochSeq, PolicyDigest: digest, Parent: parent, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: plaintext, SigningKey: fixtureSigningKey(12), ContentKey: bytes.Repeat([]byte{0x5a}, chacha20poly1305.KeySize),
		Nonce: [24]byte(bytes.Repeat([]byte{0x6b}, 24)), Recipients: preparedRecipients,
	})
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	return envelopeBytes, snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
}

func TestReaderRefusesExtraRecipientInMetadata(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)
	extra := vault.RecipientPublicKey{KeyID: bytes.Clone(readRogueKeyID), PublicKey: readX25519Key(t, 99).PublicKey().Bytes()}
	envelopeBytes, snapshot := sealFixtureSnapshotExtraRecipient(t, fixture, nil, 0x95, []byte("synthetic snapshot payload"), extra)
	envelope, err := vault.DecodeEnvelope(envelopeBytes)
	require.NoError(t, err)
	assert.Equal(t, 2, len(policy.Recipients))
	assert.Equal(t, 3, len(envelope.Recipients))
	head := signFixtureHead(t, fixture, envelopeBytes, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, envelopeBytes, snapshot, head)
	fixture.request.DeviceKey = nil
	fixture.request.DeviceKeyID = nil

	controlFixture := newReadFixture(t)
	controlEnvelope, controlSnapshot := sealFixtureSnapshot(t, controlFixture, nil, 0x95, []byte("synthetic snapshot payload"))
	controlHead := signFixtureHead(t, controlFixture, controlEnvelope, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, controlEnvelope, controlSnapshot, controlHead)
	controlFixture.request.DeviceKey = nil
	controlFixture.request.DeviceKeyID = nil
	controlResult, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "an otherwise identical envelope without the extra recipient reads")
	assert.Equal(t, 2, len(controlResult.Envelope.Recipients))

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecipientSet,
		"the reader must refuse an envelope recipient set with an extra key ID")
}

func TestReaderRefusesUnrelatedPredecessorPolicy(t *testing.T) {
	fixture := newReadFixture(t)
	policyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	p0Digest := policyRecordDigest(t, fixture.request.PreviousPolicy)
	p1Record := bytes.Clone(fixture.records[policyKey])
	inheritedSnapshotCID := fixtureSnapshotCID(t, fixture)
	inheritedControlRecordBytes := bytes.Clone(fixture.records[controlKey])
	inheritedControlRecord, err := DecodeRecord(inheritedControlRecordBytes)
	require.NoError(t, err)
	inheritedControlBytes, err := vault.EncodeControl(controlFromRecord(inheritedControlRecord.(ControlRecord)))
	require.NoError(t, err)
	inheritedControlCID := readRawCID(t, inheritedControlBytes)
	fixture.request.PreviousControl = inheritedControlRecordBytes

	p2Record, p2Object, p2Digest := craftSuccessorPolicy(t, fixture, 2, p0Digest)
	env2, snapshot2 := sealSnapshotAtEpoch(t, fixture, p2Object, p2Digest, 2, inheritedSnapshotCID, 0xE2, []byte("epoch two payload"))
	env2CID := readRawCID(t, env2)
	control2 := craftControl(t, fixture, 2, p2Digest, env2CID, inheritedControlCID)
	head2 := craftHead(t, fixture, 2, p2Digest, env2CID, inheritedSnapshotCID, 1, publisherSigner(), fixtureSigningKey(12))

	fixture.records[policyKey] = p2Record
	putReadRecord(t, fixture.records, controlKey, control2)
	installSnapshot(t, &fixture, env2, snapshot2, head2)
	fixture.request.PreviousPolicy = p1Record

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecordContext)
	var readErr *ReadError
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, ReadStageRecordContext, readErr.Stage)
	var contextErr *RecordContextError
	require.ErrorAs(t, err, &contextErr)
	assert.Equal(t, "prevPolicyDigest", contextErr.Field)
}

func TestReaderRefusesCoherentForkBehindHead(t *testing.T) {
	fixture := newReadFixture(t)
	s0CID, s1CID := buildGenuineChain(t, &fixture, 0xC0)
	require.NotEqual(t, s0CID, s1CID)

	forkEnvelope, forkSnapshot := sealFixtureSnapshot(t, fixture, s0CID, 0xC3, []byte("fork payload"))
	forkHead := signFixtureHead(t, fixture, forkEnvelope, 2, s0CID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, forkEnvelope, forkSnapshot, forkHead)
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrVaultPublicationAncestry,
		"the reader refuses a coherent fork that descends from S0, behind the observed head S1")

	controlFixture := newReadFixture(t)
	controlS0, controlS1 := buildGenuineChain(t, &controlFixture, 0xC0)
	require.NotEqual(t, controlS0, controlS1)
	coherentEnvelope, coherentSnapshot := sealFixtureSnapshot(t, controlFixture, controlS1, 0xC3, []byte("coherent S2 payload"))
	coherentHead := signFixtureHead(t, controlFixture, coherentEnvelope, 2, controlS1, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, coherentEnvelope, coherentSnapshot, coherentHead)
	controlResult, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "the same S2 construction reads when both ancestry fields name observed S1")
	assert.Equal(t, []byte("coherent S2 payload"), controlResult.Plaintext)
	assert.Equal(t, controlS1, controlResult.Envelope.Parent)
	assert.Equal(t, controlS1, controlResult.Head.PrevHeadCID)
}

func TestReaderRefusesOlderSnapshotAtNextCount(t *testing.T) {
	fixture := newReadFixture(t)
	s1Blob := bytes.Clone(fixture.transport.blob)
	s1Record := currentSnapshotRecord(t, fixture)
	s1CID := fixtureSnapshotCID(t, fixture)
	reader := fixture.reader()
	_, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)

	s2Envelope, s2Snapshot := sealFixtureSnapshot(t, fixture, s1CID, 0x92, []byte("second snapshot payload"))
	s2Head := signFixtureHead(t, fixture, s2Envelope, 2, s1CID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, s2Envelope, s2Snapshot, s2Head)
	_, err = reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)

	replayHead := signFixtureHead(t, fixture, s1Blob, 3, s1Record.Parent, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, s1Blob, s1Record, replayHead)
	_, err = reader.Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrVaultPublicationAncestry,
		"the reader refuses an older snapshot republished at the next publication count")
}

func TestReaderRefusesHeadEnvelopeSignerMismatch(t *testing.T) {
	fixture := newReadFixture(t)
	snapshot := currentSnapshotRecord(t, fixture)
	rootSigner := vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")}
	head := signFixtureHead(t, fixture, fixture.transport.blob, 1, fixtureHeadObject(t, fixture).PrevHeadCID, rootSigner, fixtureSigningKey(11))
	installSnapshot(t, &fixture, bytes.Clone(fixture.transport.blob), snapshot, head)
	envelope, err := vault.DecodeEnvelope(fixture.transport.blob)
	require.NoError(t, err)
	assert.Equal(t, "root", head.SignerDeviceID)
	assert.Equal(t, "publisher", envelope.DeviceID)
	assert.NotEqual(t, head.SignerDeviceID, envelope.DeviceID,
		"the hostile input uses distinct authorized head and envelope signers")

	controlFixture := newReadFixture(t)
	controlSnapshot := currentSnapshotRecord(t, controlFixture)
	controlHead := signFixtureHead(t, controlFixture, controlFixture.transport.blob, 1, fixtureHeadObject(t, controlFixture).PrevHeadCID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, bytes.Clone(controlFixture.transport.blob), controlSnapshot, controlHead)
	positive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "the same snapshot reads when head and envelope signers match")
	assert.Equal(t, "publisher", positive.Head.SignerDeviceID)
	assert.Equal(t, "publisher", positive.Envelope.DeviceID)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadSignerMismatch,
		"the reader refuses a head and envelope with different authorized signers")
}

func TestReaderRefusesControlAncestry(t *testing.T) {
	fixture := newReadFixture(t)
	policyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	c1Record := bytes.Clone(fixture.records[controlKey])
	c1Decoded, err := DecodeRecord(c1Record)
	require.NoError(t, err)
	c1Object := controlFromRecord(c1Decoded.(ControlRecord))
	c0CID := bytes.Clone(c1Object.PrevControlCID)
	c1Bytes, err := vault.EncodeControl(c1Object)
	require.NoError(t, err)
	c1CID := readRawCID(t, c1Bytes)
	fixture.request.PreviousControl = c1Record
	require.False(t, bytes.Equal(c0CID, c1CID))

	_, _, p1Digest := fixturePolicyParts(t, fixture)
	p1Record := bytes.Clone(fixture.records[policyKey])

	p2Record, p2Object, p2Digest := craftSuccessorPolicy(t, fixture, 2, p1Digest)
	env2, snapshot2 := sealSnapshotAtEpoch(t, fixture, p2Object, p2Digest, 2, nil, 0xF2, []byte("epoch two payload"))
	env2CID := readRawCID(t, env2)
	control2 := craftControl(t, fixture, 2, p2Digest, env2CID, c0CID)
	head2 := craftHead(t, fixture, 2, p2Digest, env2CID, nil, 1, publisherSigner(), fixtureSigningKey(12))

	fixture.records[policyKey] = p2Record
	putReadRecord(t, fixture.records, controlKey, control2)
	installSnapshot(t, &fixture, env2, snapshot2, head2)
	fixture.request.PreviousPolicy = p1Record

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlLinkage)
	assert.NotErrorIs(t, err, ErrReadControlType)
	assert.NotErrorIs(t, err, ErrReadControlSignature)
	assert.NotErrorIs(t, err, ErrReadControlSigner)
	assert.NotErrorIs(t, err, ErrReadControlEpoch)
	assert.NotErrorIs(t, err, ErrReadControlPolicyDigest)

	controlFixture := newReadFixture(t)
	controlPolicyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlKey = RecordKey{Collection: VaultControlNSID, RKey: "self"}
	controlC1Record := bytes.Clone(controlFixture.records[controlKey])
	controlC1, err := DecodeRecord(controlC1Record)
	require.NoError(t, err)
	controlC1Object := controlFromRecord(controlC1.(ControlRecord))
	controlC1Bytes, err := vault.EncodeControl(controlC1Object)
	require.NoError(t, err)
	controlC1CID := readRawCID(t, controlC1Bytes)
	_, _, controlP1Digest := fixturePolicyParts(t, controlFixture)
	controlP1Record := bytes.Clone(controlFixture.records[controlPolicyKey])
	controlP2Record, controlP2Object, controlP2Digest := craftSuccessorPolicy(t, controlFixture, 2, controlP1Digest)
	controlEnv2, controlSnapshot2 := sealSnapshotAtEpoch(t, controlFixture, controlP2Object, controlP2Digest, 2, nil, 0xF2, []byte("epoch two payload"))
	controlEnv2CID := readRawCID(t, controlEnv2)
	coherentControl2 := craftControl(t, controlFixture, 2, controlP2Digest, controlEnv2CID, controlC1CID)
	controlHead2 := craftHead(t, controlFixture, 2, controlP2Digest, controlEnv2CID, nil, 1, publisherSigner(), fixtureSigningKey(12))
	controlFixture.records[controlPolicyKey] = controlP2Record
	putReadRecord(t, controlFixture.records, controlKey, coherentControl2)
	installSnapshot(t, &controlFixture, controlEnv2, controlSnapshot2, controlHead2)
	controlFixture.request.PreviousPolicy = controlP1Record
	controlFixture.request.PreviousControl = controlC1Record

	positive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err)
	assert.Equal(t, []byte("epoch two payload"), positive.Plaintext)
	assert.Equal(t, controlC1CID, positive.Control.PrevControlCID)
	assert.Equal(t, controlP1Digest[:], positive.Policy.PrevPolicyDigest)
}

func TestReaderRefusesHeadAboveMaxPublications(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)
	maximum := uint64(policy.MaxPublications)
	require.Greater(t, maximum, uint64(2))
	reader := fixture.reader()
	genuinePrev := fixtureSnapshotCID(t, fixture)

	below, belowSnapshot := sealFixtureSnapshot(t, fixture, genuinePrev, 0x40, []byte("n-1 payload"))
	belowHead := signFixtureHead(t, fixture, below, maximum-1, genuinePrev, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, below, belowSnapshot, belowHead)
	belowResult, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	assert.Equal(t, genuinePrev, belowResult.Envelope.Parent)
	assert.Equal(t, genuinePrev, belowResult.Head.PrevHeadCID)
	belowCID := readRawCID(t, below)

	atMax, atMaxSnapshot := sealFixtureSnapshot(t, fixture, belowCID, 0x41, []byte("n payload"))
	atMaxHead := signFixtureHead(t, fixture, atMax, maximum, belowCID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, atMax, atMaxSnapshot, atMaxHead)
	atMaxResult, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	assert.Equal(t, belowCID, atMaxResult.Envelope.Parent)
	assert.Equal(t, belowCID, atMaxResult.Head.PrevHeadCID)
	atMaxCID := readRawCID(t, atMax)

	over, overSnapshot := sealFixtureSnapshot(t, fixture, atMaxCID, 0x42, []byte("n+1 payload"))
	overHead := signFixtureHead(t, fixture, over, maximum+1, atMaxCID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, over, overSnapshot, overHead)
	_, err = reader.Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, vault.ErrPublicationCount,
		"the reader refuses a head above max_publications before recording its observation")

	installSnapshot(t, &fixture, atMax, atMaxSnapshot, atMaxHead)
	positive, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err, "the refused over-limit read did not advance the observation")
	assert.Equal(t, maximum, positive.PublicationCount)
}

func TestSeamBoundaryAttestationSignerUnauthenticated(t *testing.T) {
	fixture := newReadFixture(t)
	_, _, digest := fixturePolicyParts(t, fixture)
	policyRecordBytes := fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}]
	controlRecordBytes := fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}]
	controlCID, err := recordCID(controlRecordBytes)
	require.NoError(t, err)

	ghost := fixtureSigningKey(99)
	ghostPublic := ghost.Public().(ed25519.PublicKey)
	attestationObject := vault.Attestation{
		Vault: fixture.request.Vault, DeviceID: "ghost-device", PolicyDigest: digest,
		RetentionFloor: 0, RetainedRecoveryPoints: 0, ControlCID: bytes.Clone(controlCID),
		Signer: vault.Signer{DeviceID: "ghost-device", KeyID: []byte("ghost-key")},
	}
	attestationEncoded := signReadAttestation(t, attestationObject, ghost)
	attestationObject, err = vault.DecodeAttestation(attestationEncoded)
	require.NoError(t, err)
	require.NoError(t, verifyReadAttestationSignature(attestationEncoded, attestationObject.Signature[:], ghostPublic),
		"the attestation is genuinely signed by the ghost device under the attestation context")

	attestationRecordBytes, err := EncodeRecord(attestationRecordFromObject(attestationObject))
	require.NoError(t, err)
	require.NoError(t, VerifyRecordBinding(attestationRecordBytes, attestationEncoded),
		"the attestation record binds to its signed object")

	err = VerifyRecordContext(attestationRecordBytes, RecordContext{Policy: policyRecordBytes, Control: controlRecordBytes, TrustAnchor: fixture.request.TrustAnchor})
	assert.NoError(t, err,
		"record-context validation is not an authentication verdict: a validly signed attestation naming a device with no role still passes")
}

func wrapAppendBytes16(buffer, value []byte) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	buffer = append(buffer, length[:]...)
	return append(buffer, value...)
}

func wrapAppendUint64(buffer []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(buffer, encoded[:]...)
}

func recoverWrappedContentKey(t *testing.T, vaultID [32]byte, epoch uint64, purpose byte, keyID []byte, devicePrivate *ecdh.PrivateKey, entry vault.EnvelopeRecipient) []byte {
	t.Helper()
	ephemeral, err := ecdh.X25519().NewPublicKey(entry.Ephemeral[:])
	require.NoError(t, err)
	shared, err := devicePrivate.ECDH(ephemeral)
	require.NoError(t, err)
	info := append([]byte("dottie/v1/wrap"), vaultID[:]...)
	info = wrapAppendBytes16(info, keyID)
	info = wrapAppendUint64(info, epoch)
	info = append(info, purpose)
	wrapKey, err := hkdf.Key[hash.Hash](sha256.New, shared, nil, string(info), chacha20poly1305.KeySize)
	require.NoError(t, err)
	associated := append([]byte("dottie/v1/wrapad"), vaultID[:]...)
	associated = wrapAppendBytes16(associated, keyID)
	associated = wrapAppendUint64(associated, epoch)
	associated = append(associated, purpose)
	associated = append(associated, devicePrivate.PublicKey().Bytes()...)
	associated = append(associated, entry.Ephemeral[:]...)
	aead, err := chacha20poly1305.NewX(wrapKey)
	require.NoError(t, err)
	contentKey, err := aead.Open(nil, entry.WrapNonce[:], entry.WrappedKey, associated)
	require.NoError(t, err)
	return contentKey
}

func sealRogueRecipientEnvelope(t *testing.T, fixture readFixture) (vault.Policy, []byte, *ecdh.PrivateKey, vault.Envelope) {
	t.Helper()
	policy, _, digest := fixturePolicyParts(t, fixture)
	contentKey := bytes.Repeat([]byte{0x5a}, chacha20poly1305.KeySize)
	publisherRecipientKey := readX25519Key(t, 22)
	rootRecipientKey := readX25519Key(t, 21)
	rogueRecipientKey := readX25519Key(t, 98)
	prepared := vault.PreparedSeal{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{0x99}, 16)),
		EpochSeq: policy.EpochSeq, PolicyDigest: digest, Parent: nil, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: []byte("synthetic snapshot payload"), SigningKey: fixtureSigningKey(12), ContentKey: contentKey,
		Nonce: [24]byte(bytes.Repeat([]byte{0x6b}, 24)),
		Recipients: []vault.PreparedRecipient{
			{KeyID: []byte("publisher-sign"), PublicKey: publisherRecipientKey.PublicKey().Bytes(), EphemeralPrivate: readX25519Key(t, 31).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{0x33}, 24))},
			{KeyID: []byte("root-sign"), PublicKey: rootRecipientKey.PublicKey().Bytes(), EphemeralPrivate: readX25519Key(t, 32).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{0x34}, 24))},
			{KeyID: bytes.Clone(readRogueKeyID), PublicKey: rogueRecipientKey.PublicKey().Bytes(), EphemeralPrivate: readX25519Key(t, 97).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{0x35}, 24))},
		},
	}
	envelope, err := vault.SealPrepared(prepared)
	require.NoError(t, err)
	return policy, contentKey, rogueRecipientKey, envelope
}

func TestReaderRefusesMissingPolicyRecipientKeyID(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, policyDigest := fixturePolicyParts(t, fixture)
	recipients := preparedRecipientsForPolicy(t, policy, 71)
	require.Len(t, recipients, 2)
	envelope, err := vault.SealPrepared(vault.PreparedSeal{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{0x97}, 16)),
		EpochSeq: policy.EpochSeq, PolicyDigest: policyDigest, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: []byte("synthetic snapshot payload"), SigningKey: fixtureSigningKey(12),
		ContentKey: bytes.Repeat([]byte{0x5a}, 32), Nonce: [24]byte(bytes.Repeat([]byte{0x6b}, 24)),
		Recipients: recipients[:1],
	})
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
	head := signFixtureHead(t, fixture, envelopeBytes, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, envelopeBytes, snapshot, head)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecipientSet,
		"the reader refuses a correctly signed envelope that omits a policy recipient key ID")
}

func TestReaderRefusesUnnamedRecipientSet(t *testing.T) {
	fixture := newReadFixture(t)
	_, _, _, envelope := sealRogueRecipientEnvelope(t, fixture)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
	head := signFixtureHead(t, fixture, envelopeBytes, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, envelopeBytes, snapshot, head)

	controlFixture := newReadFixture(t)
	controlEnvelope, controlSnapshot := sealFixtureSnapshot(t, controlFixture, nil, 0x99, []byte("synthetic snapshot payload"))
	controlHead := signFixtureHead(t, controlFixture, controlEnvelope, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, controlEnvelope, controlSnapshot, controlHead)
	controlResult, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "an otherwise identical envelope without the unnamed recipient reads")
	assert.Equal(t, []byte("synthetic snapshot payload"), controlResult.Plaintext)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecipientSet,
		"the reader must refuse a key-ID set containing a recipient absent from policy")
}

func TestRogueWrapDisclosesContentKeyOutsideReader(t *testing.T) {
	fixture := newReadFixture(t)
	policy, contentKey, rogueRecipientKey, envelope := sealRogueRecipientEnvelope(t, fixture)
	var rogueEntry vault.EnvelopeRecipient
	found := false
	for _, entry := range envelope.Recipients {
		if bytes.Equal(entry.KeyID, readRogueKeyID) {
			rogueEntry = entry
			found = true
		}
	}
	require.True(t, found, "the hostile prepared envelope contains the rogue recipient wrap")
	recovered := recoverWrappedContentKey(t, fixture.request.Vault, policy.EpochSeq, byte(vault.PurposeSnapshot), readRogueKeyID, rogueRecipientKey, rogueEntry)
	require.Equal(t, contentKey, recovered,
		"the rogue private key recovers the content key through X25519, HKDF and AEAD without a reader call")
}

func TestRogueWrapUnderPolicyKeyIDStillDisclosesContentKey(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, policyDigest := fixturePolicyParts(t, fixture)
	contentKey := bytes.Repeat([]byte{0x5a}, chacha20poly1305.KeySize)
	rogueRecipientKey := readX25519Key(t, 98)
	recipients := preparedRecipientsForPolicy(t, policy, 71)
	require.Len(t, recipients, len(policy.Recipients))
	var substitutedKeyID []byte
	for index := range recipients {
		if bytes.Equal(recipients[index].KeyID, []byte("root-sign")) {
			substitutedKeyID = bytes.Clone(recipients[index].KeyID)
			recipients[index].PublicKey = rogueRecipientKey.PublicKey().Bytes()
		}
	}
	require.Equal(t, []byte("root-sign"), substitutedKeyID,
		"the substituted public key keeps a key ID named by policy")

	envelope, err := vault.SealPrepared(vault.PreparedSeal{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{0x99}, 16)),
		EpochSeq: policy.EpochSeq, PolicyDigest: policyDigest, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: []byte("synthetic snapshot payload"), SigningKey: fixtureSigningKey(12), ContentKey: contentKey,
		Nonce: [24]byte(bytes.Repeat([]byte{0x6b}, 24)), Recipients: recipients,
	})
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
	head := signFixtureHead(t, fixture, envelopeBytes, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, envelopeBytes, snapshot, head)

	result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err,
		"the reader accepts the substituted public key because envelope and policy key-ID sets match")
	assert.Equal(t, []byte("synthetic snapshot payload"), result.Plaintext)

	var rogueEntry vault.EnvelopeRecipient
	found := false
	for _, entry := range result.Envelope.Recipients {
		if bytes.Equal(entry.KeyID, substitutedKeyID) {
			rogueEntry = entry
			found = true
		}
	}
	require.True(t, found, "the accepted envelope retains the policy key ID on the rogue wrapper")
	recovered := recoverWrappedContentKey(t, fixture.request.Vault, policy.EpochSeq, byte(vault.PurposeSnapshot), substitutedKeyID, rogueRecipientKey, rogueEntry)
	require.Equal(t, contentKey, recovered,
		"the rogue private key independently unwraps this snapshot's content key")
}

func fixturePublisherCertKey(t *testing.T, fixture readFixture) RecordKey {
	t.Helper()
	for key, data := range fixture.records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		decoded, err := DecodeRecord(data)
		require.NoError(t, err)
		if record, ok := decoded.(CertificateRecord); ok && record.DeviceID == "publisher" {
			return key
		}
	}
	require.FailNow(t, "publisher certificate record not found")
	return RecordKey{}
}

func TestReaderRefusesRevokedDeviceEnvelope(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)

	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	controlDecoded, err := DecodeRecord(fixture.records[controlKey])
	require.NoError(t, err)
	control := controlFromRecord(controlDecoded.(ControlRecord))
	control.Revoked = append(control.Revoked, vault.RevokedDevice{DeviceID: "publisher", CertEpoch: 1})
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	rebuiltControl, err := vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, controlKey, controlRecordFromObject(rebuiltControl))
	controlCID, err := recordCID(fixture.records[controlKey])
	require.NoError(t, err)

	certKey := fixturePublisherCertKey(t, fixture)
	certDecoded, err := DecodeRecord(fixture.records[certKey])
	require.NoError(t, err)
	certificate := certificateFromRecord(certDecoded.(CertificateRecord))
	certificate.RevocationRef = bytes.Clone(controlCID)
	certBytes := signReadCertificate(t, certificate, fixtureSigningKey(11))
	rebuiltCert, err := vault.DecodeCertificate(certBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, certKey, certificateRecordFromObject(rebuiltCert))

	rootSigner := vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")}
	head := signFixtureHead(t, fixture, fixture.transport.blob, 1, fixtureHeadObject(t, fixture).PrevHeadCID, rootSigner, fixtureSigningKey(11))
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, head)
	replaceReadCAR(t, &fixture, fixture.records)

	_, headAuthErr := authorizedReadSigner(rootSigner, policy.Roles, fixtureCertificates(t, fixture),
		fixture.request.Vault, policy.EpochSeq, fixture.request.TrustAnchor, rebuiltControl.Revoked, vault.RolePublisher)
	require.NoError(t, headAuthErr,
		"the active root head signer is authorized under the revoked set, so the head path does not refuse")

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadVaultAuthentication)
	var readErr *ReadError
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, ReadStageVaultAuth, readErr.Stage)
	assert.ErrorContains(t, err, "revoked",
		"the refusal is the revocation check reached through the envelope signer, not the head signer")
}

func preparedRecipientsForPolicy(t *testing.T, policy vault.Policy, seed byte) []vault.PreparedRecipient {
	t.Helper()
	prepared := make([]vault.PreparedRecipient, len(policy.Recipients))
	for index, recipient := range policy.Recipients {
		prepared[index] = vault.PreparedRecipient{
			KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:]),
			EphemeralPrivate: readX25519Key(t, seed+byte(index)).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{seed + byte(index)}, 24)),
		}
	}
	return prepared
}

func buildRestoreOnlyReaderFixture(t *testing.T) readFixture {
	t.Helper()
	rootSigning := fixtureSigningKey(11)
	rootRecipient := readX25519Key(t, 21)
	restoreSigning := fixtureSigningKey(12)
	restoreRecipient := readX25519Key(t, 22)
	kit := bytes.Repeat([]byte{7}, 32)
	rootDevice := vault.DeviceMaterial{DeviceID: "root", KeyID: []byte("root-sign"), Signing: rootSigning, Recipient: rootRecipient}
	bootstrap, err := vault.Bootstrap(kit, "read fixture", rootDevice)
	require.NoError(t, err)
	restore := vault.DeviceMaterial{DeviceID: "restore", KeyID: []byte("restore-sign"), Signing: restoreSigning, Recipient: restoreRecipient}
	intent := vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: bootstrap.Vault, Signer: rootDevice, NewDevice: &restore, RequestedRole: vault.RoleRestoreOnly,
		ContentKey: bytes.Repeat([]byte{41}, 32), Recipients: [][]byte{bootstrap.Certificate},
		Wraps: []vault.RecipientWrapInput{
			{KeyID: []byte("restore-sign"), EphemeralPrivate: [32]byte(readX25519Key(t, 31).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{51}, 24))},
			{KeyID: []byte("root-sign"), EphemeralPrivate: [32]byte(readX25519Key(t, 32).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{52}, 24))},
		},
		Plaintext: []byte("synthetic snapshot payload"), PublicationID: [16]byte(bytes.Repeat([]byte{61}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{62}, 24)),
	}
	predecessor := vault.Predecessor{
		ControlCID: readRawCID(t, bootstrap.Control), PolicyDigest: readPolicyDigest(t, bootstrap.Policy), EpochSeq: 0,
		Control: bootstrap.Control, Policy: bootstrap.Policy, Certificates: [][]byte{bootstrap.Certificate}, TrustAnchor: bootstrap.Anchor,
	}
	transition, err := vault.PrepareTransition(predecessor, intent)
	require.NoError(t, err)
	policyObject, err := vault.DecodePolicy(transition.Policy)
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(transition.Policy)
	require.NoError(t, err)
	envelope, err := vault.SealPrepared(vault.PreparedSeal{
		Purpose: vault.PurposeSnapshot, Vault: bootstrap.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{71}, 16)),
		EpochSeq: policyObject.EpochSeq, PolicyDigest: policyDigest, Parent: nil, DeviceID: "restore", KeyID: []byte("restore-sign"),
		Plaintext: []byte("synthetic snapshot payload"), SigningKey: restoreSigning, ContentKey: bytes.Repeat([]byte{45}, 32),
		Nonce: [24]byte(bytes.Repeat([]byte{63}, 24)), Recipients: preparedRecipientsForPolicy(t, policyObject, 80),
	})
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	envelopeCID := readRawCID(t, envelopeBytes)
	controlObject, err := vault.DecodeControl(transition.Control)
	require.NoError(t, err)
	headObject := vault.Head{
		Vault: bootstrap.Vault, EpochSeq: policyObject.EpochSeq, PolicyDigest: policyDigest,
		SnapshotCID: bytes.Clone(envelopeCID), BlobCID: bytes.Clone(envelopeCID), PublicationCount: 1,
		Signer: vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	headBytes := signReadHead(t, headObject, rootSigning)
	headObject, err = vault.DecodeHead(headBytes)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, restoreSigning)
	records := map[RecordKey][]byte{}
	putReadRecord(t, records, RecordKey{Collection: VaultPolicyNSID, RKey: "self"}, policyRecordFromObject(policyObject))
	putReadRecord(t, records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, controlRecordFromObject(controlObject))
	putReadRecord(t, records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, headRecordFromObject(headObject))
	snapshotBytes, err := EncodeRecord(snapshot)
	require.NoError(t, err)
	records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}] = snapshotBytes
	for index, encodedCertificate := range transition.Recipients {
		certificate, decodeErr := vault.DecodeCertificate(encodedCertificate)
		require.NoError(t, decodeErr)
		putReadRecord(t, records, RecordKey{Collection: VaultCertificateNSID, RKey: fmtKey(index + 1)}, certificateRecordFromObject(certificate))
	}
	car, blocks, root, method := buildReadCAR(t, records)
	transport := &readTransport{proofTransport: &proofTransport{carBytes: car, latestCIDs: repeatedCIDs(root.String(), 20), streamStatus: 200}, blob: bytes.Clone(envelopeBytes)}
	previousPolicyRecord, err := EncodeRecord(policyRecordFromObject(mustDecodePolicy(t, bootstrap.Policy)))
	require.NoError(t, err)
	previousControlRecord := encodeReadControlRecord(t, bootstrap.Control)
	store := newObservationStore(t)
	return readFixture{
		request: ReadRequest{
			DID: proofTestDID, DIDDocumentID: proofTestDID,
			VerificationMethods: []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: method}},
			Vault:               bootstrap.Vault, TrustAnchor: bootstrap.Anchor, PreviousPolicy: previousPolicyRecord,
			PreviousControl: previousControlRecord,
		},
		transport: transport, observationStore: store, records: records, blocks: blocks, root: root,
	}
}

func fmtKey(index int) string { return "r" + string(rune('0'+index)) }

func mustDecodePolicy(t *testing.T, encoded []byte) vault.Policy {
	t.Helper()
	policy, err := vault.DecodePolicy(encoded)
	require.NoError(t, err)
	return policy
}

func newObservationStore(t *testing.T) *state.Store {
	t.Helper()
	root := t.TempDir()
	store, err := state.Open(platform.Paths{
		Home: filepath.Join(root, "home"), StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return store
}

func TestReaderRefusesRestoreOnlySnapshotSigner(t *testing.T) {
	fixture := buildRestoreOnlyReaderFixture(t)
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecordContext)
	var readErr *ReadError
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, ReadStageRecordContext, readErr.Stage)
	var contextErr *RecordContextError
	require.ErrorAs(t, err, &contextErr)
	assert.Equal(t, "role", contextErr.Field)
}

func buildEpochTwoReaderFixture(t *testing.T) readFixture {
	t.Helper()
	rootSigning := fixtureSigningKey(11)
	publisherSigning := fixtureSigningKey(12)
	thirdSigning := fixtureSigningKey(13)
	kit := bytes.Repeat([]byte{7}, 32)
	rootDevice := vault.DeviceMaterial{DeviceID: "root", KeyID: []byte("root-sign"), Signing: rootSigning, Recipient: readX25519Key(t, 21)}
	bootstrap, err := vault.Bootstrap(kit, "read fixture", rootDevice)
	require.NoError(t, err)
	publisher := vault.DeviceMaterial{DeviceID: "publisher", KeyID: []byte("publisher-sign"), Signing: publisherSigning, Recipient: readX25519Key(t, 22)}
	intentOne := vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: bootstrap.Vault, Signer: rootDevice, NewDevice: &publisher, RequestedRole: vault.RolePublisher,
		ContentKey: bytes.Repeat([]byte{41}, 32), Recipients: [][]byte{bootstrap.Certificate},
		Wraps: []vault.RecipientWrapInput{
			{KeyID: []byte("publisher-sign"), EphemeralPrivate: [32]byte(readX25519Key(t, 31).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{51}, 24))},
			{KeyID: []byte("root-sign"), EphemeralPrivate: [32]byte(readX25519Key(t, 32).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{52}, 24))},
		},
		Plaintext: []byte("epoch one payload"), PublicationID: [16]byte(bytes.Repeat([]byte{61}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{62}, 24)),
	}
	predecessorOne := vault.Predecessor{
		ControlCID: readRawCID(t, bootstrap.Control), PolicyDigest: readPolicyDigest(t, bootstrap.Policy), EpochSeq: 0,
		Control: bootstrap.Control, Policy: bootstrap.Policy, Certificates: [][]byte{bootstrap.Certificate}, TrustAnchor: bootstrap.Anchor,
	}
	transitionOne, err := vault.PrepareTransition(predecessorOne, intentOne)
	require.NoError(t, err)
	policyOne, err := vault.DecodePolicy(transitionOne.Policy)
	require.NoError(t, err)
	digestOne, err := vault.ComputePolicyDigest(transitionOne.Policy)
	require.NoError(t, err)
	publisherCertificate, err := vault.DecodeCertificate(transitionOne.Certificate)
	require.NoError(t, err)
	epochOneEnvelope, err := vault.SealAuthorized(vault.SealRequest{
		Purpose: vault.PurposeSnapshot, Vault: bootstrap.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{71}, 16)),
		EpochSeq: policyOne.EpochSeq, PolicyDigest: digestOne, Parent: nil, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: []byte("epoch one payload"), SigningKey: publisherSigning, Recipients: fixtureRecipientPublicKeys(policyOne),
	}, publisherCertificate, policyOne)
	require.NoError(t, err)
	epochOneBytes, err := vault.EncodeEnvelope(epochOneEnvelope)
	require.NoError(t, err)
	epochOneCID := readRawCID(t, epochOneBytes)

	transitionOneHead, err := vault.DecodeHead(transitionOne.Head)
	require.NoError(t, err)
	predecessorTwo := vault.Predecessor{
		ControlCID: readRawCID(t, transitionOne.Control), PolicyDigest: digestOne, EpochSeq: 1,
		HeadCID: bytes.Clone(transitionOneHead.SnapshotCID), Head: transitionOne.Head, Control: transitionOne.Control,
		Policy: transitionOne.Policy, Certificates: transitionOne.Recipients, TrustAnchor: bootstrap.Anchor,
	}
	third := vault.DeviceMaterial{DeviceID: "third", KeyID: []byte("third-sign"), Signing: thirdSigning, Recipient: readX25519Key(t, 23)}
	intentTwo := vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: bootstrap.Vault, Signer: rootDevice, NewDevice: &third, RequestedRole: vault.RolePublisher,
		ContentKey: bytes.Repeat([]byte{42}, 32), Recipients: transitionOne.Recipients,
		Wraps: []vault.RecipientWrapInput{
			{KeyID: []byte("root-sign"), EphemeralPrivate: [32]byte(readX25519Key(t, 33).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{53}, 24))},
			{KeyID: []byte("publisher-sign"), EphemeralPrivate: [32]byte(readX25519Key(t, 34).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{54}, 24))},
			{KeyID: []byte("third-sign"), EphemeralPrivate: [32]byte(readX25519Key(t, 35).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{55}, 24))},
		},
		Plaintext: []byte("epoch two payload"), PublicationID: [16]byte(bytes.Repeat([]byte{72}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{73}, 24)),
	}
	transitionTwo, err := vault.PrepareTransition(predecessorTwo, intentTwo)
	require.NoError(t, err)
	policyTwo, err := vault.DecodePolicy(transitionTwo.Policy)
	require.NoError(t, err)
	digestTwo, err := vault.ComputePolicyDigest(transitionTwo.Policy)
	require.NoError(t, err)
	controlTwo, err := vault.DecodeControl(transitionTwo.Control)
	require.NoError(t, err)

	head := vault.Head{
		Vault: bootstrap.Vault, EpochSeq: policyTwo.EpochSeq, PolicyDigest: digestTwo,
		SnapshotCID: bytes.Clone(epochOneCID), BlobCID: bytes.Clone(epochOneCID), PublicationCount: 1,
		Signer: vault.Signer{DeviceID: "publisher", KeyID: []byte("publisher-sign")},
	}
	headBytes := signReadHead(t, head, publisherSigning)
	head, err = vault.DecodeHead(headBytes)
	require.NoError(t, err)
	parsedEpochOneCID, err := cid.Cast(epochOneCID)
	require.NoError(t, err)
	envelopeSignatureDigest := sha256Digest(epochOneEnvelope.Signature[:])
	snapshot := SnapshotRecord{
		SchemaVersion: 1, Vault: bytes.Clone(epochOneEnvelope.Vault[:]), PublicationID: bytes.Clone(epochOneEnvelope.PublicationID[:]),
		EpochSeq: policyTwo.EpochSeq, PolicyDigest: bytes.Clone(digestTwo[:]), Parent: bytes.Clone(epochOneEnvelope.Parent),
		Blob:           atdata.Blob{Ref: atdata.CIDLink(parsedEpochOneCID), MimeType: "application/octet-stream", Size: int64(len(epochOneBytes))},
		SignerDeviceID: "publisher", SignerKeyID: []byte("publisher-sign"), EnvelopeSignatureDigest: envelopeSignatureDigest[:],
	}
	snapshot, err = SignSnapshotRecord(snapshot, publisherSigning)
	require.NoError(t, err)
	snapshotBytes, err := EncodeRecord(snapshot)
	require.NoError(t, err)

	records := map[RecordKey][]byte{}
	putReadRecord(t, records, RecordKey{Collection: VaultPolicyNSID, RKey: "self"}, policyRecordFromObject(policyTwo))
	putReadRecord(t, records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, controlRecordFromObject(controlTwo))
	putReadRecord(t, records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, headRecordFromObject(head))
	records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}] = snapshotBytes
	for index, encodedCertificate := range transitionTwo.Recipients {
		certificate, decodeErr := vault.DecodeCertificate(encodedCertificate)
		require.NoError(t, decodeErr)
		putReadRecord(t, records, RecordKey{Collection: VaultCertificateNSID, RKey: fmtKey(index + 1)}, certificateRecordFromObject(certificate))
	}
	car, blocks, root, method := buildReadCAR(t, records)
	transport := &readTransport{proofTransport: &proofTransport{carBytes: car, latestCIDs: repeatedCIDs(root.String(), 20), streamStatus: 200}, blob: bytes.Clone(epochOneBytes)}
	previousPolicyRecord, err := EncodeRecord(policyRecordFromObject(policyOne))
	require.NoError(t, err)
	previousControlRecord := encodeReadControlRecord(t, transitionOne.Control)
	return readFixture{
		request: ReadRequest{
			DID: proofTestDID, DIDDocumentID: proofTestDID,
			VerificationMethods: []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: method}},
			Vault:               bootstrap.Vault, TrustAnchor: bootstrap.Anchor, PreviousPolicy: previousPolicyRecord,
			PreviousControl: previousControlRecord,
		},
		transport: transport, observationStore: newObservationStore(t), records: records, blocks: blocks, root: root,
	}
}

func TestReaderRefusesEpochMixedSnapshotObject(t *testing.T) {
	fixture := buildEpochTwoReaderFixture(t)
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecordBinding)
	var readErr *ReadError
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, ReadStageRecordBinding, readErr.Stage)
	var bindingErr *RecordBindingError
	require.ErrorAs(t, err, &bindingErr)
	assert.Equal(t, "epochSeq", bindingErr.Field)
}

func signReadPolicy(t *testing.T, value vault.Policy, key ed25519.PrivateKey) []byte {
	t.Helper()
	value.Signature = [ed25519.SignatureSize]byte{}
	unsigned, err := vault.EncodePolicy(value)
	require.NoError(t, err)
	preimage := append([]byte("dottie/v1/sig"), unsigned[:len(unsigned)-ed25519.SignatureSize]...)
	signature, err := vault.Sign("dottie/v1/sig-policy", preimage, key)
	require.NoError(t, err)
	copy(value.Signature[:], signature)
	encoded, err := vault.EncodePolicy(value)
	require.NoError(t, err)
	return encoded
}

func dualRootPolicyRecipient(t *testing.T, deviceID string, keyID []byte, key *ecdh.PrivateKey) vault.PolicyRecipient {
	t.Helper()
	var public [32]byte
	copy(public[:], key.PublicKey().Bytes())
	return vault.PolicyRecipient{DeviceID: deviceID, KeyID: bytes.Clone(keyID), PublicKey: public}
}

func dualRootCertificate(t *testing.T, vaultID [32]byte, deviceID string, keyID []byte, signing ed25519.PrivateKey, recipient *ecdh.PrivateKey, certEpoch uint64, issuer string, issuerKeyID []byte, issuerSigning ed25519.PrivateKey) ([]byte, vault.Certificate) {
	t.Helper()
	var encryption [32]byte
	copy(encryption[:], recipient.PublicKey().Bytes())
	certificate := vault.Certificate{
		Vault: vaultID, DeviceID: deviceID, KeyID: bytes.Clone(keyID),
		SigningPublicKey: [ed25519.PublicKeySize]byte(signing.Public().(ed25519.PublicKey)), EncryptionPublicKey: encryption,
		Role: vault.RoleRoot, CertEpoch: certEpoch, Issuer: issuer,
		Signer: vault.Signer{DeviceID: issuer, KeyID: bytes.Clone(issuerKeyID)},
	}
	encoded := signReadCertificate(t, certificate, issuerSigning)
	decoded, err := vault.DecodeCertificate(encoded)
	require.NoError(t, err)
	return encoded, decoded
}

func buildDualRootReaderFixture(t *testing.T) readFixture {
	t.Helper()
	var vaultID [32]byte
	copy(vaultID[:], bytes.Repeat([]byte{0x5c}, 32))
	rootZeroSigning := fixtureSigningKey(60)
	rootZeroRecipient := readX25519Key(t, 61)
	rootOneSigning := fixtureSigningKey(62)
	rootOneRecipient := readX25519Key(t, 63)
	var anchor [32]byte
	copy(anchor[:], func() []byte { digest := sha256Digest(rootZeroSigning.Public().(ed25519.PublicKey)); return digest[:] }())

	rootZeroCertBytes, _ := dualRootCertificate(t, vaultID, "r0", []byte("r0-sign"), rootZeroSigning, rootZeroRecipient, 0, "r0", []byte("r0-sign"), rootZeroSigning)
	rootOneCertBytes, rootOneCert := dualRootCertificate(t, vaultID, "r1", []byte("r1-sign"), rootOneSigning, rootOneRecipient, 1, "r0", []byte("r0-sign"), rootZeroSigning)

	genesisPolicy := vault.Policy{
		Vault: vaultID, EpochSeq: 0, Roles: []vault.RoleBinding{{DeviceID: "r0", Role: vault.RoleRoot}},
		Recipients:           []vault.PolicyRecipient{dualRootPolicyRecipient(t, "r0", []byte("r0-sign"), rootZeroRecipient)},
		PolicyRetentionFloor: 0, RetainedRecoveryPoints: 3, MaxPublications: 100, MaxEpochAge: 86400, RecoveryAnchor: anchor,
		Signer: vault.Signer{DeviceID: "r0", KeyID: []byte("r0-sign")},
	}
	genesisBytes := signReadPolicy(t, genesisPolicy, rootZeroSigning)
	genesisDigest := readPolicyDigest(t, genesisBytes)
	genesisObject, err := vault.DecodePolicy(genesisBytes)
	require.NoError(t, err)

	successorPolicy := vault.Policy{
		Vault: vaultID, EpochSeq: 1,
		Roles: []vault.RoleBinding{{DeviceID: "r0", Role: vault.RoleRoot}, {DeviceID: "r1", Role: vault.RoleRoot}},
		Recipients: []vault.PolicyRecipient{
			dualRootPolicyRecipient(t, "r0", []byte("r0-sign"), rootZeroRecipient),
			dualRootPolicyRecipient(t, "r1", []byte("r1-sign"), rootOneRecipient),
		},
		PolicyRetentionFloor: 0, RetainedRecoveryPoints: 3, MaxPublications: 100, MaxEpochAge: 86400, RecoveryAnchor: anchor,
		PrevPolicyDigest: genesisDigest, Signer: vault.Signer{DeviceID: "r1", KeyID: []byte("r1-sign")},
	}
	successorBytes := signReadPolicy(t, successorPolicy, rootOneSigning)
	successorDigest := readPolicyDigest(t, successorBytes)
	successorObject, err := vault.DecodePolicy(successorBytes)
	require.NoError(t, err)

	envelope, err := vault.SealAuthorized(vault.SealRequest{
		Purpose: vault.PurposeSnapshot, Vault: vaultID, PublicationID: [16]byte(bytes.Repeat([]byte{71}, 16)),
		EpochSeq: 1, PolicyDigest: successorDigest, Parent: nil, DeviceID: "r1", KeyID: []byte("r1-sign"),
		Plaintext: []byte("dual root payload"), SigningKey: rootOneSigning, Recipients: fixtureRecipientPublicKeys(successorObject),
	}, rootOneCert, successorObject)
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	envelopeCID := readRawCID(t, envelopeBytes)

	genesisControlBytes := signReadControl(t, vault.Control{
		Vault: vaultID, EpochSeq: genesisObject.EpochSeq, PolicyDigest: genesisDigest,
		Signer: vault.Signer{DeviceID: "r0", KeyID: []byte("r0-sign")},
	}, rootZeroSigning)
	genesisControlRecord := encodeReadControlRecord(t, genesisControlBytes)
	control := vault.Control{
		Vault: vaultID, EpochSeq: 1, PolicyDigest: successorDigest, HeadSnapshotCID: bytes.Clone(envelopeCID),
		PrevControlCID: readRawCID(t, genesisControlBytes), Signer: vault.Signer{DeviceID: "r1", KeyID: []byte("r1-sign")},
	}
	controlBytes := signReadControl(t, control, rootOneSigning)
	controlObject, err := vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	head := vault.Head{
		Vault: vaultID, EpochSeq: 1, PolicyDigest: successorDigest, SnapshotCID: bytes.Clone(envelopeCID),
		BlobCID: bytes.Clone(envelopeCID), PublicationCount: 1, Signer: vault.Signer{DeviceID: "r1", KeyID: []byte("r1-sign")},
	}
	headBytes := signReadHead(t, head, rootOneSigning)
	headObject, err := vault.DecodeHead(headBytes)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, rootOneSigning)

	records := map[RecordKey][]byte{}
	putReadRecord(t, records, RecordKey{Collection: VaultPolicyNSID, RKey: "self"}, policyRecordFromObject(successorObject))
	putReadRecord(t, records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, controlRecordFromObject(controlObject))
	putReadRecord(t, records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, headRecordFromObject(headObject))
	snapshotBytes, err := EncodeRecord(snapshot)
	require.NoError(t, err)
	records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}] = snapshotBytes
	rootZeroCertObject, err := vault.DecodeCertificate(rootZeroCertBytes)
	require.NoError(t, err)
	rootOneCertObject, err := vault.DecodeCertificate(rootOneCertBytes)
	require.NoError(t, err)
	putReadRecord(t, records, RecordKey{Collection: VaultCertificateNSID, RKey: "r1"}, certificateRecordFromObject(rootZeroCertObject))
	putReadRecord(t, records, RecordKey{Collection: VaultCertificateNSID, RKey: "r2"}, certificateRecordFromObject(rootOneCertObject))
	car, blocks, root, method := buildReadCAR(t, records)
	transport := &readTransport{proofTransport: &proofTransport{carBytes: car, latestCIDs: repeatedCIDs(root.String(), 20), streamStatus: 200}, blob: bytes.Clone(envelopeBytes)}
	previousPolicyRecord, err := EncodeRecord(policyRecordFromObject(genesisObject))
	require.NoError(t, err)
	return readFixture{
		request: ReadRequest{
			DID: proofTestDID, DIDDocumentID: proofTestDID,
			VerificationMethods: []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: method}},
			Vault:               vaultID, TrustAnchor: anchor, PreviousPolicy: previousPolicyRecord,
			PreviousControl: genesisControlRecord,
		},
		transport: transport, observationStore: newObservationStore(t), records: records, blocks: blocks, root: root,
	}
}

func TestReaderRefusesSuccessorPolicyFromUnauthorizedRoot(t *testing.T) {
	fixture := buildDualRootReaderFixture(t)
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadVaultAuthentication)
	var readErr *ReadError
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, ReadStageVaultAuth, readErr.Stage)
	assert.ErrorContains(t, err, "current policy signer was not a predecessor root")
}
