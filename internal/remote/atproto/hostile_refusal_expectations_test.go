//go:build known_defects

package atproto

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/vault"
)

func TestExpectedRefusalReaderHeadEnvelopeParentLink(t *testing.T) {
	fixture := newReadFixture(t)
	s0CID, s1CID := buildGenuineChain(t, &fixture, 0xA0)
	s2CID := buildGenuineThirdPublication(t, &fixture, s1CID, 0xA2)
	s3Envelope, s3Snapshot := sealFixtureSnapshot(t, fixture, s2CID, 0xA3, []byte("hostile S3 payload"))
	s3Head := signFixtureHead(t, fixture, s3Envelope, 3, s1CID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, s3Envelope, s3Snapshot, s3Head)

	observedResult, observedErr := fixture.reader().Read(context.Background(), fixture.request)
	assert.Error(t, observedErr, "the observed-store hostile read must refuse the Parent/PrevHeadCID mismatch")
	assert.Equal(t, []byte("hostile S3 payload"), observedResult.Plaintext)
	assert.Equal(t, s2CID, observedResult.Envelope.Parent, "observed-store hostile envelope Parent is S2")
	assert.Equal(t, s1CID, observedResult.Head.PrevHeadCID, "observed-store hostile head PrevHeadCID is S1")
	assert.NotEqual(t, s0CID, observedResult.Head.PrevHeadCID, "the hostile predecessor differs from control.HeadSnapshotCID S0")
	assert.NotEqual(t, s2CID, observedResult.Head.PrevHeadCID, "the hostile predecessor differs from observed head S2")
	assert.NotEqual(t, observedResult.Envelope.Parent, observedResult.Head.PrevHeadCID,
		"the observed-store hostile input has Parent=S2 and PrevHeadCID=S1")

	fixture.observationStore = newObservationStore(t)
	freshResult, freshErr := fixture.reader().Read(context.Background(), fixture.request)
	assert.Error(t, freshErr, "the empty-store hostile read must refuse the Parent/PrevHeadCID mismatch")
	assert.Equal(t, []byte("hostile S3 payload"), freshResult.Plaintext)
	assert.Equal(t, s2CID, freshResult.Envelope.Parent, "fresh-store hostile envelope Parent is S2")
	assert.Equal(t, s1CID, freshResult.Head.PrevHeadCID, "fresh-store hostile head PrevHeadCID is S1")
	assert.NotEqual(t, s0CID, freshResult.Head.PrevHeadCID, "fresh-store hostile predecessor differs from control.HeadSnapshotCID S0")
	assert.NotEqual(t, freshResult.Envelope.Parent, freshResult.Head.PrevHeadCID,
		"the empty-store hostile input has Parent=S2 and PrevHeadCID=S1")

	controlFixture := newReadFixture(t)
	_, controlS1 := buildGenuineChain(t, &controlFixture, 0xB0)
	controlS2 := buildGenuineThirdPublication(t, &controlFixture, controlS1, 0xB2)
	coherentEnvelope, coherentSnapshot := sealFixtureSnapshot(t, controlFixture, controlS2, 0xB3, []byte("coherent S3 payload"))
	coherentHead := signFixtureHead(t, controlFixture, coherentEnvelope, 3, controlS2, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, coherentEnvelope, coherentSnapshot, coherentHead)
	positive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "the observed-store positive control reads coherent S3")
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

func TestExpectedRefusalReaderExtraRecipientInMetadata(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)
	extra := vault.RecipientPublicKey{KeyID: bytes.Clone(readRogueKeyID), PublicKey: readX25519Key(t, 99).PublicKey().Bytes()}
	envelopeBytes, snapshot := sealFixtureSnapshotExtraRecipient(t, fixture, nil, 0x95, []byte("synthetic snapshot payload"), extra)
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
	assert.Equal(t, len(policy.Recipients), len(controlResult.Envelope.Recipients))

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.Error(t, err, "the reader must compare the envelope recipient set with the policy")
}

func TestExpectedRefusalReaderUnauthorizedWrap(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, digest := fixturePolicyParts(t, fixture)
	prepared := vault.PreparedSeal{
		Purpose: vault.PurposeSnapshot, Vault: fixture.request.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{0x99}, 16)),
		EpochSeq: policy.EpochSeq, PolicyDigest: digest, DeviceID: "publisher", KeyID: []byte("publisher-sign"),
		Plaintext: []byte("synthetic snapshot payload"), SigningKey: fixtureSigningKey(12), ContentKey: bytes.Repeat([]byte{0x5a}, 32),
		Nonce: [24]byte(bytes.Repeat([]byte{0x6b}, 24)),
		Recipients: []vault.PreparedRecipient{
			{KeyID: []byte("publisher-sign"), PublicKey: readX25519Key(t, 22).PublicKey().Bytes(), EphemeralPrivate: readX25519Key(t, 31).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{0x33}, 24))},
			{KeyID: []byte("root-sign"), PublicKey: readX25519Key(t, 21).PublicKey().Bytes(), EphemeralPrivate: readX25519Key(t, 32).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{0x34}, 24))},
			{KeyID: bytes.Clone(readRogueKeyID), PublicKey: readX25519Key(t, 98).PublicKey().Bytes(), EphemeralPrivate: readX25519Key(t, 97).Bytes(), WrapNonce: [24]byte(bytes.Repeat([]byte{0x35}, 24))},
		},
	}
	envelope, err := vault.SealPrepared(prepared)
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
	head := signFixtureHead(t, fixture, envelopeBytes, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, envelopeBytes, snapshot, head)

	controlFixture := newReadFixture(t)
	controlPrepared := prepared
	controlPrepared.Recipients = append([]vault.PreparedRecipient(nil), prepared.Recipients[:len(prepared.Recipients)-1]...)
	controlEnvelope, err := vault.SealPrepared(controlPrepared)
	require.NoError(t, err)
	controlEnvelopeBytes, err := vault.EncodeEnvelope(controlEnvelope)
	require.NoError(t, err)
	controlSnapshot := snapshotRecordForEnvelope(t, controlEnvelope, controlEnvelopeBytes, fixtureSigningKey(12))
	controlHead := signFixtureHead(t, controlFixture, controlEnvelopeBytes, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, controlEnvelopeBytes, controlSnapshot, controlHead)
	controlResult, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "the same prepared envelope without the unauthorized wrap reads")
	assert.Equal(t, []byte("synthetic snapshot payload"), controlResult.Plaintext)
	assert.Equal(t, len(prepared.Recipients)-1, len(controlResult.Envelope.Recipients))

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.Error(t, err, "the reader must reject an envelope carrying a wrap for a device the policy never named")
}

func TestExpectedRefusalReaderOlderSnapshotAtNextCount(t *testing.T) {
	controlFixture := newReadFixture(t)
	controlReader := controlFixture.reader()
	controlS1CID := fixtureSnapshotCID(t, controlFixture)
	_, err := controlReader.Read(context.Background(), controlFixture.request)
	require.NoError(t, err)
	controlS2, controlS2Snapshot := sealFixtureSnapshot(t, controlFixture, controlS1CID, 0x92, []byte("second snapshot payload"))
	controlS2CID := readRawCID(t, controlS2)
	installSnapshot(t, &controlFixture, controlS2, controlS2Snapshot, signFixtureHead(t, controlFixture, controlS2, 2, controlS1CID, publisherSigner(), fixtureSigningKey(12)))
	controlS2Result, err := controlReader.Read(context.Background(), controlFixture.request)
	require.NoError(t, err)
	assert.Equal(t, []byte("second snapshot payload"), controlS2Result.Plaintext)
	assert.Equal(t, controlS1CID, controlS2Result.Envelope.Parent)
	assert.Equal(t, controlS1CID, controlS2Result.Head.PrevHeadCID)
	controlS3, controlS3Snapshot := sealFixtureSnapshot(t, controlFixture, controlS2CID, 0x93, []byte("fresh third snapshot payload"))
	installSnapshot(t, &controlFixture, controlS3, controlS3Snapshot, signFixtureHead(t, controlFixture, controlS3, 3, controlS2CID, publisherSigner(), fixtureSigningKey(12)))
	controlS3Result, err := controlReader.Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "a fresh snapshot at the next count reads with consistent ancestry")
	assert.Equal(t, []byte("fresh third snapshot payload"), controlS3Result.Plaintext)
	assert.Equal(t, controlS2CID, controlS3Result.Envelope.Parent)
	assert.Equal(t, controlS2CID, controlS3Result.Head.PrevHeadCID)

	fixture := newReadFixture(t)
	s1Blob := bytes.Clone(fixture.transport.blob)
	s1Record := currentSnapshotRecord(t, fixture)
	s1CID := fixtureSnapshotCID(t, fixture)
	reader := fixture.reader()
	_, err = reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	s2Envelope, s2Snapshot := sealFixtureSnapshot(t, fixture, s1CID, 0x92, []byte("second snapshot payload"))
	installSnapshot(t, &fixture, s2Envelope, s2Snapshot, signFixtureHead(t, fixture, s2Envelope, 2, s1CID, publisherSigner(), fixtureSigningKey(12)))
	_, err = reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	installSnapshot(t, &fixture, s1Blob, s1Record, signFixtureHead(t, fixture, s1Blob, 3, s1Record.Parent, publisherSigner(), fixtureSigningKey(12)))
	_, err = reader.Read(context.Background(), fixture.request)
	require.Error(t, err, "the reader must reject an older snapshot republished at the next count")
}

func TestExpectedRefusalReaderCoherentForkBehindHead(t *testing.T) {
	fixture := newReadFixture(t)
	s0CID, _ := buildGenuineChain(t, &fixture, 0xC0)
	forkEnvelope, forkSnapshot := sealFixtureSnapshot(t, fixture, s0CID, 0xC3, []byte("fork payload"))
	forkHead := signFixtureHead(t, fixture, forkEnvelope, 2, s0CID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, forkEnvelope, forkSnapshot, forkHead)

	controlFixture := newReadFixture(t)
	controlS0, controlS1 := buildGenuineChain(t, &controlFixture, 0xC0)
	require.NotEqual(t, controlS0, controlS1)
	coherentEnvelope, coherentSnapshot := sealFixtureSnapshot(t, controlFixture, controlS1, 0xC3, []byte("coherent S2 payload"))
	coherentHead := signFixtureHead(t, controlFixture, coherentEnvelope, 2, controlS1, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, coherentEnvelope, coherentSnapshot, coherentHead)
	positive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "the same S2 construction reads when both ancestry fields name observed S1")
	assert.Equal(t, []byte("coherent S2 payload"), positive.Plaintext)
	assert.Equal(t, controlS1, positive.Envelope.Parent)
	assert.Equal(t, controlS1, positive.Head.PrevHeadCID)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.Error(t, err, "the reader must reject a coherent fork that descends from S0, behind the observed head S1")
}

func TestExpectedRefusalReaderSplitHeadAndEnvelopeSigners(t *testing.T) {
	fixture := newReadFixture(t)
	snapshot := currentSnapshotRecord(t, fixture)
	rootSigner := vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")}
	head := signFixtureHead(t, fixture, fixture.transport.blob, 1, fixtureHeadObject(t, fixture).PrevHeadCID, rootSigner, fixtureSigningKey(11))
	installSnapshot(t, &fixture, bytes.Clone(fixture.transport.blob), snapshot, head)

	controlFixture := newReadFixture(t)
	controlSnapshot := currentSnapshotRecord(t, controlFixture)
	controlHead := signFixtureHead(t, controlFixture, controlFixture.transport.blob, 1, fixtureHeadObject(t, controlFixture).PrevHeadCID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &controlFixture, bytes.Clone(controlFixture.transport.blob), controlSnapshot, controlHead)
	positive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "the same snapshot reads when its head and envelope use the same authorized signer")
	assert.Equal(t, []byte("synthetic snapshot payload"), positive.Plaintext)
	assert.Equal(t, "publisher", positive.Head.SignerDeviceID)
	assert.Equal(t, "publisher", positive.Envelope.DeviceID)
	assert.Equal(t, []byte("publisher-sign"), positive.Head.SignerKeyID)
	assert.Equal(t, []byte("publisher-sign"), positive.Envelope.KeyID)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.Error(t, err, "the reader must require the head and envelope signers to be equal")
}

func TestExpectedRefusalReaderControlAncestry(t *testing.T) {
	fixture := newReadFixture(t)
	policyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	c1Decoded, err := DecodeRecord(fixture.records[controlKey])
	require.NoError(t, err)
	c1Object := controlFromRecord(c1Decoded.(ControlRecord))
	c0CID := bytes.Clone(c1Object.PrevControlCID)
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
	controlFixture := newReadFixture(t)
	controlPolicyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlRecordKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	controlRecord, err := DecodeRecord(controlFixture.records[controlRecordKey])
	require.NoError(t, err)
	controlObject := controlFromRecord(controlRecord.(ControlRecord))
	controlBytes, err := vault.EncodeControl(controlObject)
	require.NoError(t, err)
	controlC1CID := readRawCID(t, controlBytes)
	_, _, controlP1Digest := fixturePolicyParts(t, controlFixture)
	controlP1Record := bytes.Clone(controlFixture.records[controlPolicyKey])
	controlP2Record, controlP2Object, controlP2Digest := craftSuccessorPolicy(t, controlFixture, 2, controlP1Digest)
	controlEnv2, controlSnapshot2 := sealSnapshotAtEpoch(t, controlFixture, controlP2Object, controlP2Digest, 2, nil, 0xF2, []byte("epoch two payload"))
	controlEnv2CID := readRawCID(t, controlEnv2)
	coherentControl2 := craftControl(t, controlFixture, 2, controlP2Digest, controlEnv2CID, controlC1CID)
	controlHead2 := craftHead(t, controlFixture, 2, controlP2Digest, controlEnv2CID, nil, 1, publisherSigner(), fixtureSigningKey(12))
	controlFixture.records[controlPolicyKey] = controlP2Record
	putReadRecord(t, controlFixture.records, controlRecordKey, coherentControl2)
	installSnapshot(t, &controlFixture, controlEnv2, controlSnapshot2, controlHead2)
	controlFixture.request.PreviousPolicy = controlP1Record
	positive, err := controlFixture.reader().Read(context.Background(), controlFixture.request)
	require.NoError(t, err, "the same successor reads when control and policy ancestry both name their genuine predecessors")
	assert.Equal(t, []byte("epoch two payload"), positive.Plaintext)
	assert.Equal(t, controlC1CID, positive.Control.PrevControlCID)
	assert.Equal(t, controlP1Digest[:], positive.Policy.PrevPolicyDigest)

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.Error(t, err, "the reader must validate control ancestry (C2 names C0, skipping C1) against policy ancestry")
}

func TestExpectedRefusalReaderHeadAboveMaxPublications(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)
	maximum := uint64(policy.MaxPublications)
	reader := fixture.reader()
	genuinePrev := fixtureSnapshotCID(t, fixture)
	below, belowSnapshot := sealFixtureSnapshot(t, fixture, genuinePrev, 0x40, []byte("n-1 payload"))
	installSnapshot(t, &fixture, below, belowSnapshot, signFixtureHead(t, fixture, below, maximum-1, genuinePrev, publisherSigner(), fixtureSigningKey(12)))
	belowResult, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	assert.Equal(t, []byte("n-1 payload"), belowResult.Plaintext)
	assert.Equal(t, genuinePrev, belowResult.Envelope.Parent)
	assert.Equal(t, genuinePrev, belowResult.Head.PrevHeadCID)
	belowCID := readRawCID(t, below)
	atMax, atMaxSnapshot := sealFixtureSnapshot(t, fixture, belowCID, 0x41, []byte("n payload"))
	installSnapshot(t, &fixture, atMax, atMaxSnapshot, signFixtureHead(t, fixture, atMax, maximum, belowCID, publisherSigner(), fixtureSigningKey(12)))
	atMaxResult, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	assert.Equal(t, []byte("n payload"), atMaxResult.Plaintext)
	assert.Equal(t, belowCID, atMaxResult.Envelope.Parent)
	assert.Equal(t, belowCID, atMaxResult.Head.PrevHeadCID)
	atMaxCID := readRawCID(t, atMax)
	over, overSnapshot := sealFixtureSnapshot(t, fixture, atMaxCID, 0x42, []byte("n+1 payload"))
	installSnapshot(t, &fixture, over, overSnapshot, signFixtureHead(t, fixture, over, maximum+1, atMaxCID, publisherSigner(), fixtureSigningKey(12)))
	_, err = reader.Read(context.Background(), fixture.request)
	require.Error(t, err, "the reader must reject a head above the policy publication maximum")
}

var frozenSecurityDefectCases = []struct {
	id      string
	refusal string
}{
	{id: "1a", refusal: "TestExpectedRefusalReaderHeadEnvelopeParentLink"},
	{id: "3b", refusal: "TestExpectedRefusalReaderExtraRecipientInMetadata"},
	{id: "3c", refusal: "TestExpectedRefusalReaderUnauthorizedWrap"},
	{id: "5b", refusal: "TestExpectedRefusalReaderOlderSnapshotAtNextCount"},
	{id: "5c", refusal: "TestExpectedRefusalReaderCoherentForkBehindHead"},
	{id: "10", refusal: "TestExpectedRefusalReaderSplitHeadAndEnvelopeSigners"},
	{id: "11", refusal: "TestExpectedRefusalReaderControlAncestry"},
	{id: "18", refusal: "TestExpectedRefusalReaderHeadAboveMaxPublications"},
}

func TestCaseMatrixMatchesRefusalTests(t *testing.T) {
	functions := testSourceFunctions(t)
	matrixByID := make(map[string]matrixCase, len(caseMatrix))
	for _, entry := range caseMatrix {
		matrixByID[entry.id] = entry
	}
	frozenByID := make(map[string]string, len(frozenSecurityDefectCases))
	frozenRefusalNames := make(map[string]bool, len(frozenSecurityDefectCases))
	for _, frozen := range frozenSecurityDefectCases {
		frozenByID[frozen.id] = frozen.refusal
		frozenRefusalNames[frozen.refusal] = true
		row, ok := matrixByID[frozen.id]
		require.True(t, ok, "frozen defect %s has no matrix row", frozen.id)
		require.NotEmpty(t, row.refusal, "frozen defect %s has no refusal test name", frozen.id)
		assert.Equal(t, frozen.refusal, row.refusal, "frozen defect %s names a different refusal test", frozen.id)
		assert.True(t, functions[frozen.refusal], "frozen defect %s refusal test %q does not exist", frozen.id, frozen.refusal)
	}
	for _, entry := range caseMatrix {
		if _, frozen := frozenByID[entry.id]; !frozen {
			assert.Empty(t, entry.refusal, "case %s is not a frozen defect but claims a refusal counterpart", entry.id)
		}
	}
	for name := range testSourceFunctionsWithPrefix(t, "TestExpectedRefusal") {
		assert.True(t, frozenRefusalNames[name], "expected-refusal test %q is not in the frozen defect inventory", name)
	}
}

func TestCaseSecurityGateIsClosed(t *testing.T) {
	matrixByID := make(map[string]matrixCase, len(caseMatrix))
	for _, entry := range caseMatrix {
		matrixByID[entry.id] = entry
	}
	var open []string
	for _, frozen := range frozenSecurityDefectCases {
		if row, ok := matrixByID[frozen.id]; ok && row.status == statusKnownDefect {
			open = append(open, frozen.id)
		}
	}
	for _, defect := range knownSecurityDefects {
		assert.Fail(t, "open security defect", "%s (%s) owner=%s contract=%s observation=%s", defect.caseID, defect.finding, defect.owner, defect.contract, defect.observation)
	}
	assert.Empty(t, open, "the security gate is open while frozen defect rows remain known-defect")
	assert.Empty(t, knownSecurityDefects, "the security gate is open while the known-defect registry is non-empty")
}
