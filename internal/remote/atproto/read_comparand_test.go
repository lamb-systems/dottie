package atproto

import (
	"bytes"
	"context"
	"sort"
	"testing"

	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReaderRecipientSetComparandVariesIndependently(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.request.DeviceKey = nil
	fixture.request.DeviceKeyID = nil
	policy, _, _ := fixturePolicyParts(t, fixture)
	rogueKeyID := bytes.Clone(readRogueKeyID)
	baseEnvelope, _ := sealFixtureSnapshot(t, fixture, nil, 0xA1, []byte("fixed recipient set"))
	policyKeyIDs := make([][]byte, len(policy.Recipients))
	for index, recipient := range policy.Recipients {
		policyKeyIDs[index] = bytes.Clone(recipient.KeyID)
	}
	policyKeyIDs[0] = bytes.Clone(rogueKeyID)
	hostileEnvelope, hostileSnapshot := forgeEnvelopeRecipientKeyIDs(t, baseEnvelope, policyKeyIDs, fixtureSigningKey(12))
	hostileHead := signFixtureHead(t, fixture, hostileEnvelope, 1, nil, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, hostileEnvelope, hostileSnapshot, hostileHead)

	hostileIDs := envelopeRecipientKeyIDs(t, hostileEnvelope)
	assert.Equal(t, len(policy.Recipients), len(hostileIDs), "the hostile key-ID set keeps recipient cardinality unchanged")
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecipientSet)

	originalRecipient := policy.Recipients[0]
	policy.Recipients[0] = vault.PolicyRecipient{
		DeviceID: originalRecipient.DeviceID, KeyID: bytes.Clone(rogueKeyID), PublicKey: originalRecipient.PublicKey,
	}
	sort.Slice(policy.Recipients, func(i, j int) bool {
		return bytes.Compare(policy.Recipients[i].KeyID, policy.Recipients[j].KeyID) < 0
	})
	policyBytes := signReadPolicy(t, policy, fixtureSigningKey(11))
	policyObject, err := vault.DecodePolicy(policyBytes)
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultPolicyNSID, RKey: "self"}, policyRecordFromObject(policyObject))

	controlRecordBytes := fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}]
	controlRecord, err := DecodeRecord(controlRecordBytes)
	require.NoError(t, err)
	control := controlFromRecord(controlRecord.(ControlRecord))
	control.PolicyDigest = policyDigest
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	control, err = vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, controlRecordFromObject(control))

	matchingEnvelope, matchingSnapshot := sealFixtureSnapshot(t, fixture, nil, 0xA2, []byte("fixed recipient set"))
	assert.Equal(t, hostileIDs, envelopeRecipientKeyIDs(t, matchingEnvelope), "only the trusted policy recipient set changes")
	matchingCID := readRawCID(t, matchingEnvelope)
	matchingHead := craftHead(t, fixture, policyObject.EpochSeq, policyDigest, matchingCID, nil, 1, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, matchingEnvelope, matchingSnapshot, matchingHead)

	result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err)
	assert.Equal(t, hostileIDs, envelopeRecipientKeyIDs(t, matchingEnvelope))
	assert.Equal(t, 2, len(result.Envelope.Recipients))
}

func envelopeRecipientKeyIDs(t *testing.T, envelopeBytes []byte) [][]byte {
	t.Helper()
	envelope, err := vault.DecodeEnvelope(envelopeBytes)
	require.NoError(t, err)
	keyIDs := make([][]byte, len(envelope.Recipients))
	for index, recipient := range envelope.Recipients {
		keyIDs[index] = bytes.Clone(recipient.KeyID)
	}
	return keyIDs
}

func TestReaderPreviousControlSignerComparandVariesIndependently(t *testing.T) {
	fixture := newReadFixture(t)
	certificates := fixtureCertificates(t, fixture)
	rootIdentity := certificateIdentity("root", []byte("root-sign"))
	rootCertificate, ok := certificates[rootIdentity]
	require.True(t, ok)

	alternateKeyID := []byte("root-alt-sign")
	alternateCertificate := rootCertificate.object
	alternateCertificate.KeyID = bytes.Clone(alternateKeyID)
	alternateCertificate.Signer = vault.Signer{DeviceID: "root", KeyID: bytes.Clone(alternateKeyID)}
	alternateCertificateBytes := signReadCertificate(t, alternateCertificate, fixtureSigningKey(11))
	alternateCertificate, err := vault.DecodeCertificate(alternateCertificateBytes)
	require.NoError(t, err)
	alternateCertificateObjectBytes, err := vault.EncodeCertificate(alternateCertificate)
	require.NoError(t, err)
	alternateCertificateRecordBytes, err := EncodeRecord(certificateRecordFromObject(alternateCertificate))
	require.NoError(t, err)
	certificates[certificateIdentity("root", alternateKeyID)] = storedCertificate{
		recordBytes: alternateCertificateRecordBytes, objectBytes: alternateCertificateObjectBytes, object: alternateCertificate,
	}

	previousPolicyRecord, err := DecodeRecord(fixture.request.PreviousPolicy)
	require.NoError(t, err)
	alternatePolicy := policyFromRecord(previousPolicyRecord.(PolicyRecord))
	alternatePolicy.Signer = vault.Signer{DeviceID: "root", KeyID: bytes.Clone(alternateKeyID)}
	alternatePolicyBytes := signReadPolicy(t, alternatePolicy, fixtureSigningKey(11))
	alternatePolicyObject, err := vault.DecodePolicy(alternatePolicyBytes)
	require.NoError(t, err)
	alternatePolicyRecordBytes, err := EncodeRecord(policyRecordFromObject(alternatePolicyObject))
	require.NoError(t, err)
	require.NoError(t, VerifyRecordBinding(alternatePolicyRecordBytes, alternatePolicyBytes))
	alternateSigner, err := authorizedReadSigner(alternatePolicyObject.Signer, alternatePolicyObject.Roles, certificates,
		alternatePolicyObject.Vault, alternatePolicyObject.EpochSeq, fixture.request.TrustAnchor, nil, vault.RoleRoot)
	require.NoError(t, err, "the alternative policy signer is independently certificate-authorized")
	require.NoError(t, verifySignedObject(alternatePolicyBytes, "dottie/v1/sig-policy", alternatePolicyObject.Signature[:], alternateSigner.object.SigningPublicKey[:]))

	currentPolicyRecord, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}])
	require.NoError(t, err)
	currentControlRecord, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	currentPolicy := policyFromRecord(currentPolicyRecord.(PolicyRecord))
	currentControl := controlFromRecord(currentControlRecord.(ControlRecord))

	request := fixture.request
	request.PreviousPolicy = alternatePolicyRecordBytes
	err = authorizeControlPredecessor(request, currentPolicy, currentControl, certificates)
	require.ErrorIs(t, err, ErrReadControlSigner)

	request.PreviousPolicy = bytes.Clone(fixture.request.PreviousPolicy)
	err = authorizeControlPredecessor(request, currentPolicy, currentControl, certificates)
	assert.NoError(t, err, "the fixed predecessor control is accepted when only the trusted policy-signer comparand matches")
}

func TestReaderRevocationComparandVariesIndependently(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)
	certificates := fixtureCertificates(t, fixture)
	envelope, err := vault.DecodeEnvelope(fixture.transport.blob)
	require.NoError(t, err)
	signer := vault.Signer{DeviceID: envelope.DeviceID, KeyID: bytes.Clone(envelope.KeyID)}
	revoked := []vault.RevokedDevice{{DeviceID: signer.DeviceID, CertEpoch: 1}}

	_, err = authorizedReadSigner(signer, policy.Roles, certificates, policy.Vault, policy.EpochSeq,
		fixture.request.TrustAnchor, revoked, vault.RolePublisher)
	require.ErrorContains(t, err, "signing certificate is revoked")

	_, err = authorizedReadSigner(signer, policy.Roles, certificates, policy.Vault, policy.EpochSeq,
		fixture.request.TrustAnchor, nil, vault.RolePublisher)
	assert.NoError(t, err, "the same fixed signer and certificate authorize when the signed revocation comparand is absent")
}

func TestReaderPreviousPolicyDigestComparandVariesIndependently(t *testing.T) {
	fixture := newReadFixture(t)
	policyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	previousPolicyBytes := bytes.Clone(fixture.records[policyKey])
	previousPolicyRecord, err := DecodeRecord(previousPolicyBytes)
	require.NoError(t, err)
	previousPolicy := policyFromRecord(previousPolicyRecord.(PolicyRecord))
	previousPolicyObjectBytes, err := vault.EncodePolicy(previousPolicy)
	require.NoError(t, err)
	previousPolicyDigest, err := vault.ComputePolicyDigest(previousPolicyObjectBytes)
	require.NoError(t, err)
	previousControlBytes := bytes.Clone(fixture.records[controlKey])
	previousControlObject, err := vault.EncodeControl(controlFromRecord(mustControlRecord(t, previousControlBytes)))
	require.NoError(t, err)
	previousControlCID := readRawCID(t, previousControlObject)
	previousSnapshotCID := fixtureSnapshotCID(t, fixture)

	currentPolicyRecordBytes, currentPolicy, currentPolicyDigest := craftSuccessorPolicy(t, fixture, 2, previousPolicyDigest)
	currentEnvelope, currentSnapshot := sealSnapshotAtEpoch(t, fixture, currentPolicy, currentPolicyDigest, 2,
		previousSnapshotCID, 0xB2, []byte("epoch two payload"))
	currentCID := readRawCID(t, currentEnvelope)
	currentControl := craftControl(t, fixture, 2, currentPolicyDigest, currentCID, previousControlCID)
	currentHead := craftHead(t, fixture, 2, currentPolicyDigest, currentCID, previousSnapshotCID, 1,
		publisherSigner(), fixtureSigningKey(12))
	fixture.records[policyKey] = currentPolicyRecordBytes
	putReadRecord(t, fixture.records, controlKey, currentControl)
	installSnapshot(t, &fixture, currentEnvelope, currentSnapshot, currentHead)
	fixture.request.PreviousControl = previousControlBytes

	decoyPolicy := previousPolicy
	decoyPolicy.MaxPublications++
	decoyPolicyBytes := signReadPolicy(t, decoyPolicy, fixtureSigningKey(11))
	decoyPolicyObject, err := vault.DecodePolicy(decoyPolicyBytes)
	require.NoError(t, err)
	decoyPolicyRecordBytes, err := EncodeRecord(policyRecordFromObject(decoyPolicyObject))
	require.NoError(t, err)
	require.NoError(t, VerifyRecordBinding(decoyPolicyRecordBytes, decoyPolicyBytes))
	decoySigner, err := authorizedReadSigner(decoyPolicyObject.Signer, decoyPolicyObject.Roles, fixtureCertificates(t, fixture),
		decoyPolicyObject.Vault, decoyPolicyObject.EpochSeq, fixture.request.TrustAnchor, nil, vault.RoleRoot)
	require.NoError(t, err)
	require.NoError(t, verifySignedObject(decoyPolicyBytes, "dottie/v1/sig-policy", decoyPolicyObject.Signature[:], decoySigner.object.SigningPublicKey[:]))
	fixture.request.PreviousPolicy = decoyPolicyRecordBytes

	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecordContext)
	var contextErr *RecordContextError
	require.ErrorAs(t, err, &contextErr)
	assert.Equal(t, "prevPolicyDigest", contextErr.Field)

	fixture.request.PreviousPolicy = previousPolicyBytes
	result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err, "the fixed current policy succeeds when only PreviousPolicy is varied to its signed predecessor")
	assert.Equal(t, currentPolicy.EpochSeq, result.Policy.EpochSeq)
	assert.Equal(t, previousPolicyDigest[:], result.Policy.PrevPolicyDigest)
}

func mustControlRecord(t *testing.T, data []byte) ControlRecord {
	t.Helper()
	record, err := DecodeRecord(data)
	require.NoError(t, err)
	control, ok := record.(ControlRecord)
	require.True(t, ok)
	return control
}

func TestReaderPublicationMaximumComparandVariesIndependently(t *testing.T) {
	fixture := newReadFixture(t)
	s0CID, s1CID := buildGenuineChain(t, &fixture, 0xC0)
	require.NotEqual(t, s0CID, s1CID)
	s2CID := buildGenuineThirdPublication(t, &fixture, s1CID, 0xC2)
	require.NotEqual(t, s1CID, s2CID)
	result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err)
	require.Equal(t, uint64(2), result.PublicationCount)

	options := PublicationCountOptions{
		MaxPublications: 1, EnforceMaximum: true,
		PrevHeadCID: bytes.Clone(result.Head.PrevHeadCID), ParentCID: bytes.Clone(result.Envelope.Parent), EnforceParent: true,
	}
	err = CheckPublicationCount(context.Background(), fixture.observationStore, fixture.request.Vault, result, options)
	require.ErrorIs(t, err, vault.ErrPublicationCount)

	options.MaxPublications = 2
	err = CheckPublicationCount(context.Background(), fixture.observationStore, fixture.request.Vault, result, options)
	assert.NoError(t, err, "the same authenticated two-publication input passes when only the trusted maximum is raised to two")
}

func TestReaderRecordBindingComparandVariesIndependently(t *testing.T) {
	fixture := newReadFixture(t)
	recordBytes := bytes.Clone(fixture.records[RecordKey{Collection: VaultHeadNSID, RKey: "self"}])
	hostileHead := fixtureHeadObject(t, fixture)
	hostileHead.PrevHeadCID = []byte("signed alternate predecessor")
	hostileHeadBytes := signReadHead(t, hostileHead, fixtureSigningKey(12))
	decodedHostileHead, err := vault.DecodeHead(hostileHeadBytes)
	require.NoError(t, err)

	err = VerifyRecordBinding(recordBytes, hostileHeadBytes)
	var bindingErr *RecordBindingError
	require.ErrorAs(t, err, &bindingErr)
	assert.Equal(t, "prevHeadCid", bindingErr.Field)

	matchingRecordBytes, err := EncodeRecord(headRecordFromObject(decodedHostileHead))
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordBinding(matchingRecordBytes, hostileHeadBytes),
		"the fixed valid signed head passes when only the repository-record comparison value matches it")
}
