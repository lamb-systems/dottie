package vault

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	{id: "1b", status: statusNewRefusal, test: "TestEnrollmentRefusesParentMismatch", refusal: "TestExpectedRefusalEnrollmentParentJoin"},
	{id: "2", status: statusNewRefusal, test: "TestExportRefusesCheckpointNamingAbsentRoot"},
	{id: "3a-i", status: statusExisting, test: "TestOpenVerificationOrderAndAuthorizationErrors"},
	{id: "3a-ii", status: statusNewRefusal, test: "TestOpenRefusesRecipientAbsentFromPolicy"},
	{id: "12", status: statusNewRefusal, test: "TestExportRefusesOverCapAndMismatchedMembers"},
	{id: "13", status: statusNewRefusal, test: "TestVerifyControlStateRefusesSkippedPolicyChain", refusal: "TestExpectedRefusalCheckpointSkippedPolicyChain"},
	{id: "14", status: statusNewRefusal, test: "TestEnrollmentRefusesNonRosterPolicyFieldChanges", refusal: "TestExpectedRefusalEnrollmentDeltaPolicyFields"},
	{id: "15", status: statusNewRefusal, test: "TestRevocationRefusesNonRosterPolicyFieldChanges", refusal: "TestExpectedRefusalRevocationDeltaPolicyFields"},
	{id: "19", status: statusNewRefusal, test: "TestVerifyControlStateRefusesCertificatePolicyRoleMismatch", refusal: "TestExpectedRefusalCheckpointCertPolicyRole"},
	{id: "20", status: statusNewRefusal, test: "TestPolicyDecoderRefusesOutOfRangeBounds", refusal: "TestExpectedRefusalPolicyDecoderOutOfRangeBounds"},
}

var knownSecurityDefects []securityDefect

const hostilePackageName = "vault"

var frozenCaseInventory = []string{"1b", "2", "3a-i", "3a-ii", "12", "13", "14", "15", "19", "20"}

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

func rebuildEnrollment(t *testing.T, fixture devicesFixture, parentOverride []byte, mutate func(*Policy)) Transition {
	t.Helper()
	policy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	if mutate != nil {
		mutate(&policy)
	}
	policyBytes, err := signPolicy(policy, fixture.root.Signing)
	require.NoError(t, err)
	policy, err = DecodePolicy(policyBytes)
	require.NoError(t, err)
	digest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	parent := bytes.Clone(fixture.predecessor.HeadCID)
	if parentOverride != nil {
		parent = bytes.Clone(parentOverride)
	}
	wraps, err := prepareRecipientWraps(policy, fixture.intent.Wraps)
	require.NoError(t, err)
	recipients, err := prepareSealRecipients(policy, wraps)
	require.NoError(t, err)
	envelope, err := SealPrepared(PreparedSeal{
		Purpose: PurposeSnapshot, Vault: policy.Vault, PublicationID: fixture.intent.PublicationID, EpochSeq: policy.EpochSeq,
		PolicyDigest: digest, Parent: parent, DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID),
		Plaintext: fixture.intent.Plaintext, SigningKey: fixture.root.Signing, ContentKey: fixture.intent.ContentKey,
		Nonce: fixture.intent.Nonce, Recipients: recipients, Policy: policy,
	})
	require.NoError(t, err)
	envelopeBytes, err := EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshotCID, err := rawCID(envelopeBytes)
	require.NoError(t, err)
	oldControl, err := DecodeControl(fixture.transition.Control)
	require.NoError(t, err)
	control := Control{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: digest, HeadSnapshotCID: bytes.Clone(snapshotCID),
		Revoked: oldControl.Revoked, PrevControlCID: bytes.Clone(fixture.predecessor.ControlCID),
		Signer: Signer{DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID)},
	}
	controlBytes, err := signControl(control, fixture.root.Signing)
	require.NoError(t, err)
	head := Head{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: digest, SnapshotCID: bytes.Clone(snapshotCID),
		BlobCID: bytes.Clone(snapshotCID), PublicationCount: 0, PrevHeadCID: bytes.Clone(fixture.predecessor.HeadCID),
		Signer: Signer{DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID)},
	}
	headBytes, err := signHead(head, fixture.root.Signing)
	require.NoError(t, err)
	transition := Transition{
		Kind: TransitionEnroll, Predecessor: fixture.transition.Predecessor, Policy: policyBytes, Control: controlBytes,
		Certificate: fixture.transition.Certificate, Head: headBytes, Snapshot: envelopeBytes, SnapshotCID: snapshotCID,
		BlobCID: bytes.Clone(snapshotCID), Recipients: fixture.transition.Recipients,
	}
	transition.Digest = ComputeTransitionDigest(transition)
	return transition
}

func enrollmentPolicyFieldMutators() []struct {
	name   string
	mutate func(*Policy)
} {
	return []struct {
		name   string
		mutate func(*Policy)
	}{
		{"PolicyRetentionFloor", func(p *Policy) { p.PolicyRetentionFloor = 7 }},
		{"RetainedRecoveryPoints", func(p *Policy) { p.RetainedRecoveryPoints = 9 }},
		{"MaxPublications", func(p *Policy) { p.MaxPublications = 5 }},
		{"MaxEpochAge", func(p *Policy) { p.MaxEpochAge = 7200 }},
		{"RecoveryAnchor", func(p *Policy) { p.RecoveryAnchor = [32]byte{0xAB, 0xCD} }},
	}
}

func TestEnrollmentRefusesParentMismatch(t *testing.T) {
	fixture := newDevicesFixture(t)
	foreignParent, err := rawCID([]byte("unrelated predecessor head Q"))
	require.NoError(t, err)
	transition := rebuildEnrollment(t, fixture, foreignParent, nil)
	envelope, err := DecodeEnvelope(transition.Snapshot)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(envelope.Parent, fixture.predecessor.HeadCID),
		"the hostile enrollment snapshot names a parent the predecessor never held")
	require.ErrorIs(t, ValidateTransition(transition, fixture.predecessor), ErrSnapshotEpoch,
		"enrollment refuses an envelope parent that differs from the predecessor head")

	controlFixture := newDevicesFixture(t)
	require.NoError(t, ValidateTransition(controlFixture.transition, controlFixture.predecessor),
		"enrollment accepts a snapshot whose envelope parent matches the predecessor head")
}

func TestEnrollmentRefusesNonRosterPolicyFieldChanges(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			transition := rebuildEnrollment(t, fixture, nil, mutator.mutate)
			require.ErrorIs(t, ValidateTransition(transition, fixture.predecessor), ErrTransitionDelta,
				"enrollment must reject a non-roster change to %s", mutator.name)
		})
	}

	fixture := newDevicesFixture(t)
	require.NoError(t, ValidateTransition(fixture.transition, fixture.predecessor),
		"enrollment accepts a transition with all non-roster policy fields unchanged")
}

func rebuildRevocation(t *testing.T, base Transition, predecessor Predecessor, signer DeviceMaterial, intent TransitionIntent, mutate func(*Policy)) Transition {
	t.Helper()
	policy, err := DecodePolicy(base.Policy)
	require.NoError(t, err)
	if mutate != nil {
		mutate(&policy)
	}
	policyBytes, err := signPolicy(policy, signer.Signing)
	require.NoError(t, err)
	policy, err = DecodePolicy(policyBytes)
	require.NoError(t, err)
	digest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	wraps, err := prepareRecipientWraps(policy, intent.Wraps)
	require.NoError(t, err)
	recipients, err := prepareSealRecipients(policy, wraps)
	require.NoError(t, err)
	envelope, err := SealPrepared(PreparedSeal{
		Purpose: PurposeSnapshot, Vault: policy.Vault, PublicationID: intent.PublicationID, EpochSeq: policy.EpochSeq,
		PolicyDigest: digest, Parent: bytes.Clone(predecessor.HeadCID), DeviceID: signer.DeviceID, KeyID: bytes.Clone(signer.KeyID),
		Plaintext: intent.Plaintext, SigningKey: signer.Signing, ContentKey: intent.ContentKey, Nonce: intent.Nonce, Recipients: recipients, Policy: policy,
	})
	require.NoError(t, err)
	envelopeBytes, err := EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshotCID, err := rawCID(envelopeBytes)
	require.NoError(t, err)
	oldControl, err := DecodeControl(base.Control)
	require.NoError(t, err)
	control := Control{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: digest, HeadSnapshotCID: bytes.Clone(snapshotCID),
		Revoked: oldControl.Revoked, PrevControlCID: bytes.Clone(predecessor.ControlCID),
		Signer: Signer{DeviceID: signer.DeviceID, KeyID: bytes.Clone(signer.KeyID)},
	}
	controlBytes, err := signControl(control, signer.Signing)
	require.NoError(t, err)
	head := Head{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: digest, SnapshotCID: bytes.Clone(snapshotCID),
		BlobCID: bytes.Clone(snapshotCID), PublicationCount: 0, PrevHeadCID: bytes.Clone(predecessor.HeadCID),
		Signer: Signer{DeviceID: signer.DeviceID, KeyID: bytes.Clone(signer.KeyID)},
	}
	headBytes, err := signHead(head, signer.Signing)
	require.NoError(t, err)
	transition := Transition{
		Kind: TransitionRevoke, Predecessor: base.Predecessor, Policy: policyBytes, Control: controlBytes,
		Head: headBytes, Snapshot: envelopeBytes, SnapshotCID: snapshotCID, BlobCID: bytes.Clone(snapshotCID),
		Recipients: base.Recipients,
	}
	transition.Digest = ComputeTransitionDigest(transition)
	return transition
}

func revocationFixture(t *testing.T) (devicesFixture, Predecessor, Transition, TransitionIntent) {
	t.Helper()
	fixture, predecessor, _, _ := newPublicationTestFixture(t)
	intent := TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root, RevokeDeviceID: fixture.newDevice.DeviceID,
		ContentKey: fixtureBytes(31, 32), Recipients: [][]byte{predecessor.Certificates[0]},
		Wraps:     []RecipientWrapInput{{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(91, 32)), WrapNonce: [24]byte(fixtureBytes(123, 24))}},
		Plaintext: []byte("complete current snapshot"), PublicationID: [16]byte(fixtureBytes(157, 16)), Nonce: [24]byte(fixtureBytes(173, 24)),
	}
	base, err := PrepareTransition(predecessor, intent)
	require.NoError(t, err)
	return fixture, predecessor, base, intent
}

func TestRevocationRefusesNonRosterPolicyFieldChanges(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture, predecessor, base, intent := revocationFixture(t)
			transition := rebuildRevocation(t, base, predecessor, fixture.root, intent, mutator.mutate)
			require.ErrorIs(t, ValidateTransition(transition, predecessor), ErrTransitionDelta,
				"revocation must reject a non-roster change to %s", mutator.name)
		})
	}

	_, predecessor, base, _ := revocationFixture(t)
	require.NoError(t, ValidateTransition(base, predecessor),
		"revocation accepts a transition with all non-roster policy fields unchanged")
}

func demotedRootEvidence(t *testing.T, fixture checkpointFixture, heldCID []byte) ControlEvidence {
	t.Helper()
	boot, err := Bootstrap(fixture.kit, "checkpoint fixture", fixture.root)
	require.NoError(t, err)
	policy, err := DecodePolicy(boot.Policy)
	require.NoError(t, err)
	policy.EpochSeq = 1
	policy.PrevPolicyDigest = mustPolicyDigest(boot.Policy)
	policy.Roles = []RoleBinding{{DeviceID: fixture.root.DeviceID, Role: RolePublisher}}
	policyBytes, err := signPolicy(policy, fixture.root.Signing)
	require.NoError(t, err)
	digest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	controlBytes, err := signControl(Control{
		Vault: fixture.vaultID, EpochSeq: 1, PolicyDigest: digest, PrevControlCID: bytes.Clone(heldCID),
		Signer: Signer{DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID)},
	}, fixture.root.Signing)
	require.NoError(t, err)
	return ControlEvidence{Control: controlBytes, Policy: policyBytes, Certificates: [][]byte{fixture.cert}}
}

func TestVerifyControlStateRefusesCertificatePolicyRoleMismatch(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	heldCID, err := rawCID(held.Control)
	require.NoError(t, err)
	supplied := demotedRootEvidence(t, fixture, heldCID)

	suppliedPolicy, err := DecodePolicy(supplied.Policy)
	require.NoError(t, err)
	role, found := policyRole(suppliedPolicy, fixture.root.DeviceID)
	require.True(t, found)
	certificate, err := DecodeCertificate(fixture.cert)
	require.NoError(t, err)
	assert.Equal(t, RolePublisher, role)
	assert.Equal(t, RoleRoot, certificate.Role)

	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, trustedContext.SetHeldCheckpoint(*checkpointHeld(t, held)))
	result, err := VerifyControlState(trustedContext, VerificationRequest{Supplied: supplied})
	var refusal *VerificationRefusal
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "supplied", refusal.Side)
	assert.Equal(t, "policy-signer-role", refusal.Code)
	assert.Equal(t, VerificationResult{}, result)
}

func TestVerifyControlStateRefusesSkippedPolicyChain(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	heldCID, err := rawCID(held.Control)
	require.NoError(t, err)
	one := fixture.evidence(t, 1, heldCID)
	oneCID, err := rawCID(one.Control)
	require.NoError(t, err)
	two := fixture.evidenceWithPolicyPredecessor(t, 2, oneCID, held.Policy)
	oneControl, err := DecodeControl(one.Control)
	require.NoError(t, err)
	twoControl, err := DecodeControl(two.Control)
	require.NoError(t, err)
	assert.Equal(t, heldCID, oneControl.PrevControlCID)
	assert.Equal(t, oneCID, twoControl.PrevControlCID)

	genesisDigest := mustPolicyDigest(held.Policy)
	intermediateDigest := mustPolicyDigest(one.Policy)
	twoPolicy, err := DecodePolicy(two.Policy)
	require.NoError(t, err)
	assert.Equal(t, genesisDigest, twoPolicy.PrevPolicyDigest)
	assert.NotEqual(t, intermediateDigest, twoPolicy.PrevPolicyDigest,
		"the epoch-2 policy skips the epoch-1 policy in its ancestry")

	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, trustedContext.SetHeldCheckpoint(*checkpointHeld(t, held)))
	result, err := VerifyControlState(trustedContext, VerificationRequest{Supplied: two, Intermediates: []ControlEvidence{one}})
	var refusal *VerificationRefusal
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "supplied", refusal.Side)
	assert.Equal(t, "policy-ancestry", refusal.Code)
	assert.Equal(t, VerificationResult{}, result)
}

func TestOpenRefusesRecipientAbsentFromPolicy(t *testing.T) {
	fixture := newDevicesFixture(t)
	policyBytes := fixture.transition.Policy
	policy, err := DecodePolicy(policyBytes)
	require.NoError(t, err)
	digest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	absent := fixedX25519Key(90)
	absentID := []byte("absent-recipient")
	var ephemeral [32]byte
	copy(ephemeral[:], fixedX25519Key(43).PublicKey().Bytes())
	envelope := Envelope{
		Purpose: PurposeSnapshot, Vault: policy.Vault, PublicationID: [16]byte(fixtureBytes(201, 16)), EpochSeq: policy.EpochSeq,
		PolicyDigest: digest, DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID),
		Commit: [32]byte(fixtureBytes(221, 32)), Nonce: [24]byte(fixtureBytes(5, 24)),
		Ciphertext: []byte("hostile synthetic payload"),
		Recipients: []EnvelopeRecipient{{
			KeyID: bytes.Clone(absentID), Ephemeral: ephemeral, WrapNonce: [24]byte(fixtureBytes(81, 24)), WrappedKey: fixtureBytes(113, 48),
		}},
	}
	unsignedBytes, err := EncodeEnvelope(envelope)
	require.NoError(t, err)
	preimage := append([]byte(preimageSig), unsignedBytes[:len(unsignedBytes)-ed25519.SignatureSize]...)
	signature, err := Sign(contextForPurpose(envelope.Purpose), preimage, fixture.root.Signing)
	require.NoError(t, err)
	copy(envelope.Signature[:], signature)
	hostileBytes, err := EncodeEnvelope(envelope)
	require.NoError(t, err)
	hostileEnvelope, err := DecodeEnvelope(hostileBytes)
	require.NoError(t, err)
	request := OpenRequest{
		Vault: fixture.bootstrap.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: digest,
		Policy: policyBytes, Control: fixture.transition.Control, TrustAnchor: fixture.bootstrap.Anchor,
		Certificates: fixture.transition.Recipients, DeviceKeyID: absentID, DeviceKey: absent,
	}
	_, err = Open(hostileEnvelope, request)
	require.ErrorIs(t, err, ErrRecipient, "Open must refuse a signed envelope recipient absent from policy authorization")
}

func splitExportArchive(t *testing.T, encoded []byte) (ExportManifest, []exportTestMember) {
	t.Helper()
	require.True(t, bytes.HasPrefix(encoded, []byte(exportMagic)))
	tarReader := tar.NewReader(bytes.NewReader(encoded[len(exportMagic):]))
	var members []exportTestMember
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tarReader)
		require.NoError(t, err)
		members = append(members, exportTestMember{name: header.Name, data: data})
	}
	require.NotEmpty(t, members)
	var manifest ExportManifest
	require.NoError(t, json.Unmarshal(members[0].data, &manifest))
	return manifest, members[1:]
}

func buildHostileExportArchive(t *testing.T, manifest ExportManifest, members []exportTestMember) []byte {
	t.Helper()
	manifestBytes, err := encodeExportManifest(manifest)
	require.NoError(t, err)
	var result bytes.Buffer
	result.WriteString(exportMagic)
	writer := tar.NewWriter(&result)
	require.NoError(t, writeMember(writer, exportManifestMember, manifestBytes))
	for _, member := range members {
		require.NoError(t, writeMember(writer, member.name, member.data))
	}
	require.NoError(t, writer.Close())
	return result.Bytes()
}

func TestExportRefusesCheckpointNamingAbsentRoot(t *testing.T) {
	input, fixture := exportTestInput(t)
	anchorA := fixture.bootstrap.Anchor
	require.Equal(t, anchorA, exportTestOptions(fixture).ExpectedAnchor)
	genuine, err := EncodeExportArchive(input)
	require.NoError(t, err)
	manifest, members := splitExportArchive(t, genuine)
	checkpointIndex := -1
	for index, entry := range manifest.Entries {
		if entry.Kind == exportEntryCheckpoint {
			checkpointIndex = index
		}
	}
	require.GreaterOrEqual(t, checkpointIndex, 0)
	original, err := DecodeCheckpoint(members[checkpointIndex].data)
	require.NoError(t, err)
	require.Equal(t, anchorA, original.Anchor)
	var anchorB [32]byte
	copy(anchorB[:], bytes.Repeat([]byte{0xB1}, 32))
	require.NotEqual(t, anchorA, anchorB)
	original.Anchor = anchorB
	kitKey, err := deriveKitSigningKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	forged := signCheckpointValue(t, original, kitKey)
	members[checkpointIndex].data = forged
	manifest.Entries[checkpointIndex].SHA256 = exportDigest(forged)
	manifest.Entries[checkpointIndex].Length = int64(len(forged))

	kitPublic, err := RecoveryKitSigningPublicKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	forgedCheckpoint, verifyErr := VerifyCheckpoint(forged, kitPublic)
	require.NoError(t, verifyErr, "the forged checkpoint is correctly kit-signed")
	require.Equal(t, anchorB, forgedCheckpoint.Anchor)
	require.NotEqual(t, anchorA, forgedCheckpoint.Anchor)

	rejected := input
	rejected.Checkpoint = forged
	_, encodeErr := EncodeExportArchive(rejected)
	require.ErrorIs(t, encodeErr, ErrAuthorization, "EncodeExportArchive refuses the foreign-anchor checkpoint up front")

	hostile := buildHostileExportArchive(t, manifest, members)
	err = readExportRefusalWithoutMutation(t, hostile, exportTestOptions(fixture))
	require.ErrorIs(t, err, ErrAuthorization)
	require.ErrorContains(t, err, "checkpoint vault or anchor")
}
