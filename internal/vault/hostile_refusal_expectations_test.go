//go:build known_defects

package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var frozenSecurityDefectCases = []struct {
	id      string
	refusal string
}{
	{id: "1b", refusal: "TestExpectedRefusalEnrollmentParentJoin"},
	{id: "13", refusal: "TestExpectedRefusalCheckpointSkippedPolicyChain"},
	{id: "14", refusal: "TestExpectedRefusalEnrollmentDeltaPolicyFields"},
	{id: "15", refusal: "TestExpectedRefusalRevocationDeltaPolicyFields"},
	{id: "19", refusal: "TestExpectedRefusalCheckpointCertPolicyRole"},
	{id: "20", refusal: "TestExpectedRefusalPolicyDecoderOutOfRangeBounds"},
}

func outOfRangePolicyDigest(encoded []byte) [32]byte {
	return sha256.Sum256(append([]byte(preimagePolicy), encoded...))
}

func outOfRangePolicyWire(t *testing.T, value Policy, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodePolicyPrefix(value)
	require.NoError(t, err)
	signature, err := signObject("dottie/v1/sig-policy", prefix, key)
	require.NoError(t, err)
	value.Signature = signature
	encoded, err := EncodePolicy(value)
	require.NoError(t, err)
	return encoded
}

func rebuildEnrollmentRaw(t *testing.T, fixture devicesFixture, mutate func(*Policy)) Transition {
	t.Helper()
	policy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	mutate(&policy)
	policyBytes := outOfRangePolicyWire(t, policy, fixture.root.Signing)
	digest := outOfRangePolicyDigest(policyBytes)
	wraps, err := prepareRecipientWraps(policy, fixture.intent.Wraps)
	require.NoError(t, err)
	recipients, err := prepareSealRecipients(policy, wraps)
	require.NoError(t, err)
	envelope, err := SealPrepared(PreparedSeal{
		Purpose: PurposeSnapshot, Vault: policy.Vault, PublicationID: fixture.intent.PublicationID, EpochSeq: policy.EpochSeq,
		PolicyDigest: digest, Parent: bytes.Clone(fixture.predecessor.HeadCID), DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID),
		Plaintext: fixture.intent.Plaintext, SigningKey: fixture.root.Signing, ContentKey: fixture.intent.ContentKey, Nonce: fixture.intent.Nonce, Recipients: recipients,
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

func TestExpectedRefusalEnrollmentParentJoin(t *testing.T) {
	fixture := newDevicesFixture(t)
	foreignParent, err := rawCID([]byte("unrelated predecessor head Q"))
	require.NoError(t, err)
	transition := rebuildEnrollment(t, fixture, foreignParent, nil)
	require.Error(t, ValidateTransition(transition, fixture.predecessor),
		"enrollment must join the envelope parent to the predecessor head")
}

func TestExpectedRefusalEnrollmentDeltaPolicyFields(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			transition := rebuildEnrollment(t, fixture, nil, mutator.mutate)
			require.Error(t, ValidateTransition(transition, fixture.predecessor),
				"enrollment must reject a non-roster change to %s", mutator.name)
		})
	}
}

func TestExpectedRefusalRevocationDeltaPolicyFields(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture, predecessor, base, intent := revocationFixture(t)
			transition := rebuildRevocation(t, base, predecessor, fixture.root, intent, mutator.mutate)
			require.Error(t, ValidateTransition(transition, predecessor),
				"revocation must reject a non-roster change to %s", mutator.name)
		})
	}
}

func TestExpectedRefusalPolicyDecoderOutOfRangeBounds(t *testing.T) {
	checks := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"max_publications", func(p *Policy) { p.MaxPublications = 0 }},
		{"max_epoch_age", func(p *Policy) { p.MaxEpochAge = 0 }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			outOfRange, err := DecodePolicy(fixture.transition.Policy)
			require.NoError(t, err)
			check.mutate(&outOfRange)
			encoded := outOfRangePolicyWire(t, outOfRange, fixture.root.Signing)
			_, decodeErr := DecodePolicy(encoded)
			require.Error(t, decodeErr, "DecodePolicy must reject an out-of-range %s", check.name)

			transition := rebuildEnrollmentRaw(t, fixture, check.mutate)
			require.Error(t, ValidateTransition(transition, fixture.predecessor),
				"vault transition validation must reject an out-of-range %s", check.name)
		})
	}
}

func TestExpectedRefusalCheckpointCertPolicyRole(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	heldCID, err := rawCID(held.Control)
	require.NoError(t, err)
	supplied := demotedRootEvidence(t, fixture, heldCID)
	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, trustedContext.SetHeldCheckpoint(*checkpointHeld(t, held)))
	result, err := VerifyControlState(trustedContext, VerificationRequest{Supplied: supplied})
	require.ErrorIs(t, err, ErrInvalidVerification,
		"the checkpoint verifier must refuse a policy that demotes the anchored root")
	var refusal *VerificationRefusal
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "supplied", refusal.Side)
	assert.Equal(t, "policy-signer-role", refusal.Code)
	assert.Equal(t, VerificationResult{}, result)
}

func TestExpectedRefusalCheckpointSkippedPolicyChain(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	heldCID, err := rawCID(held.Control)
	require.NoError(t, err)
	one := fixture.evidence(t, 1, heldCID)
	oneCID, err := rawCID(one.Control)
	require.NoError(t, err)
	two := fixture.evidence(t, 2, oneCID)
	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, trustedContext.SetHeldCheckpoint(*checkpointHeld(t, held)))
	result, err := VerifyControlState(trustedContext, VerificationRequest{Supplied: two, Intermediates: []ControlEvidence{one}})
	require.ErrorIs(t, err, ErrInvalidVerification,
		"the checkpoint verifier must refuse a descendant whose policy chain skips an epoch")
	var refusal *VerificationRefusal
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "supplied", refusal.Side)
	assert.Equal(t, "policy-ancestry", refusal.Code)
	assert.Equal(t, VerificationResult{}, result)
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
