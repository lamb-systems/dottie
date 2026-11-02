//go:build known_defects

package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pinnedFrozenDefectIDs = []string{"1b", "13", "14", "15", "19", "20"}

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

func TestExpectedRefusalEnrollmentParentJoin(t *testing.T) {
	fixture := newDevicesFixture(t)
	foreignParent, err := rawCID([]byte("unrelated predecessor head Q"))
	require.NoError(t, err)
	transition := rebuildEnrollment(t, fixture, foreignParent, nil)
	require.ErrorIs(t, ValidateTransition(transition, fixture.predecessor), ErrSnapshotEpoch,
		"enrollment refuses an envelope parent that differs from the predecessor head")

	controlFixture := newDevicesFixture(t)
	require.NoError(t, ValidateTransition(controlFixture.transition, controlFixture.predecessor),
		"enrollment accepts a snapshot whose envelope parent matches the predecessor head")
}

func TestEnrollmentPolicyFieldRefusalSentinel(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			transition := rebuildEnrollment(t, fixture, nil, mutator.mutate)
			require.ErrorIs(t, ValidateTransition(transition, fixture.predecessor), ErrTransitionDelta,
				"enrollment must reject a non-roster change to %s", mutator.name)
		})
	}
}

func TestRevocationPolicyFieldRefusalSentinel(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture, predecessor, base, intent := revocationFixture(t)
			transition := rebuildRevocation(t, base, predecessor, fixture.root, intent, mutator.mutate)
			require.ErrorIs(t, ValidateTransition(transition, predecessor), ErrTransitionDelta,
				"revocation must reject a non-roster change to %s", mutator.name)
		})
	}
}

func TestExpectedRefusalPolicyDecoderOutOfRangeBounds(t *testing.T) {
	for _, check := range outOfRangePolicyCases() {
		t.Run(check.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			outOfRange, err := DecodePolicy(fixture.transition.Policy)
			require.NoError(t, err)
			check.mutate(&outOfRange)
			encoded := outOfRangePolicyWire(t, outOfRange, fixture.root.Signing)
			_, decodeErr := DecodePolicy(encoded)
			require.ErrorIs(t, decodeErr, ErrLimit, "DecodePolicy rejects out-of-range %s", check.name)
			assert.ErrorContains(t, decodeErr, check.field, "DecodePolicy identifies out-of-range %s", check.field)

			transition := rebuildEnrollmentRaw(t, fixture, check.mutate)
			transitionErr := ValidateTransition(transition, fixture.predecessor)
			require.ErrorIs(t, transitionErr, ErrTransitionSignature,
				"vault transition validation rejects out-of-range %s", check.name)
			assert.ErrorIs(t, transitionErr, ErrLimit, "vault transition preserves the policy range error")
			assert.ErrorContains(t, transitionErr, check.field, "vault transition identifies out-of-range %s", check.field)
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
	two := fixture.evidenceWithPolicyPredecessor(t, 2, oneCID, held.Policy)
	oneControl, err := DecodeControl(one.Control)
	require.NoError(t, err)
	twoControl, err := DecodeControl(two.Control)
	require.NoError(t, err)
	assert.Equal(t, heldCID, oneControl.PrevControlCID)
	assert.Equal(t, oneCID, twoControl.PrevControlCID)
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
	frozenIDs := make([]string, 0, len(frozenSecurityDefectCases))
	for _, frozen := range frozenSecurityDefectCases {
		frozenIDs = append(frozenIDs, frozen.id)
	}
	assert.ElementsMatch(t, pinnedFrozenDefectIDs, frozenIDs,
		"the frozen defect inventory is pinned: closing a defect moves its matrix status, it never removes the entry")
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

func TestExpectedRefusalEnrollmentDeltaPolicyFields(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			transition := rebuildEnrollment(t, fixture, nil, mutator.mutate)
			require.ErrorIs(t, ValidateTransition(transition, fixture.predecessor), ErrTransitionDelta,
				"enrollment must refuse a non-roster change to %s", mutator.name)
		})
	}
	fixture := newDevicesFixture(t)
	require.NoError(t, ValidateTransition(fixture.transition, fixture.predecessor),
		"enrollment accepts a transition whose non-roster fields are unchanged")
}

func TestExpectedRefusalRevocationDeltaPolicyFields(t *testing.T) {
	for _, mutator := range enrollmentPolicyFieldMutators() {
		t.Run(mutator.name, func(t *testing.T) {
			fixture, predecessor, base, intent := revocationFixture(t)
			transition := rebuildRevocation(t, base, predecessor, fixture.root, intent, mutator.mutate)
			require.ErrorIs(t, ValidateTransition(transition, predecessor), ErrTransitionDelta,
				"revocation must refuse a non-roster change to %s", mutator.name)
		})
	}
	_, predecessor, base, _ := revocationFixture(t)
	require.NoError(t, ValidateTransition(base, predecessor),
		"revocation accepts a transition whose non-roster fields are unchanged")
}
