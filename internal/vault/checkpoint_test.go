package vault

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type checkpointFixture struct {
	vaultID       [32]byte
	anchor        [32]byte
	root          DeviceMaterial
	cert          []byte
	kit           []byte
	checkpoint    []byte
	genesisPolicy []byte
}

func newCheckpointFixture(t *testing.T) checkpointFixture {
	t.Helper()
	root := DeviceMaterial{DeviceID: "checkpoint-root", KeyID: []byte("checkpoint-root-key"), Signing: fixedSigningKey(11), Recipient: fixedX25519Key(21)}
	kit := fixtureBytes(1, 32)
	boot, err := Bootstrap(kit, "checkpoint fixture", root)
	require.NoError(t, err)
	return checkpointFixture{
		vaultID: boot.Vault, anchor: boot.Anchor, root: root, cert: boot.Certificate, kit: kit,
		checkpoint: boot.Checkpoint, genesisPolicy: bytes.Clone(boot.Policy),
	}
}

func (f checkpointFixture) policyWithPredecessor(t *testing.T, epoch uint64, predecessor []byte) []byte {
	t.Helper()
	policy, err := DecodePolicy(f.genesisPolicy)
	require.NoError(t, err)
	policy.EpochSeq = epoch
	if epoch > 0 {
		policy.PrevPolicyDigest = mustPolicyDigest(predecessor)
	}
	policyBytes, err := signPolicy(policy, f.root.Signing)
	require.NoError(t, err)
	return policyBytes
}

func (f checkpointFixture) policyAtEpoch(t *testing.T, epoch uint64) []byte {
	t.Helper()
	policyBytes := bytes.Clone(f.genesisPolicy)
	for current := uint64(1); current <= epoch; current++ {
		policyBytes = f.policyWithPredecessor(t, current, policyBytes)
	}
	return policyBytes
}

func (f checkpointFixture) evidenceWithPolicy(t *testing.T, epoch uint64, previous, policyBytes []byte) ControlEvidence {
	t.Helper()
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	controlBytes, err := signControl(Control{
		Vault: f.vaultID, EpochSeq: epoch, PolicyDigest: policyDigest, PrevControlCID: bytes.Clone(previous),
		Signer: Signer{DeviceID: f.root.DeviceID, KeyID: bytes.Clone(f.root.KeyID)},
	}, f.root.Signing)
	require.NoError(t, err)
	return ControlEvidence{Control: controlBytes, Policy: bytes.Clone(policyBytes), Certificates: [][]byte{f.cert}}
}

func (f checkpointFixture) evidenceWithPolicyPredecessor(t *testing.T, epoch uint64, previous, predecessorPolicy []byte) ControlEvidence {
	policyBytes := f.policyWithPredecessor(t, epoch, predecessorPolicy)
	return f.evidenceWithPolicy(t, epoch, previous, policyBytes)
}

func (f checkpointFixture) evidence(t *testing.T, epoch uint64, previous []byte) ControlEvidence {
	t.Helper()
	return f.evidenceWithPolicy(t, epoch, previous, f.policyAtEpoch(t, epoch))
}

func (f checkpointFixture) enrollmentEvidence(t *testing.T, genesis ControlEvidence, branch byte) ControlEvidence {
	t.Helper()
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	device := DeviceMaterial{
		DeviceID: fmt.Sprintf("checkpoint-publisher-%d", branch), KeyID: []byte(fmt.Sprintf("checkpoint-publisher-key-%d", branch)),
		Signing: fixedSigningKey(31 + branch), Recipient: fixedX25519Key(41 + branch),
	}
	certificate, err := certificateForEnrollment(f.vaultID, device, RolePublisher, 1, f.root, genesisCID)
	require.NoError(t, err)
	policy, err := DecodePolicy(genesis.Policy)
	require.NoError(t, err)
	policy.EpochSeq = 1
	policy.PrevPolicyDigest = mustPolicyDigest(genesis.Policy)
	policy.Roles = append(policy.Roles, RoleBinding{DeviceID: device.DeviceID, Role: RolePublisher})
	var publicKey [32]byte
	copy(publicKey[:], device.Recipient.PublicKey().Bytes())
	policy.Recipients = append(policy.Recipients, PolicyRecipient{DeviceID: device.DeviceID, KeyID: bytes.Clone(device.KeyID), PublicKey: publicKey})
	sort.Slice(policy.Roles, func(i, j int) bool { return policy.Roles[i].DeviceID < policy.Roles[j].DeviceID })
	sort.Slice(policy.Recipients, func(i, j int) bool {
		return bytes.Compare(policy.Recipients[i].KeyID, policy.Recipients[j].KeyID) < 0
	})
	policyBytes, err := signPolicy(policy, f.root.Signing)
	require.NoError(t, err)
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	headCID, err := rawCID([]byte(device.DeviceID))
	require.NoError(t, err)
	controlBytes, err := signControl(Control{
		Vault: f.vaultID, EpochSeq: 1, PolicyDigest: policyDigest, HeadSnapshotCID: headCID,
		PrevControlCID: bytes.Clone(genesisCID), Signer: Signer{DeviceID: f.root.DeviceID, KeyID: bytes.Clone(f.root.KeyID)},
	}, f.root.Signing)
	require.NoError(t, err)
	return ControlEvidence{Control: controlBytes, Policy: policyBytes, Certificates: [][]byte{f.cert, certificate}}
}

func checkpointHeld(t *testing.T, evidence ControlEvidence) *ControlEvidence {
	t.Helper()
	return &ControlEvidence{
		Control: bytes.Clone(evidence.Control), Policy: bytes.Clone(evidence.Policy),
		Certificates: cloneByteSlices(evidence.Certificates),
	}
}

func verifyFixture(t *testing.T, fixture checkpointFixture, held *ControlEvidence, supplied ControlEvidence, intermediates ...ControlEvidence) VerificationResult {
	t.Helper()
	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	if held != nil {
		require.NoError(t, trustedContext.SetHeldCheckpoint(*held))
	}
	result, err := VerifyControlState(trustedContext, VerificationRequest{
		Supplied: supplied, Intermediates: intermediates,
	})
	require.NoError(t, err)
	return result
}

func TestVerifyControlStateCurrent(t *testing.T) {
	fixture := newCheckpointFixture(t)
	current := fixture.evidence(t, 0, nil)
	result := verifyFixture(t, fixture, checkpointHeld(t, current), current)
	assert.Equal(t, CheckpointCurrent, result.Outcome)
	assert.Equal(t, "same-control", result.ReasonCode)
}

func TestVerifyControlStateRefusesSelfSuppliedAnchorAndCheckpoint(t *testing.T) {
	requestType := reflect.TypeOf(VerificationRequest{})
	_, hasTrustAnchor := requestType.FieldByName("TrustAnchor")
	_, hasHeldCheckpoint := requestType.FieldByName("Held")
	assert.False(t, hasTrustAnchor)
	assert.False(t, hasHeldCheckpoint)

	fixture := newCheckpointFixture(t)
	supplied := fixture.evidence(t, 0, nil)
	artifact := struct {
		Anchor     [32]byte
		Checkpoint []byte
		Supplied   ControlEvidence
	}{Anchor: fixture.anchor, Checkpoint: fixture.checkpoint, Supplied: supplied}

	_, err := VerifyControlState(nil, VerificationRequest{Supplied: artifact.Supplied})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVerification)
	var refusal *VerificationRefusal
	require.True(t, errors.As(err, &refusal))
	assert.Equal(t, "missing-trusted-context", refusal.Code)
}

func TestVerifyControlStateDescendant(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	heldCID, err := rawCID(held.Control)
	require.NoError(t, err)
	supplied := fixture.evidence(t, 1, heldCID)
	result := verifyFixture(t, fixture, checkpointHeld(t, held), supplied)
	assert.Equal(t, CheckpointDescendant, result.Outcome)
	assert.Equal(t, 1, result.LinkCount)
}

func TestVerifyControlStateStale(t *testing.T) {
	fixture := newCheckpointFixture(t)
	old := fixture.evidence(t, 0, nil)
	oldCID, err := rawCID(old.Control)
	require.NoError(t, err)
	held := fixture.evidence(t, 1, oldCID)
	result := verifyFixture(t, fixture, checkpointHeld(t, held), old)
	assert.Equal(t, CheckpointStale, result.Outcome)
	assert.Equal(t, 1, result.LinkCount)
}

func TestVerifyControlStateConflicting(t *testing.T) {
	fixture := newCheckpointFixture(t)
	genesis := fixture.evidence(t, 0, nil)
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	held := fixture.enrollmentEvidence(t, genesis, 1)
	supplied := fixture.enrollmentEvidence(t, genesis, 2)
	heldControl, err := DecodeControl(held.Control)
	require.NoError(t, err)
	suppliedControl, err := DecodeControl(supplied.Control)
	require.NoError(t, err)
	assert.Equal(t, genesisCID, heldControl.PrevControlCID)
	assert.Equal(t, genesisCID, suppliedControl.PrevControlCID)
	assert.NotEqual(t, held.Control, supplied.Control)
	assert.NotEqual(t, mustPolicyDigest(held.Policy), mustPolicyDigest(supplied.Policy))
	heldPolicy, err := DecodePolicy(held.Policy)
	require.NoError(t, err)
	suppliedPolicy, err := DecodePolicy(supplied.Policy)
	require.NoError(t, err)
	genesisDigest := mustPolicyDigest(genesis.Policy)
	assert.Equal(t, genesisDigest, heldPolicy.PrevPolicyDigest)
	assert.Equal(t, genesisDigest, suppliedPolicy.PrevPolicyDigest)
	result := verifyFixture(t, fixture, checkpointHeld(t, held), supplied, genesis)
	assert.Equal(t, CheckpointConflicting, result.Outcome)
	assert.Equal(t, "independent-histories", result.ReasonCode)
}

func TestVerifyControlStateUnverifiableWithoutCheckpoint(t *testing.T) {
	fixture := newCheckpointFixture(t)
	supplied := fixture.evidence(t, 0, nil)
	result := verifyFixture(t, fixture, nil, supplied)
	assert.Equal(t, CheckpointUnverifiable, result.Outcome)
	assert.Equal(t, "no-checkpoint", result.ReasonCode)
	assert.True(t, result.ConsentAvailable)
}

func TestVerifyControlStatePrecedenceCurrentBeforeLink(t *testing.T) {
	fixture := newCheckpointFixture(t)
	heldEvidence := fixture.evidence(t, 0, nil)
	heldPosition, _, err := verifyControlPositionEvidence(fixture.vaultID, fixture.anchor, heldEvidence)
	require.NoError(t, err)
	heldCID, err := rawCID(heldEvidence.Control)
	require.NoError(t, err)
	supplied := fixture.evidence(t, 1, heldCID)
	suppliedPosition, _, err := verifyControlPositionEvidence(fixture.vaultID, fixture.anchor, supplied)
	require.NoError(t, err)
	result, compareErr := compareAuthenticatedControls(suppliedPosition, heldCID, &heldPosition, heldCID, nil)
	require.NoError(t, compareErr)
	assert.Equal(t, CheckpointCurrent, result.Outcome)
}

func TestVerifyControlStateLargerEpochWithoutLinkIsNotCurrent(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	supplied := fixture.evidence(t, 100, nil)
	result := verifyFixture(t, fixture, checkpointHeld(t, held), supplied)
	assert.Equal(t, CheckpointConflicting, result.Outcome)
	assert.NotEqual(t, CheckpointCurrent, result.Outcome)
}

func TestVerifyControlStateWalksSuppliedAndHeldHistory(t *testing.T) {
	fixture := newCheckpointFixture(t)
	genesis := fixture.evidence(t, 0, nil)
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	one := fixture.evidence(t, 1, genesisCID)
	oneCID, err := rawCID(one.Control)
	require.NoError(t, err)
	two := fixture.evidence(t, 2, oneCID)
	genesisDigest := mustPolicyDigest(genesis.Policy)
	oneDigest := mustPolicyDigest(one.Policy)
	twoDigest := mustPolicyDigest(two.Policy)
	assert.NotEqual(t, genesisDigest, oneDigest)
	assert.NotEqual(t, oneDigest, twoDigest)
	onePolicy, err := DecodePolicy(one.Policy)
	require.NoError(t, err)
	twoPolicy, err := DecodePolicy(two.Policy)
	require.NoError(t, err)
	assert.Equal(t, genesisDigest, onePolicy.PrevPolicyDigest)
	assert.Equal(t, oneDigest, twoPolicy.PrevPolicyDigest)

	descendant := verifyFixture(t, fixture, checkpointHeld(t, genesis), two, one)
	assert.Equal(t, CheckpointDescendant, descendant.Outcome)
	assert.Equal(t, "verified-descendant", descendant.ReasonCode)
	assert.Equal(t, 2, descendant.LinkCount)

	stale := verifyFixture(t, fixture, checkpointHeld(t, two), genesis, one)
	assert.Equal(t, CheckpointStale, stale.Outcome)
	assert.Equal(t, "verified-stale", stale.ReasonCode)
	assert.Equal(t, 2, stale.LinkCount)
}

func TestVerifyControlStateRefusesDirectPolicyControlMismatch(t *testing.T) {
	fixture := newCheckpointFixture(t)
	genesis := fixture.evidence(t, 0, nil)
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	wrongParent := fixture.policyAtEpoch(t, 1)
	directDescendant := fixture.evidenceWithPolicyPredecessor(t, 1, genesisCID, wrongParent)
	descendantContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, descendantContext.SetHeldCheckpoint(*checkpointHeld(t, genesis)))
	_, err = VerifyControlState(descendantContext, VerificationRequest{Supplied: directDescendant})
	var descendantRefusal *VerificationRefusal
	require.ErrorAs(t, err, &descendantRefusal)
	assert.Equal(t, "supplied", descendantRefusal.Side)
	assert.Equal(t, "policy-ancestry", descendantRefusal.Code)

	suppliedCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	directStale := fixture.evidenceWithPolicyPredecessor(t, 1, suppliedCID, wrongParent)
	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, trustedContext.SetHeldCheckpoint(*checkpointHeld(t, directStale)))
	_, err = VerifyControlState(trustedContext, VerificationRequest{Supplied: genesis})
	var staleRefusal *VerificationRefusal
	require.ErrorAs(t, err, &staleRefusal)
	assert.Equal(t, "held", staleRefusal.Side)
	assert.Equal(t, "policy-ancestry", staleRefusal.Code)

	epochGap := fixture.evidenceWithPolicyPredecessor(t, 2, genesisCID, genesis.Policy)
	descendantContext = NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, descendantContext.SetHeldCheckpoint(*checkpointHeld(t, genesis)))
	_, err = VerifyControlState(descendantContext, VerificationRequest{Supplied: epochGap})
	var epochRefusal *VerificationRefusal
	require.ErrorAs(t, err, &epochRefusal)
	assert.Equal(t, "supplied", epochRefusal.Side)
	assert.Equal(t, "policy-ancestry", epochRefusal.Code)

	maximumEpoch := ^uint64(0)
	maximumPolicy := fixture.policyWithPredecessor(t, maximumEpoch, genesis.Policy)
	maximum := fixture.evidenceWithPolicy(t, maximumEpoch, nil, maximumPolicy)
	maximumCID, err := rawCID(maximum.Control)
	require.NoError(t, err)
	successorPolicy, err := DecodePolicy(fixture.genesisPolicy)
	require.NoError(t, err)
	successorPolicy.PrevPolicyDigest = mustPolicyDigest(maximum.Policy)
	successorPolicyBytes, err := signPolicy(successorPolicy, fixture.root.Signing)
	require.NoError(t, err)
	successor := fixture.evidenceWithPolicy(t, 0, maximumCID, successorPolicyBytes)
	overflowContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, overflowContext.SetHeldCheckpoint(*checkpointHeld(t, maximum)))
	_, err = VerifyControlState(overflowContext, VerificationRequest{Supplied: successor})
	var overflowRefusal *VerificationRefusal
	require.ErrorAs(t, err, &overflowRefusal)
	assert.Equal(t, "supplied", overflowRefusal.Side)
	assert.Equal(t, "policy-ancestry", overflowRefusal.Code)
}

func TestVerifyControlStateRefusesTerminalPolicyControlMismatch(t *testing.T) {
	fixture := newCheckpointFixture(t)
	genesis := fixture.evidence(t, 0, nil)
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	wrongParent := fixture.policyAtEpoch(t, 1)
	one := fixture.evidenceWithPolicyPredecessor(t, 1, genesisCID, wrongParent)
	oneCID, err := rawCID(one.Control)
	require.NoError(t, err)
	two := fixture.evidenceWithPolicyPredecessor(t, 2, oneCID, one.Policy)
	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, trustedContext.SetHeldCheckpoint(*checkpointHeld(t, genesis)))
	_, err = VerifyControlState(trustedContext, VerificationRequest{
		Supplied: two, Intermediates: []ControlEvidence{one},
	})
	var refusal *VerificationRefusal
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "intermediate", refusal.Side)
	assert.Equal(t, "invalid-intermediate", refusal.Code)
	assert.Equal(t, "policy-ancestry", refusal.Check)
}

func TestVerifyControlStateMissingIntermediateIsUnverifiable(t *testing.T) {
	fixture := newCheckpointFixture(t)
	genesis := fixture.evidence(t, 0, nil)
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	one := fixture.evidence(t, 1, genesisCID)
	oneCID, err := rawCID(one.Control)
	require.NoError(t, err)
	two := fixture.evidence(t, 2, oneCID)
	result := verifyFixture(t, fixture, checkpointHeld(t, genesis), two)
	assert.Equal(t, CheckpointUnverifiable, result.Outcome)
	assert.Equal(t, "missing-intermediate", result.ReasonCode)
	assert.True(t, result.ConsentAvailable)
}

func TestVerifyControlStateDepthBoundAndMissingEvidenceAreUnverifiable(t *testing.T) {
	fixture := newCheckpointFixture(t)
	chain := make([]ControlEvidence, 10)
	chain[0] = fixture.evidence(t, 0, nil)
	previous, err := rawCID(chain[0].Control)
	require.NoError(t, err)
	for index := 1; index < len(chain); index++ {
		chain[index] = fixture.evidence(t, uint64(index), previous)
		previous, err = rawCID(chain[index].Control)
		require.NoError(t, err)
	}
	intermediates := chain[1:9]
	result := verifyFixture(t, fixture, checkpointHeld(t, chain[0]), chain[9], intermediates...)
	assert.Equal(t, CheckpointUnverifiable, result.Outcome)
	assert.Equal(t, "depth-exceeded", result.ReasonCode)
}

func TestVerifyControlStateInvalidSignatureCannotReachConsent(t *testing.T) {
	fixture := newCheckpointFixture(t)
	supplied := fixture.evidence(t, 0, nil)
	supplied.Control = bytes.Clone(supplied.Control)
	supplied.Control[len(supplied.Control)-1] ^= 0x80
	_, err := VerifyControlState(NewTrustedContext(fixture.vaultID, fixture.anchor), VerificationRequest{Supplied: supplied})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVerification)
	var refusal *VerificationRefusal
	require.True(t, errors.As(err, &refusal))
	assert.Equal(t, "control-signature", refusal.Code)
	_, err = AcceptUnverifiableConsent(VerificationResult{})
	assert.ErrorIs(t, err, ErrConsentNotOffered)
}

func TestVerifyControlStateConsentIsRecordedWithoutChangingState(t *testing.T) {
	fixture := newCheckpointFixture(t)
	supplied := fixture.evidence(t, 0, nil)
	result := verifyFixture(t, fixture, nil, supplied)
	accepted, err := AcceptUnverifiableConsent(result)
	require.NoError(t, err)
	assert.True(t, accepted.ConsentRecorded)
	assert.Equal(t, CheckpointUnverifiable, accepted.Outcome)
	assert.True(t, accepted.ConsentAvailable, "consent leaves the freshness result unverifiable")
	_, err = AcceptUnverifiableConsent(VerificationResult{Outcome: CheckpointCurrent, validityPassed: true})
	assert.ErrorIs(t, err, ErrConsentNotOffered)
}

func TestVerifyControlStateRefusesInvalidIntermediate(t *testing.T) {
	fixture := newCheckpointFixture(t)
	genesis := fixture.evidence(t, 0, nil)
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	one := fixture.evidence(t, 1, genesisCID)
	one.Control = bytes.Clone(one.Control)
	one.Control[len(one.Control)-1] ^= 1
	two := fixture.evidence(t, 2, []byte("missing-link"))
	trustedContext := NewTrustedContext(fixture.vaultID, fixture.anchor)
	require.NoError(t, trustedContext.SetHeldCheckpoint(*checkpointHeld(t, genesis)))
	_, err = VerifyControlState(trustedContext, VerificationRequest{
		Supplied: two, Intermediates: []ControlEvidence{one},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVerification)
	var refusal *VerificationRefusal
	require.True(t, errors.As(err, &refusal))
	assert.Equal(t, "invalid-intermediate", refusal.Code)
}
