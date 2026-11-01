package vault

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type checkpointFixture struct {
	vaultID [32]byte
	anchor  [32]byte
	root    DeviceMaterial
	cert    []byte
	kit     []byte
}

func newCheckpointFixture(t *testing.T) checkpointFixture {
	t.Helper()
	root := DeviceMaterial{DeviceID: "checkpoint-root", KeyID: []byte("checkpoint-root-key"), Signing: fixedSigningKey(11), Recipient: fixedX25519Key(21)}
	kit := fixtureBytes(1, 32)
	boot, err := Bootstrap(kit, "checkpoint fixture", root)
	require.NoError(t, err)
	return checkpointFixture{vaultID: boot.Vault, anchor: boot.Anchor, root: root, cert: boot.Certificate, kit: kit}
}

func (f checkpointFixture) evidence(t *testing.T, epoch uint64, previous []byte) ControlEvidence {
	t.Helper()
	boot, err := Bootstrap(f.kit, "checkpoint fixture", f.root)
	require.NoError(t, err)
	policy, err := DecodePolicy(boot.Policy)
	require.NoError(t, err)
	policy.EpochSeq = epoch
	if epoch > 0 {
		policy.PrevPolicyDigest = mustPolicyDigest(boot.Policy)
	}
	policyBytes, err := signPolicy(policy, f.root.Signing)
	require.NoError(t, err)
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	controlBytes, err := signControl(Control{
		Vault: f.vaultID, EpochSeq: epoch, PolicyDigest: policyDigest, PrevControlCID: bytes.Clone(previous),
		Signer: Signer{DeviceID: f.root.DeviceID, KeyID: bytes.Clone(f.root.KeyID)},
	}, f.root.Signing)
	require.NoError(t, err)
	return ControlEvidence{Control: controlBytes, Policy: policyBytes, Certificates: [][]byte{f.cert}}
}

func checkpointHeld(t *testing.T, fixture checkpointFixture, evidence ControlEvidence) *HeldCheckpoint {
	t.Helper()
	control, err := DecodeControl(evidence.Control)
	require.NoError(t, err)
	controlCID, err := rawCID(evidence.Control)
	require.NoError(t, err)
	return &HeldCheckpoint{
		Position: CheckpointPosition{
			Vault: fixture.vaultID, Anchor: fixture.anchor, ControlCID: controlCID,
			ControlBytes: bytes.Clone(evidence.Control), SnapshotCID: bytes.Clone(control.HeadSnapshotCID),
			EpochSeq: control.EpochSeq, PolicyDigest: control.PolicyDigest,
		},
		Evidence: ControlEvidence{Policy: evidence.Policy, Certificates: evidence.Certificates},
	}
}

func verifyFixture(t *testing.T, fixture checkpointFixture, held *HeldCheckpoint, supplied ControlEvidence, intermediates ...ControlEvidence) VerificationResult {
	t.Helper()
	result, err := VerifyControlState(VerificationRequest{
		Vault: fixture.vaultID, TrustAnchor: fixture.anchor, Held: held, Supplied: supplied, Intermediates: intermediates,
	})
	require.NoError(t, err)
	return result
}

func TestVerifyControlStateCurrent(t *testing.T) {
	fixture := newCheckpointFixture(t)
	current := fixture.evidence(t, 0, nil)
	result := verifyFixture(t, fixture, checkpointHeld(t, fixture, current), current)
	assert.Equal(t, CheckpointCurrent, result.Outcome)
	assert.Equal(t, "same-control", result.ReasonCode)
}

func TestVerifyControlStateDescendant(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	heldCID, err := rawCID(held.Control)
	require.NoError(t, err)
	supplied := fixture.evidence(t, 1, heldCID)
	result := verifyFixture(t, fixture, checkpointHeld(t, fixture, held), supplied)
	assert.Equal(t, CheckpointDescendant, result.Outcome)
	assert.Equal(t, 1, result.LinkCount)
}

func TestVerifyControlStateStale(t *testing.T) {
	fixture := newCheckpointFixture(t)
	old := fixture.evidence(t, 0, nil)
	oldCID, err := rawCID(old.Control)
	require.NoError(t, err)
	held := fixture.evidence(t, 1, oldCID)
	result := verifyFixture(t, fixture, checkpointHeld(t, fixture, held), old)
	assert.Equal(t, CheckpointStale, result.Outcome)
	assert.Equal(t, 1, result.LinkCount)
}

func TestVerifyControlStateConflicting(t *testing.T) {
	fixture := newCheckpointFixture(t)
	genesis := fixture.evidence(t, 0, nil)
	genesisCID, err := rawCID(genesis.Control)
	require.NoError(t, err)
	held := fixture.evidence(t, 1, genesisCID)
	supplied := fixture.evidence(t, 2, genesisCID)
	result := verifyFixture(t, fixture, checkpointHeld(t, fixture, held), supplied, genesis)
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
	heldControl, err := DecodeControl(heldEvidence.Control)
	require.NoError(t, err)
	_, _, err = verifyControlEvidence(fixture.vaultID, fixture.anchor, heldEvidence)
	require.NoError(t, err)
	heldCID, err := rawCID(heldEvidence.Control)
	require.NoError(t, err)
	supplied := fixture.evidence(t, 1, heldCID)
	suppliedControl, err := DecodeControl(supplied.Control)
	require.NoError(t, err)
	_, _, err = verifyControlEvidence(fixture.vaultID, fixture.anchor, supplied)
	require.NoError(t, err)
	result, compareErr := compareAuthenticatedControls(suppliedControl, heldCID, &heldControl, heldCID, nil)
	require.NoError(t, compareErr)
	assert.Equal(t, CheckpointCurrent, result.Outcome)
}

func TestVerifyControlStateLargerEpochWithoutLinkIsNotCurrent(t *testing.T) {
	fixture := newCheckpointFixture(t)
	held := fixture.evidence(t, 0, nil)
	supplied := fixture.evidence(t, 100, nil)
	result := verifyFixture(t, fixture, checkpointHeld(t, fixture, held), supplied)
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

	descendant := verifyFixture(t, fixture, checkpointHeld(t, fixture, genesis), two, one)
	assert.Equal(t, CheckpointDescendant, descendant.Outcome)
	assert.Equal(t, "verified-descendant", descendant.ReasonCode)
	assert.Equal(t, 2, descendant.LinkCount)

	stale := verifyFixture(t, fixture, checkpointHeld(t, fixture, two), genesis, one)
	assert.Equal(t, CheckpointStale, stale.Outcome)
	assert.Equal(t, "verified-stale", stale.ReasonCode)
	assert.Equal(t, 2, stale.LinkCount)
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
	result := verifyFixture(t, fixture, checkpointHeld(t, fixture, genesis), two)
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
	result := verifyFixture(t, fixture, checkpointHeld(t, fixture, chain[0]), chain[9], intermediates...)
	assert.Equal(t, CheckpointUnverifiable, result.Outcome)
	assert.Equal(t, "depth-exceeded", result.ReasonCode)
}

func TestVerifyControlStateInvalidSignatureCannotReachConsent(t *testing.T) {
	fixture := newCheckpointFixture(t)
	supplied := fixture.evidence(t, 0, nil)
	supplied.Control = bytes.Clone(supplied.Control)
	supplied.Control[len(supplied.Control)-1] ^= 0x80
	_, err := VerifyControlState(VerificationRequest{Vault: fixture.vaultID, TrustAnchor: fixture.anchor, Supplied: supplied})
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
	_, err = VerifyControlState(VerificationRequest{
		Vault: fixture.vaultID, TrustAnchor: fixture.anchor, Held: checkpointHeld(t, fixture, genesis),
		Supplied: two, Intermediates: []ControlEvidence{one},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVerification)
	var refusal *VerificationRefusal
	require.True(t, errors.As(err, &refusal))
	assert.Equal(t, "invalid-intermediate", refusal.Code)
}
