package vault

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyControlPositionEvidenceBindsTrustedControlAndPolicyPosition(t *testing.T) {
	fixture := newCheckpointFixture(t)
	baseline := fixture.evidence(t, 0, nil)
	_, _, err := verifyControlPositionEvidence(fixture.vaultID, fixture.anchor, baseline)
	require.NoError(t, err)

	t.Run("control vault", func(t *testing.T) {
		control, err := DecodeControl(baseline.Control)
		require.NoError(t, err)
		control.Vault[0] ^= 1
		altered := baseline
		altered.Control = signControlValue(t, control, fixture.root.Signing)
		assertControlPositionRefusalCode(t, fixture, altered, "wrong-vault")
	})

	t.Run("policy vault", func(t *testing.T) {
		policy, err := DecodePolicy(baseline.Policy)
		require.NoError(t, err)
		policy.Vault[0] ^= 1
		policyBytes := signPolicyValue(t, policy, fixture.root.Signing)
		altered := fixture.evidenceWithPolicy(t, 0, nil, policyBytes)
		assertControlPositionRefusalCode(t, fixture, altered, "policy-vault-or-epoch")
	})

	t.Run("policy epoch", func(t *testing.T) {
		policy, err := DecodePolicy(baseline.Policy)
		require.NoError(t, err)
		policy.EpochSeq++
		policyBytes := signPolicyValue(t, policy, fixture.root.Signing)
		altered := fixture.evidenceWithPolicy(t, 0, nil, policyBytes)
		assertControlPositionRefusalCode(t, fixture, altered, "policy-vault-or-epoch")
	})

	t.Run("policy digest", func(t *testing.T) {
		control, err := DecodeControl(baseline.Control)
		require.NoError(t, err)
		control.PolicyDigest[0] ^= 1
		altered := baseline
		altered.Control = signControlValue(t, control, fixture.root.Signing)
		assertControlPositionRefusalCode(t, fixture, altered, "policy-digest")
	})
}

func TestVerifyControlPositionEvidenceRequiresRootPolicySigner(t *testing.T) {
	fixture := newDevicesFixture(t)
	rootEvidence := ControlEvidence{
		Control: fixture.bootstrap.Control, Policy: fixture.bootstrap.Policy,
		Certificates: [][]byte{fixture.bootstrap.Certificate},
	}
	_, _, err := verifyControlPositionEvidence(fixture.bootstrap.Vault, fixture.bootstrap.Anchor, rootEvidence)
	require.NoError(t, err)

	policy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	policy.Signer = Signer{DeviceID: fixture.newDevice.DeviceID, KeyID: bytes.Clone(fixture.newDevice.KeyID)}
	policyBytes := signPolicyValue(t, policy, fixture.newDevice.Signing)
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	control, err := DecodeControl(fixture.transition.Control)
	require.NoError(t, err)
	control.PolicyDigest = policyDigest
	control.Signer = Signer{DeviceID: fixture.newDevice.DeviceID, KeyID: bytes.Clone(fixture.newDevice.KeyID)}
	evidence := ControlEvidence{
		Control: signControlValue(t, control, fixture.newDevice.Signing), Policy: policyBytes,
		Certificates: cloneByteSlices(fixture.transition.Recipients),
	}

	assertControlPositionRefusalCodeForTrust(t, fixture.bootstrap.Vault, fixture.bootstrap.Anchor, evidence, "policy-signer-chain")
}

func TestVerifyControlPositionEvidenceRequiresMatchingPolicyAndControlSigner(t *testing.T) {
	fixture := newCheckpointFixture(t)
	baseline := fixture.evidence(t, 0, nil)
	_, _, err := verifyControlPositionEvidence(fixture.vaultID, fixture.anchor, baseline)
	require.NoError(t, err)

	for _, check := range []struct {
		name   string
		mutate func(*Control)
	}{
		{
			name: "device ID",
			mutate: func(control *Control) {
				control.Signer.DeviceID = "other-root"
			},
		},
		{
			name: "key ID",
			mutate: func(control *Control) {
				control.Signer.KeyID = []byte("other-root-key")
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			control, err := DecodeControl(baseline.Control)
			require.NoError(t, err)
			check.mutate(&control)
			controlBytes, err := EncodeControl(control)
			require.NoError(t, err)
			altered := baseline
			altered.Control = controlBytes
			assertControlPositionRefusalCode(t, fixture, altered, "signer-mismatch")
		})
	}
}

func assertControlPositionRefusalCode(t *testing.T, fixture checkpointFixture, evidence ControlEvidence, code string) {
	t.Helper()
	assertControlPositionRefusalCodeForTrust(t, fixture.vaultID, fixture.anchor, evidence, code)
}

func assertControlPositionRefusalCodeForTrust(t *testing.T, vaultID, anchor [32]byte, evidence ControlEvidence, code string) {
	t.Helper()
	_, _, err := verifyControlPositionEvidence(vaultID, anchor, evidence)
	require.Error(t, err)
	var refusal *VerificationRefusal
	require.True(t, errors.As(err, &refusal))
	assert.Equal(t, code, refusal.Code)
}
