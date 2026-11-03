package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyControlPositionEvidenceRequiresPolicySignerRoleBinding(t *testing.T) {
	fixture := newCheckpointFixture(t)
	policy, err := DecodePolicy(fixture.genesisPolicy)
	require.NoError(t, err)
	policy.Roles = nil
	policyBytes := signPolicyValue(t, policy, fixture.root.Signing)
	evidence := fixture.evidenceWithPolicy(t, 0, nil, policyBytes)

	_, _, err = verifyControlPositionEvidence(fixture.vaultID, fixture.anchor, evidence)
	require.Error(t, err)
	var refusal *VerificationRefusal
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "policy-signer-role", refusal.Code)
}
