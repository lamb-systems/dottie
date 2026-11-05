package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvaluateRetentionDeclarationRejectsDuplicateRecoveryPoints(t *testing.T) {
	fixture := newRetentionDeclarationFixture(t)
	_, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
		VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
		DeviceID: "device-restore", RetentionFloor: 4,
		RecoveryPoints: []RetentionRecoveryPoint{fixture.point, fixture.point},
		PointEvidence:  []RetentionRecoveryPointEvidence{fixture.pointEvidence, fixture.pointEvidence},
	})
	assert.ErrorContains(t, err, "duplicate retention recovery point")
}

func TestEvaluateRetentionDeclarationRejectsFloorAboveSignedRange(t *testing.T) {
	fixture := newRetentionDeclarationFixture(t)
	_, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
		VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
		DeviceID: "device-restore", RetentionFloor: uint64(1) << 63,
		RecoveryPoints: []RetentionRecoveryPoint{fixture.point},
		PointEvidence:  []RetentionRecoveryPointEvidence{fixture.pointEvidence},
	})
	assert.Error(t, err)
}
