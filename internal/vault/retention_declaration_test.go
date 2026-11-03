package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvaluateRetentionDeclarationRejectsDuplicateRecoveryPoints(t *testing.T) {
	fixture := newAttestationFixture(t)
	point := RetentionRecoveryPoint{Epoch: 4, SnapshotCID: []byte("snapshot-four")}
	_, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
		VaultID: fixture.request.VaultID, TrustAnchor: fixture.request.TrustAnchor, State: fixture.request.State,
		DeviceID: "device-restore", RetentionFloor: 4,
		RecoveryPoints: []RetentionRecoveryPoint{point, point},
	})
	assert.ErrorContains(t, err, "duplicate retention recovery point")
}

func TestEvaluateRetentionDeclarationRejectsFloorAboveSignedRange(t *testing.T) {
	fixture := newAttestationFixture(t)
	_, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
		VaultID: fixture.request.VaultID, TrustAnchor: fixture.request.TrustAnchor, State: fixture.request.State,
		DeviceID: "device-restore", RetentionFloor: uint64(1) << 63,
		RecoveryPoints: []RetentionRecoveryPoint{{Epoch: 4, SnapshotCID: []byte("snapshot-four")}},
	})
	assert.Error(t, err)
}
