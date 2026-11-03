package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateRetentionDeclarationReportsPolicyFloor(t *testing.T) {
	for _, test := range []struct {
		name        string
		floor       uint64
		pointEpoch  uint64
		status      AttestationStatus
		compromised bool
	}{
		{name: "above", floor: 3, pointEpoch: 3, status: AttestationStatusMeetsPolicy},
		{name: "at", floor: 2, pointEpoch: 2, status: AttestationStatusMeetsPolicy},
		{name: "below", floor: 1, pointEpoch: 1, status: AttestationStatusBelowPolicyFloor, compromised: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAttestationFixture(t)
			result, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
				VaultID: fixture.request.VaultID, TrustAnchor: fixture.request.TrustAnchor, State: fixture.request.State,
				DeviceID: "device-restore", RetentionFloor: test.floor,
				RecoveryPoints: []RetentionRecoveryPoint{{Epoch: test.pointEpoch, SnapshotCID: []byte("snapshot-cid")}},
			})
			require.NoError(t, err)
			assert.Equal(t, test.status, result.Status)
			assert.Equal(t, test.compromised, result.CompromisedForConfidentiality)
			assert.Equal(t, test.floor, result.Declaration.RetentionFloor)
			assert.Equal(t, "device-restore", result.Declaration.DeviceID)
			assert.Equal(t, [32]byte(fixture.request.VaultID), result.Declaration.Vault)
			assert.Equal(t, RetentionRecoveryPoint{Epoch: test.pointEpoch, SnapshotCID: []byte("snapshot-cid")}, result.Declaration.RecoveryPoints[0])
		})
	}
}

func TestEvaluateRetentionDeclarationRequiresAuthenticatedPolicyControl(t *testing.T) {
	fixture := newAttestationFixture(t)
	request := RetentionDeclarationRequest{
		VaultID: fixture.request.VaultID, TrustAnchor: fixture.request.TrustAnchor, State: fixture.request.State,
		DeviceID: "device-restore", RetentionFloor: 2,
	}
	request.State.Control = append([]byte(nil), request.State.Control...)
	request.State.Control[len(request.State.Control)-1] ^= 0x80
	_, err := EvaluateRetentionDeclaration(request)
	assert.ErrorIs(t, err, ErrInvalidVerification)
}
