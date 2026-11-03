package vault

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type RetentionRecoveryPoint struct {
	Epoch       uint64
	SnapshotCID []byte
}

type RetentionDeclaration struct {
	Vault          [32]byte
	DeviceID       string
	PolicyDigest   [32]byte
	RetentionFloor uint64
	RecoveryPoints []RetentionRecoveryPoint
}

type RetentionDeclarationRequest struct {
	VaultID        [32]byte
	TrustAnchor    [32]byte
	State          ControlEvidence
	DeviceID       string
	RetentionFloor uint64
	RecoveryPoints []RetentionRecoveryPoint
}

type RetentionDeclarationJudgement struct {
	Declaration                   RetentionDeclaration
	Status                        AttestationStatus
	CompromisedForConfidentiality bool
}

func EvaluateRetentionDeclaration(request RetentionDeclarationRequest) (RetentionDeclarationJudgement, error) {
	if request.DeviceID == "" || len(request.DeviceID) > MaxDeviceIDBytes || strings.IndexByte(request.DeviceID, 0) >= 0 ||
		request.RetentionFloor > uint64(^uint64(0)>>1) || len(request.RecoveryPoints) > int(^uint16(0)) {
		return RetentionDeclarationJudgement{}, errors.New("invalid retention declaration")
	}
	position, _, err := verifyControlPositionEvidence(request.VaultID, request.TrustAnchor, request.State)
	if err != nil {
		return RetentionDeclarationJudgement{}, err
	}
	declaration := RetentionDeclaration{
		Vault: position.policy.Vault, DeviceID: request.DeviceID, PolicyDigest: position.policyDigest,
		RetentionFloor: request.RetentionFloor, RecoveryPoints: make([]RetentionRecoveryPoint, len(request.RecoveryPoints)),
	}
	for index, point := range request.RecoveryPoints {
		if point.Epoch > uint64(^uint64(0)>>1) || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > MaxParentBytes {
			return RetentionDeclarationJudgement{}, fmt.Errorf("invalid retention recovery point")
		}
		declaration.RecoveryPoints[index] = RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)}
	}
	sort.Slice(declaration.RecoveryPoints, func(i, j int) bool {
		if declaration.RecoveryPoints[i].Epoch != declaration.RecoveryPoints[j].Epoch {
			return declaration.RecoveryPoints[i].Epoch < declaration.RecoveryPoints[j].Epoch
		}
		return bytes.Compare(declaration.RecoveryPoints[i].SnapshotCID, declaration.RecoveryPoints[j].SnapshotCID) < 0
	})
	for index := 1; index < len(declaration.RecoveryPoints); index++ {
		previous, current := declaration.RecoveryPoints[index-1], declaration.RecoveryPoints[index]
		if current.Epoch == previous.Epoch && bytes.Equal(current.SnapshotCID, previous.SnapshotCID) {
			return RetentionDeclarationJudgement{}, fmt.Errorf("duplicate retention recovery point")
		}
	}
	judgement := RetentionDeclarationJudgement{Declaration: declaration, Status: AttestationStatusMeetsPolicy}
	if request.RetentionFloor < position.policy.PolicyRetentionFloor {
		judgement.Status = AttestationStatusBelowPolicyFloor
		judgement.CompromisedForConfidentiality = true
	}
	return judgement, nil
}
