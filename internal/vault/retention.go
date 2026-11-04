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

func retentionRecoveryPointLess(left, right RetentionRecoveryPoint) bool {
	if left.Epoch != right.Epoch {
		return left.Epoch < right.Epoch
	}
	return bytes.Compare(left.SnapshotCID, right.SnapshotCID) < 0
}

func normalizeRetentionRecoveryPoints(points []RetentionRecoveryPoint) ([]RetentionRecoveryPoint, error) {
	if len(points) > int(^uint16(0)) {
		return nil, fmt.Errorf("invalid retention recovery point count")
	}
	result := make([]RetentionRecoveryPoint, len(points))
	for index, point := range points {
		if point.Epoch > MaxAttestationInteger || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > MaxParentBytes {
			return nil, fmt.Errorf("invalid retention recovery point")
		}
		result[index] = RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)}
	}
	sort.Slice(result, func(i, j int) bool { return retentionRecoveryPointLess(result[i], result[j]) })
	for index := 1; index < len(result); index++ {
		if !retentionRecoveryPointLess(result[index-1], result[index]) {
			return nil, fmt.Errorf("duplicate retention recovery point")
		}
	}
	return result, nil
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
		request.RetentionFloor > MaxAttestationInteger || len(request.RecoveryPoints) > int(^uint16(0)) {
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
	declaration.RecoveryPoints, err = normalizeRetentionRecoveryPoints(request.RecoveryPoints)
	if err != nil {
		return RetentionDeclarationJudgement{}, err
	}
	for _, point := range declaration.RecoveryPoints {
		if point.Epoch > position.control.EpochSeq {
			return RetentionDeclarationJudgement{}, fmt.Errorf("recovery point epoch is newer than the attested control")
		}
	}
	judgement := RetentionDeclarationJudgement{Declaration: declaration, Status: AttestationStatusMeetsPolicy}
	if request.RetentionFloor < position.policy.PolicyRetentionFloor {
		judgement.Status = AttestationStatusBelowPolicyFloor
		judgement.CompromisedForConfidentiality = true
	}
	return judgement, nil
}
