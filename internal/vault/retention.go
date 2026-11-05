package vault

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type RetentionRecoveryPoint struct {
	Epoch        uint64
	SnapshotCID  []byte
	PolicyDigest [32]byte
	ControlCID   []byte
}

type RetentionRecoveryPointEvidence struct {
	Point              RetentionRecoveryPoint
	Position           ControlEvidence
	Intermediates      []ControlEvidence
	EpochStartHead     []byte
	EpochStartSnapshot []byte
	Head               []byte
	Ciphertext         []byte
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
		result[index] = RetentionRecoveryPoint{
			Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID),
			PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID),
		}
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
	VaultID              [32]byte
	TrustAnchor          [32]byte
	State                ControlEvidence
	DeviceID             string
	RetentionFloor       uint64
	RecoveryPoints       []RetentionRecoveryPoint
	PointEvidence        []RetentionRecoveryPointEvidence
	UnknownEpochMaterial bool
}

type RetentionDeclarationJudgement struct {
	Declaration                   RetentionDeclaration
	Status                        AttestationStatus
	CompromisedForConfidentiality bool
}

func EvaluateRetentionDeclaration(request RetentionDeclarationRequest) (RetentionDeclarationJudgement, error) {
	if request.DeviceID == "" || len(request.DeviceID) > MaxDeviceIDBytes || strings.IndexByte(request.DeviceID, 0) >= 0 ||
		request.RetentionFloor > MaxAttestationInteger || len(request.RecoveryPoints) == 0 || len(request.RecoveryPoints) > int(^uint16(0)) || len(request.PointEvidence) != len(request.RecoveryPoints) {
		return RetentionDeclarationJudgement{}, errors.New("invalid retention declaration")
	}
	held, heldControlCID, err := verifyControlPositionEvidence(request.VaultID, request.TrustAnchor, request.State)
	if err != nil {
		return RetentionDeclarationJudgement{}, err
	}
	trusted := NewTrustedContext(request.VaultID, request.TrustAnchor)
	if err := trusted.SetHeldCheckpoint(request.State); err != nil {
		return RetentionDeclarationJudgement{}, err
	}
	declarationFloor := request.RetentionFloor
	if request.UnknownEpochMaterial {
		declarationFloor = 0
	}
	declaration := RetentionDeclaration{
		Vault: held.policy.Vault, DeviceID: request.DeviceID, PolicyDigest: held.policyDigest,
		RetentionFloor: declarationFloor,
	}
	declaration.RecoveryPoints, err = normalizeRetentionRecoveryPoints(request.RecoveryPoints)
	if err != nil {
		return RetentionDeclarationJudgement{}, err
	}
	boundary := RetentionRecoveryPoint{
		Epoch: held.control.EpochSeq, SnapshotCID: held.control.HeadSnapshotCID,
		PolicyDigest: held.policyDigest, ControlCID: heldControlCID,
	}
	boundaryFound := false
	for _, point := range declaration.RecoveryPoints {
		if sameRetentionPoint(point, boundary) {
			boundaryFound = true
			break
		}
	}
	if !boundaryFound {
		return RetentionDeclarationJudgement{}, errors.New("retention boundary does not match the held checkpoint position")
	}
	for _, point := range declaration.RecoveryPoints {
		if point.PolicyDigest == ([32]byte{}) || len(point.ControlCID) == 0 || len(point.ControlCID) > MaxParentBytes {
			return RetentionDeclarationJudgement{}, errors.New("retention recovery point has incomplete or future position binding")
		}
	}
	byIdentity := make(map[string]RetentionRecoveryPointEvidence, len(request.PointEvidence))
	for _, evidence := range request.PointEvidence {
		identity := retentionPointEvidenceIdentity(evidence.Point)
		if _, exists := byIdentity[identity]; exists {
			return RetentionDeclarationJudgement{}, errors.New("duplicate retention recovery point evidence")
		}
		byIdentity[identity] = evidence
	}
	for _, point := range declaration.RecoveryPoints {
		evidence, exists := byIdentity[retentionPointEvidenceIdentity(point)]
		if !exists || !sameRetentionPoint(point, evidence.Point) {
			return RetentionDeclarationJudgement{}, errors.New("retention recovery point evidence does not match its declaration")
		}
		if err := verifyRetentionPointEvidence(trusted, point, evidence); err != nil {
			return RetentionDeclarationJudgement{}, err
		}
	}
	judgement := RetentionDeclarationJudgement{Declaration: declaration, Status: AttestationStatusMeetsPolicy}
	if request.UnknownEpochMaterial || declaration.RetentionFloor < held.policy.PolicyRetentionFloor {
		judgement.Status = AttestationStatusBelowPolicyFloor
		judgement.CompromisedForConfidentiality = true
	}
	return judgement, nil
}

func verifyRetentionPointEvidence(trusted *TrustedContext, point RetentionRecoveryPoint, evidence RetentionRecoveryPointEvidence) error {
	position, controlCID, err := verifyControlPositionEvidence(trusted.vault, trusted.anchor, evidence.Position)
	if err != nil {
		return err
	}
	if position.policyDigest != point.PolicyDigest || !bytes.Equal(controlCID, point.ControlCID) || position.control.EpochSeq != point.Epoch {
		return errors.New("retention recovery point does not match its authenticated control position")
	}
	result, err := VerifyControlState(trusted, VerificationRequest{Supplied: evidence.Position, Intermediates: evidence.Intermediates})
	if err != nil {
		return err
	}
	if result.Outcome != CheckpointCurrent && result.Outcome != CheckpointDescendant {
		return fmt.Errorf("retention point control outcome %q is not current or descendant", result.Outcome)
	}
	startHead, startEnvelope, startSigner, err := verifyRetentionSnapshotPosition(position, trusted.anchor, evidence.Position.Certificates, evidence.EpochStartHead, evidence.EpochStartSnapshot, true)
	if err != nil {
		return fmt.Errorf("authenticate epoch-start snapshot for retention control: %w", err)
	}
	if !bytes.Equal(startHead.SnapshotCID, position.control.HeadSnapshotCID) || !bytes.Equal(startHead.SnapshotCID, startHead.BlobCID) || !bytes.Equal(startEnvelope.Parent, startHead.PrevHeadCID) || startSigner.DeviceID != startHead.Signer.DeviceID {
		return errors.New("retention epoch-start snapshot does not match its control")
	}
	if bytes.Equal(point.SnapshotCID, position.control.HeadSnapshotCID) {
		if len(evidence.Head) != 0 || len(evidence.Ciphertext) != 0 {
			return errors.New("epoch-start recovery point supplies a second snapshot body")
		}
		return nil
	}
	if len(evidence.Head) == 0 || len(evidence.Ciphertext) == 0 {
		return errors.New("ordinary-publication recovery point requires its signed head and exact envelope")
	}
	head, envelope, _, err := verifyRetentionSnapshotPosition(position, trusted.anchor, evidence.Position.Certificates, evidence.Head, evidence.Ciphertext, false)
	if err != nil {
		return err
	}
	if head.PublicationCount == 0 || head.EpochSeq != point.Epoch || head.PolicyDigest != point.PolicyDigest ||
		!bytes.Equal(head.SnapshotCID, point.SnapshotCID) || !bytes.Equal(head.BlobCID, point.SnapshotCID) ||
		!bytes.Equal(envelope.Parent, head.PrevHeadCID) {
		return errors.New("ordinary-publication recovery point head and envelope do not match")
	}
	return nil
}

func verifyRetentionSnapshotPosition(position authenticatedControlPosition, trustAnchor [32]byte, certificates [][]byte, headBytes, envelopeBytes []byte, epochStart bool) (Head, Envelope, Certificate, error) {
	var emptyHead Head
	var emptyEnvelope Envelope
	var emptyCertificate Certificate
	head, err := DecodeHead(headBytes)
	if err != nil {
		return emptyHead, emptyEnvelope, emptyCertificate, err
	}
	envelope, err := DecodeEnvelope(envelopeBytes)
	if err != nil {
		return emptyHead, emptyEnvelope, emptyCertificate, err
	}
	if head.Vault != position.policy.Vault || head.EpochSeq != position.control.EpochSeq || head.PolicyDigest != position.policyDigest ||
		envelope.Vault != position.policy.Vault || envelope.EpochSeq != position.control.EpochSeq || envelope.PolicyDigest != position.policyDigest || envelope.Purpose != PurposeSnapshot ||
		!bytes.Equal(head.SnapshotCID, rawCIDBytes(envelopeBytes)) || !bytes.Equal(head.BlobCID, head.SnapshotCID) {
		return emptyHead, emptyEnvelope, emptyCertificate, errors.New("retention head and envelope context does not match its control position")
	}
	if epochStart && head.PublicationCount != 0 || !epochStart && head.PublicationCount == 0 {
		return emptyHead, emptyEnvelope, emptyCertificate, errors.New("retention head publication count has the wrong position kind")
	}
	if !epochStart && head.PublicationCount > uint64(position.policy.MaxPublications) {
		return emptyHead, emptyEnvelope, emptyCertificate, fmt.Errorf("%w: retention publication count exceeds policy maximum", ErrAuthorization)
	}
	if head.Signer.DeviceID != envelope.DeviceID || !bytes.Equal(head.Signer.KeyID, envelope.KeyID) {
		return emptyHead, emptyEnvelope, emptyCertificate, fmt.Errorf("%w: retention head and envelope signer mismatch", ErrAuthorization)
	}
	if !envelopeRecipientKeyIDsMatchPolicy(envelope.Recipients, position.policy) {
		return emptyHead, emptyEnvelope, emptyCertificate, fmt.Errorf("%w: retention envelope recipient set", ErrRecipient)
	}
	request := OpenRequest{Vault: position.policy.Vault, EpochSeq: position.control.EpochSeq, PolicyDigest: position.policyDigest, TrustAnchor: trustAnchor, Certificates: certificates}
	envelopeSigner, err := authorizedSigner(envelope, request, position.policy)
	if err != nil || signerRevoked(envelopeSigner, position.control) {
		return emptyHead, emptyEnvelope, emptyCertificate, fmt.Errorf("retention snapshot signer is not authorized: %w", ErrAuthorization)
	}
	if len(headBytes) < len(head.Signature) || Verify("dottie/v1/sig-head", objectSignaturePreimage(headBytes[:len(headBytes)-len(head.Signature)]), head.Signature[:], envelopeSigner.SigningPublicKey[:]) != nil {
		return emptyHead, emptyEnvelope, emptyCertificate, fmt.Errorf("retention head signature: %w", ErrSignature)
	}
	if len(envelopeBytes) < len(envelope.Signature) || Verify("dottie/v1/sig-snapshot", objectSignaturePreimage(envelopeBytes[:len(envelopeBytes)-len(envelope.Signature)]), envelope.Signature[:], envelopeSigner.SigningPublicKey[:]) != nil {
		return emptyHead, emptyEnvelope, emptyCertificate, fmt.Errorf("retention envelope signature: %w", ErrSignature)
	}
	return head, envelope, envelopeSigner, nil
}

func sameRetentionPoint(left, right RetentionRecoveryPoint) bool {
	return left.Epoch == right.Epoch && left.PolicyDigest == right.PolicyDigest && bytes.Equal(left.SnapshotCID, right.SnapshotCID) && bytes.Equal(left.ControlCID, right.ControlCID)
}

func retentionPointEvidenceIdentity(point RetentionRecoveryPoint) string {
	buffer := bytes.NewBuffer(nil)
	var encoded [8]byte
	for shift := 56; shift >= 0; shift -= 8 {
		encoded[7-shift/8] = byte(point.Epoch >> shift)
	}
	buffer.Write(encoded[:])
	writeLengthDelimited(buffer, point.SnapshotCID)
	buffer.Write(point.PolicyDigest[:])
	writeLengthDelimited(buffer, point.ControlCID)
	return buffer.String()
}

func writeLengthDelimited(buffer *bytes.Buffer, value []byte) {
	var encoded [8]byte
	length := uint64(len(value))
	for index := 7; index >= 0; index-- {
		encoded[index] = byte(length)
		length >>= 8
	}
	buffer.Write(encoded[:])
	buffer.Write(value)
}

func rawCIDBytes(data []byte) []byte {
	cid, err := rawCID(data)
	if err != nil {
		return nil
	}
	return cid
}
