package vault

import (
	"bytes"
	"errors"
	"fmt"
)

type CheckpointOutcome string

const (
	CheckpointCurrent          CheckpointOutcome = "current"
	CheckpointDescendant       CheckpointOutcome = "descendant"
	CheckpointStale            CheckpointOutcome = "stale"
	CheckpointConflicting      CheckpointOutcome = "conflicting"
	CheckpointUnverifiable     CheckpointOutcome = "unverifiable"
	MaxCheckpointWalkDepth                       = 8
	MaxCheckpointIntermediates                   = 4096
)

var (
	ErrConsentRequired     = errors.New("explicit consent is required for unverifiable state")
	ErrConsentNotOffered   = errors.New("consent is available only for unverifiable state")
	ErrInvalidVerification = errors.New("verification evidence is invalid")
)

type CheckpointIntermediatesLimitError struct {
	Limit    int
	Observed int
}

func (err *CheckpointIntermediatesLimitError) Error() string {
	return fmt.Sprintf("%v: checkpoint intermediates observed %d exceeds limit %d", ErrLimit, err.Observed, err.Limit)
}

func (err *CheckpointIntermediatesLimitError) Unwrap() error {
	return ErrLimit
}

type ControlEvidence struct {
	Control      []byte
	Policy       []byte
	Certificates [][]byte
}

type TrustedContext struct {
	vault       [32]byte
	anchor      [32]byte
	held        *ControlEvidence
	initialized bool
}

type VerificationRequest struct {
	Supplied      ControlEvidence
	Intermediates []ControlEvidence
}

type authenticatedControlPosition struct {
	control      Control
	policy       Policy
	policyDigest [32]byte
}

func NewTrustedContext(vaultID, trustAnchor [32]byte) *TrustedContext {
	return &TrustedContext{vault: vaultID, anchor: trustAnchor, initialized: true}
}

func (context *TrustedContext) SetHeldCheckpoint(evidence ControlEvidence) error {
	if context == nil || !context.initialized {
		return &VerificationRefusal{Side: "context", Code: "missing-trusted-context", Err: ErrAuthorization}
	}
	context.held = &ControlEvidence{
		Control:      bytes.Clone(evidence.Control),
		Policy:       bytes.Clone(evidence.Policy),
		Certificates: cloneByteSlices(evidence.Certificates),
	}
	return nil
}

type VerificationResult struct {
	Outcome          CheckpointOutcome
	ReasonCode       string
	Reason           string
	NewerControlCID  []byte
	NeededControlCID []byte
	LinkCount        int
	ConsentAvailable bool
	ConsentRecorded  bool
	validityPassed   bool
	proof            *verificationProof
}

type verificationProof struct {
	outcome          CheckpointOutcome
	consentAvailable bool
	validityPassed   bool
}

type VerificationRefusal struct {
	Side  string
	Code  string
	Check string
	CID   []byte
	Err   error
}

func (r *VerificationRefusal) Error() string {
	if len(r.CID) > 0 {
		return fmt.Sprintf("%v: %s %s at %x", ErrInvalidVerification, r.Side, r.Code, r.CID)
	}
	return fmt.Sprintf("%v: %s %s", ErrInvalidVerification, r.Side, r.Code)
}

func (r *VerificationRefusal) Unwrap() []error {
	return []error{ErrInvalidVerification, r.Err}
}

func verifyControlEvidence(vaultID, trustAnchor [32]byte, evidence ControlEvidence) (Control, []byte, error) {
	position, controlCID, err := verifyControlPositionEvidence(vaultID, trustAnchor, evidence)
	return position.control, controlCID, err
}

func verifyControlPositionEvidence(vaultID, trustAnchor [32]byte, evidence ControlEvidence) (authenticatedControlPosition, []byte, error) {
	control, err := DecodeControl(evidence.Control)
	if err != nil {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "decode-control", Err: err}
	}
	if control.Vault != vaultID {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "wrong-vault", Err: ErrAuthorization}
	}
	policy, err := DecodePolicy(evidence.Policy)
	if err != nil {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "policy", Code: "decode-policy", Err: err}
	}
	if policy.Vault != vaultID || policy.EpochSeq != control.EpochSeq {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-vault-or-epoch", Err: ErrAuthorization}
	}
	policyDigest, err := ComputePolicyDigest(evidence.Policy)
	if err != nil || policyDigest != control.PolicyDigest {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-digest", Err: ErrAuthorization}
	}
	request := OpenRequest{Vault: vaultID, EpochSeq: control.EpochSeq, PolicyDigest: policyDigest, TrustAnchor: trustAnchor, Certificates: evidence.Certificates}
	policySigner, err := resolveTrustedCertificate(policy.Signer.DeviceID, policy.Signer.KeyID, request)
	if err != nil || policySigner.Role != RoleRoot {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-signer-chain", Err: ErrAuthorization}
	}
	policyPrefix, err := encodePolicyPrefix(policy)
	if err != nil {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-encoding", Err: err}
	}
	if err := Verify("dottie/v1/sig-policy", objectSignaturePreimage(policyPrefix), policy.Signature[:], policySigner.SigningPublicKey[:]); err != nil {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-signature", Err: err}
	}
	policySignerRole, policySignerRoleExists := policyRole(policy, policySigner.DeviceID)
	if !policySignerRoleExists || policySignerRole != policySigner.Role {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-signer-role", Err: ErrAuthorization}
	}
	if policy.Signer.DeviceID != control.Signer.DeviceID || !bytes.Equal(policy.Signer.KeyID, control.Signer.KeyID) {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "signer-mismatch", Err: ErrAuthorization}
	}
	controlSigner, err := resolveTrustedCertificate(control.Signer.DeviceID, control.Signer.KeyID, request)
	if err != nil || controlSigner.Role != RoleRoot {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "control-signer-chain", Err: ErrAuthorization}
	}
	controlPrefix, err := encodeControlPrefix(control)
	if err != nil {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "control-encoding", Err: err}
	}
	if err := Verify("dottie/v1/sig-control", objectSignaturePreimage(controlPrefix), control.Signature[:], controlSigner.SigningPublicKey[:]); err != nil {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "control-signature", Err: err}
	}
	controlSignerRole, controlSignerRoleExists := policyRole(policy, controlSigner.DeviceID)
	if !controlSignerRoleExists || controlSignerRole != controlSigner.Role {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "control-signer-role", Err: ErrAuthorization}
	}
	controlCID, err := rawCID(evidence.Control)
	if err != nil {
		return authenticatedControlPosition{}, nil, &VerificationRefusal{Side: "control", Code: "control-cid", Err: err}
	}
	return authenticatedControlPosition{control: control, policy: policy, policyDigest: policyDigest}, controlCID, nil
}

func authenticateVerificationPositions(context *TrustedContext, request VerificationRequest) (authenticatedControlPosition, []byte, *authenticatedControlPosition, []byte, error) {
	if context == nil || !context.initialized {
		return authenticatedControlPosition{}, nil, nil, nil, &VerificationRefusal{Side: "context", Code: "missing-trusted-context", Err: ErrAuthorization}
	}
	supplied, suppliedCID, err := verifyControlPositionEvidence(context.vault, context.anchor, request.Supplied)
	if err != nil {
		return authenticatedControlPosition{}, nil, nil, nil, refusalForSide(err, "supplied")
	}
	var heldPosition *authenticatedControlPosition
	var heldCID []byte
	if context.held != nil {
		decoded, computedCID, verifyErr := verifyControlPositionEvidence(context.vault, context.anchor, *context.held)
		if verifyErr != nil {
			return authenticatedControlPosition{}, nil, nil, nil, refusalForSide(verifyErr, "held")
		}
		heldPosition = &decoded
		heldCID = computedCID
	}
	return supplied, suppliedCID, heldPosition, heldCID, nil
}

func authenticateCheckpointIntermediates(context *TrustedContext, evidenceSet []ControlEvidence) (map[string]authenticatedControlPosition, error) {
	intermediates := make(map[string]authenticatedControlPosition, len(evidenceSet))
	for _, evidence := range evidenceSet {
		position, controlCID, err := verifyControlPositionEvidence(context.vault, context.anchor, evidence)
		if err != nil {
			return nil, refusalForSide(err, "intermediate", evidence.Control)
		}
		key := string(controlCID)
		if existing, ok := intermediates[key]; ok {
			if !bytes.Equal(existing.control.Signature[:], position.control.Signature[:]) {
				return nil, &VerificationRefusal{Side: "intermediate", Code: "cid-collision", CID: controlCID, Err: ErrAuthorization}
			}
			continue
		}
		intermediates[key] = position
	}
	return intermediates, nil
}

func refusalForSide(err error, side string, encoded ...[]byte) error {
	var refusal *VerificationRefusal
	if errors.As(err, &refusal) {
		copyOf := *refusal
		copyOf.Side = side
		if side == "intermediate" {
			copyOf.Check = copyOf.Code
			copyOf.Code = "invalid-intermediate"
			if len(copyOf.CID) == 0 && len(encoded) > 0 {
				copyOf.CID, _ = rawCID(encoded[0])
			}
		}
		return &copyOf
	}
	return &VerificationRefusal{Side: side, Code: "invalid-evidence", Err: err}
}

func compareDirectAuthenticatedControls(supplied authenticatedControlPosition, suppliedCID []byte, held *authenticatedControlPosition, heldCID []byte) (VerificationResult, bool, error) {
	if held == nil {
		return unverifiableResult("no-checkpoint", "no checkpoint is held locally", nil, 0), true, nil
	}
	if bytes.Equal(suppliedCID, heldCID) {
		return VerificationResult{Outcome: CheckpointCurrent, ReasonCode: "same-control", Reason: "the supplied control matches the held checkpoint", NewerControlCID: bytes.Clone(heldCID), validityPassed: true}, true, nil
	}
	if bytes.Equal(supplied.control.PrevControlCID, heldCID) {
		if err := checkMirroredControlEdge(*held, supplied, "supplied", suppliedCID); err != nil {
			return VerificationResult{}, true, err
		}
		return VerificationResult{Outcome: CheckpointDescendant, ReasonCode: "direct-descendant", Reason: "the supplied control directly names the held control as its predecessor", NewerControlCID: bytes.Clone(suppliedCID), LinkCount: 1, validityPassed: true}, true, nil
	}
	if bytes.Equal(held.control.PrevControlCID, suppliedCID) {
		if err := checkMirroredControlEdge(supplied, *held, "held", heldCID); err != nil {
			return VerificationResult{}, true, err
		}
		return VerificationResult{Outcome: CheckpointStale, ReasonCode: "direct-stale", Reason: "the held control directly names the supplied control as its predecessor", NewerControlCID: bytes.Clone(heldCID), LinkCount: 1, validityPassed: true}, true, nil
	}
	return VerificationResult{}, false, nil
}

func compareAuthenticatedControls(supplied authenticatedControlPosition, suppliedCID []byte, held *authenticatedControlPosition, heldCID []byte, intermediates map[string]authenticatedControlPosition) (VerificationResult, error) {
	if directResult, direct, err := compareDirectAuthenticatedControls(supplied, suppliedCID, held, heldCID); direct || err != nil {
		return directResult, err
	}
	suppliedWalk := walkControlHistory(supplied, suppliedCID, held, heldCID, "supplied", intermediates)
	if suppliedWalk.refusal != nil {
		return VerificationResult{}, suppliedWalk.refusal
	}
	if suppliedWalk.reached {
		return VerificationResult{Outcome: CheckpointDescendant, ReasonCode: "verified-descendant", Reason: "the supplied control is a verified descendant of the held checkpoint", NewerControlCID: bytes.Clone(suppliedCID), LinkCount: suppliedWalk.links, validityPassed: true}, nil
	}
	heldWalk := walkControlHistory(*held, heldCID, &supplied, suppliedCID, "held", intermediates)
	if heldWalk.refusal != nil {
		return VerificationResult{}, heldWalk.refusal
	}
	if heldWalk.reached {
		return VerificationResult{Outcome: CheckpointStale, ReasonCode: "verified-stale", Reason: "the supplied control is a verified ancestor of the held checkpoint", NewerControlCID: bytes.Clone(heldCID), LinkCount: heldWalk.links, validityPassed: true}, nil
	}
	if suppliedWalk.incomplete != nil {
		return *suppliedWalk.incomplete, nil
	}
	if heldWalk.incomplete != nil {
		return *heldWalk.incomplete, nil
	}
	return VerificationResult{Outcome: CheckpointConflicting, ReasonCode: "independent-histories", Reason: "both authenticated histories terminate without linking to one another", validityPassed: true}, nil
}

type controlWalk struct {
	reached    bool
	links      int
	incomplete *VerificationResult
	refusal    error
}

func checkMirroredControlEdge(predecessor, successor authenticatedControlPosition, side string, successorCID []byte) error {
	if predecessor.control.EpochSeq == ^uint64(0) || predecessor.control.EpochSeq+1 != successor.control.EpochSeq || successor.policy.PrevPolicyDigest != predecessor.policyDigest {
		if side == "intermediate" {
			return &VerificationRefusal{Side: side, Code: "invalid-intermediate", Check: "policy-ancestry", CID: bytes.Clone(successorCID), Err: ErrAuthorization}
		}
		return &VerificationRefusal{Side: side, Code: "policy-ancestry", CID: bytes.Clone(successorCID), Err: ErrAuthorization}
	}
	return nil
}

func walkControlHistory(start authenticatedControlPosition, startCID []byte, target *authenticatedControlPosition, targetCID []byte, startSide string, intermediates map[string]authenticatedControlPosition) controlWalk {
	current := start
	currentCID := bytes.Clone(startCID)
	currentSide := startSide
	visited := map[string]bool{string(startCID): true}
	visitedPositions := map[string]authenticatedControlPosition{string(startCID): start}
	for links := 0; links < MaxCheckpointWalkDepth; links++ {
		if len(current.control.PrevControlCID) == 0 {
			return controlWalk{links: links}
		}
		nextCID := bytes.Clone(current.control.PrevControlCID)
		if bytes.Equal(nextCID, targetCID) {
			if err := checkMirroredControlEdge(*target, current, currentSide, currentCID); err != nil {
				return controlWalk{refusal: err}
			}
			return controlWalk{reached: true, links: links + 1}
		}
		key := string(nextCID)
		if visited[key] {
			if predecessor, ok := visitedPositions[key]; ok {
				if err := checkMirroredControlEdge(predecessor, current, currentSide, currentCID); err != nil {
					return controlWalk{refusal: err}
				}
			}
			return controlWalk{refusal: &VerificationRefusal{Side: "intermediate", Code: "invalid-intermediate", CID: nextCID, Err: ErrAuthorization}}
		}
		next, ok := intermediates[key]
		if !ok {
			result := unverifiableResult("missing-intermediate", fmt.Sprintf("control history needs locally supplied object %x", nextCID), nextCID, links+1)
			return controlWalk{incomplete: &result}
		}
		if err := checkMirroredControlEdge(next, current, currentSide, currentCID); err != nil {
			return controlWalk{refusal: err}
		}
		visited[key] = true
		visitedPositions[key] = next
		current = next
		currentCID = nextCID
		currentSide = "intermediate"
	}
	if len(current.control.PrevControlCID) == 0 {
		return controlWalk{links: MaxCheckpointWalkDepth}
	}
	result := unverifiableResult("depth-exceeded", "control history exceeds the eight-link verification bound", current.control.PrevControlCID, MaxCheckpointWalkDepth)
	return controlWalk{incomplete: &result}
}

func unverifiableResult(code, reason string, neededCID []byte, links int) VerificationResult {
	return VerificationResult{Outcome: CheckpointUnverifiable, ReasonCode: code, Reason: reason, NeededControlCID: bytes.Clone(neededCID), LinkCount: links, ConsentAvailable: true, validityPassed: true}
}

func compareControlCheckpoints(context *TrustedContext, request VerificationRequest) (VerificationResult, error) {
	if len(request.Intermediates) > MaxCheckpointIntermediates {
		return VerificationResult{}, &CheckpointIntermediatesLimitError{Limit: MaxCheckpointIntermediates, Observed: len(request.Intermediates)}
	}
	supplied, suppliedCID, held, heldCID, err := authenticateVerificationPositions(context, request)
	if err != nil {
		return VerificationResult{}, err
	}
	if directResult, direct, err := compareDirectAuthenticatedControls(supplied, suppliedCID, held, heldCID); direct || err != nil {
		return directResult, err
	}
	intermediates, err := authenticateCheckpointIntermediates(context, request.Intermediates)
	if err != nil {
		return VerificationResult{}, err
	}
	return compareAuthenticatedControls(supplied, suppliedCID, held, heldCID, intermediates)
}

func AcceptUnverifiableConsent(result VerificationResult) (VerificationResult, error) {
	if result.proof == nil || !result.proof.validityPassed || result.proof.outcome != CheckpointUnverifiable || !result.proof.consentAvailable || result.Outcome != result.proof.outcome || !result.ConsentAvailable {
		return VerificationResult{}, ErrConsentNotOffered
	}
	result.ConsentRecorded = true
	return result, nil
}

func RequireUnverifiableConsent(result VerificationResult) error {
	if result.proof == nil || !result.proof.validityPassed || result.proof.outcome != CheckpointUnverifiable || !result.proof.consentAvailable || result.Outcome != result.proof.outcome || !result.ConsentAvailable {
		return ErrConsentNotOffered
	}
	return ErrConsentRequired
}
