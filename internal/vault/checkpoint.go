package vault

import (
	"bytes"
	"errors"
	"fmt"
)

type CheckpointOutcome string

const (
	CheckpointCurrent      CheckpointOutcome = "current"
	CheckpointDescendant   CheckpointOutcome = "descendant"
	CheckpointStale        CheckpointOutcome = "stale"
	CheckpointConflicting  CheckpointOutcome = "conflicting"
	CheckpointUnverifiable CheckpointOutcome = "unverifiable"
	MaxCheckpointWalkDepth                   = 8
)

var (
	ErrConsentRequired     = errors.New("explicit consent is required for unverifiable state")
	ErrConsentNotOffered   = errors.New("consent is available only for unverifiable state")
	ErrInvalidVerification = errors.New("verification evidence is invalid")
)

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
	control, err := DecodeControl(evidence.Control)
	if err != nil {
		return Control{}, nil, &VerificationRefusal{Side: "control", Code: "decode-control", Err: err}
	}
	if control.Vault != vaultID {
		return Control{}, nil, &VerificationRefusal{Side: "control", Code: "wrong-vault", Err: ErrAuthorization}
	}
	policy, err := DecodePolicy(evidence.Policy)
	if err != nil {
		return Control{}, nil, &VerificationRefusal{Side: "policy", Code: "decode-policy", Err: err}
	}
	if policy.Vault != vaultID || policy.EpochSeq != control.EpochSeq {
		return Control{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-vault-or-epoch", Err: ErrAuthorization}
	}
	policyDigest, err := ComputePolicyDigest(evidence.Policy)
	if err != nil || policyDigest != control.PolicyDigest {
		return Control{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-digest", Err: ErrAuthorization}
	}
	request := OpenRequest{Vault: vaultID, EpochSeq: control.EpochSeq, PolicyDigest: policyDigest, TrustAnchor: trustAnchor, Certificates: evidence.Certificates}
	policySigner, err := resolveTrustedCertificate(policy.Signer.DeviceID, policy.Signer.KeyID, request)
	if err != nil || policySigner.Role != RoleRoot {
		return Control{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-signer-chain", Err: ErrAuthorization}
	}
	policyPrefix, err := encodePolicyPrefix(policy)
	if err != nil {
		return Control{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-encoding", Err: err}
	}
	if err := Verify("dottie/v1/sig-policy", objectSignaturePreimage(policyPrefix), policy.Signature[:], policySigner.SigningPublicKey[:]); err != nil {
		return Control{}, nil, &VerificationRefusal{Side: "policy", Code: "policy-signature", Err: err}
	}
	if policy.Signer.DeviceID != control.Signer.DeviceID || !bytes.Equal(policy.Signer.KeyID, control.Signer.KeyID) {
		return Control{}, nil, &VerificationRefusal{Side: "control", Code: "signer-mismatch", Err: ErrAuthorization}
	}
	controlSigner, err := resolveTrustedCertificate(control.Signer.DeviceID, control.Signer.KeyID, request)
	if err != nil || controlSigner.Role != RoleRoot {
		return Control{}, nil, &VerificationRefusal{Side: "control", Code: "control-signer-chain", Err: ErrAuthorization}
	}
	controlPrefix, err := encodeControlPrefix(control)
	if err != nil {
		return Control{}, nil, &VerificationRefusal{Side: "control", Code: "control-encoding", Err: err}
	}
	if err := Verify("dottie/v1/sig-control", objectSignaturePreimage(controlPrefix), control.Signature[:], controlSigner.SigningPublicKey[:]); err != nil {
		return Control{}, nil, &VerificationRefusal{Side: "control", Code: "control-signature", Err: err}
	}
	controlCID, err := rawCID(evidence.Control)
	if err != nil {
		return Control{}, nil, &VerificationRefusal{Side: "control", Code: "control-cid", Err: err}
	}
	return control, controlCID, nil
}

func authenticateVerificationRequest(context *TrustedContext, request VerificationRequest) (Control, []byte, *Control, []byte, map[string]Control, error) {
	if context == nil || !context.initialized {
		return Control{}, nil, nil, nil, nil, &VerificationRefusal{Side: "context", Code: "missing-trusted-context", Err: ErrAuthorization}
	}
	supplied, suppliedCID, err := verifyControlEvidence(context.vault, context.anchor, request.Supplied)
	if err != nil {
		return Control{}, nil, nil, nil, nil, refusalForSide(err, "supplied")
	}
	var heldControl *Control
	var heldCID []byte
	if context.held != nil {
		decoded, computedCID, verifyErr := verifyControlEvidence(context.vault, context.anchor, *context.held)
		if verifyErr != nil {
			return Control{}, nil, nil, nil, nil, refusalForSide(verifyErr, "held")
		}
		heldControl = &decoded
		heldCID = computedCID
	}
	intermediates := make(map[string]Control, len(request.Intermediates))
	for _, evidence := range request.Intermediates {
		control, controlCID, verifyErr := verifyControlEvidence(context.vault, context.anchor, evidence)
		if verifyErr != nil {
			return Control{}, nil, nil, nil, nil, refusalForSide(verifyErr, "intermediate", evidence.Control)
		}
		key := string(controlCID)
		if existing, ok := intermediates[key]; ok {
			if !bytes.Equal(existing.Signature[:], control.Signature[:]) {
				return Control{}, nil, nil, nil, nil, &VerificationRefusal{Side: "intermediate", Code: "cid-collision", CID: controlCID, Err: ErrAuthorization}
			}
			continue
		}
		intermediates[key] = control
	}
	return supplied, suppliedCID, heldControl, heldCID, intermediates, nil
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

func compareAuthenticatedControls(supplied Control, suppliedCID []byte, held *Control, heldCID []byte, intermediates map[string]Control) (VerificationResult, error) {
	if held == nil {
		return unverifiableResult("no-checkpoint", "no checkpoint is held locally", nil, 0), nil
	}
	if bytes.Equal(suppliedCID, heldCID) {
		return VerificationResult{Outcome: CheckpointCurrent, ReasonCode: "same-control", Reason: "the supplied control matches the held checkpoint", NewerControlCID: bytes.Clone(heldCID), validityPassed: true}, nil
	}
	if bytes.Equal(supplied.PrevControlCID, heldCID) {
		return VerificationResult{Outcome: CheckpointDescendant, ReasonCode: "direct-descendant", Reason: "the supplied control directly names the held control as its predecessor", NewerControlCID: bytes.Clone(suppliedCID), LinkCount: 1, validityPassed: true}, nil
	}
	if bytes.Equal(held.PrevControlCID, suppliedCID) {
		return VerificationResult{Outcome: CheckpointStale, ReasonCode: "direct-stale", Reason: "the held control directly names the supplied control as its predecessor", NewerControlCID: bytes.Clone(heldCID), LinkCount: 1, validityPassed: true}, nil
	}

	suppliedWalk := walkControlHistory(supplied, suppliedCID, heldCID, intermediates)
	if suppliedWalk.refusal != nil {
		return VerificationResult{}, suppliedWalk.refusal
	}
	if suppliedWalk.reached {
		return VerificationResult{Outcome: CheckpointDescendant, ReasonCode: "verified-descendant", Reason: "the supplied control is a verified descendant of the held checkpoint", NewerControlCID: bytes.Clone(suppliedCID), LinkCount: suppliedWalk.links, validityPassed: true}, nil
	}
	heldWalk := walkControlHistory(*held, heldCID, suppliedCID, intermediates)
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

func walkControlHistory(start Control, startCID, targetCID []byte, intermediates map[string]Control) controlWalk {
	current := start
	visited := map[string]bool{string(startCID): true}
	for links := 0; links < MaxCheckpointWalkDepth; links++ {
		if len(current.PrevControlCID) == 0 {
			return controlWalk{links: links}
		}
		nextCID := bytes.Clone(current.PrevControlCID)
		if bytes.Equal(nextCID, targetCID) {
			return controlWalk{reached: true, links: links + 1}
		}
		key := string(nextCID)
		if visited[key] {
			return controlWalk{refusal: &VerificationRefusal{Side: "intermediate", Code: "invalid-intermediate", CID: nextCID, Err: ErrAuthorization}}
		}
		next, ok := intermediates[key]
		if !ok {
			result := unverifiableResult("missing-intermediate", fmt.Sprintf("control history needs locally supplied object %x", nextCID), nextCID, links+1)
			return controlWalk{incomplete: &result}
		}
		visited[key] = true
		current = next
	}
	if len(current.PrevControlCID) == 0 {
		return controlWalk{links: MaxCheckpointWalkDepth}
	}
	result := unverifiableResult("depth-exceeded", "control history exceeds the eight-link verification bound", current.PrevControlCID, MaxCheckpointWalkDepth)
	return controlWalk{incomplete: &result}
}

func unverifiableResult(code, reason string, neededCID []byte, links int) VerificationResult {
	return VerificationResult{Outcome: CheckpointUnverifiable, ReasonCode: code, Reason: reason, NeededControlCID: bytes.Clone(neededCID), LinkCount: links, ConsentAvailable: true, validityPassed: true}
}

func compareControlCheckpoints(context *TrustedContext, request VerificationRequest) (VerificationResult, error) {
	supplied, suppliedCID, held, heldCID, intermediates, err := authenticateVerificationRequest(context, request)
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
