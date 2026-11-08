package publicationstate

import (
	"bytes"
	"errors"
)

type localReviewWire struct {
	SelectionDigest   []byte `json:"selectionDigest"`
	SelectionRevision uint64 `json:"selectionRevision"`
	ApprovalDigest    []byte `json:"approvalDigest"`
	ApprovalRevision  uint64 `json:"approvalRevision"`
}

type attemptCoreWire struct {
	Version                 uint32          `json:"version"`
	AttemptID               []byte          `json:"attemptId"`
	DatabaseID              []byte          `json:"databaseId"`
	Binding                 bindingWire     `json:"binding"`
	Kind                    string          `json:"kind"`
	CapturedFloor           *floorWire      `json:"capturedFloor"`
	CapturedRevision        uint64          `json:"capturedRevision"`
	CapturedGeneration      uint64          `json:"capturedGeneration"`
	PredecessorKey          string          `json:"predecessorKey"`
	PredecessorRecord       []byte          `json:"predecessorRecord"`
	PredecessorCID          []byte          `json:"predecessorCid"`
	SnapshotKey             string          `json:"snapshotKey"`
	SnapshotRecord          []byte          `json:"snapshotRecord"`
	SnapshotCID             []byte          `json:"snapshotCid"`
	HeadRecord              []byte          `json:"headRecord"`
	HeadCID                 []byte          `json:"headCid"`
	BlobCID                 []byte          `json:"blobCid"`
	BlobSize                uint64          `json:"blobSize"`
	InitialContext          contextWire     `json:"initialContext"`
	InitialViewDigest       []byte          `json:"initialViewDigest"`
	Review                  localReviewWire `json:"review"`
	CandidateConfirmation   []byte          `json:"candidateConfirmation"`
	ReservedCompletionBytes uint64          `json:"reservedCompletionBytes"`
}

type attemptStateWire struct {
	Version            uint32 `json:"version"`
	AttemptID          []byte `json:"attemptId"`
	CoreDigest         []byte `json:"coreDigest"`
	Lifecycle          string `json:"lifecycle"`
	Outcome            string `json:"outcome"`
	Blocked            string `json:"blocked"`
	MutationRevision   uint64 `json:"mutationRevision"`
	TerminalEvidence   []byte `json:"terminalEvidence"`
	RetirementEvidence []byte `json:"retirementEvidence"`
}

type attemptEventWire struct {
	Version        uint32 `json:"version"`
	Ordinal        uint32 `json:"ordinal"`
	Kind           string `json:"kind"`
	PreviousDigest []byte `json:"previousDigest"`
	Evidence       []byte `json:"evidence"`
	StateDigest    []byte `json:"stateDigest"`
}

type attemptEvidenceWire struct {
	Version           uint32          `json:"version"`
	Role              string          `json:"role"`
	Scope             string          `json:"scope"`
	ViewDigest        []byte          `json:"viewDigest"`
	Origin            bindingWire     `json:"origin"`
	Context           contextWire     `json:"context"`
	Head              []byte          `json:"head"`
	AttemptedKey      string          `json:"attemptedKey"`
	AttemptedRecord   []byte          `json:"attemptedRecord"`
	PredecessorRecord []byte          `json:"predecessorRecord"`
	Suffix            []SnapshotBlock `json:"suffix"`
	Outcome           string          `json:"outcome"`
}

type firstConflictWire struct {
	Version          uint32              `json:"version"`
	AttemptID        []byte              `json:"attemptId"`
	CoreDigest       []byte              `json:"coreDigest"`
	EventOrdinal     uint32              `json:"eventOrdinal"`
	MutationRevision uint64              `json:"mutationRevision"`
	EventStateDigest []byte              `json:"eventStateDigest"`
	Blocked          string              `json:"blocked"`
	Proof            attemptEvidenceWire `json:"proof"`
}

type attemptTokenWire struct {
	Version             uint32            `json:"version"`
	DatabaseID          []byte            `json:"databaseId"`
	FloorRevision       uint64            `json:"floorRevision"`
	Generation          uint64            `json:"generation"`
	Floor               *floorWire        `json:"floor"`
	MutationRevision    uint64            `json:"mutationRevision"`
	ActiveAttemptID     []byte            `json:"activeAttemptId"`
	ActiveAttemptDigest []byte            `json:"activeAttemptDigest"`
	PositionLimits      limitsWire        `json:"positionLimits"`
	AttemptLimits       attemptLimitsWire `json:"attemptLimits"`
}

type candidateConfirmationWire struct {
	Version         uint32          `json:"version"`
	DatabaseID      []byte          `json:"databaseId"`
	StateToken      []byte          `json:"stateToken"`
	AttemptID       []byte          `json:"attemptId"`
	CandidateDigest []byte          `json:"candidateDigest"`
	ViewDigest      []byte          `json:"viewDigest"`
	Review          localReviewWire `json:"review"`
}

type dispatchConfirmationWire struct {
	Version    uint32          `json:"version"`
	DatabaseID []byte          `json:"databaseId"`
	StateToken []byte          `json:"stateToken"`
	AttemptID  []byte          `json:"attemptId"`
	Kind       string          `json:"kind"`
	ViewDigest []byte          `json:"viewDigest"`
	Review     localReviewWire `json:"review"`
}

type compactViewDigestWire struct {
	Version   uint32          `json:"version"`
	Origin    bindingWire     `json:"origin"`
	Scope     string          `json:"scope"`
	Context   contextWire     `json:"context"`
	Head      []byte          `json:"head"`
	Snapshots []SnapshotBlock `json:"snapshots"`
}

func reviewToWire(review LocalReviewContext) localReviewWire {
	return localReviewWire{SelectionDigest: bytes.Clone(review.SelectionDigest[:]), SelectionRevision: review.SelectionRevision, ApprovalDigest: bytes.Clone(review.ApprovalDigest[:]), ApprovalRevision: review.ApprovalRevision}
}

func makeAttemptCoreDigest(core []byte) [32]byte {
	return domainHash("systems.lamb.dottie.publication-attempt-core.v1", core)
}

func makeAttemptStateDigest(core []byte, lifecycle AttemptLifecycle, outcome AttemptOutcome, blocked string, mutationRevision uint64, terminal, retirement []byte) ([32]byte, error) {
	coreDigest := makeAttemptCoreDigest(core)
	wire := attemptStateWire{Version: 1, CoreDigest: bytes.Clone(coreDigest[:]), Lifecycle: string(lifecycle), Outcome: string(outcome), Blocked: blocked, MutationRevision: mutationRevision, TerminalEvidence: bytes.Clone(terminal), RetirementEvidence: bytes.Clone(retirement)}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.publication-attempt-state.v1", body), nil
}

func makeAttemptToken(databaseID [32]byte, state stateSnapshot, mutationRevision uint64, activeID, activeDigest []byte, positionLimits Limits, limits AttemptLimits) ([32]byte, error) {
	wire := attemptTokenWire{Version: 2, DatabaseID: bytes.Clone(databaseID[:]), FloorRevision: state.revision, Generation: state.generation, MutationRevision: mutationRevision, ActiveAttemptID: bytes.Clone(activeID), ActiveAttemptDigest: bytes.Clone(activeDigest), PositionLimits: limitsToWire(positionLimits), AttemptLimits: attemptLimitsWire{ActiveAttempts: limits.ActiveAttempts, HistoricalAttempts: limits.HistoricalAttempts, RetainedPublications: limits.RetainedPublications, ManagedObjects: limits.ManagedObjects, CustodyBytes: limits.CustodyBytes, MetadataBytes: limits.MetadataBytes, EvidenceBytes: limits.EvidenceBytes, EvidenceSlotBytes: limits.EvidenceSlotBytes, LifecycleEvents: limits.LifecycleEvents, EventBytes: limits.EventBytes, CoreBytes: limits.CoreBytes, HistoryPageEntries: limits.HistoryPageEntries, HistoryPageBytes: limits.HistoryPageBytes}}
	if state.floor != nil {
		floor := floorToWire(*state.floor)
		wire.Floor = &floor
	}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.local-attempt-state.v1", body), nil
}

func makeCandidateConfirmation(databaseID [32]byte, stateToken [32]byte, attemptID [16]byte, candidateDigest, viewDigest [32]byte, review LocalReviewContext) ([32]byte, error) {
	wire := candidateConfirmationWire{Version: 1, DatabaseID: bytes.Clone(databaseID[:]), StateToken: bytes.Clone(stateToken[:]), AttemptID: bytes.Clone(attemptID[:]), CandidateDigest: bytes.Clone(candidateDigest[:]), ViewDigest: bytes.Clone(viewDigest[:]), Review: reviewToWire(review)}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.local-attempt-consent.v1", body), nil
}

func makeDispatchConfirmation(databaseID [32]byte, stateToken [32]byte, attemptID [16]byte, kind DispatchKind, viewDigest [32]byte, review LocalReviewContext) ([32]byte, error) {
	wire := dispatchConfirmationWire{Version: 1, DatabaseID: bytes.Clone(databaseID[:]), StateToken: bytes.Clone(stateToken[:]), AttemptID: bytes.Clone(attemptID[:]), Kind: string(kind), ViewDigest: bytes.Clone(viewDigest[:]), Review: reviewToWire(review)}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.local-attempt-dispatch.v1", body), nil
}

func makeViewDigest(view SuppliedRepositoryView, snapshots []SnapshotBlock) ([32]byte, error) {
	wire := compactViewDigestWire{Version: 1, Origin: bindingToWire(view.Origin), Scope: string(view.Scope), Context: contextToWire(view.SuppliedContext), Head: bytes.Clone(view.Head), Snapshots: cloneSnapshotBlocks(snapshots)}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.supplied-repository-view.v1", body), nil
}

func decodeAttemptCore(encoded []byte) (attemptCoreWire, error) {
	var wire attemptCoreWire
	if len(encoded) == 0 || strictJSON(encoded, &wire) != nil || wire.Version != 1 || len(wire.AttemptID) != 16 || len(wire.DatabaseID) != 32 || len(wire.SnapshotCID) == 0 || len(wire.HeadCID) == 0 || len(wire.BlobCID) == 0 || len(wire.CandidateConfirmation) != 32 || len(wire.InitialViewDigest) != 32 {
		return attemptCoreWire{}, errors.New("invalid attempt core")
	}
	return wire, nil
}

func encodeAttemptCore(wire attemptCoreWire) ([]byte, error) {
	return canonicalJSON(wire)
}

func encodeAttemptEvidence(wire attemptEvidenceWire) ([]byte, error) {
	return canonicalJSON(wire)
}

func encodeAttemptEvent(wire attemptEventWire) ([]byte, error) {
	return canonicalJSON(wire)
}
