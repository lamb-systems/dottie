package publicationstate

import (
	"context"
	"errors"
	"fmt"
)

type Stage string
type Reason string
type Backend string
type Mode string
type Provenance string

type Error struct {
	class        error
	stage        Stage
	reason       Reason
	cancellation error
}

type closedError = Error

func (e *Error) Error() string {
	return fmt.Sprintf("publication state: %s/%s/%s", className(e.class), e.stage, e.reason)
}

func (e *Error) Unwrap() error { return e.class }
func (e *Error) Is(target error) bool {
	return target != nil && (target == e.class || target == e.cancellation)
}
func (e *Error) Class() error   { return e.class }
func (e *Error) Stage() Stage   { return e.stage }
func (e *Error) Reason() Reason { return e.reason }

func className(err error) string {
	switch err {
	case ErrInvalid:
		return "invalid"
	case ErrContinuity:
		return "continuity"
	case ErrConsent:
		return "consent"
	case ErrLimit:
		return "limit"
	case ErrLocked:
		return "locked"
	case ErrClosed:
		return "closed"
	case ErrSchema:
		return "schema"
	default:
		return "storage"
	}
}

var (
	ErrInvalid    = errors.New("publication state invalid")
	ErrContinuity = errors.New("publication state continuity")
	ErrConsent    = errors.New("publication state consent")
	ErrLimit      = errors.New("publication state limit")
	ErrLocked     = errors.New("publication state locked")
	ErrClosed     = errors.New("publication state closed")
	ErrSchema     = errors.New("publication state schema")
	ErrStorage    = errors.New("publication state storage")
)

const (
	StageOpen              Stage  = "open"
	StageInput             Stage  = "input"
	StageObserve           Stage  = "observe"
	StagePrepare           Stage  = "prepare"
	StageAccept            Stage  = "accept"
	StageLoad              Stage  = "load"
	StageHistory           Stage  = "history"
	StageClose             Stage  = "close"
	ReasonBinding          Reason = "binding"
	ReasonContext          Reason = "context"
	ReasonRecordSet        Reason = "record_set"
	ReasonMode             Reason = "mode"
	ReasonLimits           Reason = "limits"
	ReasonFirstUseRequired Reason = "first_use_required"
	ReasonRollback         Reason = "rollback"
	ReasonFork             Reason = "fork"
	ReasonMissingLineage   Reason = "missing_lineage"
	ReasonStale            Reason = "stale"
	ReasonConfirmation     Reason = "confirmation"
	ReasonCapacity         Reason = "capacity"
	ReasonLocked           Reason = "locked"
	ReasonClosed           Reason = "closed"
	ReasonSchema           Reason = "schema"
	ReasonCorrupt          Reason = "corrupt"
	ReasonIO               Reason = "io"
	ReasonCommitUnknown    Reason = "commit_unknown"
	ReasonCanceled         Reason = "canceled"

	BackendSpaces      Backend    = "spaces"
	BackendPublicRepo  Backend    = "public-repo"
	ModeFirstUse       Mode       = "first-use"
	ModeAdvance        Mode       = "advance"
	ModeReplaceFloor   Mode       = "replace-floor"
	ProvenanceFirst    Provenance = "first-use"
	ProvenanceReplace  Provenance = "floor-replacement"
	WarningFirstUse               = "first-use: no independent freshness floor"
	WarningReplacement            = "replace floor: loses continuity with the prior recorded publication; no apply"
	storageProfile                = "systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"
)

type Binding struct {
	AccountDID string
	Backend    Backend
	Repository string
	Vault      [32]byte
}

type Policy struct {
	Revision  string
	Identity  []byte
	OwnerOnly bool
}

type SuppliedContext struct {
	RepositoryRevision string
	RepositoryDigest   []byte
	Policy             *Policy
}

type SnapshotBlock struct {
	Key string
	Raw []byte
}

type Observation struct {
	Origin          Binding
	SuppliedContext SuppliedContext
	Head            []byte
	Snapshots       []SnapshotBlock
}

type Limits struct {
	SuppliedSnapshotCount uint32
	SuppliedTotalBytes    uint64
	SuppliedContextBytes  uint32
	MaxLineageLinks       uint32
	CacheRecordCount      uint32
	CacheObservationCount uint32
	CacheLogicalBytes     uint64
	AcceptedRecordCount   uint32
	AcceptedEventCount    uint32
	AcceptedLogicalBytes  uint64
	HistoryPageEvents     uint32
	HistoryEvidenceBytes  uint64
}

func DefaultLimits() Limits {
	return Limits{
		SuppliedSnapshotCount: 4095,
		SuppliedTotalBytes:    8 << 20,
		SuppliedContextBytes:  16 << 10,
		MaxLineageLinks:       4094,
		CacheRecordCount:      4096,
		CacheObservationCount: 1024,
		CacheLogicalBytes:     16 << 20,
		AcceptedRecordCount:   16384,
		AcceptedEventCount:    8192,
		AcceptedLogicalBytes:  128 << 20,
		HistoryPageEvents:     100,
		HistoryEvidenceBytes:  16 << 20,
	}
}

type RecordReference struct {
	Key      string
	CID      []byte
	Sequence uint64
}

type Floor struct {
	DatabaseID          [32]byte
	Revision            uint64
	Generation          uint64
	Provenance          Provenance
	AnchorCID           []byte
	Binding             Binding
	SuppliedContext     SuppliedContext
	Head                []byte
	SnapshotKey         string
	Sequence            uint64
	PublicationID       [16]byte
	RecordCID           []byte
	BlobCID             []byte
	BlobSize            uint64
	ObservationDigest   [32]byte
	AcceptedEventDigest [32]byte
}

type Proposal struct {
	Mode              Mode
	Reason            Reason
	Warning           string
	StateToken        [32]byte
	ObservationID     [32]byte
	ObservationDigest [32]byte
	Confirmation      [32]byte
	Trace             []RecordReference
	Stop              string
}

type RecordEvidence struct {
	Reference RecordReference
	Raw       []byte
}

type HistoryEvent struct {
	Revision          uint64
	Mode              Mode
	Reason            Reason
	Stop              string
	OldFloor          *Floor
	NewFloor          Floor
	Trace             []RecordReference
	ObservationDigest [32]byte
	SuppliedSetDigest [32]byte
	EventDigest       [32]byte
}

type HistoryPage struct {
	Events       []HistoryEvent
	Records      []RecordEvidence
	NextRevision uint64
	HasMore      bool
}

func classified(class error, stage Stage, reason Reason) error {
	return &Error{class: class, stage: stage, reason: reason}
}

func canceled(stage Stage, cause error) error {
	safe := error(nil)
	if errors.Is(cause, context.Canceled) {
		safe = context.Canceled
	} else if errors.Is(cause, context.DeadlineExceeded) {
		safe = context.DeadlineExceeded
	}
	return &Error{class: ErrStorage, stage: stage, reason: ReasonCanceled, cancellation: safe}
}

func storageFailure(ctx context.Context, stage Stage, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		return canceled(stage, ctx.Err())
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return canceled(stage, cause)
	}
	return classified(ErrStorage, stage, ReasonIO)
}

func zeroFloor() Floor { return Floor{} }
