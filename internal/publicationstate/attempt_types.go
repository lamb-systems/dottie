package publicationstate

import (
	"database/sql"

	"github.com/lamb-systems/dottie/internal/publication"
)

type AttemptKind string
type AttemptLifecycle string
type AttemptOutcome string
type AttemptAvailability string
type DispatchKind string

type AttemptLimits struct {
	ActiveAttempts       uint32
	HistoricalAttempts   uint32
	RetainedPublications uint32
	ManagedObjects       uint32
	CustodyBytes         uint64
	MetadataBytes        uint64
	EvidenceBytes        uint64
	EvidenceSlotBytes    uint64
	LifecycleEvents      uint32
	EventBytes           uint64
	CoreBytes            uint64
	HistoryPageEntries   uint32
	HistoryPageBytes     uint64
}

func DefaultAttemptLimits() AttemptLimits {
	return AttemptLimits{
		ActiveAttempts: 1, HistoricalAttempts: 1024, RetainedPublications: 64,
		ManagedObjects: 64, CustodyBytes: 4 * publication.MaxBlobBytes,
		MetadataBytes: 128 << 20, EvidenceBytes: 128 << 20,
		EvidenceSlotBytes: 16 << 20, LifecycleEvents: 16,
		EventBytes: 64 << 10, CoreBytes: 256 << 10,
		HistoryPageEntries: 100, HistoryPageBytes: 16 << 20,
	}
}

type OpenOptions struct {
	PositionLimits       Limits
	AttemptLimits        AttemptLimits
	UpgradeFromPositions bool
	UpgradeFromAttempts  bool
	upgradeFault         func(int) error
	upgradeCommit        func(*sql.Tx) error
	openFault            func(int, *Store) error
	createdDatabaseChmod func(string) error
}

func DefaultOpenOptions() OpenOptions {
	return OpenOptions{PositionLimits: DefaultLimits(), AttemptLimits: DefaultAttemptLimits()}
}

type LocalReviewContext struct {
	SelectionDigest   [32]byte
	SelectionRevision uint64
	ApprovalDigest    [32]byte
	ApprovalRevision  uint64
}

type ViewScope string

const (
	ViewScopePublicRepository ViewScope           = "public-repository"
	ViewScopeDedicatedSpace   ViewScope           = "dedicated-space"
	ViewScopeWholeRepository  ViewScope           = "whole-repository"
	AttemptGenesis            AttemptKind         = "genesis"
	AttemptSuccessor          AttemptKind         = "successor"
	AttemptPrepared           AttemptLifecycle    = "prepared"
	AttemptUploadStarted      AttemptLifecycle    = "upload-started"
	AttemptMayHaveSubmitted   AttemptLifecycle    = "may-have-submitted"
	AttemptRetiredSuccess     AttemptLifecycle    = "retired-success"
	AttemptRetiredAbandoned   AttemptLifecycle    = "retired-abandoned"
	OutcomeNotSubmitted       AttemptOutcome      = "not-submitted"
	OutcomeUnresolved         AttemptOutcome      = "unresolved"
	OutcomeAbsentUnresolved   AttemptOutcome      = "observed-absent-unresolved"
	OutcomeCurrent            AttemptOutcome      = "observed-current"
	OutcomeSuperseded         AttemptOutcome      = "committed-superseded"
	OutcomeLostFence          AttemptOutcome      = "lost-fence"
	AvailabilityUnchecked     AttemptAvailability = "unchecked"
	AvailabilityAvailable     AttemptAvailability = "available-and-decoded"
	AvailabilityMissing       AttemptAvailability = "missing"
	AvailabilityCorrupt       AttemptAvailability = "corrupt"
	AvailabilityUnsafe        AttemptAvailability = "unsafe-object"
	AvailabilityUnavailable   AttemptAvailability = "io-unavailable"
	DispatchUpload            DispatchKind        = "upload"
	DispatchSubmission        DispatchKind        = "submission"
)

type SuppliedRepositoryView struct {
	Origin          Binding
	Scope           ViewScope
	SuppliedContext SuppliedContext
	Head            []byte
	Snapshots       []SnapshotBlock
}

type CandidateInput struct {
	SnapshotKey    string
	SnapshotRecord []byte
	HeadRecord     []byte
	Payload        []byte
}

type AttemptProposal struct {
	AttemptID          [16]byte
	Kind               AttemptKind
	StateToken         [32]byte
	CandidateDigest    [32]byte
	Confirmation       [32]byte
	CapturedFloor      *Floor
	CapturedGeneration uint64
	CandidateRecordCID []byte
	CandidateBlobCID   []byte
	CandidateBlobSize  uint64
}

type Attempt struct {
	ID                 [16]byte
	Kind               AttemptKind
	Lifecycle          AttemptLifecycle
	Outcome            AttemptOutcome
	Blocked            string
	Sequence           uint64
	SnapshotKey        string
	SnapshotRecordCID  []byte
	HeadRecordCID      []byte
	BlobCID            []byte
	BlobSize           uint64
	CapturedFloor      *Floor
	CapturedRevision   uint64
	CapturedGeneration uint64
	MutationRevision   uint64
	StateDigest        [32]byte
	Availability       AttemptAvailability
}

type AttemptEvidence struct {
	AttemptID [16]byte
	Role      string
	Evidence  []byte
}

type AttemptPage struct {
	Attempts []Attempt
	Evidence []AttemptEvidence
	NextID   [16]byte
	HasMore  bool
}

type CandidateMaterial struct {
	AttemptID      [16]byte
	SnapshotKey    string
	SnapshotRecord []byte
	HeadRecord     []byte
	Payload        []byte
	Blob           publication.BlobReference
}

type DispatchProposal struct {
	AttemptID    [16]byte
	Kind         DispatchKind
	StateToken   [32]byte
	Confirmation [32]byte
}

type UploadMaterial struct {
	AttemptID [16]byte
	Payload   []byte
	Blob      publication.BlobReference
}

type SubmissionMaterial struct {
	AttemptID             [16]byte
	SnapshotCollection    string
	SnapshotKey           string
	SnapshotRecord        []byte
	ExpectedSnapshotCID   []byte
	SnapshotCreateOnly    bool
	HeadCollection        string
	HeadKey               string
	HeadRecord            []byte
	HeadCreate            bool
	ExpectedPredecessor   *RecordReference
	ExpectedContext       SuppliedContext
	RequiresAtomicBatch   bool
	RequiresCreateExclude bool
	RequiresPolicyCheck   bool
}

type AttemptResolution struct {
	Attempt    Attempt
	Outcome    AttemptOutcome
	ViewDigest [32]byte
	Evidence   []byte
}

type Finalization struct {
	Attempt Attempt
	Floor   Floor
}

type AbandonProposal struct {
	AttemptID    [16]byte
	StateToken   [32]byte
	Confirmation [32]byte
	Warning      string
}

const AbandonWarning = "local retirement does not retract provider bytes or securely erase local plaintext"
