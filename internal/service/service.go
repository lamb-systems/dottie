package service

import (
	"context"
	"errors"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
)

var (
	ErrNoVaultSelection                 = errors.New("no local vault selection")
	ErrAmbiguousVaultSelection          = errors.New("multiple local vault selections require an explicit vault")
	ErrNoCheckpoint                     = errors.New("no local trust checkpoint is recorded")
	ErrMissingPredecessorEvidence       = errors.New("authenticated predecessor evidence is missing")
	ErrDeviceKeyMissing                 = errors.New("device keyring item is missing")
	ErrTrustEvidenceInvalid             = errors.New("local trust evidence is invalid")
	ErrCheckpointNotCurrent             = errors.New("remote checkpoint is not current or a verified descendant")
	ErrFreshnessUnverified              = errors.New("freshness is unverifiable; inspection/export-only continuation requires --consent; no data is applied")
	ErrApplyNotPermitted                = errors.New("local consent does not permit apply")
	ErrBaseRecordingFailed              = errors.New("applied-base recording failed")
	ErrCandidateChanged                 = errors.New("restore candidate digest changed")
	ErrGNOMEReapproval                  = errors.New("GNOME category approval requires re-approval")
	ErrUnapprovedEntry                  = errors.New("remote or base entry is not approved by local target policy")
	ErrAdministrativeRootRequired       = errors.New("administrative operation requires the selected root device")
	ErrRecoveryKitMismatch              = errors.New("recovery kit does not match the vault recovery anchor")
	ErrOnboardingAnchorMismatch         = errors.New("onboarding anchor does not match the supplied root fingerprint")
	ErrOnboardingVaultMismatch          = errors.New("onboarding bundle does not match the selected vault")
	ErrOnboardingDeviceMismatch         = errors.New("onboarding bundle does not contain the selected device recipient")
	ErrOnboardingCheckpoint             = errors.New("onboarding checkpoint does not match authenticated state")
	ErrOnboardingChain                  = errors.New("onboarding evidence does not form an authenticated successor chain")
	ErrOnboardingStateConflict          = errors.New("onboarding conflicts with existing local vault state")
	ErrRevokeApprovalMismatch           = errors.New("revocation approval fingerprint does not match the current verified device")
	ErrFinalizeKeysMissing              = errors.New("device keys for this vault are missing from Secret Service")
	ErrFinalizeStateConflict            = errors.New("local vault trust exists but does not match the verified remote position")
	ErrFinalizeStateIncomplete          = errors.New("local vault trust is incomplete")
	ErrBootstrapKitDeliveryFailed       = errors.New("recovery kit delivery failed before publication")
	ErrBootstrapTrustFinalizationFailed = errors.New("verified genesis local trust finalization failed")
)

type ConfigPort interface {
	Load(context.Context) (config.Config, error)
	Save(context.Context, config.Config) error
}

type CapturePort interface {
	Capture(context.Context, config.Target, string) (files.Result, error)
}

type SettingsPort interface {
	Resolve(context.Context, string, string, string) (string, error)
	Capture(context.Context, string, []SettingRef) (SettingsCapture, error)
	Backend() syncengine.SettingsBackend
}

type SessionPort interface {
	ReadRequest(context.Context, VaultSelection, vault.DeviceMaterial, [32]byte, []byte, []byte) (atproto.ReadRequest, error)
}

type RemoteReadPort interface {
	Read(context.Context, atproto.ReadRequest) (atproto.ReadResult, error)
}

type PublicationIOPort interface {
	PublicationIO(context.Context, VaultSelection, TrustMaterial, ReadOutcome) (atproto.ATProtoPublicationIO, error)
}

type GenesisPort interface {
	Preflight(context.Context) error
	BlobUploadLimit(context.Context) (int64, error)
	CommitGenesis(context.Context, int64, []byte, vault.DeviceMaterial, vault.Genesis) (atproto.GenesisCommitResult, error)
}

type TrustSource interface {
	Resolve(context.Context, VaultSelection) (TrustMaterial, error)
}

type TrustMaterial struct {
	Selection          VaultSelection
	Anchor             [32]byte
	Checkpoint         state.VaultCheckpoint
	Held               vault.ControlEvidence
	ImportedCheckpoint bool
	PredecessorPolicy  []byte
	PredecessorControl []byte
	Device             vault.DeviceMaterial
}

type VaultSelection struct {
	Vault    [32]byte
	DeviceID string
}

type SettingRef struct {
	SchemaID string
	Path     string
	Key      string
}

type SettingsCapture struct {
	Entries []model.Entry
	Unknown []model.EntryKey
}

type Dependencies struct {
	Config     ConfigPort
	State      *state.Store
	DeviceKeys DeviceKeySource
	Files      CapturePort
	Settings   SettingsPort
	Trust      TrustSource
	Session    SessionPort
	Remote     RemoteReadPort
	Publisher  PublicationIOPort
	Genesis    GenesisPort
	Clock      func() time.Time
	Filesystem files.ApplyFileSystem
	Paths      platform.Paths
}

type StatusState string

const (
	StatusCaptured            StatusState = "captured"
	StatusPending             StatusState = "pending"
	StatusCommitted           StatusState = "committed"
	StatusDownloaded          StatusState = "downloaded"
	StatusApplied             StatusState = "applied"
	StatusSkipped             StatusState = "skipped"
	StatusConflicted          StatusState = "conflicted"
	StatusUnknown             StatusState = "unknown"
	StatusLocked              StatusState = "locked"
	StatusAuthExpired         StatusState = "auth-expired"
	StatusFreshnessUnverified StatusState = "freshness-unverified"
	StatusBaseRecordingFailed StatusState = "base-recording-failed"
	StatusNoOp                StatusState = "no-op"
	StatusQueued              StatusState = "queued"
	StatusStarved             StatusState = "starved"
	StatusFenceLost           StatusState = "fence-lost"
	StatusSuperseded          StatusState = "superseded"
	StatusUnavailable         StatusState = "unavailable"
	StatusRejected            StatusState = "rejected"
)

type Status struct {
	Targets []TargetStatus
}

type TargetStatus struct {
	ID     string
	Source string
	Mode   config.Mode
	State  StatusState
	Reason string
	Items  int
}

type ReadOutcome struct {
	Snapshot         model.Snapshot
	VerifiedSnapshot model.Snapshot
	Read             atproto.ReadResult
	Currency         vault.VerificationResult
	Freshness        atproto.FreshnessStatus
	InspectOnly      bool
	Untracked        []model.EntryKey
	Retention        RetentionReport
}

type Candidate struct {
	Preview       syncengine.Preview
	Digest        string
	Actions       []syncengine.PreviewEntry
	TargetID      string
	Freshness     atproto.FreshnessStatus
	Currency      vault.CheckpointOutcome
	InspectOnly   bool
	Untracked     []model.EntryKey
	Retention     *state.RetentionBinding
	plan          syncengine.Plan
	observations  []model.Observation
	configuration config.Config
	localEntries  []model.Entry
	baseEntries   []model.Entry
	remoteEntries []model.Entry
}

type RestoreReport struct {
	CandidateDigest     string
	Applied             []syncengine.JournalResult
	Failed              *syncengine.JournalResult
	Untouched           []syncengine.PreviewEntry
	NoActions           bool
	BaseRecordingFailed bool
	Items               []RestoreItem
}

type RestoreItem struct {
	Key    model.EntryKey
	Status string
}

type RestoreRequest struct {
	Selection VaultSelection
	TargetID  string
	Confirm   string
}

type EnrollRequest struct {
	Selection           VaultSelection
	Device              vault.PublicDeviceInput
	Role                vault.Role
	ApprovalFingerprint [32]byte
	Kit                 []byte
}

type RevokeRequest struct {
	Selection           VaultSelection
	DeviceID            string
	Kit                 []byte
	ApprovalFingerprint [32]byte
}

type RevokeApprovalTranscript struct {
	Vault                    [32]byte
	DeviceID                 string
	Role                     vault.Role
	SigningKeyFingerprint    [32]byte
	RecipientKeyFingerprint  [32]byte
	CurrentEpoch             uint64
	SuccessorEpoch           uint64
	KitSigningKeyFingerprint [32]byte
	ApprovalFingerprint      [32]byte
}

type AdministrativeResult struct {
	Status            StatusState
	TransitionOutcome atproto.TransitionOutcome
	Bundle            vault.OnboardingBundle
	EncodedBundle     []byte
	Retention         RetentionReport
}
