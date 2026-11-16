package service

import (
	"context"
	"errors"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
)

var (
	ErrNoVaultSelection           = errors.New("no local vault selection")
	ErrAmbiguousVaultSelection    = errors.New("multiple local vault selections require an explicit vault")
	ErrCheckpointNotCurrent       = errors.New("remote checkpoint is not current or a verified descendant")
	ErrBaseRecordingFailed        = errors.New("applied-base recording failed")
	ErrGNOMEReapproval            = errors.New("GNOME category approval requires re-approval")
	ErrUnapprovedEntry            = errors.New("remote or base entry is not approved by local target policy")
	ErrAdministrativeRootRequired = errors.New("administrative operation requires the selected root device")
	ErrOnboardingAnchorMismatch   = errors.New("onboarding anchor does not match the supplied root fingerprint")
	ErrOnboardingDeviceMismatch   = errors.New("onboarding bundle does not contain the selected device recipient")
	ErrOnboardingCheckpoint       = errors.New("onboarding checkpoint does not match authenticated state")
	ErrOnboardingStateConflict    = errors.New("onboarding conflicts with existing local vault state")
	ErrRevokeApprovalMismatch     = errors.New("revocation approval fingerprint does not match the current verified device")
)

type ConfigPort interface {
	Load(context.Context) (config.Config, error)
	Snapshot(context.Context) (config.Snapshot, error)
	Update(context.Context, config.Token, func(config.Config) (config.Config, error)) (config.Snapshot, error)
}

type ConfigGuard interface {
	Release()
}

type ReviewSource interface {
	Acquire(context.Context) (publicationstate.LocalReviewContext, config.Token, ConfigGuard, error)
}

type CapturePort interface {
	Capture(context.Context, config.Target, string) (files.Result, error)
}

type SettingsPort interface {
	Resolve(context.Context, string, string, string) (string, error)
	Capture(context.Context, string, []SettingRef) (SettingsCapture, error)
	Backend() syncengine.SettingsBackend
}

type DeviceKeySource interface {
	LoadDeviceKeys(context.Context, [32]byte, string) (vault.DeviceMaterial, error)
}

type GenesisPreflightPort interface {
	Preflight(context.Context) error
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
	Config           ConfigPort
	State            *state.Store
	DeviceKeys       DeviceKeySource
	Files            CapturePort
	Settings         SettingsPort
	GenesisPreflight GenesisPreflightPort
	Clock            func() time.Time
	Filesystem       files.ApplyFileSystem
	Paths            platform.Paths
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
	Vaults  []VaultSelection
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
