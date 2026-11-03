package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
)

const LatestSchemaVersion = 10
const PayloadRetention = "Pruning requires classified material below the oldest retained recovery-point boundary, no retained-point association, no base, intent or conflict reference, and an expired verified journal backup when pruning a backup."
const RetentionPruneScope = "Epoch-scoped material pruning requires complete payload and backup associations for every retained recovery point; the current sync path does not yet populate those inventories."

var ErrStateLocked = errors.New("state is already locked")
var ErrUnsupportedSchema = errors.New("unsupported state schema")
var ErrTargetBindingChanged = errors.New("target binding changed")
var ErrCheckpointBackwards = errors.New("vault checkpoint update would move backwards")
var ErrVaultCheckpointNotFound = errors.New("vault checkpoint not found")
var ErrVaultPublicationBackwards = errors.New("vault publication observation would move backwards")
var ErrVaultPublicationGap = errors.New("vault publication observation has a count gap")
var ErrVaultPublicationConflict = errors.New("vault publication count and head CID conflict")
var ErrPublicationAncestry = errors.New("vault publication ancestry does not match the observed head")
var ErrVaultPublicationControlAncestry = errors.New("vault publication control ancestry does not match the observed control")
var ErrVaultPublicationControlReplacement = errors.New("vault publication observation would replace the observed control within an epoch")
var ErrInvalidJournalTransition = errors.New("invalid apply journal transition")
var ErrRetentionDeclarationNotFound = errors.New("retention declaration not found")
var ErrRetentionBoundaryNotVerified = errors.New("retention boundary is not pinned by a matching verified checkpoint")
var ErrRetentionLiveHead = errors.New("retention boundary may not include or exceed the live head epoch")
var ErrRetentionConfirmationRequired = errors.New("retention pruning requires explicit confirmation")
var ErrRetentionRecoveryPointInventoryUnknown = errors.New("retention recovery-point material inventory is missing or incomplete")
var ErrRetentionBoundaryNewerThanFloor = errors.New("retention boundary is newer than the oldest retained recovery point")

type TargetDescriptor struct {
	ID            string
	Version       uint32
	Source        model.SourceKind
	SourceVersion uint32
	LogicalBase   model.RootBase
	LogicalPath   string
	Kind          model.SelectionKind
	Mode          string
	CreatedAt     int64
}

func (d TargetDescriptor) Validate() error {
	if d.Version != 1 {
		return errors.New("unsupported target descriptor version")
	}
	if d.Mode != "auto-apply" && d.Mode != "review" && d.Mode != "backup-only" {
		return errors.New("invalid target mode")
	}
	target := model.Target{ID: d.ID, Source: d.Source, SourceVersion: d.SourceVersion}
	switch d.Source {
	case model.SourceFiles:
		target.Root = &model.FileRoot{Base: d.LogicalBase, Path: d.LogicalPath, Kind: d.Kind}
	case model.SourceGNOME:
		if d.LogicalBase != "" || d.LogicalPath != "" || d.Kind != "" {
			return errors.New("GNOME target cannot carry a filesystem descriptor")
		}
	default:
		return errors.New("unsupported target source")
	}
	return target.Validate()
}

type Fingerprint struct {
	State      string
	Kind       model.FileKind
	Mode       uint32
	LinkTarget string
	ValueType  string
	ValueText  string
	Size       int64
	Digest     string
}

func NewFingerprint(state string, kind model.FileKind, mode uint32, linkTarget, valueType, valueText string, payload []byte) Fingerprint {
	digest := sha256.Sum256(payload)
	return Fingerprint{State: state, Kind: kind, Mode: mode, LinkTarget: linkTarget, ValueType: valueType, ValueText: valueText, Size: int64(len(payload)), Digest: hex.EncodeToString(digest[:])}
}

func (f Fingerprint) Validate(identity model.EntryKey) error {
	if f.Size < 0 || len(f.Digest) != sha256.Size*2 {
		return errors.New("invalid fingerprint size or digest")
	}
	if decoded, err := hex.DecodeString(f.Digest); err != nil || len(decoded) != sha256.Size || strings.ToLower(f.Digest) != f.Digest {
		return errors.New("invalid fingerprint digest")
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	switch identity.Source {
	case model.SourceFiles:
		switch f.State {
		case string(model.FilePresent):
			switch f.Kind {
			case model.FileRegular:
				if f.LinkTarget != "" || f.ValueType != "" || f.ValueText != "" || f.Mode&^uint32(0o777) != 0 {
					return errors.New("invalid regular-file fingerprint")
				}
			case model.FileDirectory:
				if f.LinkTarget != "" || f.ValueType != "" || f.ValueText != "" || f.Mode&^uint32(0o777) != 0 || f.Size != 0 {
					return errors.New("invalid directory fingerprint")
				}
			case model.FileSymlink:
				if f.Mode != 0 || f.ValueType != "" || f.ValueText != "" || f.Size != 0 {
					return errors.New("invalid symlink fingerprint")
				}
				if err := (model.FileEntry{Path: identity.FilePath, State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: f.LinkTarget}).Validate(); err != nil {
					return err
				}
			default:
				return errors.New("invalid present-file fingerprint kind")
			}
		case string(model.FileDeleted):
			if f.Kind != "" || f.Mode != 0 || f.LinkTarget != "" || f.ValueType != "" || f.ValueText != "" || f.Size != 0 {
				return errors.New("invalid deleted-file fingerprint")
			}
		default:
			return errors.New("invalid file fingerprint state")
		}
	case model.SourceGNOME:
		if f.Kind != "" || f.Mode != 0 || f.LinkTarget != "" {
			return errors.New("invalid setting fingerprint fields")
		}
		switch f.State {
		case "present":
			if f.ValueType == "" || f.ValueText == "" {
				return errors.New("present setting fingerprint requires a typed value")
			}
			value := &model.VariantValue{Type: f.ValueType, Text: f.ValueText}
			if err := (model.SettingEntry{SchemaID: identity.SchemaID, Path: identity.SettingsPath, Key: identity.SettingKey, State: model.SettingPresent, Value: value}).Validate(); err != nil {
				return err
			}
		case "reset":
			if f.ValueType != "" || f.ValueText != "" || f.Size != 0 {
				return errors.New("reset setting fingerprint cannot carry a value")
			}
			if err := (model.SettingEntry{SchemaID: identity.SchemaID, Path: identity.SettingsPath, Key: identity.SettingKey, State: model.SettingReset}).Validate(); err != nil {
				return err
			}
		default:
			return errors.New("invalid setting fingerprint state")
		}
	default:
		return errors.New("unsupported fingerprint source")
	}
	return nil
}

type BaseRecord struct {
	Identity    model.EntryKey
	Fingerprint Fingerprint
	PayloadRef  string
	RecordedAt  int64
}

type Intent struct {
	ID         string
	Identity   model.EntryKey
	PayloadRef string
	State      string
	Attempts   int
	CreatedAt  int64
}

type Conflict struct {
	ID               string
	Identity         model.EntryKey
	LocalPayloadRef  string
	RemotePayloadRef string
	State            string
	CreatedAt        int64
}

type Checkpoint struct {
	ID         string
	Counter    int64
	CID        string
	RecordedAt int64
}

type VaultCheckpoint struct {
	Vault        [32]byte
	Anchor       [32]byte
	ControlCID   []byte
	ControlBytes []byte
	SnapshotCID  []byte
	Epoch        uint64
	PolicyDigest [32]byte
	RecordedAt   int64
}

type VaultPublicationObservation struct {
	Vault            [32]byte
	Epoch            uint64
	PublicationCount uint64
	HeadCID          []byte
	ControlCID       []byte
	PrevControlCID   []byte
	PrevHeadCID      []byte
	ParentCID        []byte
	EnforceParent    bool
}

type RetentionRecoveryPoint struct {
	Epoch       uint64
	SnapshotCID []byte
}

type RetentionDeclaration struct {
	Vault                     [32]byte
	DeviceID                  string
	PolicyDigest              [32]byte
	RetentionFloor            uint64
	RecoveryPoints            []RetentionRecoveryPoint
	DeclarationDigest         [32]byte
	DeclaredAt                int64
	PreviousDeclarationDigest [32]byte
	PreviousDeclaredAt        int64
}

type RetentionDeclarationRevision struct {
	RetentionDeclaration
	Revision int64
}

type RetentionPruneRequest struct {
	Vault    [32]byte
	DeviceID string
	Boundary RetentionRecoveryPoint
	Now      time.Time
}

type RetentionPruneCandidateKind string

const (
	RetentionPruneCandidatePayload RetentionPruneCandidateKind = "payload"
	RetentionPruneCandidateBackup  RetentionPruneCandidateKind = "backup"
)

type RetentionPruneCandidate struct {
	Kind                    RetentionPruneCandidateKind
	Reference               string
	JournalID               string
	RecoveryPointEpochs     []uint64
	RecoveryPointEpochKnown bool
	Eligible                bool
	Reasons                 []string
}

type RetentionPrunePlan struct {
	Vault             [32]byte
	DeviceID          string
	Boundary          RetentionRecoveryPoint
	PolicyDigest      [32]byte
	RetentionFloor    uint64
	RecoveryPoints    []RetentionRecoveryPoint
	PayloadReferences []string
	ExpiredBackupIDs  []string
	Candidates        []RetentionPruneCandidate
	EpochScope        string
}

type RetentionPruneReport struct {
	Plan            RetentionPrunePlan
	DeletedPayloads []string
	PrunedBackupIDs []string
	EpochScope      string
}

type JournalEntry struct {
	ID              string
	Operation       string
	State           string
	Stage           string
	Identity        model.EntryKey
	RootPath        string
	DestinationPath string
	RootDevice      int64
	RootInode       int64
	Preimage        Fingerprint
	Postimage       Fingerprint
	BackupRef       string
	CreatedAt       int64
}

type JournalBackupHolder struct {
	Reference string
	Size      int64
	Entries   []string
}

type JournalBackupUsage struct {
	Bytes   int64
	Holders []JournalBackupHolder
}

const (
	TransitionAttemptPrepared    = "prepared"
	TransitionAttemptStaged      = "staged"
	TransitionAttemptSubmitted   = "submitted"
	TransitionAttemptCommitted   = "committed"
	TransitionAttemptSuperseded  = "committed-but-superseded"
	TransitionAttemptNotLanded   = "not-landed"
	TransitionAttemptUnavailable = "unavailable"
	TransitionAttemptFenceLost   = "fence-lost"
)

type TransitionAttempt struct {
	ID                string
	MarkerCollection  string
	MarkerRKey        string
	ExpectedRecordCID string
	CandidateBlobCID  string
	EpochSeq          uint64
	PolicyDigest      string
	Outcome           string
	Evidence          string
	CreatedAt         int64
}

func validateTransitionAttempt(attempt TransitionAttempt) error {
	if !validTransitionAttemptOutcome(attempt.Outcome) || attempt.Outcome != TransitionAttemptPrepared {
		return errors.New("transition attempt must begin in prepared outcome")
	}
	for _, field := range []struct {
		value string
		name  string
	}{
		{value: attempt.ID, name: "transition attempt id"},
		{value: attempt.MarkerCollection, name: "transition marker collection"},
		{value: attempt.MarkerRKey, name: "transition marker rkey"},
		{value: attempt.ExpectedRecordCID, name: "transition expected record CID"},
		{value: attempt.CandidateBlobCID, name: "transition candidate blob CID"},
		{value: attempt.Outcome, name: "transition outcome"},
	} {
		if err := validateID(field.value, field.name); err != nil {
			return err
		}
	}
	if strings.IndexByte(attempt.MarkerCollection, 0) >= 0 || strings.IndexByte(attempt.MarkerRKey, 0) >= 0 || attempt.EpochSeq > uint64(^uint64(0)>>1) {
		return errors.New("invalid transition attempt identity or epoch")
	}
	digest, err := hex.DecodeString(attempt.PolicyDigest)
	if err != nil || len(digest) != sha256.Size || strings.ToLower(attempt.PolicyDigest) != attempt.PolicyDigest {
		return errors.New("invalid transition policy digest")
	}
	return nil
}

func validTransitionAttemptOutcome(outcome string) bool {
	switch outcome {
	case TransitionAttemptPrepared, TransitionAttemptStaged, TransitionAttemptSubmitted, TransitionAttemptCommitted, TransitionAttemptSuperseded, TransitionAttemptNotLanded, TransitionAttemptUnavailable, TransitionAttemptFenceLost:
		return true
	default:
		return false
	}
}

func validTransitionAttemptOutcomeChange(current, next string) bool {
	if current == next {
		return true
	}
	switch current {
	case TransitionAttemptPrepared:
		return next == TransitionAttemptStaged || next == TransitionAttemptCommitted || next == TransitionAttemptSuperseded || next == TransitionAttemptNotLanded || next == TransitionAttemptUnavailable || next == TransitionAttemptFenceLost
	case TransitionAttemptStaged:
		return next == TransitionAttemptSubmitted || next == TransitionAttemptCommitted || next == TransitionAttemptSuperseded || next == TransitionAttemptNotLanded || next == TransitionAttemptUnavailable || next == TransitionAttemptFenceLost
	case TransitionAttemptSubmitted:
		return next == TransitionAttemptCommitted || next == TransitionAttemptSuperseded || next == TransitionAttemptNotLanded || next == TransitionAttemptUnavailable || next == TransitionAttemptFenceLost
	default:
		return false
	}
}

func validateID(value, name string) error {
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func validateIdentity(targetID string, identity model.EntryKey) error {
	if err := identity.Validate(); err != nil {
		return err
	}
	if identity.TargetID != targetID {
		return errors.New("entry identity target does not match record target")
	}
	return nil
}
