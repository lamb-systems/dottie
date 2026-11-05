package syncengine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
)

var ErrPreconditionChanged = errors.New("apply precondition changed")
var ErrNotActionable = errors.New("preview entry is not actionable for local apply")
var ErrRecoveryRequired = errors.New("pending apply journal entries require recovery before apply")

var applyBetweenOperations func(int)

type PartialApplyError struct {
	Applied []JournalResult
	Failed  JournalResult
	Cause   error
}

func (e *PartialApplyError) Error() string {
	return fmt.Sprintf("apply stopped after %d applied entries at %s/%s: %v", len(e.Applied), e.Failed.Key.TargetID, entryKeyName(e.Failed.Key), e.Cause)
}

func (e *PartialApplyError) Unwrap() error {
	return e.Cause
}

type UnsupportedApplyEntryError struct {
	Key    model.EntryKey
	Reason string
}

func (e *UnsupportedApplyEntryError) Error() string {
	return fmt.Sprintf("unsupported apply entry %s/%s: %s", e.Key.TargetID, e.Key.FilePath, e.Reason)
}

type NotActionableError struct {
	Key    model.EntryKey
	Action Action
}

func (e *NotActionableError) Error() string {
	return fmt.Sprintf("%s: %s/%s has reconciliation action %q", ErrNotActionable, e.Key.TargetID, e.Key.FilePath, e.Action)
}

func (e *NotActionableError) Unwrap() error {
	return ErrNotActionable
}

type Postimage struct {
	TargetID string
	Key      string
	Data     []byte
	Digest   []byte
	Mode     os.FileMode
}

type ModePolicy struct {
	Default   os.FileMode
	Overrides map[string]os.FileMode
}

type SettingValue struct {
	Present  bool
	Type     string
	Text     string
	Writable bool
}

type SettingsBackend interface {
	Observe(context.Context, model.EntryKey) (SettingValue, error)
	Canonicalize(context.Context, model.EntryKey, string, string) (SettingValue, error)
	Set(context.Context, model.EntryKey, string, string) error
	Reset(context.Context, model.EntryKey) error
}

type SettingPostimage struct {
	TargetID     string
	SchemaID     string
	SettingsPath string
	SettingKey   string
	State        model.SettingState
	Value        *model.VariantValue
}

func (p SettingPostimage) identity() model.EntryKey {
	return model.EntryKey{TargetID: p.TargetID, Source: model.SourceGNOME, SchemaID: p.SchemaID, SettingsPath: p.SettingsPath, SettingKey: p.SettingKey}
}

func (p SettingPostimage) entry() model.SettingEntry {
	return model.SettingEntry{SchemaID: p.SchemaID, Path: p.SettingsPath, Key: p.SettingKey, State: p.State, Value: p.Value}
}

type ApplyRequest struct {
	Preview           Preview
	Roots             map[string]string
	ModePolicy        ModePolicy
	Content           []Postimage
	Settings          SettingsBackend
	SettingPostimages []SettingPostimage
	Retention         *state.RetentionBinding
	FileSystem        files.ApplyFileSystem
	Now               func() time.Time
}

type applyOperation struct {
	entry            PreviewEntry
	root             string
	rootPath         string
	destinationPath  string
	rootDevice       int64
	rootInode        int64
	postimage        *Postimage
	settingPostimage SettingPostimage
	settingPost      SettingValue
	setting          bool
	filesystem       files.ApplyFileSystem
	settings         SettingsBackend
	pre              state.Fingerprint
	post             state.Fingerprint
	operation        string
	destination      os.FileMode
	journalID        string
	journalAdded     bool
	outcome          string
}

func Apply(ctx context.Context, store *state.Store, request ApplyRequest) error {
	if store == nil {
		return errors.New("apply state store is required")
	}
	if request.Now == nil {
		return errors.New("apply clock is required")
	}
	pending, err := store.PendingJournalEntries(ctx)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return ErrRecoveryRequired
	}
	filesystem := request.FileSystem
	if filesystem == nil {
		filesystem = files.DefaultApplyFileSystem()
	}
	operations, err := prepareApply(request, filesystem)
	if err != nil {
		return err
	}
	backupUsage, err := store.JournalBackupUsage(ctx)
	if err != nil {
		return err
	}
	applied := make([]JournalResult, 0, len(operations))
	for index := range operations {
		operation := &operations[index]
		if err := ctx.Err(); err != nil {
			if len(applied) != 0 {
				return applyFailure(applied, operation, err)
			}
			return err
		}
		if operation.setting {
			result, applyErr := applySettingOperation(ctx, store, request, operation, &backupUsage)
			if applyErr != nil {
				return applyFailure(applied, operation, applyErr)
			}
			applied = append(applied, result)
			if applyBetweenOperations != nil {
				applyBetweenOperations(len(applied))
			}
			continue
		}
		current, err := files.ObserveFile(filesystem, operation.root, operation.entry.Key.FilePath)
		if err != nil {
			return applyFailure(applied, operation, fmt.Errorf("recheck %s before apply: %w", operation.entry.Key.FilePath, err))
		}
		if err := checkPreviewPreimage(operation.entry, current); err != nil {
			return applyFailure(applied, operation, err)
		}
		if err := verifyRootIdentity(filesystem, operation.rootPath, operation.rootDevice, operation.rootInode); err != nil {
			return applyFailure(applied, operation, fmt.Errorf("recheck destination root before apply: %w", err))
		}
		id, err := newJournalID()
		if err != nil {
			return applyFailure(applied, operation, err)
		}
		operation.journalID = id
		if err := checkJournalBackupUsage(backupUsage, current.Data, MaxRollbackMaterialBytes); err != nil {
			return applyFailure(applied, operation, err)
		}
		entry := state.JournalEntry{
			ID:              id,
			Operation:       operation.operation,
			State:           "pending",
			Stage:           state.JournalStagePending,
			Identity:        operation.entry.Key,
			RootPath:        operation.rootPath,
			DestinationPath: operation.destinationPath,
			RootDevice:      operation.rootDevice,
			RootInode:       operation.rootInode,
			Preimage:        fingerprintForObservation(current),
			Postimage:       operation.post,
			Retention:       request.Retention,
			CreatedAt:       request.Now().Unix(),
		}
		if _, err := store.AppendJournal(ctx, entry, current.Data); err != nil {
			return applyFailure(applied, operation, fmt.Errorf("journal %s before apply: %w", operation.entry.Key.FilePath, err))
		}
		addJournalBackupUsage(&backupUsage, current.Data, operation.journalID)
		operation.journalAdded = true
		if err := verifyRootIdentity(filesystem, operation.rootPath, operation.rootDevice, operation.rootInode); err != nil {
			return applyFailure(applied, operation, failApply(ctx, store, operation, state.JournalStagePrecondition, err))
		}
		current, err = files.ObserveFile(filesystem, operation.root, operation.entry.Key.FilePath)
		if err != nil {
			cause := fmt.Errorf("recheck %s after journaling: %w", operation.entry.Key.FilePath, err)
			return applyFailure(applied, operation, failApply(ctx, store, operation, state.JournalStagePrecondition, cause))
		}
		if err := checkPreviewPreimage(operation.entry, current); err != nil {
			return applyFailure(applied, operation, failApply(ctx, store, operation, state.JournalStagePrecondition, err))
		}
		if err := verifyRootIdentity(filesystem, operation.rootPath, operation.rootDevice, operation.rootInode); err != nil {
			return applyFailure(applied, operation, failApply(ctx, store, operation, state.JournalStagePrecondition, err))
		}
		expected := files.ExpectedPreimage{Exists: current.Exists, Digest: current.Digest, Mode: current.Mode}
		if operation.operation == "delete" {
			err = files.DeleteFile(filesystem, operation.root, operation.entry.Key.FilePath, expected)
		} else {
			err = files.ReplaceFile(filesystem, operation.root, operation.entry.Key.FilePath, operation.postimage.Data, operation.destination, expected)
		}
		if err != nil {
			var precondition *files.PreconditionError
			if errors.As(err, &precondition) {
				err = fmt.Errorf("%w: %w", ErrPreconditionChanged, err)
			}
			return applyFailure(applied, operation, failApply(ctx, store, operation, journalStage(err, operation.operation), err))
		}
		verified, err := files.ObserveFile(filesystem, operation.root, operation.entry.Key.FilePath)
		if err != nil {
			cause := fmt.Errorf("read back %s: %w", operation.entry.Key.FilePath, err)
			return applyFailure(applied, operation, failApply(ctx, store, operation, state.JournalStageReadBack, cause))
		}
		if operation.operation == "delete" {
			if verified.Exists {
				err = errors.New("deleted path still exists after apply")
			}
		} else if !verified.Exists || verified.Digest != operation.post.Digest || verified.Mode != uint32(operation.destination.Perm()) {
			err = errors.New("read-back does not match intended postimage")
		}
		if err != nil {
			return applyFailure(applied, operation, failApply(ctx, store, operation, state.JournalStageReadBack, err))
		}
		if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "applied", state.JournalStageVerified); err != nil {
			operation.outcome = "indeterminate"
			return applyFailure(applied, operation, fmt.Errorf("mark apply journal %s applied: %w", operation.entry.Key.FilePath, err))
		}
		result := journalResult(state.JournalEntry{ID: operation.journalID, Identity: operation.entry.Key})
		result.Outcome = "applied"
		applied = append(applied, result)
		if applyBetweenOperations != nil {
			applyBetweenOperations(len(applied))
		}
	}
	return nil
}

func prepareApply(request ApplyRequest, filesystem files.ApplyFileSystem) ([]applyOperation, error) {
	for _, target := range request.Preview.Targets {
		for _, entry := range target.Entries {
			if entry.DecisionAction == ActionUnchanged && entry.Action == "" {
				continue
			}
			if entry.Key.Source == model.SourceGNOME {
				if entry.DecisionAction != ActionDownload {
					return nil, &NotActionableError{Key: entry.Key, Action: entry.DecisionAction}
				}
				if entry.Action != PreviewCreate && entry.Action != PreviewChange {
					return nil, unsupportedApply(entry.Key, "setting deletes are not applicable")
				}
				continue
			}
			if entry.DecisionAction != ActionDownload && entry.DecisionAction != ActionDeleteLocal {
				return nil, &NotActionableError{Key: entry.Key, Action: entry.DecisionAction}
			}
		}
	}
	if !request.Preview.Complete || request.Preview.UnresolvedEntries != 0 {
		return nil, errors.New("cannot apply an incomplete preview")
	}
	content := make(map[string]Postimage, len(request.Content))
	for _, postimage := range request.Content {
		key := postimageID(postimage.TargetID, postimage.Key)
		if _, exists := content[key]; exists {
			return nil, fmt.Errorf("duplicate postimage for %s/%s", postimage.TargetID, postimage.Key)
		}
		content[key] = postimage
	}
	settingPostimages := make(map[model.EntryKey]SettingPostimage, len(request.SettingPostimages))
	for _, postimage := range request.SettingPostimages {
		identity := postimage.identity()
		if err := identity.Validate(); err != nil {
			return nil, fmt.Errorf("invalid setting postimage identity: %w", err)
		}
		if _, exists := settingPostimages[identity]; exists {
			return nil, fmt.Errorf("duplicate setting postimage for %s/%s/%s", identity.SchemaID, identity.SettingsPath, identity.SettingKey)
		}
		if err := postimage.entry().Validate(); err != nil {
			return nil, fmt.Errorf("invalid setting postimage: %w", err)
		}
		settingPostimages[identity] = postimage
	}
	seen := make(map[string]struct{})
	previewKeys := make(map[model.EntryKey]struct{})
	needsContent := make(map[string]struct{})
	needsSettings := make(map[model.EntryKey]struct{})
	targetIDs := make(map[string]struct{}, len(request.Preview.Targets))
	operations := make([]applyOperation, 0)
	for _, target := range request.Preview.Targets {
		identity := model.EntryKey{TargetID: target.ID, Source: model.SourceFiles, FilePath: "."}
		if err := identity.Validate(); err != nil {
			return nil, unsupportedApply(identity, "invalid preview target identity")
		}
		if _, exists := targetIDs[target.ID]; exists {
			return nil, fmt.Errorf("duplicate preview target %q", target.ID)
		}
		targetIDs[target.ID] = struct{}{}
		for _, entry := range target.Entries {
			if entry.Key.TargetID != target.ID {
				return nil, unsupportedApply(entry.Key, "entry target does not match preview target")
			}
			if err := entry.Key.Validate(); err != nil {
				return nil, unsupportedApply(entry.Key, "invalid entry identity")
			}
			if _, exists := previewKeys[entry.Key]; exists {
				return nil, unsupportedApply(entry.Key, "duplicate preview entry")
			}
			previewKeys[entry.Key] = struct{}{}
			if entry.Action == "" {
				if entry.State != PreviewStateUnchanged || (entry.DecisionAction != "" && entry.DecisionAction != ActionUnchanged) {
					return nil, unsupportedApply(entry.Key, "entry has no resolved local action")
				}
				continue
			}
			if entry.Key.Source == model.SourceGNOME {
				if entry.DecisionAction != ActionDownload {
					return nil, &NotActionableError{Key: entry.Key, Action: entry.DecisionAction}
				}
				if entry.Action != PreviewCreate && entry.Action != PreviewChange {
					return nil, unsupportedApply(entry.Key, "setting deletes are not applicable")
				}
				switch entry.State {
				case "", PreviewStateMissing, PreviewStateUnmatched:
				default:
					return nil, unsupportedApply(entry.Key, "entry state is unresolved or unsupported")
				}
				postimage, exists := settingPostimages[entry.Key]
				if !exists {
					return nil, unsupportedApply(entry.Key, "matching setting postimage is missing")
				}
				if request.Settings == nil {
					return nil, unsupportedApply(entry.Key, "settings backend is required")
				}
				needsSettings[entry.Key] = struct{}{}
				operation := applyOperation{entry: entry, setting: true, settings: request.Settings, settingPostimage: postimage, operation: "setting-set"}
				if postimage.State == model.SettingReset {
					operation.operation = "setting-reset"
				}
				operations = append(operations, operation)
				continue
			}
			if entry.Key.Source != model.SourceFiles {
				return nil, unsupportedApply(entry.Key, "entry source is not applicable")
			}
			if entry.DecisionAction != ActionDownload && entry.DecisionAction != ActionDeleteLocal {
				return nil, &NotActionableError{Key: entry.Key, Action: entry.DecisionAction}
			}
			if entry.Action != PreviewCreate && entry.Action != PreviewChange && entry.Action != PreviewDelete {
				return nil, unsupportedApply(entry.Key, "action is not applicable")
			}
			switch entry.State {
			case "", PreviewStateMissing, PreviewStateUnmatched:
			default:
				return nil, unsupportedApply(entry.Key, "entry state is unresolved or unsupported")
			}
			id := postimageID(entry.Key.TargetID, entry.Key.FilePath)
			if _, exists := seen[id]; exists {
				return nil, unsupportedApply(entry.Key, "duplicate preview entry")
			}
			seen[id] = struct{}{}
			if entry.Key.FilePath == "." && entry.Action == PreviewDelete {
				return nil, unsupportedApply(entry.Key, "deleting the target root is not representable")
			}
			root, ok := request.Roots[target.ID]
			if !ok || !filepath.IsAbs(root) {
				return nil, unsupportedApply(entry.Key, "target has no absolute destination root")
			}
			operation := applyOperation{entry: entry, root: filepath.Clean(root), filesystem: filesystem}
			rootPath, destinationPath, rootDevice, rootInode, resolveErr := resolveApplyDestination(filesystem, operation.root, entry.Key.FilePath)
			if resolveErr != nil {
				return nil, unsupportedApply(entry.Key, resolveErr.Error())
			}
			operation.rootPath = rootPath
			operation.destinationPath = destinationPath
			operation.rootDevice = rootDevice
			operation.rootInode = rootInode
			switch entry.Action {
			case PreviewCreate, PreviewChange:
				postimage, exists := content[id]
				if !exists {
					return nil, unsupportedApply(entry.Key, "matching postimage is missing")
				}
				if len(postimage.Digest) != sha256.Size {
					return nil, unsupportedApply(entry.Key, "postimage digest must be SHA-256")
				}
				digest := sha256.Sum256(postimage.Data)
				if !equalDigest(digest[:], postimage.Digest) {
					return nil, unsupportedApply(entry.Key, "postimage digest does not match content")
				}
				mode := request.ModePolicy.Default
				if mode == 0 {
					mode = 0o600
				}
				if override, exists := request.ModePolicy.Overrides[target.ID]; exists {
					mode = override
				}
				if err := validateMode(mode); err != nil {
					return nil, unsupportedApply(entry.Key, err.Error())
				}
				if err := validateMode(postimage.Mode); err != nil || postimage.Mode.Perm() != mode.Perm() {
					return nil, unsupportedApply(entry.Key, "captured mode does not match the local destination mode policy")
				}
				if postimage.TargetID != entry.Key.TargetID || postimage.Key != entry.Key.FilePath {
					return nil, unsupportedApply(entry.Key, "postimage identity does not match preview entry")
				}
				operation.postimage = &postimage
				needsContent[id] = struct{}{}
				operation.operation = "replace"
				operation.destination = mode
				operation.post = state.NewFingerprint(string(model.FilePresent), model.FileRegular, uint32(mode.Perm()), "", "", "", postimage.Data)
			case PreviewDelete:
				if entry.Preimage == nil {
					return nil, unsupportedApply(entry.Key, "delete has no preimage")
				}
				operation.operation = "delete"
				operation.post = state.NewFingerprint(string(model.FileDeleted), "", 0, "", "", "", nil)
			}
			observed, err := files.ObserveFile(filesystem, operation.root, entry.Key.FilePath)
			if err != nil {
				var unsupported *files.UnsupportedPathError
				if errors.As(err, &unsupported) {
					return nil, unsupportedApply(entry.Key, unsupported.Reason)
				}
				return nil, fmt.Errorf("observe %s before apply: %w", entry.Key.FilePath, err)
			}
			if err := checkPreviewPreimage(entry, observed); err != nil {
				return nil, err
			}
			operations = append(operations, operation)
		}
	}
	for id, postimage := range content {
		if _, exists := seen[id]; !exists {
			key := model.EntryKey{TargetID: postimage.TargetID, Source: model.SourceFiles, FilePath: postimage.Key}
			return nil, unsupportedApply(key, "postimage has no preview entry")
		}
		if _, matched := needsContent[id]; !matched {
			key := model.EntryKey{TargetID: postimage.TargetID, Source: model.SourceFiles, FilePath: postimage.Key}
			return nil, unsupportedApply(key, "postimage does not match a create or change action")
		}
	}
	for identity := range settingPostimages {
		if _, matched := needsSettings[identity]; !matched {
			return nil, unsupportedApply(identity, "setting postimage does not match a create or change action")
		}
	}
	return operations, nil
}

func entryKeyName(key model.EntryKey) string {
	if key.Source == model.SourceGNOME {
		return key.SchemaID + "/" + key.SettingsPath + "/" + key.SettingKey
	}
	return key.FilePath
}

func applyFailure(applied []JournalResult, operation *applyOperation, cause error) error {
	if len(applied) == 0 {
		return cause
	}
	failed := journalResult(state.JournalEntry{ID: operation.journalID, Identity: operation.entry.Key})
	failed.Outcome = operation.outcome
	if failed.Outcome == "" {
		failed.Outcome = "failed"
	}
	failed.Reason = cause.Error()
	return &PartialApplyError{Applied: append([]JournalResult(nil), applied...), Failed: failed, Cause: cause}
}

func applySettingOperation(ctx context.Context, store *state.Store, request ApplyRequest, operation *applyOperation, backupUsage *state.JournalBackupUsage) (JournalResult, error) {
	key := operation.entry.Key
	observed, err := operation.settings.Observe(ctx, key)
	if err != nil {
		return JournalResult{}, fmt.Errorf("observe setting %s before apply: %w", entryKeyName(key), err)
	}
	if err := checkSettingPreviewPreimage(operation.entry, observed); err != nil {
		return JournalResult{}, err
	}
	if !observed.Writable {
		return JournalResult{}, fmt.Errorf("setting %s is not writable", entryKeyName(key))
	}
	preimage, backup, err := settingFingerprint(observed, key)
	if err != nil {
		return JournalResult{}, err
	}
	operation.pre = preimage
	post := operation.settingPostimage
	if post.State == model.SettingPresent {
		canonical, err := operation.settings.Canonicalize(ctx, key, post.Value.Type, post.Value.Text)
		if err != nil {
			return JournalResult{}, fmt.Errorf("canonicalize setting %s: %w", entryKeyName(key), err)
		}
		if !canonical.Present {
			return JournalResult{}, errors.New("canonicalized setting postimage is not present")
		}
		if _, _, err := settingFingerprint(canonical, key); err != nil {
			return JournalResult{}, fmt.Errorf("invalid canonical setting postimage: %w", err)
		}
		operation.settingPost = canonical
		operation.post = state.NewSettingFingerprint(model.SettingPresent, canonical.Type, canonical.Text)
	} else {
		operation.settingPost = SettingValue{}
		operation.post = state.NewSettingFingerprint(model.SettingReset, "", "")
	}
	if err := checkJournalBackupUsage(*backupUsage, backup, MaxRollbackMaterialBytes); err != nil {
		return JournalResult{}, err
	}
	id, err := newJournalID()
	if err != nil {
		return JournalResult{}, err
	}
	operation.journalID = id
	entry := state.JournalEntry{
		ID:        id,
		Operation: operation.operation,
		State:     "pending",
		Stage:     state.JournalStagePending,
		Identity:  key,
		Preimage:  operation.pre,
		Postimage: operation.post,
		Retention: request.Retention,
		CreatedAt: request.Now().Unix(),
	}
	if _, err := store.AppendJournal(ctx, entry, backup); err != nil {
		return JournalResult{}, fmt.Errorf("journal setting %s before apply: %w", entryKeyName(key), err)
	}
	addJournalBackupUsage(backupUsage, backup, id)
	operation.journalAdded = true
	observed, err = operation.settings.Observe(ctx, key)
	if err != nil {
		cause := fmt.Errorf("reobserve setting %s after journaling: %w", entryKeyName(key), err)
		return JournalResult{}, failSettingApply(ctx, store, operation, state.JournalStagePrecondition, cause)
	}
	if err := checkSettingPreviewPreimage(operation.entry, observed); err != nil {
		return JournalResult{}, failSettingApply(ctx, store, operation, state.JournalStagePrecondition, err)
	}
	if !observed.Writable {
		cause := fmt.Errorf("setting %s is no longer writable", entryKeyName(key))
		return JournalResult{}, failSettingApply(ctx, store, operation, state.JournalStagePrecondition, cause)
	}
	if !settingValueMatchesFingerprint(observed, key, operation.pre) {
		cause := fmt.Errorf("%w: setting %s changed after journaling", ErrPreconditionChanged, entryKeyName(key))
		return JournalResult{}, failSettingApply(ctx, store, operation, state.JournalStagePrecondition, cause)
	}
	if post.State == model.SettingPresent {
		err = operation.settings.Set(ctx, key, operation.settingPost.Type, operation.settingPost.Text)
	} else {
		err = operation.settings.Reset(ctx, key)
	}
	if err != nil {
		stage := state.JournalStageSettingSet
		if post.State == model.SettingReset {
			stage = state.JournalStageSettingReset
		}
		cause := fmt.Errorf("write setting %s: %w", entryKeyName(key), err)
		return JournalResult{}, failSettingApply(ctx, store, operation, stage, cause)
	}
	verified, err := operation.settings.Observe(ctx, key)
	if err != nil {
		cause := fmt.Errorf("read back setting %s: %w", entryKeyName(key), err)
		return JournalResult{}, failSettingApply(ctx, store, operation, state.JournalStageSettingReadBack, cause)
	}
	if !settingValueMatchesFingerprint(verified, key, operation.post) {
		cause := errors.New("setting read-back does not match intended postimage")
		return JournalResult{}, failSettingApply(ctx, store, operation, state.JournalStageSettingReadBack, cause)
	}
	if err := store.TransitionJournalEntry(ctx, id, "pending", "applied", state.JournalStageVerified); err != nil {
		cause := fmt.Errorf("mark setting journal %s applied: %w", entryKeyName(key), err)
		return JournalResult{}, failSettingApply(ctx, store, operation, state.JournalStageSettingReadBack, cause)
	}
	result := journalResult(state.JournalEntry{ID: id, Identity: key})
	result.Outcome = "applied"
	return result, nil
}

func checkSettingPreviewPreimage(entry PreviewEntry, observed SettingValue) error {
	if entry.Preimage == nil {
		if observed.Present {
			return fmt.Errorf("%w: setting %s appeared after preview", ErrPreconditionChanged, entryKeyName(entry.Key))
		}
		return nil
	}
	fingerprint, _, err := settingFingerprint(observed, entry.Key)
	if err != nil {
		return err
	}
	if fingerprint.Digest != entry.Preimage.Digest {
		return fmt.Errorf("%w: setting preimage differs for %s", ErrPreconditionChanged, entryKeyName(entry.Key))
	}
	return nil
}

func settingFingerprint(observed SettingValue, key model.EntryKey) (state.Fingerprint, []byte, error) {
	if !observed.Present {
		return state.NewSettingFingerprint(model.SettingReset, "", ""), []byte{}, nil
	}
	value := &model.VariantValue{Type: observed.Type, Text: observed.Text}
	if err := (model.SettingEntry{SchemaID: key.SchemaID, Path: key.SettingsPath, Key: key.SettingKey, State: model.SettingPresent, Value: value}).Validate(); err != nil {
		return state.Fingerprint{}, nil, fmt.Errorf("invalid observed setting %s: %w", entryKeyName(key), err)
	}
	payload := []byte(observed.Type + "\x00" + observed.Text)
	return state.NewSettingFingerprint(model.SettingPresent, observed.Type, observed.Text), payload, nil
}

func settingValueMatchesFingerprint(observed SettingValue, key model.EntryKey, fingerprint state.Fingerprint) bool {
	if err := fingerprint.Validate(key); err != nil {
		return false
	}
	if fingerprint.State == string(model.SettingReset) {
		return fingerprint == state.NewSettingFingerprint(model.SettingReset, "", "") && !observed.Present
	}
	if fingerprint.State != string(model.SettingPresent) || !observed.Present {
		return false
	}
	if fingerprint != state.NewSettingFingerprint(model.SettingPresent, fingerprint.ValueType, fingerprint.ValueText) {
		return false
	}
	if _, _, err := settingFingerprint(observed, key); err != nil {
		return false
	}
	return observed.Type == fingerprint.ValueType && observed.Text == fingerprint.ValueText
}

func failSettingApply(ctx context.Context, store *state.Store, operation *applyOperation, stage string, cause error) error {
	observed, observeErr := operation.settings.Observe(ctx, operation.entry.Key)
	if observeErr == nil && settingValueMatchesFingerprint(observed, operation.entry.Key, operation.pre) {
		operation.outcome = "failed"
		if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "failed", stage); err != nil {
			return errors.Join(cause, fmt.Errorf("mark setting journal failed: %w", err))
		}
	} else {
		operation.outcome = "indeterminate"
		if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "indeterminate", state.JournalStageIndeterminate); err != nil {
			return errors.Join(cause, fmt.Errorf("mark setting journal indeterminate: %w", err))
		}
	}
	return cause
}

func checkPreviewPreimage(entry PreviewEntry, observed files.ApplyObservation) error {
	if entry.Preimage == nil {
		if observed.Exists {
			return fmt.Errorf("%w: %s appeared after preview", ErrPreconditionChanged, entry.Key.FilePath)
		}
		return nil
	}
	if !observed.Exists || observed.Digest != entry.Preimage.Digest || observed.Mode != entry.Preimage.Mode {
		return fmt.Errorf("%w: digest or mode differs for %s", ErrPreconditionChanged, entry.Key.FilePath)
	}
	return nil
}

func fingerprintForObservation(observed files.ApplyObservation) state.Fingerprint {
	if !observed.Exists {
		return state.NewFingerprint(string(model.FileDeleted), "", 0, "", "", "", nil)
	}
	return state.NewFingerprint(string(model.FilePresent), model.FileRegular, observed.Mode, "", "", "", observed.Data)
}

func failApply(ctx context.Context, store *state.Store, operation *applyOperation, stage string, cause error) error {
	if operation.journalAdded {
		observed, observeErr := files.ObserveFile(operation.filesystem, operation.root, operation.entry.Key.FilePath)
		if operation.entry.Preimage != nil && observeErr == nil && observed.Exists && observed.Digest == operation.entry.Preimage.Digest && observed.Mode == operation.entry.Preimage.Mode {
			operation.outcome = "failed"
			if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "failed", stage); err != nil {
				return errors.Join(cause, fmt.Errorf("mark apply journal failed: %w", err))
			}
		} else if operation.entry.Preimage == nil && observeErr == nil && !observed.Exists {
			operation.outcome = "failed"
			if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "failed", stage); err != nil {
				return errors.Join(cause, fmt.Errorf("mark apply journal failed: %w", err))
			}
		} else {
			operation.outcome = "indeterminate"
			if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "indeterminate", state.JournalStageIndeterminate); err != nil {
				return errors.Join(cause, fmt.Errorf("mark apply journal indeterminate: %w", err))
			}
		}
	}
	return cause
}

func journalStage(err error, operation string) string {
	var precondition *files.PreconditionError
	if errors.As(err, &precondition) {
		return state.JournalStagePrecondition
	}
	var applyError *files.ApplyError
	if errors.As(err, &applyError) {
		switch applyError.Stage {
		case files.ApplyStageCreateTemp:
			return state.JournalStageCreateTemp
		case files.ApplyStageSetMode:
			return state.JournalStageSetMode
		case files.ApplyStageWrite:
			return state.JournalStageWrite
		case files.ApplyStageSyncFile:
			return state.JournalStageSyncFile
		case files.ApplyStageClose:
			return state.JournalStageClose
		case files.ApplyStageRename:
			return state.JournalStageRename
		case files.ApplyStageSyncDirectory:
			return state.JournalStageSyncDirectory
		case files.ApplyStageDelete:
			return state.JournalStageDelete
		default:
			return state.JournalStagePrecondition
		}
	}
	var unsupported *files.UnsupportedPathError
	if errors.As(err, &unsupported) {
		return state.JournalStagePrecondition
	}
	if operation == "delete" {
		return state.JournalStageDelete
	}
	return state.JournalStagePrecondition
}

func unsupportedApply(key model.EntryKey, reason string) error {
	return &UnsupportedApplyEntryError{Key: key, Reason: reason}
}

func validateMode(mode os.FileMode) error {
	if mode&^os.FileMode(0o777) != 0 {
		return errors.New("destination mode contains unsupported bits")
	}
	return nil
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func postimageID(targetID, key string) string {
	return targetID + "\x00" + key
}

func resolveApplyDestination(filesystem files.ApplyFileSystem, targetRoot, key string) (string, string, int64, int64, error) {
	rootInfo, rootErr := filesystem.Lstat(targetRoot)
	if rootErr != nil && !errors.Is(rootErr, os.ErrNotExist) {
		return "", "", 0, 0, rootErr
	}
	anchor := targetRoot
	destination := key
	singleFile := errors.Is(rootErr, os.ErrNotExist)
	if rootErr == nil {
		if rootInfo.Mode()&os.ModeSymlink != 0 {
			return "", "", 0, 0, errors.New("target root is a symbolic link")
		}
		if rootInfo.IsDir() {
			singleFile = false
		} else if rootInfo.Mode().IsRegular() {
			singleFile = true
		} else {
			return "", "", 0, 0, errors.New("target root is not a directory or regular file")
		}
	}
	if singleFile {
		if key != "." {
			return "", "", 0, 0, errors.New("single-file targets only support the root entry")
		}
		anchor = filepath.Dir(targetRoot)
		destination = filepath.Base(targetRoot)
	}
	anchor = filepath.Clean(anchor)
	info, err := filesystem.Lstat(anchor)
	if err != nil {
		return "", "", 0, 0, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", 0, 0, errors.New("apply root is not a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev > uint64(^uint64(0)>>1) || stat.Ino > uint64(^uint64(0)>>1) {
		return "", "", 0, 0, errors.New("apply root has no supported device and inode identity")
	}
	return anchor, filepath.ToSlash(destination), int64(stat.Dev), int64(stat.Ino), nil
}

func checkJournalBackupCapacityLimit(ctx context.Context, store *state.Store, backup []byte, limit int64) error {
	usage, err := store.JournalBackupUsage(ctx)
	if err != nil {
		return err
	}
	return checkJournalBackupUsage(usage, backup, limit)
}

func checkJournalBackupUsage(usage state.JournalBackupUsage, backup []byte, limit int64) error {
	reference := journalBackupReference(backup)
	for _, holder := range usage.Holders {
		if holder.Reference == reference {
			return nil
		}
	}
	requested := int64(len(backup))
	if limit < 0 || usage.Bytes > limit || requested > limit-usage.Bytes {
		entries := make([]string, 0)
		for _, holder := range usage.Holders {
			entries = append(entries, holder.Entries...)
		}
		return &RollbackMaterialLimitError{LimitBytes: limit, CurrentBytes: usage.Bytes, RequestedBytes: requested, Entries: entries}
	}
	return nil
}

func addJournalBackupUsage(usage *state.JournalBackupUsage, backup []byte, entryID string) {
	reference := journalBackupReference(backup)
	for index := range usage.Holders {
		if usage.Holders[index].Reference == reference {
			usage.Holders[index].Entries = append(usage.Holders[index].Entries, entryID)
			return
		}
	}
	usage.Bytes += int64(len(backup))
	usage.Holders = append(usage.Holders, state.JournalBackupHolder{Reference: reference, Size: int64(len(backup)), Entries: []string{entryID}})
}

func journalBackupReference(backup []byte) string {
	digest := sha256.Sum256(backup)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func newJournalID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
