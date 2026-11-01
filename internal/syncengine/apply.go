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

type ApplyRequest struct {
	Preview    Preview
	Roots      map[string]string
	ModePolicy ModePolicy
	Content    []Postimage
	FileSystem files.ApplyFileSystem
	Now        func() time.Time
}

type applyOperation struct {
	entry           PreviewEntry
	root            string
	rootPath        string
	destinationPath string
	rootDevice      int64
	rootInode       int64
	postimage       *Postimage
	filesystem      files.ApplyFileSystem
	post            state.Fingerprint
	operation       string
	destination     os.FileMode
	journalID       string
	journalAdded    bool
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
	for index := range operations {
		if err := ctx.Err(); err != nil {
			return err
		}
		operation := &operations[index]
		current, err := files.ObserveFile(filesystem, operation.root, operation.entry.Key.FilePath)
		if err != nil {
			return fmt.Errorf("recheck %s before apply: %w", operation.entry.Key.FilePath, err)
		}
		if err := checkPreviewPreimage(operation.entry, current); err != nil {
			return err
		}
		if err := verifyRootIdentity(filesystem, operation.rootPath, operation.rootDevice, operation.rootInode); err != nil {
			return fmt.Errorf("recheck destination root before apply: %w", err)
		}
		id, err := newJournalID()
		if err != nil {
			return err
		}
		operation.journalID = id
		if err := checkJournalBackupUsage(backupUsage, current.Data, MaxRollbackMaterialBytes); err != nil {
			return err
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
			CreatedAt:       request.Now().Unix(),
		}
		if _, err := store.AppendJournal(ctx, entry, current.Data); err != nil {
			return fmt.Errorf("journal %s before apply: %w", operation.entry.Key.FilePath, err)
		}
		addJournalBackupUsage(&backupUsage, current.Data, operation.journalID)
		operation.journalAdded = true
		if err := verifyRootIdentity(filesystem, operation.rootPath, operation.rootDevice, operation.rootInode); err != nil {
			return failApply(ctx, store, operation, state.JournalStagePrecondition, err)
		}
		current, err = files.ObserveFile(filesystem, operation.root, operation.entry.Key.FilePath)
		if err != nil {
			return failApply(ctx, store, operation, state.JournalStagePrecondition, fmt.Errorf("recheck %s after journaling: %w", operation.entry.Key.FilePath, err))
		}
		if err := checkPreviewPreimage(operation.entry, current); err != nil {
			return failApply(ctx, store, operation, state.JournalStagePrecondition, err)
		}
		if err := verifyRootIdentity(filesystem, operation.rootPath, operation.rootDevice, operation.rootInode); err != nil {
			return failApply(ctx, store, operation, state.JournalStagePrecondition, err)
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
			return failApply(ctx, store, operation, journalStage(err, operation.operation), err)
		}
		verified, err := files.ObserveFile(filesystem, operation.root, operation.entry.Key.FilePath)
		if err != nil {
			return failApply(ctx, store, operation, state.JournalStageReadBack, fmt.Errorf("read back %s: %w", operation.entry.Key.FilePath, err))
		}
		if operation.operation == "delete" {
			if verified.Exists {
				return failApply(ctx, store, operation, state.JournalStageReadBack, errors.New("deleted path still exists after apply"))
			}
		} else if !verified.Exists || verified.Digest != operation.post.Digest || verified.Mode != uint32(operation.destination.Perm()) {
			return failApply(ctx, store, operation, state.JournalStageReadBack, errors.New("read-back does not match intended postimage"))
		}
		if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "applied", state.JournalStageVerified); err != nil {
			return fmt.Errorf("mark apply journal %s applied: %w", operation.entry.Key.FilePath, err)
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
	seen := make(map[string]struct{})
	needsContent := make(map[string]struct{})
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
			if entry.Key.Source != model.SourceFiles {
				return nil, unsupportedApply(entry.Key, "settings entries are not applied by this filesystem path")
			}
			id := postimageID(entry.Key.TargetID, entry.Key.FilePath)
			if _, exists := seen[id]; exists {
				return nil, unsupportedApply(entry.Key, "duplicate preview entry")
			}
			seen[id] = struct{}{}
			if entry.Action == "" {
				if entry.State != PreviewStateUnchanged || (entry.DecisionAction != "" && entry.DecisionAction != ActionUnchanged) {
					return nil, unsupportedApply(entry.Key, "entry has no resolved local action")
				}
				continue
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
	return operations, nil
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
			if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "failed", stage); err != nil {
				return errors.Join(cause, fmt.Errorf("mark apply journal failed: %w", err))
			}
		} else if operation.entry.Preimage == nil && observeErr == nil && !observed.Exists {
			if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "failed", stage); err != nil {
				return errors.Join(cause, fmt.Errorf("mark apply journal failed: %w", err))
			}
		} else if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "indeterminate", state.JournalStageIndeterminate); err != nil {
			return errors.Join(cause, fmt.Errorf("mark apply journal indeterminate: %w", err))
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
