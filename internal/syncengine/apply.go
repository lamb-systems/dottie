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
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
)

var ErrPreconditionChanged = errors.New("apply precondition changed")

type UnsupportedApplyEntryError struct {
	Key    model.EntryKey
	Reason string
}

func (e *UnsupportedApplyEntryError) Error() string {
	return fmt.Sprintf("unsupported apply entry %s/%s: %s", e.Key.TargetID, e.Key.FilePath, e.Reason)
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
}

type applyOperation struct {
	entry        PreviewEntry
	root         string
	postimage    *Postimage
	post         state.Fingerprint
	operation    string
	destination  os.FileMode
	journalID    string
	journalAdded bool
}

func Apply(ctx context.Context, store *state.Store, request ApplyRequest) error {
	if store == nil {
		return errors.New("apply state store is required")
	}
	filesystem := request.FileSystem
	if filesystem == nil {
		filesystem = files.DefaultApplyFileSystem()
	}
	operations, err := prepareApply(request, filesystem)
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
		id, err := newJournalID()
		if err != nil {
			return err
		}
		operation.journalID = id
		entry := state.JournalEntry{
			ID:        id,
			Operation: operation.operation,
			State:     "pending",
			Stage:     state.JournalStagePending,
			Identity:  operation.entry.Key,
			Preimage:  fingerprintForObservation(current),
			Postimage: operation.post,
			CreatedAt: time.Now().Unix(),
		}
		if _, err := store.AppendJournal(ctx, entry, current.Data); err != nil {
			return fmt.Errorf("journal %s before apply: %w", operation.entry.Key.FilePath, err)
		}
		operation.journalAdded = true
		current, err = files.ObserveFile(filesystem, operation.root, operation.entry.Key.FilePath)
		if err != nil {
			return failApply(ctx, store, operation, state.JournalStagePrecondition, fmt.Errorf("recheck %s after journaling: %w", operation.entry.Key.FilePath, err))
		}
		if err := checkPreviewPreimage(operation.entry, current); err != nil {
			return failApply(ctx, store, operation, state.JournalStagePrecondition, err)
		}
		if operation.operation == "delete" {
			err = files.DeleteFile(filesystem, operation.root, operation.entry.Key.FilePath)
		} else {
			err = files.ReplaceFile(filesystem, operation.root, operation.entry.Key.FilePath, operation.postimage.Data, operation.destination)
		}
		if err != nil {
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
		if err := store.PruneJournalBackup(ctx, operation.journalID); err != nil {
			return fmt.Errorf("prune verified backup for %s: %w", operation.entry.Key.FilePath, err)
		}
	}
	return nil
}

func prepareApply(request ApplyRequest, filesystem files.ApplyFileSystem) ([]applyOperation, error) {
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
				if entry.State != PreviewStateUnchanged {
					return nil, unsupportedApply(entry.Key, "entry has no resolved action")
				}
				continue
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
			operation := applyOperation{entry: entry, root: filepath.Clean(root)}
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
		if err := store.TransitionJournalEntry(ctx, operation.journalID, "pending", "failed", stage); err != nil {
			return errors.Join(cause, fmt.Errorf("mark apply journal failed: %w", err))
		}
	}
	return cause
}

func journalStage(err error, operation string) string {
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

func newJournalID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
