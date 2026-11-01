package syncengine

import (
	"context"
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

const MaxRollbackMaterialBytes int64 = 256 * 1024 * 1024

type RollbackMaterialLimitError struct {
	LimitBytes     int64
	CurrentBytes   int64
	RequestedBytes int64
	Entries        []string
}

func (e *RollbackMaterialLimitError) Error() string {
	return fmt.Sprintf("rollback material limit exceeded: %d bytes in entries %v plus %d requested exceeds %d bytes", e.CurrentBytes, e.Entries, e.RequestedBytes, e.LimitBytes)
}

type JournalResult struct {
	JournalID string
	TargetID  string
	FilePath  string
	Outcome   string
	Reason    string
}

type RecoveryReport struct {
	Entries []JournalResult
	Pruned  []string
}

type RollbackReport struct {
	Entries []JournalResult
	Pruned  []string
}

func RecoverInterrupted(ctx context.Context, store *state.Store, filesystem files.ApplyFileSystem, now func() time.Time) (RecoveryReport, error) {
	if store == nil {
		return RecoveryReport{}, errors.New("recovery state store is required")
	}
	if now == nil {
		return RecoveryReport{}, errors.New("recovery clock is required")
	}
	if filesystem == nil {
		filesystem = files.DefaultApplyFileSystem()
	}
	report := RecoveryReport{Entries: make([]JournalResult, 0)}
	entries, err := store.PendingJournalEntries(ctx)
	if err != nil {
		return report, err
	}
	for _, entry := range entries {
		result := journalResult(entry)
		if err := verifyJournalRoot(filesystem, entry); err != nil {
			if transitionErr := store.TransitionJournalEntry(ctx, entry.ID, "pending", "indeterminate", state.JournalStageIndeterminate); transitionErr != nil {
				return report, errors.Join(err, transitionErr)
			}
			result.Outcome = "indeterminate"
			result.Reason = "destination root missing or changed"
			report.Entries = append(report.Entries, result)
			continue
		}
		observed, observeErr := files.ObserveFile(filesystem, entry.RootPath, entry.DestinationPath)
		if observeErr == nil {
			observeErr = verifyJournalRoot(filesystem, entry)
		}
		if observeErr != nil {
			if transitionErr := store.TransitionJournalEntry(ctx, entry.ID, "pending", "indeterminate", state.JournalStageIndeterminate); transitionErr != nil {
				return report, errors.Join(observeErr, transitionErr)
			}
			result.Outcome = "indeterminate"
			result.Reason = "destination could not be observed"
			report.Entries = append(report.Entries, result)
			continue
		}
		switch {
		case observationMatches(observed, entry.Postimage):
			if err := store.TransitionJournalEntry(ctx, entry.ID, "pending", "indeterminate", state.JournalStageIndeterminate); err != nil {
				return report, err
			}
			result.Outcome = "indeterminate"
			result.Reason = "destination matches the postimage but cannot be distinguished from an identical user edit"
		case observationMatches(observed, entry.Preimage):
			if err := store.TransitionJournalEntry(ctx, entry.ID, "pending", "failed", state.JournalStagePrecondition); err != nil {
				return report, err
			}
			result.Outcome = "failed"
			result.Reason = "destination still matches preimage"
		default:
			if err := store.TransitionJournalEntry(ctx, entry.ID, "pending", "indeterminate", state.JournalStageIndeterminate); err != nil {
				return report, err
			}
			result.Outcome = "indeterminate"
			result.Reason = "destination matches neither preimage nor postimage"
		}
		report.Entries = append(report.Entries, result)
	}
	pruned, err := store.PruneExpiredJournalBackups(ctx, now())
	if err != nil {
		return report, err
	}
	report.Pruned = pruned
	return report, nil
}

func RollbackApplied(ctx context.Context, store *state.Store, filesystem files.ApplyFileSystem, now func() time.Time) (RollbackReport, error) {
	if store == nil {
		return RollbackReport{}, errors.New("rollback state store is required")
	}
	if now == nil {
		return RollbackReport{}, errors.New("rollback clock is required")
	}
	if filesystem == nil {
		filesystem = files.DefaultApplyFileSystem()
	}
	currentTime := now()
	pruned, err := store.PruneExpiredJournalBackups(ctx, currentTime)
	if err != nil {
		return RollbackReport{}, err
	}
	entries, err := store.JournalEntriesAll(ctx)
	if err != nil {
		return RollbackReport{}, err
	}
	report := RollbackReport{Entries: make([]JournalResult, 0), Pruned: pruned}
	blockedDestinations := make(map[string]bool)
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		if entry.State != "applied" {
			continue
		}
		result := journalResult(entry)
		destination := entry.RootPath + "\x00" + entry.DestinationPath
		if blockedDestinations[destination] {
			result.Outcome = "skipped-newer-edit"
			result.Reason = "newer journal history was left unresolved; older history was not restored"
			report.Entries = append(report.Entries, result)
			continue
		}
		if entry.Stage == state.JournalStageRollbackSkipped {
			blockedDestinations[destination] = true
			result.Outcome = "skipped-newer-edit"
			result.Reason = "a previous rollback preserved a newer edit; this outcome is durable"
			report.Entries = append(report.Entries, result)
			continue
		}
		if entry.Stage == state.JournalStageRollbackPending || entry.Stage == state.JournalStageRollbackIndeterminate || entry.Stage != state.JournalStageVerified {
			if entry.Stage == state.JournalStageRollbackPending || entry.Stage == state.JournalStageVerified {
				if err := store.RecordJournalRollbackIndeterminate(ctx, entry.ID); err != nil {
					return report, err
				}
			}
			blockedDestinations[destination] = true
			result.Outcome = "indeterminate"
			result.Reason = "a previous or unresolved rollback attempt has no durable completion proof"
			report.Entries = append(report.Entries, result)
			continue
		}
		markIndeterminate := func(reason string) error {
			if err := store.RecordJournalRollbackIndeterminate(ctx, entry.ID); err != nil {
				return err
			}
			blockedDestinations[destination] = true
			result.Outcome = "indeterminate"
			result.Reason = reason
			report.Entries = append(report.Entries, result)
			return nil
		}
		if entry.BackupRef == "" {
			result.Outcome = "applied"
			result.Reason = "rollback backup expired or was already pruned"
			report.Entries = append(report.Entries, result)
			continue
		}
		if err := verifyJournalRoot(filesystem, entry); err != nil {
			if markErr := markIndeterminate("destination root missing or changed"); markErr != nil {
				return report, markErr
			}
			continue
		}
		observed, err := files.ObserveFile(filesystem, entry.RootPath, entry.DestinationPath)
		if err != nil {
			if markErr := markIndeterminate("destination could not be observed"); markErr != nil {
				return report, markErr
			}
			continue
		}
		if !observationMatches(observed, entry.Postimage) {
			if err := store.RecordJournalRollbackSkipped(ctx, entry.ID); err != nil {
				return report, err
			}
			blockedDestinations[destination] = true
			result.Outcome = "skipped-newer-edit"
			result.Reason = "destination no longer matches intended postimage; left unchanged"
			report.Entries = append(report.Entries, result)
			continue
		}
		backup, err := store.Payload(entry.BackupRef)
		if err != nil {
			if markErr := markIndeterminate("rollback backup is unavailable"); markErr != nil {
				return report, markErr
			}
			continue
		}
		if !backupMatchesPreimage(backup, entry.Preimage) {
			if markErr := markIndeterminate("rollback backup does not match recorded preimage"); markErr != nil {
				return report, markErr
			}
			continue
		}
		current, err := files.ObserveFile(filesystem, entry.RootPath, entry.DestinationPath)
		if err == nil {
			err = verifyJournalRoot(filesystem, entry)
		}
		if err != nil {
			if markErr := markIndeterminate("destination could not be rechecked before restore"); markErr != nil {
				return report, markErr
			}
			continue
		}
		if !observationMatches(current, entry.Postimage) {
			if err := store.RecordJournalRollbackSkipped(ctx, entry.ID); err != nil {
				return report, err
			}
			blockedDestinations[destination] = true
			result.Outcome = "skipped-newer-edit"
			result.Reason = "destination changed before restore; left unchanged"
			report.Entries = append(report.Entries, result)
			continue
		}
		if err := store.BeginJournalRollback(ctx, entry.ID); err != nil {
			return report, err
		}
		if err := restorePreimage(filesystem, entry, backup); err != nil {
			var precondition *files.PreconditionError
			if errors.As(err, &precondition) {
				if err := store.RecordJournalRollbackSkipped(ctx, entry.ID); err != nil {
					return report, err
				}
				blockedDestinations[destination] = true
				result.Outcome = "skipped-newer-edit"
				result.Reason = "destination changed at the filesystem precondition check; left unchanged"
			} else {
				if err := store.RecordJournalRollbackIndeterminate(ctx, entry.ID); err != nil {
					return report, err
				}
				blockedDestinations[destination] = true
				result.Outcome = "indeterminate"
				result.Reason = "restore failed"
			}
			report.Entries = append(report.Entries, result)
			continue
		}
		verified, err := files.ObserveFile(filesystem, entry.RootPath, entry.DestinationPath)
		if err != nil || !observationMatches(verified, entry.Preimage) {
			if err := store.RecordJournalRollbackIndeterminate(ctx, entry.ID); err != nil {
				return report, err
			}
			blockedDestinations[destination] = true
			result.Outcome = "indeterminate"
			result.Reason = "restored destination did not verify against preimage"
			report.Entries = append(report.Entries, result)
			continue
		}
		if err := store.TransitionJournalEntry(ctx, entry.ID, "applied", "rolled-back", state.JournalStageRolledBack); err != nil {
			return report, err
		}
		if err := store.PruneJournalBackup(ctx, entry.ID, currentTime); err != nil {
			result.Outcome = "rolled-back"
			result.Reason = "restore verified; backup retained because pruning failed"
			report.Entries = append(report.Entries, result)
			return report, err
		}
		result.Outcome = "rolled-back"
		result.Reason = "backup restored and verified"
		report.Entries = append(report.Entries, result)
		report.Pruned = append(report.Pruned, entry.ID)
	}
	return report, nil
}

func journalResult(entry state.JournalEntry) JournalResult {
	return JournalResult{JournalID: entry.ID, TargetID: entry.Identity.TargetID, FilePath: entry.Identity.FilePath}
}

func verifyJournalRoot(filesystem files.ApplyFileSystem, entry state.JournalEntry) error {
	if entry.RootPath == "" || !filepath.IsAbs(entry.RootPath) || filepath.Clean(entry.RootPath) != entry.RootPath || entry.RootDevice < 0 || entry.RootInode < 0 {
		return errors.New("journal destination root is missing or invalid")
	}
	if err := verifyRootIdentity(filesystem, entry.RootPath, entry.RootDevice, entry.RootInode); err != nil {
		return err
	}
	destination := model.EntryKey{TargetID: entry.Identity.TargetID, Source: model.SourceFiles, FilePath: entry.DestinationPath}
	if entry.DestinationPath == "" || filepath.IsAbs(entry.DestinationPath) || filepath.ToSlash(filepath.FromSlash(entry.DestinationPath)) != entry.DestinationPath || destination.Validate() != nil {
		return errors.New("journal destination path is invalid")
	}
	return nil
}

func verifyRootIdentity(filesystem files.ApplyFileSystem, rootPath string, device, inode int64) error {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || device < 0 || inode < 0 {
		return errors.New("journal destination root is missing or invalid")
	}
	info, err := filesystem.Lstat(rootPath)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("journal destination root is not a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev != uint64(device) || stat.Ino != uint64(inode) {
		return errors.New("journal destination root identity changed")
	}
	return nil
}

func observationMatches(observed files.ApplyObservation, fingerprint state.Fingerprint) bool {
	if fingerprint.State == string(model.FileDeleted) {
		return !observed.Exists
	}
	return fingerprint.State == string(model.FilePresent) && fingerprint.Kind == model.FileRegular && observed.Exists && observed.Digest == fingerprint.Digest && observed.Mode == fingerprint.Mode
}

func backupMatchesPreimage(backup []byte, preimage state.Fingerprint) bool {
	if preimage.State == string(model.FileDeleted) {
		return len(backup) == 0
	}
	if preimage.State != string(model.FilePresent) || preimage.Kind != model.FileRegular || int64(len(backup)) != preimage.Size {
		return false
	}
	digest := sha256.Sum256(backup)
	return hex.EncodeToString(digest[:]) == preimage.Digest
}

func restorePreimage(filesystem files.ApplyFileSystem, entry state.JournalEntry, backup []byte) error {
	expected := files.ExpectedPreimage{Exists: entry.Postimage.State == string(model.FilePresent), Digest: entry.Postimage.Digest, Mode: entry.Postimage.Mode}
	if entry.Preimage.State == string(model.FileDeleted) {
		return files.DeleteFile(filesystem, entry.RootPath, entry.DestinationPath, expected)
	}
	if entry.Preimage.State == string(model.FilePresent) && entry.Preimage.Kind == model.FileRegular {
		return files.ReplaceFile(filesystem, entry.RootPath, entry.DestinationPath, backup, os.FileMode(entry.Preimage.Mode), expected)
	}
	return errors.New("journal preimage cannot be restored by the filesystem apply path")
}
