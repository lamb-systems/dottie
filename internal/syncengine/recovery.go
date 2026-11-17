package syncengine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
)

type JournalResult struct {
	JournalID string
	Key       model.EntryKey
	TargetID  string
	FilePath  string
	Outcome   string
	Reason    string
}

type RecoveryReport struct {
	Entries []JournalResult
	Pruned  []string
}

func RecoverInterrupted(
	ctx context.Context,
	store *state.Store,
	filesystem files.ApplyFileSystem,
	now func() time.Time,
) (RecoveryReport, error) {
	return RecoverInterruptedWithSettings(ctx, store, filesystem, nil, now)
}

func RecoverInterruptedWithSettings(
	ctx context.Context,
	store *state.Store,
	filesystem files.ApplyFileSystem,
	settings SettingsBackend,
	now func() time.Time,
) (RecoveryReport, error) {
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
		if entry.Identity.Source == model.SourceGNOME {
			result, err = recoverPendingSetting(ctx, store, settings, entry, result)
			if err != nil {
				return report, err
			}
			report.Entries = append(report.Entries, result)
			continue
		}
		if err := verifyJournalRoot(filesystem, entry); err != nil {
			if transitionErr := store.TransitionJournalEntry(
				ctx,
				entry.ID,
				"pending",
				"indeterminate",
				state.JournalStageIndeterminate,
			); transitionErr != nil {
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
			if transitionErr := store.TransitionJournalEntry(
				ctx,
				entry.ID,
				"pending",
				"indeterminate",
				state.JournalStageIndeterminate,
			); transitionErr != nil {
				return report, errors.Join(observeErr, transitionErr)
			}
			result.Outcome = "indeterminate"
			result.Reason = "destination could not be observed"
			report.Entries = append(report.Entries, result)
			continue
		}
		switch {
		case observationMatches(observed, entry.Postimage):
			if err := store.TransitionJournalEntry(
				ctx,
				entry.ID,
				"pending",
				"indeterminate",
				state.JournalStageIndeterminate,
			); err != nil {
				return report, err
			}
			result.Outcome = "indeterminate"
			result.Reason = "destination matches the postimage but cannot be distinguished from an identical user edit"
		case observationMatches(observed, entry.Preimage):
			if err := store.TransitionJournalEntry(
				ctx,
				entry.ID,
				"pending",
				"failed",
				state.JournalStagePrecondition,
			); err != nil {
				return report, err
			}
			result.Outcome = "failed"
			result.Reason = "destination still matches preimage"
		default:
			if err := store.TransitionJournalEntry(
				ctx,
				entry.ID,
				"pending",
				"indeterminate",
				state.JournalStageIndeterminate,
			); err != nil {
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

func recoverPendingSetting(
	ctx context.Context,
	store *state.Store,
	settings SettingsBackend,
	entry state.JournalEntry,
	result JournalResult,
) (JournalResult, error) {
	resolve := func(outcome, reason, stage string) (JournalResult, error) {
		if err := store.TransitionJournalEntry(ctx, entry.ID, "pending", outcome, stage); err != nil {
			return result, err
		}
		result.Outcome = outcome
		result.Reason = reason
		return result, nil
	}
	if settings == nil {
		return resolve("indeterminate", "settings backend is unavailable", state.JournalStageIndeterminate)
	}
	observed, err := settings.Observe(ctx, entry.Identity)
	if err != nil || !observed.Writable {
		return resolve("indeterminate", "setting could not be observed or is locked", state.JournalStageIndeterminate)
	}
	switch {
	case settingValueMatchesFingerprint(observed, entry.Identity, entry.Postimage):
		return resolve(
			"indeterminate",
			"setting matches the postimage but cannot be distinguished from an identical user edit",
			state.JournalStageIndeterminate,
		)
	case settingValueMatchesFingerprint(observed, entry.Identity, entry.Preimage):
		return resolve("failed", "setting still matches preimage", state.JournalStagePrecondition)
	default:
		return resolve(
			"indeterminate",
			"setting matches neither preimage nor postimage",
			state.JournalStageIndeterminate,
		)
	}
}

func journalResult(entry state.JournalEntry) JournalResult {
	return JournalResult{
		JournalID: entry.ID,
		Key:       entry.Identity,
		TargetID:  entry.Identity.TargetID,
		FilePath:  entry.Identity.FilePath,
	}
}

func verifyJournalRoot(filesystem files.ApplyFileSystem, entry state.JournalEntry) error {
	if entry.RootPath == "" || !filepath.IsAbs(entry.RootPath) || filepath.Clean(entry.RootPath) != entry.RootPath ||
		entry.RootDevice < 0 ||
		entry.RootInode < 0 {
		return errors.New("journal destination root is missing or invalid")
	}
	if err := verifyRootIdentity(filesystem, entry.RootPath, entry.RootDevice, entry.RootInode); err != nil {
		return err
	}
	destination := model.EntryKey{
		TargetID: entry.Identity.TargetID,
		Source:   model.SourceFiles,
		FilePath: entry.DestinationPath,
	}
	if entry.DestinationPath == "" || filepath.IsAbs(entry.DestinationPath) ||
		filepath.ToSlash(filepath.FromSlash(entry.DestinationPath)) != entry.DestinationPath ||
		destination.Validate() != nil {
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
	return fingerprint.State == string(model.FilePresent) && fingerprint.Kind == model.FileRegular && observed.Exists &&
		observed.Digest == fingerprint.Digest &&
		observed.Mode == fingerprint.Mode
}
