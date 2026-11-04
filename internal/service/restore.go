package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

func (coordinator *Coordinator) Restore(ctx context.Context, request RestoreRequest) (RestoreReport, error) {
	if err := coordinator.lock(ctx); err != nil {
		return RestoreReport{}, err
	}
	defer coordinator.mu.Unlock()
	candidate, err := coordinator.previewLocked(ctx, request.Selection, request.TargetID)
	if err != nil {
		return RestoreReport{}, err
	}
	report := RestoreReport{CandidateDigest: candidate.Digest}
	target, exists := candidate.configuration.Target(candidate.TargetID)
	if !exists {
		return report, errors.New("restore target disappeared from local configuration")
	}
	mode := target.ModeOrDefault(candidate.configuration.Defaults)
	if mode == config.BackupOnly {
		return report, fmt.Errorf("%w: target %q is backup-only", ErrApplyNotPermitted, target.ID)
	}
	if candidate.Currency == "unverifiable" || candidate.InspectOnly {
		return report, ErrFreshnessUnverified
	}
	if candidate.Currency != "current" && candidate.Currency != "descendant" {
		return report, ErrCheckpointNotCurrent
	}
	if !candidate.Preview.Complete {
		return report, errors.New("restore candidate is incomplete or contains unresolved items")
	}
	if mode == config.Review && request.Confirm != candidate.Digest {
		return report, ErrCandidateChanged
	}
	if request.Confirm != "" && request.Confirm != candidate.Digest {
		return report, ErrCandidateChanged
	}
	applyPreview := applicablePreview(candidate.Preview)
	if len(applyPreview.Targets) == 0 || countApplyActions(applyPreview) == 0 {
		report.NoActions = true
		return report, nil
	}
	pending, err := coordinator.deps.State.PendingJournalEntries(ctx)
	if err != nil {
		return report, err
	}
	if len(pending) != 0 {
		filesystem := coordinator.deps.Filesystem
		if filesystem == nil {
			filesystem = files.DefaultApplyFileSystem()
		}
		settings := coordinator.settingsBackend()
		if closer, ok := settings.(interface{ Close() error }); ok {
			defer closer.Close()
		}
		if _, err := syncengine.RecoverInterruptedWithSettings(ctx, coordinator.deps.State, filesystem, settings, coordinator.deps.Clock); err != nil {
			return report, err
		}
	}
	before, err := coordinator.deps.State.JournalEntriesAll(ctx)
	if err != nil {
		return report, err
	}
	beforeIDs := make(map[string]struct{}, len(before))
	for _, entry := range before {
		beforeIDs[entry.ID] = struct{}{}
	}
	applyRequest, err := coordinator.applyRequest(candidate, applyPreview)
	if err != nil {
		return report, err
	}
	if closer, ok := applyRequest.Settings.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	applyErr := syncengine.Apply(ctx, coordinator.deps.State, applyRequest)
	var partial *syncengine.PartialApplyError
	if applyErr != nil && !errors.As(applyErr, &partial) {
		return report, applyErr
	}
	if partial != nil {
		report.Applied = append(report.Applied, partial.Applied...)
		failed := partial.Failed
		report.Failed = &failed
		report.Untouched = untouchedAfter(applyPreview, failed.Key)
		report.Items = restoreItems(applyPreview, report.Applied, &failed, report.Untouched)
	} else {
		after, journalErr := coordinator.deps.State.JournalEntriesAll(ctx)
		if journalErr != nil {
			return report, journalErr
		}
		for _, entry := range after {
			if _, existed := beforeIDs[entry.ID]; !existed && entry.State == "applied" {
				report.Applied = append(report.Applied, syncengine.JournalResult{JournalID: entry.ID, Key: entry.Identity, TargetID: entry.Identity.TargetID, FilePath: entry.Identity.FilePath, Outcome: "applied"})
			}
		}
		report.Items = restoreItems(applyPreview, report.Applied, nil, nil)
	}
	if err := coordinator.recordAppliedBases(ctx, candidate, report.Applied); err != nil {
		report.BaseRecordingFailed = true
		return report, fmt.Errorf("%w: %w", ErrBaseRecordingFailed, err)
	}
	if partial != nil {
		return report, applyErr
	}
	return report, nil
}

func applicablePreview(preview syncengine.Preview) syncengine.Preview {
	result := preview
	result.Targets = make([]syncengine.PreviewTarget, 0, len(preview.Targets))
	for _, target := range preview.Targets {
		filtered := syncengine.PreviewTarget{ID: target.ID, Entries: make([]syncengine.PreviewEntry, 0, len(target.Entries))}
		for _, entry := range target.Entries {
			if entry.DecisionAction == syncengine.ActionDownload || entry.DecisionAction == syncengine.ActionDeleteLocal || entry.DecisionAction == syncengine.ActionUnchanged {
				filtered.Entries = append(filtered.Entries, entry)
			}
		}
		result.Targets = append(result.Targets, filtered)
	}
	return result
}

func countApplyActions(preview syncengine.Preview) int {
	count := 0
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Action != "" {
				count++
			}
		}
	}
	return count
}

func (coordinator *Coordinator) applyRequest(candidate Candidate, preview syncengine.Preview) (syncengine.ApplyRequest, error) {
	target, exists := candidate.configuration.Target(candidate.TargetID)
	if !exists {
		return syncengine.ApplyRequest{}, errors.New("restore target is missing")
	}
	request := syncengine.ApplyRequest{
		Preview: preview, Roots: make(map[string]string),
		Settings: coordinator.settingsBackend(), FileSystem: coordinator.deps.Filesystem, Now: coordinator.deps.Clock,
	}
	if target.Source == model.SourceFiles {
		root, err := target.ResolvedPath(coordinator.deps.Paths)
		if err != nil {
			return syncengine.ApplyRequest{}, err
		}
		request.Roots[target.ID] = root
	}
	modeSet := false
	var fileMode os.FileMode
	for _, decision := range candidate.plan.Decisions {
		if decision.Action != syncengine.ActionDownload || decision.Remote == nil {
			continue
		}
		entry := *decision.Remote
		if entry.TargetID != target.ID {
			continue
		}
		if entry.File != nil {
			if entry.File.State != model.FilePresent || entry.File.Kind != model.FileRegular {
				continue
			}
			mode := os.FileMode(entry.File.Mode)
			if modeSet && fileMode.Perm() != mode.Perm() {
				return syncengine.ApplyRequest{}, errors.New("sync engine cannot preserve different file modes within one target")
			}
			fileMode, modeSet = mode, true
			request.Content = append(request.Content, syncengine.Postimage{
				TargetID: target.ID, Key: entry.File.Path, Data: append([]byte(nil), entry.File.Content...),
				Digest: sha256Bytes(entry.File.Content), Mode: mode,
			})
		} else if entry.Setting != nil {
			setting := entry.Setting
			request.SettingPostimages = append(request.SettingPostimages, syncengine.SettingPostimage{
				TargetID: target.ID, SchemaID: setting.SchemaID, SettingsPath: setting.Path,
				SettingKey: setting.Key, State: setting.State, Value: setting.Value,
			})
		}
	}
	if modeSet {
		request.ModePolicy = syncengine.ModePolicy{Default: fileMode, Overrides: map[string]os.FileMode{target.ID: fileMode}}
	}
	if len(request.SettingPostimages) != 0 && request.Settings == nil {
		return syncengine.ApplyRequest{}, errors.New("GNOME apply backend is unavailable")
	}
	return request, nil
}

func sha256Bytes(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return append([]byte(nil), digest[:]...)
}

func (coordinator *Coordinator) recordAppliedBases(ctx context.Context, candidate Candidate, applied []syncengine.JournalResult) error {
	entries := make([]model.Entry, 0, len(applied))
	for _, result := range applied {
		entry, found := basePostimage(candidate.TargetID, result.Key, candidate.plan)
		if !found {
			continue
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil
	}
	return coordinator.recordBaseLocked(ctx, candidate.TargetID, entries)
}

func appliedResults(preview syncengine.Preview) []syncengine.JournalResult {
	results := make([]syncengine.JournalResult, 0)
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Action == "" {
				continue
			}
			results = append(results, syncengine.JournalResult{Key: entry.Key, TargetID: target.ID, FilePath: entry.Key.FilePath, Outcome: "applied"})
		}
	}
	return results
}

func untouchedAfter(preview syncengine.Preview, failed model.EntryKey) []syncengine.PreviewEntry {
	untouched := make([]syncengine.PreviewEntry, 0)
	foundFailed := false
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Key == failed {
				foundFailed = true
				continue
			}
			if foundFailed && entry.Action != "" {
				untouched = append(untouched, entry)
			}
		}
	}
	return untouched
}

func restoreItems(preview syncengine.Preview, applied []syncengine.JournalResult, failed *syncengine.JournalResult, untouched []syncengine.PreviewEntry) []RestoreItem {
	items := make([]RestoreItem, 0)
	for _, result := range applied {
		items = append(items, RestoreItem{Key: result.Key, Status: "applied"})
	}
	if failed != nil {
		items = append(items, RestoreItem{Key: failed.Key, Status: "failed"})
	}
	for _, entry := range untouched {
		items = append(items, RestoreItem{Key: entry.Key, Status: "untouched"})
	}
	return items
}
