package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

func (coordinator *Coordinator) Preview(ctx context.Context, selection VaultSelection, targetID string) (Candidate, error) {
	if err := coordinator.lock(ctx); err != nil {
		return Candidate{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.previewLocked(ctx, selection, targetID)
}

func (coordinator *Coordinator) previewLocked(ctx context.Context, selection VaultSelection, targetID string) (Candidate, error) {
	if targetID == "" {
		return Candidate{}, errors.New("target ID is required")
	}
	pulled, err := coordinator.pullLocked(ctx, selection)
	if err != nil {
		return Candidate{}, err
	}
	configuration, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return Candidate{}, err
	}
	var target config.Target
	found := false
	for _, current := range configuration.Targets {
		if current.ID == targetID {
			target = current
			found = true
			break
		}
	}
	if !found {
		return Candidate{}, fmt.Errorf("unknown target %q", targetID)
	}
	if target.Source == model.SourceGNOME {
		if target.GNOMEPolicy == nil || target.GNOMEPolicy.Approval != config.GNOMEApprovalApproved {
			return Candidate{}, fmt.Errorf("%w: target %q has pending GNOME category policy", ErrGNOMEReapproval, target.ID)
		}
	}
	portable, err := targetFromConfig(target)
	if err != nil {
		return Candidate{}, err
	}
	observations, localEntries, unknown, untracked, coverage, err := coordinator.captureLocal(ctx, target)
	if err != nil {
		return Candidate{}, err
	}
	baseEntries, baseStatus, baseUntracked, err := coordinator.loadBase(ctx, target, portable, configuration)
	if err != nil {
		return Candidate{}, err
	}
	untracked = append(untracked, pulled.Untracked...)
	untracked = append(untracked, baseUntracked...)
	local := syncengine.LocalView{Entries: localEntries, Unknown: unknown, Untracked: untracked, Coverage: coverage}
	remoteEntries := make([]model.Entry, 0)
	for _, entry := range pulled.Snapshot.Entries {
		if entry.TargetID == target.ID {
			remoteEntries = append(remoteEntries, entry)
		}
	}
	binding, err := syncengine.NewTargetBinding(portable)
	if err != nil {
		return Candidate{}, err
	}
	plan, err := syncengine.Reconcile(syncengine.BaseView{Entries: baseEntries, Status: baseStatus}, local, remoteEntries,
		syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
	if err != nil {
		return Candidate{}, err
	}
	preview, err := syncengine.BuildPreview(plan, []model.Target{portable}, observations)
	if err != nil {
		return Candidate{}, err
	}
	digest, err := candidateDigest(pulled.VerifiedSnapshot, target, target.ModeOrDefault(configuration.Defaults), plan, observations, preview)
	if err != nil {
		return Candidate{}, err
	}
	selected, err := coordinator.selectVault(ctx, selection)
	if err != nil {
		return Candidate{}, err
	}
	retention, err := retentionBindingForRead(ctx, coordinator.deps.State, selected, pulled.Read)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{
		Preview: preview, Digest: digest, Actions: previewActions(preview), TargetID: target.ID,
		Freshness: pulled.Freshness, Currency: pulled.Currency.Outcome, InspectOnly: pulled.InspectOnly,
		Untracked: untracked, Retention: retention, plan: plan, observations: observations, configuration: configuration,
		localEntries: localEntries, baseEntries: baseEntries, remoteEntries: remoteEntries,
	}, nil
}

func retentionBindingForRead(ctx context.Context, store *state.Store, selection VaultSelection, read atproto.ReadResult) (*state.RetentionBinding, error) {
	declaration, err := store.RetentionDeclaration(ctx, selection.Vault, selection.DeviceID)
	if errors.Is(err, state.ErrRetentionDeclarationNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if declaration.DigestVersion != 2 || len(read.Head.PolicyDigest) != 32 {
		return nil, nil
	}
	var policyDigest [32]byte
	copy(policyDigest[:], read.Head.PolicyDigest)
	for _, point := range declaration.RecoveryPoints {
		if point.Epoch == read.EpochSeq && bytes.Equal(point.SnapshotCID, read.HeadCID) && point.PolicyDigest == policyDigest && bytes.Equal(point.ControlCID, read.ControlCID) {
			return &state.RetentionBinding{
				Vault: selection.Vault, Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID),
				PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID),
			}, nil
		}
	}
	return nil, nil
}

func (coordinator *Coordinator) captureLocal(ctx context.Context, target config.Target) ([]model.Observation, []model.Entry, []model.EntryKey, []model.EntryKey, []string, error) {
	observations := make([]model.Observation, 0)
	entries := make([]model.Entry, 0)
	unknown := make([]model.EntryKey, 0)
	coverage := make([]string, 0, 1)
	switch target.Source {
	case model.SourceFiles:
		if target.Root == nil {
			return nil, nil, nil, nil, nil, errors.New("filesystem target has no root")
		}
		path, err := target.ResolvedPath(coordinator.deps.Paths)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		capture := coordinator.deps.Files
		if capture == nil {
			capture = LocalFilesCapture{}
		}
		result, err := capture.Capture(ctx, target, path)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		observations = append(observations, result.Observations...)
		for _, observation := range result.Observations {
			switch observation.State {
			case model.ObservationPresent:
				entries = append(entries, *observation.Entry)
			case model.ObservationUnknown:
				unknown = append(unknown, observation.Identity)
			}
		}
		if len(unknown) == 0 {
			coverage = append(coverage, target.ID)
		}
	case model.SourceGNOME:
		if coordinator.deps.Settings == nil {
			return nil, nil, nil, nil, nil, errors.New("GNOME settings source is unavailable")
		}
		refs, err := approvedSettings(ctx, coordinator.deps.Settings, target)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		captured, err := coordinator.deps.Settings.Capture(ctx, target.ID, refs)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		allowed := make(map[model.EntryKey]struct{}, len(refs))
		for _, ref := range refs {
			allowed[model.EntryKey{TargetID: target.ID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}] = struct{}{}
		}
		for _, entry := range captured.Entries {
			if entry.TargetID != target.ID {
				return nil, nil, nil, nil, nil, ErrUnapprovedEntry
			}
			if _, ok := allowed[entry.Identity()]; !ok {
				return nil, nil, nil, nil, nil, ErrUnapprovedEntry
			}
			observation := model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}
			observations = append(observations, observation)
			entries = append(entries, entry)
		}
		for _, key := range captured.Unknown {
			if _, ok := allowed[key]; !ok {
				return nil, nil, nil, nil, nil, ErrUnapprovedEntry
			}
			unknown = append(unknown, key)
			observations = append(observations, model.Observation{State: model.ObservationUnknown, Identity: key})
		}
		if len(unknown) == 0 {
			coverage = append(coverage, target.ID)
		}
	default:
		return nil, nil, nil, nil, nil, errors.New("unsupported target source")
	}
	return observations, entries, unknown, nil, coverage, nil
}

func (coordinator *Coordinator) loadBase(ctx context.Context, target config.Target, portable model.Target, configuration config.Config) ([]model.Entry, syncengine.BaseStatus, []model.EntryKey, error) {
	records, err := coordinator.deps.State.AppliedBase(ctx, target.ID)
	if err != nil {
		return nil, "", nil, err
	}
	if len(records) == 0 {
		return nil, syncengine.BaseMissing, nil, nil
	}
	entries := make([]model.Entry, 0, len(records))
	for _, record := range records {
		var entry model.Entry
		switch record.Identity.Source {
		case model.SourceFiles:
			file := &model.FileEntry{Path: record.Identity.FilePath, State: model.FileState(record.Fingerprint.State), Kind: record.Fingerprint.Kind, Mode: record.Fingerprint.Mode, LinkTarget: record.Fingerprint.LinkTarget}
			if file.State == model.FilePresent && file.Kind == model.FileRegular {
				payload, err := coordinator.deps.State.Payload(record.PayloadRef)
				if err != nil {
					return nil, "", nil, err
				}
				file.Content = payload
			}
			entry = model.Entry{TargetID: target.ID, File: file}
		case model.SourceGNOME:
			setting := &model.SettingEntry{SchemaID: record.Identity.SchemaID, Path: record.Identity.SettingsPath, Key: record.Identity.SettingKey, State: model.SettingState(record.Fingerprint.State)}
			if setting.State == model.SettingPresent {
				setting.Value = &model.VariantValue{Type: record.Fingerprint.ValueType, Text: record.Fingerprint.ValueText}
			}
			entry = model.Entry{TargetID: target.ID, Setting: setting}
		default:
			return nil, "", nil, errors.New("base record has an unsupported source")
		}
		if err := entry.Validate(); err != nil {
			return nil, "", nil, err
		}
		entries = append(entries, entry)
	}
	filtered, untracked, err := filterSnapshot(ctx, configuration, coordinator.deps.Settings, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: entries})
	if err != nil {
		return nil, "", nil, err
	}
	status := syncengine.BaseKnown
	if len(untracked) != 0 {
		status = syncengine.BaseStale
	}
	return filtered.Entries, status, untracked, nil
}

func previewActions(preview syncengine.Preview) []syncengine.PreviewEntry {
	if len(preview.Targets) == 0 {
		return nil
	}
	actions := make([]syncengine.PreviewEntry, 0)
	for _, entry := range preview.Targets[0].Entries {
		if entry.Action != "" {
			actions = append(actions, entry)
		}
	}
	return actions
}

func candidateDigest(remote model.Snapshot, target config.Target, mode config.Mode, plan syncengine.Plan, observations []model.Observation, preview syncengine.Preview) (string, error) {
	material := struct {
		Domain       string
		Remote       model.Snapshot
		Target       config.Target
		Mode         config.Mode
		Plan         syncengine.Plan
		Observations []model.Observation
		Actions      []syncengine.PreviewEntry
	}{"dottie/s1b/candidate/v1", remote, target, mode, plan, observations, previewActions(preview)}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func basePostimage(targetID string, key model.EntryKey, plan syncengine.Plan) (model.Entry, bool) {
	for _, decision := range plan.Decisions {
		if decision.Key != key {
			continue
		}
		if decision.Remote != nil {
			return *decision.Remote, true
		}
		if decision.Action == syncengine.ActionDeleteLocal {
			return model.Entry{TargetID: targetID, File: &model.FileEntry{Path: key.FilePath, State: model.FileDeleted}}, true
		}
		return model.Entry{}, false
	}
	return model.Entry{}, false
}

var _ CapturePort = LocalFilesCapture{}

type LocalFilesCapture struct{}

func (LocalFilesCapture) Capture(_ context.Context, target config.Target, path string) (files.Result, error) {
	if target.Root == nil {
		return files.Result{}, errors.New("filesystem target has no root")
	}
	return files.Capture(files.Root{TargetID: target.ID, Path: path, Kind: target.Root.Kind, Exclude: append([]string(nil), target.Root.Exclude...)})
}
