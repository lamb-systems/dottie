package service

import (
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

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

var _ CapturePort = LocalFilesCapture{}

type LocalFilesCapture struct{}

func (LocalFilesCapture) Capture(_ context.Context, target config.Target, path string) (files.Result, error) {
	if target.Root == nil {
		return files.Result{}, errors.New("filesystem target has no root")
	}
	return files.Capture(files.Root{TargetID: target.ID, Path: path, Kind: target.Root.Kind, Exclude: append([]string(nil), target.Root.Exclude...)})
}
