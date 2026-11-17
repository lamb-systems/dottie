package service

import (
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
)

func (coordinator *Coordinator) captureLocal(
	ctx context.Context,
	target config.Target,
) ([]model.Observation, []model.Entry, []model.EntryKey, []model.EntryKey, []string, error) {
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

var _ CapturePort = LocalFilesCapture{}

type LocalFilesCapture struct{}

func (LocalFilesCapture) Capture(_ context.Context, target config.Target, path string) (files.Result, error) {
	if target.Root == nil {
		return files.Result{}, errors.New("filesystem target has no root")
	}
	return files.Capture(
		files.Root{
			TargetID: target.ID,
			Path:     path,
			Kind:     target.Root.Kind,
			Exclude:  append([]string(nil), target.Root.Exclude...),
		},
	)
}
