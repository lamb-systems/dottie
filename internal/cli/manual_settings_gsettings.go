//go:build linux && cgo && gsettings

package cli

import (
	"context"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/gnome"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

type manualSettingsSource struct{}

func manualGNOMESettings() service.SettingsPort { return manualSettingsSource{} }

func (manualSettingsSource) Resolve(_ context.Context, _, schemaID, path string) (string, error) {
	settings, err := gnome.OpenDefault(schemaID, path)
	if err != nil {
		return "", err
	}
	defer settings.Close()
	return settings.Path(), nil
}

func (manualSettingsSource) Capture(ctx context.Context, targetID string, refs []service.SettingRef) (service.SettingsCapture, error) {
	keys := make([]matrix.KeyRef, 0, len(refs))
	for _, ref := range refs {
		keys = append(keys, matrix.KeyRef{SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key})
	}
	captured, err := gnome.Capture(ctx, gnome.CaptureRequest{TargetID: targetID, Keys: keys})
	if err != nil {
		return service.SettingsCapture{}, err
	}
	unknown := make([]model.EntryKey, 0, len(captured.Unknown))
	for _, key := range captured.Unknown {
		unknown = append(unknown, model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: key.SchemaID, SettingsPath: key.Path, SettingKey: key.Key})
	}
	return service.SettingsCapture{Entries: captured.Entries, Unknown: unknown}, nil
}

func (manualSettingsSource) Backend() syncengine.SettingsBackend {
	backend, err := gnome.NewSettingsBackend()
	if err != nil {
		return nil
	}
	return backend
}
