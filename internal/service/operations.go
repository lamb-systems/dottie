package service

import (
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

type FileConfigPort struct {
	Paths platform.Paths
}

func (port FileConfigPort) Load(context.Context) (config.Config, error) {
	return config.Load(port.Paths)
}

func (port FileConfigPort) Save(_ context.Context, value config.Config) error {
	return config.Save(port.Paths, value)
}

func (coordinator *Coordinator) UpdateConfig(ctx context.Context, update func(config.Config) (config.Config, error)) (config.Config, error) {
	if update == nil || coordinator.deps.Config == nil {
		return config.Config{}, errors.New("coordinator config update is unavailable")
	}
	if err := coordinator.lock(ctx); err != nil {
		return config.Config{}, err
	}
	defer coordinator.mu.Unlock()
	current, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return config.Config{}, err
	}
	updated, err := update(current)
	if err != nil {
		return config.Config{}, err
	}
	if err := updated.Validate(); err != nil {
		return config.Config{}, err
	}
	if err := coordinator.deps.Config.Save(ctx, updated); err != nil {
		return config.Config{}, err
	}
	return updated, nil
}

func (coordinator *Coordinator) RecordCheckpoint(ctx context.Context, checkpoint state.VaultCheckpoint) error {
	if err := coordinator.lock(ctx); err != nil {
		return err
	}
	defer coordinator.mu.Unlock()
	return coordinator.deps.State.PutVaultCheckpoint(ctx, checkpoint)
}

func (coordinator *Coordinator) RecordBase(ctx context.Context, targetID string, entries []model.Entry) error {
	if err := coordinator.lock(ctx); err != nil {
		return err
	}
	defer coordinator.mu.Unlock()
	return coordinator.recordBaseLocked(ctx, targetID, entries)
}

func (coordinator *Coordinator) recordBaseLocked(ctx context.Context, targetID string, entries []model.Entry) error {
	now := coordinator.deps.Clock()
	for _, entry := range entries {
		if entry.TargetID != targetID {
			return errors.New("base entry belongs to a different target")
		}
		if err := entry.Validate(); err != nil {
			return err
		}
		var record state.BaseRecord
		var payload []byte
		if entry.File != nil {
			file := entry.File
			payload = append([]byte(nil), file.Content...)
			record = state.BaseRecord{
				Identity:    entry.Identity(),
				Fingerprint: state.NewFingerprint(string(file.State), file.Kind, file.Mode, file.LinkTarget, "", "", payload),
				RecordedAt:  now.Unix(),
			}
		} else {
			setting := entry.Setting
			valueType, valueText := "", ""
			if setting.Value != nil {
				valueType, valueText = setting.Value.Type, setting.Value.Text
				payload = []byte(valueType + "\x00" + valueText)
			}
			record = state.BaseRecord{
				Identity:    entry.Identity(),
				Fingerprint: state.NewSettingFingerprint(setting.State, valueType, valueText),
				RecordedAt:  now.Unix(),
			}
		}
		if _, err := coordinator.deps.State.PutAppliedBase(ctx, record, payload); err != nil {
			return err
		}
	}
	return nil
}

func (coordinator *Coordinator) Recover(ctx context.Context) (syncengine.RecoveryReport, error) {
	if err := coordinator.lock(ctx); err != nil {
		return syncengine.RecoveryReport{}, err
	}
	defer coordinator.mu.Unlock()
	filesystem := coordinator.deps.Filesystem
	if filesystem == nil {
		filesystem = files.DefaultApplyFileSystem()
	}
	settings := coordinator.settingsBackend()
	if closer, ok := settings.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	return syncengine.RecoverInterruptedWithSettings(ctx, coordinator.deps.State, filesystem, settings, coordinator.deps.Clock)
}

func (coordinator *Coordinator) settingsBackend() syncengine.SettingsBackend {
	if coordinator.deps.Settings == nil {
		return nil
	}
	return coordinator.deps.Settings.Backend()
}
