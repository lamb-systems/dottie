//go:build linux && cgo && gsettings

package gnome

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

const maxBackendSettingsHandles = 64

var openBackendSettings = OpenDefault

type settingsHandleKey struct {
	schemaID string
	path     string
}

type SettingsBackend struct {
	opMu    sync.RWMutex
	mu      sync.Mutex
	handles map[settingsHandleKey]*Settings
	closed  bool
}

var _ syncengine.SettingsBackend = (*SettingsBackend)(nil)

func NewSettingsBackend() (*SettingsBackend, error) {
	return &SettingsBackend{handles: make(map[settingsHandleKey]*Settings)}, nil
}

func (backend *SettingsBackend) Observe(ctx context.Context, key model.EntryKey) (syncengine.SettingValue, error) {
	backend.opMu.RLock()
	defer backend.opMu.RUnlock()
	if err := validateSettingsRequest(ctx, key); err != nil {
		return syncengine.SettingValue{}, err
	}
	settings, err := backend.settingsFor(key)
	if err != nil {
		return syncengine.SettingValue{}, err
	}
	value, err := settings.ReadUser(key.SettingKey)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return syncengine.SettingValue{}, fmt.Errorf("observe GNOME setting %q in schema %q: %w", key.SettingKey, key.SchemaID, ErrKeyNotFound)
		}
		return syncengine.SettingValue{}, fmt.Errorf("observe GNOME setting %q in schema %q: user value read failed", key.SettingKey, key.SchemaID)
	}
	return syncengine.SettingValue{Present: value.Present, Type: value.Type, Text: value.Text, Writable: value.Writable}, nil
}

func (backend *SettingsBackend) Canonicalize(ctx context.Context, key model.EntryKey, valueType, text string) (syncengine.SettingValue, error) {
	backend.opMu.RLock()
	defer backend.opMu.RUnlock()
	if err := validateSettingsRequest(ctx, key); err != nil {
		return syncengine.SettingValue{}, err
	}
	settings, err := backend.settingsFor(key)
	if err != nil {
		return syncengine.SettingValue{}, err
	}
	canonicalType, canonicalText, err := settings.Canonicalize(key.SettingKey, valueType, text)
	if err != nil {
		return syncengine.SettingValue{}, fmt.Errorf("canonicalize GNOME setting %q in schema %q: value rejected", key.SettingKey, key.SchemaID)
	}
	return syncengine.SettingValue{Present: true, Type: canonicalType, Text: canonicalText}, nil
}

func (backend *SettingsBackend) Set(ctx context.Context, key model.EntryKey, valueType, text string) error {
	backend.opMu.RLock()
	defer backend.opMu.RUnlock()
	if err := validateSettingsRequest(ctx, key); err != nil {
		return err
	}
	settings, err := backend.settingsFor(key)
	if err != nil {
		return err
	}
	if err := settings.Set(key.SettingKey, valueType, text); err != nil {
		return fmt.Errorf("set GNOME setting %q in schema %q: value rejected", key.SettingKey, key.SchemaID)
	}
	if err := settings.Sync(); err != nil {
		return fmt.Errorf("sync GNOME setting %q in schema %q: backend completion failed", key.SettingKey, key.SchemaID)
	}
	return nil
}

func (backend *SettingsBackend) Reset(ctx context.Context, key model.EntryKey) error {
	backend.opMu.RLock()
	defer backend.opMu.RUnlock()
	if err := validateSettingsRequest(ctx, key); err != nil {
		return err
	}
	settings, err := backend.settingsFor(key)
	if err != nil {
		return err
	}
	if err := settings.Reset(key.SettingKey); err != nil {
		return fmt.Errorf("reset GNOME setting %q in schema %q: operation failed", key.SettingKey, key.SchemaID)
	}
	if err := settings.Sync(); err != nil {
		return fmt.Errorf("sync GNOME setting %q in schema %q: backend completion failed", key.SettingKey, key.SchemaID)
	}
	return nil
}

func (backend *SettingsBackend) Close() error {
	backend.opMu.Lock()
	defer backend.opMu.Unlock()
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return nil
	}
	backend.closed = true
	var closeErrors []error
	for key, settings := range backend.handles {
		if err := settings.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close GNOME schema %q at %q: %w", key.schemaID, key.path, err))
		}
		delete(backend.handles, key)
	}
	return errors.Join(closeErrors...)
}

func (backend *SettingsBackend) settingsFor(key model.EntryKey) (*Settings, error) {
	cacheKey := settingsHandleKey{schemaID: key.SchemaID, path: key.SettingsPath}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return nil, errors.New("GNOME settings backend is closed")
	}
	if settings := backend.handles[cacheKey]; settings != nil {
		return settings, nil
	}
	if len(backend.handles) >= maxBackendSettingsHandles {
		return nil, fmt.Errorf("GNOME settings handle limit of %d reached", maxBackendSettingsHandles)
	}
	settings, err := openBackendSettings(key.SchemaID, key.SettingsPath)
	if err != nil {
		if errors.Is(err, ErrSchemaNotFound) {
			return nil, fmt.Errorf("open GNOME schema %q: %w", key.SchemaID, ErrSchemaNotFound)
		}
		return nil, fmt.Errorf("open GNOME schema %q: settings backend unavailable", key.SchemaID)
	}
	if settings == nil {
		return nil, fmt.Errorf("open GNOME schema %q: settings handle unavailable", key.SchemaID)
	}
	if settings.Path() != key.SettingsPath {
		_ = settings.Close()
		return nil, fmt.Errorf("open GNOME schema %q: resolved path does not match requested path", key.SchemaID)
	}
	backend.handles[cacheKey] = settings
	return settings, nil
}

func validateSettingsRequest(ctx context.Context, key model.EntryKey) error {
	if ctx == nil {
		return errors.New("GNOME settings context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := key.Validate(); err != nil || key.Source != model.SourceGNOME {
		return errors.New("invalid GNOME setting identity")
	}
	return nil
}
