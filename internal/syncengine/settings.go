package syncengine

import (
	"context"
	"fmt"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/state"
)

type SettingValue struct {
	Present  bool
	Type     string
	Text     string
	Writable bool
}

type SettingsBackend interface {
	Observe(context.Context, model.EntryKey) (SettingValue, error)
	Canonicalize(context.Context, model.EntryKey, string, string) (SettingValue, error)
	Set(context.Context, model.EntryKey, string, string) error
	Reset(context.Context, model.EntryKey) error
}

func entryKeyName(key model.EntryKey) string {
	if key.Source == model.SourceGNOME {
		return key.SchemaID + "/" + key.SettingsPath + "/" + key.SettingKey
	}
	return key.FilePath
}

func settingFingerprint(observed SettingValue, key model.EntryKey) (state.Fingerprint, []byte, error) {
	if !observed.Present {
		return state.NewSettingFingerprint(model.SettingReset, "", ""), []byte{}, nil
	}
	value := &model.VariantValue{Type: observed.Type, Text: observed.Text}
	if err := (model.SettingEntry{SchemaID: key.SchemaID, Path: key.SettingsPath, Key: key.SettingKey, State: model.SettingPresent, Value: value}).Validate(); err != nil {
		return state.Fingerprint{}, nil, fmt.Errorf("invalid observed setting %s: %w", entryKeyName(key), err)
	}
	payload := []byte(observed.Type + "\x00" + observed.Text)
	return state.NewSettingFingerprint(model.SettingPresent, observed.Type, observed.Text), payload, nil
}

func settingValueMatchesFingerprint(observed SettingValue, key model.EntryKey, fingerprint state.Fingerprint) bool {
	if err := fingerprint.Validate(key); err != nil {
		return false
	}
	if fingerprint.State == string(model.SettingReset) {
		return fingerprint == state.NewSettingFingerprint(model.SettingReset, "", "") && !observed.Present
	}
	if fingerprint.State != string(model.SettingPresent) || !observed.Present {
		return false
	}
	if fingerprint != state.NewSettingFingerprint(model.SettingPresent, fingerprint.ValueType, fingerprint.ValueText) {
		return false
	}
	if _, _, err := settingFingerprint(observed, key); err != nil {
		return false
	}
	return observed.Type == fingerprint.ValueType && observed.Text == fingerprint.ValueText
}
