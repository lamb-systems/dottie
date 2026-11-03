//go:build linux && cgo && gsettings

package gnome

import (
	"context"
	"fmt"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useApplyOpener(t *testing.T, opener func(string, string) (*Settings, error)) {
	t.Helper()
	previous := openBackendSettings
	openBackendSettings = opener
	t.Cleanup(func() { openBackendSettings = previous })
}

func memorySettingsBackend(t *testing.T) (*SettingsBackend, string) {
	t.Helper()
	schemas := schemaDirectory(t)
	useApplyOpener(t, func(schemaID, path string) (*Settings, error) {
		return Open(schemas, schemaID, path, MemoryBackend, nil)
	})
	backend, err := NewSettingsBackend()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })
	return backend, schemas
}

func applySettingKey(schemaID, path, settingKey string) model.EntryKey {
	return model.EntryKey{
		TargetID:     "settings",
		Source:       model.SourceGNOME,
		SchemaID:     schemaID,
		SettingsPath: path,
		SettingKey:   settingKey,
	}
}

func TestSettingsBackendObserveSetResetAndReadBack(t *testing.T) {
	backend, _ := memorySettingsBackend(t)
	key := applySettingKey("org.dottie.Test", "/org/dottie/test/", "vendor-text")
	initial, err := backend.Observe(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, syncengine.SettingValue{Writable: true}, initial)

	require.NoError(t, backend.Set(context.Background(), key, "s", "'adapter-value'"))
	present, err := backend.Observe(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, syncengine.SettingValue{Present: true, Type: "s", Text: "'adapter-value'", Writable: true}, present)

	require.Error(t, backend.Set(context.Background(), key, "b", "true"), "wrong-type setting write was accepted")
	unchanged, err := backend.Observe(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, present, unchanged, "rejected wrong-type write changed the user value")

	require.NoError(t, backend.Reset(context.Background(), key))
	reset, err := backend.Observe(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, syncengine.SettingValue{Writable: true}, reset)
}

func TestSettingsBackendCanonicalize(t *testing.T) {
	backend, _ := memorySettingsBackend(t)
	for _, testCase := range []struct {
		name     string
		key      string
		typeName string
		text     string
		want     string
	}{
		{name: "trailing whitespace", key: "vendor-text", typeName: "s", text: "'canonical'  \t\n", want: "'canonical'"},
		{name: "annotated value", key: "items", typeName: "as", text: "@as []", want: "@as []"},
		{name: "empty container", key: "items", typeName: "as", text: "[]", want: "@as []"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key := applySettingKey("org.dottie.Test", "/org/dottie/test/", testCase.key)
			value, err := backend.Canonicalize(context.Background(), key, testCase.typeName, testCase.text)
			require.NoError(t, err)
			require.Equal(t, syncengine.SettingValue{Present: true, Type: testCase.typeName, Text: testCase.want}, value)
		})
	}
}

func TestSettingsBackendFixedAndRelocatablePaths(t *testing.T) {
	backend, _ := memorySettingsBackend(t)
	fixedKey := applySettingKey("org.dottie.Test", "/org/dottie/test/", "enabled")
	require.NoError(t, backend.Set(context.Background(), fixedKey, "b", "true"))
	fixed, err := backend.Observe(context.Background(), fixedKey)
	require.NoError(t, err)
	require.Equal(t, syncengine.SettingValue{Present: true, Type: "b", Text: "true", Writable: true}, fixed)

	relocatableKey := applySettingKey("org.dottie.Test.Relocatable", "/org/dottie/instance/", "label")
	relocatable, err := backend.Observe(context.Background(), relocatableKey)
	require.NoError(t, err)
	require.Equal(t, syncengine.SettingValue{Writable: true}, relocatable)
	require.NoError(t, backend.Set(context.Background(), relocatableKey, "s", "'relocated'"))
	got, err := backend.Observe(context.Background(), relocatableKey)
	require.NoError(t, err)
	require.Equal(t, syncengine.SettingValue{Present: true, Type: "s", Text: "'relocated'", Writable: true}, got)

	wrongPath := applySettingKey("org.dottie.Test", "/org/dottie/mismatch/", "enabled")
	_, err = backend.Observe(context.Background(), wrongPath)
	require.Error(t, err)
}

func TestSettingsBackendRejectsResolvedPathMismatch(t *testing.T) {
	schemas := schemaDirectory(t)
	useApplyOpener(t, func(schemaID, _ string) (*Settings, error) {
		return Open(schemas, schemaID, "/org/dottie/actual/", MemoryBackend, nil)
	})
	backend, err := NewSettingsBackend()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })
	key := applySettingKey("org.dottie.Test.Relocatable", "/org/dottie/requested/", "label")
	_, err = backend.Observe(context.Background(), key)
	require.Error(t, err)
	require.Empty(t, backend.handles)
}

func TestSettingsBackendNullAndMissingIdentities(t *testing.T) {
	schemas := schemaDirectory(t)
	useApplyOpener(t, func(schemaID, path string) (*Settings, error) {
		return Open(schemas, schemaID, path, NullBackend, nil)
	})
	backend, err := NewSettingsBackend()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	key := applySettingKey("org.dottie.Test", "/org/dottie/test/", "vendor-text")
	value, err := backend.Observe(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, syncengine.SettingValue{}, value)
	require.Error(t, backend.Set(context.Background(), key, "s", "'not-writable'"))

	missingKey := applySettingKey("org.dottie.Test", "/org/dottie/test/", "missing-key")
	_, err = backend.Observe(context.Background(), missingKey)
	require.ErrorIs(t, err, ErrKeyNotFound)
	missingSchema := applySettingKey("org.dottie.Missing", "/org/dottie/test/", "enabled")
	_, err = backend.Observe(context.Background(), missingSchema)
	require.ErrorIs(t, err, ErrSchemaNotFound)
	invalidSource := key
	invalidSource.Source = model.SourceFiles
	_, err = backend.Observe(context.Background(), invalidSource)
	require.Error(t, err)
}

func TestSettingsBackendHandleCacheIsBoundedAndClosed(t *testing.T) {
	backend, _ := memorySettingsBackend(t)
	for i := 0; i < maxBackendSettingsHandles; i++ {
		key := applySettingKey("org.dottie.Test.Relocatable", fmt.Sprintf("/org/dottie/instance-%d/", i), "label")
		_, err := backend.Observe(context.Background(), key)
		require.NoError(t, err)
	}
	require.Len(t, backend.handles, maxBackendSettingsHandles)
	overLimit := applySettingKey("org.dottie.Test.Relocatable", "/org/dottie/over-limit/", "label")
	_, err := backend.Observe(context.Background(), overLimit)
	require.Error(t, err)
	require.Len(t, backend.handles, maxBackendSettingsHandles)
	require.NoError(t, backend.Close())
	require.Empty(t, backend.handles)
	require.NoError(t, backend.Close())
	_, err = backend.Observe(context.Background(), overLimit)
	require.Error(t, err)
}
