//go:build linux && cgo && gsettings

package gnome

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixtureValue struct {
	Type string
	Text string
}

func categoryFixtureValues() map[matrix.KeyRef]fixtureValue {
	return map[matrix.KeyRef]fixtureValue{
		{SchemaID: "org.gnome.desktop.interface", Key: "gtk-theme"}:           {Type: "s", Text: "'User-Gtk'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "icon-theme"}:          {Type: "s", Text: "'User-Icons'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "cursor-theme"}:        {Type: "s", Text: "'User-Cursors'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "color-scheme"}:        {Type: "s", Text: "'prefer-dark'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "accent-color"}:        {Type: "s", Text: "'purple'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "font-name"}:           {Type: "s", Text: "'User Sans 12'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "document-font-name"}:  {Type: "s", Text: "'User Serif 12'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "monospace-font-name"}: {Type: "s", Text: "'User Mono 12'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "text-scaling-factor"}: {Type: "d", Text: "1.25"},
		{SchemaID: "org.gnome.desktop.interface", Key: "clock-format"}:        {Type: "s", Text: "'12h'"},
		{SchemaID: "org.gnome.desktop.interface", Key: "clock-show-date"}:     {Type: "b", Text: "false"},
		{SchemaID: "org.gnome.desktop.interface", Key: "clock-show-seconds"}:  {Type: "b", Text: "true"},
		{SchemaID: "org.gnome.desktop.interface", Key: "clock-show-weekday"}:  {Type: "b", Text: "true"},
		{SchemaID: "org.gnome.desktop.calendar", Key: "show-weekdate"}:        {Type: "b", Text: "true"},
	}
}

func TestShippedCategoriesCaptureFixtureValues(t *testing.T) {
	schemas := schemaDirectory(t)
	values := categoryFixtureValues()
	categories, err := matrix.Categories()
	require.NoError(t, err)
	require.Equal(t, len(values), countCategoryKeys(t, categories))
	for _, category := range categories {
		t.Run(category.ID, func(t *testing.T) {
			selected := categoryKeyRefs(category)
			useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
				settings, err := Open(schemas, schemaID, path, MemoryBackend, nil)
				if err != nil {
					return nil, err
				}
				for _, key := range selected {
					if key.SchemaID != schemaID {
						continue
					}
					value, ok := values[matrix.KeyRef{SchemaID: key.SchemaID, Key: key.Key}]
					if !ok {
						_ = settings.Close()
						return nil, fmt.Errorf("missing fixture value for %s/%s", key.SchemaID, key.Key)
					}
					if err := settings.Set(key.Key, value.Type, value.Text); err != nil {
						_ = settings.Close()
						return nil, err
					}
				}
				return settings, nil
			})
			result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
			require.NoError(t, err)
			require.Empty(t, result.Unknown)
			require.Empty(t, result.Errors)
			require.Len(t, result.Entries, len(selected))
			for _, entry := range result.Entries {
				require.NotNil(t, entry.Setting)
				expected := values[matrix.KeyRef{SchemaID: entry.Setting.SchemaID, Key: entry.Setting.Key}]
				assert.Equal(t, model.SettingPresent, entry.Setting.State)
				require.NotNil(t, entry.Setting.Value)
				assert.Equal(t, expected.Type, entry.Setting.Value.Type)
				assert.Equal(t, expected.Text, entry.Setting.Value.Text)
			}
		})
	}
}

func TestShippedCategoriesWithoutOverridesCaptureReset(t *testing.T) {
	schemas := schemaDirectory(t)
	categories, err := matrix.Categories()
	require.NoError(t, err)
	for _, category := range categories {
		t.Run(category.ID, func(t *testing.T) {
			selected := categoryKeyRefs(category)
			values := categoryFixtureValues()
			useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
				settings, err := Open(schemas, schemaID, path, MemoryBackend, nil)
				if err != nil {
					return nil, err
				}
				for _, key := range selected {
					if key.SchemaID != schemaID {
						continue
					}
					value := values[matrix.KeyRef{SchemaID: key.SchemaID, Key: key.Key}]
					if err := settings.Set(key.Key, value.Type, value.Text); err != nil {
						_ = settings.Close()
						return nil, err
					}
					if err := settings.Reset(key.Key); err != nil {
						_ = settings.Close()
						return nil, err
					}
				}
				return settings, nil
			})
			result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
			require.NoError(t, err)
			require.Empty(t, result.Unknown)
			require.Len(t, result.Entries, len(selected))
			for _, entry := range result.Entries {
				require.NotNil(t, entry.Setting)
				assert.Equal(t, model.SettingReset, entry.Setting.State)
				assert.Nil(t, entry.Setting.Value)
			}
		})
	}
}

func TestLaterCategoryKeysStayMissingOnOlderSurface(t *testing.T) {
	schemas := olderSchemaDirectory(t)
	selected, err := matrix.SelectCategories([]string{"appearance", "fonts", "clock"})
	require.NoError(t, err)
	categories, err := matrix.Categories()
	require.NoError(t, err)
	since := make(map[matrix.KeyRef]uint32)
	for _, category := range categories {
		for _, key := range category.Keys {
			since[key.KeyRef] = key.Since
		}
	}
	var expectedUnknown []KeyRef
	for _, key := range selected {
		if since[key] != 0 {
			expectedUnknown = append(expectedUnknown, key)
		}
	}
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		return Open(schemas, schemaID, path, MemoryBackend, nil)
	})
	result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
	require.NoError(t, err)
	require.Len(t, result.Entries, len(selected)-len(expectedUnknown))
	assert.Equal(t, expectedUnknown, result.Unknown)
	require.Len(t, result.Errors, len(expectedUnknown))
	for _, captureErr := range result.Errors {
		assert.Equal(t, CaptureMissingKey, captureErr.Reason)
	}
	for _, entry := range result.Entries {
		require.NotNil(t, entry.Setting)
		assert.Equal(t, model.SettingReset, entry.Setting.State)
		assert.Nil(t, entry.Setting.Value)
	}
}

func olderSchemaDirectory(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "locate native test source")
	fixture := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../tests/testdata/gsettings-older"))
	compiled := filepath.Join(t.TempDir(), "schemas")
	return compileSchemas(t, fixture, compiled)
}

func categoryKeyRefs(category matrix.Category) []KeyRef {
	keys := make([]KeyRef, len(category.Keys))
	for index, key := range category.Keys {
		keys[index] = key.KeyRef
	}
	return keys
}

func countCategoryKeys(t *testing.T, categories []matrix.Category) int {
	t.Helper()
	total := 0
	for _, category := range categories {
		total += len(category.Keys)
	}
	return total
}
