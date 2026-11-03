//go:build linux && cgo && gsettings

package gnome

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useCaptureOpener(t *testing.T, opener func(string, string) (*Settings, error)) {
	t.Helper()
	previous := openSettings
	openSettings = opener
	t.Cleanup(func() { openSettings = previous })
}

func memoryCaptureOpener(t *testing.T, schemas string) {
	t.Helper()
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		return Open(schemas, schemaID, path, MemoryBackend, nil)
	})
}

func requireCaptureCoverage(t *testing.T, selected []KeyRef, result CaptureResult) {
	t.Helper()
	seen := make(map[KeyRef]int, len(selected))
	for _, entry := range result.Entries {
		require.NotNil(t, entry.Setting)
		for _, key := range selected {
			if key.SchemaID == entry.Setting.SchemaID && key.Key == entry.Setting.Key && (key.Path == "" || key.Path == entry.Setting.Path) {
				seen[key]++
			}
		}
	}
	for _, key := range result.Unknown {
		seen[key]++
	}
	for _, key := range selected {
		assert.Equal(t, 1, seen[key], "selected key must appear exactly once: %#v", key)
	}
}

func TestCaptureMemoryPreservesUserAndReset(t *testing.T) {
	schemas := schemaDirectory(t)
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		settings, err := Open(schemas, schemaID, path, MemoryBackend, nil)
		if err != nil {
			return nil, err
		}
		if schemaID == "org.dottie.Test" {
			for _, value := range []struct{ key, variantType, text string }{
				{"vendor-text", "s", "'user-value'"},
				{"enabled", "b", "false"},
				{"pair", "(is)", "(7, 'seven')"},
			} {
				if err := settings.Set(value.key, value.variantType, value.text); err != nil {
					_ = settings.Close()
					return nil, err
				}
			}
		}
		return settings, nil
	})
	selected := []KeyRef{
		{SchemaID: "org.dottie.Test", Key: "vendor-text"},
		{SchemaID: "org.dottie.Test", Key: "limited"},
		{SchemaID: "org.dottie.Test", Key: "pair"},
		{SchemaID: "org.dottie.Test", Key: "enabled"},
	}
	result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
	require.NoError(t, err)
	require.Empty(t, result.Unknown)
	require.Empty(t, result.Errors)
	require.Len(t, result.Entries, 4)
	requireCaptureCoverage(t, selected, result)
	wantKeys := []string{"enabled", "limited", "pair", "vendor-text"}
	for index, entry := range result.Entries {
		require.NoError(t, entry.Validate())
		require.NoError(t, entry.Identity().Validate())
		assert.Equal(t, wantKeys[index], entry.Setting.Key)
		assert.Equal(t, "/org/dottie/test/", entry.Setting.Path)
	}
	assert.Equal(t, model.SettingPresent, result.Entries[0].Setting.State)
	assert.Equal(t, &model.VariantValue{Type: "b", Text: "false"}, result.Entries[0].Setting.Value)
	assert.Equal(t, model.SettingReset, result.Entries[1].Setting.State)
	assert.Nil(t, result.Entries[1].Setting.Value)
	assert.Equal(t, model.SettingPresent, result.Entries[2].Setting.State)
	assert.Equal(t, &model.VariantValue{Type: "(is)", Text: "(7, 'seven')"}, result.Entries[2].Setting.Value)
	assert.Equal(t, &model.VariantValue{Type: "s", Text: "'user-value'"}, result.Entries[3].Setting.Value)
}

func TestCaptureFieldLengthBoundaries(t *testing.T) {
	schemaID := strings.Repeat("s", model.MaxSettingSchemaIDBytes)
	key := strings.Repeat("k", model.MaxSettingKeyBytes)
	path := "/" + strings.Repeat("p", model.MaxRelativePathBytes-2) + "/"
	opened := false
	useCaptureOpener(t, func(gotSchemaID, gotPath string) (*Settings, error) {
		opened = true
		assert.Equal(t, schemaID, gotSchemaID)
		assert.Equal(t, path, gotPath)
		return nil, ErrSchemaNotFound
	})
	selected := []KeyRef{{SchemaID: schemaID, Path: path, Key: key}}
	result, err := Capture(context.Background(), CaptureRequest{TargetID: strings.Repeat("t", model.MaxTargetIDBytes), Keys: selected})
	require.NoError(t, err)
	require.True(t, opened)
	require.Equal(t, selected, result.Unknown)
	require.Equal(t, []CaptureError{{Key: selected[0], Reason: CaptureMissingSchema}}, result.Errors)
	requireCaptureCoverage(t, selected, result)
}

func TestCaptureGroupsHandlesAndAccepts256Keys(t *testing.T) {
	schemas := schemaDirectory(t)
	opens := 0
	memoryCaptureOpener(t, schemas)
	delegate := openSettings
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		opens++
		return delegate(schemaID, path)
	})
	keys := make([]KeyRef, 256)
	for index := range keys {
		keys[index] = KeyRef{SchemaID: "org.dottie.Test", Key: fmt.Sprintf("missing-%03d", index)}
	}
	result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: keys})
	require.NoError(t, err)
	assert.Equal(t, 1, opens, "one handle must serve all keys for a schema/path")
	require.Empty(t, result.Entries)
	require.Len(t, result.Unknown, 256)
	require.Len(t, result.Errors, 256)
	for index, key := range result.Unknown {
		assert.Equal(t, keys[index].Key, key.Key)
		assert.Equal(t, CaptureMissingKey, result.Errors[index].Reason)
	}
	requireCaptureCoverage(t, keys, result)
}

func TestCaptureMixedMissingSchemaAndKeyKeepsCoverage(t *testing.T) {
	schemas := schemaDirectory(t)
	memoryCaptureOpener(t, schemas)
	selected := []KeyRef{
		{SchemaID: "org.dottie.Test", Key: "enabled"},
		{SchemaID: "org.dottie.Test", Key: "not-present"},
		{SchemaID: "org.dottie.Unknown", Key: "anything"},
	}
	result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)
	require.Len(t, result.Unknown, 2)
	require.Len(t, result.Errors, 2)
	requireCaptureCoverage(t, selected, result)
	assert.Equal(t, CaptureMissingKey, result.Errors[0].Reason)
	assert.Equal(t, CaptureMissingSchema, result.Errors[1].Reason)
	assert.Equal(t, selected[1], result.Unknown[0])
	assert.Equal(t, selected[2], result.Unknown[1])
}

func TestCaptureOversizedRenderedValueIsUnknown(t *testing.T) {
	schemas := schemaDirectory(t)
	compactItems := "[" + strings.TrimSuffix(strings.Repeat("'x',", 14000), ",") + "]"
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		settings, err := Open(schemas, schemaID, path, MemoryBackend, nil)
		if err != nil {
			return nil, err
		}
		if err := settings.Set("items", "as", compactItems); err != nil {
			_ = settings.Close()
			return nil, err
		}
		return settings, nil
	})
	selected := []KeyRef{{SchemaID: "org.dottie.Test", Key: "items"}}
	result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
	require.NoError(t, err)
	require.Empty(t, result.Entries)
	require.Equal(t, selected, result.Unknown)
	require.Equal(t, []CaptureError{{Key: selected[0], Reason: CaptureReadFailed}}, result.Errors)
	requireCaptureCoverage(t, selected, result)
}

func TestCaptureNullBackendDoesNotEmitReset(t *testing.T) {
	schemas := schemaDirectory(t)
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		return Open(schemas, schemaID, path, NullBackend, nil)
	})
	selected := []KeyRef{{SchemaID: "org.dottie.Test", Key: "enabled"}}
	result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
	require.NoError(t, err)
	require.Empty(t, result.Entries)
	require.Equal(t, selected, result.Unknown)
	require.Equal(t, []CaptureError{{Key: selected[0], Reason: CaptureNotWritable}}, result.Errors)
	requireCaptureCoverage(t, selected, result)
}

func TestCaptureValidatesRequestBeforeOpening(t *testing.T) {
	opens := 0
	useCaptureOpener(t, func(string, string) (*Settings, error) {
		opens++
		return nil, errors.New("unexpected open")
	})
	valid := KeyRef{SchemaID: "org.dottie.Test", Key: "enabled"}
	invalid := []struct {
		name    string
		request CaptureRequest
	}{
		{name: "empty-target", request: CaptureRequest{Keys: []KeyRef{valid}}},
		{name: "control-target", request: CaptureRequest{TargetID: "bad\ntarget", Keys: []KeyRef{valid}}},
		{name: "empty-schema", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{Key: "enabled"}}}},
		{name: "oversized-schema", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: strings.Repeat("s", model.MaxSettingSchemaIDBytes+1), Key: "enabled"}}}},
		{name: "control-schema", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie\x01Test", Key: "enabled"}}}},
		{name: "empty-key", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test"}}}},
		{name: "oversized-key", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test", Key: strings.Repeat("k", model.MaxSettingKeyBytes+1)}}}},
		{name: "key-control", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test", Key: "bad\x7fkey"}}}},
		{name: "key-separator", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test", Key: "bad/key"}}}},
		{name: "oversized-path", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test.Relocatable", Path: "/" + strings.Repeat("p", model.MaxRelativePathBytes-1) + "/", Key: "label"}}}},
		{name: "relative-path", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test.Relocatable", Path: "org/dottie/", Key: "label"}}}},
		{name: "double-slash-path", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test.Relocatable", Path: "/org//dottie/", Key: "label"}}}},
		{name: "path-control", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test.Relocatable", Path: "/org/\x00/dottie/", Key: "label"}}}},
		{name: "duplicate", request: CaptureRequest{TargetID: "desktop", Keys: []KeyRef{valid, valid}}},
		{name: "257-keys", request: CaptureRequest{TargetID: "desktop", Keys: make([]KeyRef, 257)}},
	}
	for _, testCase := range invalid {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := Capture(context.Background(), testCase.request)
			require.Error(t, err)
			assert.Empty(t, result.Entries)
			assert.Empty(t, result.Unknown)
			assert.Empty(t, result.Errors)
		})
	}
	assert.Zero(t, opens, "invalid requests must be rejected before settings I/O")
}

func TestCaptureRejectsFixedPathAndRequiresRelocatablePath(t *testing.T) {
	schemas := schemaDirectory(t)
	memoryCaptureOpener(t, schemas)
	for _, key := range []KeyRef{
		{SchemaID: "org.dottie.Test", Path: "/org/dottie/test/", Key: "enabled"},
		{SchemaID: "org.dottie.Test.Relocatable", Key: "label"},
	} {
		result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: []KeyRef{key}})
		require.Error(t, err)
		assert.Empty(t, result.Entries)
		assert.Empty(t, result.Unknown)
	}
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		return Open(schemas, schemaID, path, MemoryBackend, nil)
	})
	selected := []KeyRef{{SchemaID: "org.dottie.Test.Relocatable", Path: "/org/dottie/instance/", Key: "label"}}
	result, err := Capture(context.Background(), CaptureRequest{TargetID: "desktop", Keys: selected})
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)
	assert.Equal(t, selected[0].Path, result.Entries[0].Setting.Path)
	requireCaptureCoverage(t, selected, result)
}

func TestCaptureHonorsCancellationAfterOpening(t *testing.T) {
	schemas := schemaDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	var opened *Settings
	useCaptureOpener(t, func(schemaID, path string) (*Settings, error) {
		settings, err := Open(schemas, schemaID, path, MemoryBackend, nil)
		if err == nil {
			opened = settings
			cancel()
		}
		return settings, err
	})
	result, err := Capture(ctx, CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test", Key: "enabled"}}})
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, result.Entries)
	assert.Empty(t, result.Unknown)
	require.NotNil(t, opened)
	_, err = opened.ReadUser("enabled")
	require.Error(t, err, "canceled capture did not close its handle")
}

func TestCaptureCanceledBeforeOpening(t *testing.T) {
	opens := 0
	useCaptureOpener(t, func(string, string) (*Settings, error) {
		opens++
		return nil, errors.New("unexpected open")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Capture(ctx, CaptureRequest{TargetID: "desktop", Keys: []KeyRef{{SchemaID: "org.dottie.Test", Key: "enabled"}}})
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, result.Entries)
	assert.Zero(t, opens)
}
