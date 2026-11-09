package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publicationCaptureGNOMESettings struct {
	resolveCalls int
	captureCalls int
	backendCalls int
	resolve      func(context.Context, string, string, string, int) (string, error)
	capture      func(context.Context, string, []SettingRef) (SettingsCapture, error)
}

func (settings *publicationCaptureGNOMESettings) Resolve(ctx context.Context, targetID, schemaID, path string) (string, error) {
	settings.resolveCalls++
	if settings.resolve != nil {
		return settings.resolve(ctx, targetID, schemaID, path, settings.resolveCalls)
	}
	return "/synthetic/", nil
}

func (settings *publicationCaptureGNOMESettings) Capture(ctx context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
	settings.captureCalls++
	if settings.capture == nil {
		return SettingsCapture{}, nil
	}
	return settings.capture(ctx, targetID, refs)
}

func (settings *publicationCaptureGNOMESettings) Backend() syncengine.SettingsBackend {
	settings.backendCalls++
	return nil
}

func publicationCaptureGNOMESelectionFor(t *testing.T, settings *publicationCaptureGNOMESettings, targetID string) (publicationSelectionFixture, publicationSelection) {
	t.Helper()
	fixture := newPublicationSelectionFixture(t)
	target := newApprovedPublicationGNOMETarget(t, targetID, []string{"clock"})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(fixture.paths, fixture.capture, settings)
	require.NoError(t, err)
	selection, err := selectPublicationTarget(context.Background(), local, configuration, target.ID, model.Target{ID: target.ID, Source: model.SourceGNOME, SourceVersion: model.SourceVersion})
	require.NoError(t, err)
	settings.resolveCalls = 0
	settings.captureCalls = 0
	settings.backendCalls = 0
	return fixture, selection
}

func publicationCaptureGNOMEEntry(targetID string, ref SettingRef, state model.SettingState, value *model.VariantValue) model.Entry {
	return model.Entry{TargetID: targetID, Setting: &model.SettingEntry{SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key, State: state, Value: value}}
}

func publicationCaptureGNOMEUnknown(targetID string, ref SettingRef) model.EntryKey {
	return model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}
}

func assertPublicationCaptureGNOMEError(t *testing.T, err error, reason string) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublicationReconciliation)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, "capture", classified.Stage())
	assert.Equal(t, reason, classified.Reason())
}

func TestCapturePublicationGNOMEEmitsCompletePresentAndResetInCanonicalOrder(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	fixture, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
	refs := append([]SettingRef(nil), selection.settingRefs...)
	settings.capture = func(_ context.Context, targetID string, got []SettingRef) (SettingsCapture, error) {
		assert.Equal(t, refs, got)
		entries := []model.Entry{
			publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingPresent, &model.VariantValue{Type: "s", Text: "'synthetic'"}),
			publicationCaptureGNOMEEntry(targetID, refs[1], model.SettingReset, nil),
		}
		for _, ref := range refs[2:] {
			entries = append(entries, publicationCaptureGNOMEEntry(targetID, ref, model.SettingReset, nil))
		}
		for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
			entries[left], entries[right] = entries[right], entries[left]
		}
		return SettingsCapture{Entries: entries}, nil
	}

	captured, err := capturePublicationGNOME(context.Background(), selection)
	require.NoError(t, err)
	require.Len(t, captured.observations, len(refs))
	assert.True(t, captured.complete)
	for index, ref := range refs {
		assert.Equal(t, publicationCaptureGNOMEUnknown("desktop", ref), captured.observations[index].Identity)
		assert.Equal(t, model.ObservationPresent, captured.observations[index].State)
		assert.NoError(t, captured.observations[index].Validate())
		assert.Equal(t, ref, SettingRef{SchemaID: captured.observations[index].Entry.Setting.SchemaID, Path: captured.observations[index].Entry.Setting.Path, Key: captured.observations[index].Entry.Setting.Key})
	}
	assert.Equal(t, model.SettingPresent, captured.observations[0].Entry.Setting.State)
	assert.Equal(t, &model.VariantValue{Type: "s", Text: "'synthetic'"}, captured.observations[0].Entry.Setting.Value)
	assert.Equal(t, model.SettingReset, captured.observations[1].Entry.Setting.State)
	assert.Nil(t, captured.observations[1].Entry.Setting.Value)
	assert.Equal(t, 2*len(refs), settings.resolveCalls)
	assert.Equal(t, 1, settings.captureCalls)
	assert.Zero(t, settings.backendCalls)
	assert.Zero(t, fixture.capture.calls)
}

func TestCapturePublicationGNOMEAccountsForUnknownAndOmittedRefs(t *testing.T) {
	for _, test := range []struct {
		name    string
		capture func(string, []SettingRef) SettingsCapture
	}{
		{
			name: "explicit unknown and partial omission",
			capture: func(targetID string, refs []SettingRef) SettingsCapture {
				return SettingsCapture{
					Entries: []model.Entry{publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingReset, nil)},
					Unknown: []model.EntryKey{publicationCaptureGNOMEUnknown(targetID, refs[1])},
				}
			},
		},
		{name: "empty producer output", capture: func(string, []SettingRef) SettingsCapture { return SettingsCapture{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := &publicationCaptureGNOMESettings{}
			_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
			refs := append([]SettingRef(nil), selection.settingRefs...)
			settings.capture = func(_ context.Context, targetID string, _ []SettingRef) (SettingsCapture, error) {
				return test.capture(targetID, refs), nil
			}
			captured, err := capturePublicationGNOME(context.Background(), selection)
			require.NoError(t, err)
			require.Len(t, captured.observations, len(refs))
			assert.False(t, captured.complete)
			for index, observation := range captured.observations {
				assert.Equal(t, publicationCaptureGNOMEUnknown("desktop", refs[index]), observation.Identity)
				if index == 0 && test.name == "explicit unknown and partial omission" {
					assert.Equal(t, model.ObservationPresent, observation.State)
					assert.Equal(t, model.SettingReset, observation.Entry.Setting.State)
				} else {
					assert.Equal(t, model.ObservationUnknown, observation.State)
					assert.Nil(t, observation.Entry)
				}
			}
		})
	}
}

func TestCapturePublicationGNOMERejectsMalformedProducerResults(t *testing.T) {
	for _, test := range []struct {
		name   string
		result func(string, []SettingRef) SettingsCapture
	}{
		{name: "duplicate entries", result: func(id string, refs []SettingRef) SettingsCapture {
			entry := publicationCaptureGNOMEEntry(id, refs[0], model.SettingReset, nil)
			return SettingsCapture{Entries: []model.Entry{entry, entry}}
		}},
		{name: "duplicate unknown", result: func(id string, refs []SettingRef) SettingsCapture {
			key := publicationCaptureGNOMEUnknown(id, refs[0])
			return SettingsCapture{Unknown: []model.EntryKey{key, key}}
		}},
		{name: "entry and unknown overlap", result: func(id string, refs []SettingRef) SettingsCapture {
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(id, refs[0], model.SettingReset, nil)}, Unknown: []model.EntryKey{publicationCaptureGNOMEUnknown(id, refs[0])}}
		}},
		{name: "foreign target", result: func(_ string, refs []SettingRef) SettingsCapture {
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry("foreign-target", refs[0], model.SettingReset, nil)}}
		}},
		{name: "wrong source", result: func(id string, refs []SettingRef) SettingsCapture {
			return SettingsCapture{Unknown: []model.EntryKey{{TargetID: id, Source: model.SourceFiles, FilePath: "file"}}}
		}},
		{name: "foreign schema", result: func(id string, refs []SettingRef) SettingsCapture {
			ref := refs[0]
			ref.SchemaID = "org.example.Foreign"
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(id, ref, model.SettingReset, nil)}}
		}},
		{name: "foreign key", result: func(id string, refs []SettingRef) SettingsCapture {
			ref := refs[0]
			ref.Key = "foreign-key"
			return SettingsCapture{Unknown: []model.EntryKey{publicationCaptureGNOMEUnknown(id, ref)}}
		}},
		{name: "foreign path", result: func(id string, refs []SettingRef) SettingsCapture {
			ref := refs[0]
			ref.Path = "/foreign/"
			return SettingsCapture{Unknown: []model.EntryKey{publicationCaptureGNOMEUnknown(id, ref)}}
		}},
		{name: "control character locator", result: func(id string, refs []SettingRef) SettingsCapture {
			ref := refs[0]
			ref.Path = "/synthetic/\n"
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(id, ref, model.SettingReset, nil)}}
		}},
		{name: "file payload", result: func(id string, _ []SettingRef) SettingsCapture {
			return SettingsCapture{Entries: []model.Entry{{TargetID: id, File: &model.FileEntry{Path: "file", State: model.FilePresent, Kind: model.FileRegular, Content: []byte{}}}}}
		}},
		{name: "present without value", result: func(id string, refs []SettingRef) SettingsCapture {
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(id, refs[0], model.SettingPresent, nil)}}
		}},
		{name: "reset with value", result: func(id string, refs []SettingRef) SettingsCapture {
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(id, refs[0], model.SettingReset, &model.VariantValue{Type: "s", Text: "'x'"})}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := &publicationCaptureGNOMESettings{}
			_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
			refs := append([]SettingRef(nil), selection.settingRefs...)
			settings.capture = func(_ context.Context, targetID string, _ []SettingRef) (SettingsCapture, error) {
				return test.result(targetID, refs), nil
			}
			captured, err := capturePublicationGNOME(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonProvider))
			assert.Equal(t, 1, settings.captureCalls)
		})
	}
}

func TestCapturePublicationGNOMEUsesPerValueBoundsBeforeAdmission(t *testing.T) {
	for _, test := range []struct {
		name     string
		typeText string
		value    string
		wantErr  bool
	}{
		{name: "maximum type and text", typeText: strings.Repeat("t", model.MaxVariantTypeBytes), value: strings.Repeat("v", model.MaxVariantTextBytes)},
		{name: "type over maximum", typeText: strings.Repeat("t", model.MaxVariantTypeBytes+1), value: "x", wantErr: true},
		{name: "text over maximum", typeText: "s", value: strings.Repeat("v", model.MaxVariantTextBytes+1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := &publicationCaptureGNOMESettings{}
			_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
			ref := selection.settingRefs[0]
			settings.capture = func(_ context.Context, targetID string, _ []SettingRef) (SettingsCapture, error) {
				entry := publicationCaptureGNOMEEntry(targetID, ref, model.SettingPresent, &model.VariantValue{Type: test.typeText, Text: test.value})
				return SettingsCapture{Entries: []model.Entry{entry}}, nil
			}
			captured, err := capturePublicationGNOME(context.Background(), selection)
			if test.wantErr {
				assert.Equal(t, publicationCapture{}, captured)
				assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonBounds))
				return
			}
			require.NoError(t, err)
			assert.False(t, captured.complete)
			assert.Equal(t, test.typeText, captured.observations[0].Entry.Setting.Value.Type)
			assert.Equal(t, test.value, captured.observations[0].Entry.Setting.Value.Text)
		})
	}
}

func TestCapturePublicationGNOMEDetachesCallbackRefsAndReturnedPointers(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
	originalRefs := append([]SettingRef(nil), selection.settingRefs...)
	producerValue := &model.VariantValue{Type: "s", Text: "'original'"}
	producerSetting := &model.SettingEntry{SchemaID: originalRefs[0].SchemaID, Path: originalRefs[0].Path, Key: originalRefs[0].Key, State: model.SettingPresent, Value: producerValue}
	producerEntry := model.Entry{TargetID: "desktop", Setting: producerSetting}
	settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
		refs[0] = SettingRef{SchemaID: "mutated", Path: "/mutated/", Key: "mutated"}
		entry := producerEntry
		entry.TargetID = targetID
		return SettingsCapture{Entries: []model.Entry{entry}}, nil
	}
	first, err := capturePublicationGNOME(context.Background(), selection)
	require.NoError(t, err)
	second, err := capturePublicationGNOME(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, originalRefs, selection.settingRefs)
	assert.Equal(t, originalRefs[0].Key, first.observations[0].Identity.SettingKey)
	assert.NotSame(t, producerEntry.Setting, first.observations[0].Entry.Setting)
	assert.NotSame(t, producerValue, first.observations[0].Entry.Setting.Value)
	assert.NotSame(t, first.observations[0].Entry, second.observations[0].Entry)
	assert.NotSame(t, first.observations[0].Entry.Setting, second.observations[0].Entry.Setting)
	assert.NotSame(t, first.observations[0].Entry.Setting.Value, second.observations[0].Entry.Setting.Value)

	producerValue.Text = "'producer-mutated'"
	producerSetting.Key = "producer-mutated"
	producerEntry.TargetID = "producer-mutated"
	assert.Equal(t, "'original'", first.observations[0].Entry.Setting.Value.Text)
	assert.Equal(t, originalRefs[0].Key, second.observations[0].Entry.Setting.Key)
	first.observations[0].Entry.Setting.Value.Text = "'first-result-mutated'"
	first.observations[0].Entry.Setting.Key = "first-result-mutated"
	assert.Equal(t, "'original'", second.observations[0].Entry.Setting.Value.Text)
	assert.Equal(t, originalRefs[0].Key, second.observations[0].Entry.Setting.Key)
}

func TestCapturePublicationGNOMERevalidatesResolvedRefsBeforeAndAfterCapture(t *testing.T) {
	t.Run("pre-capture drift skips callback", func(t *testing.T) {
		var selectionDone bool
		settings := &publicationCaptureGNOMESettings{resolve: func(_ context.Context, _, _, _ string, call int) (string, error) {
			if selectionDone && call > 0 {
				return "/changed/", nil
			}
			return "/synthetic/", nil
		}}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
		selectionDone = true
		captured, err := capturePublicationGNOME(context.Background(), selection)
		assert.Equal(t, publicationCapture{}, captured)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureGNOMESettingsChanged))
		assert.Zero(t, settings.captureCalls)
	})

	t.Run("pre-capture resolver error", func(t *testing.T) {
		fail := false
		settings := &publicationCaptureGNOMESettings{resolve: func(context.Context, string, string, string, int) (string, error) {
			if fail {
				return "", errors.New("private-resolver-canary")
			}
			return "/synthetic/", nil
		}}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "private-target-canary")
		fail = true
		captured, err := capturePublicationGNOME(context.Background(), selection)
		assert.Equal(t, publicationCapture{}, captured)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureGNOMESettingsChanged))
		assert.Zero(t, settings.captureCalls)
		assert.NotContains(t, err.Error(), "private-resolver-canary")
		assert.NotContains(t, err.Error(), "private-target-canary")
		assert.False(t, errors.Is(err, context.Canceled))
		assert.False(t, errors.Is(err, context.DeadlineExceeded))
	})

	t.Run("post-capture path drift discards output", func(t *testing.T) {
		changed := false
		settings := &publicationCaptureGNOMESettings{resolve: func(_ context.Context, _, _, _ string, _ int) (string, error) {
			if changed {
				return "/changed/", nil
			}
			return "/synthetic/", nil
		}}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			changed = true
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingReset, nil)}}, nil
		}
		captured, err := capturePublicationGNOME(context.Background(), selection)
		assert.Equal(t, publicationCapture{}, captured)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureGNOMESettingsChanged))
	})

	t.Run("post-capture resolver error", func(t *testing.T) {
		fail := false
		settings := &publicationCaptureGNOMESettings{resolve: func(context.Context, string, string, string, int) (string, error) {
			if fail {
				return "", errors.New("private-post-resolver-canary")
			}
			return "/synthetic/", nil
		}}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			fail = true
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingReset, nil)}}, nil
		}
		captured, err := capturePublicationGNOME(context.Background(), selection)
		assert.Equal(t, publicationCapture{}, captured)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureGNOMESettingsChanged))
		assert.NotContains(t, err.Error(), "private-post-resolver-canary")
		assert.False(t, errors.Is(err, context.Canceled))
		assert.False(t, errors.Is(err, context.DeadlineExceeded))
	})
}

func TestCapturePublicationGNOMEResolverCancellationClassifiesSafely(t *testing.T) {
	for _, phase := range []string{"pre", "post"} {
		for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
			for _, wrapped := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/wrapped-%t", phase, sentinel, wrapped)
				t.Run(name, func(t *testing.T) {
					resolverCanary := "private-resolver-cause-canary"
					var resolverErr error
					settings := &publicationCaptureGNOMESettings{resolve: func(ctx context.Context, _, _, _ string, _ int) (string, error) {
						assert.NoError(t, ctx.Err(), "the supplied context remains live during resolver failure")
						if resolverErr != nil {
							return "", resolverErr
						}
						return "/synthetic/", nil
					}}
					fixture, selection := publicationCaptureGNOMESelectionFor(t, settings, "private-target-canary")
					cause := sentinel
					if wrapped {
						cause = fmt.Errorf("%s: %w", resolverCanary, sentinel)
					}
					if phase == "pre" {
						resolverErr = cause
					} else {
						settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
							resolverErr = cause
							value := &model.VariantValue{Type: "s", Text: "'resolver-value-canary'"}
							return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingPresent, value)}}, nil
						}
					}

					ctx := context.Background()
					captured, err := capturePublicationGNOME(ctx, selection)
					assert.Equal(t, publicationCapture{}, captured)
					assert.ErrorIs(t, err, sentinel)
					assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonCanceled))
					assert.Nil(t, errors.Unwrap(err), "the raw resolver error must not be in the unwrap chain")
					assert.NotContains(t, err.Error(), resolverCanary)
					assert.NotContains(t, err.Error(), "private-target-canary")
					assert.NotContains(t, err.Error(), "resolver-value-canary")
					assert.NotContains(t, err.Error(), selection.settingRefs[0].SchemaID)
					assert.Zero(t, settings.backendCalls)
					assert.Zero(t, fixture.capture.calls)
					if phase == "pre" {
						assert.Zero(t, settings.captureCalls)
						assert.Equal(t, 1, settings.resolveCalls)
					} else {
						assert.Equal(t, 1, settings.captureCalls)
						assert.Equal(t, len(selection.settingRefs)+1, settings.resolveCalls)
					}

					captureCalls := settings.captureCalls
					ordinaryCanary := "private-next-resolver-error-canary"
					resolverErr = errors.New(ordinaryCanary)
					ordinary, ordinaryErr := capturePublicationGNOME(ctx, selection)
					assert.Equal(t, publicationCapture{}, ordinary)
					assertPublicationCaptureGNOMEError(t, ordinaryErr, string(publicationCaptureGNOMESettingsChanged))
					assert.False(t, errors.Is(ordinaryErr, context.Canceled))
					assert.False(t, errors.Is(ordinaryErr, context.DeadlineExceeded))
					assert.Nil(t, errors.Unwrap(ordinaryErr), "ordinary resolver errors must not be exposed")
					assert.NotContains(t, ordinaryErr.Error(), ordinaryCanary)
					assert.NotContains(t, ordinaryErr.Error(), resolverCanary)
					assert.NotContains(t, ordinaryErr.Error(), "private-target-canary")
					assert.NotContains(t, ordinaryErr.Error(), "resolver-value-canary")
					assert.NotContains(t, ordinaryErr.Error(), selection.settingRefs[0].SchemaID)
					assert.Equal(t, captureCalls, settings.captureCalls)
					assert.Zero(t, settings.backendCalls)
					assert.Zero(t, fixture.capture.calls)

					resolverErr = nil
					settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
						entries := make([]model.Entry, 0, len(refs))
						for _, ref := range refs {
							entries = append(entries, publicationCaptureGNOMEEntry(targetID, ref, model.SettingReset, nil))
						}
						return SettingsCapture{Entries: entries}, nil
					}
					healthy, healthyErr := capturePublicationGNOME(ctx, selection)
					require.NoError(t, healthyErr)
					assert.True(t, healthy.complete, "a safe-cause value from one check must not poison a later healthy operation")
					assert.Len(t, healthy.observations, len(selection.settingRefs))
				})
			}
		}
	}
}

func TestCapturePublicationGNOMEClearsPartialErrorsAndKeepsOnlyCancellation(t *testing.T) {
	t.Run("provider partial output and error canary", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "private-target-canary")
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingReset, nil)}}, errors.New("private-value-path-provider-canary")
		}
		captured, err := capturePublicationGNOME(context.Background(), selection)
		assert.Equal(t, publicationCapture{}, captured)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonProvider))
		assert.NotContains(t, err.Error(), "private-value-path-provider-canary")
		assert.NotContains(t, err.Error(), "private-target-canary")
	})

	t.Run("provider cancellation", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingReset, nil)}}, context.Canceled
		}
		captured, err := capturePublicationGNOME(context.Background(), selection)
		assert.Equal(t, publicationCapture{}, captured)
		assert.ErrorIs(t, err, context.Canceled)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonCanceled))
	})

	t.Run("pre-cancellation avoids ports", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
		settings.resolveCalls = 0
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		captured, err := capturePublicationGNOME(ctx, selection)
		assert.Equal(t, publicationCapture{}, captured)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonCanceled))
		assert.Zero(t, settings.resolveCalls)
		assert.Zero(t, settings.captureCalls)
	})

	t.Run("deadline classification", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
		settings.capture = func(context.Context, string, []SettingRef) (SettingsCapture, error) {
			return SettingsCapture{}, fmt.Errorf("opaque deadline: %w", context.DeadlineExceeded)
		}
		captured, err := capturePublicationGNOME(context.Background(), selection)
		assert.Equal(t, publicationCapture{}, captured)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonCanceled))
	})
}

func TestCapturePublicationGNOMERejectsInvalidSelectedInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*publicationSelection)
	}{
		{name: "missing context", mutate: func(selection *publicationSelection) { selection.context = nil }},
		{name: "missing settings port", mutate: func(selection *publicationSelection) { selection.context.settings = nil }},
		{name: "missing refs", mutate: func(selection *publicationSelection) { selection.settingRefs = nil }},
		{name: "duplicate refs", mutate: func(selection *publicationSelection) { selection.settingRefs[1] = selection.settingRefs[0] }},
		{name: "portable mismatch", mutate: func(selection *publicationSelection) { selection.portable.ID = "other" }},
		{name: "file source", mutate: func(selection *publicationSelection) { selection.target.Source = model.SourceFiles }},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := &publicationCaptureGNOMESettings{}
			_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
			test.mutate(&selection)
			captured, err := capturePublicationGNOME(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonInput))
			assert.Zero(t, settings.captureCalls)
		})
	}
}

func TestCapturePublicationGNOMECombinedCountOverageIsBounded(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
	settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
		unknown := make([]model.EntryKey, 0, len(refs))
		for _, ref := range refs {
			unknown = append(unknown, publicationCaptureGNOMEUnknown(targetID, ref))
		}
		return SettingsCapture{Entries: []model.Entry{publicationCaptureGNOMEEntry(targetID, refs[0], model.SettingReset, nil)}, Unknown: unknown}, nil
	}
	captured, err := capturePublicationGNOME(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureGNOMEError(t, err, string(publicationCaptureReasonBounds))
}
