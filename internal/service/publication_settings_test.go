package service

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

type settingsTestBackend struct {
	values  map[string]syncengine.SettingValue
	sets    []string
	resets  []string
	observe error
	mutate  error
}

func newSettingsTestBackend() *settingsTestBackend {
	return &settingsTestBackend{values: make(map[string]syncengine.SettingValue)}
}

func settingsTestIdentity(key model.EntryKey) string {
	return key.SchemaID + "\x00" + key.SettingsPath + "\x00" + key.SettingKey
}

func (backend *settingsTestBackend) Observe(
	ctx context.Context,
	key model.EntryKey,
) (syncengine.SettingValue, error) {
	if backend.observe != nil {
		return syncengine.SettingValue{}, backend.observe
	}
	return backend.values[settingsTestIdentity(key)], nil
}

func (backend *settingsTestBackend) Canonicalize(
	ctx context.Context,
	key model.EntryKey,
	valueType, text string,
) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{Present: true, Type: valueType, Text: text, Writable: true}, nil
}

func (backend *settingsTestBackend) Set(
	ctx context.Context,
	key model.EntryKey,
	valueType, text string,
) error {
	if backend.mutate != nil {
		return backend.mutate
	}
	backend.sets = append(backend.sets, settingsTestIdentity(key))
	backend.values[settingsTestIdentity(key)] = syncengine.SettingValue{
		Present: true, Type: valueType, Text: text, Writable: true,
	}
	return nil
}

func (backend *settingsTestBackend) Reset(ctx context.Context, key model.EntryKey) error {
	if backend.mutate != nil {
		return backend.mutate
	}
	backend.resets = append(backend.resets, settingsTestIdentity(key))
	delete(backend.values, settingsTestIdentity(key))
	return nil
}

func settingsTestPolicy(t *testing.T, categories ...string) config.GNOMEPolicy {
	t.Helper()
	policy, err := config.ApprovedGNOMEPolicy(categories)
	require.NoError(t, err)
	return policy
}

func settingsTestConfiguration(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		Version: config.Version,
		Targets: []config.Target{{
			ID: "desktop", Source: model.SourceGNOME, Mode: config.Review,
			GNOMEPolicy: func() *config.GNOMEPolicy {
				policy := settingsTestPolicy(t, "appearance")
				return &policy
			}(),
		}},
	}
}

func settingsTestRecord(t *testing.T, settings ...publication.SnapshotSetting) []byte {
	t.Helper()
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: settingsTestVault(), PublicationID: [16]byte{0x31},
		Segments: []publication.SnapshotSegment{{
			Target: model.Target{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
			Form:   publication.SegmentFormSettings, Settings: settings,
		}},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	return raw
}

func settingsTestEntry(t *testing.T, key string, value *model.VariantValue) publication.SnapshotSetting {
	t.Helper()
	keys, err := matrix.SelectCategories([]string{"appearance"})
	require.NoError(t, err)
	for _, candidate := range keys {
		if candidate.Key != key {
			continue
		}
		state := model.SettingPresent
		if value == nil {
			state = model.SettingReset
		}
		return publication.SnapshotSetting{
			SchemaID: candidate.SchemaID, Path: "/org/gnome/desktop/interface/",
			Key: candidate.Key, State: state, Value: value,
		}
	}
	require.FailNow(t, "matrix key not found: "+key)
	return publication.SnapshotSetting{}
}

func settingsTestObservedKey(t *testing.T, key string) string {
	t.Helper()
	setting := settingsTestEntry(t, key, nil)
	return setting.SchemaID + "\x00" + setting.Path + "\x00" + key
}

func TestPlanPublicationSettingsReportsChangedAndUnchangedKeys(t *testing.T) {
	backend := newSettingsTestBackend()
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
		settingsTestEntry(t, "color-scheme", &model.VariantValue{Type: "s", Text: "'prefer-dark'"}),
	)
	backend.values[settingsTestObservedKey(t, "color-scheme")] =
		syncengine.SettingValue{Present: true, Type: "s", Text: "'prefer-dark'"}

	plan, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), FloorRevision: 1, Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend,
	})
	require.NoError(t, err)
	require.Len(t, plan.Operations, 2)
	assert.Equal(t, 1, plan.Changes)
	assert.NotEqual(t, [32]byte{}, plan.Digest)
}

func TestPlanPublicationSettingsRefusesAnUnapprovedKey(t *testing.T) {
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'24h'"}),
	)
	configuration := settingsTestConfiguration(t)
	policy := settingsTestPolicy(t, "fonts")
	configuration.Targets[0].GNOMEPolicy = &policy

	_, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: configuration, Record: material,
		Backend: newSettingsTestBackend(),
	})
	require.ErrorIs(t, err, ErrPublicationSettings)
}

func TestApplyPublicationSettingsJournalsAndMutates(t *testing.T) {
	ctx := context.Background()
	backend := newSettingsTestBackend()
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
		settingsTestEntry(t, "color-scheme", nil),
	)
	backend.values[settingsTestObservedKey(t, "color-scheme")] =
		syncengine.SettingValue{Present: true, Type: "s", Text: "'default'"}
	journal, directory := settingsTestJournal(t)
	_ = directory

	request := PublicationSettingsRequest{
		Vault: settingsTestVault(), FloorRevision: 0, Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend, Journal: journal,
	}
	plan, err := PlanPublicationSettings(ctx, request)
	require.NoError(t, err)
	request.ExpectedPlan = plan.Digest

	report, err := ApplyPublicationSettings(ctx, request)
	require.NoError(t, err)
	assert.Equal(t, 2, report.Applied)
	assert.Equal(t, 0, report.Unchanged)
	assert.Equal(t, []string{settingsTestObservedKey(t, "accent-color")}, backend.sets)
	assert.Equal(t, []string{settingsTestObservedKey(t, "color-scheme")}, backend.resets)

	count, err := journal.SettingsEntryCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
	live, err := journal.LiveSettingsEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, live)

	replay, err := ApplyPublicationSettings(ctx, request)
	require.NoError(t, err)
	assert.Equal(t, 0, replay.Applied)
	assert.Equal(t, 2, replay.Unchanged)
}

func TestApplyPublicationSettingsRefusesAStalePlan(t *testing.T) {
	backend := newSettingsTestBackend()
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	)
	journal, _ := settingsTestJournal(t)
	_, err := ApplyPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend, Journal: journal,
		ExpectedPlan: [32]byte{0x01},
	})
	require.ErrorIs(t, err, ErrPublicationSettings)
	assert.Empty(t, backend.sets)
}

func TestApplyPublicationSettingsSettlesAFailedMutation(t *testing.T) {
	ctx := context.Background()
	backend := newSettingsTestBackend()
	backend.mutate = errors.New("backend refused")
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	)
	journal, _ := settingsTestJournal(t)
	_, err := ApplyPublicationSettings(ctx, PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend, Journal: journal,
	})
	require.ErrorIs(t, err, ErrPublicationSettings)
	count, err := journal.SettingsEntryCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	live, err := journal.LiveSettingsEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, live, "a failed mutation left a live row")
}

func TestPlanPublicationSettingsReportsAnUnobservableKey(t *testing.T) {
	backend := newSettingsTestBackend()
	backend.observe = errors.New("backend unavailable")
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	)
	_, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend,
	})
	require.ErrorIs(t, err, ErrPublicationSettings)
}

func TestPlanPublicationSettingsIgnoresAnUnconfiguredSettingsTarget(t *testing.T) {
	backend := newSettingsTestBackend()
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	)
	plan, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: config.Default(), Record: material, Backend: backend,
	})
	require.NoError(t, err)
	assert.Empty(t, plan.Operations)
	assert.Equal(t, 0, plan.Changes)
}

func TestPublicationSettingsPolicyMatchesTheMatrix(t *testing.T) {
	policy := settingsTestPolicy(t, "appearance")
	keys, err := matrix.SelectCategories([]string{"appearance"})
	require.NoError(t, err)
	approved, err := publicationApprovedSettingKeys(config.Target{
		ID: "desktop", Source: model.SourceGNOME, GNOMEPolicy: &policy,
	})
	require.NoError(t, err)
	require.Len(t, approved, len(keys))
}

func settingsTestJournal(t *testing.T) (*publicationstate.Journal, string) {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	journal, err := publicationstate.OpenJournal(directory)
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	return journal, directory
}

func settingsTestVault() [32]byte {
	var vault [32]byte
	vault[0] = 0x62
	return vault
}
