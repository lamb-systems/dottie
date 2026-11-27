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
	locked  map[string]struct{}
	sets    []string
	resets  []string
	observe error
	mutate  error
	effect  func()
}

func newSettingsTestBackend() *settingsTestBackend {
	return &settingsTestBackend{
		values: make(map[string]syncengine.SettingValue),
		locked: make(map[string]struct{}),
	}
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
	value := backend.values[settingsTestIdentity(key)]
	_, locked := backend.locked[settingsTestIdentity(key)]
	value.Writable = !locked
	return value, nil
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
		if backend.effect != nil {
			backend.effect()
		}
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

func TestPlanPublicationSettingsRefusesALockedKey(t *testing.T) {
	backend := newSettingsTestBackend()
	locked := settingsTestObservedKey(t, "color-scheme")
	backend.locked[locked] = struct{}{}
	backend.values[locked] = syncengine.SettingValue{
		Present: true, Type: "s", Text: "'prefer-dark'",
	}
	material := settingsTestRecord(t,
		settingsTestEntry(t, "color-scheme", &model.VariantValue{Type: "s", Text: "'prefer-dark'"}),
	)
	_, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend,
	})
	require.ErrorIs(t, err, ErrPublicationSettings, "a locked key that matches was accepted")
}

func TestApplyPublicationSettingsRefusesALockedKey(t *testing.T) {
	backend := newSettingsTestBackend()
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	)
	journal, _ := settingsTestJournal(t)
	request := PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend, Journal: journal,
	}
	plan, err := PlanPublicationSettings(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, 1, plan.Changes)
	request.ExpectedPlan = plan.Digest

	backend.locked[settingsTestIdentity(model.EntryKey{
		Source: model.SourceGNOME, SchemaID: plan.Operations[0].SchemaID,
		SettingsPath: plan.Operations[0].Path, SettingKey: plan.Operations[0].Key,
	})] = struct{}{}
	_, err = ApplyPublicationSettings(context.Background(), request)
	require.ErrorIs(t, err, ErrPublicationSettings)
	assert.Empty(t, backend.sets, "a locked key was written")
}

func TestApplyPublicationResolvesAnInterruptedSettingsRowBeforeWriting(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "synthetic")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"note.ini": "synthetic",
	}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"note.ini": "synthetic",
	}))

	settled := settingsJournalIntentFor(t, fixture.vault, "accent-color")
	entry, err := fixture.journal.BeginSettingsJournal(context.Background(), settled)
	require.NoError(t, err)
	require.NoError(t, fixture.journal.FailSettingsJournal(context.Background(), entry))

	backend := newSettingsTestBackend()
	request := fixture.request(fixture.local, base, remote)
	request.Settings = backend
	report, err := ApplyPublication(context.Background(), request)
	require.NoError(t, err)
	for _, entry := range report.Entries {
		assert.Equal(t, PublicationApplyUnchanged, entry.Operation, "the file plan changed something")
	}

	live, err := fixture.journal.LiveSettingsEntries(context.Background())
	require.NoError(t, err)
	assert.Empty(t, live)
}

func TestApplyPublicationRefusesAnIndeterminateSettingsRow(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "synthetic")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"note.ini": "synthetic",
	}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"note.ini": "synthetic",
	}))

	intent := settingsJournalIntentFor(t, fixture.vault, "accent-color")
	entry, err := fixture.journal.BeginSettingsJournal(context.Background(), intent)
	require.NoError(t, err)
	require.NoError(t, fixture.journal.MarkSettingsIndeterminate(context.Background(), entry))

	backend := newSettingsTestBackend()
	backend.values[settingsTestIdentity(model.EntryKey{
		Source: model.SourceGNOME, SchemaID: intent.Anchor.SchemaID,
		SettingsPath: intent.Anchor.Path, SettingKey: intent.Anchor.Key,
	})] = syncengine.SettingValue{Present: true, Type: "s", Text: "'third-party'", Writable: true}

	request := fixture.request(fixture.local, base, remote)
	request.Settings = backend
	_, err = ApplyPublication(context.Background(), request)
	require.ErrorIs(t, err, ErrPublicationApply)
	live, liveErr := fixture.journal.LiveSettingsEntries(context.Background())
	require.NoError(t, liveErr)
	assert.Len(t, live, 1, "the indeterminate settings row was retired")
}

func settingsJournalIntentFor(
	t *testing.T,
	vault [32]byte,
	key string,
) publicationstate.SettingsJournalIntent {
	t.Helper()
	setting := settingsTestEntry(t, key, nil)
	return publicationstate.SettingsJournalIntent{
		Vault: vault,
		Anchor: publicationstate.SettingsJournalAnchor{
			TargetID: "desktop", SchemaID: setting.SchemaID, Path: setting.Path, Key: setting.Key,
		},
		Prior:             publicationstate.SettingsValue{Present: true, Type: "s", Text: "'old'"},
		Written:           publicationstate.SettingsValue{Present: true, Type: "s", Text: "'new'"},
		SeenFloorRevision: 1,
	}
}

func TestApplyPublicationRefusesALockedSettingsRow(t *testing.T) {
	fixture := newPublicationApplyFixture(t)
	fixture.write(t, "note.ini", "synthetic")
	base := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"note.ini": "synthetic",
	}))
	remote := fixture.targetSnapshot(publicationPreviewFileEntries(fixture.target.ID, map[string]string{
		"note.ini": "synthetic",
	}))

	intent := settingsJournalIntentFor(t, fixture.vault, "accent-color")
	_, err := fixture.journal.BeginSettingsJournal(context.Background(), intent)
	require.NoError(t, err)

	backend := newSettingsTestBackend()
	backend.locked[settingsTestIdentity(model.EntryKey{
		Source: model.SourceGNOME, SchemaID: intent.Anchor.SchemaID,
		SettingsPath: intent.Anchor.Path, SettingKey: intent.Anchor.Key,
	})] = struct{}{}

	request := fixture.request(fixture.local, base, remote)
	request.Settings = backend
	_, err = ApplyPublication(context.Background(), request)
	require.ErrorIs(t, err, ErrPublicationApply)
	live, liveErr := fixture.journal.LiveSettingsEntries(context.Background())
	require.NoError(t, liveErr)
	assert.Len(t, live, 1, "a locked key classified a settings row")
}

func TestPlanPublicationSettingsAcceptsAnySchemaPathForANonRelocatableKey(t *testing.T) {
	backend := newSettingsTestBackend()
	material := settingsTestRecord(t,
		settingsTestEntry(t, "color-scheme", &model.VariantValue{Type: "s", Text: "'prefer-dark'"}),
	)
	plan, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend,
	})
	require.NoError(t, err, "a non-relocatable key was rejected for carrying the schema's own path")
	assert.Equal(t, 1, plan.Changes)
}

func TestPlanPublicationSettingsRefusesTwoTargetsDisagreeingOnOnePhysicalKey(t *testing.T) {
	setting := settingsTestEntry(t, "color-scheme", &model.VariantValue{Type: "s", Text: "'prefer-dark'"})
	other := setting
	other.Value = &model.VariantValue{Type: "s", Text: "'prefer-light'"}
	desktop := model.Target{ID: "desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	laptop := model.Target{ID: "laptop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: settingsTestVault(), PublicationID: [16]byte{0x31},
		Segments: []publication.SnapshotSegment{
			{Target: desktop, Form: publication.SegmentFormSettings, Settings: []publication.SnapshotSetting{setting}},
			{Target: laptop, Form: publication.SegmentFormSettings, Settings: []publication.SnapshotSetting{other}},
		},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)

	policy := settingsTestPolicy(t, "appearance")
	configuration := config.Config{Version: config.Version, Targets: []config.Target{
		{ID: "desktop", Source: model.SourceGNOME, Mode: config.Review, GNOMEPolicy: &policy},
		{ID: "laptop", Source: model.SourceGNOME, Mode: config.Review, GNOMEPolicy: &policy},
	}}
	_, err = PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: configuration, Record: raw,
		Backend: newSettingsTestBackend(),
	})
	require.ErrorIs(t, err, ErrPublicationSettings, "two targets set one physical key to different values")

	record.Segments[1].Settings = []publication.SnapshotSetting{setting}
	raw, err = publication.EncodeSnapshot(record)
	require.NoError(t, err)
	plan, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: configuration, Record: raw,
		Backend: newSettingsTestBackend(),
	})
	require.NoError(t, err, "identical operations for one physical key were refused")
	assert.Len(t, plan.Operations, 1, "an identical duplicate was not coalesced")
}

func TestApplyPublicationSettingsSettlesAMutationErrorFromObservation(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		after    syncengine.SettingValue
		expected publicationstate.JournalState
	}{
		{
			name:     "the write landed",
			after:    syncengine.SettingValue{Present: true, Type: "s", Text: "'blue'", Writable: true},
			expected: publicationstate.JournalStateApplied,
		},
		{
			name:     "the prior image is still visible",
			after:    syncengine.SettingValue{},
			expected: publicationstate.JournalStateFailed,
		},
		{
			name:     "a third image is visible",
			after:    syncengine.SettingValue{Present: true, Type: "s", Text: "'green'", Writable: true},
			expected: publicationstate.JournalStateIndeterminate,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			backend := newSettingsTestBackend()
			journal, _ := settingsTestJournal(t)
			material := settingsTestRecord(t,
				settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
			)
			request := PublicationSettingsRequest{
				Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
				Record: material, Backend: backend, Journal: journal,
			}
			plan, err := PlanPublicationSettings(context.Background(), request)
			require.NoError(t, err)
			request.ExpectedPlan = plan.Digest
			backend.mutate = errors.New("synthetic native failure")
			backend.effect = func() {
				backend.values[settingsTestObservedKey(t, "accent-color")] = testCase.after
			}
			_, err = ApplyPublicationSettings(context.Background(), request)
			require.ErrorIs(t, err, ErrPublicationSettings)

			live, liveErr := journal.LiveSettingsEntries(context.Background())
			require.NoError(t, liveErr)
			if testCase.expected == publicationstate.JournalStateIndeterminate {
				require.Len(t, live, 1, "an unclassifiable outcome retired the row")
				return
			}
			assert.Empty(t, live, "a classified outcome left the row live")
			count, countErr := journal.SettingsEntryCount(context.Background())
			require.NoError(t, countErr)
			assert.Equal(t, int64(1), count)
		})
	}
}

func TestApplyPublicationSettingsRefusesWhenThePriorImageMovedBeforeTheWrite(t *testing.T) {
	backend := newSettingsTestBackend()
	journal, _ := settingsTestJournal(t)
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	)
	request := PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, Backend: backend, Journal: journal,
	}
	plan, err := PlanPublicationSettings(context.Background(), request)
	require.NoError(t, err)
	request.ExpectedPlan = plan.Digest
	request.Barrier = func(_ publicationstate.SettingsJournalEntry) error {
		backend.values[settingsTestObservedKey(t, "accent-color")] =
			syncengine.SettingValue{Present: true, Type: "s", Text: "'third-party'", Writable: true}
		return nil
	}
	_, err = ApplyPublicationSettings(context.Background(), request)
	require.ErrorIs(t, err, ErrPublicationSettings)
	assert.Empty(t, backend.sets, "a drifted preimage was overwritten")
	live, liveErr := journal.LiveSettingsEntries(context.Background())
	require.NoError(t, liveErr)
	assert.Empty(t, live, "the unexecuted intent stayed live")
	count, countErr := journal.SettingsEntryCount(context.Background())
	require.NoError(t, countErr)
	assert.Equal(t, int64(1), count, "the refused intent was not journaled")
}

func TestPlanPublicationSettingsBindsTheRecordCIDItWasGiven(t *testing.T) {
	backend := newSettingsTestBackend()
	material := settingsTestRecord(t,
		settingsTestEntry(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	)
	record, err := publication.DecodeSnapshot(material)
	require.NoError(t, err)
	cid, err := publication.RecordCID(material)
	require.NoError(t, err)

	plan, err := PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: material, RecordCID: cid, Backend: backend,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, plan.Changes)

	record.PublicationID = [16]byte{0x32}
	other, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	_, err = PlanPublicationSettings(context.Background(), PublicationSettingsRequest{
		Vault: settingsTestVault(), Configuration: settingsTestConfiguration(t),
		Record: other, RecordCID: cid, Backend: backend,
	})
	require.ErrorIs(t, err, ErrPublicationSettings, "a record that is not the bound one was planned")
}
