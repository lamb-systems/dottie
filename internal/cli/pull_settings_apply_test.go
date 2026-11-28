package cli

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
)

type pullTestSettingsBackend struct {
	values map[string]syncengine.SettingValue
	sets   []string
}

func newPullTestSettingsBackend() *pullTestSettingsBackend {
	return &pullTestSettingsBackend{values: make(map[string]syncengine.SettingValue)}
}

func (backend *pullTestSettingsBackend) identity(key model.EntryKey) string {
	return key.SchemaID + "\x00" + key.SettingsPath + "\x00" + key.SettingKey
}

func (backend *pullTestSettingsBackend) Observe(
	_ context.Context,
	key model.EntryKey,
) (syncengine.SettingValue, error) {
	value := backend.values[backend.identity(key)]
	value.Writable = true
	return value, nil
}

func (backend *pullTestSettingsBackend) Canonicalize(
	_ context.Context,
	_ model.EntryKey,
	valueType, text string,
) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{Present: true, Type: valueType, Text: text, Writable: true}, nil
}

func (backend *pullTestSettingsBackend) Set(
	_ context.Context,
	key model.EntryKey,
	valueType, text string,
) error {
	backend.sets = append(backend.sets, backend.identity(key))
	backend.values[backend.identity(key)] = syncengine.SettingValue{
		Present: true, Type: valueType, Text: text, Writable: true,
	}
	return nil
}

func (backend *pullTestSettingsBackend) Reset(_ context.Context, key model.EntryKey) error {
	delete(backend.values, backend.identity(key))
	return nil
}

type pullTestSettingsPort struct {
	backend *pullTestSettingsBackend
}

func (port pullTestSettingsPort) Resolve(context.Context, string, string, string) (string, error) {
	return "", nil
}

func (port pullTestSettingsPort) Capture(
	context.Context,
	string,
	[]service.SettingRef,
) (service.SettingsCapture, error) {
	return service.SettingsCapture{}, nil
}

func (port pullTestSettingsPort) Backend() syncengine.SettingsBackend { return port.backend }

func pullTestPublishedSetting(t *testing.T, key string, value *model.VariantValue) publication.SnapshotSetting {
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

func pullTestMixedView(
	t *testing.T,
	fixture *pullTestFixture,
	settings []publication.SnapshotSetting,
) (publicationstate.SuppliedRepositoryView, *pullTestReader) {
	t.Helper()
	portable, err := fixtureSettingsTarget(t).Model()
	require.NoError(t, err)
	packed, err := vault.PackTarget(fixture.snapshot, fixture.snapshot.Targets[0].ID)
	require.NoError(t, err)
	block, record := pullTestRecordFromSegments(t, fixture.binding, []publication.SnapshotSegment{
		{Target: portable, Form: publication.SegmentFormSettings, Settings: settings},
		pullTestPackedSegment(t, fixture.snapshot.Targets[0], packed.Payload),
	}, 0, nil)
	view := publicationstate.SuppliedRepositoryView{
		Origin: fixture.binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: fixture.context,
		Head:            pullTestHead(t, fixture.binding, block, record),
		Snapshots:       []publicationstate.SnapshotBlock{block},
	}
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	reader := &pullTestReader{view: view, entries: map[string][]byte{
		string(blobCID): packed.Payload,
	}}
	return view, reader
}

func fixtureSettingsTarget(t *testing.T) config.Target {
	t.Helper()
	policy, err := config.ApprovedGNOMEPolicy([]string{"appearance"})
	require.NoError(t, err)
	return config.Target{
		ID: "desktop", Source: model.SourceGNOME, Mode: config.Review, GNOMEPolicy: &policy,
	}
}

func newPullTestCommandWithSettings(
	t *testing.T,
	fixture *pullTestFixture,
	stdout, stderr *bytes.Buffer,
	exitCode *int,
	reader *pullTestReader,
	settings service.SettingsPort,
) *urfave.Command {
	t.Helper()
	t.Setenv("HOME", fixture.paths.Home)
	t.Setenv("XDG_CONFIG_HOME", fixture.paths.ConfigHome)
	t.Setenv("XDG_STATE_HOME", fixture.paths.StateHome)
	t.Setenv("XDG_CACHE_HOME", fixture.paths.CacheHome)
	t.Setenv("XDG_DATA_HOME", fixture.paths.DataHome)
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		return pushSession{Session: pullTestSession()}, nil
	}
	remotes := func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error) {
		return pullRemote{Reader: reader, Entry: reader.ReadEntry, Close: func() {}}, nil
	}
	return newPullCommand(
		stdout,
		stderr,
		exitCode,
		sessions,
		remotes,
		func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
			return fixture.binding.Vault, nil
		},
		productionPullApplySourcesFactory(os.Getenv, settings),
		pushTestDIDs(pullTestDID),
		os.Getenv,
	)
}

func TestPullAppliesPublishedSettingsBesideFiles(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	target := fixtureSettingsTarget(t)
	snapshot, err := service.FileConfigPort{Paths: fixture.paths}.Snapshot(t.Context())
	require.NoError(t, err)
	_, err = service.FileConfigPort{Paths: fixture.paths}.Update(
		t.Context(), snapshot.Token,
		func(current config.Config) (config.Config, error) {
			current.Targets = append(current.Targets, target)
			return current, nil
		},
	)
	require.NoError(t, err)

	view, reader := pullTestMixedView(t, fixture, []publication.SnapshotSetting{
		pullTestPublishedSetting(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	})
	reader.mu.Lock()
	reader.view = view
	reader.mu.Unlock()
	backend := newPullTestSettingsBackend()

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithSettings(
		t, fixture, &stdout, &stderr, &code, reader, pullTestSettingsPort{backend: backend},
	)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(t, stdout.String(), "pull: first-use")
	assert.Contains(t, stdout.String(), "apply: setting set desktop")
	token := pullTestConfirmation(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommandWithSettings(
		t, fixture, &stdout, &stderr, &code, reader, pullTestSettingsPort{backend: backend},
	)
	code = runPullForTest(
		command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token,
	)
	require.Equal(t, 0, code, stderr.String())
	require.Len(t, backend.sets, 1, "the published setting was not written")
	assert.Contains(t, backend.sets[0], "accent-color")
	assert.Equal(t, []byte(pullTestBaseContent), fixtureReadFile(t, fixture.targetPath("init.lua")))

	inspection, err := publicationstate.Inspect(
		context.Background(), fixture.paths.PublicationStateDir(), fixture.binding,
	)
	require.NoError(t, err)
	assert.True(t, inspection.Present)
}

func fixtureReadFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return content
}

func TestPullRefusesAPublishedSettingsTargetWithoutASettingsBackend(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	target := fixtureSettingsTarget(t)
	snapshot, err := service.FileConfigPort{Paths: fixture.paths}.Snapshot(t.Context())
	require.NoError(t, err)
	_, err = service.FileConfigPort{Paths: fixture.paths}.Update(
		t.Context(), snapshot.Token,
		func(current config.Config) (config.Config, error) {
			current.Targets = append(current.Targets, target)
			return current, nil
		},
	)
	require.NoError(t, err)

	view, reader := pullTestMixedView(t, fixture, []publication.SnapshotSetting{
		pullTestPublishedSetting(t, "accent-color", &model.VariantValue{Type: "s", Text: "'blue'"}),
	})
	reader.mu.Lock()
	reader.view = view
	reader.mu.Unlock()

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithSettings(t, fixture, &stdout, &stderr, &code, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	assert.Equal(t, 3, code, stderr.String())
	assert.Contains(t, stderr.String(), "cannot apply settings")
	assert.NotContains(t, stdout.String(), "confirmation:", "a token was printed for a refused settings apply")
	_, statErr := os.Lstat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "a refused settings apply wrote local files")

	inspection, err := publicationstate.Inspect(
		context.Background(), fixture.paths.PublicationStateDir(), fixture.binding,
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present)
}
