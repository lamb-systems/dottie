package cli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runManualCommandForTest(command *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	arguments := append([]string{"dottie"}, args...)
	if err := command.Run(ctx, arguments); err != nil && *exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return *exitCode
}

func TestManualPreviewRequiresRemoteIdentityBeforeFactory(t *testing.T) {
	factoryCalls := 0
	factory := func(context.Context, *urfave.Command, bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		factoryCalls++
		return nil, service.VaultSelection{}, func() {}, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "preview", "--target", "prefs")
	assert.Equal(t, 2, code)
	assert.Equal(t, 0, factoryCalls)
	assert.Empty(t, stdout.String())
	assert.NotEmpty(t, stderr.String())
}

func TestManualReadRefusalUsesDistinctExitCodeAndEscapesControls(t *testing.T) {
	factory := func(context.Context, *urfave.Command, bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		return nil, service.VaultSelection{}, func() {}, errors.New("unsafe\nrefusal")
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "pull", "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Empty(t, stdout.String())
	assert.NotContains(t, stderr.String(), "unsafe\nrefusal")
	assert.Contains(t, stderr.String(), "unsafe\\x0Arefusal")
}

func TestManualRestoreRequiresTarget(t *testing.T) {
	factoryCalls := 0
	factory := func(context.Context, *urfave.Command, bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		factoryCalls++
		return nil, service.VaultSelection{}, func() {}, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "restore", "--did", "did:plc:example")
	assert.Equal(t, 2, code)
	assert.Equal(t, 0, factoryCalls)
}

func TestManualRecoverInvokesCoordinatorSettingsBackend(t *testing.T) {
	store, settings, backend := manualRecoveryFixture(t)
	if productionSettings := manualGNOMESettings(); productionSettings != nil {
		settings.source = productionSettings
	}
	stdout := runManualRecoverForTest(t, store, settings)
	assert.Equal(t, 1, settings.backendRequests)
	assert.Equal(t, 1, backend.observations)
	assert.Contains(t, stdout, "failed")
	entries, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "failed", entries[0].State)
}

func runManualRecoverForTest(t *testing.T, store *state.Store, settings *manualRecoverySettings) string {
	t.Helper()
	factory := func(_ context.Context, _ *urfave.Command, needsRemote bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		require.False(t, needsRemote)
		coordinator, err := service.NewCoordinator(service.Dependencies{State: store, Settings: settings})
		return coordinator, service.VaultSelection{}, func() {}, err
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "recover")
	require.Equal(t, 0, code)
	assert.Empty(t, stderr.String())
	return stdout.String()
}

type manualRecoverySettings struct {
	source          service.SettingsPort
	backend         *manualRecoveryBackend
	backendRequests int
}

func (settings *manualRecoverySettings) Resolve(ctx context.Context, targetID, schemaID, path string) (string, error) {
	if settings.source != nil {
		return settings.source.Resolve(ctx, targetID, schemaID, path)
	}
	return "", errors.New("unexpected settings resolution")
}

func (settings *manualRecoverySettings) Capture(ctx context.Context, targetID string, refs []service.SettingRef) (service.SettingsCapture, error) {
	if settings.source != nil {
		return settings.source.Capture(ctx, targetID, refs)
	}
	return service.SettingsCapture{}, errors.New("unexpected settings capture")
}

func (settings *manualRecoverySettings) Backend() syncengine.SettingsBackend {
	settings.backendRequests++
	return settings.backend
}

type manualRecoveryBackend struct {
	observations int
}

func (backend *manualRecoveryBackend) Observe(context.Context, model.EntryKey) (syncengine.SettingValue, error) {
	backend.observations++
	return syncengine.SettingValue{Present: true, Writable: true, Type: "s", Text: "'before'"}, nil
}

func (*manualRecoveryBackend) Canonicalize(context.Context, model.EntryKey, string, string) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{}, errors.New("unexpected setting canonicalization")
}

func (*manualRecoveryBackend) Set(context.Context, model.EntryKey, string, string) error {
	return errors.New("unexpected setting write")
}

func (*manualRecoveryBackend) Reset(context.Context, model.EntryKey) error {
	return errors.New("unexpected setting reset")
}

func manualRecoveryFixture(t *testing.T) (*state.Store, *manualRecoverySettings, *manualRecoveryBackend) {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{Home: root + "/home", StateHome: root + "/state", CacheHome: root + "/cache"}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{ID: "desktop", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 1}))
	identity := model.EntryKey{TargetID: "desktop", Source: model.SourceGNOME, SchemaID: "org.example.Desktop", SettingsPath: "/org/example/", SettingKey: "theme"}
	preimage := state.NewSettingFingerprint(model.SettingPresent, "s", "'before'")
	postimage := state.NewSettingFingerprint(model.SettingPresent, "s", "'after'")
	_, err = store.AppendJournal(context.Background(), state.JournalEntry{
		ID: "pending-setting", Operation: "setting-set", State: "pending", Stage: state.JournalStagePending,
		Identity: identity, Preimage: preimage, Postimage: postimage, CreatedAt: 1,
	}, []byte("s\x00'before'"))
	require.NoError(t, err)
	backend := &manualRecoveryBackend{}
	return store, &manualRecoverySettings{backend: backend}, backend
}
