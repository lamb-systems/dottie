package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryConfig struct {
	value config.Config
}

func (store *memoryConfig) Load(context.Context) (config.Config, error) { return store.value, nil }
func (store *memoryConfig) Save(_ context.Context, value config.Config) error {
	store.value = value
	return nil
}

type emptyTrust struct{}

type unavailableSession struct{}

func (emptyTrust) Resolve(_ context.Context, selection VaultSelection) (TrustMaterial, error) {
	return TrustMaterial{Selection: selection}, nil
}

func (unavailableSession) ReadRequest(context.Context, VaultSelection, vault.DeviceMaterial, [32]byte, []byte, []byte) (atproto.ReadRequest, error) {
	return atproto.ReadRequest{}, errors.New("unexpected session request")
}

type unavailableRemote struct{}

func (unavailableRemote) Read(context.Context, atproto.ReadRequest) (atproto.ReadResult, error) {
	return atproto.ReadResult{}, errors.New("unexpected remote read")
}

func openCoordinatorState(t *testing.T) *state.Store {
	store, _ := openCoordinatorStateWithPaths(t)
	return store
}

func openCoordinatorStateWithPaths(t *testing.T) (*state.Store, platform.Paths) {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{Home: root + "/home", StateHome: root + "/state", CacheHome: root + "/cache"}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return store, paths
}

func TestRecordBaseGNOMEStoresFingerprintPayloadAndRejectsMismatch(t *testing.T) {
	store := openCoordinatorState(t)
	coordinator, err := NewCoordinator(Dependencies{Config: &memoryConfig{value: config.Default()}, State: store})
	require.NoError(t, err)
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{ID: "desktop", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: string(config.Review), CreatedAt: 1}))
	present := model.Entry{TargetID: "desktop", Setting: &model.SettingEntry{
		SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "theme", State: model.SettingPresent,
		Value: &model.VariantValue{Type: "s", Text: "'synthetic'"},
	}}
	reset := model.Entry{TargetID: "desktop", Setting: &model.SettingEntry{
		SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "icon-theme", State: model.SettingReset,
	}}
	require.NoError(t, coordinator.RecordBase(context.Background(), "desktop", []model.Entry{present, reset}))
	bases, err := store.AppliedBase(context.Background(), "desktop")
	require.NoError(t, err)
	require.Len(t, bases, 2)
	for _, test := range []struct {
		entry   model.Entry
		payload []byte
	}{
		{entry: present, payload: []byte("s\x00'synthetic'")},
		{entry: reset, payload: []byte{}},
	} {
		var record state.BaseRecord
		for _, base := range bases {
			if base.Identity == test.entry.Identity() {
				record = base
				break
			}
		}
		require.NotEmpty(t, record.Identity.TargetID)
		assert.Equal(t, test.entry.Identity(), record.Identity)
		assert.Zero(t, record.Fingerprint.Mode)
		stored, payloadErr := store.Payload(record.PayloadRef)
		require.NoError(t, payloadErr)
		assert.Equal(t, test.payload, stored)
		digest := sha256.Sum256(stored)
		assert.Equal(t, hex.EncodeToString(digest[:]), record.Fingerprint.Digest)
		assert.Equal(t, state.NewSettingFingerprint(test.entry.Setting.State, record.Fingerprint.ValueType, record.Fingerprint.ValueText), record.Fingerprint)
	}
	presentFingerprint := state.NewSettingFingerprint(model.SettingPresent, "s", "'synthetic'")
	_, err = store.PutAppliedBase(context.Background(), state.BaseRecord{Identity: present.Identity(), Fingerprint: presentFingerprint, RecordedAt: 1}, []byte("mismatch"))
	require.ErrorContains(t, err, "base fingerprint does not match payload")
}

func TestStatusReturnsSortedTargetsWithoutRemoteAccess(t *testing.T) {
	store := openCoordinatorState(t)
	configuration := config.Default()
	configuration.Targets = []config.Target{
		{ID: "z-target", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "z", Kind: model.SelectionDirectory}},
		{ID: "a-target", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "a", Kind: model.SelectionDirectory}},
	}
	coordinator, err := NewCoordinator(Dependencies{Config: &memoryConfig{value: configuration}, State: store})
	require.NoError(t, err)
	status, err := coordinator.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, status.Targets, 2)
	assert.Equal(t, "a-target", status.Targets[0].ID)
	assert.Equal(t, StatusUnknown, status.Targets[0].State)
	assert.Equal(t, config.Review, status.Targets[0].Mode)
	assert.Equal(t, "z-target", status.Targets[1].ID)
}

func TestPullRefusesWithoutSelectionOrLocalCheckpoint(t *testing.T) {
	store := openCoordinatorState(t)
	coordinator, err := NewCoordinator(Dependencies{
		Config: &memoryConfig{value: config.Default()}, State: store, Trust: emptyTrust{}, Session: unavailableSession{}, Remote: unavailableRemote{},
	})
	require.NoError(t, err)
	_, err = coordinator.Pull(context.Background(), VaultSelection{})
	assert.ErrorIs(t, err, ErrNoVaultSelection)

	selection := state.VaultSelection{Vault: [32]byte{1}, DeviceID: "device-a", RecordedAt: 123}
	require.NoError(t, store.PutVaultSelection(context.Background(), selection))
	_, err = coordinator.Pull(context.Background(), VaultSelection{})
	assert.ErrorIs(t, err, ErrNoCheckpoint)
}

func TestVaultSelectionRequiresExplicitChoiceWhenAmbiguous(t *testing.T) {
	store := openCoordinatorState(t)
	coordinator, err := NewCoordinator(Dependencies{Config: &memoryConfig{value: config.Default()}, State: store})
	require.NoError(t, err)
	require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: [32]byte{1}, DeviceID: "device-a", RecordedAt: 1}))
	require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: [32]byte{2}, DeviceID: "device-b", RecordedAt: 2}))
	_, err = coordinator.selectVault(context.Background(), VaultSelection{})
	assert.ErrorIs(t, err, ErrAmbiguousVaultSelection)
	selected, err := coordinator.selectVault(context.Background(), VaultSelection{Vault: [32]byte{2}})
	require.NoError(t, err)
	assert.Equal(t, VaultSelection{Vault: [32]byte{2}, DeviceID: "device-b"}, selected)
}
