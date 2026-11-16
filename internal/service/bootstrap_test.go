package service

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bootstrapTestKeyStore struct {
	items       map[string]vault.DeviceMaterial
	storeErr    error
	deleteCalls int
}

func (keyring *bootstrapTestKeyStore) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if device, exists := keyring.items[deviceID]; exists && vaultID != ([32]byte{}) {
		return device, nil
	}
	return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
}

func (keyring *bootstrapTestKeyStore) StoreDeviceKeys(_ context.Context, _ [32]byte, device vault.DeviceMaterial) error {
	if keyring.storeErr != nil {
		return keyring.storeErr
	}
	keyring.items[device.DeviceID] = device
	return nil
}

func (keyring *bootstrapTestKeyStore) LoadDeviceKeysForVault(_ context.Context, vaultID [32]byte) ([]vault.DeviceMaterial, error) {
	if vaultID == ([32]byte{}) || len(keyring.items) == 0 {
		return nil, platform.ErrKeyringItemNotFound
	}
	materials := make([]vault.DeviceMaterial, 0, len(keyring.items))
	for _, device := range keyring.items {
		materials = append(materials, device)
	}
	return materials, nil
}

func (keyring *bootstrapTestKeyStore) DeleteDeviceKeys(_ context.Context, _ [32]byte, deviceID string) error {
	keyring.deleteCalls++
	delete(keyring.items, deviceID)
	return nil
}

type bootstrapTestPreflight struct {
	err   error
	calls int
}

func (port *bootstrapTestPreflight) Preflight(context.Context) error {
	port.calls++
	return port.err
}

func newBootstrapTestDevice(t *testing.T, deviceID string) vault.DeviceMaterial {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	t.Cleanup(func() { clear(signing) })
	return vault.DeviceMaterial{DeviceID: deviceID, KeyID: signing.Public().(ed25519.PublicKey), Signing: signing, Recipient: recipient}
}

func TestCoordinatorPreflightVaultRequiresThePreflightPort(t *testing.T) {
	store, _ := openCoordinatorStateWithPaths(t)
	coordinator, err := NewCoordinator(Dependencies{State: store})
	require.NoError(t, err)
	require.Error(t, coordinator.PreflightVault(context.Background()))
}

func TestCoordinatorInitializeVaultRecordsTheSelectionAndPublishesNothing(t *testing.T) {
	store, _ := openCoordinatorStateWithPaths(t)
	keyring := &bootstrapTestKeyStore{items: make(map[string]vault.DeviceMaterial)}
	preflight := &bootstrapTestPreflight{}
	clock := func() time.Time { return time.Unix(1_800_000_000, 0) }
	coordinator, err := NewCoordinator(Dependencies{State: store, DeviceKeys: keyring, GenesisPreflight: preflight, Clock: clock})
	require.NoError(t, err)
	require.NoError(t, coordinator.PreflightVault(context.Background()))
	device := newBootstrapTestDevice(t, "bootstrap-test-root")
	result, err := coordinator.InitializeVault(context.Background(), BootstrapRequest{VaultName: "bootstrap test", Device: device})
	require.NoError(t, err)
	assert.Equal(t, BootstrapLocalIdentityRecorded, result.Outcome)
	assert.NotEqual(t, [32]byte{}, result.Bootstrap.Vault)
	assert.Equal(t, 1, preflight.calls)
	assert.Equal(t, device.DeviceID, keyring.items[device.DeviceID].DeviceID)
	selections, err := store.VaultSelections(context.Background())
	require.NoError(t, err)
	require.Len(t, selections, 1)
	assert.Equal(t, result.Bootstrap.Vault, selections[0].Vault)
	assert.Equal(t, device.DeviceID, selections[0].DeviceID)
	assert.Equal(t, time.Unix(1_800_000_000, 0).Unix(), selections[0].RecordedAt)
	selected, err := coordinator.ResolveSelection(context.Background(), VaultSelection{})
	require.NoError(t, err)
	assert.Equal(t, VaultSelection{Vault: result.Bootstrap.Vault, DeviceID: device.DeviceID}, selected)
}

func TestCoordinatorInitializeVaultRefusesCustodyAndSelectionFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		storeErr    error
		existing    bool
		wantOutcome BootstrapOutcome
		wantDelete  int
		wantKeys    int
	}{
		{name: "keyring failure", storeErr: platform.ErrKeyringUnavailable, wantOutcome: BootstrapNotRecorded, wantDelete: 1},
		{name: "device keys already exist", existing: true, wantOutcome: BootstrapNotRecorded, wantKeys: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, _ := openCoordinatorStateWithPaths(t)
			keyring := &bootstrapTestKeyStore{items: make(map[string]vault.DeviceMaterial), storeErr: test.storeErr}
			device := newBootstrapTestDevice(t, "custody-test-root")
			if test.existing {
				keyring.items[device.DeviceID] = device
			}
			coordinator, err := NewCoordinator(Dependencies{State: store, DeviceKeys: keyring, GenesisPreflight: &bootstrapTestPreflight{}})
			require.NoError(t, err)
			result, initializeErr := coordinator.InitializeVault(context.Background(), BootstrapRequest{VaultName: "custody test", Device: device})
			require.Error(t, initializeErr)
			assert.NotEqual(t, BootstrapLocalIdentityRecorded, result.Outcome)
			assert.Equal(t, test.wantDelete, keyring.deleteCalls)
			selections, err := store.VaultSelections(context.Background())
			require.NoError(t, err)
			assert.Empty(t, selections)
			if !test.existing {
				assert.Empty(t, keyring.items)
			}
		})
	}
}

func TestCoordinatorInitializeVaultDeletesStoredKeysWhenTheSelectionCannotBeRecorded(t *testing.T) {
	store, paths := openCoordinatorStateWithPaths(t)
	keyring := &bootstrapTestKeyStore{items: make(map[string]vault.DeviceMaterial)}
	coordinator, err := NewCoordinator(Dependencies{State: store, DeviceKeys: keyring, GenesisPreflight: &bootstrapTestPreflight{}})
	require.NoError(t, err)
	interruptVaultSelectionWrites(t, paths)
	result, initializeErr := coordinator.InitializeVault(context.Background(), BootstrapRequest{
		VaultName: "selection test", Device: newBootstrapTestDevice(t, "selection-test-root"),
	})
	require.Error(t, initializeErr)
	assert.Equal(t, BootstrapNotRecorded, result.Outcome)
	assert.Equal(t, 1, keyring.deleteCalls)
	assert.Empty(t, keyring.items)
	selections, err := store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Empty(t, selections)
}

func interruptVaultSelectionWrites(t *testing.T, paths platform.Paths) {
	t.Helper()
	database, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.Join(paths.AppStateDir(), "state.db")}).String())
	require.NoError(t, err)
	defer database.Close()
	_, err = database.Exec(`CREATE TRIGGER fail_bootstrap_selection BEFORE INSERT ON vault_selections BEGIN SELECT RAISE(FAIL, 'interrupted write'); END`)
	require.NoError(t, err)
}

func TestCoordinatorInitializeVaultRequiresDeviceKeyCustody(t *testing.T) {
	store, _ := openCoordinatorStateWithPaths(t)
	coordinator, err := NewCoordinator(Dependencies{State: store, GenesisPreflight: &bootstrapTestPreflight{}})
	require.NoError(t, err)
	device := newBootstrapTestDevice(t, "custody-required-root")
	_, initializeErr := coordinator.InitializeVault(context.Background(), BootstrapRequest{VaultName: "custody required", Device: device})
	require.Error(t, initializeErr)
}

func TestCoordinatorInitializeVaultRequiresAVaultName(t *testing.T) {
	store, _ := openCoordinatorStateWithPaths(t)
	keyring := &bootstrapTestKeyStore{items: make(map[string]vault.DeviceMaterial)}
	coordinator, err := NewCoordinator(Dependencies{State: store, DeviceKeys: keyring, GenesisPreflight: &bootstrapTestPreflight{}})
	require.NoError(t, err)
	_, initializeErr := coordinator.InitializeVault(context.Background(), BootstrapRequest{Device: newBootstrapTestDevice(t, "nameless-root")})
	require.Error(t, initializeErr)
	assert.Empty(t, keyring.items)
	assert.Zero(t, keyring.deleteCalls)
}
