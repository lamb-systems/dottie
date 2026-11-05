package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
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

type bootstrapTestRemoteReader struct {
	calls int
}

func (reader *bootstrapTestRemoteReader) Read(context.Context, atproto.ReadRequest) (atproto.ReadResult, error) {
	reader.calls++
	return atproto.ReadResult{}, errors.New("unexpected provider read")
}

type bootstrapTestGenesisPort struct {
	result      atproto.GenesisCommitResult
	commitErr   error
	limitErr    error
	order       *[]string
	commitCalls int
}

func (port *bootstrapTestGenesisPort) Preflight(context.Context) error {
	*port.order = append(*port.order, "preflight")
	return nil
}

func (port *bootstrapTestGenesisPort) BlobUploadLimit(context.Context) (int64, error) {
	*port.order = append(*port.order, "blob-limit")
	return 1 << 20, port.limitErr
}

func (port *bootstrapTestGenesisPort) CommitGenesis(_ context.Context, _ int64, _ []byte, _ vault.DeviceMaterial, _ vault.Genesis) (atproto.GenesisCommitResult, error) {
	port.commitCalls++
	*port.order = append(*port.order, "publication")
	return port.result, port.commitErr
}

func TestCoordinatorFinalizeVaultRefusesWhenDeviceKeysAreMissing(t *testing.T) {
	store, _ := openCoordinatorStateWithPaths(t)
	keyring := &bootstrapTestKeyStore{items: make(map[string]vault.DeviceMaterial)}
	remote := &bootstrapTestRemoteReader{}
	coordinator, err := NewCoordinator(Dependencies{
		State: store, DeviceKeys: keyring, Session: pushTestSession{did: pushTestDID}, Remote: remote,
	})
	require.NoError(t, err)
	_, err = coordinator.FinalizeVaultTrust(context.Background(), [32]byte{1})
	require.ErrorIs(t, err, ErrFinalizeKeysMissing)
	assert.Zero(t, remote.calls)
}

func TestCoordinatorInitializeVaultMapsGenesisOutcomesAndCustody(t *testing.T) {
	for _, test := range []struct {
		name        string
		phase       atproto.GenesisPhase
		commitErr   error
		outcome     BootstrapOutcome
		keyRetained bool
		deleteCalls int
	}{
		{name: "definite precommit", phase: atproto.GenesisNotSubmitted, commitErr: atproto.ErrBatchRejected, outcome: BootstrapPrecommitFailure, deleteCalls: 1},
		{name: "empty-repository race", phase: atproto.GenesisNotSubmitted, commitErr: atproto.ErrGenesisRepositoryNotEmpty, outcome: BootstrapPrecommitFailure, deleteCalls: 1},
		{name: "verified absence", phase: atproto.GenesisSubmitted, commitErr: atproto.ErrGenesisNotLanded, outcome: BootstrapVerifiedAbsence, deleteCalls: 1},
		{name: "submitted unresolved", phase: atproto.GenesisSubmitted, commitErr: atproto.ErrGenesisUnavailable, outcome: BootstrapUnresolved, keyRetained: true},
		{name: "membership verified final readback failed", phase: atproto.GenesisMembershipVerified, commitErr: atproto.ErrGenesisReadbackRejected, outcome: BootstrapUnresolved, keyRetained: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, _ := openCoordinatorStateWithPaths(t)
			order := make([]string, 0, 3)
			keyring := &bootstrapTestKeyStore{items: make(map[string]vault.DeviceMaterial)}
			port := &bootstrapTestGenesisPort{result: atproto.GenesisCommitResult{Phase: test.phase}, commitErr: test.commitErr, order: &order}
			coordinator, err := NewCoordinator(Dependencies{State: store, DeviceKeys: keyring, Genesis: port})
			require.NoError(t, err)
			kit, err := vault.GenerateRecoveryKit()
			require.NoError(t, err)
			defer clear(kit)
			signing, recipient, err := vault.GenerateDeviceKeys()
			require.NoError(t, err)
			defer clear(signing)
			device := vault.DeviceMaterial{DeviceID: "bootstrap-test-root", KeyID: signing.Public().(ed25519.PublicKey), Signing: signing, Recipient: recipient}
			delivered := false
			result, initializeErr := coordinator.InitializeVault(context.Background(), BootstrapRequest{
				VaultName: "bootstrap test", Kit: kit, Device: device,
				DeliverKit: func(_ vault.BootstrapResult, deliveredKit []byte) error {
					assert.Equal(t, kit, deliveredKit)
					delivered = true
					order = append(order, "kit-delivered")
					return nil
				},
			})
			require.ErrorIs(t, initializeErr, test.commitErr)
			assert.Equal(t, test.outcome, result.Outcome)
			assert.True(t, delivered)
			assert.Equal(t, 1, port.commitCalls)
			assert.Equal(t, test.deleteCalls, keyring.deleteCalls)
			assert.Equal(t, test.keyRetained, len(keyring.items) == 1)
			assert.Equal(t, []string{"kit-delivered", "blob-limit", "publication"}, order)
			assert.Empty(t, result.RecordTargets)
			selections, err := store.VaultSelections(context.Background())
			require.NoError(t, err)
			assert.Empty(t, selections)
		})
	}
}

func TestCoordinatorInitializeVaultAbortsBeforePublicationOnCustodyFailure(t *testing.T) {
	for _, test := range []struct {
		name        string
		storeErr    error
		deliverErr  error
		wantStored  int
		wantDelete  int
		wantOutcome BootstrapOutcome
		wantErr     error
	}{
		{name: "keyring failure", storeErr: platform.ErrKeyringUnavailable, wantDelete: 1, wantErr: platform.ErrKeyringUnavailable},
		{name: "kit delivery failure", deliverErr: errors.New("synthetic stdout failure"), wantStored: 1, wantDelete: 1, wantOutcome: BootstrapPrecommitFailure, wantErr: ErrBootstrapKitDeliveryFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, _ := openCoordinatorStateWithPaths(t)
			order := make([]string, 0, 3)
			keyring := &bootstrapTestKeyStore{items: make(map[string]vault.DeviceMaterial), storeErr: test.storeErr}
			port := &bootstrapTestGenesisPort{order: &order}
			coordinator, err := NewCoordinator(Dependencies{State: store, DeviceKeys: keyring, Genesis: port})
			require.NoError(t, err)
			kit, err := vault.GenerateRecoveryKit()
			require.NoError(t, err)
			defer clear(kit)
			signing, recipient, err := vault.GenerateDeviceKeys()
			require.NoError(t, err)
			defer clear(signing)
			device := vault.DeviceMaterial{DeviceID: "custody-test-root", KeyID: signing.Public().(ed25519.PublicKey), Signing: signing, Recipient: recipient}
			result, initializeErr := coordinator.InitializeVault(context.Background(), BootstrapRequest{
				VaultName: "custody test", Kit: kit, Device: device,
				DeliverKit: func(vault.BootstrapResult, []byte) error {
					order = append(order, "kit-delivered")
					return test.deliverErr
				},
			})
			require.ErrorIs(t, initializeErr, test.wantErr)
			assert.Equal(t, test.wantOutcome, result.Outcome)
			assert.Equal(t, 0, port.commitCalls)
			assert.Equal(t, 0, len(keyring.items))
			assert.Equal(t, test.wantDelete, keyring.deleteCalls)
			assert.Equal(t, test.wantStored, func() int {
				if test.storeErr != nil {
					return 0
				}
				return 1
			}())
			assert.NotContains(t, order, "blob-limit")
			assert.NotContains(t, order, "publication")
			selections, err := store.VaultSelections(context.Background())
			require.NoError(t, err)
			assert.Empty(t, selections)
		})
	}
}
