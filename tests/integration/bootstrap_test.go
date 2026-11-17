package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const publicationAuditDID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"

type publicationKeyring struct {
	devices map[string]vault.DeviceMaterial
}

func (keyring *publicationKeyring) LoadDeviceKeys(
	_ context.Context,
	vaultID [32]byte,
	deviceID string,
) (vault.DeviceMaterial, error) {
	device, ok := keyring.devices[deviceID]
	if vaultID == ([32]byte{}) {
		return vault.DeviceMaterial{}, errors.New("synthetic device key is unavailable")
	}
	if !ok {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	return device, nil
}

func (keyring *publicationKeyring) StoreDeviceKeys(
	_ context.Context,
	vaultID [32]byte,
	device vault.DeviceMaterial,
) error {
	if vaultID == ([32]byte{}) || device.DeviceID == "" {
		return errors.New("invalid synthetic device keys")
	}
	if _, exists := keyring.devices[device.DeviceID]; exists {
		return errors.New("synthetic device keys already exist")
	}
	keyring.devices[device.DeviceID] = device
	return nil
}

func (keyring *publicationKeyring) LoadDeviceKeysForVault(
	_ context.Context,
	vaultID [32]byte,
) ([]vault.DeviceMaterial, error) {
	if vaultID == ([32]byte{}) || len(keyring.devices) == 0 {
		return nil, platform.ErrKeyringItemNotFound
	}
	materials := make([]vault.DeviceMaterial, 0, len(keyring.devices))
	for _, device := range keyring.devices {
		materials = append(materials, device)
	}
	return materials, nil
}

func (keyring *publicationKeyring) DeleteDeviceKeys(_ context.Context, _ [32]byte, deviceID string) error {
	delete(keyring.devices, deviceID)
	return nil
}

type bootstrapPreflightPort struct {
	identity  atproto.Identity
	transport atproto.Transport
	order     *[]string
}

func (port bootstrapPreflightPort) Preflight(ctx context.Context) error {
	*port.order = append(*port.order, "preflight")
	return atproto.CheckNoDottiePublication(ctx, atproto.RevisionReader{
		Transport: port.transport, DIDDocumentID: port.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...),
	}, port.transport, port.identity.DID)
}

type bootstrapFixture struct {
	coordinator *service.Coordinator
	store       *state.Store
	paths       platform.Paths
	pds         *atprototest.MemoryPDS
	reader      atproto.RevisionReader
	keyring     *publicationKeyring
	device      vault.DeviceMaterial
	order       *[]string
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home:       filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(
			root,
			"state",
		),
		CacheHome: filepath.Join(root, "cache"),
		DataHome:  filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationAuditDID, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	identity := atproto.Identity{
		DID: publicationAuditDID, DIDDocumentID: publicationAuditDID,
		VerificationMethods: []atproto.VerificationMethod{
			{
				ID:                 method.ID,
				Type:               method.Type,
				Controller:         method.Controller,
				PublicKeyMultibase: method.PublicKeyMultibase,
			},
		},
	}
	reader := atproto.RevisionReader{
		Transport: pds, DIDDocumentID: identity.DIDDocumentID, VerificationMethods: identity.VerificationMethods,
	}
	order := make([]string, 0, 2)
	keyring := &publicationKeyring{devices: map[string]vault.DeviceMaterial{}}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		State: store, DeviceKeys: keyring,
		GenesisPreflight: bootstrapPreflightPort{identity: identity, transport: pds, order: &order},
		Clock:            func() time.Time { return time.Unix(1_800_000_000, 0) },
	})
	require.NoError(t, err)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	t.Cleanup(func() { clear(signing) })
	return &bootstrapFixture{
		coordinator: coordinator, store: store, paths: paths, pds: pds, reader: reader, keyring: keyring,
		order: &order, device: vault.DeviceMaterial{
			DeviceID: "coordinator-bootstrap-root", KeyID: bytes.Clone(signing.Public().(ed25519.PublicKey)),
			Signing: signing, Recipient: recipient,
		},
	}
}

func TestCoordinatorBootstrapRecordsLocalIdentityAndPublishesNoRecord(t *testing.T) {
	ctx := context.Background()
	fixture := newBootstrapFixture(t)
	before, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	require.Empty(t, before.Membership())
	require.NoError(t, fixture.coordinator.PreflightVault(ctx))
	result, err := fixture.coordinator.InitializeVault(ctx, service.BootstrapRequest{
		VaultName: "coordinator bootstrap", Device: fixture.device,
	})
	require.NoError(t, err)
	assert.Equal(t, service.BootstrapLocalIdentityRecorded, result.Outcome)
	assert.Equal(t, []string{"preflight"}, *fixture.order)
	assert.Equal(t, fixture.device.DeviceID, fixture.keyring.devices[fixture.device.DeviceID].DeviceID)
	selections, err := fixture.store.VaultSelections(ctx)
	require.NoError(t, err)
	require.Len(t, selections, 1)
	assert.Equal(t, result.Bootstrap.Vault, selections[0].Vault)
	assert.Equal(t, fixture.device.DeviceID, selections[0].DeviceID)
	assert.Equal(t, time.Unix(1_800_000_000, 0).Unix(), selections[0].RecordedAt)
	_, err = fixture.store.VaultCheckpoint(ctx, result.Bootstrap.Vault)
	require.ErrorIs(t, err, state.ErrVaultCheckpointNotFound)
	after, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	assert.Empty(t, after.Membership())
	assert.Equal(t, before.CommitCID(), after.CommitCID())
}

func seedBootstrapRepositoryRecord(t *testing.T, pds *atprototest.MemoryPDS, collection, rkey string) {
	t.Helper()
	body := []byte(
		`{"repo":"` + publicationAuditDID + `","swapCommit":"` + pds.CurrentRevision().CommitCID.String() + `","writes":[{"$type":"com.atproto.repo.applyWrites#create","collection":"` + collection + `","rkey":"` + rkey + `","value":{"$type":"` + collection + `","probe":"bootstrap"}}]}`,
	)
	status, _, err := pds.Do(
		context.Background(),
		"POST",
		"com.atproto.repo.applyWrites",
		nil,
		body,
		"application/json",
	)
	require.NoError(t, err)
	require.Equal(t, 200, status)
}

func TestCoordinatorBootstrapSucceedsOnRepositoryHoldingOtherApplicationsRecords(t *testing.T) {
	ctx := context.Background()
	fixture := newBootstrapFixture(t)
	seedBootstrapRepositoryRecord(t, fixture.pds, "app.bsky.actor.profile", "self")
	seedBootstrapRepositoryRecord(t, fixture.pds, "com.example.thirdparty.note", "3foreignrecord")
	before, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	require.Len(t, before.Membership(), 2)
	require.NoError(t, fixture.coordinator.PreflightVault(ctx))
	result, err := fixture.coordinator.InitializeVault(ctx, service.BootstrapRequest{
		VaultName: "used account bootstrap", Device: fixture.device,
	})
	require.NoError(t, err)
	assert.Equal(t, service.BootstrapLocalIdentityRecorded, result.Outcome)
	assert.Equal(t, fixture.device.DeviceID, fixture.keyring.devices[fixture.device.DeviceID].DeviceID)
	selections, err := fixture.store.VaultSelections(ctx)
	require.NoError(t, err)
	require.Len(t, selections, 1)
	assert.Equal(t, result.Bootstrap.Vault, selections[0].Vault)
	after, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	assert.Contains(t, after.Membership(), atproto.RecordKey{Collection: "app.bsky.actor.profile", RKey: "self"})
	assert.Contains(
		t,
		after.Membership(),
		atproto.RecordKey{Collection: "com.example.thirdparty.note", RKey: "3foreignrecord"},
	)
	assert.Equal(t, before.CommitCID(), after.CommitCID())
}

func TestCoordinatorBootstrapPreflightRefusesAnExistingDottiePublication(t *testing.T) {
	ctx := context.Background()
	fixture := newBootstrapFixture(t)
	seedBootstrapRepositoryRecord(t, fixture.pds, "app.bsky.actor.profile", "self")
	seedBootstrapRepositoryRecord(t, fixture.pds, publication.HeadNSID, "self")
	before, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	require.Len(t, before.Membership(), 2)
	require.ErrorIs(t, fixture.coordinator.PreflightVault(ctx), atproto.ErrDottiePublicationPresent)
	selections, err := fixture.store.VaultSelections(ctx)
	require.NoError(t, err)
	assert.Empty(t, selections)
	assert.Empty(t, fixture.keyring.devices)
	after, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	assert.Len(t, after.Membership(), 2)
	assert.Equal(t, before.CommitCID(), after.CommitCID())
}
