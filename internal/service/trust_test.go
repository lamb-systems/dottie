package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryDeviceKeys struct {
	device vault.DeviceMaterial
	err    error
}

func (source memoryDeviceKeys) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if source.err != nil {
		return vault.DeviceMaterial{}, source.err
	}
	if source.device.DeviceID != deviceID || vaultID == ([32]byte{}) {
		return vault.DeviceMaterial{}, errors.New("key item not found")
	}
	return source.device, nil
}

func seedGenesisTrust(t *testing.T, store *state.Store) (vault.Genesis, vault.DeviceMaterial) {
	t.Helper()
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	device := vault.DeviceMaterial{DeviceID: "trust-root", KeyID: bytes.Repeat([]byte{7}, 32), Signing: signing, Recipient: recipient}
	public := signing.Public().(ed25519.PublicKey)
	copy(device.KeyID, public[:])
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: "trust fixture", RootDevice: device, ContentKey: bytes.Repeat([]byte{9}, 32),
		Wraps:         []vault.RecipientWrapInput{{KeyID: bytes.Clone(device.KeyID), EphemeralPrivate: [32]byte(bytes.Repeat([]byte{3}, 32)), WrapNonce: [24]byte(bytes.Repeat([]byte{4}, 24))}},
		PublicationID: [16]byte(bytes.Repeat([]byte{5}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{6}, 24)),
	})
	require.NoError(t, err)
	require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID, RecordedAt: 1}))
	checkpoint := state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: bytes.Clone(genesis.ControlCID), ControlBytes: bytes.Clone(genesis.Control),
		SnapshotCID: bytes.Clone(genesis.SnapshotCID), Epoch: 0, PolicyDigest: genesis.PolicyDigest, RecordedAt: 1,
	}
	require.NoError(t, store.PutVaultCheckpoint(context.Background(), checkpoint))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(context.Background(), state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest,
		Policy: bytes.Clone(genesis.Policy), Control: bytes.Clone(genesis.Control), Head: bytes.Clone(genesis.Head),
		Certificates: [][]byte{bytes.Clone(genesis.Certificate)}, CheckpointPosition: bytes.Clone(genesis.Checkpoint),
	}))
	return genesis, device
}

func TestStateTrustSourceLoadsAndAuthenticatesLocalCheckpoint(t *testing.T) {
	store := openCoordinatorState(t)
	genesis, device := seedGenesisTrust(t, store)
	trust, err := (StateTrustSource{State: store, Keyring: memoryDeviceKeys{device: device}}).Resolve(context.Background(), VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, genesis.Anchor, trust.Anchor)
	assert.Equal(t, genesis.Control, trust.Held.Control)
	assert.Equal(t, device.DeviceID, trust.Device.DeviceID)
}

func TestStateTrustSourceRefusesMissingCheckpointEvidenceKeyAndTamperedAnchor(t *testing.T) {
	ctx := context.Background()
	t.Run("no checkpoint", func(t *testing.T) {
		store, paths := openCoordinatorStateWithPaths(t)
		genesis, device := seedGenesisTrust(t, store)
		require.NoError(t, store.Close())
		raw := openRawState(t, paths)
		_, err := raw.ExecContext(ctx, "DELETE FROM vault_checkpoints WHERE vault = ?", genesis.Vault[:])
		require.NoError(t, err)
		require.NoError(t, raw.Close())
		reopened, err := state.Open(paths)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		_, err = (StateTrustSource{State: reopened, Keyring: memoryDeviceKeys{device: device}}).Resolve(ctx, VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID})
		assert.ErrorIs(t, err, ErrNoCheckpoint)
	})
	t.Run("genesis can begin from the recorded control and anchor", func(t *testing.T) {
		store, paths := openCoordinatorStateWithPaths(t)
		genesis, device := seedGenesisTrust(t, store)
		require.NoError(t, store.Close())
		raw := openRawState(t, paths)
		_, err := raw.ExecContext(ctx, "DELETE FROM authenticated_position_evidence WHERE vault = ?", genesis.Vault[:])
		require.NoError(t, err)
		require.NoError(t, raw.Close())
		reopened, err := state.Open(paths)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		trust, err := (StateTrustSource{State: reopened, Keyring: memoryDeviceKeys{device: device}}).Resolve(ctx, VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID})
		require.NoError(t, err)
		assert.Empty(t, trust.Held.Policy)
		assert.Equal(t, genesis.Control, trust.Held.Control)
	})
	t.Run("missing keyring item", func(t *testing.T) {
		store := openCoordinatorState(t)
		genesis, device := seedGenesisTrust(t, store)
		_, err := (StateTrustSource{State: store, Keyring: memoryDeviceKeys{device: device, err: errors.New("not found")}}).Resolve(ctx, VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID})
		assert.ErrorIs(t, err, ErrDeviceKeyMissing)
	})
	t.Run("tampered anchor", func(t *testing.T) {
		store, paths := openCoordinatorStateWithPaths(t)
		genesis, device := seedGenesisTrust(t, store)
		require.NoError(t, store.Close())
		raw := openRawState(t, paths)
		altered := bytes.Clone(genesis.Anchor[:])
		altered[0] ^= 0xff
		_, err := raw.ExecContext(ctx, "UPDATE vault_checkpoints SET anchor = ? WHERE vault = ?", altered, genesis.Vault[:])
		require.NoError(t, err)
		require.NoError(t, raw.Close())
		reopened, err := state.Open(paths)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		_, err = (StateTrustSource{State: reopened, Keyring: memoryDeviceKeys{device: device}}).Resolve(ctx, VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID})
		assert.ErrorIs(t, err, ErrTrustEvidenceInvalid)
	})
}

func TestStateTrustSourceRefusesMissingEpochPredecessorEvidence(t *testing.T) {
	ctx := context.Background()
	store, paths := openCoordinatorStateWithPaths(t)
	genesis, root := seedGenesisTrust(t, store)
	publisherSigning, publisherRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	publisher := vault.DeviceMaterial{DeviceID: "trust-successor", KeyID: bytes.Repeat([]byte{8}, 32), Signing: publisherSigning, Recipient: publisherRecipient}
	predecessor := vault.Predecessor{
		ControlCID: bytes.Clone(genesis.ControlCID), PolicyDigest: genesisPolicyDigest(t, genesis.Policy), EpochSeq: 0,
		HeadCID: bytes.Clone(genesis.SnapshotCID), Head: bytes.Clone(genesis.Head), Control: bytes.Clone(genesis.Control),
		Policy: bytes.Clone(genesis.Policy), Certificates: [][]byte{bytes.Clone(genesis.Certificate)}, TrustAnchor: genesis.Anchor,
	}
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: genesis.Vault, Signer: root, NewDevice: &publisher, RequestedRole: vault.RolePublisher,
		ContentKey: bytes.Repeat([]byte{9}, 32), Recipients: [][]byte{bytes.Clone(genesis.Certificate)},
		Wraps: []vault.RecipientWrapInput{
			{KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(bytes.Repeat([]byte{11}, 32)), WrapNonce: [24]byte(bytes.Repeat([]byte{12}, 24))},
			{KeyID: bytes.Clone(publisher.KeyID), EphemeralPrivate: [32]byte(bytes.Repeat([]byte{13}, 32)), WrapNonce: [24]byte(bytes.Repeat([]byte{14}, 24))},
		},
		Plaintext: []byte("synthetic successor snapshot"), PublicationID: [16]byte(bytes.Repeat([]byte{15}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{16}, 24)),
	})
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(transition.Policy)
	require.NoError(t, err)
	controlCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(transition.Control)
	require.NoError(t, err)
	head, err := vault.DecodeHead(transition.Head)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: controlCID.Bytes(), ControlBytes: bytes.Clone(transition.Control),
		SnapshotCID: bytes.Clone(head.SnapshotCID), Epoch: head.EpochSeq, PolicyDigest: policyDigest, RecordedAt: 2,
	}))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(ctx, state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 1, PolicyDigest: policyDigest, Policy: bytes.Clone(transition.Policy),
		Control: bytes.Clone(transition.Control), Head: bytes.Clone(transition.Head),
		Certificates: [][]byte{bytes.Clone(transition.Recipients[0]), bytes.Clone(transition.Recipients[1])},
	}))
	require.NoError(t, store.Close())
	raw := openRawState(t, paths)
	_, err = raw.ExecContext(ctx, "DELETE FROM authenticated_position_evidence WHERE vault = ? AND epoch = 0", genesis.Vault[:])
	require.NoError(t, err)
	require.NoError(t, raw.Close())
	reopened, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	_, err = (StateTrustSource{State: reopened, Keyring: memoryDeviceKeys{device: root}}).Resolve(ctx, VaultSelection{Vault: genesis.Vault, DeviceID: root.DeviceID})
	assert.ErrorIs(t, err, ErrMissingPredecessorEvidence)
}

func genesisPolicyDigest(t *testing.T, policy []byte) [32]byte {
	t.Helper()
	digest, err := vault.ComputePolicyDigest(policy)
	require.NoError(t, err)
	return digest
}

func openRawState(t *testing.T, paths platform.Paths) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.Join(paths.AppStateDir(), "state.db")}).String())
	require.NoError(t, err)
	return database
}
