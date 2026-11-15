package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	urfave "github.com/urfave/cli/v3"
)

type memoryAccountKeyring struct {
	items       map[string]vault.DeviceMaterial
	err         error
	storeCalls  int
	deleteCalls int
}

func (k *memoryAccountKeyring) StoreDeviceKeys(_ context.Context, vaultID [32]byte, material vault.DeviceMaterial) error {
	k.storeCalls++
	if k.err != nil {
		return k.err
	}
	cloned, err := cloneAccountMaterial(material)
	if err != nil {
		return err
	}
	k.items[accountItemKey(vaultID, material.DeviceID)] = cloned
	return nil
}

func (k *memoryAccountKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if k.err != nil {
		return vault.DeviceMaterial{}, k.err
	}
	material, ok := k.items[accountItemKey(vaultID, deviceID)]
	if !ok {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	return cloneAccountMaterial(material)
}

func (k *memoryAccountKeyring) LoadDeviceKeysForVault(ctx context.Context, vaultID [32]byte) ([]vault.DeviceMaterial, error) {
	prefix := hex.EncodeToString(vaultID[:]) + ":"
	materials := make([]vault.DeviceMaterial, 0)
	for name := range k.items {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		deviceID := strings.TrimPrefix(name, prefix)
		material, err := k.LoadDeviceKeys(ctx, vaultID, deviceID)
		if err != nil {
			return nil, err
		}
		materials = append(materials, material)
	}
	if len(materials) == 0 {
		return nil, platform.ErrKeyringItemNotFound
	}
	return materials, nil
}

func (k *memoryAccountKeyring) DeleteDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) error {
	k.deleteCalls++
	if k.err != nil {
		return k.err
	}
	delete(k.items, accountItemKey(vaultID, deviceID))
	return nil
}

func (k *memoryAccountKeyring) Close() error {
	return nil
}

func cloneAccountMaterial(material vault.DeviceMaterial) (vault.DeviceMaterial, error) {
	recipient, err := ecdh.X25519().NewPrivateKey(material.Recipient.Bytes())
	if err != nil {
		return vault.DeviceMaterial{}, err
	}
	return vault.DeviceMaterial{
		DeviceID: material.DeviceID, KeyID: bytes.Clone(material.KeyID),
		Signing: bytes.Clone(material.Signing), Recipient: recipient,
	}, nil
}

func accountItemKey(vaultID [32]byte, deviceID string) string {
	return hex.EncodeToString(vaultID[:]) + ":" + deviceID
}

type bootstrapOutputFailure struct{}

func (bootstrapOutputFailure) Write([]byte) (int, error) {
	return 0, errors.New("synthetic output failure")
}

type injectedBootstrapGenesisPort struct {
	transport    atproto.Transport
	reader       atproto.RevisionReader
	did          string
	observations atproto.PublicationObservationStore
	limit        int64
	unresolved   bool
}

func (port injectedBootstrapGenesisPort) Preflight(ctx context.Context) error {
	return atproto.CheckGenesisRepositoryEmpty(ctx, port.reader, port.transport, port.did)
}

func (port injectedBootstrapGenesisPort) BlobUploadLimit(context.Context) (int64, error) {
	return port.limit, nil
}

func (port injectedBootstrapGenesisPort) CommitGenesis(ctx context.Context, limit int64, kit []byte, root vault.DeviceMaterial, genesis vault.Genesis) (atproto.GenesisCommitResult, error) {
	result, err := atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: port.reader, Transport: port.transport, BlobUploadLimit: limit, DID: port.did,
		ObservationStore: port.observations,
	}, kit, root, genesis)
	if err == nil && port.unresolved {
		result.Phase = atproto.GenesisSubmitted
		return result, atproto.ErrGenesisUnavailable
	}
	return result, err
}

func TestAccountBootstrapCommandPublishesWithInjectedAuthenticatedProvider(t *testing.T) {
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"), DataHome: filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	const did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(did, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	reader := atproto.RevisionReader{Transport: pds, DIDDocumentID: did, VerificationMethods: []atproto.VerificationMethod{{
		ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
	}}}
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	unresolved := false
	factory := func(ctx context.Context, command *urfave.Command) (bootstrapCoordinator, func(), error) {
		if command.String("did") != did {
			return nil, func() {}, errors.New("unexpected authenticated identity")
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, func() {}, err
		}
		port := injectedBootstrapGenesisPort{transport: pds, reader: reader, did: did, observations: store, limit: 1 << 20, unresolved: unresolved}
		clock := func() time.Time { return time.Unix(1_800_000_000, 0) }
		coordinator, err := service.NewCoordinator(service.Dependencies{
			State: store, DeviceKeys: keyring, Genesis: port,
			Trust:   service.StateTrustSource{State: store, Keyring: keyring},
			Session: manualReadSession{identity: atproto.Identity{DID: did, DIDDocumentID: did, VerificationMethods: reader.VerificationMethods}},
			Remote:  service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: clock}},
			Clock:   clock,
		})
		if err != nil {
			_ = store.Close()
			return nil, func() {}, err
		}
		return coordinator, func() { _ = store.Close() }, nil
	}
	open := func() (accountKeyring, error) { return keyring, nil }
	runArgs := func(args []string, stdout, stderr io.Writer) int {
		code := 0
		command := newAccountCommandWithFactories(stdout, stderr, open, &code,
			accountSessionOptions{env: func(string) string { return "" }}, factory)
		return runAccountCommandForAccountTest(command, &code, args...)
	}
	run := func(stdout, stderr io.Writer) int {
		return runArgs([]string{"bootstrap", "--vault-name", "personal", "--device-id", "root-device", "--did", did}, stdout, stderr)
	}
	var stderr bytes.Buffer
	code := run(bootstrapOutputFailure{}, &stderr)
	assert.NotZero(t, code)
	assert.Empty(t, keyring.items)
	store, err := state.Open(paths)
	require.NoError(t, err)
	selections, err := store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Empty(t, selections)
	require.NoError(t, store.Close())
	emptyRevision, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Empty(t, emptyRevision.Membership())
	keyring.err = platform.ErrKeyringUnavailable
	var refusedOut, refusedErr bytes.Buffer
	code = run(&refusedOut, &refusedErr)
	require.Equal(t, 1, code)
	assert.NotContains(t, refusedOut.String(), "recovery kit (keep offline):")
	assert.Empty(t, keyring.items)
	revisionAfterKeyringFailure, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Equal(t, emptyRevision.CommitCID(), revisionAfterKeyringFailure.CommitCID())
	keyring.err = nil
	var stdout bytes.Buffer
	stderr.Reset()
	code = run(&stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Empty(t, stderr.String())
	assert.Equal(t, 1, strings.Count(stdout.String(), "recovery kit (keep offline):"))
	assert.Contains(t, stdout.String(), "genesis: verified-commit")
	kitLine := strings.SplitN(stdout.String(), "recovery kit (keep offline): ", 2)
	require.Len(t, kitLine, 2)
	groupedKit := strings.Fields(kitLine[1])[0]
	kit, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(groupedKit, "-", ""))
	require.NoError(t, err)
	require.Len(t, kit, 32)
	assert.Len(t, keyring.items, 1)
	for _, device := range keyring.items {
		assert.False(t, bytes.Contains(device.Signing, kit))
		assert.False(t, bytes.Contains(device.Recipient.Bytes(), kit))
	}
	store, err = state.Open(paths)
	require.NoError(t, err)
	selections, err = store.VaultSelections(context.Background())
	require.NoError(t, err)
	require.Len(t, selections, 1)
	checkpoint, err := store.VaultCheckpoint(context.Background(), selections[0].Vault)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), checkpoint.Epoch)
	evidence, err := store.AuthenticatedPositionEvidenceAtEpoch(context.Background(), selections[0].Vault, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, evidence.CheckpointPosition)
	require.NoError(t, store.Close())
	var finalizeOut, finalizeErr bytes.Buffer
	code = runArgs([]string{"finalize", "--vault", hex.EncodeToString(selections[0].Vault[:]), "--did", did}, &finalizeOut, &finalizeErr)
	require.Equal(t, 0, code)
	assert.Empty(t, finalizeErr.String())
	assert.Contains(t, finalizeOut.String(), "trust already finalized; no change")
	assert.NotContains(t, finalizeOut.String(), "recovery kit")
	stateBytes, err := os.ReadFile(filepath.Join(paths.AppStateDir(), "state.db"))
	require.NoError(t, err)
	assert.False(t, bytes.Contains(stateBytes, kit))
	revision, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	beforeCommit := revision.CommitCID()
	storeCallsBeforeRefusal := keyring.storeCalls
	deleteCallsBeforeRefusal := keyring.deleteCalls
	stdout.Reset()
	stderr.Reset()
	code = run(&stdout, &stderr)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "genesis requires an empty verified repository")
	assert.NotContains(t, stdout.String(), "recovery kit (keep offline):")
	assert.Len(t, keyring.items, 1)
	store, err = state.Open(paths)
	require.NoError(t, err)
	selections, err = store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Len(t, selections, 1)
	require.NoError(t, store.Close())
	stateAfterRefusal, err := os.ReadFile(filepath.Join(paths.AppStateDir(), "state.db"))
	require.NoError(t, err)
	assert.Equal(t, stateBytes, stateAfterRefusal)
	assert.Equal(t, storeCallsBeforeRefusal, keyring.storeCalls)
	assert.Equal(t, deleteCallsBeforeRefusal, keyring.deleteCalls)
	keyName := accountItemKey(selections[0].Vault, selections[0].DeviceID)
	device, exists := keyring.items[keyName]
	require.True(t, exists)
	delete(keyring.items, keyName)
	var missingKeysOut, missingKeysErr bytes.Buffer
	code = runArgs([]string{"finalize", "--vault", hex.EncodeToString(selections[0].Vault[:]), "--did", did}, &missingKeysOut, &missingKeysErr)
	require.Equal(t, 3, code)
	assert.Contains(t, missingKeysErr.String(), "device keys for this vault are missing from Secret Service")
	assert.NotContains(t, missingKeysOut.String(), "recovery kit")
	keyring.items[keyName] = device
	revision, err = reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Equal(t, beforeCommit, revision.CommitCID())
	assert.Len(t, revision.Records(), 6)
	assert.NotContains(t, stdout.String(), string(kit))
	secondRepositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err = atprototest.NewMemoryPDS(did, secondRepositoryKey)
	require.NoError(t, err)
	method = pds.VerificationMethod()
	reader = atproto.RevisionReader{Transport: pds, DIDDocumentID: did, VerificationMethods: []atproto.VerificationMethod{{
		ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
	}}}
	unresolved = true
	stdout.Reset()
	stderr.Reset()
	code = runArgs([]string{"bootstrap", "--vault-name", "unresolved vault", "--device-id", "second-root", "--did", did}, &stdout, &stderr)
	require.Equal(t, 4, code)
	assert.Contains(t, stdout.String(), "genesis: unresolved")
	assert.Equal(t, 1, strings.Count(stdout.String(), "recovery kit (keep offline):"))
	assert.Equal(t, 6, strings.Count(stdout.String(), "record target:"))
	assert.Contains(t, stdout.String(), "do not retry bootstrap until publication is resolved")
	assert.Contains(t, stderr.String(), "genesis publication is unresolved")
	assert.Len(t, keyring.items, 2)
	revision, err = reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Len(t, revision.Records(), 6)
}

func TestAccountKeyringFactoryErrorDoesNotExposeDetails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	open := func() (accountKeyring, error) { return nil, errors.New("synthetic backend detail") }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"bootstrap", "--vault-name", "vault", "--device-id", "root", "--did", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}, &stdout, &stderr, open)
	require.Equal(t, 1, code, "keyring error exit code")
	assert.NotContains(t, stderr.String(), "synthetic backend detail", "keyring detail leaked")
}

func runAccountCommandForAccountTest(root *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	if err := root.Run(ctx, append([]string{"account"}, args...)); err != nil && *exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return *exitCode
}
