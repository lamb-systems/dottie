package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
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
	"github.com/lamb-systems/dottie/internal/publication"
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

type flushRecordingWriter struct {
	buffer bytes.Buffer
	flush  int
}

func (writer *flushRecordingWriter) Write(data []byte) (int, error) {
	return writer.buffer.Write(data)
}

func (writer *flushRecordingWriter) Flush() error {
	writer.flush++
	return nil
}

type injectedBootstrapPreflight struct {
	transport atproto.Transport
	reader    atproto.RevisionReader
	did       string
}

func (port injectedBootstrapPreflight) Preflight(ctx context.Context) error {
	return atproto.CheckNoDottiePublication(ctx, port.reader, port.transport, port.did)
}

func TestAccountBootstrapCommandRecordsLocalIdentityWithoutPublishing(t *testing.T) {
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
	factory := func(ctx context.Context, command *urfave.Command) (bootstrapCoordinator, func(), error) {
		if command.String("did") != did {
			return nil, func() {}, errors.New("unexpected authenticated identity")
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, func() {}, err
		}
		port := injectedBootstrapPreflight{transport: pds, reader: reader, did: did}
		coordinator, err := service.NewCoordinator(service.Dependencies{
			State: store, DeviceKeys: keyring, GenesisPreflight: port,
			Clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
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
	emptyRevision, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Empty(t, emptyRevision.Membership())
	keyring.err = platform.ErrKeyringUnavailable
	var refusedOut, refusedErr bytes.Buffer
	code := run(&refusedOut, &refusedErr)
	require.Equal(t, 3, code)
	assert.Contains(t, refusedOut.String(), "bootstrap: not-recorded")
	assert.Contains(t, refusedErr.String(), "bootstrap recorded no local vault")
	assert.Empty(t, keyring.items)
	revisionAfterKeyringFailure, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Equal(t, emptyRevision.CommitCID(), revisionAfterKeyringFailure.CommitCID())
	keyring.err = nil
	stdout := &flushRecordingWriter{}
	stderr.Reset()
	code = run(stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Empty(t, stderr.String())
	assert.Contains(t, stdout.buffer.String(), "bootstrap: local-identity-recorded")
	assert.NotContains(t, stdout.buffer.String(), "record target:")
	assert.NotContains(t, stdout.buffer.String(), "commit:")
	assert.NotContains(t, strings.ToLower(stdout.buffer.String()), "kit")
	assert.Zero(t, stdout.flush)
	assert.Len(t, keyring.items, 1)
	store, err := state.Open(paths)
	require.NoError(t, err)
	selections, err := store.VaultSelections(context.Background())
	require.NoError(t, err)
	require.Len(t, selections, 1)
	assert.Equal(t, "root-device", selections[0].DeviceID)
	_, err = store.VaultCheckpoint(context.Background(), selections[0].Vault)
	assert.ErrorIs(t, err, state.ErrVaultCheckpointNotFound)
	assert.Contains(t, stdout.buffer.String(), hex.EncodeToString(selections[0].Vault[:]))
	require.NoError(t, store.Close())
	revision, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Empty(t, revision.Membership())
	assert.Equal(t, emptyRevision.CommitCID(), revision.CommitCID())
	stdout.buffer.Reset()
	stderr.Reset()
	code = run(stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.buffer.String(), "bootstrap: local-identity-recorded")
	assert.Len(t, keyring.items, 2)
	store, err = state.Open(paths)
	require.NoError(t, err)
	selections, err = store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Len(t, selections, 2, "each bootstrap derives a fresh vault identity from fresh device keys")
	require.NoError(t, store.Close())
	revision, err = reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Empty(t, revision.Membership())
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

func TestAccountBootstrapRefusesAccountHoldingADottiePublication(t *testing.T) {
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
	seed := []byte(`{"repo":"` + did + `","swapCommit":"` + pds.CurrentRevision().CommitCID.String() + `","writes":[` +
		`{"$type":"com.atproto.repo.applyWrites#create","collection":"app.bsky.actor.profile","rkey":"self","value":{"$type":"app.bsky.actor.profile","probe":"bootstrap"}},` +
		`{"$type":"com.atproto.repo.applyWrites#create","collection":"` + publication.HeadNSID + `","rkey":"self","value":{"$type":"` + publication.HeadNSID + `","schemaVersion":2}}]}`)
	status, _, err := pds.Do(context.Background(), "POST", "com.atproto.repo.applyWrites", nil, seed, "application/json")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	before, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	require.Len(t, before.Membership(), 2)
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	factory := func(ctx context.Context, command *urfave.Command) (bootstrapCoordinator, func(), error) {
		if command.String("did") != did {
			return nil, func() {}, errors.New("unexpected authenticated identity")
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, func() {}, err
		}
		coordinator, err := service.NewCoordinator(service.Dependencies{
			State: store, DeviceKeys: keyring,
			GenesisPreflight: injectedBootstrapPreflight{transport: pds, reader: reader, did: did},
		})
		if err != nil {
			_ = store.Close()
			return nil, func() {}, err
		}
		return coordinator, func() { _ = store.Close() }, nil
	}
	open := func() (accountKeyring, error) { return keyring, nil }
	var stdout, stderr bytes.Buffer
	code := 0
	command := newAccountCommandWithFactories(&stdout, &stderr, open, &code,
		accountSessionOptions{env: func(string) string { return "" }}, factory)
	code = runAccountCommandForAccountTest(command, &code, "bootstrap", "--vault-name", "personal", "--device-id", "root-device", "--did", did)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "no existing Dottie publication")
	assert.Empty(t, keyring.items)
	assert.Zero(t, keyring.storeCalls)
	store, err := state.Open(paths)
	require.NoError(t, err)
	selections, err := store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Empty(t, selections)
	require.NoError(t, store.Close())
	after, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Len(t, after.Membership(), 2)
	assert.Equal(t, before.CommitCID(), after.CommitCID())
}

func runAccountCommandForAccountTest(root *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	if err := root.Run(ctx, append([]string{"account"}, args...)); err != nil && *exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return *exitCode
}
