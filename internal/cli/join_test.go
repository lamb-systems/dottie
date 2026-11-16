package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	joinGateDID      = "did:plc:joinjoinjoinjoinjoinjoin"
	joinGateDeviceID = "join-device"
	joinGateContent  = "synthetic join gate payload\n"
	joinGateTargetID = "dotfiles"
)

type joinGateKeyring struct {
	devices map[string]vault.DeviceMaterial
}

func (keyring *joinGateKeyring) StoreDeviceKeys(_ context.Context, vaultID [32]byte, device vault.DeviceMaterial) error {
	if vaultID == ([32]byte{}) || device.DeviceID == "" {
		return errors.New("invalid synthetic device keys")
	}
	if _, exists := keyring.devices[device.DeviceID]; exists {
		return errors.New("synthetic device keys already exist")
	}
	keyring.devices[device.DeviceID] = device
	return nil
}

func (keyring *joinGateKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	device, ok := keyring.devices[deviceID]
	if !ok || vaultID == ([32]byte{}) {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	return device, nil
}

func (keyring *joinGateKeyring) DeleteDeviceKeys(_ context.Context, _ [32]byte, deviceID string) error {
	delete(keyring.devices, deviceID)
	return nil
}

func (keyring *joinGateKeyring) Close() error { return nil }

type joinGatePreflight struct {
	identity  atproto.Identity
	transport atproto.Transport
}

func (port joinGatePreflight) Preflight(ctx context.Context) error {
	return atproto.CheckNoDottiePublication(ctx, atproto.RevisionReader{
		Transport: port.transport, DIDDocumentID: port.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...),
	}, port.transport, port.identity.DID)
}

type joinGateMachine struct {
	paths    platform.Paths
	selected string
}

type joinGate struct {
	pds      *atprototest.MemoryPDS
	identity atproto.Identity
	keyring  *joinGateKeyring
	a        *joinGateMachine
	b        *joinGateMachine
}

func newJoinGate(t *testing.T) *joinGate {
	t.Helper()
	key, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(joinGateDID, key)
	require.NoError(t, err)
	pds.SetHooks(atprototest.MemoryPDSHooks{CanonicalizeBlobMIMEType: true})
	method := pds.VerificationMethod()
	identity := atproto.Identity{
		DID: joinGateDID, DIDDocumentID: joinGateDID, Handle: "join.example.test",
		VerificationMethods: []atproto.VerificationMethod{{
			ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
		}},
	}
	root := t.TempDir()
	return &joinGate{
		pds: pds, identity: identity, keyring: &joinGateKeyring{devices: map[string]vault.DeviceMaterial{}},
		a: newJoinGateMachine(t, root, "machine-a"), b: newJoinGateMachine(t, root, "machine-b"),
	}
}

func newJoinGateMachine(t *testing.T, root, name string) *joinGateMachine {
	t.Helper()
	machineRoot := filepath.Join(root, name)
	paths := platform.Paths{
		Home: filepath.Join(machineRoot, "home"), ConfigHome: filepath.Join(machineRoot, "config"),
		StateHome: filepath.Join(machineRoot, "state"), CacheHome: filepath.Join(machineRoot, "cache"),
		DataHome: filepath.Join(machineRoot, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	selected := filepath.Join(paths.Home, joinGateTargetID)
	require.NoError(t, os.MkdirAll(selected, 0o700))
	configurationDir := paths.AppConfigDir()
	require.NoError(t, os.MkdirAll(configurationDir, 0o700))
	require.NoError(t, os.Chmod(configurationDir, 0o700))
	document := "config_version = 2\nselection_revision = 1\napproval_revision = 1\n\n[[targets]]\nid = \"" + joinGateTargetID + "\"\nsource = \"files\"\n\n[targets.root]\nbase = \"home\"\npath = \"" + joinGateTargetID + "\"\nkind = \"directory\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(configurationDir, config.FileName), []byte(document), 0o600))
	return &joinGateMachine{paths: paths, selected: selected}
}

func (machine *joinGateMachine) setEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", machine.paths.Home)
	t.Setenv("XDG_CONFIG_HOME", machine.paths.ConfigHome)
	t.Setenv("XDG_STATE_HOME", machine.paths.StateHome)
	t.Setenv("XDG_CACHE_HOME", machine.paths.CacheHome)
	t.Setenv("XDG_DATA_HOME", machine.paths.DataHome)
}

func (machine *joinGateMachine) trackedPath() string {
	return filepath.Join(machine.selected, "init.lua")
}

func (gate *joinGate) session() *atproto.Session {
	return &atproto.Session{DID: joinGateDID, Handle: gate.identity.Handle, Scopes: atproto.VaultScopes()}
}

func (gate *joinGate) revisionReader() atproto.RevisionReader {
	return atproto.RevisionReader{
		Transport: gate.pds, Budgets: atproto.DefaultBudgets(), DIDDocumentID: gate.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), gate.identity.VerificationMethods...),
	}
}

func joinGateVault(t *testing.T, output string) string {
	t.Helper()
	match := regexp.MustCompile(`(?m)^vault fingerprint: ([0-9a-f]{64})$`).FindStringSubmatch(output)
	require.Len(t, match, 2)
	return match[1]
}

func joinGateBinding(t *testing.T, vaultHex string) publicationstate.Binding {
	t.Helper()
	vault, err := parseVaultFingerprint(vaultHex)
	require.NoError(t, err)
	return publicationstate.Binding{
		AccountDID: joinGateDID, Backend: publicationstate.BackendPublicRepo,
		Repository: "at://" + joinGateDID, Vault: vault,
	}
}

func (gate *joinGate) bootstrap(t *testing.T, machine *joinGateMachine) string {
	t.Helper()
	machine.setEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := 0
	factory := func(ctx context.Context, _ *urfave.Command) (bootstrapCoordinator, func(), error) {
		paths, err := platform.Resolve(os.Getenv)
		if err != nil {
			return nil, func() {}, err
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, func() {}, err
		}
		coordinator, err := service.NewCoordinator(service.Dependencies{
			State: store, DeviceKeys: gate.keyring, Clock: time.Now,
			GenesisPreflight: joinGatePreflight{identity: gate.identity, transport: gate.pds},
		})
		if err != nil {
			_ = store.Close()
			return nil, func() {}, err
		}
		return coordinator, func() { _ = store.Close() }, nil
	}
	command := newAccountCommandWithFactories(&stdout, &stderr, func() (accountKeyring, error) {
		return gate.keyring, nil
	}, &code, accountSessionOptions{browser: func(string) error { return nil }, env: os.Getenv}, factory)
	ctx := context.Background()
	if err := command.Run(ctx, []string{"account", "bootstrap", "--vault-name", "join", "--device-id", joinGateDeviceID, "--did", joinGateDID}); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	require.Equal(t, 0, code, stderr.String())
	require.Contains(t, stdout.String(), "bootstrap: local-identity-recorded")
	return joinGateVault(t, stdout.String())
}

func (gate *joinGate) pushSources(ctx context.Context) (publicationPushSources, error) {
	paths, err := platform.Resolve(os.Getenv)
	if err != nil {
		return publicationPushSources{}, err
	}
	store, err := state.Open(paths)
	if err != nil {
		return publicationPushSources{}, err
	}
	closeStore := func() { _ = store.Close() }
	configuration := service.FileConfigPort{Paths: paths}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: configuration, State: store, Settings: manualGNOMESettings(), Paths: paths, Clock: time.Now,
	})
	if err != nil {
		closeStore()
		return publicationPushSources{}, err
	}
	selected, err := coordinator.ResolveSelection(ctx, service.VaultSelection{DeviceID: joinGateDeviceID})
	if err != nil {
		closeStore()
		return publicationPushSources{}, err
	}
	loaded, err := configuration.Load(ctx)
	if err != nil {
		closeStore()
		return publicationPushSources{}, err
	}
	if err := loaded.Validate(); err != nil {
		closeStore()
		return publicationPushSources{}, err
	}
	binding := publicationstate.Binding{
		AccountDID: joinGateDID, Backend: publicationstate.BackendPublicRepo,
		Repository: "at://" + joinGateDID, Vault: selected.Vault,
	}
	adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
		Binding: binding, DID: joinGateDID, Reader: gate.revisionReader(), Transport: gate.pds,
		BlobUploadLimit: int64(publication.MaxBlobBytes),
	})
	if err != nil {
		closeStore()
		return publicationPushSources{}, err
	}
	reader, err := service.NewPublicationReader(service.PublicationReaderConfig{
		Binding: binding, DID: joinGateDID, Session: gate.session(), Adapter: adapter,
		Blobs: atproto.VaultReader{Transport: gate.pds, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: time.Now},
	})
	if err != nil {
		closeStore()
		return publicationPushSources{}, err
	}
	return publicationPushSources{
		Paths: paths, Binding: binding, Coordinator: coordinator, Reader: reader,
		Transport: adapter, Reviews: configuration, Records: newPublicationProposalStore(paths.PublicationStateDir()),
		Configuration: loaded, Close: closeStore,
	}, nil
}

func (gate *joinGate) pullRemotes(_ context.Context, _ *urfave.Command, _ pushSession, binding publicationstate.Binding) (pullRemote, error) {
	adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
		Binding: binding, DID: joinGateDID, Reader: gate.revisionReader(), Transport: gate.pds,
		BlobUploadLimit: int64(publication.MaxBlobBytes),
	})
	if err != nil {
		return pullRemote{}, err
	}
	blobs := atproto.VaultReader{Transport: gate.pds, Budgets: atproto.DefaultBudgets()}
	reader, err := service.NewPublicationReader(service.PublicationReaderConfig{
		Binding: binding, DID: joinGateDID, Session: gate.session(), Adapter: adapter, Blobs: blobs,
	})
	if err != nil {
		return pullRemote{}, err
	}
	return pullRemote{
		Reader: reader,
		Blob: func(ctx context.Context, record publication.SnapshotRecord) ([]byte, error) {
			return blobs.FetchBlob(ctx, joinGateDID, record.Blob.CID, int64(record.Blob.Size))
		},
		Close: func() {},
	}, nil
}

func (gate *joinGate) push(t *testing.T, machine *joinGateMachine, args ...string) (int, string, string) {
	t.Helper()
	machine.setEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		return pushSession{Session: gate.session()}, nil
	}
	sources := func(ctx context.Context, _ *urfave.Command, _ pushSession) (publicationPushSources, error) {
		return gate.pushSources(ctx)
	}
	command := newPushCommand(&stdout, &stderr, &code, sessions, sources, pushTestDIDs(gate.session().DID))
	ctx := context.Background()
	if err := command.Run(ctx, append([]string{"dottie", "push"}, args...)); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code, stdout.String(), stderr.String()
}

func (gate *joinGate) pull(t *testing.T, machine *joinGateMachine, args ...string) (int, string, string) {
	t.Helper()
	machine.setEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		return pushSession{Session: gate.session()}, nil
	}
	command := newPullCommand(&stdout, &stderr, &code, sessions, gate.pullRemotes, productionPullApplySourcesFactory(os.Getenv), pushTestDIDs(gate.session().DID), os.Getenv)
	ctx := context.Background()
	if err := command.Run(ctx, append([]string{"dottie", "pull"}, args...)); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code, stdout.String(), stderr.String()
}

func TestJoinGateBootstrapPushAndNewcomerPull(t *testing.T) {
	gate := newJoinGate(t)
	vaultHex := gate.bootstrap(t, gate.a)
	require.NoError(t, os.WriteFile(gate.a.trackedPath(), []byte(joinGateContent), 0o600))

	code, stdout, stderr := gate.push(t, gate.a, "--did", joinGateDID)
	require.Equal(t, 3, code, stderr+"\n"+stdout)
	assert.Contains(t, stdout, "push: review required\n")
	assert.Contains(t, stdout, "accepted floor: none (first publication)\n")
	confirmation := confirmationFromOutput(t, stdout)
	info, err := os.Stat(gate.a.paths.PublicationStateDir())
	require.NoError(t, err, "the reviewed push did not provision the position store")
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	code, stdout, stderr = gate.push(t, gate.a, "--did", joinGateDID, "--confirm", confirmation)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "push: committed")
	assert.Contains(t, stdout, "floor: revision=1 generation=1 sequence=0\n")

	_, statErr := os.Lstat(gate.b.paths.PublicationStateDir())
	require.ErrorIs(t, statErr, os.ErrNotExist, "the newcomer started with a publication position store")

	code, stdout, stderr = gate.pull(t, gate.b, "--did", joinGateDID, "--vault", vaultHex)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(t, stdout, fmt.Sprintf("apply: write init.lua size=%d\n", len(joinGateContent)))
	assert.Contains(t, stdout, "pull: plan only; nothing was applied; repeat with --confirm ")
	inspection, err := publicationstate.Inspect(context.Background(), gate.b.paths.PublicationStateDir(), joinGateBinding(t, vaultHex))
	require.NoError(t, err)
	assert.False(t, inspection.Present, "the unconfirmed newcomer pull accepted a floor")
	_, statErr = os.Lstat(gate.b.trackedPath())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the unconfirmed newcomer pull applied a target file")
	token := pullTestConfirmation(t, stdout)

	code, stdout, stderr = gate.pull(t, gate.b, "--did", joinGateDID, "--vault", vaultHex, "--confirm", token)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(t, stdout, fmt.Sprintf("pull: applied changes=1 unchanged=0 bytes=%d\n", len(joinGateContent)))
	assert.Contains(t, stdout, "floor: revision=1 generation=1 sequence=0\n")
	applied, err := os.ReadFile(gate.b.trackedPath())
	require.NoError(t, err)
	assert.Equal(t, joinGateContent, string(applied))
	adopted, err := publicationstate.Inspect(context.Background(), gate.b.paths.PublicationStateDir(), joinGateBinding(t, vaultHex))
	require.NoError(t, err)
	require.True(t, adopted.Present)
	assert.Equal(t, uint64(1), adopted.Floor.Revision)
	assert.Equal(t, publicationstate.ProvenanceFirst, adopted.Floor.Provenance)

	code, stdout, stderr = gate.pull(t, gate.b, "--did", joinGateDID, "--vault", vaultHex)
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "pull: matches\n", stdout)
	unchanged, err := publicationstate.Inspect(context.Background(), gate.b.paths.PublicationStateDir(), joinGateBinding(t, vaultHex))
	require.NoError(t, err)
	assert.Equal(t, adopted.Floor, unchanged.Floor, "the second pull moved the adopted floor")
}
