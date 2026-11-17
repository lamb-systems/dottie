package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
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

func (keyring *joinGateKeyring) StoreDeviceKeys(
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

func (keyring *joinGateKeyring) LoadDeviceKeys(
	_ context.Context,
	vaultID [32]byte,
	deviceID string,
) (vault.DeviceMaterial, error) {
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

	vaultReads int
}

func newJoinGate(t *testing.T) *joinGate {
	t.Helper()
	key, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(joinGateDID, key)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	identity := atproto.Identity{
		DID: joinGateDID, DIDDocumentID: joinGateDID, Handle: "join.example.test",
		VerificationMethods: []atproto.VerificationMethod{
			{
				ID:                 method.ID,
				Type:               method.Type,
				Controller:         method.Controller,
				PublicKeyMultibase: method.PublicKeyMultibase,
			},
		},
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
	factory := func(_ context.Context, _ *urfave.Command) (bootstrapCoordinator, func(), error) {
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
	}, &code, accountSessionOptions{browser: func(context.Context, string) error { return nil }, env: os.Getenv}, factory)
	ctx := context.Background()
	if err := command.Run(
		ctx,
		[]string{"account", "bootstrap", "--vault-name", "join", "--device-id", joinGateDeviceID, "--did", joinGateDID},
	); err != nil &&
		code == 0 {
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
		Binding: binding,
		DID:     joinGateDID,
		Session: gate.session(),
		Adapter: adapter,
		Blobs: atproto.VaultReader{
			Transport:        gate.pds,
			ObservationStore: store,
			Budgets:          atproto.DefaultBudgets(),
			Clock:            time.Now,
		},
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

func (gate *joinGate) pullRemotes(
	_ context.Context,
	_ *urfave.Command,
	_ pushSession,
	binding publicationstate.Binding,
) (pullRemote, error) {
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

func (gate *joinGate) pullVaults(ctx context.Context, _ *urfave.Command, session pushSession) ([32]byte, error) {
	gate.vaultReads++
	head, err := service.ReadPublishedHead(ctx, service.PublicationHeadConfig{
		DID: joinGateDID, Session: session.Session, Reader: gate.revisionReader(),
	})
	if err != nil {
		return [32]byte{}, err
	}
	return head.Vault, nil
}

func (gate *joinGate) pull(t *testing.T, machine *joinGateMachine, args ...string) (int, string, string) {
	t.Helper()
	machine.setEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		return pushSession{Session: gate.session()}, nil
	}
	command := newPullCommand(
		&stdout,
		&stderr,
		&code,
		sessions,
		gate.pullRemotes,
		gate.pullVaults,
		productionPullApplySourcesFactory(os.Getenv),
		pushTestDIDs(gate.session().DID),
		os.Getenv,
	)
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
	inspection, err := publicationstate.Inspect(
		context.Background(),
		gate.b.paths.PublicationStateDir(),
		joinGateBinding(t, vaultHex),
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present, "the unconfirmed newcomer pull accepted a floor")
	_, statErr = os.Lstat(gate.b.trackedPath())
	require.ErrorIs(t, statErr, os.ErrNotExist, "the unconfirmed newcomer pull applied a target file")
	token := pullTestConfirmation(t, stdout)

	code, stdout, stderr = gate.pull(t, gate.b, "--did", joinGateDID, "--vault", vaultHex, "--confirm", token)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(t, stdout, fmt.Sprintf("pull: applied changes=1 unchanged=0 bytes=%d\n", len(joinGateContent)))
	assert.Contains(t, stdout, "floor: revision=1 generation=1 sequence=0\n")
	applied, err := os.ReadFile(gate.b.trackedPath())
	require.NoError(t, err)
	assert.Equal(t, joinGateContent, string(applied))
	adopted, err := publicationstate.Inspect(
		context.Background(),
		gate.b.paths.PublicationStateDir(),
		joinGateBinding(t, vaultHex),
	)
	require.NoError(t, err)
	require.True(t, adopted.Present)
	assert.Equal(t, uint64(1), adopted.Floor.Revision)
	assert.Equal(t, publicationstate.ProvenanceFirst, adopted.Floor.Provenance)

	code, stdout, stderr = gate.pull(t, gate.b, "--did", joinGateDID, "--vault", vaultHex)
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "pull: matches\n", stdout)
	unchanged, err := publicationstate.Inspect(
		context.Background(),
		gate.b.paths.PublicationStateDir(),
		joinGateBinding(t, vaultHex),
	)
	require.NoError(t, err)
	assert.Equal(t, adopted.Floor, unchanged.Floor, "the second pull moved the adopted floor")
}

func (gate *joinGate) publish(t *testing.T) {
	t.Helper()
	require.NoError(t, os.WriteFile(gate.a.trackedPath(), []byte(joinGateContent), 0o600))
	code, stdout, stderr := gate.push(t, gate.a, "--did", joinGateDID)
	require.Equal(t, 3, code, stderr+"\n"+stdout)
	code, stdout, stderr = gate.push(t, gate.a, "--did", joinGateDID, "--confirm", confirmationFromOutput(t, stdout))
	require.Equal(t, 0, code, stderr+"\n"+stdout)
	require.Contains(t, stdout, "push: committed")
}

func (gate *joinGate) provisionStore(t *testing.T, machine *joinGateMachine, binding publicationstate.Binding) {
	t.Helper()
	machine.setEnvironment(t)
	require.NoError(t, os.MkdirAll(machine.paths.PublicationStateDir(), 0o700))
	require.NoError(t, os.Chmod(machine.paths.PublicationStateDir(), 0o700))
	store, err := publicationstate.Open(machine.paths.PublicationStateDir(), binding)
	require.NoError(t, err)
	require.NoError(t, store.Close())
}

func joinGateForeignVault() [32]byte {
	return [32]byte{0x91, 0x92, 0x93}
}

func joinGateForeignVaultHex() string {
	vault := joinGateForeignVault()
	return hex.EncodeToString(vault[:])
}

func TestJoinGateNewcomerPullsWithoutBeingToldTheVault(t *testing.T) {
	gate := newJoinGate(t)
	vaultHex := gate.bootstrap(t, gate.a)
	gate.publish(t)
	_, statErr := os.Lstat(gate.b.paths.PublicationStateDir())
	require.ErrorIs(t, statErr, os.ErrNotExist, "the newcomer started with a publication position store")

	code, stdout, stderr := gate.pull(t, gate.b, "--did", joinGateDID)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "vault: "+vaultHex+" (adopted from the published position at self)\n")
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(t, stdout, fmt.Sprintf("apply: write init.lua size=%d\n", len(joinGateContent)))
	assert.Contains(t, stdout, "pull: plan only; nothing was applied; repeat with --confirm ")
	assert.Equal(t, 1, gate.vaultReads, "the pull did not resolve the published vault")

	info, err := os.Stat(gate.b.paths.PublicationStateDir())
	require.NoError(t, err, "the unconfirmed newcomer pull did not provision the position store")
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	stored, err := publicationstate.ReadBinding(gate.b.paths.PublicationStateDir())
	require.NoError(t, err)
	assert.Equal(t, joinGateBinding(t, vaultHex), stored, "the adopted binding was not recorded")
	inspection, err := publicationstate.Inspect(context.Background(), gate.b.paths.PublicationStateDir(), stored)
	require.NoError(t, err)
	assert.False(t, inspection.Present, "the unconfirmed newcomer pull accepted a floor")
	_, payloadErr := os.Lstat(filepath.Join(gate.b.paths.PublicationStateDir(), "payloads"))
	require.ErrorIs(t, payloadErr, os.ErrNotExist, "the unconfirmed newcomer pull retained accepted material")
	_, statErr = os.Lstat(gate.b.trackedPath())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the unconfirmed newcomer pull applied a target file")
}

func TestJoinGateNewcomerConfirmsTheFirstUseJoin(t *testing.T) {
	gate := newJoinGate(t)
	vaultHex := gate.bootstrap(t, gate.a)
	gate.publish(t)

	code, stdout, stderr := gate.pull(t, gate.b, "--did", joinGateDID)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "vault: "+vaultHex+" (adopted from the published position at self)\n")
	token := pullTestConfirmation(t, stdout)

	code, stdout, stderr = gate.pull(t, gate.b, "--did", joinGateDID, "--confirm", token)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "vault: "+vaultHex+" (resolved from the recorded binding)\n")
	assert.NotContains(t, stdout, "adopted from the published position")
	assert.Contains(t, stdout, "pull: first-use\n")
	assert.Contains(t, stdout, fmt.Sprintf("pull: applied changes=1 unchanged=0 bytes=%d\n", len(joinGateContent)))
	assert.Contains(t, stdout, "floor: revision=1 generation=1 sequence=0\n")
	applied, err := os.ReadFile(gate.b.trackedPath())
	require.NoError(t, err)
	assert.Equal(t, joinGateContent, string(applied))
	joined, err := publicationstate.Inspect(
		context.Background(),
		gate.b.paths.PublicationStateDir(),
		joinGateBinding(t, vaultHex),
	)
	require.NoError(t, err)
	require.True(t, joined.Present)
	assert.Equal(t, uint64(1), joined.Floor.Revision)
	assert.Equal(t, publicationstate.ProvenanceFirst, joined.Floor.Provenance)

	code, stdout, stderr = gate.pull(t, gate.b, "--did", joinGateDID)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: matches\n")
	unchanged, err := publicationstate.Inspect(
		context.Background(),
		gate.b.paths.PublicationStateDir(),
		joinGateBinding(t, vaultHex),
	)
	require.NoError(t, err)
	assert.Equal(t, joined.Floor, unchanged.Floor, "the second pull moved the joined floor")
}

func TestJoinGateExplicitVaultOverridesThePublishedHead(t *testing.T) {
	gate := newJoinGate(t)
	gate.bootstrap(t, gate.a)
	gate.publish(t)

	code, stdout, stderr := gate.pull(t, gate.b, "--did", joinGateDID, "--vault", joinGateForeignVaultHex())
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: unreadable (vault)\n", stdout)
	assert.Contains(t, stderr, "the provider position cannot be read or validated")
	assert.Zero(t, gate.vaultReads, "an explicit --vault still read the published vault")
	_, statErr := os.Lstat(gate.b.trackedPath())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the refused pull applied a target file")
}

func TestJoinGateNewcomerRefusesAnAccountWithNoPublication(t *testing.T) {
	gate := newJoinGate(t)
	gate.bootstrap(t, gate.a)

	code, stdout, stderr := gate.pull(t, gate.b, "--did", joinGateDID)
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: no-publication\n", stdout)
	assert.Contains(t, stderr, "the account publishes no v2 position record at self")
	assert.Contains(t, stderr, "pass --vault to name the vault this command acts on")
	_, statErr := os.Lstat(gate.b.paths.PublicationStateDir())
	require.ErrorIs(t, statErr, os.ErrNotExist, "the refusal created the position store")
	_, statErr = os.Lstat(gate.b.trackedPath())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the refusal applied a target file")
}

func TestJoinGateStoredBindingThatDiffersFromThePublishedHeadRefuses(t *testing.T) {
	gate := newJoinGate(t)
	vaultHex := gate.bootstrap(t, gate.a)
	gate.publish(t)
	wrong := joinGateBinding(t, vaultHex)
	wrong.Vault = joinGateForeignVault()
	gate.provisionStore(t, gate.b, wrong)

	code, stdout, stderr := gate.pull(t, gate.b, "--did", joinGateDID)
	require.Equal(t, 3, code)
	assert.Contains(t, stdout, "vault: "+joinGateForeignVaultHex()+" (resolved from the recorded binding)\n")
	assert.Contains(t, stdout, "pull: unreadable (vault)\n")
	assert.Contains(t, stderr, "the provider position cannot be read or validated")
	assert.Zero(t, gate.vaultReads, "a recorded binding still read the published vault")
	inspection, err := publicationstate.Inspect(context.Background(), gate.b.paths.PublicationStateDir(), wrong)
	require.NoError(t, err)
	assert.False(t, inspection.Present, "the refused pull adopted the published floor")
	assert.NotEqual(
		t,
		wrong,
		joinGateBinding(t, vaultHex),
		"the fixture wrote the published vault instead of the differing one",
	)
	_, statErr := os.Lstat(gate.b.trackedPath())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the refused pull applied a target file")
}
