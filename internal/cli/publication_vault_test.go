package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	urfave "github.com/urfave/cli/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
)

func newVaultResolutionTestPaths(t *testing.T) platform.Paths {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home:       filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "config"),
		StateHome:  filepath.Join(root, "state"),
		CacheHome:  filepath.Join(root, "cache"),
		DataHome:   filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	return paths
}

func writeVaultResolutionBinding(t *testing.T, paths platform.Paths, binding publicationstate.Binding) {
	t.Helper()
	directory := paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	require.NoError(t, store.Close())
}

func newVaultResolutionStore(t *testing.T, paths platform.Paths) *state.Store {
	t.Helper()
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return store
}

func newVaultResolutionCoordinator(t *testing.T, paths platform.Paths) *service.Coordinator {
	t.Helper()
	coordinator, err := service.NewCoordinator(
		service.Dependencies{State: newVaultResolutionStore(t, paths), Paths: paths},
	)
	require.NoError(t, err)
	return coordinator
}

func TestResolvePublicationSelectionAdoptsTheBindingWithoutARecordedSelection(t *testing.T) {
	paths := newVaultResolutionTestPaths(t)
	binding := publicationstate.Binding{
		AccountDID: pushTestDID,
		Backend:    publicationstate.BackendPublicRepo,
		Repository: "at://" + pushTestDID,
		Vault:      [32]byte{0x51},
	}
	writeVaultResolutionBinding(t, paths, binding)
	coordinator := newVaultResolutionCoordinator(t, paths)
	resolved, err := resolvePublicationSelection(
		context.Background(),
		coordinator,
		service.VaultSelection{},
		paths.PublicationStateDir(),
		pushTestDID,
	)
	require.NoError(t, err)
	assert.Equal(t, binding.Vault, resolved.Vault, "resolved vault")
	assert.Equal(t, pullVaultFromBinding, resolved.Origin, "resolved origin")
	assert.Equal(
		t,
		"vault: "+hex.EncodeToString(binding.Vault[:])+" (resolved from the recorded binding)\n",
		renderResolvedVault(resolved),
		"rendered vault line",
	)
}

func TestResolvePublicationSelectionPrefersTheRecordedSelection(t *testing.T) {
	paths := newVaultResolutionTestPaths(t)
	store := newVaultResolutionStore(t, paths)
	recorded := [32]byte{0x52}
	require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{
		Vault: recorded, DeviceID: "synthetic-device", RecordedAt: 7,
	}))
	writeVaultResolutionBinding(t, paths, publicationstate.Binding{
		AccountDID: pushTestDID,
		Backend:    publicationstate.BackendPublicRepo,
		Repository: "at://" + pushTestDID,
		Vault:      [32]byte{0x53},
	})
	coordinator, err := service.NewCoordinator(service.Dependencies{State: store, Paths: paths})
	require.NoError(t, err)
	resolved, err := resolvePublicationSelection(
		context.Background(),
		coordinator,
		service.VaultSelection{},
		paths.PublicationStateDir(),
		pushTestDID,
	)
	require.NoError(t, err)
	assert.Equal(t, recorded, resolved.Vault, "resolved vault")
	assert.Empty(t, resolved.Origin, "resolved origin")
}

func TestResolvePublicationSelectionPrefersAnExplicitVaultOverTheBinding(t *testing.T) {
	paths := newVaultResolutionTestPaths(t)
	store := newVaultResolutionStore(t, paths)
	recorded := [32]byte{0x54}
	require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{
		Vault: recorded, DeviceID: "synthetic-device", RecordedAt: 7,
	}))
	writeVaultResolutionBinding(t, paths, publicationstate.Binding{
		AccountDID: pushTestDID,
		Backend:    publicationstate.BackendPublicRepo,
		Repository: "at://" + pushTestDID,
		Vault:      [32]byte{0x55},
	})
	coordinator, err := service.NewCoordinator(service.Dependencies{State: store, Paths: paths})
	require.NoError(t, err)
	resolved, err := resolvePublicationSelection(
		context.Background(),
		coordinator,
		service.VaultSelection{Vault: recorded, DeviceID: "synthetic-device"},
		paths.PublicationStateDir(),
		pushTestDID,
	)
	require.NoError(t, err)
	assert.Equal(t, recorded, resolved.Vault, "resolved vault")
	assert.Empty(t, resolved.Origin, "resolved origin")
	assert.Empty(t, renderResolvedVault(resolved), "an explicit vault is never echoed")
}

func TestResolvePublicationSelectionIgnoresAnotherAccountsBinding(t *testing.T) {
	paths := newVaultResolutionTestPaths(t)
	writeVaultResolutionBinding(t, paths, publicationstate.Binding{
		AccountDID: "did:plc:zyxwvutsrqponmlkjihgfedc",
		Backend:    publicationstate.BackendPublicRepo,
		Repository: "at://did:plc:zyxwvutsrqponmlkjihgfedc",
		Vault:      [32]byte{0x56},
	})
	coordinator := newVaultResolutionCoordinator(t, paths)
	resolved, err := resolvePublicationSelection(
		context.Background(),
		coordinator,
		service.VaultSelection{},
		paths.PublicationStateDir(),
		pushTestDID,
	)
	assert.Equal(t, resolvedVault{}, resolved, "resolved vault")
	require.ErrorIs(t, err, service.ErrNoVaultSelection)
}

func TestResolvePublicationSelectionRefusesWithoutAnyLocalVault(t *testing.T) {
	paths := newVaultResolutionTestPaths(t)
	coordinator := newVaultResolutionCoordinator(t, paths)
	resolved, err := resolvePublicationSelection(
		context.Background(),
		coordinator,
		service.VaultSelection{},
		paths.PublicationStateDir(),
		pushTestDID,
	)
	assert.Equal(t, resolvedVault{}, resolved, "resolved vault")
	require.ErrorIs(t, err, service.ErrNoVaultSelection)
	_, statErr := os.Lstat(paths.PublicationStateDir())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "vault resolution created the position store")
}

func TestOpenPublicationPushSourcesResolvesTheVaultBeforeTheAccountKeyring(t *testing.T) {
	paths := newVaultResolutionTestPaths(t)
	t.Setenv("HOME", paths.Home)
	t.Setenv("XDG_CONFIG_HOME", paths.ConfigHome)
	t.Setenv("XDG_STATE_HOME", paths.StateHome)
	t.Setenv("XDG_CACHE_HOME", paths.CacheHome)
	t.Setenv("XDG_DATA_HOME", paths.DataHome)
	session := pushSession{Session: &atproto.Session{DID: pushTestDID, Scopes: atproto.VaultScopes()}}
	errSyntheticKeyring := errors.New("synthetic keyring refusal")

	t.Run("nothing resolves", func(t *testing.T) {
		calls := 0
		openKeyring := func() (accountKeyring, error) {
			calls++
			return nil, errSyntheticKeyring
		}
		sources, err := openPublicationPushSources(
			context.Background(),
			nil,
			session,
			service.VaultSelection{},
			openKeyring,
			os.Getenv,
		)
		assert.Equal(t, publicationPushSources{}, sources, "resolved sources")
		require.ErrorIs(t, err, service.ErrNoVaultSelection)
		assert.Zero(t, calls, "vault resolution opened the account keyring")
	})

	t.Run("the binding resolves", func(t *testing.T) {
		writeVaultResolutionBinding(t, paths, publicationstate.Binding{
			AccountDID: pushTestDID,
			Backend:    publicationstate.BackendPublicRepo,
			Repository: "at://" + pushTestDID,
			Vault:      [32]byte{0x57},
		})
		calls := 0
		openKeyring := func() (accountKeyring, error) {
			calls++
			return nil, errSyntheticKeyring
		}
		sources, err := openPublicationPushSources(
			context.Background(),
			nil,
			session,
			service.VaultSelection{},
			openKeyring,
			os.Getenv,
		)
		assert.Equal(t, publicationPushSources{}, sources, "resolved sources")
		require.ErrorIs(t, err, errSyntheticKeyring)
		assert.Equal(t, 1, calls, "the account keyring opens once, after vault resolution")
	})
}

func pushResolvingSourcesFactory(
	t *testing.T,
	fixture *publicationPushTestFixture,
	calls *int,
) pushSourcesFactory {
	t.Helper()
	return func(ctx context.Context, command *urfave.Command, session pushSession) (publicationPushSources, error) {
		if calls != nil {
			*calls++
		}
		requested, err := requestedVaultSelection(command)
		if err != nil {
			return publicationPushSources{}, err
		}
		resolved, err := resolvePublicationSelection(
			ctx,
			fixture.coordinator,
			requested,
			fixture.paths.PublicationStateDir(),
			session.Session.DID,
		)
		if err != nil {
			return publicationPushSources{}, err
		}
		sources := fixture.sources()
		sources.Vault = resolved
		sources.Binding.Vault = resolved.Vault
		return sources, nil
	}
}

func TestPushAdoptsTheRecordedBindingVaultAndPrintsIt(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	writeVaultResolutionBinding(t, fixture.paths, fixture.binding)
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		return pushTestSession(t), nil
	}
	calls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPushCommand(
		&stdout,
		&stderr,
		&code,
		sessions,
		pushResolvingSourcesFactory(t, fixture, &calls),
		pushTestDIDs(pushTestDID),
	)
	code = runPushForTest(command, &code, "push", "--did", pushTestDID)
	require.Equal(t, 3, code, "exit code")
	assert.Equal(t, 1, calls, "sources factory calls")
	assert.Contains(t, stderr.String(), "review the publication above")
	assert.True(
		t,
		bytes.HasPrefix(
			stdout.Bytes(),
			[]byte("vault: "+hex.EncodeToString(fixture.binding.Vault[:])+" (resolved from the recorded binding)\n"),
		),
		"stdout: %s",
		stdout.String(),
	)
	assert.Contains(t, stdout.String(), "push: review required\n")
	assert.Contains(t, stdout.String(), "confirmation: ")
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "uploads")
	assert.Zero(t, sends, "sends")

	confirmation := confirmationFromOutput(t, stdout.String())
	stdout.Reset()
	stderr.Reset()
	code = 0
	confirmed := newPushCommand(
		&stdout,
		&stderr,
		&code,
		sessions,
		pushResolvingSourcesFactory(t, fixture, &calls),
		pushTestDIDs(pushTestDID),
	)
	code = runPushForTest(confirmed, &code, "push", "--did", pushTestDID, "--confirm", confirmation)
	require.Equal(t, 0, code, "confirmed exit code")
	assert.Equal(t, 2, calls, "sources factory calls")
	assert.Empty(t, stderr.String(), "stderr")
	assert.True(
		t,
		bytes.HasPrefix(
			stdout.Bytes(),
			[]byte("vault: "+hex.EncodeToString(fixture.binding.Vault[:])+" (resolved from the recorded binding)\n"),
		),
		"stdout: %s",
		stdout.String(),
	)
	assert.Contains(t, stdout.String(), "push: committed\n")
	assert.Contains(t, stdout.String(), "floor: revision=1 generation=1 sequence=0\n")
}

func TestPushStillRefusesWithoutAnyLocalVaultAndNamesEverySource(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		return pushTestSession(t), nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPushCommand(
		&stdout,
		&stderr,
		&code,
		sessions,
		pushResolvingSourcesFactory(t, fixture, nil),
		pushTestDIDs(pushTestDID),
	)
	code = runPushForTest(command, &code, "push", "--did", pushTestDID)
	assert.Equal(t, 3, code, "exit code")
	assert.Empty(t, stdout.String(), "stdout")
	assert.Equal(
		t,
		"dottie: push refused: local vault selection is unavailable; checked an explicit --vault, the recorded local vault selection and the local publication binding, and none resolves one vault for this account; pass --vault and --device-id, or run dottie pull --confirm to adopt the published position\n",
		stderr.String(),
		"stderr",
	)
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "uploads")
	assert.Zero(t, sends, "sends")
}
