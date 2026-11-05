//go:build linux && cgo && gsettings

package local_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRestoreMilestoneGNOMEKeyfileTwoHome(t *testing.T) {
	root := t.TempDir()
	publisher := newManualSyncMachine(t, root, "milestone-publisher")
	newcomer := newManualSyncMachine(t, root, "milestone-newcomer")
	fileTarget, settingsTarget := manualSyncTargets(t)
	configureManualSyncMachine(t, publisher, fileTarget, settingsTarget)
	configureManualSyncMachine(t, newcomer, fileTarget, settingsTarget)

	fileBytes := []byte("checkpoint-backed keyfile restore bytes\n")
	publisherFile := filepath.Join(publisher.home, manualSyncFileTarget, "prefs.ini")
	newcomerRoot := filepath.Join(newcomer.home, manualSyncFileTarget)
	require.NoError(t, os.MkdirAll(filepath.Dir(publisherFile), 0o700))
	require.NoError(t, os.MkdirAll(newcomerRoot, 0o700))
	require.NoError(t, os.WriteFile(publisherFile, fileBytes, 0o640))
	wantSettings := map[string]string{
		"gtk-theme": "'Milestone-Theme'", "icon-theme": "'Milestone-Icons'",
		"cursor-theme": "'Milestone-Cursor'", "color-scheme": "'prefer-dark'", "accent-color": "'red'",
	}
	manualSyncSetSettings(t, publisher, wantSettings, nil)
	manualSyncSetSettings(t, newcomer, map[string]string{
		"gtk-theme": "'Newcomer-Theme'", "icon-theme": "'Newcomer-Icons'",
		"cursor-theme": "'Newcomer-Cursor'", "color-scheme": "'default'", "accent-color": "'blue'",
	}, nil)

	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(manualVaultDID, repositoryKey)
	require.NoError(t, err)
	reader := manualSyncReader(pds)
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	defer clear(kit)
	rootDevice := manualSyncDevice(t, "restore-milestone-root")
	genesis := manualSyncGenesis(t, kit, rootDevice)
	clock := time.Unix(1_800_000_000, 0)
	_, err = atproto.CommitGenesis(context.Background(), atproto.GenesisIO{
		Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: manualVaultDID, ObservationStore: publisher.store,
		Clock: func() time.Time { return clock },
	}, kit, rootDevice, genesis)
	require.NoError(t, err)
	manualSyncSeedGenesisTrust(t, publisher, genesis, rootDevice)
	publisher.keyring.devices[rootDevice.DeviceID] = rootDevice
	publisherCoordinator := manualSyncCoordinator(t, publisher, pds, reader,
		manualSyncSession{did: manualVaultDID, methods: reader.VerificationMethods}, true, clock)

	manualSyncSetEnvironment(t, publisher)
	published, err := publisherCoordinator.Push(context.Background(), service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, service.StatusCommitted, published.Status)
	assert.False(t, published.NoOp)
	assert.Equal(t, fileBytes, manualSyncReadFile(t, publisherFile))

	newcomerDevice, publicDevice := manualSyncNewDevice(t, "restore-milestone-newcomer")
	approval := vault.EnrollmentTranscriptFingerprint(
		genesis.Vault, publicDevice.DeviceID, publicDevice.KeyID, vault.RoleRestoreOnly,
		publicDevice.SigningPublicKey, publicDevice.RecipientPublicKey,
	)
	enrollment, err := publisherCoordinator.Enroll(context.Background(), service.EnrollRequest{
		Selection: service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID}, Device: publicDevice,
		Role: vault.RoleRestoreOnly, ApprovalFingerprint: approval, Kit: kit,
	})
	require.NoError(t, err)
	assert.Equal(t, service.StatusCommitted, enrollment.Status)
	assert.NotEmpty(t, enrollment.EncodedBundle)

	newcomer.keyring.devices[newcomerDevice.DeviceID] = newcomerDevice
	newcomerCoordinator := manualSyncCoordinator(t, newcomer, pds, reader,
		manualSyncSession{did: manualVaultDID, methods: reader.VerificationMethods}, false, clock)
	manualSyncSetEnvironment(t, newcomer)
	selection := service.VaultSelection{Vault: genesis.Vault, DeviceID: newcomerDevice.DeviceID}
	baselineKeys, err := matrix.SelectCategories(settingsTarget.GNOMEPolicy.Categories)
	require.NoError(t, err)
	baselineRefs := make([]service.SettingRef, 0, len(baselineKeys))
	for _, key := range baselineKeys {
		baselineRefs = append(baselineRefs, service.SettingRef{SchemaID: key.SchemaID, Path: key.Path, Key: key.Key})
	}
	baseline, err := newcomer.settings.Capture(context.Background(), settingsTarget.ID, baselineRefs)
	require.NoError(t, err)
	require.Empty(t, baseline.Unknown)
	require.Len(t, baseline.Entries, len(wantSettings))
	require.NoError(t, newcomerCoordinator.RecordBase(context.Background(), settingsTarget.ID, baseline.Entries))
	require.NoError(t, newcomerCoordinator.ImportOnboarding(context.Background(), enrollment.EncodedBundle, genesis.Vault, genesis.Anchor, newcomerDevice.DeviceID))
	pulled, err := newcomerCoordinator.Pull(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, vault.CheckpointCurrent, pulled.Currency.Outcome)
	assert.Equal(t, uint64(1), pulled.Read.EpochSeq)

	fileCandidate, err := newcomerCoordinator.Preview(context.Background(), selection, fileTarget.ID)
	require.NoError(t, err)
	require.True(t, fileCandidate.Preview.Complete)
	assert.Len(t, fileCandidate.Actions, 1)
	fileRestore, err := newcomerCoordinator.Restore(context.Background(), service.RestoreRequest{
		Selection: selection, TargetID: fileTarget.ID, Confirm: fileCandidate.Digest,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, fileRestore.Applied)
	assert.Equal(t, fileBytes, manualSyncReadFile(t, filepath.Join(newcomerRoot, "prefs.ini")))

	settingsCandidate, err := newcomerCoordinator.Preview(context.Background(), selection, settingsTarget.ID)
	require.NoError(t, err)
	require.True(t, settingsCandidate.Preview.Complete, "%+v", settingsCandidate.Preview)
	assert.Len(t, settingsCandidate.Actions, len(wantSettings))
	settingsRestore, err := newcomerCoordinator.Restore(context.Background(), service.RestoreRequest{
		Selection: selection, TargetID: settingsTarget.ID, Confirm: settingsCandidate.Digest,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, settingsRestore.Applied)
	gotSettings := manualSyncReadSettings(t, newcomer)
	for key, value := range wantSettings {
		assert.True(t, gotSettings[key].Present, "%s must be a user override", key)
		assert.Equal(t, value, gotSettings[key].Text)
	}
	assert.Equal(t, fileBytes, manualSyncReadFile(t, filepath.Join(newcomerRoot, "prefs.ini")))
}
