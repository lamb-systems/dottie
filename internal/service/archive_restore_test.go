package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const archiveRestoreValue = "theme = 'checkpoint-A'\n"
const archiveLaterValue = "theme = 'later-B'\n"

type archiveNeverRemote struct {
	t     *testing.T
	calls int
}

func (remote *archiveNeverRemote) Read(context.Context, atproto.ReadRequest) (atproto.ReadResult, error) {
	remote.calls++
	remote.t.Errorf("archive restore contacted the remote reader")
	return atproto.ReadResult{}, errors.New("unexpected remote read")
}

type archiveNeverSession struct {
	t     *testing.T
	calls int
}

func (session *archiveNeverSession) ReadRequest(context.Context, VaultSelection, vault.DeviceMaterial, [32]byte, []byte, []byte) (atproto.ReadRequest, error) {
	session.calls++
	session.t.Errorf("archive restore requested a provider session")
	return atproto.ReadRequest{}, errors.New("unexpected provider session")
}

func TestRestoreFromArchiveAppliesOnlyKitCheckpointThroughSharedApply(t *testing.T) {
	ctx := context.Background()
	fixture, archivePath, checkpointEpoch := makeArchiveRestoreFixture(t)
	destination := newArchiveRestoreDestination(t, fixture, nil)
	remote := &archiveNeverRemote{t: t}
	session := &archiveNeverSession{t: t}
	destination.coordinator.deps.Remote = remote
	destination.coordinator.deps.Session = session
	restoreRequest := ArchiveRestoreRequest{
		Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID},
		Path:      archivePath, Anchor: fixture.genesis.Anchor, Kit: fixture.kit, TargetID: fixture.target.ID,
	}

	previewRefusal, err := destination.coordinator.RestoreFromArchive(ctx, restoreRequest)
	require.ErrorIs(t, err, ErrCandidateChanged)
	assert.Equal(t, "archive", previewRefusal.Source)
	assert.Equal(t, checkpointEpoch, previewRefusal.PositionEpoch)
	assert.False(t, previewRefusal.ProviderContacted)
	assert.True(t, previewRefusal.ArchiveMayNotBeNewest)
	assert.NotEmpty(t, previewRefusal.CandidateDigest)

	restoreRequest.Confirm = previewRefusal.CandidateDigest
	report, err := destination.coordinator.RestoreFromArchive(ctx, restoreRequest)
	require.NoError(t, err)
	assert.Equal(t, "archive", report.Source)
	assert.Equal(t, checkpointEpoch, report.PositionEpoch)
	assert.False(t, report.ProviderContacted)
	assert.True(t, report.ArchiveMayNotBeNewest)
	assert.Len(t, report.Applied, 1)
	assert.False(t, report.NoActions)
	content, err := os.ReadFile(filepath.Join(destination.root, "prefs.toml"))
	require.NoError(t, err)
	assert.Equal(t, []byte(archiveRestoreValue), content)
	assert.NotContains(t, string(content), "later-B", "the later archive.Current marker must not be applied")
	bases, err := destination.store.AppliedBase(ctx, fixture.target.ID)
	require.NoError(t, err)
	assert.Len(t, bases, 1)

	noOp, err := destination.coordinator.RestoreFromArchive(ctx, restoreRequest)
	require.ErrorIs(t, err, ErrCandidateChanged)
	restoreRequest.Confirm = noOp.CandidateDigest
	noOp, err = destination.coordinator.RestoreFromArchive(ctx, restoreRequest)
	require.NoError(t, err)
	assert.True(t, noOp.NoActions)
	assert.Empty(t, noOp.Applied)
	assert.Zero(t, remote.calls)
	assert.Zero(t, session.calls)
}

func TestRestoreFromArchiveRefusalsUseTheirSentinelsWithoutProviderCalls(t *testing.T) {
	ctx := context.Background()
	fixture, archivePath, _ := makeArchiveRestoreFixture(t)
	destination := newArchiveRestoreDestination(t, fixture, nil)
	remote := &archiveNeverRemote{t: t}
	session := &archiveNeverSession{t: t}
	destination.coordinator.deps.Remote = remote
	destination.coordinator.deps.Session = session
	request := ArchiveRestoreRequest{
		Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID},
		Path:      archivePath, Anchor: fixture.genesis.Anchor, Kit: fixture.kit, TargetID: fixture.target.ID,
	}

	wrongKit := request
	wrongKit.Kit = bytes.Repeat([]byte{0x73}, 32)
	_, err := destination.coordinator.RestoreFromArchive(ctx, wrongKit)
	assert.ErrorIs(t, err, ErrRecoveryKitMismatch)

	wrongAnchor := request
	wrongAnchor.Anchor[0] ^= 0xff
	_, err = destination.coordinator.RestoreFromArchive(ctx, wrongAnchor)
	assert.ErrorIs(t, err, vault.ErrForeignAnchor)

	foreignVault := request
	foreignVault.Selection.Vault[0] ^= 0xff
	require.NoError(t, destination.store.PutVaultSelection(ctx, state.VaultSelection{
		Vault: foreignVault.Selection.Vault, DeviceID: foreignVault.Selection.DeviceID, RecordedAt: 2,
	}))
	_, err = destination.coordinator.RestoreFromArchive(ctx, foreignVault)
	assert.ErrorIs(t, err, vault.ErrForeignVault)

	missingKey := destination.coordinator.deps.DeviceKeys
	destination.coordinator.deps.DeviceKeys = nil
	_, err = destination.coordinator.RestoreFromArchive(ctx, request)
	assert.ErrorIs(t, err, ErrDeviceKeyMissing)
	keySourceCases := []struct {
		name   string
		device vault.DeviceMaterial
		err    error
	}{
		{name: "keyring error", device: fixture.device, err: errors.New("synthetic keyring failure")},
		{name: "device identity mismatch", device: mismatchedArchiveDevice(fixture.device, "another-device", fixture.device.KeyID)},
		{name: "key ID is not in checkpoint policy", device: mismatchedArchiveDevice(fixture.device, fixture.device.DeviceID, []byte("not-authorized-key-id"))},
	}
	for _, test := range keySourceCases {
		t.Run(test.name, func(t *testing.T) {
			destination.coordinator.deps.DeviceKeys = archiveDeviceKeySourceFunc(func(context.Context, [32]byte, string) (vault.DeviceMaterial, error) {
				return test.device, test.err
			})
			_, keyErr := destination.coordinator.RestoreFromArchive(ctx, request)
			assert.ErrorIs(t, keyErr, ErrDeviceKeyMissing)
			assert.NotErrorIs(t, keyErr, vault.ErrRecipient)
		})
	}
	destination.coordinator.deps.DeviceKeys = missingKey

	unknownTarget := request
	unknownTarget.TargetID = "not-configured"
	_, err = destination.coordinator.RestoreFromArchive(ctx, unknownTarget)
	assert.ErrorIs(t, err, ErrUnknownTarget)

	backupConfig := destination.coordinator.deps.Config.(*memoryConfig)
	originalMode := backupConfig.value.Targets[0].Mode
	backupConfig.value.Targets[0].Mode = config.BackupOnly
	_, err = destination.coordinator.RestoreFromArchive(ctx, request)
	assert.ErrorIs(t, err, ErrApplyNotPermitted)
	backupConfig.value.Targets[0].Mode = originalMode

	wrongDigest := request
	wrongDigest.Confirm = "not-the-candidate-digest"
	_, err = destination.coordinator.RestoreFromArchive(ctx, wrongDigest)
	assert.ErrorIs(t, err, ErrCandidateChanged)

	destination.coordinator.deps.Files = archiveUnknownCapture{}
	_, err = destination.coordinator.RestoreFromArchive(ctx, request)
	assert.ErrorIs(t, err, ErrCandidateIncomplete)
	destination.coordinator.deps.Files = nil

	tamperedPath := filepath.Join(t.TempDir(), "tampered.dtv")
	archiveBytes, err := os.ReadFile(archivePath)
	require.NoError(t, err)
	memberOffset := bytes.Index(archiveBytes, []byte("DTE"))
	require.GreaterOrEqual(t, memberOffset, 0)
	archiveBytes[memberOffset+8] ^= 0x01
	require.NoError(t, os.WriteFile(tamperedPath, archiveBytes, 0o600))
	tampered := request
	tampered.Path = tamperedPath
	_, err = destination.coordinator.RestoreFromArchive(ctx, tampered)
	assert.ErrorIs(t, err, vault.ErrExportIntegrity)

	if len(archiveBytes) > 0 {
		clear(archiveBytes)
	}
	assert.Zero(t, remote.calls)
	assert.Zero(t, session.calls)
}

func TestOpenCheckpointSnapshotRefusesMissingAuthorizedRecipientWrapper(t *testing.T) {
	fixture, archivePath, _ := makeArchiveRestoreFixture(t)
	archiveFile, err := os.Open(archivePath)
	require.NoError(t, err)
	archive, err := vault.ReadExportArchive(archiveFile, vault.ImportOptions{
		ExpectedVaultID: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, RecoveryKit: fixture.kit,
	})
	assert.NoError(t, archiveFile.Close())
	require.NoError(t, err)
	checkpoint, position, err := checkpointExportPosition(archive, fixture.kit)
	require.NoError(t, err)
	found := false
	for index := range archive.Blobs {
		if !bytes.Equal(archive.Blobs[index].CID, checkpoint.SnapshotCID) {
			continue
		}
		envelope, decodeErr := vault.DecodeEnvelope(archive.Blobs[index].Data)
		require.NoError(t, decodeErr)
		filtered := make([]vault.EnvelopeRecipient, 0, len(envelope.Recipients))
		for _, recipient := range envelope.Recipients {
			if !bytes.Equal(recipient.KeyID, fixture.device.KeyID) {
				filtered = append(filtered, recipient)
			}
		}
		if len(filtered) == len(envelope.Recipients) {
			continue
		}
		require.NotEmpty(t, filtered)
		envelope.Recipients = filtered
		unsigned, encodeErr := vault.EncodeEnvelope(envelope)
		require.NoError(t, encodeErr)
		prefix := unsigned[:len(unsigned)-ed25519.SignatureSize]
		preimage := append([]byte("dottie/v1/sig"), prefix...)
		signature, signErr := vault.Sign("dottie/v1/sig-snapshot", preimage, fixture.device.Signing)
		require.NoError(t, signErr)
		copy(envelope.Signature[:], signature)
		archive.Blobs[index].Data, err = vault.EncodeEnvelope(envelope)
		require.NoError(t, err)
		found = true
		break
	}
	require.True(t, found, "checkpoint envelope should contain the selected root recipient")
	_, err = openCheckpointSnapshot(archive, checkpoint, position, fixture.device)
	assert.ErrorIs(t, err, vault.ErrRecipient)
	assert.NotErrorIs(t, err, ErrDeviceKeyMissing)
}

func TestRemotePreviewUnknownTargetUsesSentinel(t *testing.T) {
	fixture := newPushFixture(t)
	_, err := fixture.coordinator.Preview(context.Background(), VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, "not-configured")
	assert.ErrorIs(t, err, ErrUnknownTarget)
}

func TestRestoreFromArchiveRequiresCheckpointPayloadAndReportsJournalBlockers(t *testing.T) {
	ctx := context.Background()
	fixture, archivePath, _ := makeArchiveRestoreFixture(t)
	destination := newArchiveRestoreDestination(t, fixture, nil)
	remote := &archiveNeverRemote{t: t}
	session := &archiveNeverSession{t: t}
	destination.coordinator.deps.Remote = remote
	destination.coordinator.deps.Session = session
	request := ArchiveRestoreRequest{
		Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID},
		Path:      archivePath, Anchor: fixture.genesis.Anchor, Kit: fixture.kit, TargetID: fixture.target.ID,
	}

	archiveFile, err := os.Open(archivePath)
	require.NoError(t, err)
	archive, err := vault.ReadExportArchive(archiveFile, vault.ImportOptions{
		ExpectedVaultID: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, RecoveryKit: fixture.kit,
	})
	assert.NoError(t, archiveFile.Close())
	require.NoError(t, err)
	checkpoint, position, err := checkpointExportPosition(archive, fixture.kit)
	require.NoError(t, err)
	archive.Blobs = nil
	_, err = openCheckpointSnapshot(archive, checkpoint, position, fixture.device)
	assert.ErrorIs(t, err, vault.ErrExportBlob)

	pendingRoot := destination.root
	stat, err := os.Stat(pendingRoot)
	require.NoError(t, err)
	fileInfo, ok := stat.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	pendingPayload := []byte("pending preimage")
	postimage := []byte("pending postimage")
	_, err = destination.store.AppendJournal(ctx, state.JournalEntry{
		ID: "archive-pending", Operation: "replace", State: "pending", Stage: state.JournalStagePending,
		Identity: model.EntryKey{TargetID: fixture.target.ID, Source: model.SourceFiles, FilePath: "journal.toml"},
		RootPath: pendingRoot, DestinationPath: "journal.toml", RootDevice: int64(fileInfo.Dev), RootInode: int64(fileInfo.Ino),
		Preimage:  state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", pendingPayload),
		Postimage: state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", postimage), CreatedAt: time.Now().Unix(),
	}, pendingPayload)
	require.NoError(t, err)
	previewRefusal, err := destination.coordinator.RestoreFromArchive(ctx, request)
	require.ErrorIs(t, err, ErrCandidateChanged)
	request.Confirm = previewRefusal.CandidateDigest
	destination.coordinator.deps.Clock = nil
	_, err = destination.coordinator.RestoreFromArchive(ctx, request)
	assert.ErrorIs(t, err, ErrPendingJournal)
	assert.ErrorIs(t, err, ErrPendingJournalRecoveryFailed)
	assert.NotErrorIs(t, err, ErrPendingJournalRemains)
	assert.Zero(t, remote.calls)
	assert.Zero(t, session.calls)
}

type archiveDeviceKeySourceFunc func(context.Context, [32]byte, string) (vault.DeviceMaterial, error)

func (source archiveDeviceKeySourceFunc) LoadDeviceKeys(ctx context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	return source(ctx, vaultID, deviceID)
}

func mismatchedArchiveDevice(device vault.DeviceMaterial, deviceID string, keyID []byte) vault.DeviceMaterial {
	device.DeviceID = deviceID
	device.KeyID = bytes.Clone(keyID)
	return device
}

type archiveRestoreDestination struct {
	coordinator *Coordinator
	store       *state.Store
	root        string
}

func newArchiveRestoreDestination(t *testing.T, fixture *pushFixture, filesPort CapturePort) archiveRestoreDestination {
	t.Helper()
	store, paths := openCoordinatorStateWithPaths(t)
	ctx := context.Background()
	selection := state.VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID, RecordedAt: 1}
	require.NoError(t, store.PutVaultSelection(ctx, selection))
	target := fixture.target
	root := filepath.Join(paths.Home, target.Root.Path)
	require.NoError(t, os.MkdirAll(root, 0o700))
	require.NoError(t, store.PutTarget(ctx, state.TargetDescriptor{
		ID: target.ID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Mode: string(config.Review), LogicalBase: target.Root.Base, LogicalPath: target.Root.Path,
		Kind: target.Root.Kind, CreatedAt: 1,
	}))
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	coordinator, err := NewCoordinator(Dependencies{
		Config: &memoryConfig{value: configuration}, State: store, DeviceKeys: fixture.keyring,
		Files: filesPort, Paths: paths, Clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
	})
	require.NoError(t, err)
	return archiveRestoreDestination{coordinator: coordinator, store: store, root: root}
}

func makeArchiveRestoreFixture(t *testing.T) (*pushFixture, string, uint64) {
	t.Helper()
	fixture := newPushFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	_, err := fixture.coordinator.PublishRetentionAttestation(ctx, selection)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixture.file, []byte(archiveRestoreValue), 0o600))
	published, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, published.Status)
	newcomer, public := newAdminNewcomer(t, "archive-restore-newcomer")
	enrollWithFixture(t, fixture, newcomer, public)
	checkpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixture.file, []byte(archiveLaterValue), 0o600))
	later, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, later.Status)
	advancer := newArchiveAdvancer(t, fixture)
	secondNewcomer, secondPublic := newAdminNewcomer(t, "archive-restore-advancer")
	approval := vault.EnrollmentTranscriptFingerprint(fixture.genesis.Vault, secondPublic.DeviceID, secondPublic.KeyID, vault.RoleRestoreOnly, secondPublic.SigningPublicKey, secondPublic.RecipientPublicKey)
	advanced, err := advancer.Enroll(ctx, EnrollRequest{
		Selection: selection, Device: secondPublic, Role: vault.RoleRestoreOnly,
		ApprovalFingerprint: approval, Kit: fixture.kit,
	})
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, advanced.Status)
	assert.NotNil(t, secondNewcomer.Recipient)
	archivePath := filepath.Join(fixture.paths.StateHome, "checkpoint-restore.dtv")
	exported, err := fixture.coordinator.Export(ctx, ExportRequest{
		Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: fixture.kit, Path: archivePath,
	})
	require.NoError(t, err)
	assert.Greater(t, exported.Current.Epoch, checkpoint.Epoch)
	checkpointCID, err := cid.Cast(checkpoint.SnapshotCID)
	require.NoError(t, err)
	assert.NotEqual(t, checkpointCID.String(), exported.Current.SnapshotCID, "archive current position must be strictly later than the signed checkpoint")
	return fixture, archivePath, checkpoint.Epoch
}

func newArchiveAdvancer(t *testing.T, fixture *pushFixture) *Coordinator {
	t.Helper()
	store, _ := openCoordinatorStateWithPaths(t)
	ctx := context.Background()
	selection := state.VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID, RecordedAt: 1}
	require.NoError(t, store.PutVaultSelection(ctx, selection))
	checkpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, checkpoint))
	history, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	for _, position := range history {
		require.NoError(t, store.PutAuthenticatedPositionEvidence(ctx, position))
	}
	coordinator, err := NewCoordinator(Dependencies{
		Config: fixture.coordinator.deps.Config, State: store, DeviceKeys: fixture.keyring,
		Trust:     StateTrustSource{State: store, Keyring: fixture.keyring},
		Session:   fixture.coordinator.deps.Session,
		Remote:    VaultReader{Reader: atproto.VaultReader{Transport: fixture.pds, ObservationStore: store, Clock: func() time.Time { return fixture.clock }}},
		Publisher: fixture.provider, Clock: func() time.Time { return fixture.clock }, Paths: fixture.paths,
	})
	require.NoError(t, err)
	return coordinator
}

type archiveUnknownCapture struct{}

func (archiveUnknownCapture) Capture(_ context.Context, target config.Target, _ string) (files.Result, error) {
	identity := model.EntryKey{TargetID: target.ID, Source: model.SourceFiles, FilePath: "prefs.toml"}
	return files.Result{Observations: []model.Observation{{State: model.ObservationUnknown, Identity: identity}}}, nil
}
