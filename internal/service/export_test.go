package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorExportAndImportArchiveCoverAuthenticatedClosure(t *testing.T) {
	fixture := newExportFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	published, err := fixture.coordinator.PublishRetentionAttestation(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, published.Status)
	first, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, first.Status)
	require.Equal(t, uint64(1), first.PublicationCount)
	require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'second'\n"), 0o600))
	second, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, second.Status)
	require.Equal(t, uint64(2), second.PublicationCount)
	before, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	assert.Len(t, before, 3)

	archivePath := filepath.Join(fixture.paths.StateHome, "complete.dtv")
	exportSession := &exportNoDeviceSession{base: pushTestSession{did: pushTestDID, methods: fixture.reader.VerificationMethods}}
	fixture.coordinator.deps.Session = exportSession
	report, err := fixture.coordinator.Export(ctx, ExportRequest{
		Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: fixture.kit, Path: archivePath,
	})
	require.NoError(t, err)
	assert.Greater(t, exportSession.calls, 0)
	assert.False(t, exportSession.deviceKeySeen)
	assert.Equal(t, uint64(0), report.CurrentEpoch)
	assert.NotEmpty(t, report.Current.SnapshotCID)
	assert.Len(t, report.Lineage, 2)
	assert.Len(t, report.RecoveryPoints, 1)
	assert.Empty(t, report.Omissions)
	archiveBytes, err := os.ReadFile(archivePath)
	require.NoError(t, err)
	assert.NotContains(t, string(archiveBytes), string(fixture.kit))

	imported, err := fixture.coordinator.ImportExportArchive(ctx, ImportExportRequest{
		Path: archivePath, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, Kit: fixture.kit,
	})
	require.NoError(t, err)
	assert.Equal(t, report.VaultID, imported.VaultID)
	assert.Equal(t, report.Anchor, imported.Anchor)
	assert.Equal(t, report.CurrentEpoch, imported.CurrentEpoch)
	assert.Len(t, imported.Lineage, len(report.Lineage))
	assert.Len(t, imported.RecoveryPoints, len(report.RecoveryPoints))
	assert.Equal(t, report.Omissions, imported.Omissions)

	after, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	assert.Len(t, after, len(before), "repeated verified reads must not duplicate head identities")
	require.NoError(t, fixture.store.Close())
	reopened, err := state.Open(fixture.paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	restarted, err := reopened.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	assert.Len(t, restarted, 3, "append-only position history survives a state-store restart")
}

func TestCoordinatorExportRefusesMissingRequiredBlobOrRecordByCID(t *testing.T) {
	for _, remove := range []string{"blob", "record"} {
		for _, index := range []int{0, 1, 2} {
			t.Run(remove+"-"+string(rune('0'+index)), func(t *testing.T) {
				fixture := newExportFixture(t)
				ctx := context.Background()
				selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
				_, err := fixture.coordinator.Push(ctx, selection)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'second'\n"), 0o600))
				_, err = fixture.coordinator.Push(ctx, selection)
				require.NoError(t, err)
				read, err := fixture.coordinator.Pull(ctx, selection)
				require.NoError(t, err)
				history, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
				require.NoError(t, err)
				require.Len(t, history, 3, "all three observed signed heads are retained")
				var snapshotCID []byte
				for _, evidence := range history {
					head, decodeErr := vault.DecodeHead(evidence.Head)
					require.NoError(t, decodeErr)
					if head.PublicationCount == uint64(index) {
						snapshotCID = bytes.Clone(head.SnapshotCID)
					}
				}
				if index == 0 {
					snapshotCID = bytes.Clone(fixture.genesis.SnapshotCID)
				}
				require.NotEmpty(t, snapshotCID)
				parsedCID, err := cid.Cast(snapshotCID)
				require.NoError(t, err)
				if remove == "blob" {
					fixture.pds.RemoveBlob(parsedCID.String())
				} else {
					var recordKey atproto.RecordKey
					for key, proven := range read.Read.Revision.Records() {
						if key.Collection != atproto.VaultSnapshotNSID {
							continue
						}
						record, decodeErr := atproto.DecodeRecord(proven.Data)
						require.NoError(t, decodeErr)
						snapshot := record.(atproto.SnapshotRecord)
						if bytes.Equal(cid.Cid(snapshot.Blob.Ref).Bytes(), snapshotCID) {
							recordKey = key
						}
					}
					require.NotEmpty(t, recordKey.RKey)
					require.NoError(t, fixture.pds.RemoveRecord(recordKey.Collection, recordKey.RKey))
				}
				output := filepath.Join(fixture.paths.StateHome, "must-not-exist.dtv")
				_, err = fixture.coordinator.Export(ctx, ExportRequest{
					Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
					Kit: fixture.kit, Path: output,
				})
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrExportRefused)
				assert.ErrorContains(t, err, parsedCID.String())
				_, statErr := os.Stat(output)
				assert.ErrorIs(t, statErr, os.ErrNotExist)
			})
		}
	}
}

func TestCoordinatorExportRejectsMissingLineageAndV1Retention(t *testing.T) {
	t.Run("missing publication-head position", func(t *testing.T) {
		fixture := newExportFixture(t)
		ctx := context.Background()
		selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
		_, err := fixture.coordinator.Pull(ctx, selection)
		require.NoError(t, err)
		fixture.publishRemoteFileDirect(t, []byte("theme = 'one'\n"))
		fixture.publishRemoteFileDirect(t, []byte("theme = 'two'\n"))
		output := filepath.Join(fixture.paths.StateHome, "lineage.dtv")
		_, err = fixture.coordinator.Export(ctx, ExportRequest{
			Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
			Kit: fixture.kit, Path: output,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrExportLineageUnavailable)
		predecessorCID := remoteHeadPredecessorCID(t, fixture)
		assert.ErrorContains(t, err, predecessorCID)
		_, statErr := os.Stat(output)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("v1 nonzero count", func(t *testing.T) {
		fixture := newExportFixture(t)
		ctx := context.Background()
		selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
		pulled, err := fixture.coordinator.Pull(ctx, selection)
		require.NoError(t, err)
		predecessor, err := publicationPredecessor(pulled.Read, fixture.genesis.Anchor)
		require.NoError(t, err)
		policyDigest, err := vault.ComputePolicyDigest(predecessor.Policy)
		require.NoError(t, err)
		legacy := vault.Attestation{
			SchemaVersion: vault.AttestationVersion1, Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID,
			PolicyDigest: policyDigest, RetentionFloor: 0, RetainedRecoveryPoints: 1,
			ControlCID: rawVaultCID(predecessor.Control),
			Signer:     vault.Signer{DeviceID: fixture.device.DeviceID, KeyID: bytes.Clone(fixture.device.KeyID)},
		}
		attestation, err := vault.EncodeAttestation(legacy)
		require.NoError(t, err)
		signature, err := vault.Sign("dottie/v1/sig-attestation", append([]byte("dottie/v1/sig"), attestation[:len(attestation)-64]...), fixture.device.Signing)
		require.NoError(t, err)
		copy(attestation[len(attestation)-64:], signature)
		decoded, err := vault.DecodeAttestation(attestation)
		require.NoError(t, err)
		require.Equal(t, uint8(1), decoded.SchemaVersion)
		published, err := fixture.coordinator.PublishAttestation(ctx, selection, attestation)
		require.NoError(t, err)
		output := filepath.Join(fixture.paths.StateHome, "v1-refused.dtv")
		_, err = fixture.coordinator.Export(ctx, ExportRequest{
			Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
			Kit: fixture.kit, Path: output,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrExportUnenumerableRetention)
		assert.ErrorContains(t, err, published.RecordCID)
		_, statErr := os.Stat(output)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})
}

func TestCoordinatorExportAndImportRejectIdentityAndTamperingWithoutMutation(t *testing.T) {
	fixture := newExportFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	_, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	archivePath := filepath.Join(fixture.paths.StateHome, "valid.dtv")
	_, err = fixture.coordinator.Export(ctx, ExportRequest{
		Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: fixture.kit, Path: archivePath,
	})
	require.NoError(t, err)
	wrongKit := bytes.Repeat([]byte{0x71}, 32)
	_, err = fixture.coordinator.Export(ctx, ExportRequest{
		Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: wrongKit, Path: filepath.Join(fixture.paths.StateHome, "wrong-kit.dtv"),
	})
	assert.ErrorIs(t, err, ErrRecoveryKitMismatch)
	_, err = fixture.coordinator.Export(ctx, ExportRequest{
		Selection: selection, ExpectedVault: [32]byte{99}, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: fixture.kit, Path: filepath.Join(fixture.paths.StateHome, "wrong-vault.dtv"),
	})
	assert.ErrorIs(t, err, vault.ErrForeignVault)
	_, err = fixture.coordinator.Export(ctx, ExportRequest{
		Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: [32]byte{99},
		Kit: fixture.kit, Path: filepath.Join(fixture.paths.StateHome, "wrong-anchor.dtv"),
	})
	assert.ErrorIs(t, err, vault.ErrForeignAnchor)

	beforeCheckpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	beforeHistory, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	beforeSelections, err := fixture.store.VaultSelections(ctx)
	require.NoError(t, err)
	beforeBases, err := fixture.store.AppliedBase(ctx, "files")
	require.NoError(t, err)
	beforeConfig, err := fixture.coordinator.deps.Config.Load(ctx)
	require.NoError(t, err)
	validBytes, err := os.ReadFile(archivePath)
	require.NoError(t, err)
	tampered := bytes.Clone(validBytes)
	tampered[len(tampered)-20] ^= 0x40
	tamperedPath := filepath.Join(fixture.paths.StateHome, "tampered.dtv")
	require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o600))
	_, err = fixture.coordinator.ImportExportArchive(ctx, ImportExportRequest{
		Path: tamperedPath, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, Kit: fixture.kit,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, vault.ErrExportIntegrity) || errors.Is(err, vault.ErrIncompleteExport))
	afterCheckpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	afterHistory, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	assert.Equal(t, beforeCheckpoint, afterCheckpoint)
	assert.Equal(t, beforeHistory, afterHistory)
	afterSelections, err := fixture.store.VaultSelections(ctx)
	require.NoError(t, err)
	afterBases, err := fixture.store.AppliedBase(ctx, "files")
	require.NoError(t, err)
	afterConfig, err := fixture.coordinator.deps.Config.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, beforeSelections, afterSelections)
	assert.Equal(t, beforeBases, afterBases)
	assert.Equal(t, beforeConfig, afterConfig)

	_, err = fixture.coordinator.ImportExportArchive(ctx, ImportExportRequest{
		Path: archivePath, ExpectedVault: [32]byte{99}, ExpectedAnchor: fixture.genesis.Anchor, Kit: fixture.kit,
	})
	assert.ErrorIs(t, err, vault.ErrForeignVault)
	_, err = fixture.coordinator.ImportExportArchive(ctx, ImportExportRequest{
		Path: archivePath, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: [32]byte{99}, Kit: fixture.kit,
	})
	assert.ErrorIs(t, err, vault.ErrForeignAnchor)
	_, err = fixture.coordinator.ImportExportArchive(ctx, ImportExportRequest{
		Path: archivePath, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, Kit: wrongKit,
	})
	assert.Error(t, err)
}

func TestCoordinatorExportRefusesDestinationsInsideSelectionAndSymlinkAlias(t *testing.T) {
	fixture := newExportFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	_, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	root := filepath.Join(fixture.paths.Home, "selected")
	alias := filepath.Join(fixture.paths.Home, "selected-alias")
	require.NoError(t, os.Symlink(root, alias))
	for _, path := range []string{filepath.Join(root, "direct.dtv"), filepath.Join(alias, "alias.dtv")} {
		_, err := fixture.coordinator.Export(ctx, ExportRequest{
			Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
			Kit: fixture.kit, Path: path,
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "capture selection")
		_, statErr := os.Stat(path)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	}
}

func TestCoordinatorExportFromImportedCheckpointRefusesUnretainedLineage(t *testing.T) {
	fixture := newExportFixture(t)
	newcomer, publicDevice := newAdminNewcomer(t, "export-newcomer")
	enrollment := enrollWithFixture(t, fixture, newcomer, publicDevice)
	store, paths := openCoordinatorStateWithPaths(t)
	keyring := &pushDeviceKeyring{devices: map[string]vault.DeviceMaterial{newcomer.DeviceID: newcomer}}
	coordinator := newNewcomerCoordinator(t, fixture, store, paths, keyring)
	require.NoError(t, coordinator.ImportOnboarding(context.Background(), enrollment.EncodedBundle, fixture.genesis.Vault, fixture.genesis.Anchor, newcomer.DeviceID))
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: newcomer.DeviceID}
	_, err := coordinator.Pull(context.Background(), selection)
	require.NoError(t, err)
	output := filepath.Join(paths.StateHome, "restore-only.dtv")
	_, err = coordinator.Export(context.Background(), ExportRequest{
		Selection: selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: fixture.kit, Path: output,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExportLineageUnavailable)
	_, statErr := os.Stat(output)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

type exportNoDeviceSession struct {
	base          pushTestSession
	calls         int
	deviceKeySeen bool
}

func (session *exportNoDeviceSession) ReadRequest(ctx context.Context, selection VaultSelection, device vault.DeviceMaterial, anchor [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	session.calls++
	if device.Recipient != nil || len(device.Signing) != 0 || len(device.KeyID) != 0 {
		session.deviceKeySeen = true
	}
	return session.base.ReadRequest(ctx, selection, device, anchor, previousPolicy, previousControl)
}

func newExportFixture(t *testing.T) *pushFixture {
	t.Helper()
	fixture := newPushFixture(t)
	return fixture
}

func remoteHeadPredecessorCID(t *testing.T, fixture *pushFixture) string {
	t.Helper()
	record, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	decoded, err := atproto.DecodeRecord(record.Data)
	require.NoError(t, err)
	head, ok := decoded.(atproto.HeadRecord)
	require.True(t, ok)
	parsed, err := cid.Cast(head.PrevHeadCID)
	require.NoError(t, err)
	return parsed.String()
}
