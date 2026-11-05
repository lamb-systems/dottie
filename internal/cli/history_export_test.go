package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"
)

func manualHistoryTestFactory(t *testing.T, paths platform.Paths, localErr, remoteErr error, remoteStatus *bool) manualFactory {
	t.Helper()
	return func(_ context.Context, _ *urfave.Command, needsRemote bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		if needsRemote && remoteStatus != nil {
			*remoteStatus = true
		}
		if needsRemote && remoteErr != nil {
			return nil, service.VaultSelection{}, func() {}, remoteErr
		}
		if !needsRemote && localErr != nil {
			return nil, service.VaultSelection{}, func() {}, localErr
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, service.VaultSelection{}, func() {}, err
		}
		coordinator, err := service.NewCoordinator(service.Dependencies{Config: service.FileConfigPort{Paths: paths}, State: store})
		if err != nil {
			_ = store.Close()
			return nil, service.VaultSelection{}, func() {}, err
		}
		return coordinator, service.VaultSelection{}, func() { assert.NoError(t, store.Close()) }, nil
	}
}

func TestManualHistoryLocalOnlyAndRemoteUnavailable(t *testing.T) {
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"),
	}
	for _, path := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	for _, test := range []struct {
		name              string
		args              []string
		remoteErr         error
		wantRemote        string
		wantRemoteFactory bool
	}{
		{name: "offline", args: []string{"history"}, wantRemote: "not-requested"},
		{name: "remote unavailable", args: []string{"history", "--did", "did:plc:example"}, remoteErr: errors.New("synthetic outage"), wantRemote: "unavailable", wantRemoteFactory: true},
		{name: "expired session", args: []string{"history", "--did", "did:plc:example"}, remoteErr: atproto.ErrSessionNotFound, wantRemote: "auth-expired", wantRemoteFactory: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			remoteCalled := false
			var stdout, stderr bytes.Buffer
			code := 0
			command := newManualCommand(&stdout, &stderr, &code, manualHistoryTestFactory(t, paths, nil, test.remoteErr, &remoteCalled))
			code = runManualCommandForTest(command, &code, test.args...)
			require.Equal(t, 0, code)
			assert.Empty(t, stderr.String())
			assert.Contains(t, stdout.String(), "local history")
			assert.Contains(t, stdout.String(), "remote: "+test.wantRemote)
			if test.wantRemote == "not-requested" {
				assert.Contains(t, stdout.String(), "freshness: not-checked")
			}
			assert.Equal(t, test.wantRemoteFactory, remoteCalled)
			assert.NotContains(t, stdout.String(), paths.Home)
		})
	}
}

func TestManualHistoryEscapesUntrustedSummaryFields(t *testing.T) {
	output := renderHistory(service.HistoryReport{
		Targets: []service.HistoryTargetSummary{{
			ID: "prefs\n\x1b[2J", JournalCount: 1,
			JournalCounts:      []state.JournalHistoryCount{{State: "applied\n", Stage: "verified\x1b", Count: 1}},
			LatestJournalState: "applied", LatestJournalReason: "stage\r",
			AppliedBaseCount: 1, AppliedBaseRecorded: 123, AppliedBaseDigest: strings.Repeat("a", 64),
		}},
		Remote: service.HistoryRemoteSummary{Status: service.HistoryRemoteVerified, HeadCID: "cid\n\x1b", PublicationCount: 4},
	})
	assert.Contains(t, output, `target prefs\x0A\x1B[2J`)
	assert.Contains(t, output, `stage=verified\x1B`)
	assert.Contains(t, output, `stage=stage\x0D`)
	assert.Contains(t, output, `cid\x0A\x1B`)
	assert.NotContains(t, output, "\x1b")
	assert.NotContains(t, output, "/home/")
}

func TestManualImportRequiresIndependentVaultAndAnchorBeforeFactory(t *testing.T) {
	const fingerprint = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "missing vault", args: []string{"import", "--archive", "/does/not/exist", "--kit-file", "/does/not/exist", "--anchor", fingerprint}},
		{name: "missing anchor", args: []string{"import", "--archive", "/does/not/exist", "--kit-file", "/does/not/exist", "--vault", fingerprint}},
		{name: "malformed vault", args: []string{"import", "--archive", "/does/not/exist", "--kit-file", "/does/not/exist", "--anchor", fingerprint, "--vault", "abcd"}},
		{name: "malformed anchor", args: []string{"import", "--archive", "/does/not/exist", "--kit-file", "/does/not/exist", "--anchor", "abcd", "--vault", fingerprint}},
	} {
		t.Run(test.name, func(t *testing.T) {
			factoryCalls := 0
			factory := func(context.Context, *urfave.Command, bool) (*service.Coordinator, service.VaultSelection, func(), error) {
				factoryCalls++
				return nil, service.VaultSelection{}, func() {}, nil
			}
			var stdout, stderr bytes.Buffer
			code := 0
			command := newManualCommand(&stdout, &stderr, &code, factory)
			code = runManualCommandForTest(command, &code, test.args...)
			require.Equal(t, 2, code)
			assert.Zero(t, factoryCalls)
			assert.Empty(t, stdout.String())
			assert.Contains(t, stderr.String(), "usage:")
		})
	}
}

func TestManualExportRefusesExistingOutputWithoutOverwriteBeforeRemoteFactory(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "existing.dtv")
	require.NoError(t, os.WriteFile(outputPath, []byte("unchanged"), 0o600))
	kitPath := filepath.Join(t.TempDir(), "kit")
	require.NoError(t, os.WriteFile(kitPath, []byte("invalid"), 0o600))
	factoryCalls := 0
	factory := func(context.Context, *urfave.Command, bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		factoryCalls++
		return nil, service.VaultSelection{}, func() {}, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "export", "--out", outputPath, "--kit-file", kitPath, "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls)
	assert.Contains(t, stderr.String(), "already exists")
	assert.NotContains(t, stdout.String(), "invalid")
}

type manualCLIExportKeyring struct {
	device vault.DeviceMaterial
}

func (keyring manualCLIExportKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if vaultID == ([32]byte{}) || deviceID != keyring.device.DeviceID {
		return vault.DeviceMaterial{}, errors.New("synthetic device key is unavailable")
	}
	return keyring.device, nil
}

type manualCLIExportSession struct {
	did     string
	methods []atproto.VerificationMethod
}

func (session manualCLIExportSession) ReadRequest(_ context.Context, selection service.VaultSelection, _ vault.DeviceMaterial, anchor [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	return atproto.ReadRequest{
		DID: session.did, DIDDocumentID: session.did, VerificationMethods: append([]atproto.VerificationMethod(nil), session.methods...),
		Vault: selection.Vault, TrustAnchor: anchor, PreviousPolicy: append([]byte(nil), previousPolicy...),
		PreviousControl: append([]byte(nil), previousControl...),
	}, nil
}

func manualCLIExportFixture(t *testing.T) (*service.Coordinator, service.VaultSelection, []byte, [32]byte, [32]byte, platform.Paths) {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"),
	}
	for _, path := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	t.Cleanup(func() { clear(kit) })
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	device := vault.DeviceMaterial{DeviceID: "cli-export-root", KeyID: append([]byte(nil), signing.Public().(ed25519.PublicKey)...), Signing: signing, Recipient: recipient}
	var contentKey [32]byte
	var ephemeral [32]byte
	var wrapNonce [24]byte
	var publicationID [16]byte
	var nonce [24]byte
	for _, value := range [][]byte{contentKey[:], ephemeral[:], wrapNonce[:], publicationID[:], nonce[:]} {
		_, err = rand.Read(value)
		require.NoError(t, err)
	}
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: "cli export fixture", RootDevice: device, ContentKey: contentKey[:],
		Wraps:         []vault.RecipientWrapInput{{KeyID: append([]byte(nil), device.KeyID...), EphemeralPrivate: ephemeral, WrapNonce: wrapNonce}},
		PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	selection := service.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID}
	ctx := context.Background()
	require.NoError(t, store.PutVaultSelection(ctx, state.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID, RecordedAt: 1}))
	require.NoError(t, store.PutVaultCheckpoint(ctx, state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: append([]byte(nil), genesis.ControlCID...),
		ControlBytes: append([]byte(nil), genesis.Control...), SnapshotCID: append([]byte(nil), genesis.SnapshotCID...),
		Epoch: 0, PolicyDigest: genesis.PolicyDigest, RecordedAt: 1,
	}))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(ctx, state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest, Policy: append([]byte(nil), genesis.Policy...),
		Control: append([]byte(nil), genesis.Control...), Head: append([]byte(nil), genesis.Head...),
		Certificates: [][]byte{append([]byte(nil), genesis.Certificate...)}, CheckpointPosition: append([]byte(nil), genesis.Checkpoint...),
	}))
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	const did = "did:plc:cccccccccccccccccccccccc"
	pds, err := atprototest.NewMemoryPDS(did, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	methods := []atproto.VerificationMethod{{ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase}}
	reader := atproto.RevisionReader{Transport: pds, DIDDocumentID: did, VerificationMethods: methods}
	now := time.Unix(1_800_000_000, 0)
	_, err = atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: did, ObservationStore: store,
		Clock: func() time.Time { return now },
	}, kit, device, genesis)
	require.NoError(t, err)
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store,
		Trust:   service.StateTrustSource{State: store, Keyring: manualCLIExportKeyring{device: device}},
		Session: manualCLIExportSession{did: did, methods: methods},
		Remote:  service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: func() time.Time { return now }}},
		Clock:   func() time.Time { return now }, Paths: paths,
	})
	require.NoError(t, err)
	return coordinator, selection, kit, genesis.Vault, genesis.Anchor, paths
}

func TestManualExportAndValidationOnlyImportCommands(t *testing.T) {
	coordinator, selection, kit, vaultID, anchor, paths := manualCLIExportFixture(t)
	kitText, err := vault.RenderRecoveryKit(kit)
	require.NoError(t, err)
	kitPath := filepath.Join(paths.CacheHome, "kit.txt")
	require.NoError(t, os.WriteFile(kitPath, []byte(kitText), 0o600))
	archivePath := filepath.Join(paths.CacheHome, "vault.dtv")
	factory := func(_ context.Context, _ *urfave.Command, _ bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		return coordinator, selection, func() {}, nil
	}

	var exportOut, exportErr bytes.Buffer
	exportCode := 0
	exportCommand := newManualCommand(&exportOut, &exportErr, &exportCode, factory)
	exportCode = runManualCommandForTest(exportCommand, &exportCode, "export", "--out", archivePath, "--kit-file", kitPath, "--did", "did:plc:cccccccccccccccccccccccc")
	require.Equal(t, 0, exportCode)
	assert.Empty(t, exportErr.String())
	assert.Contains(t, exportOut.String(), "archive: written atomically with mode 0600")
	assert.Contains(t, exportOut.String(), "positions: 1")
	assert.Contains(t, exportOut.String(), "blobs: 1")
	assert.Contains(t, exportOut.String(), "recovery kit: not stored or included")
	assert.NotContains(t, exportOut.String(), kitText)
	archive, err := os.ReadFile(archivePath)
	require.NoError(t, err)
	assert.NotContains(t, string(archive), kitText)
	assert.NotContains(t, string(archive), fmt.Sprintf("%x", kit))
	archiveInfo, err := os.Stat(archivePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), archiveInfo.Mode().Perm())

	var importOut, importErr bytes.Buffer
	importCode := 0
	importCommand := newManualCommand(&importOut, &importErr, &importCode, factory)
	importCode = runManualCommandForTest(importCommand, &importCode, "import", "--archive", archivePath, "--kit-file", kitPath, "--anchor", fmt.Sprintf("%x", anchor), "--vault", fmt.Sprintf("%x", vaultID))
	require.Equal(t, 0, importCode)
	assert.Empty(t, importErr.String())
	assert.Contains(t, importOut.String(), "archive validation: successful")
	assert.Contains(t, importOut.String(), fmt.Sprintf("expected vault: %x", vaultID))
	assert.Contains(t, importOut.String(), fmt.Sprintf("contained anchor: %x", anchor))
	assert.Contains(t, importOut.String(), "validation-only; no state")
	assert.NotContains(t, importOut.String(), kitText)

	wrongKit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	wrongKitText, err := vault.RenderRecoveryKit(wrongKit)
	require.NoError(t, err)
	wrongKitPath := filepath.Join(paths.CacheHome, "wrong-kit.txt")
	require.NoError(t, os.WriteFile(wrongKitPath, []byte(wrongKitText), 0o600))
	var wrongKitOut, wrongKitErr bytes.Buffer
	wrongKitCode := 0
	wrongKitCommand := newManualCommand(&wrongKitOut, &wrongKitErr, &wrongKitCode, factory)
	wrongKitCode = runManualCommandForTest(wrongKitCommand, &wrongKitCode, "import", "--archive", archivePath, "--kit-file", wrongKitPath, "--anchor", fmt.Sprintf("%x", anchor), "--vault", fmt.Sprintf("%x", vaultID))
	require.Equal(t, 3, wrongKitCode)
	assert.Contains(t, wrongKitErr.String(), "archive integrity check failed")

	wrongAnchor := anchor
	wrongAnchor[0] ^= 0x01
	var wrongAnchorOut, wrongAnchorErr bytes.Buffer
	wrongAnchorCode := 0
	wrongAnchorCommand := newManualCommand(&wrongAnchorOut, &wrongAnchorErr, &wrongAnchorCode, factory)
	wrongAnchorCode = runManualCommandForTest(wrongAnchorCommand, &wrongAnchorCode, "import", "--archive", archivePath, "--kit-file", kitPath, "--anchor", fmt.Sprintf("%x", wrongAnchor), "--vault", fmt.Sprintf("%x", vaultID))
	require.Equal(t, 3, wrongAnchorCode)
	assert.Contains(t, wrongAnchorErr.String(), "expected anchor does not match archive")

	wrongVault := vaultID
	wrongVault[0] ^= 0x01
	var wrongVaultOut, wrongVaultErr bytes.Buffer
	wrongVaultCode := 0
	wrongVaultCommand := newManualCommand(&wrongVaultOut, &wrongVaultErr, &wrongVaultCode, factory)
	wrongVaultCode = runManualCommandForTest(wrongVaultCommand, &wrongVaultCode, "import", "--archive", archivePath, "--kit-file", kitPath, "--anchor", fmt.Sprintf("%x", anchor), "--vault", fmt.Sprintf("%x", wrongVault))
	require.Equal(t, 3, wrongVaultCode)
	assert.Contains(t, wrongVaultErr.String(), "expected vault does not match archive")
}

type manualCLIPruneClock struct {
	now    time.Time
	calls  int
	hookAt int
	hook   func()
}

func (clock *manualCLIPruneClock) Now() time.Time {
	clock.calls++
	if clock.hookAt == clock.calls && clock.hook != nil {
		clock.hookAt = 0
		clock.hook()
	}
	return clock.now
}

type manualCLIPruneFixture struct {
	coordinator        *service.Coordinator
	selection          service.VaultSelection
	store              *state.Store
	paths              platform.Paths
	clock              *manualCLIPruneClock
	genesis            vault.Genesis
	device             vault.DeviceMaterial
	kit                []byte
	pds                *atprototest.MemoryPDS
	methods            []atproto.VerificationMethod
	did                string
	eligiblePayload    string
	eligibleBackup     state.JournalEntry
	boundaryPayload    string
	retainedBackup     state.JournalEntry
	unassociatedBackup state.JournalEntry
	unboundBackup      state.JournalEntry
	crossSubject       string
}

func manualCLIPruneFixtureForTest(t *testing.T) *manualCLIPruneFixture {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"),
	}
	for _, path := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	t.Cleanup(func() { clear(kit) })
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	device := vault.DeviceMaterial{DeviceID: "cli-prune-root", KeyID: append([]byte(nil), signing.Public().(ed25519.PublicKey)...), Signing: signing, Recipient: recipient}
	var contentKey [32]byte
	var ephemeral [32]byte
	var wrapNonce [24]byte
	var publicationID [16]byte
	var nonce [24]byte
	for _, value := range [][]byte{contentKey[:], ephemeral[:], wrapNonce[:], publicationID[:], nonce[:]} {
		_, err = rand.Read(value)
		require.NoError(t, err)
	}
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: "cli prune fixture", RootDevice: device, ContentKey: contentKey[:],
		Wraps:         []vault.RecipientWrapInput{{KeyID: append([]byte(nil), device.KeyID...), EphemeralPrivate: ephemeral, WrapNonce: wrapNonce}},
		PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	selection := service.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID}
	ctx := context.Background()
	require.NoError(t, store.PutVaultSelection(ctx, state.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID, RecordedAt: 1}))
	require.NoError(t, store.PutVaultCheckpoint(ctx, state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: append([]byte(nil), genesis.ControlCID...),
		ControlBytes: append([]byte(nil), genesis.Control...), SnapshotCID: append([]byte(nil), genesis.SnapshotCID...),
		Epoch: 0, PolicyDigest: genesis.PolicyDigest, RecordedAt: 1,
	}))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(ctx, state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest, Policy: append([]byte(nil), genesis.Policy...),
		Control: append([]byte(nil), genesis.Control...), Head: append([]byte(nil), genesis.Head...),
		Certificates: [][]byte{append([]byte(nil), genesis.Certificate...)}, CheckpointPosition: append([]byte(nil), genesis.Checkpoint...),
	}))
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	const did = "did:plc:dddddddddddddddddddddddd"
	pds, err := atprototest.NewMemoryPDS(did, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	methods := []atproto.VerificationMethod{{ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase}}
	reader := atproto.RevisionReader{Transport: pds, DIDDocumentID: did, VerificationMethods: methods}
	clock := &manualCLIPruneClock{now: time.Unix(1_800_000_000, 0)}
	_, err = atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: did, ObservationStore: store,
		Clock: func() time.Time { return clock.now },
	}, kit, device, genesis)
	require.NoError(t, err)
	coordinator := manualCLIRetentionCoordinator(t, store, paths, clock, device, pds, did, methods)
	initial, err := coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, service.RetentionAdmissionUpdated, initial.Retention.Admission)
	declaration, err := store.RetentionDeclaration(ctx, genesis.Vault, device.DeviceID)
	require.NoError(t, err)
	require.Len(t, declaration.RecoveryPoints, 1)
	oldPoint := declaration.RecoveryPoints[0]
	inventory, err := store.RetentionInventory(ctx, genesis.Vault, device.DeviceID)
	require.NoError(t, err)
	var oldBodyReference string
	for _, material := range inventory.Materials {
		if material.Epoch == oldPoint.Epoch && bytes.Equal(material.SnapshotCID, oldPoint.SnapshotCID) && material.PayloadReference != "" {
			oldBodyReference = material.PayloadReference
			break
		}
	}
	require.NotEmpty(t, oldBodyReference)
	oldBody, err := store.Payload(oldBodyReference)
	require.NoError(t, err)
	require.NoError(t, store.PutTarget(ctx, state.TargetDescriptor{ID: "cli-prune-target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, Mode: "review", LogicalBase: model.RootHome, LogicalPath: "selected", Kind: model.SelectionDirectory, CreatedAt: 1}))
	eligiblePayload, err := store.PutRetentionMaterialPayload(ctx, []byte("identified pre-boundary payload"))
	require.NoError(t, err)
	eligibleBackup := appendCLIRetentionBackup(t, store, selection, oldPoint, "eligible-evicted-backup", 1, true)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, genesis.Vault, device.DeviceID, oldPoint,
		[]string{oldBodyReference, eligiblePayload}, []string{eligibleBackup.BackupRef}))
	crossSubject, err := store.PutRetentionMaterialPayload(ctx, []byte("cross-subject retained sentinel"))
	require.NoError(t, err)
	otherVault := [32]byte{0xE2}
	_, err = store.ReplaceRetentionDeclarationWithMaterials(ctx, state.RetentionDeclaration{
		Vault: otherVault, DeviceID: "other-device", PolicyDigest: oldPoint.PolicyDigest, RetentionFloor: oldPoint.Epoch, DeclaredAt: 1,
		RecoveryPoints: []state.RetentionRecoveryPoint{oldPoint},
	}, []state.RetentionRecoveryPointMaterials{{Point: oldPoint, Payloads: [][]byte{oldBody, []byte("cross-subject retained sentinel")}}})
	require.NoError(t, err)
	firstPublic := manualCLIRetentionPublicDevice(t, "cli-prune-one")
	firstApproval := vault.EnrollmentTranscriptFingerprint(genesis.Vault, firstPublic.DeviceID, firstPublic.KeyID, vault.RoleRestoreOnly, firstPublic.SigningPublicKey, firstPublic.RecipientPublicKey)
	firstEnrollment, err := coordinator.Enroll(ctx, service.EnrollRequest{Selection: selection, Device: firstPublic, Role: vault.RoleRestoreOnly, ApprovalFingerprint: firstApproval, Kit: kit})
	require.NoError(t, err)
	require.Equal(t, service.StatusCommitted, firstEnrollment.Status)
	checkpoint, err := store.VaultCheckpoint(ctx, genesis.Vault)
	require.NoError(t, err)
	require.Equal(t, uint64(1), checkpoint.Epoch)
	currentDeclaration, err := store.RetentionDeclaration(ctx, genesis.Vault, device.DeviceID)
	require.NoError(t, err)
	var boundaryPoint state.RetentionRecoveryPoint
	for _, point := range currentDeclaration.RecoveryPoints {
		if point.Epoch == checkpoint.Epoch {
			boundaryPoint = point
		}
	}
	require.NotEmpty(t, boundaryPoint.SnapshotCID)
	currentInventory, err := store.RetentionInventory(ctx, genesis.Vault, device.DeviceID)
	require.NoError(t, err)
	var boundaryBodyReference string
	for _, material := range currentInventory.Materials {
		if material.Epoch == boundaryPoint.Epoch && bytes.Equal(material.SnapshotCID, boundaryPoint.SnapshotCID) && material.PayloadReference != "" {
			boundaryBodyReference = material.PayloadReference
			break
		}
	}
	require.NotEmpty(t, boundaryBodyReference)
	_, err = store.Payload(boundaryBodyReference)
	require.NoError(t, err)
	retainedBackup := appendCLIRetentionBackup(t, store, selection, boundaryPoint, "retained-boundary-backup", 1, true)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, genesis.Vault, device.DeviceID, boundaryPoint, []string{boundaryBodyReference}, []string{retainedBackup.BackupRef}))
	unassociatedBackup := appendCLIRetentionBackup(t, store, selection, boundaryPoint, "bound-unassociated-backup", 1, true)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, genesis.Vault, device.DeviceID, boundaryPoint, []string{boundaryBodyReference}, []string{retainedBackup.BackupRef}))
	unboundBackup := appendCLIRetentionBackup(t, store, selection, boundaryPoint, "unbound-backup-sentinel", 1, false)
	clonePaths := platform.Paths{
		Home: filepath.Join(root, "clone-home"), ConfigHome: filepath.Join(root, "clone-config"),
		StateHome: filepath.Join(root, "clone-state"), CacheHome: filepath.Join(root, "clone-cache"),
	}
	for _, path := range []string{clonePaths.Home, clonePaths.ConfigHome, clonePaths.StateHome, clonePaths.CacheHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	cloneStore, err := state.Open(clonePaths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, cloneStore.Close()) })
	cloneClock := &manualCLIPruneClock{now: clock.now}
	clone := manualCLIRetentionCoordinator(t, cloneStore, clonePaths, cloneClock, device, pds, did, methods)
	require.NoError(t, clone.ImportOnboarding(ctx, firstEnrollment.EncodedBundle, genesis.Vault, genesis.Anchor, device.DeviceID))
	secondPublic := manualCLIRetentionPublicDevice(t, "cli-prune-two")
	secondApproval := vault.EnrollmentTranscriptFingerprint(genesis.Vault, secondPublic.DeviceID, secondPublic.KeyID, vault.RoleRestoreOnly, secondPublic.SigningPublicKey, secondPublic.RecipientPublicKey)
	secondEnrollment, err := clone.Enroll(ctx, service.EnrollRequest{Selection: selection, Device: secondPublic, Role: vault.RoleRestoreOnly, ApprovalFingerprint: secondApproval, Kit: kit})
	require.NoError(t, err)
	require.Equal(t, service.StatusCommitted, secondEnrollment.Status)
	return &manualCLIPruneFixture{
		coordinator: coordinator, selection: selection, store: store, paths: paths, clock: clock, genesis: genesis,
		device: device, kit: kit, pds: pds, methods: methods, did: did,
		eligiblePayload: eligiblePayload, eligibleBackup: eligibleBackup, boundaryPayload: boundaryBodyReference,
		retainedBackup: retainedBackup, unassociatedBackup: unassociatedBackup, unboundBackup: unboundBackup,
		crossSubject: crossSubject,
	}
}

func manualCLIRetentionCoordinator(t *testing.T, store *state.Store, paths platform.Paths, clock *manualCLIPruneClock, device vault.DeviceMaterial, pds *atprototest.MemoryPDS, did string, methods []atproto.VerificationMethod) *service.Coordinator {
	t.Helper()
	identity := atproto.Identity{DID: did, DIDDocumentID: did, VerificationMethods: methods}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, DeviceKeys: manualCLIExportKeyring{device: device},
		Trust:     service.StateTrustSource{State: store, Keyring: manualCLIExportKeyring{device: device}},
		Session:   manualCLIExportSession{did: did, methods: methods},
		Remote:    service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: func() time.Time { return clock.now }}},
		Publisher: sessionPublicationPort{identity: identity, transport: pds},
		Clock:     clock.Now, Paths: paths,
	})
	require.NoError(t, err)
	return coordinator
}

func manualCLIRetentionPublicDevice(t *testing.T, id string) vault.PublicDeviceInput {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	return vault.PublicDeviceInput{
		DeviceID: id, KeyID: append([]byte(nil), signing.Public().(ed25519.PublicKey)...),
		SigningPublicKey: append([]byte(nil), signing.Public().(ed25519.PublicKey)...), RecipientPublicKey: recipient.PublicKey().Bytes(),
	}
}

func appendCLIRetentionBackup(t *testing.T, store *state.Store, selection service.VaultSelection, point state.RetentionRecoveryPoint, id string, createdAt int64, bound bool) state.JournalEntry {
	t.Helper()
	ctx := context.Background()
	before, after := []byte(id+" preimage"), []byte(id+" postimage")
	entry := state.JournalEntry{
		ID: id, Operation: "replace", State: "pending", Stage: state.JournalStagePending,
		Identity:  model.EntryKey{TargetID: "cli-prune-target", Source: model.SourceFiles, FilePath: id + ".toml"},
		Preimage:  state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", before),
		Postimage: state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", after), CreatedAt: createdAt,
	}
	if bound {
		entry.Retention = &state.RetentionBinding{Vault: selection.Vault, Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID)}
	}
	stored, err := store.AppendJournal(ctx, entry, before)
	require.NoError(t, err)
	require.NoError(t, store.TransitionJournalEntry(ctx, stored.ID, "pending", "applied", state.JournalStageVerified))
	stored.State = "applied"
	stored.Stage = state.JournalStageVerified
	return stored
}

func TestPruneForegroundCLIReportsPlansRefusesUnconfirmedAndPreservesSentinels(t *testing.T) {
	unconfirmedFixture := manualCLIPruneFixtureForTest(t)
	unconfirmedPayload, err := unconfirmedFixture.store.Payload(unconfirmedFixture.eligiblePayload)
	require.NoError(t, err)
	unconfirmedBackup, err := unconfirmedFixture.store.Payload(unconfirmedFixture.eligibleBackup.BackupRef)
	require.NoError(t, err)
	var unconfirmedOut, unconfirmedErr bytes.Buffer
	unconfirmedCode := 0
	unconfirmedCommand := newOrchestrationCommand(&unconfirmedOut, &unconfirmedErr, &unconfirmedCode, orchestrationTestFactory(unconfirmedFixture.coordinator, unconfirmedFixture.selection, nil, nil))
	unconfirmedCode = runOrchestrationForTest(unconfirmedCommand, &unconfirmedCode, "prune", "--apply", "--did", unconfirmedFixture.did)
	require.Equal(t, 3, unconfirmedCode)
	assert.Contains(t, unconfirmedOut.String(), "prune: confirmation-required")
	assert.Contains(t, unconfirmedErr.String(), "prune refused")
	assert.NotContains(t, unconfirmedOut.String(), unconfirmedFixture.paths.Home)
	assert.NotContains(t, unconfirmedOut.String(), "identified pre-boundary payload")
	assert.NotContains(t, unconfirmedOut.String(), unconfirmedFixture.eligibleBackup.ID)
	payloadAfterRefusal, err := unconfirmedFixture.store.Payload(unconfirmedFixture.eligiblePayload)
	require.NoError(t, err)
	assert.Equal(t, unconfirmedPayload, payloadAfterRefusal)
	backupAfterRefusal, err := unconfirmedFixture.store.Payload(unconfirmedFixture.eligibleBackup.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, unconfirmedBackup, backupAfterRefusal)

	fixture := manualCLIPruneFixtureForTest(t)
	var planOut, planErr bytes.Buffer
	planCode := 0
	planCommand := newOrchestrationCommand(&planOut, &planErr, &planCode, orchestrationTestFactory(fixture.coordinator, fixture.selection, nil, nil))
	planCode = runOrchestrationForTest(planCommand, &planCode, "prune", "--plan", "--did", fixture.did)
	require.Equal(t, 0, planCode)
	assert.Empty(t, planErr.String())
	assert.Contains(t, planOut.String(), "recovery floor: epoch=1")
	assert.Contains(t, planOut.String(), "confidentiality floor: epoch=0")
	assert.Contains(t, planOut.String(), "floor status: unknown")
	assert.Contains(t, planOut.String(), "candidate: kind=payload reference="+fixture.eligiblePayload+" epochs=0 eligible=true")
	assert.Contains(t, planOut.String(), "candidate: kind=backup reference="+fixture.eligibleBackup.BackupRef+" epochs=0 eligible=true")
	assert.Contains(t, planOut.String(), "candidate: kind=payload reference="+fixture.boundaryPayload+" epochs=1 eligible=false")
	assert.Contains(t, planOut.String(), "candidate: kind=backup reference="+fixture.retainedBackup.BackupRef+" epochs=1 eligible=false")
	assert.Contains(t, planOut.String(), "candidate: kind=backup reference="+fixture.unassociatedBackup.BackupRef+" epochs=unknown eligible=false")
	assert.NotContains(t, planOut.String(), fixture.paths.Home)
	assert.NotContains(t, planOut.String(), "preimage")
	assert.NotContains(t, planOut.String(), "postimage")
	var eligibleCandidates []string
	for _, line := range strings.Split(planOut.String(), "\n") {
		if !strings.HasPrefix(line, "candidate: ") || !strings.Contains(line, "eligible=true") {
			continue
		}
		kind, reference := "", ""
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "kind=") {
				kind = strings.TrimPrefix(field, "kind=")
			}
			if strings.HasPrefix(field, "reference=") {
				reference = strings.TrimPrefix(field, "reference=")
			}
		}
		eligibleCandidates = append(eligibleCandidates, kind+" "+reference)
	}
	sort.Strings(eligibleCandidates)
	expectedEligible := []string{
		"backup " + fixture.eligibleBackup.BackupRef,
		"payload " + fixture.eligiblePayload,
		"payload " + fixture.eligibleBackup.BackupRef,
	}
	sort.Strings(expectedEligible)
	assert.Equal(t, expectedEligible, eligibleCandidates)
	inventory, err := fixture.store.RetentionInventory(context.Background(), fixture.selection.Vault, fixture.selection.DeviceID)
	require.NoError(t, err)
	require.Len(t, inventory.Points, 2)
	for _, point := range inventory.Points {
		assert.True(t, point.InventoryComplete, "retained point epoch %d must be complete", point.Epoch)
	}
	payloadSentinel, err := fixture.store.Payload(fixture.boundaryPayload)
	require.NoError(t, err)
	crossSubjectSentinel, err := fixture.store.Payload(fixture.crossSubject)
	require.NoError(t, err)
	retainedBackupBytes, err := fixture.store.Payload(fixture.retainedBackup.BackupRef)
	require.NoError(t, err)
	unassociatedBackupBytes, err := fixture.store.Payload(fixture.unassociatedBackup.BackupRef)
	require.NoError(t, err)
	unboundBackupBytes, err := fixture.store.Payload(fixture.unboundBackup.BackupRef)
	require.NoError(t, err)
	rowsBefore, err := fixture.store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	var applyOut, applyErr bytes.Buffer
	applyCode := 0
	applyCommand := newOrchestrationCommand(&applyOut, &applyErr, &applyCode, orchestrationTestFactory(fixture.coordinator, fixture.selection, nil, nil))
	applyCode = runOrchestrationForTest(applyCommand, &applyCode, "prune", "--apply", "--confirm", "--did", fixture.did)
	require.Equal(t, 0, applyCode)
	assert.Empty(t, applyErr.String())
	assert.Contains(t, applyOut.String(), "deleted payload references:\n  "+fixture.eligiblePayload)
	assert.Contains(t, applyOut.String(), "  "+fixture.eligibleBackup.BackupRef+"\n")
	assert.Contains(t, applyOut.String(), "pruned backup references:\n  "+fixture.eligibleBackup.BackupRef)
	assert.NotContains(t, applyOut.String(), fixture.paths.Home)
	_, err = fixture.store.Payload(fixture.eligiblePayload)
	assert.Error(t, err)
	_, err = fixture.store.Payload(fixture.eligibleBackup.BackupRef)
	assert.Error(t, err)
	payloadAfter, err := fixture.store.Payload(fixture.boundaryPayload)
	require.NoError(t, err)
	assert.Equal(t, payloadSentinel, payloadAfter)
	crossAfter, err := fixture.store.Payload(fixture.crossSubject)
	require.NoError(t, err)
	assert.Equal(t, crossSubjectSentinel, crossAfter)
	retainedAfter, err := fixture.store.Payload(fixture.retainedBackup.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, retainedBackupBytes, retainedAfter)
	unassociatedAfter, err := fixture.store.Payload(fixture.unassociatedBackup.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, unassociatedBackupBytes, unassociatedAfter)
	unboundAfter, err := fixture.store.Payload(fixture.unboundBackup.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, unboundBackupBytes, unboundAfter)
	rowsAfter, err := fixture.store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	beforeByID := make(map[string]state.JournalEntry, len(rowsBefore))
	for _, row := range rowsBefore {
		beforeByID[row.ID] = row
	}
	afterByID := make(map[string]state.JournalEntry, len(rowsAfter))
	for _, row := range rowsAfter {
		afterByID[row.ID] = row
	}
	eligibleExpected := beforeByID[fixture.eligibleBackup.ID]
	eligibleExpected.BackupRef = ""
	assert.Equal(t, eligibleExpected, afterByID[fixture.eligibleBackup.ID], "pruning detaches only the eligible aged backup reference")
	for _, sentinel := range []state.JournalEntry{fixture.retainedBackup, fixture.unassociatedBackup, fixture.unboundBackup} {
		assert.Equal(t, beforeByID[sentinel.ID], afterByID[sentinel.ID], "protected sentinel journal row remains byte-identical")
	}
}

func TestPruneForegroundCLIRefusesIncompleteInventoryWithoutDeletion(t *testing.T) {
	fixture := manualCLIPruneFixtureForTest(t)
	payloadBefore, err := fixture.store.Payload(fixture.eligiblePayload)
	require.NoError(t, err)
	backupBefore, err := fixture.store.Payload(fixture.eligibleBackup.BackupRef)
	require.NoError(t, err)
	var hookErr error
	fixture.clock.hookAt = fixture.clock.calls + 2
	fixture.clock.hook = func() {
		declaration, declarationErr := fixture.store.RetentionDeclaration(context.Background(), fixture.selection.Vault, fixture.selection.DeviceID)
		if declarationErr != nil {
			hookErr = declarationErr
			return
		}
		declaration.DeclaredAt++
		for index := range declaration.RecoveryPoints {
			declaration.RecoveryPoints[index].PolicyDigest = [32]byte{}
			declaration.RecoveryPoints[index].ControlCID = nil
		}
		declaration, hookErr = fixture.store.PutRetentionDeclaration(context.Background(), declaration)
		if hookErr != nil {
			return
		}
		inventory, inventoryErr := fixture.store.RetentionInventory(context.Background(), fixture.selection.Vault, fixture.selection.DeviceID)
		if inventoryErr != nil {
			hookErr = inventoryErr
			return
		}
		for _, point := range declaration.RecoveryPoints {
			var bodyReference string
			for _, material := range inventory.Materials {
				if material.Epoch == point.Epoch && bytes.Equal(material.SnapshotCID, point.SnapshotCID) && material.PayloadReference != "" {
					bodyReference = material.PayloadReference
					break
				}
			}
			if bodyReference == "" {
				hookErr = errors.New("synthetic retained body is missing")
				return
			}
			if hookErr = fixture.store.SetRetentionRecoveryPointMaterial(context.Background(), fixture.selection.Vault, fixture.selection.DeviceID, point, []string{bodyReference}, nil); hookErr != nil {
				return
			}
		}
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fixture.coordinator, fixture.selection, nil, nil))
	code = runOrchestrationForTest(command, &code, "prune", "--plan", "--did", fixture.did)
	require.NoError(t, hookErr)
	require.Equal(t, 3, code)
	assert.Contains(t, stdout.String(), "prune: refused")
	assert.Contains(t, stdout.String(), "reason: inventory-incomplete")
	assert.NotContains(t, stdout.String(), fixture.paths.Home)
	inventory, err := fixture.store.RetentionInventory(context.Background(), fixture.selection.Vault, fixture.selection.DeviceID)
	require.NoError(t, err)
	require.NotEmpty(t, inventory.Points)
	for _, point := range inventory.Points {
		assert.False(t, point.InventoryComplete)
	}
	payloadAfter, err := fixture.store.Payload(fixture.eligiblePayload)
	require.NoError(t, err)
	assert.Equal(t, payloadBefore, payloadAfter)
	backupAfter, err := fixture.store.Payload(fixture.eligibleBackup.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, backupBefore, backupAfter)
	entry, err := fixture.store.JournalEntries(context.Background(), "cli-prune-target")
	require.NoError(t, err)
	for _, row := range entry {
		if row.ID == fixture.eligibleBackup.ID {
			assert.Equal(t, fixture.eligibleBackup.BackupRef, row.BackupRef)
		}
	}
}
