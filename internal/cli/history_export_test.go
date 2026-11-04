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
	"strings"
	"testing"
	"time"

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
		Control: append([]byte(nil), genesis.Control...), Head: append([]byte(nil), genesis.Head...), Snapshot: append([]byte(nil), genesis.Snapshot...),
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
