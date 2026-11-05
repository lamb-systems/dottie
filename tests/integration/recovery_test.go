package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchiveRecoveryAfterSourceLoss(t *testing.T) {
	fixture := newPublicationFixture(t)
	ctx := context.Background()
	kitPath := filepath.Join(fixture.paths.CacheHome, "recovery-kit.txt")
	kitText, err := vault.RenderRecoveryKit(fixture.kit)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(kitPath, []byte(kitText), 0o600))
	kit, err := readArchiveRecoveryKit(kitPath)
	require.NoError(t, err)
	defer clear(kit)

	archivePath := filepath.Join(fixture.paths.CacheHome, "published-archive.dtv")
	beforeWrites := archiveRepositoryWriteCount(fixture.pds.Calls())
	exportReport, err := fixture.coordinator.Export(ctx, service.ExportRequest{
		Selection: fixture.selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: kit, Path: archivePath,
	})
	require.NoError(t, err)
	assert.Zero(t, archiveRepositoryWriteCount(fixture.pds.Calls())-beforeWrites, "coordinator export must be read-only")
	assert.NotEmpty(t, exportReport.Current.SnapshotCID)
	archiveBytes, err := os.ReadFile(archivePath)
	require.NoError(t, err)

	wrongExportKit := bytes.Repeat([]byte{0x71}, 32)
	wrongKitArchivePath := filepath.Join(fixture.paths.CacheHome, "wrong-kit-export.dtv")
	_, err = fixture.coordinator.Export(ctx, service.ExportRequest{
		Selection: fixture.selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: wrongExportKit, Path: wrongKitArchivePath,
	})
	clear(wrongExportKit)
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrRecoveryKitMismatch)
	_, statErr := os.Stat(wrongKitArchivePath)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "wrong-kit export must not publish an archive file")

	missingBlobCID, err := cid.Decode(exportReport.Current.SnapshotCID)
	require.NoError(t, err)
	fixture.pds.RemoveBlob(missingBlobCID.String())
	missingArchivePath := filepath.Join(fixture.paths.CacheHome, "missing-required-blob.dtv")
	_, err = fixture.coordinator.Export(ctx, service.ExportRequest{
		Selection: fixture.selection, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor,
		Kit: kit, Path: missingArchivePath,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrExportRefused)
	_, statErr = os.Stat(missingArchivePath)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "refused export must not publish an archive file")

	destroyPublicationSource(t, fixture)
	assert.Empty(t, fixture.pds.CurrentRevision().Records, "source-loss fixture still has repository records")
	assert.Empty(t, fixture.pds.StoredBlobCIDs(), "source-loss fixture still has stored blobs")
	beforeApplication := fixture.applicationStateDigest()
	beforeHome := fixture.homeTreeDigest()
	beforeFile, err := os.ReadFile(fixture.filePath)
	require.NoError(t, err)
	_, err = fixture.coordinator.Pull(ctx, fixture.selection)
	require.Error(t, err, "online read must refuse after source records and blobs are destroyed")
	_, err = fixture.coordinator.Restore(ctx, service.RestoreRequest{Selection: fixture.selection, TargetID: publicationAuditFileTargetID})
	require.Error(t, err, "online restore must refuse after source records and blobs are destroyed")
	assert.Equal(t, beforeApplication, fixture.applicationStateDigest())
	assert.Equal(t, beforeHome, fixture.homeTreeDigest())
	afterFile, err := os.ReadFile(fixture.filePath)
	require.NoError(t, err)
	assert.Equal(t, beforeFile, afterFile)

	callsBeforeArchiveValidation := len(fixture.pds.Calls())
	validatedAfterSourceLoss, err := fixture.coordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, Kit: kit,
	})
	require.NoError(t, err)
	assert.Equal(t, exportReport.VaultID, validatedAfterSourceLoss.VaultID)
	assert.Equal(t, exportReport.Anchor, validatedAfterSourceLoss.Anchor)
	assert.Equal(t, exportReport.Current.SnapshotCID, validatedAfterSourceLoss.Current.SnapshotCID)
	assert.Equal(t, callsBeforeArchiveValidation, len(fixture.pds.Calls()), "archive validation must not consult the destroyed provider")

	parsed, err := vault.ReadExportArchive(bytes.NewReader(archiveBytes), vault.ImportOptions{
		ExpectedVaultID: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, RecoveryKit: kit,
	})
	require.NoError(t, err)
	currentHead, err := vault.DecodeHead(parsed.Current.Head)
	require.NoError(t, err)
	require.Equal(t, uint64(1), currentHead.PublicationCount)
	var currentEnvelopeBytes []byte
	for _, blob := range parsed.Blobs {
		if bytes.Equal(blob.CID, currentHead.BlobCID) {
			currentEnvelopeBytes = bytes.Clone(blob.Data)
		}
	}
	require.NotEmpty(t, currentEnvelopeBytes, "parsed archive is missing the current-position envelope")

	isolatedHome := t.TempDir()
	isolatedArchivePath := filepath.Join(isolatedHome, "recovery.dtv")
	require.NoError(t, os.WriteFile(isolatedArchivePath, archiveBytes, 0o600))
	recipientPrivate := fixture.root.Recipient.Bytes()
	retainedKeyMaterial := append(bytes.Clone(fixture.root.KeyID), recipientPrivate...)
	clear(recipientPrivate)
	retainedKeyPath := filepath.Join(isolatedHome, "recipient.key")
	require.NoError(t, os.WriteFile(retainedKeyPath, retainedKeyMaterial, 0o600))
	clear(retainedKeyMaterial)
	isolatedEntries, err := os.ReadDir(isolatedHome)
	require.NoError(t, err)
	assert.Len(t, isolatedEntries, 2, "fresh recovery home must contain only the archive and retained recipient key material")
	isolatedArchiveFile, err := os.Open(isolatedArchivePath)
	require.NoError(t, err)
	isolatedArchive, err := vault.ReadExportArchive(isolatedArchiveFile, vault.ImportOptions{
		ExpectedVaultID: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, RecoveryKit: kit,
	})
	closeErr := isolatedArchiveFile.Close()
	require.NoError(t, closeErr)
	require.NoError(t, err)
	keyBytes, err := os.ReadFile(retainedKeyPath)
	require.NoError(t, err)
	require.Len(t, keyBytes, 64)
	deviceKeyID := bytes.Clone(keyBytes[:32])
	deviceRecipient, err := ecdh.X25519().NewPrivateKey(keyBytes[32:])
	clear(keyBytes)
	require.NoError(t, err)

	archiveHead, err := vault.DecodeHead(isolatedArchive.Current.Head)
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(isolatedArchive.Current.Policy)
	require.NoError(t, err)
	var archiveEnvelopeBytes []byte
	for _, blob := range isolatedArchive.Blobs {
		if bytes.Equal(blob.CID, archiveHead.BlobCID) {
			archiveEnvelopeBytes = bytes.Clone(blob.Data)
		}
	}
	require.NotEmpty(t, archiveEnvelopeBytes)
	archiveEnvelope, err := vault.DecodeEnvelope(archiveEnvelopeBytes)
	require.NoError(t, err)
	plaintext, err := vault.Open(archiveEnvelope, vault.OpenRequest{
		Vault: isolatedArchive.VaultID, EpochSeq: archiveHead.EpochSeq, PolicyDigest: policyDigest,
		Policy: isolatedArchive.Current.Policy, Control: isolatedArchive.Current.Control,
		TrustAnchor: isolatedArchive.Anchor, Certificates: isolatedArchive.Current.Certificates,
		DeviceKeyID: deviceKeyID, DeviceKey: deviceRecipient,
	})
	require.NoError(t, err)
	assert.Equal(t, fixture.publishedPlaintext, plaintext, "archive-to-plaintext recovery with a retained recipient key must reproduce the published bytes; kit-only decryption is impossible and no archive-to-files restore is performed")

	wrongKit := bytes.Repeat([]byte{0x71}, 32)
	_, err = fixture.coordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: fixture.genesis.Anchor, Kit: wrongKit,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, vault.ErrExportPolicy)
	_, err = fixture.coordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: fixture.genesis.Vault, ExpectedAnchor: [32]byte{0x91}, Kit: kit,
	})
	require.ErrorIs(t, err, vault.ErrForeignAnchor)

	tampered := tamperFirstExportMember(t, archiveBytes)
	tamperedArchivePath := filepath.Join(isolatedHome, "tampered.dtv")
	require.NoError(t, os.WriteFile(tamperedArchivePath, tampered, 0o600))
	_, err = fixture.coordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: tamperedArchivePath, ExpectedVault: parsed.VaultID, ExpectedAnchor: parsed.Anchor, Kit: kit,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, vault.ErrExportIntegrity, "modified archive member must be refused as an integrity failure")
}

func TestLiveArchiveExportAndValidation(t *testing.T) {
	handle := os.Getenv("DOTTIE_HANDLE")
	kitPath := os.Getenv("DOTTIE_RECOVERY_KIT_FILE")
	if os.Getenv("DOTTIE_LIVE_ARCHIVE") != "1" || !allowedPDSHandle(handle) || kitPath == "" {
		t.Skip("set DOTTIE_LIVE_ARCHIVE=1, an allowlisted DOTTIE_HANDLE, and DOTTIE_RECOVERY_KIT_FILE to run the read-only live archive gate")
	}
	provider := pdsProviderName(handle)
	artifactDir := liveArtifactDir(t)
	artifact := pdsFailureArtifact{Provider: provider, IntendedPDS: "redacted", Criterion: "archive-export-validation", DecisionDOTF07: "Owner review required; no production release claim.", CloudReleaseHold: true}
	artifactEvidence := "live archive gate failed before classification; details redacted"
	defer func() {
		if t.Failed() {
			artifact.RedactedEvidence = artifactEvidence
			_, writeErr := writePDSFailureArtifact(artifactDir, artifact)
			assert.NoError(t, writeErr)
		}
	}()

	kit, err := readArchiveRecoveryKit(kitPath)
	require.True(t, err == nil, "DOTTIE_RECOVERY_KIT_FILE must be a regular 0600 file decoding to exactly 32 bytes")
	defer clear(kit)
	paths, err := platform.Resolve(os.Getenv)
	require.True(t, err == nil, "operator environment paths could not be resolved")
	store, err := state.Open(paths)
	require.True(t, err == nil, "operator state store could not be opened")
	defer func() { assert.NoError(t, store.Close()) }()
	keyring, err := platform.NewKeyring()
	require.True(t, err == nil, "Secret Service keyring could not be opened")
	defer func() { assert.NoError(t, keyring.Close()) }()
	client, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	require.True(t, err == nil, "account client could not be created")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	identity, err := client.Discover(ctx, handle)
	require.True(t, err == nil && identity.DID != "", "allowlisted identity discovery failed; details redacted")
	session, err := client.LoadSession(ctx, identity.DID)
	require.True(t, err == nil, "account session could not be loaded; details redacted")
	api, err := atproto.NewSessionAPIClient(client, identity, identity.Handle, session)
	require.True(t, err == nil, "authenticated read-only PDS client could not be created")
	transport := &archiveReadOnlyTransport{base: atproto.NewATClientTransport(api)}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, DeviceKeys: keyring,
		Trust: service.StateTrustSource{State: store, Keyring: keyring}, Session: archiveLiveReadSession{identity: identity},
		Remote: service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: time.Now}},
		Paths:  paths, Clock: time.Now,
	})
	require.True(t, err == nil, "archive coordinator could not be created")
	selection, err := coordinator.ResolveSelection(ctx, service.VaultSelection{})
	require.True(t, err == nil, "existing local vault selection is unavailable or ambiguous; details redacted")
	checkpoint, err := store.VaultCheckpoint(ctx, selection.Vault)
	require.True(t, err == nil, "selected vault checkpoint is unavailable; details redacted")
	archivePath := filepath.Join(artifactDir, "live-archive.dtv")
	exportReport, err := coordinator.Export(ctx, service.ExportRequest{
		Selection: selection, ExpectedVault: selection.Vault, ExpectedAnchor: checkpoint.Anchor, Kit: kit, Path: archivePath,
	})
	if err != nil {
		assert.Zero(t, transport.writeCalls, "read-only archive gate attempted a repository write")
		if errors.Is(err, service.ErrExportRefused) {
			var refusal *service.ExportRefusalError
			if errors.As(err, &refusal) && refusal.CID != "" {
				artifactEvidence = "live export refused with a named CID; CID and identity redacted; refusal is not provider evidence"
				artifact.RedactedEvidence = artifactEvidence
				_, writeErr := writePDSFailureArtifact(artifactDir, artifact)
				assert.NoError(t, writeErr)
				t.Skip("read-only live export refused with a named CID; redacted outcome recorded and not counted as provider evidence")
			}
			artifactEvidence = "live export refusal had no named CID; detailed reason redacted"
			t.Errorf("live archive export refusal did not identify a CID; details redacted")
			return
		}
		if errors.Is(err, service.ErrRecoveryKitMismatch) {
			artifactEvidence = "provided kit did not authenticate the recorded checkpoint; details redacted"
		} else {
			artifactEvidence = "live export or checkpoint validation failed; details redacted"
		}
		t.Errorf("live archive export failed; details redacted")
		return
	}
	assert.Zero(t, transport.writeCalls, "read-only archive gate attempted a repository write")
	archiveReport, err := coordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: selection.Vault, ExpectedAnchor: checkpoint.Anchor, Kit: kit,
	})
	require.True(t, err == nil, "exported archive validation failed; details redacted")
	assert.True(t, archiveReport.VaultID == selection.Vault, "validated archive vault did not match the selected vault")
	assert.True(t, archiveReport.Anchor == checkpoint.Anchor, "validated archive anchor did not match the recorded checkpoint")
	assert.NotEmpty(t, exportReport.Current.SnapshotCID)
	assert.Zero(t, transport.writeCalls, "archive validation attempted a repository write")
	assert.NoError(t, os.Remove(archivePath))
	artifactEvidence = "live archive export and validation passed; identity, paths, CIDs, and credentials redacted"
}

type archiveReadOnlyTransport struct {
	base       atproto.Transport
	writeCalls int
}

func (transport *archiveReadOnlyTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	switch endpoint {
	case "com.atproto.repo.applyWrites", "com.atproto.repo.uploadBlob", "com.atproto.repo.createRecord", "com.atproto.repo.putRecord", "com.atproto.repo.deleteRecord":
		transport.writeCalls++
		return 0, nil, errors.New("repository writes are forbidden in the live archive gate")
	default:
		return transport.base.Do(ctx, method, endpoint, query, body, contentType)
	}
}

func (transport *archiveReadOnlyTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return transport.base.OpenStream(ctx, endpoint, query)
}

type archiveLiveReadSession struct {
	identity atproto.Identity
}

func (session archiveLiveReadSession) ReadRequest(_ context.Context, selection service.VaultSelection, device vault.DeviceMaterial, anchor [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	return atproto.ReadRequest{
		DID: session.identity.DID, DIDDocumentID: session.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), session.identity.VerificationMethods...),
		Vault:               selection.Vault, TrustAnchor: anchor, PreviousPolicy: bytes.Clone(previousPolicy), PreviousControl: bytes.Clone(previousControl),
		DeviceKeyID: bytes.Clone(device.KeyID), DeviceKey: device.Recipient,
	}, nil
}

func readArchiveRecoveryKit(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("kit file must be regular and private")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("kit file cannot be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("kit file changed or is not private")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil || len(encoded) > 512 {
		clear(encoded)
		return nil, errors.New("kit file exceeds its limit")
	}
	kit, err := vault.ParseRecoveryKit(string(encoded))
	clear(encoded)
	if err != nil || len(kit) != 32 {
		clear(kit)
		return nil, errors.New("kit file must decode to 32 bytes")
	}
	return kit, nil
}

func destroyPublicationSource(t *testing.T, fixture *publicationFixture) {
	t.Helper()
	surface := collectPublicationAudit(context.Background(), fixture.transport, fixture.transport, fixture.did, fixture.pds.StoredBlobCIDs())
	require.Empty(t, surface.incomplete)
	for _, pages := range surface.recordPages {
		for _, body := range pages {
			var page struct {
				Records []struct {
					URI string `json:"uri"`
				} `json:"records"`
			}
			require.NoError(t, json.Unmarshal(body, &page))
			for _, record := range page.Records {
				recordPath := strings.TrimPrefix(record.URI, "at://"+fixture.did+"/")
				parts := strings.SplitN(recordPath, "/", 2)
				require.Len(t, parts, 2)
				require.NoError(t, fixture.pds.RemoveRecord(parts[0], parts[1]))
			}
		}
	}
	for _, blobCID := range fixture.pds.StoredBlobCIDs() {
		fixture.pds.RemoveBlob(blobCID)
	}
}

func tamperFirstExportMember(t *testing.T, archive []byte) []byte {
	t.Helper()
	require.True(t, bytes.HasPrefix(archive, []byte("DTVA")))
	reader := tar.NewReader(bytes.NewReader(archive[len("DTVA"):]))
	var output bytes.Buffer
	output.WriteString("DTVA")
	writer := tar.NewWriter(&output)
	tampered := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		member, err := io.ReadAll(reader)
		require.NoError(t, err)
		headerCopy := *header
		if !tampered && header.Name != "000000" && len(member) != 0 {
			member[0] ^= 0x40
			tampered = true
		}
		require.NoError(t, writer.WriteHeader(&headerCopy))
		_, err = writer.Write(member)
		require.NoError(t, err)
	}
	require.True(t, tampered, "archive had no payload member to tamper")
	require.NoError(t, writer.Close())
	return output.Bytes()
}

func archiveRepositoryWriteCount(calls []string) int {
	count := 0
	for _, endpoint := range calls {
		switch endpoint {
		case "com.atproto.repo.applyWrites", "com.atproto.repo.uploadBlob", "com.atproto.repo.createRecord", "com.atproto.repo.putRecord", "com.atproto.repo.deleteRecord":
			count++
		}
	}
	return count
}
