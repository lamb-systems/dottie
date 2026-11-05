package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	dottiecli "github.com/lamb-systems/dottie/internal/cli"
	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const restoreMilestoneFileTargetID = publicationAuditFileTargetID

const restoreMilestoneFileBytes = "incumbent file bytes\n"

const restoreMilestoneFileName = "prefs/private-profile.toml"

type restoreMilestoneHome struct {
	paths       platform.Paths
	store       *state.Store
	keyring     *publicationKeyring
	settings    *restoreMilestoneSettings
	coordinator *service.Coordinator
}

type restoreMilestoneSettings struct {
	values map[model.EntryKey]syncengine.SettingValue
}

type restoreMilestoneApplyCall struct {
	body []byte
}

type restoreMilestoneRecordingTransport struct {
	base  atproto.Transport
	mu    sync.Mutex
	calls []restoreMilestoneApplyCall
}

type restoreMilestoneRemoteFactory func(*state.Store) service.RemoteReadPort

type restoreMilestoneReadOverride struct {
	result atproto.ReadResult
}

func (remote restoreMilestoneReadOverride) Read(context.Context, atproto.ReadRequest) (atproto.ReadResult, error) {
	return remote.result, nil
}

type restoreMilestoneControlEvidence struct {
	Control      string   `json:"control"`
	Policy       string   `json:"policy"`
	Certificates []string `json:"certificates"`
}

type restoreMilestoneVerifyBundle struct {
	Vault         string                            `json:"vault"`
	Held          *restoreMilestoneControlEvidence  `json:"held,omitempty"`
	Supplied      restoreMilestoneControlEvidence   `json:"supplied"`
	Intermediates []restoreMilestoneControlEvidence `json:"intermediates,omitempty"`
}

func TestRestoreMilestoneOfflineTwoHomeAndRecovery(t *testing.T) {
	ctx := context.Background()
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationAuditDID, repositoryKey)
	require.NoError(t, err)
	recorded := &restoreMilestoneRecordingTransport{base: pds}
	reader := publicationAuditReader(pds, publicationAuditDID)
	publisher := newPublicationFixtureWithTransport(t, recorded, reader, publicationAuditDID, 1<<20, pds, repositoryKey, nil)
	recorded.resetApplyCalls()
	rootConfig, err := (service.FileConfigPort{Paths: publisher.paths}).Load(ctx)
	require.NoError(t, err)
	fileTarget := milestoneFileTarget(t, rootConfig)
	require.NoError(t, os.WriteFile(publisher.filePath, []byte(restoreMilestoneFileBytes), 0o600))
	settingsTarget := milestoneSettingsTarget(t, rootConfig)
	incumbentSettings, expectedSettings := newRestoreMilestoneSettings(t, settingsTarget, "'"+publisher.settings.settingCanary+"'")
	publisher.coordinator = newRestoreMilestonePublisherCoordinator(t, publisher, recorded, incumbentSettings)

	publication, err := publisher.coordinator.Push(ctx, publisher.selection)
	require.NoError(t, err)
	require.Equal(t, service.StatusCommitted, publication.Status)
	assert.False(t, publication.NoOp)
	require.Len(t, recorded.applyCalls(), 1)
	assertRestoreMilestoneSingleBatch(t, recorded.applyCalls()[0])
	rootRead, err := publisher.coordinator.Pull(ctx, publisher.selection)
	require.NoError(t, err)
	assert.Equal(t, []byte(restoreMilestoneFileBytes), restoreMilestoneSnapshotFile(t, rootRead.Snapshot, fileTarget.ID))
	for key, value := range expectedSettings {
		assert.Equal(t, value, restoreMilestoneSnapshotSetting(t, rootRead.Snapshot, key))
	}
	assertRestoreMilestoneOrdering(t, publisher, rootRead.Read.Ciphertext)
	stalePolicyDigest := restoreMilestonePolicyDigest(t, publisher.store, publisher.genesis.Vault, 0)
	staleEvidence, err := publisher.store.AuthenticatedPositionEvidence(ctx, publisher.genesis.Vault, 0, stalePolicyDigest)
	require.NoError(t, err)

	newcomerDevice, publicDevice := restoreMilestoneNewDevice(t, "restore-milestone-newcomer")
	approval := vault.EnrollmentTranscriptFingerprint(
		publisher.genesis.Vault, publicDevice.DeviceID, publicDevice.KeyID, vault.RoleRestoreOnly,
		publicDevice.SigningPublicKey, publicDevice.RecipientPublicKey,
	)
	enrollment, err := publisher.coordinator.Enroll(ctx, service.EnrollRequest{
		Selection: publisher.selection, Device: publicDevice, Role: vault.RoleRestoreOnly,
		ApprovalFingerprint: approval, Kit: publisher.kit,
	})
	require.NoError(t, err)
	require.Equal(t, service.StatusCommitted, enrollment.Status)
	require.NotEmpty(t, enrollment.EncodedBundle)

	newcomer := newRestoreMilestoneHome(t, "newcomer", rootConfig, newcomerDevice, func(store *state.Store) service.RemoteReadPort {
		return service.VaultReader{Reader: atproto.VaultReader{
			Transport: recorded, ObservationStore: store, Clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
		}}
	}, publisher.did, publisher.reader.VerificationMethods)
	selection := service.VaultSelection{Vault: publisher.genesis.Vault, DeviceID: newcomerDevice.DeviceID}
	require.NoError(t, newcomer.coordinator.ImportOnboarding(ctx, enrollment.EncodedBundle, publisher.genesis.Vault, publisher.genesis.Anchor, newcomerDevice.DeviceID))
	newcomerRead, err := newcomer.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), newcomerRead.Read.EpochSeq)
	assert.Equal(t, vault.CheckpointCurrent, newcomerRead.Currency.Outcome)

	newcomerFileRoot, err := fileTarget.ResolvedPath(newcomer.paths)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(newcomerFileRoot, restoreMilestoneFileName)), 0o700))
	newcomerFile := filepath.Join(newcomerFileRoot, restoreMilestoneFileName)
	fileCandidate, err := newcomer.coordinator.Preview(ctx, selection, fileTarget.ID)
	require.NoError(t, err)
	require.True(t, fileCandidate.Preview.Complete)
	require.Len(t, fileCandidate.Actions, 1)
	_, err = newcomer.coordinator.Restore(ctx, service.RestoreRequest{Selection: selection, TargetID: fileTarget.ID})
	require.ErrorIs(t, err, service.ErrCandidateChanged)
	_, statErr := os.Stat(newcomerFile)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "review-mode restore without its candidate digest must not apply the file")
	fileRestore, err := newcomer.coordinator.Restore(ctx, service.RestoreRequest{
		Selection: selection, TargetID: fileTarget.ID, Confirm: fileCandidate.Digest,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, fileRestore.Applied)
	assert.Equal(t, []byte(restoreMilestoneFileBytes), restoreMilestoneReadFile(t, newcomerFile))

	settingsCandidate, err := newcomer.coordinator.Preview(ctx, selection, settingsTarget.ID)
	require.NoError(t, err)
	require.True(t, settingsCandidate.Preview.Complete)
	require.Len(t, settingsCandidate.Actions, len(expectedSettings))
	settingsRestore, err := newcomer.coordinator.Restore(ctx, service.RestoreRequest{
		Selection: selection, TargetID: settingsTarget.ID, Confirm: settingsCandidate.Digest,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, settingsRestore.Applied)
	for key, value := range expectedSettings {
		assert.Equal(t, value, newcomer.settings.values[key].Text)
		assert.True(t, newcomer.settings.values[key].Present)
	}

	fileNoOpCandidate, err := newcomer.coordinator.Preview(ctx, selection, fileTarget.ID)
	require.NoError(t, err)
	assert.Empty(t, fileNoOpCandidate.Actions)
	fileNoOp, err := newcomer.coordinator.Restore(ctx, service.RestoreRequest{
		Selection: selection, TargetID: fileTarget.ID, Confirm: fileNoOpCandidate.Digest,
	})
	require.NoError(t, err)
	assert.True(t, fileNoOp.NoActions)
	settingsNoOpCandidate, err := newcomer.coordinator.Preview(ctx, selection, settingsTarget.ID)
	require.NoError(t, err)
	assert.Empty(t, settingsNoOpCandidate.Actions)
	settingsNoOp, err := newcomer.coordinator.Restore(ctx, service.RestoreRequest{
		Selection: selection, TargetID: settingsTarget.ID, Confirm: settingsNoOpCandidate.Digest,
	})
	require.NoError(t, err)
	assert.True(t, settingsNoOp.NoActions)

	for index := 2; index <= 3; index++ {
		device, public := restoreMilestoneNewDevice(t, "restore-milestone-advance-"+strconv.Itoa(index))
		approval := vault.EnrollmentTranscriptFingerprint(
			publisher.genesis.Vault, public.DeviceID, public.KeyID, vault.RoleRestoreOnly,
			public.SigningPublicKey, public.RecipientPublicKey,
		)
		result, enrollErr := publisher.coordinator.Enroll(ctx, service.EnrollRequest{
			Selection: publisher.selection, Device: public, Role: vault.RoleRestoreOnly,
			ApprovalFingerprint: approval, Kit: publisher.kit,
		})
		require.NoError(t, enrollErr)
		assert.Equal(t, service.StatusCommitted, result.Status)
		assert.NotEmpty(t, device.DeviceID)
	}
	checkpoint, err := publisher.store.VaultCheckpoint(ctx, publisher.genesis.Vault)
	require.NoError(t, err)
	require.Equal(t, uint64(3), checkpoint.Epoch)
	finalRootRead, err := publisher.coordinator.Pull(ctx, publisher.selection)
	require.NoError(t, err)
	for key, value := range expectedSettings {
		assert.Equal(t, value, restoreMilestoneSnapshotSetting(t, finalRootRead.Snapshot, key))
	}
	position2 := restoreMilestoneEvidenceAtEpoch(t, publisher.store, publisher.genesis.Vault, 2)
	position3, err := publisher.store.AuthenticatedPositionEvidence(ctx, publisher.genesis.Vault, 3, checkpoint.PolicyDigest)
	require.NoError(t, err)
	inspection := newRestoreMilestoneHome(t, "inspection", rootConfig, publisher.root,
		func(*state.Store) service.RemoteReadPort { return restoreMilestoneReadOverride{result: rootRead.Read} }, publisher.did, publisher.reader.VerificationMethods)
	require.NoError(t, inspection.store.PutVaultSelection(ctx, state.VaultSelection{
		Vault: publisher.genesis.Vault, DeviceID: publisher.root.DeviceID, RecordedAt: 1_800_000_000,
	}))
	require.NoError(t, inspection.store.PutVaultCheckpoint(ctx, checkpoint))
	require.NoError(t, inspection.store.PutAuthenticatedPositionEvidence(ctx, position2))
	require.NoError(t, inspection.store.PutAuthenticatedPositionEvidence(ctx, position3))
	inspectionSelection := service.VaultSelection{Vault: publisher.genesis.Vault, DeviceID: publisher.root.DeviceID}
	inspectionRead, err := inspection.coordinator.Pull(ctx, inspectionSelection)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), inspectionRead.Read.EpochSeq)
	assert.Equal(t, uint64(3), checkpoint.Epoch)
	assert.Equal(t, vault.CheckpointUnverifiable, inspectionRead.Currency.Outcome)
	assert.True(t, inspectionRead.InspectOnly)
	inspectionCandidate, err := inspection.coordinator.Preview(ctx, inspectionSelection, fileTarget.ID)
	require.NoError(t, err)
	assert.Equal(t, vault.CheckpointUnverifiable, inspectionCandidate.Currency)
	assert.True(t, inspectionCandidate.InspectOnly)
	assert.Equal(t, atproto.FreshnessUnverified, inspectionCandidate.Freshness)
	_, statErr = os.Stat(filepath.Join(milestoneTargetRoot(t, fileTarget, inspection.paths), restoreMilestoneFileName))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	beforeInspectionSettings := len(inspection.settings.values)
	beforeInspectionJournal, err := inspection.store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	_, err = inspection.coordinator.Restore(ctx, service.RestoreRequest{Selection: inspectionSelection, TargetID: fileTarget.ID})
	require.ErrorIs(t, err, service.ErrFreshnessUnverified)
	_, statErr = os.Stat(filepath.Join(milestoneTargetRoot(t, fileTarget, inspection.paths), restoreMilestoneFileName))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	assert.Equal(t, beforeInspectionSettings, len(inspection.settings.values))
	afterInspectionJournal, err := inspection.store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, beforeInspectionJournal, afterInspectionJournal)

	position0 := staleEvidence
	position0Doc := restoreMilestoneEvidenceDocument(position0)
	position2Doc := restoreMilestoneEvidenceDocument(position2)
	position3Doc := restoreMilestoneEvidenceDocument(position3)
	verifyBundle, err := json.Marshal(restoreMilestoneVerifyBundle{
		Vault: hex.EncodeToString(publisher.genesis.Vault[:]), Held: &position3Doc,
		Supplied: position0Doc, Intermediates: []restoreMilestoneControlEvidence{position2Doc},
	})
	require.NoError(t, err)
	verifyBundlePath := filepath.Join(inspection.paths.CacheHome, "unverifiable-verification.json")
	require.NoError(t, os.WriteFile(verifyBundlePath, verifyBundle, 0o600))
	consentCode, consentOutput, consentError := runRestoreMilestoneConsentCLI(t, inspection, verifyBundlePath)
	assert.Equal(t, 0, consentCode)
	assert.Empty(t, consentError)
	assert.Contains(t, consentOutput, "outcome: unverifiable")
	assert.Contains(t, consentOutput, "consent recorded for this verification; no data was applied and the checkpoint was not advanced")
	inspection.coordinator, err = service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: inspection.paths}, State: inspection.store, DeviceKeys: inspection.keyring,
		Trust:   service.StateTrustSource{State: inspection.store, Keyring: inspection.keyring},
		Session: publicationReadSession{did: publisher.did, methods: publisher.reader.VerificationMethods},
		Remote:  restoreMilestoneReadOverride{result: rootRead.Read}, Settings: inspection.settings, Paths: inspection.paths,
		Clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
	})
	require.NoError(t, err)
	consentedPreview, err := inspection.coordinator.Preview(ctx, inspectionSelection, fileTarget.ID)
	require.NoError(t, err)
	assert.Equal(t, vault.CheckpointUnverifiable, consentedPreview.Currency)
	_, statErr = os.Stat(filepath.Join(milestoneTargetRoot(t, fileTarget, inspection.paths), restoreMilestoneFileName))
	assert.ErrorIs(t, statErr, os.ErrNotExist, "consented inspection leaves local files unapplied")
	assert.Empty(t, inspection.settings.values, "consented inspection leaves local settings unapplied")
	inspectionJournal, err := inspection.store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, inspectionJournal, "consented inspection creates no apply journal")

	archivePath := filepath.Join(publisher.paths.CacheHome, "restore-milestone.dtv")
	archive, err := publisher.coordinator.Export(ctx, service.ExportRequest{
		Selection: publisher.selection, ExpectedVault: publisher.genesis.Vault, ExpectedAnchor: publisher.genesis.Anchor,
		Kit: publisher.kit, Path: archivePath,
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), archive.CurrentEpoch)
	inspectedArchive, err := inspection.coordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: publisher.genesis.Vault, ExpectedAnchor: publisher.genesis.Anchor, Kit: publisher.kit,
	})
	require.NoError(t, err)
	assert.Equal(t, archive.CurrentEpoch, inspectedArchive.CurrentEpoch)
	archiveHome := newRestoreMilestoneHome(t, "archive-rollback", rootConfig, newcomerDevice, nil, "", nil)
	archiveSelection := service.VaultSelection{Vault: publisher.genesis.Vault, DeviceID: newcomerDevice.DeviceID}
	require.NoError(t, archiveHome.store.PutVaultSelection(ctx, state.VaultSelection{
		Vault: publisher.genesis.Vault, DeviceID: newcomerDevice.DeviceID, RecordedAt: 1_800_000_000,
	}))
	destroyPublicationSource(t, publisher)
	assert.Empty(t, publisher.pds.CurrentRevision().Records)
	assert.Empty(t, publisher.pds.StoredBlobCIDs())
	archiveFile := filepath.Join(milestoneTargetRoot(t, fileTarget, archiveHome.paths), restoreMilestoneFileName)
	archiveRequest := service.ArchiveRestoreRequest{
		Selection: archiveSelection, Path: archivePath, Anchor: publisher.genesis.Anchor, Kit: publisher.kit, TargetID: fileTarget.ID,
	}
	archiveRefusal, err := archiveHome.coordinator.RestoreFromArchive(ctx, archiveRequest)
	require.ErrorIs(t, err, service.ErrCandidateChanged)
	_, statErr = os.Stat(archiveFile)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	archiveRequest.Confirm = archiveRefusal.CandidateDigest
	archiveRestore, err := archiveHome.coordinator.RestoreFromArchive(ctx, archiveRequest)
	require.NoError(t, err)
	assert.Equal(t, "archive", archiveRestore.Source)
	assert.False(t, archiveRestore.ProviderContacted)
	assert.NotEmpty(t, archiveRestore.Applied)
	assert.Equal(t, []byte(restoreMilestoneFileBytes), restoreMilestoneReadFile(t, archiveFile))
	newerEdit := []byte("newer local edit survives rollback\n")
	require.NoError(t, os.WriteFile(archiveFile, newerEdit, 0o600))
	rollback, err := syncengine.RollbackAppliedWithSettings(ctx, archiveHome.store, nil, archiveHome.settings, func() time.Time { return time.Unix(1_800_000_000, 0) })
	require.NoError(t, err)
	var preserved *syncengine.JournalResult
	for index := range rollback.Entries {
		result := &rollback.Entries[index]
		if result.Key.Source == model.SourceFiles && result.Key.FilePath == restoreMilestoneFileName {
			preserved = result
		}
	}
	require.NotNil(t, preserved)
	assert.Equal(t, "skipped-newer-edit", preserved.Outcome)
	assert.Equal(t, newerEdit, restoreMilestoneReadFile(t, archiveFile))
	journalAfterConsent, err := inspection.store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, journalAfterConsent, "the consented account verification path has no apply effects")
}

func (transport *restoreMilestoneRecordingTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" {
		transport.mu.Lock()
		transport.calls = append(transport.calls, restoreMilestoneApplyCall{body: bytes.Clone(body)})
		transport.mu.Unlock()
	}
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport *restoreMilestoneRecordingTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return transport.base.OpenStream(ctx, endpoint, query)
}

func (transport *restoreMilestoneRecordingTransport) resetApplyCalls() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.calls = nil
}

func (transport *restoreMilestoneRecordingTransport) applyCalls() []restoreMilestoneApplyCall {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	calls := make([]restoreMilestoneApplyCall, len(transport.calls))
	for index, call := range transport.calls {
		calls[index] = restoreMilestoneApplyCall{body: bytes.Clone(call.body)}
	}
	return calls
}

func assertRestoreMilestoneSingleBatch(t *testing.T, call restoreMilestoneApplyCall) {
	t.Helper()
	var request struct {
		SwapCommit string            `json:"swapCommit"`
		Writes     []json.RawMessage `json:"writes"`
	}
	require.NoError(t, json.Unmarshal(call.body, &request))
	assert.NotEmpty(t, request.SwapCommit)
	assert.NotEmpty(t, request.Writes)
}

func assertRestoreMilestoneOrdering(t *testing.T, fixture *publicationFixture, currentBlob []byte) {
	t.Helper()
	headRecord, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	decodedHead, err := atproto.DecodeRecord(headRecord.Data)
	require.NoError(t, err)
	head, ok := decodedHead.(atproto.HeadRecord)
	require.True(t, ok)
	require.NotEmpty(t, head.SnapshotCID)
	assert.Equal(t, head.SnapshotCID, head.BlobCID)
	matchingSnapshots := make([]atproto.SnapshotRecord, 0, 1)
	snapshotCount := 0
	for _, record := range fixture.pds.CurrentRevision().Records {
		if record.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		descriptor, decodeErr := atproto.DecodeRecord(record.Data)
		require.NoError(t, decodeErr)
		snapshot, ok := descriptor.(atproto.SnapshotRecord)
		require.True(t, ok)
		snapshotCount++
		if bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), head.SnapshotCID) {
			matchingSnapshots = append(matchingSnapshots, snapshot)
		}
	}
	require.Len(t, matchingSnapshots, 1, "the current head resolves to exactly one snapshot record")
	assert.Greater(t, snapshotCount, 1, "historical snapshot records remain lineage and are not classified as orphans")
	current := matchingSnapshots[0]
	blobCID := current.Blob.Ref.CID()
	assert.Equal(t, head.SnapshotCID, blobCID.Bytes())
	assert.Equal(t, head.BlobCID, blobCID.Bytes())
	status, stream, err := fixture.pds.OpenStream(context.Background(), "com.atproto.sync.getBlob", url.Values{
		"did": {fixture.did}, "cid": {blobCID.String()},
	})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.NotNil(t, stream)
	blob, err := io.ReadAll(stream)
	closeErr := stream.Close()
	require.NoError(t, err)
	require.NoError(t, closeErr)
	assert.Equal(t, currentBlob, blob)
	assert.Equal(t, int64(len(blob)), current.Blob.Size)
	assert.True(t, fixture.pds.PubliclyRetrievable(blobCID.String()))
}

func newRestoreMilestoneHome(t *testing.T, name string, configuration config.Config, device vault.DeviceMaterial, remoteFactory restoreMilestoneRemoteFactory, did string, methods []atproto.VerificationMethod) *restoreMilestoneHome {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"),
		DataHome: filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	require.NoError(t, config.Save(paths, configuration))
	store, err := state.Open(paths)
	require.NoError(t, err)
	home := &restoreMilestoneHome{
		paths: paths, store: store, keyring: &publicationKeyring{devices: map[string]vault.DeviceMaterial{device.DeviceID: device}},
		settings: &restoreMilestoneSettings{values: make(map[model.EntryKey]syncengine.SettingValue)},
	}
	t.Cleanup(func() {
		if home.store != nil {
			assert.NoError(t, home.store.Close())
		}
	})
	for _, target := range configuration.Targets {
		descriptor := state.TargetDescriptor{ID: target.ID, Version: 1, Source: target.Source, SourceVersion: model.SourceVersion, Mode: string(target.Mode), CreatedAt: 1}
		if target.Root != nil {
			descriptor.LogicalBase = target.Root.Base
			descriptor.LogicalPath = target.Root.Path
			descriptor.Kind = target.Root.Kind
			resolved, resolveErr := target.ResolvedPath(paths)
			require.NoError(t, resolveErr)
			require.NoError(t, os.MkdirAll(resolved, 0o700))
			if target.ID == restoreMilestoneFileTargetID {
				require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(resolved, restoreMilestoneFileName)), 0o700))
			}
		}
		require.NoError(t, store.PutTarget(context.Background(), descriptor))
	}
	dependencies := service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, DeviceKeys: home.keyring,
		Settings: home.settings, Paths: paths, Clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
	if remoteFactory != nil {
		dependencies.Trust = service.StateTrustSource{State: store, Keyring: home.keyring}
		dependencies.Session = publicationReadSession{did: did, methods: methods}
		dependencies.Remote = remoteFactory(store)
	}
	home.coordinator, err = service.NewCoordinator(dependencies)
	require.NoError(t, err)
	return home
}

func (settings *restoreMilestoneSettings) Resolve(context.Context, string, string, string) (string, error) {
	return "/", nil
}

func (settings *restoreMilestoneSettings) Capture(_ context.Context, targetID string, refs []service.SettingRef) (service.SettingsCapture, error) {
	capture := service.SettingsCapture{}
	for _, ref := range refs {
		key := model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}
		value, exists := settings.values[key]
		if !exists || !value.Present {
			continue
		}
		capture.Entries = append(capture.Entries, model.Entry{TargetID: targetID, Setting: &model.SettingEntry{
			SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key, State: model.SettingPresent,
			Value: &model.VariantValue{Type: value.Type, Text: value.Text},
		}})
	}
	return capture, nil
}

func (settings *restoreMilestoneSettings) Backend() syncengine.SettingsBackend { return settings }

func (settings *restoreMilestoneSettings) Observe(_ context.Context, key model.EntryKey) (syncengine.SettingValue, error) {
	value, exists := settings.values[key]
	if !exists {
		return syncengine.SettingValue{Writable: true}, nil
	}
	value.Writable = true
	return value, nil
}

func (*restoreMilestoneSettings) Canonicalize(_ context.Context, _ model.EntryKey, valueType, text string) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{Present: true, Type: valueType, Text: text, Writable: true}, nil
}

func (settings *restoreMilestoneSettings) Set(_ context.Context, key model.EntryKey, valueType, text string) error {
	settings.values[key] = syncengine.SettingValue{Present: true, Type: valueType, Text: text, Writable: true}
	return nil
}

func (settings *restoreMilestoneSettings) Reset(_ context.Context, key model.EntryKey) error {
	delete(settings.values, key)
	return nil
}

func milestoneFileTarget(t *testing.T, configuration config.Config) config.Target {
	t.Helper()
	for _, target := range configuration.Targets {
		if target.ID == restoreMilestoneFileTargetID {
			return target
		}
	}
	require.FailNow(t, "publication fixture file target is missing")
	return config.Target{}
}

func milestoneSettingsTarget(t *testing.T, configuration config.Config) config.Target {
	t.Helper()
	for _, target := range configuration.Targets {
		if target.ID == publicationAuditSettingsTargetID {
			return target
		}
	}
	require.FailNow(t, "publication fixture settings target is missing")
	return config.Target{}
}

func newRestoreMilestoneSettings(t *testing.T, target config.Target, firstText string) (*restoreMilestoneSettings, map[model.EntryKey]string) {
	t.Helper()
	keys, err := matrix.SelectCategories(target.GNOMEPolicy.Categories)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(keys), 2)
	settings := &restoreMilestoneSettings{values: make(map[model.EntryKey]syncengine.SettingValue)}
	expected := make(map[model.EntryKey]string, 2)
	for index, key := range keys[:2] {
		text := firstText
		if index == 1 {
			text = "'Incumbent-" + key.Key + "'"
		}
		identity := model.EntryKey{TargetID: target.ID, Source: model.SourceGNOME, SchemaID: key.SchemaID, SettingsPath: "/", SettingKey: key.Key}
		settings.values[identity] = syncengine.SettingValue{Present: true, Type: "s", Text: text, Writable: true}
		expected[identity] = text
	}
	return settings, expected
}

func newRestoreMilestonePublisherCoordinator(t *testing.T, fixture *publicationFixture, transport atproto.Transport, settings *restoreMilestoneSettings) *service.Coordinator {
	t.Helper()
	clock := func() time.Time { return time.Unix(1_800_000_000, 0) }
	publication := atproto.ATProtoPublicationIO{
		Reader: fixture.reader, Transport: transport, BlobUploadLimit: fixture.blobLimit, DID: fixture.did,
		TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store, Clock: clock,
	}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: fixture.paths}, State: fixture.store, DeviceKeys: fixture.keyring,
		Trust:     service.StateTrustSource{State: fixture.store, Keyring: fixture.keyring},
		Session:   publicationReadSession{did: fixture.did, methods: fixture.reader.VerificationMethods},
		Remote:    service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: fixture.store, Clock: clock}},
		Publisher: publicationPublisher{io: publication}, Settings: settings, Paths: fixture.paths, Clock: clock,
	})
	require.NoError(t, err)
	return coordinator
}

func restoreMilestoneNewDevice(t *testing.T, deviceID string) (vault.DeviceMaterial, vault.PublicDeviceInput) {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	publicKey := bytes.Clone(signing.Public().(ed25519.PublicKey))
	device := vault.DeviceMaterial{DeviceID: deviceID, KeyID: bytes.Clone(publicKey), Signing: signing, Recipient: recipient}
	public := vault.PublicDeviceInput{
		DeviceID: deviceID, KeyID: bytes.Clone(publicKey), SigningPublicKey: publicKey,
		RecipientPublicKey: bytes.Clone(recipient.PublicKey().Bytes()),
	}
	return device, public
}

func restoreMilestoneSnapshotFile(t *testing.T, snapshot model.Snapshot, targetID string) []byte {
	t.Helper()
	for _, entry := range snapshot.Entries {
		if entry.TargetID == targetID && entry.File != nil && entry.File.Path == restoreMilestoneFileName {
			return bytes.Clone(entry.File.Content)
		}
	}
	require.FailNow(t, "published snapshot does not contain the milestone file")
	return nil
}

func restoreMilestoneSnapshotSetting(t *testing.T, snapshot model.Snapshot, key model.EntryKey) string {
	t.Helper()
	for _, entry := range snapshot.Entries {
		if entry.Identity() == key && entry.Setting != nil {
			return entry.Setting.Value.Text
		}
	}
	require.FailNow(t, "published snapshot does not contain setting %s", key.SettingKey)
	return ""
}

func restoreMilestoneReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func milestoneTargetRoot(t *testing.T, target config.Target, paths platform.Paths) string {
	t.Helper()
	root, err := target.ResolvedPath(paths)
	require.NoError(t, err)
	return root
}

func restoreMilestonePolicyDigest(t *testing.T, store *state.Store, vaultID [32]byte, epoch uint64) [32]byte {
	t.Helper()
	positions, err := store.AuthenticatedPositionHistory(context.Background(), vaultID)
	require.NoError(t, err)
	for _, position := range positions {
		if position.Epoch == epoch {
			return position.PolicyDigest
		}
	}
	require.FailNow(t, "authenticated position for epoch %d is missing", epoch)
	return [32]byte{}
}

func restoreMilestoneEvidenceAtEpoch(t *testing.T, store *state.Store, vaultID [32]byte, epoch uint64) state.AuthenticatedPositionEvidence {
	t.Helper()
	digest := restoreMilestonePolicyDigest(t, store, vaultID, epoch)
	position, err := store.AuthenticatedPositionEvidence(context.Background(), vaultID, epoch, digest)
	require.NoError(t, err)
	return position
}

func restoreMilestoneEvidenceDocument(position state.AuthenticatedPositionEvidence) restoreMilestoneControlEvidence {
	document := restoreMilestoneControlEvidence{Control: hex.EncodeToString(position.Control), Policy: hex.EncodeToString(position.Policy)}
	for _, certificate := range position.Certificates {
		document.Certificates = append(document.Certificates, hex.EncodeToString(certificate))
	}
	return document
}

func runRestoreMilestoneConsentCLI(t *testing.T, home *restoreMilestoneHome, bundlePath string) (int, string, string) {
	t.Helper()
	if home.store != nil {
		require.NoError(t, home.store.Close())
		home.store = nil
	}
	t.Setenv("HOME", home.paths.Home)
	t.Setenv("XDG_CONFIG_HOME", home.paths.ConfigHome)
	t.Setenv("XDG_STATE_HOME", home.paths.StateHome)
	t.Setenv("XDG_CACHE_HOME", home.paths.CacheHome)
	t.Setenv("XDG_DATA_HOME", home.paths.DataHome)
	var stdout, stderr bytes.Buffer
	code := dottiecli.Run([]string{"account", "verify", "--bundle", bundlePath, "--consent"}, &stdout, &stderr)
	home.store = closeAndReopenMilestoneStore(t, home)
	home.coordinator = nil
	return code, stdout.String(), stderr.String()
}

func closeAndReopenMilestoneStore(t *testing.T, home *restoreMilestoneHome) *state.Store {
	t.Helper()
	if home.store != nil {
		require.NoError(t, home.store.Close())
	}
	store, err := state.Open(home.paths)
	require.NoError(t, err)
	return store
}
