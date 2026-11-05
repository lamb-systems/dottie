//go:build linux && cgo

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type restoreMilestoneLiveArtifact struct {
	Outcome        string         `json:"outcome"`
	Counts         map[string]int `json:"counts"`
	PositionEpoch  uint64         `json:"position_epoch"`
	ContentMatched bool           `json:"content_matched"`
	StandingLimits []string       `json:"standing_limits"`
}

type restoreMilestoneLiveWrite struct {
	Endpoint string
	Body     []byte
	Response []byte
}

type restoreMilestoneLiveTransport struct {
	base   atproto.Transport
	mu     sync.Mutex
	writes []restoreMilestoneLiveWrite
}

func TestLiveRestoreMilestoneTwoHome(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_MILESTONE") != "1" {
		t.Skip("set DOTTIE_LIVE_MILESTONE=1, an allowlisted DOTTIE_HANDLE, and DOTTIE_RECOVERY_KIT_FILE only after explicit disposable-account authorization; skipped live tests are not evidence")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if !allowedPDSHandle(handle) {
		require.True(t, allowedPDSHandle(handle), "DOTTIE_HANDLE is not in the live disposable-identity allowlist")
	}
	kitPath := os.Getenv("DOTTIE_RECOVERY_KIT_FILE")
	require.NotEmpty(t, kitPath, "DOTTIE_RECOVERY_KIT_FILE is required for the authorized live milestone")

	artifactDir := liveArtifactDir(t)
	artifact := restoreMilestoneLiveArtifact{
		Outcome: "in-progress", Counts: map[string]int{}, StandingLimits: []string{
			"Only synthetic files and settings in temporary homes are applied; the pre-existing local vault selection, checkpoint, authenticated evidence, Secret Service device key, account session, live PDS and operator-supplied kit are used as authorization inputs.",
			"The live run does not call genesis or delete records; published records and uploaded ciphertext blobs remain on the provider, including an enrollment for an ephemeral test device whose private key is not retained.",
			"Same-host kit availability is not independent custody; the kit authorizes recovery but cannot decrypt content.",
			"Archive restore, which this live gate does not exercise, is limited to the kit-signed checkpoint and may not be newest; remote reads cannot establish global freshness, and provider logs and server-side retention are unobservable.",
		},
	}
	var transport *restoreMilestoneLiveTransport
	defer func() {
		if t.Failed() {
			artifact.Outcome = "failed"
		} else {
			artifact.Outcome = "passed"
		}
		if transport != nil {
			for _, write := range transport.writeCalls() {
				artifact.Counts["write_endpoint_"+write.Endpoint]++
			}
		}
		assert.NoError(t, writeRestoreMilestoneLiveArtifact(artifactDir, artifact))
	}()

	kit, err := readArchiveRecoveryKit(kitPath)
	require.True(t, err == nil, "DOTTIE_RECOVERY_KIT_FILE must be a private regular file containing exactly 32 kit bytes")
	defer clear(kit)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	operatorPaths, err := platform.Resolve(os.Getenv)
	require.True(t, err == nil, "operator XDG paths could not be resolved")
	localStatePath := filepath.Join(operatorPaths.AppStateDir(), "state.db")
	localStateInfo, err := os.Lstat(localStatePath)
	require.True(t, err == nil && localStateInfo.Mode().IsRegular(), "an existing Dottie state database is required; the live gate will not create or bootstrap local trust")
	localStore, err := state.Open(operatorPaths)
	require.True(t, err == nil, "existing Dottie state could not be opened; details redacted")
	defer func() { assert.NoError(t, localStore.Close()) }()
	selections, err := localStore.VaultSelectionsBounded(ctx, 2)
	require.True(t, err == nil && len(selections) == 1, "the live gate requires exactly one existing local vault selection")
	localSelection := selections[0]
	checkpoint, err := localStore.VaultCheckpoint(ctx, localSelection.Vault)
	require.True(t, err == nil, "the selected vault must have a local trust checkpoint")
	positionHistory, err := localStore.AuthenticatedPositionHistory(ctx, localSelection.Vault)
	require.True(t, err == nil && len(positionHistory) > 0, "authenticated predecessor history is required")
	checkpointEvidence, err := localStore.AuthenticatedPositionEvidence(ctx, localSelection.Vault, checkpoint.Epoch, checkpoint.PolicyDigest)
	require.True(t, err == nil, "authenticated evidence for the held checkpoint is required")
	require.True(t, kitAuthorizesHeldCheckpoint(kit, localSelection.Vault, checkpoint, checkpointEvidence) == nil, "the supplied kit must authenticate the selected checkpoint before any repository write")

	keyring, err := platform.NewKeyring()
	require.True(t, err == nil, "Secret Service keyring could not be opened; details redacted")
	defer func() { assert.NoError(t, keyring.Close()) }()
	rootDevice, err := keyring.LoadDeviceKeys(ctx, localSelection.Vault, localSelection.DeviceID)
	require.True(t, err == nil && rootDevice.DeviceID == localSelection.DeviceID, "the selected incumbent device key must survive in Secret Service")

	client, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	require.True(t, err == nil, "account client could not be created")
	identity, err := client.Discover(ctx, handle)
	require.True(t, err == nil && identity.DID != "", "allowlisted identity discovery failed; details redacted")
	session, err := client.LoadSession(ctx, identity.DID)
	require.True(t, err == nil, "an authorized account session is required")
	auth, err := atproto.NewAuthMethod(client, identity, handle, session)
	require.True(t, err == nil, "authenticated PDS access could not be initialized")
	authenticatedAPI, err := newPDSAPIClient(identity.PDS, auth, nil)
	require.True(t, err == nil, "authenticated PDS client could not be created")
	anonymousAPI, err := newPDSAPIClient(identity.PDS, nil, nil)
	require.True(t, err == nil, "PDS preflight client could not be created")
	blobLimit, knownLimit, described := describePDS(t, ctx, pdsProviderName(handle), identity.PDS, anonymousAPI)
	require.True(t, described && knownLimit && blobLimit > 0, "the live PDS must advertise a usable blob upload limit")
	transport = &restoreMilestoneLiveTransport{base: atproto.NewATClientTransport(authenticatedAPI)}
	reader := atproto.RevisionReader{
		Transport: transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), identity.VerificationMethods...),
	}
	clock := time.Now

	rootConfig := liveRestoreMilestoneConfig(t)
	rootHome := newRestoreMilestoneHome(t, "live-incumbent", rootConfig, rootDevice, func(store *state.Store) service.RemoteReadPort {
		return service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: clock}}
	}, identity.DID, identity.VerificationMethods)
	seedRestoreMilestoneLiveTrust(t, rootHome.store, localSelection, checkpoint, checkpointEvidence, positionHistory)
	fileTarget := milestoneFileTarget(t, rootConfig)
	settingsTarget := milestoneSettingsTarget(t, rootConfig)
	fileBytes := []byte("Dottie synthetic live restore milestone file\n")
	fileRoot := milestoneTargetRoot(t, fileTarget, rootHome.paths)
	filePath := filepath.Join(fileRoot, restoreMilestoneFileName)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0o700))
	require.NoError(t, os.WriteFile(filePath, fileBytes, 0o600))
	settingsKeys, err := milestoneSettingsKeys(settingsTarget)
	require.NoError(t, err)
	settingIdentity := model.EntryKey{
		TargetID: settingsTarget.ID, Source: model.SourceGNOME, SchemaID: settingsKeys[0].SchemaID,
		SettingsPath: "/", SettingKey: settingsKeys[0].Key,
	}
	settingValue := "'Dottie-Synthetic-Live-Milestone'"
	rootHome.settings.values[settingIdentity] = syncengine.SettingValue{Present: true, Type: "s", Text: settingValue, Writable: true}
	rootCoordinator, err := newRestoreMilestoneLiveRootCoordinator(rootHome, transport, reader, identity, blobLimit, checkpoint.Anchor, clock)
	require.NoError(t, err)
	rootSelection := service.VaultSelection{Vault: localSelection.Vault, DeviceID: localSelection.DeviceID}

	preflight, err := rootCoordinator.Pull(ctx, rootSelection)
	require.True(t, err == nil, "the selected Dottie vault must already be readable on the live repository; refusing without genesis")
	require.Equal(t, localSelection.Vault[:], preflight.Read.Policy.Vault)
	require.Empty(t, preflight.Snapshot.Entries, "live restore gate refuses a repository containing any existing application content")
	rootRole := false
	for _, role := range preflight.Read.Policy.Roles {
		if role.DeviceID == rootDevice.DeviceID && vault.Role(role.Role) == vault.RoleRoot {
			rootRole = true
		}
	}
	require.True(t, rootRole, "the incumbent device must be a verified root before any live write")
	artifact.Counts["preflight_records"] = len(preflight.Read.Revision.Records())
	artifact.Counts["preflight_publication_count"] = int(preflight.Read.PublicationCount)

	publication, err := rootCoordinator.Push(ctx, rootSelection)
	require.True(t, err == nil, "synthetic incumbent publication failed; details redacted")
	require.Equal(t, service.StatusCommitted, publication.Status)
	assert.False(t, publication.NoOp)
	artifact.Counts["publication_writes"]++
	artifact.Counts["file_entries_published"] = 1
	artifact.Counts["settings_entries_published"] = 1

	newcomerDevice, publicDevice := restoreMilestoneNewDevice(t, "live-restore-milestone-newcomer")
	approval := vault.EnrollmentTranscriptFingerprint(
		localSelection.Vault, publicDevice.DeviceID, publicDevice.KeyID, vault.RoleRestoreOnly,
		publicDevice.SigningPublicKey, publicDevice.RecipientPublicKey,
	)
	enrollment, err := rootCoordinator.Enroll(ctx, service.EnrollRequest{
		Selection: rootSelection, Device: publicDevice, Role: vault.RoleRestoreOnly,
		ApprovalFingerprint: approval, Kit: kit,
	})
	require.True(t, err == nil, "root enrollment failed; details redacted")
	require.Equal(t, service.StatusCommitted, enrollment.Status)
	require.NotEmpty(t, enrollment.EncodedBundle)
	artifact.Counts["enrollment_writes"]++

	newcomer := newRestoreMilestoneHome(t, "live-newcomer", rootConfig, newcomerDevice, func(store *state.Store) service.RemoteReadPort {
		return service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: clock}}
	}, identity.DID, identity.VerificationMethods)
	newcomer.coordinator, err = service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: newcomer.paths}, State: newcomer.store, DeviceKeys: newcomer.keyring,
		Trust:    service.StateTrustSource{State: newcomer.store, Keyring: newcomer.keyring},
		Session:  archiveLiveReadSession{identity: identity},
		Remote:   service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: newcomer.store, Budgets: atproto.DefaultBudgets(), Clock: clock}},
		Settings: newcomer.settings, Paths: newcomer.paths, Clock: clock,
	})
	require.NoError(t, err)
	selection := service.VaultSelection{Vault: localSelection.Vault, DeviceID: newcomerDevice.DeviceID}
	require.NoError(t, newcomer.coordinator.ImportOnboarding(ctx, enrollment.EncodedBundle, localSelection.Vault, checkpoint.Anchor, newcomerDevice.DeviceID))
	pulled, err := newcomer.coordinator.Pull(ctx, selection)
	require.True(t, err == nil, "the blank newcomer could not authenticate the imported checkpoint and pull its successor")
	require.Equal(t, vault.CheckpointCurrent, pulled.Currency.Outcome)
	artifact.PositionEpoch = pulled.Read.EpochSeq

	newcomerFile, err := newcomer.coordinator.Preview(ctx, selection, fileTarget.ID)
	require.NoError(t, err)
	require.True(t, newcomerFile.Preview.Complete)
	artifact.Counts["file_preview_actions"] = len(newcomerFile.Actions)
	fileRestore, err := newcomer.coordinator.Restore(ctx, service.RestoreRequest{
		Selection: selection, TargetID: fileTarget.ID, Confirm: newcomerFile.Digest,
	})
	require.NoError(t, err)
	artifact.Counts["file_restore_applied"] = len(fileRestore.Applied)
	assert.Equal(t, fileBytes, restoreMilestoneReadFile(t, filepath.Join(milestoneTargetRoot(t, fileTarget, newcomer.paths), restoreMilestoneFileName)))

	newcomerSettings, err := newcomer.coordinator.Preview(ctx, selection, settingsTarget.ID)
	require.NoError(t, err)
	require.True(t, newcomerSettings.Preview.Complete)
	artifact.Counts["settings_preview_actions"] = len(newcomerSettings.Actions)
	settingsRestore, err := newcomer.coordinator.Restore(ctx, service.RestoreRequest{
		Selection: selection, TargetID: settingsTarget.ID, Confirm: newcomerSettings.Digest,
	})
	require.NoError(t, err)
	artifact.Counts["settings_restore_applied"] = len(settingsRestore.Applied)
	assert.Equal(t, settingValue, newcomer.settings.values[settingIdentity].Text)
	assert.True(t, newcomer.settings.values[settingIdentity].Present)
	artifact.ContentMatched = bytes.Equal(fileBytes, restoreMilestoneReadFile(t, filepath.Join(milestoneTargetRoot(t, fileTarget, newcomer.paths), restoreMilestoneFileName))) &&
		newcomer.settings.values[settingIdentity].Text == settingValue && newcomer.settings.values[settingIdentity].Present
	assert.True(t, artifact.ContentMatched)

	readBack, err := newcomer.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, pulled.Read.EpochSeq, readBack.Read.EpochSeq)
	assertRestoreMilestoneLiveOrdering(t, transport, readBack.Read)
	assertRestoreMilestoneLiveWriteBatches(t, transport.writeCalls())
	artifact.PositionEpoch = readBack.Read.EpochSeq
	artifact.Counts["current_repository_records"] = len(readBack.Read.Revision.Records())
	artifact.Counts["current_publication_count"] = int(readBack.Read.PublicationCount)
}

func liveRestoreMilestoneConfig(t *testing.T) config.Config {
	t.Helper()
	fileTarget, settingsTarget := publicationAuditTargets(t, restoreMilestoneFileTargetID, publicationAuditSettingsTargetID)
	configuration := config.Default()
	configuration.Targets = []config.Target{fileTarget, settingsTarget}
	return configuration
}

func seedRestoreMilestoneLiveTrust(t *testing.T, store *state.Store, selection state.VaultSelection, checkpoint state.VaultCheckpoint, checkpointEvidence state.AuthenticatedPositionEvidence, history []state.AuthenticatedPositionEvidence) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.PutVaultSelection(ctx, selection))
	require.NoError(t, store.PutVaultCheckpoint(ctx, checkpoint))
	for _, position := range history {
		require.NoError(t, store.PutAuthenticatedPositionHistory(ctx, position))
	}
	require.NoError(t, store.PutAuthenticatedPositionEvidence(ctx, checkpointEvidence))
}

func newRestoreMilestoneLiveRootCoordinator(home *restoreMilestoneHome, transport atproto.Transport, reader atproto.RevisionReader, identity atproto.Identity, blobLimit int64, anchor [32]byte, clock func() time.Time) (*service.Coordinator, error) {
	publication := atproto.ATProtoPublicationIO{
		Reader: reader, Transport: transport, BlobUploadLimit: blobLimit, DID: identity.DID,
		TrustAnchor: anchor, ObservationStore: home.store, Clock: clock,
	}
	return service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: home.paths}, State: home.store, DeviceKeys: home.keyring,
		Trust:     service.StateTrustSource{State: home.store, Keyring: home.keyring},
		Session:   archiveLiveReadSession{identity: identity},
		Remote:    service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: home.store, Budgets: atproto.DefaultBudgets(), Clock: clock}},
		Publisher: publicationPublisher{io: publication}, Settings: home.settings, Paths: home.paths, Clock: clock,
	})
}

func milestoneSettingsKeys(target config.Target) ([]matrix.KeyRef, error) {
	return matrix.SelectCategories(target.GNOMEPolicy.Categories)
}

func assertRestoreMilestoneLiveOrdering(t *testing.T, transport atproto.Transport, read atproto.ReadResult) {
	t.Helper()
	require.NotNil(t, read.Revision)
	assert.Equal(t, read.Head.SnapshotCID, read.Head.BlobCID)
	matching := 0
	for key, record := range read.Revision.Records() {
		if key.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, err := atproto.DecodeRecord(record.Data)
		require.NoError(t, err)
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		require.True(t, ok)
		if bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), read.Head.SnapshotCID) {
			matching++
			assert.Equal(t, read.Head.SnapshotCID, snapshot.Blob.Ref.CID().Bytes())
			assert.Equal(t, read.Head.BlobCID, snapshot.Blob.Ref.CID().Bytes())
		}
	}
	require.Equal(t, 1, matching, "the current head must resolve to exactly one snapshot record")
	cidText := read.Snapshot.Blob.Ref.CID().String()
	status, stream, err := transport.OpenStream(context.Background(), "com.atproto.sync.getBlob", url.Values{
		"did": {read.Revision.DID()}, "cid": {cidText},
	})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.NotNil(t, stream)
	blob, err := io.ReadAll(stream)
	closeErr := stream.Close()
	require.NoError(t, err)
	require.NoError(t, closeErr)
	assert.Equal(t, read.Ciphertext, blob)
}

func assertRestoreMilestoneLiveWriteBatches(t *testing.T, calls []restoreMilestoneLiveWrite) {
	t.Helper()
	require.Empty(t, restoreMilestoneLiveUnexpectedWrites(calls))
	uploaded := make(map[string]bool)
	applyCount, uploadCount := 0, 0
	for _, call := range calls {
		switch call.Endpoint {
		case "com.atproto.repo.uploadBlob":
			var response struct {
				Blob struct {
					Ref struct {
						Link string `json:"$link"`
					} `json:"ref"`
				} `json:"blob"`
			}
			require.NoError(t, json.Unmarshal(call.Response, &response))
			require.NotEmpty(t, response.Blob.Ref.Link)
			uploaded[response.Blob.Ref.Link] = true
			uploadCount++
		case "com.atproto.repo.applyWrites":
			var request struct {
				SwapCommit string `json:"swapCommit"`
				Writes     []struct {
					Collection string          `json:"collection"`
					RKey       string          `json:"rkey"`
					Value      json.RawMessage `json:"value"`
				} `json:"writes"`
			}
			require.NoError(t, json.Unmarshal(call.Body, &request))
			require.NotEmpty(t, request.SwapCommit)
			snapshotRefs := make([]string, 0, 1)
			hasHead := false
			for _, write := range request.Writes {
				switch write.Collection {
				case atproto.VaultSnapshotNSID:
					var value struct {
						Blob struct {
							Ref struct {
								Link string `json:"$link"`
							} `json:"ref"`
						} `json:"blob"`
					}
					require.NoError(t, json.Unmarshal(write.Value, &value))
					snapshotRefs = append(snapshotRefs, value.Blob.Ref.Link)
				case atproto.VaultHeadNSID:
					if write.RKey == "self" {
						hasHead = true
					}
				}
			}
			require.Len(t, snapshotRefs, 1)
			assert.True(t, uploaded[snapshotRefs[0]], "the referenced blob must have completed upload before its fenced batch")
			assert.True(t, hasHead, "snapshot blob reference and head must be co-published in one fenced batch")
			applyCount++
		default:
			require.Fail(t, "unexpected live write endpoint")
		}
	}
	assert.Equal(t, 2, applyCount, "one publication and one enrollment are the only live repository batches")
	assert.Equal(t, 2, uploadCount, "only the intended publication and enrollment ciphertexts are uploaded")
}

func restoreMilestoneLiveUnexpectedWrites(calls []restoreMilestoneLiveWrite) []string {
	unexpected := make([]string, 0)
	for _, call := range calls {
		if call.Endpoint != "com.atproto.repo.uploadBlob" && call.Endpoint != "com.atproto.repo.applyWrites" {
			unexpected = append(unexpected, call.Endpoint)
		}
	}
	return unexpected
}

func (transport *restoreMilestoneLiveTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if strings.EqualFold(method, "POST") || strings.EqualFold(method, "PUT") || strings.EqualFold(method, "PATCH") || strings.EqualFold(method, "DELETE") {
		if endpoint != "com.atproto.repo.uploadBlob" && endpoint != "com.atproto.repo.applyWrites" {
			transport.mu.Lock()
			transport.writes = append(transport.writes, restoreMilestoneLiveWrite{Endpoint: endpoint, Body: bytes.Clone(body)})
			transport.mu.Unlock()
			return 0, nil, errors.New("unexpected live write endpoint blocked")
		}
		status, response, err := transport.base.Do(ctx, method, endpoint, query, body, contentType)
		transport.mu.Lock()
		transport.writes = append(transport.writes, restoreMilestoneLiveWrite{
			Endpoint: endpoint, Body: bytes.Clone(body), Response: bytes.Clone(response),
		})
		transport.mu.Unlock()
		return status, response, err
	}
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport *restoreMilestoneLiveTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return transport.base.OpenStream(ctx, endpoint, query)
}

func (transport *restoreMilestoneLiveTransport) writeCalls() []restoreMilestoneLiveWrite {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	calls := make([]restoreMilestoneLiveWrite, len(transport.writes))
	for index, call := range transport.writes {
		calls[index] = restoreMilestoneLiveWrite{Endpoint: call.Endpoint, Body: bytes.Clone(call.Body), Response: bytes.Clone(call.Response)}
	}
	return calls
}

func writeRestoreMilestoneLiveArtifact(directory string, artifact restoreMilestoneLiveArtifact) error {
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".restore-milestone-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(directory, "restore-milestone.json")); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
