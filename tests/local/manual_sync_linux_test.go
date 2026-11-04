//go:build linux && cgo && gsettings

package local_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	dottiecli "github.com/lamb-systems/dottie/internal/cli"
	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/gnome"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	manualSyncActorMarker = "DOTTIE_MANUAL_SYNC_GNOME_ACTOR"
	manualSyncFileTarget  = "preferences"
	manualSyncSettingsID  = "desktop"
)

type manualSyncMachine struct {
	name     string
	root     string
	home     string
	config   string
	state    string
	data     string
	cache    string
	runtime  string
	schemas  string
	paths    platform.Paths
	store    *state.Store
	keyring  *manualSyncKeyring
	settings manualSyncSettingsPort
	test     *testing.T
}

type manualSyncKeyring struct {
	devices map[string]vault.DeviceMaterial
}

type manualSyncSession struct {
	did      string
	methods  []atproto.VerificationMethod
	requests *[]manualSyncReadRequest
}

type manualSyncReadRequest struct {
	Policy  []byte
	Control []byte
}

type manualSyncPublisher struct {
	publication atproto.ATProtoPublicationIO
}

type manualSyncStaleRemote struct {
	delegate service.RemoteReadPort
	policy   []byte
	control  []byte
}

type manualSyncSettingsPort struct {
	machine *manualSyncMachine
}

type manualSyncProcessBackend struct {
	machine *manualSyncMachine
}

type manualSyncActorRequest struct {
	Operation string          `json:"operation"`
	TargetID  string          `json:"target_id,omitempty"`
	SchemaID  string          `json:"schema_id,omitempty"`
	Path      string          `json:"path,omitempty"`
	Key       string          `json:"key,omitempty"`
	ValueType string          `json:"value_type,omitempty"`
	Text      string          `json:"text,omitempty"`
	Keys      []matrix.KeyRef `json:"keys,omitempty"`
	Settings  []string        `json:"settings,omitempty"`
}

type manualSyncActorResponse struct {
	Path     string                     `json:"path,omitempty"`
	Capture  gnome.CaptureResult        `json:"capture,omitempty"`
	User     gnome.UserValue            `json:"user,omitempty"`
	Setting  syncengine.SettingValue    `json:"setting,omitempty"`
	Settings map[string]gnome.UserValue `json:"settings,omitempty"`
}

func TestManualSyncGNOMEActor(t *testing.T) {
	if os.Getenv(manualSyncActorMarker) != "1" {
		return
	}
	requestBytes, err := os.ReadFile(os.Getenv("DOTTIE_MANUAL_SYNC_INPUT"))
	require.NoError(t, err)
	var request manualSyncActorRequest
	require.NoError(t, json.Unmarshal(requestBytes, &request))
	response := manualSyncActorResponse{}
	ctx := context.Background()
	switch request.Operation {
	case "resolve":
		settings, openErr := gnome.OpenDefault(request.SchemaID, request.Path)
		require.NoError(t, openErr)
		response.Path = settings.Path()
		require.NoError(t, settings.Close())
	case "capture":
		captured, captureErr := gnome.Capture(ctx, gnome.CaptureRequest{TargetID: request.TargetID, Keys: request.Keys})
		require.NoError(t, captureErr)
		response.Capture = captured
	case "write":
		settings, openErr := gnome.OpenDefault(manualSchemaID, manualSchemaPath)
		require.NoError(t, openErr)
		if request.Operation == "write" && request.ValueType != "" {
			require.NoError(t, settings.Set(request.Key, request.ValueType, request.Text))
		} else {
			require.NoError(t, settings.Reset(request.Key))
		}
		require.NoError(t, settings.Sync())
		require.NoError(t, settings.Close())
	case "read":
		settings, openErr := gnome.OpenDefault(manualSchemaID, manualSchemaPath)
		require.NoError(t, openErr)
		response.Settings = make(map[string]gnome.UserValue, len(request.Settings))
		for _, key := range request.Settings {
			value, readErr := settings.ReadUser(key)
			require.NoError(t, readErr)
			response.Settings[key] = value
		}
		require.NoError(t, settings.Close())
	case "backend-observe", "backend-canonicalize", "backend-set", "backend-reset":
		backend, backendErr := gnome.NewSettingsBackend()
		require.NoError(t, backendErr)
		defer func() { assert.NoError(t, backend.Close()) }()
		key := model.EntryKey{TargetID: request.TargetID, Source: model.SourceGNOME, SchemaID: request.SchemaID, SettingsPath: request.Path, SettingKey: request.Key}
		switch request.Operation {
		case "backend-observe":
			value, observeErr := backend.Observe(ctx, key)
			require.NoError(t, observeErr)
			response.Setting = value
		case "backend-canonicalize":
			value, canonicalizeErr := backend.Canonicalize(ctx, key, request.ValueType, request.Text)
			require.NoError(t, canonicalizeErr)
			response.Setting = value
		case "backend-set":
			require.NoError(t, backend.Set(ctx, key, request.ValueType, request.Text))
		case "backend-reset":
			require.NoError(t, backend.Reset(ctx, key))
		}
	default:
		require.FailNow(t, "unknown GNOME actor operation")
	}
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(os.Getenv("DOTTIE_MANUAL_SYNC_OUTPUT"), encoded, 0o600))
}

func TestManualSyncEmptyRemoteTwoMachineGate(t *testing.T) {
	root := t.TempDir()
	publisher := newManualSyncMachine(t, root, "publisher")
	newcomer := newManualSyncMachine(t, root, "newcomer")
	ctx := context.Background()
	fileTarget, settingsTarget := manualSyncTargets(t)
	configureManualSyncMachine(t, publisher, fileTarget, settingsTarget)
	configureManualSyncMachine(t, newcomer, fileTarget, settingsTarget)

	publisherFile := filepath.Join(publisher.home, manualSyncFileTarget, "prefs.ini")
	newcomerRoot := filepath.Join(newcomer.home, manualSyncFileTarget)
	require.NoError(t, os.MkdirAll(filepath.Dir(publisherFile), 0o700))
	require.NoError(t, os.MkdirAll(newcomerRoot, 0o700))
	publisherFileBytes := []byte("synthetic publisher preference\n")
	require.NoError(t, os.WriteFile(publisherFile, publisherFileBytes, 0o640))
	manualSyncSetSettings(t, publisher, map[string]string{"gtk-theme": "'Source-Theme'", "cursor-theme": "'Source-Cursor'"}, []string{"icon-theme", "color-scheme", "accent-color"})
	manualSyncSetSettings(t, newcomer, map[string]string{
		"gtk-theme": "'Destination-Theme'", "cursor-theme": "'Destination-Cursor'", "icon-theme": "'Destination-Icons'",
		"color-scheme": "'prefer-dark'", "accent-color": "'red'",
	}, nil)

	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(manualVaultDID, repositoryKey)
	require.NoError(t, err)
	assert.Empty(t, pds.CurrentRevision().Records)
	reader := manualSyncReader(pds)
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	rootDevice := manualSyncDevice(t, "sync-publisher-root")
	genesis := manualSyncGenesis(t, kit, rootDevice)
	clock := time.Unix(1_800_000_000, 0)
	genesisResult, err := atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: manualVaultDID, ObservationStore: publisher.store,
		Clock: func() time.Time { return clock },
	}, kit, rootDevice, genesis)
	require.NoError(t, err)
	assert.Zero(t, genesisResult.ReadResult.PublicationCount)
	assert.Len(t, pds.CurrentRevision().Records, 6)
	manualSyncSeedGenesisTrust(t, publisher, genesis, rootDevice)
	publisher.keyring.devices[rootDevice.DeviceID] = rootDevice
	publisherCoordinator := manualSyncCoordinator(t, publisher, pds, reader, manualSyncSession{did: manualVaultDID, methods: reader.VerificationMethods}, true, clock)

	manualSyncSetEnvironment(t, publisher)
	genesisRead, err := publisherCoordinator.Pull(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID})
	require.NoError(t, err)
	assert.Zero(t, genesisRead.Read.PublicationCount)
	assert.Empty(t, genesisRead.Snapshot.Entries)

	initialRevision := pds.CurrentRevision().CommitCID.String()
	wrongKit := bytes.Clone(kit)
	wrongKit[0] ^= 0x80
	wrongNewcomer, wrongPublicDevice := manualSyncNewDevice(t, "wrong-kit-newcomer")
	wrongApproval := vault.EnrollmentTranscriptFingerprint(genesis.Vault, wrongPublicDevice.DeviceID, wrongPublicDevice.KeyID, vault.RoleRestoreOnly, wrongPublicDevice.SigningPublicKey, wrongPublicDevice.RecipientPublicKey)
	beforeWrongKitWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	beforePublisherCheckpoint := manualSyncCheckpoint(t, publisher.store, genesis.Vault)
	beforePublisherSelections, err := publisher.store.VaultSelections(ctx)
	require.NoError(t, err)
	beforePublisherBases := manualSyncBases(t, publisher.store)
	beforePublisherJournal := manualSyncJournal(t, publisher.store)
	_, err = publisherCoordinator.Enroll(ctx, service.EnrollRequest{
		Selection: service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID}, Device: wrongPublicDevice,
		Role: vault.RoleRestoreOnly, ApprovalFingerprint: wrongApproval, Kit: wrongKit,
	})
	require.ErrorIs(t, err, service.ErrRecoveryKitMismatch)
	assert.Equal(t, initialRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeWrongKitWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	assert.Equal(t, beforePublisherCheckpoint, manualSyncCheckpoint(t, publisher.store, genesis.Vault))
	publisherSelections, err := publisher.store.VaultSelections(ctx)
	require.NoError(t, err)
	assert.Equal(t, beforePublisherSelections, publisherSelections)
	assert.Equal(t, beforePublisherBases, manualSyncBases(t, publisher.store))
	assert.Equal(t, beforePublisherJournal, manualSyncJournal(t, publisher.store))
	assert.NotNil(t, wrongNewcomer.Recipient)

	firstPush, err := publisherCoordinator.Push(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, service.StatusCommitted, firstPush.Status)
	assert.False(t, firstPush.NoOp)
	assert.Equal(t, uint64(1), firstPush.PublicationCount)
	assert.NotEqual(t, initialRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, uint64(1), manualSyncHead(t, pds).PublicationCount)
	assert.Equal(t, manualSyncHead(t, pds).SnapshotCID, firstPush.HeadCID)
	assert.True(t, pds.BlobIsLive(pdsHeadBlobCID(t, pds)))
	readAfterPush, err := publisherCoordinator.Pull(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), readAfterPush.Read.PublicationCount)
	assert.Equal(t, publisherFileBytes, manualSyncFileEntry(t, readAfterPush.Snapshot, fileTarget.ID, "prefs.ini").Content)
	assert.Equal(t, publisherFileBytes, manualSyncReadFile(t, publisherFile))
	assert.NotEmpty(t, manualSyncBasesForTarget(t, publisher.store, fileTarget.ID))
	assert.NotEmpty(t, manualSyncBasesForTarget(t, publisher.store, settingsTarget.ID))
	assert.Empty(t, manualSyncJournal(t, publisher.store), "push records applied bases without restore journal rows")

	manualSyncSetEnvironment(t, publisher)
	newcomerDevice, publicDevice := manualSyncNewDevice(t, "sync-newcomer")
	publisher.keyring.devices[rootDevice.DeviceID] = rootDevice
	approval := vault.EnrollmentTranscriptFingerprint(genesis.Vault, publicDevice.DeviceID, publicDevice.KeyID, vault.RoleRestoreOnly, publicDevice.SigningPublicKey, publicDevice.RecipientPublicKey)
	beforeValidEnrollRevision := pds.CurrentRevision().CommitCID.String()
	beforeValidEnrollWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	enrollment, err := publisherCoordinator.Enroll(ctx, service.EnrollRequest{
		Selection: service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID}, Device: publicDevice,
		Role: vault.RoleRestoreOnly, ApprovalFingerprint: approval, Kit: kit,
	})
	require.NoError(t, err)
	assert.Equal(t, service.StatusCommitted, enrollment.Status)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), enrollment.TransitionOutcome)
	assert.NotEmpty(t, enrollment.EncodedBundle)
	assert.NotContains(t, string(enrollment.EncodedBundle), hex.EncodeToString(newcomerDevice.Signing))
	assert.NotContains(t, string(enrollment.EncodedBundle), hex.EncodeToString(newcomerDevice.Recipient.Bytes()))
	assert.NotContains(t, string(enrollment.EncodedBundle), hex.EncodeToString(kit))
	assert.NotEqual(t, beforeValidEnrollRevision, pds.CurrentRevision().CommitCID.String())
	assert.Greater(t, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"), beforeValidEnrollWrites)
	assert.Equal(t, uint64(1), manualSyncCheckpoint(t, publisher.store, genesis.Vault).Epoch)

	newcomer.keyring.devices[newcomerDevice.DeviceID] = newcomerDevice
	newcomerCoordinator := manualSyncCoordinator(t, newcomer, pds, reader, manualSyncSession{did: manualVaultDID, methods: reader.VerificationMethods}, true, clock)
	manualSyncSetEnvironment(t, newcomer)
	baselineKeys, err := matrix.SelectCategories([]string{"appearance"})
	require.NoError(t, err)
	baselineRefs := make([]service.SettingRef, 0, len(baselineKeys))
	for _, key := range baselineKeys {
		baselineRefs = append(baselineRefs, service.SettingRef{SchemaID: key.SchemaID, Path: key.Path, Key: key.Key})
	}
	baselineCapture, err := newcomer.settings.Capture(ctx, settingsTarget.ID, baselineRefs)
	require.NoError(t, err)
	require.Empty(t, baselineCapture.Unknown)
	require.Len(t, baselineCapture.Entries, 5)
	require.NoError(t, newcomerCoordinator.RecordBase(ctx, settingsTarget.ID, baselineCapture.Entries))
	baselineBases := manualSyncBases(t, newcomer.store)
	beforeWrongAnchorRevision := pds.CurrentRevision().CommitCID.String()
	beforeWrongAnchorWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	wrongAnchor := genesis.Anchor
	wrongAnchor[0] ^= 0x01
	err = newcomerCoordinator.ImportOnboarding(ctx, enrollment.EncodedBundle, genesis.Vault, wrongAnchor, newcomerDevice.DeviceID)
	require.ErrorIs(t, err, service.ErrOnboardingAnchorMismatch)
	selectionRows, err := newcomer.store.VaultSelections(ctx)
	require.NoError(t, err)
	assert.Empty(t, selectionRows)
	_, err = newcomer.store.VaultCheckpoint(ctx, genesis.Vault)
	assert.ErrorIs(t, err, state.ErrVaultCheckpointNotFound)
	assert.Equal(t, baselineBases, manualSyncBases(t, newcomer.store))
	assert.Empty(t, manualSyncJournal(t, newcomer.store))
	assert.Equal(t, beforeWrongAnchorRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeWrongAnchorWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))

	manualSyncSetEnvironment(t, newcomer)
	beforeImportRevision := pds.CurrentRevision().CommitCID.String()
	beforeImportWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	require.NoError(t, newcomerCoordinator.ImportOnboarding(ctx, enrollment.EncodedBundle, genesis.Vault, genesis.Anchor, newcomerDevice.DeviceID))
	selections, err := newcomer.store.VaultSelections(ctx)
	require.NoError(t, err)
	require.Len(t, selections, 1)
	assert.Equal(t, newcomerDevice.DeviceID, selections[0].DeviceID)
	importedCheckpoint := manualSyncCheckpoint(t, newcomer.store, genesis.Vault)
	assert.Equal(t, uint64(1), importedCheckpoint.Epoch)
	predecessorDigest, err := vault.ComputePolicyDigest(enrollment.Bundle.PredecessorPolicy)
	require.NoError(t, err)
	predecessorEvidence, err := newcomer.store.AuthenticatedPositionEvidence(ctx, genesis.Vault, 0, predecessorDigest)
	require.NoError(t, err)
	assert.Equal(t, enrollment.Bundle.PredecessorPolicy, predecessorEvidence.Policy)
	assert.Equal(t, enrollment.Bundle.PredecessorControl, predecessorEvidence.Control)
	_, err = newcomer.store.AuthenticatedPositionEvidenceAtEpoch(ctx, genesis.Vault, 1)
	assert.ErrorIs(t, err, state.ErrAuthenticatedPositionEvidenceNotFound)
	assert.Equal(t, beforeImportRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeImportWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))

	readRequests := make([]manualSyncReadRequest, 0)
	newcomerCoordinator = manualSyncCoordinator(t, newcomer, pds, reader, manualSyncSession{
		did: manualVaultDID, methods: reader.VerificationMethods, requests: &readRequests,
	}, true, clock)
	firstNewcomerRead, err := newcomerCoordinator.Pull(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: newcomerDevice.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), firstNewcomerRead.Read.EpochSeq)
	assert.Equal(t, vault.CheckpointCurrent, firstNewcomerRead.Currency.Outcome)
	require.NotEmpty(t, readRequests)
	expectedPredecessorPolicy, err := atproto.EncodeRecord(manualPolicyRecord(t, predecessorEvidence.Policy))
	require.NoError(t, err)
	expectedPredecessorControl, err := atproto.EncodeRecord(manualControlRecord(t, predecessorEvidence.Control))
	require.NoError(t, err)
	assert.Equal(t, expectedPredecessorPolicy, readRequests[0].Policy)
	assert.Equal(t, expectedPredecessorControl, readRequests[0].Control)
	successorPolicy, err := vault.DecodePolicy(enrollment.Bundle.SuccessorPolicy)
	require.NoError(t, err)
	assert.Equal(t, predecessorDigest, successorPolicy.PrevPolicyDigest)
	assert.True(t, bytes.Equal(firstNewcomerRead.Read.Control.PrevControlCID, manualSyncRawCID(t, predecessorEvidence.Control)))
	currentPosition, err := newcomer.store.AuthenticatedPositionEvidence(ctx, genesis.Vault, 1, importedCheckpoint.PolicyDigest)
	require.NoError(t, err)
	assert.Equal(t, enrollment.Bundle.SuccessorPolicy, currentPosition.Policy)
	assert.Equal(t, enrollment.Bundle.SuccessorControl, currentPosition.Control)

	manualSyncSetEnvironment(t, newcomer)
	beforeRemoteRestore := pds.CurrentRevision().CommitCID.String()
	beforeSourceFile := manualSyncReadFile(t, publisherFile)
	beforeSourceSettings := manualSyncReadSettings(t, publisher)
	fileCandidate, err := newcomerCoordinator.Preview(ctx, service.VaultSelection{Vault: genesis.Vault}, fileTarget.ID)
	require.NoError(t, err)
	assert.True(t, fileCandidate.Preview.Complete)
	assert.Equal(t, []string{"prefs.ini"}, manualActionNames(fileCandidate.Actions))
	assert.NotEmpty(t, fileCandidate.Digest)
	fileRestore, err := newcomerCoordinator.Restore(ctx, service.RestoreRequest{Selection: service.VaultSelection{Vault: genesis.Vault}, TargetID: fileTarget.ID, Confirm: fileCandidate.Digest})
	require.NoError(t, err)
	assert.NotEmpty(t, fileRestore.Applied)
	settingsCandidate, err := newcomerCoordinator.Preview(ctx, service.VaultSelection{Vault: genesis.Vault}, settingsTarget.ID)
	require.NoError(t, err)
	assert.True(t, settingsCandidate.Preview.Complete, "%+v", settingsCandidate.Preview)
	assert.Empty(t, settingsCandidate.Untracked)
	assert.Equal(t, []string{"accent-color", "color-scheme", "cursor-theme", "gtk-theme", "icon-theme"}, manualActionKeys(settingsCandidate.Actions))
	assert.NotEmpty(t, settingsCandidate.Digest)
	settingsRestore, err := newcomerCoordinator.Restore(ctx, service.RestoreRequest{Selection: service.VaultSelection{Vault: genesis.Vault}, TargetID: settingsTarget.ID, Confirm: settingsCandidate.Digest})
	require.NoError(t, err)
	assert.NotEmpty(t, settingsRestore.Applied)
	assert.Equal(t, publisherFileBytes, manualSyncReadFile(t, filepath.Join(newcomerRoot, "prefs.ini")))
	fileInfo, err := os.Stat(filepath.Join(newcomerRoot, "prefs.ini"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), fileInfo.Mode().Perm())
	restoredSettings := manualSyncReadSettings(t, newcomer)
	assert.Equal(t, "'Source-Theme'", restoredSettings["gtk-theme"].Text)
	assert.True(t, restoredSettings["gtk-theme"].Present)
	assert.Equal(t, "'Source-Cursor'", restoredSettings["cursor-theme"].Text)
	assert.True(t, restoredSettings["cursor-theme"].Present)
	for _, key := range []string{"icon-theme", "color-scheme", "accent-color"} {
		assert.False(t, restoredSettings[key].Present, "%s restore intent resets the user override", key)
	}
	journalAfterRestore := manualSyncJournal(t, newcomer.store)
	assert.NotEmpty(t, journalAfterRestore)
	assert.NotEmpty(t, manualSyncBasesForTarget(t, newcomer.store, fileTarget.ID))
	assert.NotEmpty(t, manualSyncBasesForTarget(t, newcomer.store, settingsTarget.ID))
	assert.Equal(t, beforeRemoteRestore, pds.CurrentRevision().CommitCID.String(), "local restore does not publish")
	assert.Equal(t, beforeSourceFile, manualSyncReadFile(t, publisherFile))
	assert.Equal(t, beforeSourceSettings, manualSyncReadSettings(t, publisher))

	manualSyncSetEnvironment(t, publisher)
	beforeSecondPushRevision := pds.CurrentRevision().CommitCID.String()
	beforeSecondPushWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	countBeforeNoOpPush := manualSyncHead(t, pds).PublicationCount
	secondPush, err := publisherCoordinator.Push(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, service.StatusNoOp, secondPush.Status)
	assert.True(t, secondPush.NoOp)
	assert.Equal(t, countBeforeNoOpPush, secondPush.PublicationCount)
	assert.Equal(t, beforeSecondPushRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeSecondPushWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))

	manualSyncSetEnvironment(t, newcomer)
	beforeSecondPullRevision := pds.CurrentRevision().CommitCID.String()
	beforeSecondPullWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	countBeforeSecondPull := manualSyncHead(t, pds).PublicationCount
	secondPull, err := newcomerCoordinator.Pull(ctx, service.VaultSelection{Vault: genesis.Vault})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), secondPull.Read.EpochSeq)
	assert.Equal(t, countBeforeSecondPull, secondPull.Read.PublicationCount)
	assert.Equal(t, beforeSecondPullRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeSecondPullWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	journalBeforeNoOpRestore := manualSyncJournal(t, newcomer.store)
	basesBeforeNoOpRestore := manualSyncBases(t, newcomer.store)
	secondFileCandidate, err := newcomerCoordinator.Preview(ctx, service.VaultSelection{Vault: genesis.Vault}, fileTarget.ID)
	require.NoError(t, err)
	assert.Empty(t, secondFileCandidate.Actions)
	secondFileRestore, err := newcomerCoordinator.Restore(ctx, service.RestoreRequest{Selection: service.VaultSelection{Vault: genesis.Vault}, TargetID: fileTarget.ID, Confirm: secondFileCandidate.Digest})
	require.NoError(t, err)
	assert.True(t, secondFileRestore.NoActions)
	secondSettingsCandidate, err := newcomerCoordinator.Preview(ctx, service.VaultSelection{Vault: genesis.Vault}, settingsTarget.ID)
	require.NoError(t, err)
	assert.Empty(t, secondSettingsCandidate.Actions)
	secondSettingsRestore, err := newcomerCoordinator.Restore(ctx, service.RestoreRequest{Selection: service.VaultSelection{Vault: genesis.Vault}, TargetID: settingsTarget.ID, Confirm: secondSettingsCandidate.Digest})
	require.NoError(t, err)
	assert.True(t, secondSettingsRestore.NoActions)
	assert.Equal(t, journalBeforeNoOpRestore, manualSyncJournal(t, newcomer.store))
	assert.Equal(t, basesBeforeNoOpRestore, manualSyncBases(t, newcomer.store))

	beforeRestoreOnlyPushRevision := pds.CurrentRevision().CommitCID.String()
	beforeRestoreOnlyPushWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	beforeRestoreOnlyBases := manualSyncBases(t, newcomer.store)
	beforeRestoreOnlyJournal := manualSyncJournal(t, newcomer.store)
	changedNewcomerBytes := []byte("restore-only device cannot publish\n")
	require.NoError(t, os.WriteFile(filepath.Join(newcomerRoot, "prefs.ini"), changedNewcomerBytes, 0o600))
	_, err = newcomerCoordinator.Push(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: newcomerDevice.DeviceID})
	require.ErrorIs(t, err, vault.ErrPublicationAuthority)
	assert.Equal(t, beforeRestoreOnlyPushRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeRestoreOnlyPushWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	assert.Equal(t, beforeRestoreOnlyBases, manualSyncBases(t, newcomer.store))
	assert.Equal(t, beforeRestoreOnlyJournal, manualSyncJournal(t, newcomer.store))

	manualSyncSetEnvironment(t, publisher)
	beforeApprovalRevision := pds.CurrentRevision().CommitCID.String()
	beforeApprovalWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	beforeApprovalCheckpoint := manualSyncCheckpoint(t, publisher.store, genesis.Vault)
	transcript, err := publisherCoordinator.RevokeApproval(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID}, newcomerDevice.DeviceID, kit)
	require.NoError(t, err)
	assert.Equal(t, newcomerDevice.DeviceID, transcript.DeviceID)
	assert.Equal(t, uint64(1), transcript.CurrentEpoch)
	assert.Equal(t, uint64(2), transcript.SuccessorEpoch)
	assert.Equal(t, beforeApprovalRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeApprovalWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	assert.Equal(t, beforeApprovalCheckpoint, manualSyncCheckpoint(t, publisher.store, genesis.Vault))
	wrongApprovalFingerprint := transcript.ApprovalFingerprint
	wrongApprovalFingerprint[0] ^= 1
	_, err = publisherCoordinator.Revoke(ctx, service.RevokeRequest{
		Selection: service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID}, DeviceID: newcomerDevice.DeviceID,
		Kit: kit, ApprovalFingerprint: wrongApprovalFingerprint,
	})
	require.ErrorIs(t, err, service.ErrRevokeApprovalMismatch)
	assert.Equal(t, beforeApprovalRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeApprovalWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	assert.Equal(t, beforeApprovalCheckpoint, manualSyncCheckpoint(t, publisher.store, genesis.Vault))

	revocation, err := publisherCoordinator.Revoke(ctx, service.RevokeRequest{
		Selection: service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID}, DeviceID: newcomerDevice.DeviceID,
		Kit: kit, ApprovalFingerprint: transcript.ApprovalFingerprint,
	})
	require.NoError(t, err)
	assert.Equal(t, service.StatusCommitted, revocation.Status)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), revocation.TransitionOutcome)
	assert.NotEqual(t, beforeApprovalRevision, pds.CurrentRevision().CommitCID.String())
	revokedPolicy, err := vault.DecodePolicy(revocation.Bundle.SuccessorPolicy)
	require.NoError(t, err)
	for _, role := range revokedPolicy.Roles {
		assert.NotEqual(t, newcomerDevice.DeviceID, role.DeviceID)
	}
	for _, recipient := range revokedPolicy.Recipients {
		assert.NotEqual(t, newcomerDevice.DeviceID, recipient.DeviceID)
	}
	verifiedSuccessor, err := publisherCoordinator.Pull(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID})
	require.NoError(t, err)
	publisherCheckpoint := manualSyncCheckpoint(t, publisher.store, genesis.Vault)
	assert.Equal(t, verifiedSuccessor.Read.EpochSeq, publisherCheckpoint.Epoch)
	assert.Equal(t, verifiedSuccessor.Read.ControlCID, publisherCheckpoint.ControlCID)
	assert.Equal(t, verifiedSuccessor.Read.Control.PolicyDigest, publisherCheckpoint.PolicyDigest[:])
	assert.Equal(t, verifiedSuccessor.Read.Control.HeadSnapshotCID, publisherCheckpoint.SnapshotCID)
	assert.Equal(t, uint64(2), revokedPolicy.EpochSeq)
	assert.Equal(t, revokedPolicy.EpochSeq, publisherCheckpoint.Epoch)

	manualSyncSetEnvironment(t, newcomer)
	beforeStaleHandoffRevision := pds.CurrentRevision().CommitCID.String()
	beforeStaleHandoffWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	beforeStaleHandoffCheckpoint := manualSyncCheckpoint(t, newcomer.store, genesis.Vault)
	beforeStaleHandoffSelections, err := newcomer.store.VaultSelections(ctx)
	require.NoError(t, err)
	beforeStaleHandoffBases := manualSyncBases(t, newcomer.store)
	beforeStaleHandoffJournal := manualSyncJournal(t, newcomer.store)
	stalePolicyRecord, err := atproto.EncodeRecord(manualPolicyRecord(t, genesis.Policy))
	require.NoError(t, err)
	staleControlRecord, err := atproto.EncodeRecord(manualControlRecord(t, genesis.Control))
	require.NoError(t, err)
	staleRemote := manualSyncStaleRemote{
		delegate: service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: newcomer.store, Clock: func() time.Time { return clock }}},
		policy:   stalePolicyRecord, control: staleControlRecord,
	}
	staleCoordinator := manualSyncCoordinator(t, newcomer, pds, reader, manualSyncSession{did: manualVaultDID, methods: reader.VerificationMethods}, true, clock, staleRemote)
	_, err = staleCoordinator.Pull(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: newcomerDevice.DeviceID})
	require.ErrorIs(t, err, atproto.ErrReadRecordContext)
	assert.Equal(t, beforeStaleHandoffRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeStaleHandoffWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	assert.Equal(t, beforeStaleHandoffCheckpoint, manualSyncCheckpoint(t, newcomer.store, genesis.Vault))
	staleHandoffSelections, err := newcomer.store.VaultSelections(ctx)
	require.NoError(t, err)
	assert.Equal(t, beforeStaleHandoffSelections, staleHandoffSelections)
	assert.Equal(t, beforeStaleHandoffBases, manualSyncBases(t, newcomer.store))
	assert.Equal(t, beforeStaleHandoffJournal, manualSyncJournal(t, newcomer.store))

	beforeRevokedReadRevision := pds.CurrentRevision().CommitCID.String()
	beforeRevokedReadWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	beforeRevokedReadCheckpoint := manualSyncCheckpoint(t, newcomer.store, genesis.Vault)
	beforeRevokedReadBases := manualSyncBases(t, newcomer.store)
	beforeRevokedReadJournal := manualSyncJournal(t, newcomer.store)
	_, err = newcomerCoordinator.Pull(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: newcomerDevice.DeviceID})
	require.ErrorIs(t, err, atproto.ErrReadDecryption)
	assert.Equal(t, beforeRevokedReadRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeRevokedReadWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	assert.Equal(t, beforeRevokedReadCheckpoint, manualSyncCheckpoint(t, newcomer.store, genesis.Vault))
	assert.Equal(t, beforeRevokedReadBases, manualSyncBases(t, newcomer.store))
	assert.Equal(t, beforeRevokedReadJournal, manualSyncJournal(t, newcomer.store))

	historicalPolicyDigest, err := vault.ComputePolicyDigest(enrollment.Bundle.SuccessorPolicy)
	require.NoError(t, err)
	historicalCertificates := manualSyncCertificates(t, firstNewcomerRead.Read.Revision)
	historicalOpen, err := vault.Open(firstNewcomerRead.Read.Envelope, vault.OpenRequest{
		Vault: genesis.Vault, EpochSeq: 1, PolicyDigest: historicalPolicyDigest, Policy: enrollment.Bundle.SuccessorPolicy,
		Control: enrollment.Bundle.SuccessorControl, TrustAnchor: genesis.Anchor, Certificates: historicalCertificates,
		DeviceKeyID: newcomerDevice.KeyID, DeviceKey: newcomerDevice.Recipient,
	})
	require.NoError(t, err)
	assert.Equal(t, firstNewcomerRead.Read.Plaintext, historicalOpen, "previously delivered snapshot remains decryptable after revocation")

	beforeRevokedPushRevision := pds.CurrentRevision().CommitCID.String()
	beforeRevokedPushWrites := manualSyncCallCount(pds, "com.atproto.repo.applyWrites")
	beforeRevokedPushCheckpoint := manualSyncCheckpoint(t, newcomer.store, genesis.Vault)
	beforeRevokedPushBases := manualSyncBases(t, newcomer.store)
	beforeRevokedPushJournal := manualSyncJournal(t, newcomer.store)
	_, err = newcomerCoordinator.Push(ctx, service.VaultSelection{Vault: genesis.Vault, DeviceID: newcomerDevice.DeviceID})
	require.ErrorIs(t, err, atproto.ErrReadDecryption)
	assert.Equal(t, beforeRevokedPushRevision, pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, beforeRevokedPushWrites, manualSyncCallCount(pds, "com.atproto.repo.applyWrites"))
	assert.Equal(t, beforeRevokedPushCheckpoint, manualSyncCheckpoint(t, newcomer.store, genesis.Vault))
	assert.Equal(t, beforeRevokedPushBases, manualSyncBases(t, newcomer.store))
	assert.Equal(t, beforeRevokedPushJournal, manualSyncJournal(t, newcomer.store))

	rootSelection := service.VaultSelection{Vault: genesis.Vault, DeviceID: rootDevice.DeviceID}
	current, err := publisherCoordinator.Pull(ctx, rootSelection)
	require.NoError(t, err)
	var currentPolicyDigest [32]byte
	copy(currentPolicyDigest[:], current.Read.Head.PolicyDigest)
	historyPosition, err := publisher.store.AuthenticatedPositionEvidence(ctx, genesis.Vault, current.Read.EpochSeq, currentPolicyDigest)
	require.NoError(t, err)
	currentPolicy, err := vault.DecodePolicy(historyPosition.Policy)
	require.NoError(t, err)
	positions, err := publisher.store.AuthenticatedPositionHistory(ctx, genesis.Vault)
	require.NoError(t, err)
	orderedPositions := append([]state.AuthenticatedPositionEvidence(nil), positions...)
	sort.Slice(orderedPositions, func(i, j int) bool {
		left, leftErr := vault.DecodeHead(orderedPositions[i].Head)
		require.NoError(t, leftErr)
		right, rightErr := vault.DecodeHead(orderedPositions[j].Head)
		require.NoError(t, rightErr)
		if left.EpochSeq != right.EpochSeq {
			return left.EpochSeq < right.EpochSeq
		}
		return bytes.Compare(left.SnapshotCID, right.SnapshotCID) < 0
	})
	retainedCount := int(currentPolicy.RetainedRecoveryPoints)
	require.GreaterOrEqual(t, len(orderedPositions), retainedCount)
	recoveryPoints := make([]vault.RetentionRecoveryPoint, 0, retainedCount)
	for _, position := range orderedPositions[len(orderedPositions)-retainedCount:] {
		head, decodeErr := vault.DecodeHead(position.Head)
		require.NoError(t, decodeErr)
		recoveryPoints = append(recoveryPoints, vault.RetentionRecoveryPoint{Epoch: head.EpochSeq, SnapshotCID: bytes.Clone(head.SnapshotCID)})
	}
	var rootCertificate []byte
	for _, encoded := range historyPosition.Certificates {
		certificate, decodeErr := vault.DecodeCertificate(encoded)
		require.NoError(t, decodeErr)
		if certificate.DeviceID == rootDevice.DeviceID {
			rootCertificate = bytes.Clone(encoded)
		}
	}
	require.NotEmpty(t, rootCertificate)
	attestation, err := vault.BuildAttestation(vault.AttestationBuildRequest{
		VaultID: genesis.Vault, TrustAnchor: genesis.Anchor,
		State:             vault.ControlEvidence{Policy: historyPosition.Policy, Control: historyPosition.Control, Certificates: historyPosition.Certificates},
		SignerCertificate: rootCertificate, SigningKey: rootDevice.Signing,
		RetentionFloor: currentPolicy.PolicyRetentionFloor, RetainedRecoveryPoints: currentPolicy.RetainedRecoveryPoints, RecoveryPoints: recoveryPoints,
	})
	require.NoError(t, err)
	attestationPublication, err := publisherCoordinator.PublishAttestation(ctx, rootSelection, attestation)
	require.NoError(t, err)
	assert.Equal(t, service.StatusCommitted, attestationPublication.Status)
	attestationRecord, exists := pds.Record(atproto.VaultAttestationNSID, attestationPublication.RKey)
	require.True(t, exists)
	decodedAttestation, err := atproto.DecodeRecord(attestationRecord.Data)
	require.NoError(t, err)
	attestationValue, ok := decodedAttestation.(atproto.AttestationRecord)
	require.True(t, ok)
	assert.Equal(t, int64(2), attestationValue.SchemaVersion)
	assert.Len(t, attestationValue.RecoveryPoints, retainedCount)

	archivePath := filepath.Join(publisher.cache, "complete.dtv")
	exportReport, err := publisherCoordinator.Export(ctx, service.ExportRequest{
		Selection: rootSelection, ExpectedVault: genesis.Vault, ExpectedAnchor: genesis.Anchor, Kit: kit, Path: archivePath,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(positions), 3)
	assert.GreaterOrEqual(t, len(exportReport.Lineage)+len(exportReport.RecoveryPoints), 2)
	assert.Empty(t, exportReport.Omissions)
	beforeArchiveImportCheckpoint := manualSyncCheckpoint(t, publisher.store, genesis.Vault)
	beforeArchiveImportBases := manualSyncBases(t, publisher.store)
	beforeArchiveImportJournal := manualSyncJournal(t, publisher.store)
	beforeArchiveImportSelections, err := publisher.store.VaultSelections(ctx)
	require.NoError(t, err)
	importReport, err := publisherCoordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: genesis.Vault, ExpectedAnchor: genesis.Anchor, Kit: kit,
	})
	require.NoError(t, err)
	assert.Equal(t, genesis.Vault, importReport.VaultID)
	assert.Equal(t, genesis.Anchor, importReport.Anchor)
	assert.Equal(t, exportReport.CurrentEpoch, importReport.CurrentEpoch)
	assert.Len(t, importReport.Lineage, len(exportReport.Lineage))
	assert.Len(t, importReport.RecoveryPoints, retainedCount)
	importWrongKit := bytes.Clone(kit)
	importWrongKit[0] ^= 0x80
	_, err = publisherCoordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: genesis.Vault, ExpectedAnchor: genesis.Anchor, Kit: importWrongKit,
	})
	assert.Error(t, err)
	importWrongAnchor := genesis.Anchor
	importWrongAnchor[0] ^= 0x01
	_, err = publisherCoordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: archivePath, ExpectedVault: genesis.Vault, ExpectedAnchor: importWrongAnchor, Kit: kit,
	})
	assert.ErrorIs(t, err, vault.ErrForeignAnchor)
	assert.Equal(t, beforeArchiveImportCheckpoint, manualSyncCheckpoint(t, publisher.store, genesis.Vault))
	assert.Equal(t, beforeArchiveImportBases, manualSyncBases(t, publisher.store))
	assert.Equal(t, beforeArchiveImportJournal, manualSyncJournal(t, publisher.store))
	afterArchiveImportSelections, err := publisher.store.VaultSelections(ctx)
	require.NoError(t, err)
	assert.Equal(t, beforeArchiveImportSelections, afterArchiveImportSelections)

	var missingBlobCID string
	if len(exportReport.Lineage) > 0 {
		missingBlobCID = exportReport.Lineage[0].SnapshotCID
	} else if len(exportReport.RecoveryPoints) > 0 {
		missingBlobCID = exportReport.RecoveryPoints[0].SnapshotCID
	}
	require.NotEmpty(t, missingBlobCID)
	pds.RemoveBlob(missingBlobCID)
	missingArchivePath := filepath.Join(publisher.cache, "missing-required-blob.dtv")
	_, err = publisherCoordinator.Export(ctx, service.ExportRequest{
		Selection: rootSelection, ExpectedVault: genesis.Vault, ExpectedAnchor: genesis.Anchor, Kit: kit, Path: missingArchivePath,
	})
	require.ErrorIs(t, err, service.ErrExportRefused)
	assert.ErrorContains(t, err, missingBlobCID)
	_, err = os.Stat(missingArchivePath)
	assert.ErrorIs(t, err, os.ErrNotExist)

	manualSyncSetEnvironment(t, publisher)
	require.NoError(t, publisher.store.Close())
	var historyOutput, historyError bytes.Buffer
	assert.Equal(t, 0, dottiecli.Run([]string{"history"}, &historyOutput, &historyError))
	assert.Empty(t, historyError.String())
	assert.Contains(t, historyOutput.String(), "remote: not-requested")
	for _, path := range []string{publisher.root, publisher.home, publisher.state, publisher.cache, newcomer.root, newcomer.home, newcomer.state} {
		assert.NotContains(t, historyOutput.String(), path)
	}
	assert.NotContains(t, historyOutput.String(), string(publisherFileBytes))
	assert.NotContains(t, historyOutput.String(), "Source-Theme")
	assert.NotContains(t, historyOutput.String(), hex.EncodeToString(kit))
	assert.NotContains(t, historyOutput.String(), hex.EncodeToString(rootDevice.Signing))
	assert.NotContains(t, historyOutput.String(), hex.EncodeToString(rootDevice.Recipient.Bytes()))
}

func newManualSyncMachine(t *testing.T, root, name string) manualSyncMachine {
	t.Helper()
	machineRoot := filepath.Join(root, name)
	machine := manualSyncMachine{
		name: name, root: machineRoot, home: filepath.Join(machineRoot, "home"), config: filepath.Join(machineRoot, "xdg-config"),
		state: filepath.Join(machineRoot, "xdg-state"), data: filepath.Join(machineRoot, "xdg-data"),
		cache: filepath.Join(machineRoot, "cache"), runtime: filepath.Join(machineRoot, "runtime"),
		schemas: filepath.Join(machineRoot, "xdg-data", "glib-2.0", "schemas"),
	}
	for _, directory := range []string{machine.home, machine.config, machine.state, machine.data, machine.cache, machine.runtime, machine.schemas} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	require.NoError(t, os.Chmod(machine.runtime, 0o700))
	machine.paths = platform.Paths{Home: machine.home, ConfigHome: machine.config, StateHome: machine.state, DataHome: machine.data, CacheHome: machine.cache}
	store, err := state.Open(machine.paths)
	require.NoError(t, err)
	machine.store = store
	t.Cleanup(func() { assert.NoError(t, machine.store.Close()) })
	machine.keyring = &manualSyncKeyring{devices: make(map[string]vault.DeviceMaterial)}
	machine.test = t
	machine.settings = manualSyncSettingsPort{machine: &machine}
	manualSyncCompileSchemas(t, machine)
	return machine
}

func manualSyncCompileSchemas(t *testing.T, machine manualSyncMachine) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	source := filepath.Join(filepath.Dir(sourceFile), "..", "testdata", "gsettings")
	entries, err := os.ReadDir(source)
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".xml") && !strings.HasSuffix(entry.Name(), ".override")) {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(source, entry.Name()))
		require.NoError(t, readErr)
		require.NoError(t, os.WriteFile(filepath.Join(machine.schemas, entry.Name()), data, 0o600))
	}
	command := exec.Command("glib-compile-schemas", machine.schemas)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
}

func manualSyncTargets(t *testing.T) (config.Target, config.Target) {
	t.Helper()
	keys, err := matrix.SelectCategories([]string{"appearance"})
	require.NoError(t, err)
	digest, err := matrix.KeySetDigest(keys)
	require.NoError(t, err)
	return config.Target{ID: manualSyncFileTarget, Source: model.SourceFiles, Mode: config.Review,
			Root: &config.Root{Base: model.RootHome, Path: manualSyncFileTarget, Kind: model.SelectionDirectory}},
		config.Target{ID: manualSyncSettingsID, Source: model.SourceGNOME, Mode: config.Review,
			GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalApproved, Categories: []string{"appearance"}, MatrixVersion: matrix.Version, KeyDigest: fmt.Sprintf("%x", digest[:])}}
}

func configureManualSyncMachine(t *testing.T, machine manualSyncMachine, fileTarget, settingsTarget config.Target) {
	t.Helper()
	configuration := config.Default()
	configuration.Targets = []config.Target{fileTarget, settingsTarget}
	require.NoError(t, config.Save(machine.paths, configuration))
	require.NoError(t, machine.store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: fileTarget.ID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		LogicalBase: fileTarget.Root.Base, LogicalPath: fileTarget.Root.Path, Kind: fileTarget.Root.Kind, Mode: string(config.Review), CreatedAt: 1,
	}))
	require.NoError(t, machine.store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: settingsTarget.ID, Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: string(config.Review), CreatedAt: 1,
	}))
}

func manualSyncDevice(t *testing.T, deviceID string) vault.DeviceMaterial {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	return vault.DeviceMaterial{DeviceID: deviceID, KeyID: bytes.Clone(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
}

func manualSyncNewDevice(t *testing.T, deviceID string) (vault.DeviceMaterial, vault.PublicDeviceInput) {
	t.Helper()
	device := manualSyncDevice(t, deviceID)
	public := vault.PublicDeviceInput{
		DeviceID: device.DeviceID, KeyID: bytes.Clone(device.KeyID), SigningPublicKey: bytes.Clone(device.Signing.Public().(ed25519.PublicKey)),
		RecipientPublicKey: bytes.Clone(device.Recipient.PublicKey().Bytes()),
	}
	return device, public
}

func manualSyncGenesis(t *testing.T, kit []byte, root vault.DeviceMaterial) vault.Genesis {
	t.Helper()
	var contentKey [32]byte
	var wrapNonce [24]byte
	var publicationID [16]byte
	var nonce [24]byte
	_, err := rand.Read(contentKey[:])
	require.NoError(t, err)
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = rand.Read(wrapNonce[:])
	require.NoError(t, err)
	_, err = rand.Read(publicationID[:])
	require.NoError(t, err)
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: "synthetic two-machine gate", RootDevice: root, ContentKey: contentKey[:],
		Wraps:         []vault.RecipientWrapInput{{KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(ephemeral.Bytes()), WrapNonce: wrapNonce}},
		PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	return genesis
}

func manualSyncSeedGenesisTrust(t *testing.T, machine manualSyncMachine, genesis vault.Genesis, device vault.DeviceMaterial) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).Unix()
	require.NoError(t, machine.store.PutVaultSelection(ctx, state.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID, RecordedAt: now}))
	require.NoError(t, machine.store.PutVaultCheckpoint(ctx, state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: bytes.Clone(genesis.ControlCID), ControlBytes: bytes.Clone(genesis.Control),
		SnapshotCID: bytes.Clone(genesis.SnapshotCID), Epoch: 0, PolicyDigest: genesis.PolicyDigest, RecordedAt: now,
	}))
	require.NoError(t, machine.store.PutAuthenticatedPositionEvidence(ctx, state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest, Policy: bytes.Clone(genesis.Policy),
		Control: bytes.Clone(genesis.Control), Head: bytes.Clone(genesis.Head), Snapshot: bytes.Clone(genesis.Snapshot),
		Certificates: [][]byte{bytes.Clone(genesis.Certificate)}, CheckpointPosition: bytes.Clone(genesis.Checkpoint),
	}))
}

func manualSyncReader(pds *atprototest.MemoryPDS) atproto.RevisionReader {
	method := pds.VerificationMethod()
	return atproto.RevisionReader{Transport: pds, DIDDocumentID: manualVaultDID, VerificationMethods: []atproto.VerificationMethod{{
		ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
	}}}
}

func manualSyncCoordinator(t *testing.T, machine manualSyncMachine, pds *atprototest.MemoryPDS, reader atproto.RevisionReader, session manualSyncSession, publishing bool, clock time.Time, remoteOverride ...service.RemoteReadPort) *service.Coordinator {
	t.Helper()
	remote := service.RemoteReadPort(service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: machine.store, Clock: func() time.Time { return clock }}})
	if len(remoteOverride) != 0 {
		remote = remoteOverride[0]
	}
	dependencies := service.Dependencies{
		Config: service.FileConfigPort{Paths: machine.paths}, State: machine.store, DeviceKeys: machine.keyring,
		Trust: service.StateTrustSource{State: machine.store, Keyring: machine.keyring}, Session: session, Remote: remote,
		Settings: machine.settings, Paths: machine.paths, Clock: func() time.Time { return clock },
	}
	if publishing {
		dependencies.Publisher = manualSyncPublisher{publication: atproto.ATProtoPublicationIO{
			Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: manualVaultDID,
		}}
	}
	coordinator, err := service.NewCoordinator(dependencies)
	require.NoError(t, err)
	return coordinator
}

func (keyring *manualSyncKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	device, exists := keyring.devices[deviceID]
	if vaultID == ([32]byte{}) || !exists {
		return vault.DeviceMaterial{}, errors.New("synthetic device key is unavailable")
	}
	return device, nil
}

func (session manualSyncSession) ReadRequest(_ context.Context, selection service.VaultSelection, device vault.DeviceMaterial, anchor [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	if session.requests != nil {
		*session.requests = append(*session.requests, manualSyncReadRequest{Policy: bytes.Clone(previousPolicy), Control: bytes.Clone(previousControl)})
	}
	return atproto.ReadRequest{
		DID: session.did, DIDDocumentID: session.did, VerificationMethods: session.methods,
		Vault: selection.Vault, TrustAnchor: anchor, DeviceKeyID: bytes.Clone(device.KeyID), DeviceKey: device.Recipient,
		PreviousPolicy: bytes.Clone(previousPolicy), PreviousControl: bytes.Clone(previousControl),
	}, nil
}

func (publisher manualSyncPublisher) PublicationIO(context.Context, service.VaultSelection, service.TrustMaterial, service.ReadOutcome) (atproto.ATProtoPublicationIO, error) {
	return publisher.publication, nil
}

func (remote manualSyncStaleRemote) Read(ctx context.Context, request atproto.ReadRequest) (atproto.ReadResult, error) {
	request.PreviousPolicy = bytes.Clone(remote.policy)
	request.PreviousControl = bytes.Clone(remote.control)
	return remote.delegate.Read(ctx, request)
}

func (settings manualSyncSettingsPort) Resolve(_ context.Context, targetID, schemaID, path string) (string, error) {
	response := manualSyncRunActor(settings.machine.test, *settings.machine, manualSyncActorRequest{Operation: "resolve", TargetID: targetID, SchemaID: schemaID, Path: path})
	return response.Path, nil
}

func (settings manualSyncSettingsPort) Capture(_ context.Context, targetID string, refs []service.SettingRef) (service.SettingsCapture, error) {
	keys := make([]matrix.KeyRef, 0, len(refs))
	for _, ref := range refs {
		keys = append(keys, matrix.KeyRef{SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key})
	}
	response := manualSyncRunActor(settings.machine.test, *settings.machine, manualSyncActorRequest{Operation: "capture", TargetID: targetID, Keys: keys})
	result := service.SettingsCapture{Entries: response.Capture.Entries}
	for _, key := range response.Capture.Unknown {
		result.Unknown = append(result.Unknown, model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: key.SchemaID, SettingsPath: key.Path, SettingKey: key.Key})
	}
	return result, nil
}

func (settings manualSyncSettingsPort) Backend() syncengine.SettingsBackend {
	return &manualSyncProcessBackend{machine: settings.machine}
}

func (backend *manualSyncProcessBackend) Observe(_ context.Context, key model.EntryKey) (syncengine.SettingValue, error) {
	response := manualSyncRunActor(backend.machine.test, *backend.machine, manualSyncBackendRequest("backend-observe", key, "", ""))
	return response.Setting, nil
}

func (backend *manualSyncProcessBackend) Canonicalize(_ context.Context, key model.EntryKey, valueType, text string) (syncengine.SettingValue, error) {
	response := manualSyncRunActor(backend.machine.test, *backend.machine, manualSyncBackendRequest("backend-canonicalize", key, valueType, text))
	return response.Setting, nil
}

func (backend *manualSyncProcessBackend) Set(_ context.Context, key model.EntryKey, valueType, text string) error {
	manualSyncRunActor(backend.machine.test, *backend.machine, manualSyncBackendRequest("backend-set", key, valueType, text))
	return nil
}

func (backend *manualSyncProcessBackend) Reset(_ context.Context, key model.EntryKey) error {
	manualSyncRunActor(backend.machine.test, *backend.machine, manualSyncBackendRequest("backend-reset", key, "", ""))
	return nil
}

func (*manualSyncProcessBackend) Close() error { return nil }

func manualSyncBackendRequest(operation string, key model.EntryKey, valueType, text string) manualSyncActorRequest {
	return manualSyncActorRequest{
		Operation: operation, TargetID: key.TargetID, SchemaID: key.SchemaID, Path: key.SettingsPath,
		Key: key.SettingKey, ValueType: valueType, Text: text,
	}
}

func manualSyncRunActor(t *testing.T, machine manualSyncMachine, request manualSyncActorRequest) manualSyncActorResponse {
	t.Helper()
	encoded, err := json.Marshal(request)
	require.NoError(t, err)
	actorDir, err := os.MkdirTemp("", "dottie-manual-sync-actor-")
	require.NoError(t, err)
	defer os.RemoveAll(actorDir)
	inputPath := filepath.Join(actorDir, "input.json")
	outputPath := filepath.Join(actorDir, "output.json")
	require.NoError(t, os.WriteFile(inputPath, encoded, 0o600))
	command := exec.Command(os.Args[0], "-test.run=^TestManualSyncGNOMEActor$")
	command.Env = manualSyncActorEnvironment(machine, inputPath, outputPath)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	require.NoError(t, command.Run(), output.String())
	result, err := os.ReadFile(outputPath)
	require.NoError(t, err, output.String())
	var response manualSyncActorResponse
	require.NoError(t, json.Unmarshal(result, &response))
	return response
}

func manualSyncActorEnvironment(machine manualSyncMachine, inputPath, outputPath string) []string {
	blocked := map[string]bool{
		"HOME": true, "XDG_CONFIG_HOME": true, "XDG_STATE_HOME": true, "XDG_DATA_HOME": true,
		"XDG_CACHE_HOME": true, "XDG_RUNTIME_DIR": true, "GSETTINGS_SCHEMA_DIR": true, "GSETTINGS_BACKEND": true,
		manualSyncActorMarker: true, "DOTTIE_MANUAL_SYNC_INPUT": true, "DOTTIE_MANUAL_SYNC_OUTPUT": true,
	}
	environment := make([]string, 0, len(os.Environ())+10)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if !blocked[name] {
			environment = append(environment, item)
		}
	}
	return append(environment,
		"HOME="+machine.home, "XDG_CONFIG_HOME="+machine.config, "XDG_STATE_HOME="+machine.state,
		"XDG_DATA_HOME="+machine.data, "XDG_CACHE_HOME="+machine.cache, "XDG_RUNTIME_DIR="+machine.runtime,
		"GSETTINGS_SCHEMA_DIR="+machine.schemas, "GSETTINGS_BACKEND=keyfile",
		manualSyncActorMarker+"=1", "DOTTIE_MANUAL_SYNC_INPUT="+inputPath, "DOTTIE_MANUAL_SYNC_OUTPUT="+outputPath,
	)
}

func manualSyncSetEnvironment(t *testing.T, machine manualSyncMachine) {
	t.Helper()
	for name, value := range map[string]string{
		"HOME": machine.home, "XDG_CONFIG_HOME": machine.config, "XDG_STATE_HOME": machine.state,
		"XDG_DATA_HOME": machine.data, "XDG_CACHE_HOME": machine.cache, "XDG_RUNTIME_DIR": machine.runtime,
		"GSETTINGS_SCHEMA_DIR": machine.schemas, "GSETTINGS_BACKEND": "keyfile",
	} {
		t.Setenv(name, value)
	}
}

func manualSyncSetSettings(t *testing.T, machine manualSyncMachine, values map[string]string, reset []string) {
	t.Helper()
	for key, text := range values {
		manualSyncRunActor(t, machine, manualSyncActorRequest{Operation: "write", Key: key, ValueType: "s", Text: text})
	}
	for _, key := range reset {
		manualSyncRunActor(t, machine, manualSyncActorRequest{Operation: "write", Key: key})
	}
}

func manualSyncReadSettings(t *testing.T, machine manualSyncMachine) map[string]gnome.UserValue {
	t.Helper()
	response := manualSyncRunActor(t, machine, manualSyncActorRequest{
		Operation: "read", Settings: []string{"gtk-theme", "icon-theme", "cursor-theme", "color-scheme", "accent-color"},
	})
	return response.Settings
}

func manualSyncCheckpoint(t *testing.T, store *state.Store, vaultID [32]byte) state.VaultCheckpoint {
	t.Helper()
	checkpoint, err := store.VaultCheckpoint(context.Background(), vaultID)
	require.NoError(t, err)
	return checkpoint
}

func manualSyncBasesForTarget(t *testing.T, store *state.Store, targetID string) []state.BaseRecord {
	t.Helper()
	bases, err := store.AppliedBase(context.Background(), targetID)
	require.NoError(t, err)
	return bases
}

func manualSyncBases(t *testing.T, store *state.Store) map[string][]state.BaseRecord {
	t.Helper()
	result := make(map[string][]state.BaseRecord)
	for _, targetID := range []string{manualSyncFileTarget, manualSyncSettingsID} {
		result[targetID] = manualSyncBasesForTarget(t, store, targetID)
	}
	return result
}

func manualSyncJournal(t *testing.T, store *state.Store) []state.JournalEntry {
	t.Helper()
	journal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	return journal
}

func manualSyncCallCount(pds *atprototest.MemoryPDS, endpoint string) int {
	count := 0
	for _, call := range pds.Calls() {
		if call == endpoint {
			count++
		}
	}
	return count
}

func manualSyncHead(t *testing.T, pds *atprototest.MemoryPDS) atproto.HeadRecord {
	t.Helper()
	record, exists := pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	decoded, err := atproto.DecodeRecord(record.Data)
	require.NoError(t, err)
	head, ok := decoded.(atproto.HeadRecord)
	require.True(t, ok)
	return head
}

func pdsHeadBlobCID(t *testing.T, pds *atprototest.MemoryPDS) string {
	t.Helper()
	head := manualSyncHead(t, pds)
	for _, record := range pds.CurrentRevision().Records {
		if record.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, err := atproto.DecodeRecord(record.Data)
		require.NoError(t, err)
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		if ok && bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), head.SnapshotCID) {
			return snapshot.Blob.Ref.CID().String()
		}
	}
	require.FailNow(t, "published head has no matching snapshot blob")
	return ""
}

func manualSyncFileEntry(t *testing.T, snapshot model.Snapshot, targetID, path string) model.FileEntry {
	t.Helper()
	for _, entry := range snapshot.Entries {
		if entry.TargetID == targetID && entry.File != nil && entry.File.Path == path {
			return *entry.File
		}
	}
	require.FailNow(t, "expected file entry is absent")
	return model.FileEntry{}
}

func manualSyncReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func manualSyncRawCID(t *testing.T, encoded []byte) []byte {
	t.Helper()
	identifier, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: 0x12, MhLength: 32}).Sum(encoded)
	require.NoError(t, err)
	return identifier.Bytes()
}

func manualSyncCertificates(t *testing.T, revision *atproto.Revision) [][]byte {
	t.Helper()
	require.NotNil(t, revision)
	certificates := make([][]byte, 0)
	for key, record := range revision.Records() {
		if key.Collection != atproto.VaultCertificateNSID {
			continue
		}
		decoded, err := atproto.DecodeRecord(record.Data)
		require.NoError(t, err)
		certificateRecord, ok := decoded.(atproto.CertificateRecord)
		require.True(t, ok)
		certificate := vault.Certificate{
			Vault: [32]byte(certificateRecord.Vault), DeviceID: certificateRecord.DeviceID, KeyID: bytes.Clone(certificateRecord.KeyID),
			Role: vault.Role(certificateRecord.Role), CertEpoch: certificateRecord.CertEpoch, Issuer: certificateRecord.Issuer,
			RevocationRef: bytes.Clone(certificateRecord.RevocationRef),
			Signer:        vault.Signer{DeviceID: certificateRecord.SignerDeviceID, KeyID: bytes.Clone(certificateRecord.SignerKeyID)},
		}
		copy(certificate.SigningPublicKey[:], certificateRecord.SigningPublicKey)
		copy(certificate.EncryptionPublicKey[:], certificateRecord.EncryptionPublicKey)
		copy(certificate.Signature[:], certificateRecord.Signature)
		encoded, encodeErr := vault.EncodeCertificate(certificate)
		require.NoError(t, encodeErr)
		certificates = append(certificates, encoded)
	}
	require.NotEmpty(t, certificates)
	return certificates
}
