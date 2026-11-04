package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pushTestDID = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"

func seedPushTrust(t *testing.T, store *state.Store) ([]byte, vault.Genesis, vault.DeviceMaterial) {
	t.Helper()
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	device := vault.DeviceMaterial{DeviceID: "push-root", KeyID: bytes.Clone(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
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
		Kit: kit, VaultName: "push fixture", RootDevice: device, ContentKey: contentKey[:],
		Wraps:         []vault.RecipientWrapInput{{KeyID: bytes.Clone(device.KeyID), EphemeralPrivate: ephemeral, WrapNonce: wrapNonce}},
		PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, store.PutVaultSelection(ctx, state.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID, RecordedAt: 1}))
	require.NoError(t, store.PutVaultCheckpoint(ctx, state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: bytes.Clone(genesis.ControlCID), ControlBytes: bytes.Clone(genesis.Control),
		SnapshotCID: bytes.Clone(genesis.SnapshotCID), Epoch: 0, PolicyDigest: genesis.PolicyDigest, RecordedAt: 1,
	}))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(ctx, state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest, Policy: bytes.Clone(genesis.Policy),
		Control: bytes.Clone(genesis.Control), Head: bytes.Clone(genesis.Head), Snapshot: bytes.Clone(genesis.Snapshot),
		Certificates: [][]byte{bytes.Clone(genesis.Certificate)}, CheckpointPosition: bytes.Clone(genesis.Checkpoint),
	}))
	return kit, genesis, device
}

type pushTestSession struct {
	did     string
	methods []atproto.VerificationMethod
}

func (session pushTestSession) ReadRequest(_ context.Context, _ VaultSelection, _ vault.DeviceMaterial, _ [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	return atproto.ReadRequest{
		DID: session.did, DIDDocumentID: session.did, VerificationMethods: session.methods,
		PreviousPolicy: bytes.Clone(previousPolicy), PreviousControl: bytes.Clone(previousControl),
	}, nil
}

type pushTestPublisher struct {
	io     atproto.ATProtoPublicationIO
	before func()
}

func (publisher *pushTestPublisher) PublicationIO(context.Context, VaultSelection, TrustMaterial, ReadOutcome) (atproto.ATProtoPublicationIO, error) {
	if publisher.before != nil {
		before := publisher.before
		publisher.before = nil
		before()
	}
	return publisher.io, nil
}

type pushFixture struct {
	coordinator *Coordinator
	store       *state.Store
	paths       platform.Paths
	pds         *atprototest.MemoryPDS
	genesis     vault.Genesis
	kit         []byte
	device      vault.DeviceMaterial
	reader      atproto.RevisionReader
	provider    *pushTestPublisher
	keyring     *pushDeviceKeyring
	target      config.Target
	file        string
	clock       time.Time
}

func newPushFixture(t *testing.T) *pushFixture {
	t.Helper()
	store, paths := openCoordinatorStateWithPaths(t)
	kit, genesis, device := seedPushTrust(t, store)
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(pushTestDID, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	methods := []atproto.VerificationMethod{{ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase}}
	reader := atproto.RevisionReader{Transport: pds, DIDDocumentID: pushTestDID, VerificationMethods: methods}
	clock := time.Unix(1_800_000_000, 0)
	_, err = atproto.CommitGenesis(context.Background(), atproto.GenesisIO{
		Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: pushTestDID, ObservationStore: store,
		Clock: func() time.Time { return clock },
	}, kit, device, genesis)
	require.NoError(t, err)

	root := filepath.Join(paths.Home, "selected")
	require.NoError(t, os.MkdirAll(root, 0o700))
	file := filepath.Join(root, "prefs.toml")
	require.NoError(t, os.WriteFile(file, []byte("theme = 'first'\n"), 0o600))
	target := config.Target{ID: "files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "selected", Kind: model.SelectionDirectory}}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: target.ID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Mode: string(config.Review), LogicalBase: target.Root.Base, LogicalPath: target.Root.Path, Kind: target.Root.Kind, CreatedAt: 1,
	}))
	publicationIO := atproto.ATProtoPublicationIO{
		Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: pushTestDID,
	}
	provider := &pushTestPublisher{io: publicationIO}
	configurationPort := &memoryConfig{value: configuration}
	keyring := &pushDeviceKeyring{devices: map[string]vault.DeviceMaterial{device.DeviceID: device}}
	coordinator, err := NewCoordinator(Dependencies{
		Config: configurationPort, State: store,
		Trust:     StateTrustSource{State: store, Keyring: keyring},
		Session:   pushTestSession{did: pushTestDID, methods: methods},
		Remote:    VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: store, Clock: func() time.Time { return clock }}},
		Publisher: provider, Clock: func() time.Time { return clock }, Paths: paths,
	})
	require.NoError(t, err)
	fixture := &pushFixture{coordinator: coordinator, store: store, paths: paths, pds: pds, genesis: genesis, kit: kit, device: device,
		reader: reader, provider: provider, keyring: keyring, target: target, file: file, clock: clock}
	return fixture
}

func TestCoordinatorPushPublishesSnapshotNoOpsAndReencryptsChanges(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	first, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, first.Status)
	assert.Equal(t, atproto.PublicationCommitted, first.PublicationStatus)
	assert.False(t, first.NoOp)
	assert.Equal(t, uint64(1), first.PublicationCount)
	head, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	header, err := atproto.DecodeRecord(head.Data)
	require.NoError(t, err)
	headRecord, ok := header.(atproto.HeadRecord)
	require.True(t, ok)
	assert.Equal(t, uint64(1), headRecord.PublicationCount)
	snapshotFound := false
	for _, record := range fixture.pds.CurrentRevision().Records {
		if record.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, decodeErr := atproto.DecodeRecord(record.Data)
		require.NoError(t, decodeErr)
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		if ok && bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), headRecord.SnapshotCID) {
			snapshotFound = true
			assert.True(t, fixture.pds.BlobIsLive(snapshot.Blob.Ref.CID().String()))
		}
	}
	assert.True(t, snapshotFound)
	readBack, err := fixture.coordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	var found bool
	for _, entry := range readBack.Snapshot.Entries {
		if entry.File != nil && entry.File.Path == "prefs.toml" {
			found = true
			assert.Equal(t, []byte("theme = 'first'\n"), entry.File.Content)
		}
	}
	assert.True(t, found, "the published blob decrypts with the policy recipient key")

	callsBeforeNoOp := countPDSCalls(fixture.pds, "com.atproto.repo.applyWrites")
	noOp, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, StatusNoOp, noOp.Status)
	assert.True(t, noOp.NoOp)
	assert.Equal(t, uint64(1), noOp.PublicationCount)
	assert.Equal(t, callsBeforeNoOp, countPDSCalls(fixture.pds, "com.atproto.repo.applyWrites"))

	require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'second'\n"), 0o600))
	changed, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, changed.Status)
	assert.Equal(t, uint64(2), changed.PublicationCount)
	changedRead, err := fixture.coordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	for _, entry := range changedRead.Snapshot.Entries {
		if entry.File != nil && entry.File.Path == "prefs.toml" {
			assert.Equal(t, []byte("theme = 'second'\n"), entry.File.Content)
		}
	}
	assertNoPublicationKeyPersistence(t, fixture.store, fixture.paths, fixture.pds, fixture.keyring)
}

func TestCoordinatorPushUsesRemoteChangesAndOmitsFileTombstones(t *testing.T) {
	t.Run("remote-only change remains in the no-op candidate", func(t *testing.T) {
		fixture := newPushFixture(t)
		ctx := context.Background()
		_, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
		require.NoError(t, err)
		fixture.publishRemoteFile(t, []byte("theme = 'remote-only'\n"))
		beforeWrites := countPublicationWrites(fixture.pds)
		result, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
		require.NoError(t, err)
		assert.Equal(t, StatusNoOp, result.Status)
		assert.True(t, result.NoOp)
		assert.Equal(t, beforeWrites, countPublicationWrites(fixture.pds))
	})

	t.Run("local deletion is represented by omission, not a tombstone", func(t *testing.T) {
		fixture := newPushFixture(t)
		ctx := context.Background()
		_, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
		require.NoError(t, err)
		require.NoError(t, os.Remove(fixture.file))
		result, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
		require.NoError(t, err)
		assert.Equal(t, StatusCommitted, result.Status)
		readBack, err := fixture.coordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
		require.NoError(t, err)
		for _, entry := range readBack.Snapshot.Entries {
			if entry.File != nil {
				assert.NotEqual(t, "prefs.toml", entry.File.Path)
			}
		}
		bases, err := fixture.store.AppliedBase(ctx, "files")
		require.NoError(t, err)
		for _, base := range bases {
			if base.Identity.FilePath == "prefs.toml" {
				assert.Equal(t, string(model.FileDeleted), base.Fingerprint.State)
			}
		}
	})
}

func TestPushStatusMapsPublicationRetryOutcomes(t *testing.T) {
	for _, test := range []struct {
		publication atproto.PublicationRetryStatus
		status      StatusState
	}{
		{publication: atproto.PublicationCommitted, status: StatusCommitted},
		{publication: atproto.PublicationQueued, status: StatusQueued},
		{publication: atproto.PublicationStarved, status: StatusStarved},
		{publication: atproto.PublicationFenceLost, status: StatusFenceLost},
		{publication: atproto.PublicationSuperseded, status: StatusSuperseded},
		{publication: atproto.PublicationUnavailable, status: StatusUnavailable},
		{publication: atproto.PublicationRejected, status: StatusRejected},
	} {
		assert.Equal(t, test.status, pushStatus(test.publication))
	}
}

func TestCoordinatorPushRefusesConflictingEditsWithoutWriting(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	_, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'local'\n"), 0o600))
	fixture.publishRemoteFile(t, []byte("theme = 'remote'\n"))
	callsBefore := countPublicationWrites(fixture.pds)
	result, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	assert.Equal(t, StatusConflicted, result.Status)
	var blocked *PushBlockedError
	require.ErrorAs(t, err, &blocked)
	assert.ErrorIs(t, err, ErrPushBlocked)
	assert.NotContains(t, err.Error(), "theme")
	assert.NotContains(t, err.Error(), "local")
	assert.NotContains(t, err.Error(), "remote")
	require.Len(t, blocked.Identities, 1)
	assert.Equal(t, model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "prefs.toml"}, blocked.Identities[0])
	assert.Equal(t, callsBefore, countPublicationWrites(fixture.pds))
	assert.Equal(t, uint64(2), fixture.remoteHeadCount(t))
	bases, err := fixture.store.AppliedBase(ctx, "files")
	require.NoError(t, err)
	require.NotEmpty(t, bases)
	payload, err := fixture.store.Payload(bases[len(bases)-1].PayloadRef)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "first")
	assert.NotContains(t, string(payload), "local")
	assert.NotContains(t, string(payload), "remote")
}

func TestCoordinatorPushLeavesBaseAndHeadUnadvancedForQueuedAndStarvedOutcomes(t *testing.T) {
	for _, test := range []struct {
		name       string
		transport  func(*atprototest.MemoryPDS) atproto.Transport
		wantStatus StatusState
		wantRetry  atproto.PublicationRetryStatus
	}{
		{name: "queued", transport: func(pds *atprototest.MemoryPDS) atproto.Transport { return &pushQueuedTransport{MemoryPDS: pds} }, wantStatus: StatusQueued, wantRetry: atproto.PublicationQueued},
		{name: "starved after lost responses", transport: func(pds *atprototest.MemoryPDS) atproto.Transport { return pushAmbiguousTransport{MemoryPDS: pds} }, wantStatus: StatusStarved, wantRetry: atproto.PublicationStarved},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPushFixture(t)
			ctx := context.Background()
			_, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
			require.NoError(t, err)
			beforeHead := fixture.remoteHeadCount(t)
			beforeBases, err := fixture.store.AppliedBase(ctx, "files")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'pending'\n"), 0o600))
			fixture.provider.io.Transport = test.transport(fixture.pds)
			fixture.provider.io.Reader.Transport = fixture.provider.io.Transport
			result, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
			require.Error(t, err)
			assert.Equal(t, test.wantStatus, result.Status)
			assert.Equal(t, test.wantRetry, result.PublicationStatus)
			assert.False(t, result.NoOp)
			assert.Equal(t, beforeHead, fixture.remoteHeadCount(t))
			afterBases, baseErr := fixture.store.AppliedBase(ctx, "files")
			require.NoError(t, baseErr)
			assert.Equal(t, beforeBases, afterBases)
		})
	}
}

func TestCoordinatorPushStalePredecessorDoesNotAdvanceBaseOrHead(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	_, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	beforeBases, err := fixture.store.AppliedBase(ctx, "files")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'local-stale'\n"), 0o600))
	fixture.provider.before = func() { fixture.publishRemoteFileDirect(t, []byte("theme = 'concurrent'\n")) }
	result, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.Error(t, err)
	assert.Equal(t, StatusStarved, result.Status)
	assert.Equal(t, atproto.PublicationStarved, result.PublicationStatus)
	assert.Equal(t, uint64(2), fixture.remoteHeadCount(t), "only the competing publication may advance the head")
	afterBases, err := fixture.store.AppliedBase(ctx, "files")
	require.NoError(t, err)
	assert.Equal(t, beforeBases, afterBases)
}

func TestCoordinatorPushResolvesLostResponseAndRestoreOnlySignerCannotPublish(t *testing.T) {
	t.Run("lost response is verified before base advances", func(t *testing.T) {
		fixture := newPushFixture(t)
		ctx := context.Background()
		_, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'lost-response'\n"), 0o600))
		fixture.pds.SetHooks(atprototest.MemoryPDSHooks{LoseNextApplyWritesResponse: true})
		result, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
		require.NoError(t, err)
		assert.Equal(t, StatusCommitted, result.Status)
		assert.Equal(t, uint64(2), result.PublicationCount)
		bases, err := fixture.store.AppliedBase(ctx, "files")
		require.NoError(t, err)
		assert.NotEmpty(t, bases)
		assert.Equal(t, uint64(2), fixture.remoteHeadCount(t))
	})

	t.Run("restore-only signer is refused before remote write", func(t *testing.T) {
		fixture := newPushFixture(t)
		ctx := context.Background()
		restoreOnly := fixture.enrollRestoreOnly(t)
		fixture.keyring.devices[restoreOnly.DeviceID] = restoreOnly
		fixture.coordinator.deps.Trust = StateTrustSource{State: fixture.store, Keyring: fixture.keyring}
		before := countPublicationWrites(fixture.pds)
		keyCountBefore := len(fixture.keyring.devices)
		result, err := fixture.coordinator.Push(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: restoreOnly.DeviceID})
		require.Error(t, err)
		assert.Empty(t, result.Status)
		assert.ErrorIs(t, err, vault.ErrPublicationAuthority)
		assert.Equal(t, before, countPublicationWrites(fixture.pds))
		assert.Equal(t, keyCountBefore, len(fixture.keyring.devices))
		assert.Zero(t, fixture.keyring.saveCalls)
	})
}

func (fixture *pushFixture) enrollRestoreOnly(t *testing.T) vault.DeviceMaterial {
	t.Helper()
	ctx := context.Background()
	newSigning, newRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	newDevice := vault.DeviceMaterial{DeviceID: "push-restore-only", KeyID: bytes.Clone(newSigning.Public().(ed25519.PublicKey)), Signing: newSigning, Recipient: newRecipient}
	transitionIO := atproto.ATProtoTransitionIO{
		Reader: fixture.reader, Transport: fixture.pds, BlobUploadLimit: 1 << 20, DID: pushTestDID,
		TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store, Clock: func() time.Time { return fixture.clock },
	}
	previousPolicy, previousControl, err := encodePositionRecords(fixture.genesis.Policy, fixture.genesis.Control)
	require.NoError(t, err)
	transitionIO.PreviousPolicies = [][]byte{previousPolicy}
	transitionIO.PreviousControls = [][]byte{previousControl}
	_, predecessor, err := transitionIO.ReadCurrent(ctx)
	require.NoError(t, err)
	currentRead, err := fixture.coordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	wraps, err := freshRecipientWraps(policy)
	require.NoError(t, err)
	newWrap, err := freshRecipientWraps(vault.Policy{Recipients: []vault.PolicyRecipient{{KeyID: bytes.Clone(newDevice.KeyID)}}})
	if err != nil {
		clearRecipientWraps(wraps)
	}
	require.NoError(t, err)
	wraps = append(wraps, newWrap...)
	defer clearRecipientWraps(wraps)
	var contentKey [32]byte
	var publicationID [16]byte
	var nonce [24]byte
	for _, value := range [][]byte{contentKey[:], publicationID[:], nonce[:]} {
		_, err = rand.Read(value)
		require.NoError(t, err)
	}
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: fixture.genesis.Vault, Signer: fixture.device,
		NewDevice: &newDevice, RequestedRole: vault.RoleRestoreOnly, ContentKey: contentKey[:],
		Recipients: predecessor.Certificates, Wraps: wraps, Plaintext: currentRead.Read.Plaintext,
		PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	committed, err := atproto.CommitTransition(ctx, transitionIO, fixture.store, transition, fixture.device.Signing, fixture.clock)
	require.NoError(t, err)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), committed.Outcome)
	require.NoError(t, fixture.store.PutVaultSelection(ctx, state.VaultSelection{Vault: fixture.genesis.Vault, DeviceID: newDevice.DeviceID, RecordedAt: 2}))
	return newDevice
}

type pushDeviceKeyring struct {
	devices   map[string]vault.DeviceMaterial
	saveCalls int
}

func (keyring *pushDeviceKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	device, exists := keyring.devices[deviceID]
	if !exists || vaultID == ([32]byte{}) {
		return vault.DeviceMaterial{}, ErrDeviceKeyMissing
	}
	return device, nil
}

func (keyring *pushDeviceKeyring) SaveDeviceKeys(context.Context, [32]byte, string, vault.DeviceMaterial) error {
	keyring.saveCalls++
	return nil
}

func (fixture *pushFixture) publishRemoteFileDirect(t *testing.T, data []byte) {
	t.Helper()
	ctx := context.Background()
	read, err := (atproto.VaultReader{Transport: fixture.pds, ObservationStore: fixture.store, Clock: func() time.Time { return fixture.clock }}).Read(ctx, atproto.ReadRequest{
		DID: pushTestDID, DIDDocumentID: pushTestDID, VerificationMethods: fixture.reader.VerificationMethods,
		Vault: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor, DeviceKeyID: bytes.Clone(fixture.device.KeyID), DeviceKey: fixture.device.Recipient,
	})
	require.NoError(t, err)
	blob, err := snapshotBlob(read.Plaintext)
	require.NoError(t, err)
	candidate, err := vault.Unpack(blob)
	require.NoError(t, err)
	for index := range candidate.Entries {
		if candidate.Entries[index].File != nil && candidate.Entries[index].File.Path == "prefs.toml" {
			candidate.Entries[index].File.Content = bytes.Clone(data)
		}
	}
	packed, err := vault.Pack(candidate)
	require.NoError(t, err)
	predecessor, err := publicationPredecessor(read, fixture.genesis.Anchor)
	require.NoError(t, err)
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	wraps, err := freshRecipientWraps(policy)
	require.NoError(t, err)
	defer clearRecipientWraps(wraps)
	contentKey := make([]byte, 32)
	_, err = rand.Read(contentKey)
	require.NoError(t, err)
	defer clear(contentKey)
	var publicationID [16]byte
	var nonce [24]byte
	for _, value := range [][]byte{publicationID[:], nonce[:]} {
		_, err = rand.Read(value)
		require.NoError(t, err)
	}
	publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
		Vault: fixture.genesis.Vault, Signer: fixture.device, ContentKey: contentKey, Wraps: wraps,
		Plaintext: packed.Payload, PublicationID: publicationID, Nonce: nonce,
		EpochFirstSeen: fixture.store, Clock: func() time.Time { return fixture.clock },
	})
	require.NoError(t, err)
	io := fixture.provider.io
	io.TrustAnchor = fixture.genesis.Anchor
	io.ObservationStore = fixture.store
	io.Clock = func() time.Time { return fixture.clock }
	committed, err := atproto.CommitPublication(ctx, io, fixture.store, publication, fixture.device.Signing, fixture.clock)
	require.NoError(t, err)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), committed.Outcome)
}

func (fixture *pushFixture) publishRemoteFile(t *testing.T, data []byte) {
	t.Helper()
	ctx := context.Background()
	trust, err := fixture.coordinator.deps.Trust.Resolve(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	read, err := fixture.coordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	candidate := read.VerifiedSnapshot
	for index := range candidate.Entries {
		if candidate.Entries[index].File != nil && candidate.Entries[index].File.Path == "prefs.toml" {
			candidate.Entries[index].File.Content = bytes.Clone(data)
		}
	}
	packed, err := vault.Pack(candidate)
	require.NoError(t, err)
	predecessor, err := publicationPredecessor(read.Read, trust.Anchor)
	require.NoError(t, err)
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	key := bytes.Repeat([]byte{41}, 32)
	wraps := make([]vault.RecipientWrapInput, 0, len(policy.Recipients))
	for index, recipient := range policy.Recipients {
		var private [32]byte
		var wrapNonce [24]byte
		copy(private[:], bytes.Repeat([]byte{byte(index + 42)}, 32))
		copy(wrapNonce[:], bytes.Repeat([]byte{byte(index + 43)}, 24))
		wraps = append(wraps, vault.RecipientWrapInput{KeyID: bytes.Clone(recipient.KeyID), EphemeralPrivate: private, WrapNonce: wrapNonce})
	}
	var publicationID [16]byte
	copy(publicationID[:], bytes.Repeat([]byte{55}, 16))
	var nonce [24]byte
	copy(nonce[:], bytes.Repeat([]byte{56}, 24))
	publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
		Vault: fixture.genesis.Vault, Signer: fixture.device, ContentKey: key, Wraps: wraps,
		Plaintext: packed.Payload, PublicationID: publicationID, Nonce: nonce,
		EpochFirstSeen: fixture.store, Clock: func() time.Time { return fixture.clock },
	})
	require.NoError(t, err)
	io := fixture.provider.io
	io.TrustAnchor = fixture.genesis.Anchor
	io.ObservationStore = fixture.store
	io.Clock = func() time.Time { return fixture.clock }
	committed, err := atproto.CommitPublication(ctx, io, fixture.store, publication, fixture.device.Signing, fixture.clock)
	require.NoError(t, err)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), committed.Outcome)
}

func countPublicationWrites(pds *atprototest.MemoryPDS) int {
	return countPDSCalls(pds, "com.atproto.repo.uploadBlob") + countPDSCalls(pds, "com.atproto.repo.applyWrites")
}

func countPDSCalls(pds *atprototest.MemoryPDS, endpoint string) int {
	count := 0
	for _, call := range pds.Calls() {
		if call == endpoint {
			count++
		}
	}
	return count
}

func (fixture *pushFixture) remoteHeadCount(t *testing.T) uint64 {
	t.Helper()
	record, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	decoded, err := atproto.DecodeRecord(record.Data)
	require.NoError(t, err)
	head, ok := decoded.(atproto.HeadRecord)
	require.True(t, ok)
	return head.PublicationCount
}

type pushQueuedTransport struct {
	*atprototest.MemoryPDS
	queued bool
}

func (transport *pushQueuedTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" && !transport.queued {
		transport.queued = true
		return 401, []byte(`{"error":"AuthenticationRequired"}`), nil
	}
	return transport.MemoryPDS.Do(ctx, method, endpoint, query, body, contentType)
}

type pushAmbiguousTransport struct {
	*atprototest.MemoryPDS
}

func (transport pushAmbiguousTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" {
		return 0, nil, atprototest.ErrLostResponse
	}
	return transport.MemoryPDS.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport pushAmbiguousTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return transport.MemoryPDS.OpenStream(ctx, endpoint, query)
}

func assertNoPublicationKeyPersistence(t *testing.T, store *state.Store, paths platform.Paths, pds *atprototest.MemoryPDS, keyring *pushDeviceKeyring) {
	t.Helper()
	ctx := context.Background()
	database := openRawState(t, paths)
	defer database.Close()
	rows, err := database.QueryContext(ctx, "SELECT name, sql FROM sqlite_master WHERE type = 'table'")
	require.NoError(t, err)
	var schema strings.Builder
	for rows.Next() {
		var name string
		var definition sql.NullString
		require.NoError(t, rows.Scan(&name, &definition))
		schema.WriteString(name)
		schema.WriteString(definition.String)
	}
	require.NoError(t, rows.Close())
	schemaText := strings.ToLower(schema.String())
	assert.NotContains(t, schemaText, "content_key")
	assert.NotContains(t, schemaText, "ephemeral_private")
	assert.NotContains(t, schemaText, "publication_nonce")
	assert.NotContains(t, schemaText, "nonce")
	assert.Len(t, keyring.devices, 1)
	assert.Zero(t, keyring.saveCalls)

	headRecord, exists := pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	header, err := atproto.DecodeRecord(headRecord.Data)
	require.NoError(t, err)
	head, ok := header.(atproto.HeadRecord)
	require.True(t, ok)
	for _, record := range pds.CurrentRevision().Records {
		if record.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, decodeErr := atproto.DecodeRecord(record.Data)
		require.NoError(t, decodeErr)
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		if !ok || !bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), head.SnapshotCID) {
			continue
		}
		attempts, attemptErr := store.TransitionAttemptsByMarker(ctx, atproto.VaultSnapshotNSID, record.RKey)
		require.NoError(t, attemptErr)
		require.NotEmpty(t, attempts)
		for _, attempt := range attempts {
			assert.NotContains(t, strings.ToLower(attempt.Evidence), "content_key")
			assert.NotContains(t, strings.ToLower(attempt.Evidence), "ephemeral_private")
			assert.NotContains(t, strings.ToLower(attempt.Evidence), "nonce")
		}
	}
}
