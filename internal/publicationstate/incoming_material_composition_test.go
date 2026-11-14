package publicationstate_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	compositionTargetID       = "synthetic-files"
	compositionTrackedName    = "settings.ini"
	compositionSentinelName   = "machine-only"
	compositionSelectedName   = "synthetic"
	compositionPayloadDirName = "payloads"
)

var (
	compositionBaseContent     = []byte("synthetic accepted base\n")
	compositionEditContent     = []byte("distinct synthetic local edit\n")
	compositionSentinelContent = []byte("synthetic local-only sentinel\n")
)

type compositionFixture struct {
	paths         platform.Paths
	tracked       string
	sentinel      string
	storeDir      string
	portable      model.Target
	configuration config.Config
}

type compositionMaterial struct {
	payload []byte
	key     string
	record  []byte
	head    []byte
}

type compositionOwnedRead struct {
	floor    publicationstate.Floor
	material publicationstate.AcceptedMaterial
}

type compositionStoreHandle struct {
	store  *publicationstate.Store
	closed bool
}

func TestIncomingMaterialCompositionEstablishesBaseAndPreviewsUpload(t *testing.T) {
	ctx := context.Background()
	binding := compositionBinding()
	f := newCompositionFixture(t)

	snapshot := compositionAcceptedSnapshot(t, f.portable, compositionBaseContent)
	setup := compositionEncode(t, binding, snapshot, [16]byte{0x62, 0x31, 0x34})
	expectedRecord := bytes.Clone(setup.record)
	expectedPayload := bytes.Clone(setup.payload)
	supplied := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	observation := compositionObservation(binding, supplied, setup)

	first := compositionOpen(t, f.storeDir, binding)
	proposal, err := first.store.Prepare(ctx, publicationstate.ModeFirstUse, observation, setup.payload)
	require.NoError(t, err)
	require.Equal(t, publicationstate.ModeFirstUse, proposal.Mode)
	require.Equal(t, "first_use", proposal.Stop)
	require.NotEqual(t, [32]byte{}, proposal.StateToken)
	require.NotEqual(t, [32]byte{}, proposal.Confirmation)
	accepted, err := publicationstate.AcceptMaterialForCompositionTest(ctx, first.store, publicationstate.ModeFirstUse, proposal.StateToken, observation, setup.payload, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), accepted.Revision)
	require.Equal(t, uint64(1), accepted.Generation)
	require.Equal(t, publicationstate.ProvenanceFirst, accepted.Provenance)
	require.Equal(t, uint64(0), accepted.Sequence)
	require.Equal(t, binding, accepted.Binding)
	first.close(t)

	compositionClearMaterial(&setup)
	compositionClearObservation(&observation)
	require.Nil(t, setup.payload)
	require.Nil(t, setup.record)
	require.Nil(t, setup.head)
	require.Nil(t, observation.Head)
	for _, block := range observation.Snapshots {
		require.Nil(t, block.Raw)
	}

	second := compositionOpen(t, f.storeDir, binding)
	before := compositionReadOwned(t, ctx, second.store, binding)
	require.Equal(t, uint64(1), before.floor.Revision)
	require.Equal(t, uint64(1), before.floor.Generation)
	require.Equal(t, publicationstate.ProvenanceFirst, before.floor.Provenance)
	require.Equal(t, uint64(0), before.floor.Sequence)
	require.Equal(t, binding, before.floor.Binding)
	require.Equal(t, before.floor, before.material.Floor)
	require.Equal(t, expectedRecord, before.material.SnapshotRecord)
	require.Equal(t, expectedPayload, before.material.Payload)

	record, err := publication.DecodeSnapshot(before.material.SnapshotRecord)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(before.material.SnapshotRecord)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	require.Equal(t, recordCID, before.floor.RecordCID)
	require.Equal(t, key, before.floor.SnapshotKey)
	require.Equal(t, record.PublicationID, before.floor.PublicationID)
	require.Equal(t, record.Vault, binding.Vault)
	require.Equal(t, record.PublicationSeq, before.floor.Sequence)
	require.Equal(t, record.Blob.CID, before.floor.BlobCID)
	require.Equal(t, record.Blob.Size, before.floor.BlobSize)
	require.Equal(t, uint64(len(expectedPayload)), before.floor.BlobSize)
	require.NoError(t, publication.VerifyHeadBinding(before.floor.Head, before.material.SnapshotRecord, before.floor.SnapshotKey))

	decoded, err := publication.DecodePayload(before.material.Payload, record.Blob)
	require.NoError(t, err)
	require.Equal(t, model.SnapshotVersion, decoded.Version)
	require.Len(t, decoded.Targets, 1)
	require.Equal(t, f.portable, decoded.Targets[0])
	require.Len(t, decoded.Entries, 1)
	require.Equal(t, model.EntryKey{TargetID: compositionTargetID, Source: model.SourceFiles, FilePath: compositionTrackedName}, decoded.Entries[0].Identity())
	require.NotNil(t, decoded.Entries[0].File)
	require.Equal(t, model.FileRegular, decoded.Entries[0].File.Kind)
	require.Equal(t, compositionBaseContent, decoded.Entries[0].File.Content)
	require.Equal(t, uint32(0o600), decoded.Entries[0].File.Mode)
	compositionRequireFile(t, f.tracked, compositionBaseContent, 0o600)
	compositionRequireFile(t, f.sentinel, compositionSentinelContent, 0o640)

	request := service.PublicationReconciliationRequest{
		Store: second.store, Binding: binding, ExpectedFloor: before.floor,
		SnapshotRecord: before.material.SnapshotRecord, Payload: before.material.Payload,
		Configuration: f.configuration, TargetID: compositionTargetID,
		Local: compositionLocal(t, f.paths),
	}

	require.Nil(t, setup.payload, "no setup buffer may remain to supply the service call")
	require.Nil(t, setup.record, "no setup buffer may remain to supply the service call")
	require.Nil(t, setup.head, "no setup buffer may remain to supply the service call")
	require.Nil(t, observation.Head, "no setup buffer may remain to supply the service call")
	for _, block := range observation.Snapshots {
		require.Nil(t, block.Raw, "no setup buffer may remain to supply the service call")
	}
	base, err := service.EstablishLocalReconciliationBase(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, base)
	afterEstablish := compositionReadOwned(t, ctx, second.store, binding)
	require.Equal(t, before, afterEstablish)
	compositionRequireFile(t, f.tracked, compositionBaseContent, 0o600)
	compositionRequireFile(t, f.sentinel, compositionSentinelContent, 0o640)

	require.NotEqual(t, compositionBaseContent, compositionEditContent)
	compositionWriteFile(t, f.tracked, compositionEditContent, 0o600)
	preview, disposition, err := service.PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	require.Equal(t, service.PublicationPreviewBaseEstablished, disposition)
	require.True(t, preview.Complete)
	require.Zero(t, preview.UnresolvedEntries)
	require.Len(t, preview.Targets, 1)
	require.Equal(t, compositionTargetID, preview.Targets[0].ID)
	require.Len(t, preview.Targets[0].Entries, 1)
	entry := preview.Targets[0].Entries[0]
	require.Equal(t, model.EntryKey{TargetID: compositionTargetID, Source: model.SourceFiles, FilePath: compositionTrackedName}, entry.Key)
	require.Equal(t, syncengine.ActionUpload, entry.DecisionAction)
	require.Equal(t, syncengine.PreviewChange, entry.Action)
	require.Equal(t, syncengine.PreviewReasonLocalChanged, entry.Reason)
	require.Empty(t, entry.State)
	require.Empty(t, entry.Detail)
	require.NotNil(t, entry.Preimage)
	editDigest := sha256.Sum256(compositionEditContent)
	require.Equal(t, hex.EncodeToString(editDigest[:]), entry.Preimage.Digest)
	require.Equal(t, uint32(0o600), entry.Preimage.Mode)
	afterPreview := compositionReadOwned(t, ctx, second.store, binding)
	require.Equal(t, before, afterPreview)
	compositionRequireFile(t, f.tracked, compositionEditContent, 0o600)
	compositionRequireFile(t, f.sentinel, compositionSentinelContent, 0o640)
	second.close(t)
}

func TestIncomingMaterialCompositionPositionOnlyReadIsCallerGated(t *testing.T) {
	ctx := context.Background()
	binding := compositionBinding()
	f := newCompositionFixture(t)

	snapshot := compositionAcceptedSnapshot(t, f.portable, compositionBaseContent)
	setup := compositionEncode(t, binding, snapshot, [16]byte{0x62, 0x31, 0x35})
	supplied := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	observation := compositionObservation(binding, supplied, setup)

	first := compositionOpen(t, f.storeDir, binding)
	proposal, err := first.store.Prepare(ctx, publicationstate.ModeFirstUse, observation, setup.payload)
	require.NoError(t, err)
	positionOnly, err := first.store.Accept(ctx, publicationstate.ModeFirstUse, proposal.StateToken, observation, setup.payload, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), positionOnly.Revision)
	require.Equal(t, publicationstate.ProvenanceFirst, positionOnly.Provenance)
	first.close(t)
	compositionClearMaterial(&setup)
	compositionClearObservation(&observation)

	second := compositionOpen(t, f.storeDir, binding)
	floor, present, err := second.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, positionOnly.Revision, floor.Revision)
	material, readErr := second.store.ReadAcceptedMaterial(ctx, binding, floor)
	require.Equal(t, publicationstate.AcceptedMaterial{}, material, "position-only ownership: caller gating leaves nothing for the reader to return")
	compositionRequireClassified(t, readErr, publicationstate.ErrStorage, publicationstate.StageReadAcceptedMaterial, publicationstate.ReasonMaterialNotRetained)
	_, payloadDirErr := os.Stat(filepath.Join(f.storeDir, compositionPayloadDirName))
	require.ErrorIs(t, payloadDirErr, os.ErrNotExist)
	compositionRequireFile(t, f.tracked, compositionBaseContent, 0o600)
	compositionRequireFile(t, f.sentinel, compositionSentinelContent, 0o640)
	second.close(t)
}

func TestIncomingMaterialCompositionDamagedPayloadRefusesMaterial(t *testing.T) {
	ctx := context.Background()
	binding := compositionBinding()
	f := newCompositionFixture(t)

	snapshot := compositionAcceptedSnapshot(t, f.portable, compositionBaseContent)
	setup := compositionEncode(t, binding, snapshot, [16]byte{0x62, 0x31, 0x36})
	expectedPayload := bytes.Clone(setup.payload)
	supplied := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	observation := compositionObservation(binding, supplied, setup)

	first := compositionOpen(t, f.storeDir, binding)
	proposal, err := first.store.Prepare(ctx, publicationstate.ModeFirstUse, observation, setup.payload)
	require.NoError(t, err)
	owned, err := publicationstate.AcceptMaterialForCompositionTest(ctx, first.store, publicationstate.ModeFirstUse, proposal.StateToken, observation, setup.payload, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), owned.Revision)
	first.close(t)
	compositionClearMaterial(&setup)
	compositionClearObservation(&observation)

	payloadDirectory := filepath.Join(f.storeDir, compositionPayloadDirName)
	payloadName := compositionPayloadFilename(t, expectedPayload)
	require.Equal(t, []string{payloadName}, compositionDirectoryNames(t, payloadDirectory))
	payloadPath := filepath.Join(payloadDirectory, payloadName)
	compositionRequireFile(t, payloadPath, expectedPayload, 0o600)
	require.NoError(t, os.Remove(payloadPath))

	second := compositionOpen(t, f.storeDir, binding)
	floor, present, err := second.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, owned.Revision, floor.Revision)
	material, readErr := second.store.ReadAcceptedMaterial(ctx, binding, floor)
	require.Equal(t, publicationstate.AcceptedMaterial{}, material, "damaged custody must not yield material for composition")
	compositionRequireClassified(t, readErr, publicationstate.ErrStorage, publicationstate.StageReadAcceptedMaterial, publicationstate.ReasonMaterialMissing)
	compositionRequireFile(t, f.tracked, compositionBaseContent, 0o600)
	compositionRequireFile(t, f.sentinel, compositionSentinelContent, 0o640)
	second.close(t)
}

func newCompositionFixture(t *testing.T) *compositionFixture {
	t.Helper()
	root, err := filepath.Abs(t.TempDir())
	require.NoError(t, err)
	root, err = filepath.EvalSymlinks(root)
	require.NoError(t, err)
	root = filepath.Clean(root)
	home := filepath.Join(root, "home")
	paths := platform.Paths{
		Home: home, ConfigHome: filepath.Join(home, ".config"),
		StateHome: filepath.Join(home, ".local", "state"), CacheHome: filepath.Join(home, ".cache"),
		DataHome: filepath.Join(home, ".local", "share"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	require.NoError(t, os.Mkdir(filepath.Join(paths.Home, compositionSelectedName), 0o700))
	selected, err := filepath.EvalSymlinks(filepath.Join(paths.Home, compositionSelectedName))
	require.NoError(t, err)
	selected = filepath.Clean(selected)
	sentinel := filepath.Join(selected, compositionSentinelName)
	compositionWriteFile(t, sentinel, compositionSentinelContent, 0o640)
	tracked := filepath.Join(selected, compositionTrackedName)
	compositionWriteFile(t, tracked, compositionBaseContent, 0o600)
	storeDir := filepath.Join(root, "publication-state")
	require.NoError(t, os.Mkdir(storeDir, 0o700))
	target := config.Target{
		ID: compositionTargetID, Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: compositionSelectedName, Kind: model.SelectionDirectory, Exclude: []string{compositionSentinelName}},
	}
	portable, err := target.Model()
	require.NoError(t, err)
	require.NoError(t, portable.Validate())
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, configuration.Validate())
	return &compositionFixture{
		paths: paths, tracked: tracked, sentinel: sentinel, storeDir: storeDir,
		portable: portable, configuration: configuration,
	}
}

func compositionBinding() publicationstate.Binding {
	return publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo,
		Repository: "at://did:plc:abcdefghijklmnopqrstuvwx", Vault: [32]byte{0x62, 0x31, 0x34},
	}
}

func compositionAcceptedSnapshot(t *testing.T, portable model.Target, content []byte) model.Snapshot {
	t.Helper()
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{portable},
		Entries: []model.Entry{{TargetID: compositionTargetID, File: &model.FileEntry{
			Path: compositionTrackedName, State: model.FilePresent, Kind: model.FileRegular,
			Content: bytes.Clone(content), Mode: 0o600,
		}}},
	}
	require.NoError(t, snapshot.Validate())
	return snapshot
}

func compositionEncode(t *testing.T, binding publicationstate.Binding, snapshot model.Snapshot, publicationID [16]byte) compositionMaterial {
	t.Helper()
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	record, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID,
		PublicationSeq: 0, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))},
	})
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(record)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: 0,
		SnapshotCID: recordCID, BlobCID: blobCID,
	})
	require.NoError(t, err)
	return compositionMaterial{payload: bytes.Clone(packed.Payload), key: key, record: record, head: head}
}

func compositionObservation(binding publicationstate.Binding, supplied publicationstate.SuppliedContext, material compositionMaterial) publicationstate.Observation {
	return publicationstate.Observation{
		Origin: binding, SuppliedContext: supplied, Head: bytes.Clone(material.head),
		Snapshots: []publicationstate.SnapshotBlock{{Key: material.key, Raw: bytes.Clone(material.record)}},
	}
}

func compositionClearMaterial(material *compositionMaterial) {
	clear(material.payload)
	material.payload = nil
	clear(material.record)
	material.record = nil
	clear(material.head)
	material.head = nil
}

func compositionClearObservation(observation *publicationstate.Observation) {
	clear(observation.Head)
	observation.Head = nil
	for index := range observation.Snapshots {
		clear(observation.Snapshots[index].Raw)
		observation.Snapshots[index].Raw = nil
	}
}

func compositionOpen(t *testing.T, directory string, binding publicationstate.Binding) *compositionStoreHandle {
	t.Helper()
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	require.NotNil(t, store)
	handle := &compositionStoreHandle{store: store}
	t.Cleanup(func() {
		if !handle.closed {
			assert.NoError(t, store.Close())
		}
	})
	return handle
}

func (h *compositionStoreHandle) close(t *testing.T) {
	t.Helper()
	require.False(t, h.closed)
	require.NoError(t, h.store.Close())
	h.closed = true
}

func compositionReadOwned(t *testing.T, ctx context.Context, store *publicationstate.Store, binding publicationstate.Binding) compositionOwnedRead {
	t.Helper()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	material, err := store.ReadAcceptedMaterial(ctx, binding, floor)
	require.NoError(t, err)
	return compositionOwnedRead{floor: floor, material: material}
}

func compositionLocal(t *testing.T, paths platform.Paths) *service.PublicationLocalContext {
	t.Helper()
	local, err := service.NewPublicationLocalContext(paths, nil, nil)
	require.NoError(t, err)
	return local
}

func compositionRequireClassified(t *testing.T, err error, class error, stage publicationstate.Stage, reason publicationstate.Reason) {
	t.Helper()
	require.Error(t, err)
	var stateError *publicationstate.Error
	require.ErrorAs(t, err, &stateError)
	require.Equal(t, class, stateError.Class())
	require.Equal(t, stage, stateError.Stage())
	require.Equal(t, reason, stateError.Reason())
}

func compositionWriteFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, mode))
	require.NoError(t, os.Chmod(path, mode))
}

func compositionRequireFile(t *testing.T, path string, expected []byte, mode os.FileMode) {
	t.Helper()
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, mode.Perm(), info.Mode().Perm())
}

func compositionDirectoryNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}

func compositionPayloadFilename(t *testing.T, payload []byte) string {
	t.Helper()
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]) + ".payload"
}
