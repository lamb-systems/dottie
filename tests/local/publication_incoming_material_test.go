package local_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const publicationIncomingPayloadDirectory = "payloads"

type publicationIncomingFixture struct {
	home            *publicationReconcileHome
	storeDirectory  string
	binding         publicationstate.Binding
	configuration   config.Config
	portable        model.Target
	setup           publicationReconcileMaterial
	observation     publicationstate.Observation
	expectedRecord  []byte
	expectedPayload []byte
}

func newPublicationIncomingFixture(t *testing.T) *publicationIncomingFixture {
	t.Helper()
	ctx := context.Background()
	binding := publicationReconcileBinding()
	home, storeDirectory := newPublicationMaterialHome(t, binding)
	target, configuration, portable := publicationMaterialTarget(t)
	writePublicationReconcileFile(t, filepath.Join(home.selected, "settings.ini"), publicationReconcileInitial, 0o600)
	captured := requirePublicationMaterialCapture(t, ctx, home, target, publicationReconcileInitial)
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: captured}
	require.NoError(t, snapshot.Validate())
	setup := encodePublicationReconcileMaterial(t, binding, snapshot, 0, nil, [16]byte{0x62, 0x34, 0x63})
	supplied := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	return &publicationIncomingFixture{
		home: home, storeDirectory: storeDirectory, binding: binding,
		configuration: configuration, portable: portable,
		setup:          setup,
		observation:    publicationReconcileObservation(binding, supplied, setup),
		expectedRecord: bytes.Clone(setup.record), expectedPayload: bytes.Clone(setup.payload),
	}
}

func (f *publicationIncomingFixture) clearSetup() {
	clear(f.setup.payload)
	f.setup.payload = nil
	clear(f.setup.record)
	f.setup.record = nil
	clear(f.setup.head)
	f.setup.head = nil
	clear(f.observation.Head)
	f.observation.Head = nil
	for index := range f.observation.Snapshots {
		clear(f.observation.Snapshots[index].Raw)
		f.observation.Snapshots[index].Raw = nil
	}
}

func (f *publicationIncomingFixture) requireSetupBuffersCleared(t *testing.T, message string) {
	t.Helper()
	require.Nil(t, f.setup.payload, message)
	require.Nil(t, f.setup.record, message)
	require.Nil(t, f.setup.head, message)
	require.Nil(t, f.observation.Head, message)
	for _, block := range f.observation.Snapshots {
		require.Nil(t, block.Raw, message)
	}
}

func (f *publicationIncomingFixture) requireLocalFiles(t *testing.T, tracked []byte) {
	t.Helper()
	requirePublicationMaterialFile(t, filepath.Join(f.home.selected, "settings.ini"), tracked, 0o600)
	requirePublicationMaterialFile(t, f.home.sentinel, publicationReconcileSentinelA, 0o640)
}

func (f *publicationIncomingFixture) acceptFirstUse(t *testing.T) (publicationstate.Floor, publicationstate.Proposal) {
	t.Helper()
	ctx := context.Background()
	proposal, err := f.home.pubStore.Prepare(ctx, publicationstate.ModeFirstUse, f.observation, f.setup.payload)
	require.NoError(t, err)
	require.Equal(t, publicationstate.ModeFirstUse, proposal.Mode)
	require.Equal(t, "first_use", proposal.Stop)
	require.NotEqual(t, [32]byte{}, proposal.StateToken)
	require.NotEqual(t, [32]byte{}, proposal.Confirmation)
	accepted, err := f.home.pubStore.AcceptMaterial(ctx, publicationstate.ModeFirstUse, proposal.StateToken, f.observation, f.setup.payload, proposal.Confirmation)
	require.NoError(t, err)
	return accepted, proposal
}

func TestPublicationIncomingMaterialIntakeDrivesFreshLocalPreview(t *testing.T) {
	ctx := context.Background()
	f := newPublicationIncomingFixture(t)

	accepted, _ := f.acceptFirstUse(t)
	require.Equal(t, uint64(1), accepted.Revision)
	require.Equal(t, uint64(1), accepted.Generation)
	require.Equal(t, publicationstate.ProvenanceFirst, accepted.Provenance)
	require.Equal(t, uint64(0), accepted.Sequence)
	require.Equal(t, f.binding, accepted.Binding)
	require.NotEqual(t, [32]byte{}, accepted.DatabaseID)
	require.NoError(t, f.home.pubStore.Close())

	f.clearSetup()
	f.requireSetupBuffersCleared(t, "no setup buffer may remain as an input oracle")

	reopened := openPublicationMaterialStore(t, f.storeDirectory, f.binding)
	beforeRead := readPublicationMaterialPositionOnlyState(t, reopened)
	require.True(t, reflect.DeepEqual(accepted, beforeRead.floor), "public load must preserve the exact intake floor")
	requirePublicationMaterialPositionOnlyLink(t, beforeRead, f.expectedRecord)
	f.requireLocalFiles(t, publicationReconcileInitial)

	material, err := reopened.ReadAcceptedMaterial(ctx, f.binding, beforeRead.floor)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(beforeRead.floor, material.Floor), "reader floor must match the independently loaded current floor")
	require.True(t, bytes.Equal(f.expectedRecord, material.SnapshotRecord), "reader record must match the assertions-only setup oracle")
	require.True(t, bytes.Equal(f.expectedPayload, material.Payload), "reader payload must match the assertions-only setup oracle")
	f.requireLocalFiles(t, publicationReconcileInitial)
	record, err := publication.DecodeSnapshot(material.SnapshotRecord)
	require.NoError(t, err)
	snapshot, err := publication.DecodePayload(material.Payload, record.Blob)
	require.NoError(t, err)
	require.Equal(t, model.SnapshotVersion, snapshot.Version)
	require.Len(t, snapshot.Targets, 1)
	require.True(t, reflect.DeepEqual(f.portable, snapshot.Targets[0]), "reader snapshot must contain the independently selected target")
	require.Len(t, snapshot.Entries, 1)
	require.NotNil(t, snapshot.Entries[0].File)
	require.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, snapshot.Entries[0].Identity())
	require.Equal(t, model.FileRegular, snapshot.Entries[0].File.Kind)
	require.True(t, bytes.Equal(publicationReconcileInitial, snapshot.Entries[0].File.Content), "reader snapshot must contain the accepted synthetic file bytes")
	require.Equal(t, uint32(0o600), snapshot.Entries[0].File.Mode)

	f.requireSetupBuffersCleared(t, "no setup buffer may remain to supply the service call")
	request := service.PublicationReconciliationRequest{
		Store: reopened, Binding: f.binding, ExpectedFloor: beforeRead.floor,
		SnapshotRecord: bytes.Clone(material.SnapshotRecord), Payload: bytes.Clone(material.Payload),
		Configuration: f.configuration, TargetID: publicationReconcileTargetID,
		Local: newPublicationReconcileContext(t, f.home.paths),
	}

	base, err := service.EstablishLocalReconciliationBase(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, base)
	afterEstablish := readPublicationMaterialPositionOnlyState(t, reopened)
	require.True(t, reflect.DeepEqual(beforeRead, afterEstablish), "base establishment must preserve fresh public publication state")
	f.requireLocalFiles(t, publicationReconcileInitial)

	localEdit := []byte("distinct synthetic local edit\n")
	require.False(t, bytes.Equal(publicationReconcileInitial, localEdit), "the local edit must differ from the accepted base bytes")
	writePublicationReconcileFile(t, filepath.Join(f.home.selected, "settings.ini"), localEdit, 0o600)
	preview, disposition, err := service.PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	require.Equal(t, service.PublicationPreviewBaseEstablished, disposition)
	require.True(t, preview.Complete)
	require.Zero(t, preview.UnresolvedEntries)
	require.Len(t, preview.Targets, 1)
	require.Equal(t, publicationReconcileTargetID, preview.Targets[0].ID)
	require.Len(t, preview.Targets[0].Entries, 1)
	entry := preview.Targets[0].Entries[0]
	require.True(t, entry.Key == (model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}), "preview must identify the selected synthetic file")
	require.Equal(t, syncengine.ActionUpload, entry.DecisionAction)
	require.Equal(t, syncengine.PreviewChange, entry.Action)
	require.Equal(t, syncengine.PreviewReasonLocalChanged, entry.Reason)
	require.Empty(t, entry.State)
	require.Empty(t, entry.Detail)
	require.NotNil(t, entry.Preimage)
	localDigest := sha256.Sum256(localEdit)
	require.True(t, hex.EncodeToString(localDigest[:]) == entry.Preimage.Digest, "preview preimage must match the independent synthetic edit SHA256")
	require.Equal(t, uint32(0o600), entry.Preimage.Mode)
	afterPreview := readPublicationMaterialPositionOnlyState(t, reopened)
	require.True(t, reflect.DeepEqual(beforeRead, afterPreview), "preview must preserve fresh public publication state")
	f.requireLocalFiles(t, localEdit)
}

func TestPublicationIncomingMaterialRefusesTypedInputs(t *testing.T) {
	ctx := context.Background()

	t.Run("unsupported mode", func(t *testing.T) {
		f := newPublicationIncomingFixture(t)
		floor, err := f.home.pubStore.AcceptMaterial(ctx, publicationstate.Mode("bogus"), [32]byte{}, f.observation, f.setup.payload, [32]byte{})
		require.Equal(t, publicationstate.Floor{}, floor)
		requirePublicationIncomingError(t, err, publicationstate.ErrInvalid, publicationstate.StageInput, publicationstate.ReasonMode)
		requirePublicationIncomingNoAcceptedState(t, f.home.pubStore)
		f.requireLocalFiles(t, publicationReconcileInitial)
	})

	t.Run("consumed state token", func(t *testing.T) {
		f := newPublicationIncomingFixture(t)
		accepted, consumed := f.acceptFirstUse(t)
		floor, err := f.home.pubStore.AcceptMaterial(ctx, publicationstate.ModeAdvance, consumed.StateToken, f.observation, f.setup.payload, [32]byte{})
		require.Equal(t, publicationstate.Floor{}, floor)
		requirePublicationIncomingError(t, err, publicationstate.ErrConsent, publicationstate.StageAcceptMaterial, publicationstate.ReasonStale)
		requirePublicationIncomingAcceptedState(t, f.home.pubStore, accepted)
		f.requireLocalFiles(t, publicationReconcileInitial)
	})

	t.Run("custody capacity", func(t *testing.T) {
		f := newPublicationIncomingFixture(t)
		payloadBytes := uint64(len(f.setup.payload))
		options := publicationstate.DefaultOpenOptions()
		require.Greater(t, options.AttemptLimits.CustodyBytes, payloadBytes)
		require.Greater(t, payloadBytes, uint64(1))
		options.AttemptLimits.CustodyBytes = payloadBytes - 1
		storeDirectory := filepath.Join(canonicalPublicationReconcileTempDir(t), "limited-publication-state")
		require.NoError(t, os.Mkdir(storeDirectory, 0o700))
		store, err := publicationstate.OpenWithOptions(storeDirectory, f.binding, options)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		proposal, err := store.Prepare(ctx, publicationstate.ModeFirstUse, f.observation, f.setup.payload)
		require.NoError(t, err)
		floor, err := store.AcceptMaterial(ctx, publicationstate.ModeFirstUse, proposal.StateToken, f.observation, f.setup.payload, proposal.Confirmation)
		require.Equal(t, publicationstate.Floor{}, floor)
		requirePublicationIncomingError(t, err, publicationstate.ErrLimit, publicationstate.StageAcceptMaterial, publicationstate.ReasonCapacity)
		requirePublicationIncomingNoAcceptedState(t, store)
		f.requireLocalFiles(t, publicationReconcileInitial)
	})

	t.Run("missing payload file", func(t *testing.T) {
		f := newPublicationIncomingFixture(t)
		accepted, _ := f.acceptFirstUse(t)
		noOp, err := f.home.pubStore.Prepare(ctx, publicationstate.ModeAdvance, f.observation, f.setup.payload)
		require.NoError(t, err)
		require.Equal(t, "same", noOp.Stop)
		payloadDirectory := filepath.Join(f.storeDirectory, publicationIncomingPayloadDirectory)
		name := publicationIncomingPayloadBasename(t, f.setup.payload)
		require.Equal(t, []string{name}, publicationIncomingDirectoryNames(t, payloadDirectory))
		require.NoError(t, os.Remove(filepath.Join(payloadDirectory, name)))
		floor, err := f.home.pubStore.AcceptMaterial(ctx, publicationstate.ModeAdvance, noOp.StateToken, f.observation, f.setup.payload, [32]byte{})
		require.Equal(t, publicationstate.Floor{}, floor)
		requirePublicationIncomingError(t, err, publicationstate.ErrStorage, publicationstate.StageAcceptMaterial, publicationstate.ReasonMaterialMissing)
		requirePublicationIncomingAcceptedState(t, f.home.pubStore, accepted)
		require.Empty(t, publicationIncomingDirectoryNames(t, payloadDirectory))
		f.requireLocalFiles(t, publicationReconcileInitial)
	})

	t.Run("payload reference mismatch", func(t *testing.T) {
		f := newPublicationIncomingFixture(t)
		mismatched := bytes.Clone(f.setup.payload)
		mismatched[0] ^= 0xff
		require.Len(t, mismatched, len(f.setup.payload))
		floor, err := f.home.pubStore.AcceptMaterial(ctx, publicationstate.ModeFirstUse, [32]byte{0x63}, f.observation, mismatched, [32]byte{})
		require.Equal(t, publicationstate.Floor{}, floor)
		require.ErrorIs(t, err, publication.ErrPayload)
		var violation *publication.Violation
		require.ErrorAs(t, err, &violation)
		var stateError *publicationstate.Error
		require.False(t, errors.As(err, &stateError), "forwarded payload errors must stay in the inherited publication family")
		requirePublicationIncomingNoAcceptedState(t, f.home.pubStore)
		f.requireLocalFiles(t, publicationReconcileInitial)
	})

	t.Run("malformed packed payload", func(t *testing.T) {
		f := newPublicationIncomingFixture(t)
		malformed := []byte("synthetic malformed packed payload bytes\n")
		blobCID, err := publication.RawPayloadCID(malformed)
		require.NoError(t, err)
		blob := publication.BlobReference{CID: blobCID, Size: uint64(len(malformed))}
		require.NoError(t, publication.VerifyPayload(malformed, blob), "the malformed bytes must be referenced exactly by the record")
		record, err := publication.EncodeSnapshot(publication.SnapshotRecord{
			SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault,
			PublicationID: [16]byte{0x62, 0x34, 0x63}, PublicationSeq: 0, Blob: blob,
		})
		require.NoError(t, err)
		recordCID, err := publication.RecordCID(record)
		require.NoError(t, err)
		key, err := publication.SequenceKey(0)
		require.NoError(t, err)
		head, err := publication.EncodeHead(publication.HeadRecord{
			SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault,
			PublicationSeq: 0, SnapshotCID: recordCID, BlobCID: blobCID,
		})
		require.NoError(t, err)
		observation := publicationstate.Observation{
			Origin: f.binding, SuppliedContext: f.observation.SuppliedContext, Head: head,
			Snapshots: []publicationstate.SnapshotBlock{{Key: key, Raw: record}},
		}
		floor, err := f.home.pubStore.AcceptMaterial(ctx, publicationstate.ModeFirstUse, [32]byte{0x63}, observation, malformed, [32]byte{})
		require.Equal(t, publicationstate.Floor{}, floor)
		require.ErrorIs(t, err, vault.ErrInvalidPayload)
		var payloadError *vault.PayloadError
		require.ErrorAs(t, err, &payloadError)
		require.NotEmpty(t, payloadError.Reason)
		var stateError *publicationstate.Error
		require.False(t, errors.As(err, &stateError), "forwarded vault payload errors must stay in the inherited vault family")
		requirePublicationIncomingNoAcceptedState(t, f.home.pubStore)
		f.requireLocalFiles(t, publicationReconcileInitial)
	})
}

func TestPublicationIncomingMaterialReopenPreservesExactFloor(t *testing.T) {
	f := newPublicationIncomingFixture(t)
	accepted, _ := f.acceptFirstUse(t)
	require.Equal(t, uint64(1), accepted.Revision)
	require.Equal(t, uint64(1), accepted.Generation)
	require.Equal(t, publicationstate.ProvenanceFirst, accepted.Provenance)
	require.Equal(t, uint64(0), accepted.Sequence)
	require.NoError(t, f.home.pubStore.Close())

	reopened := openPublicationMaterialStore(t, f.storeDirectory, f.binding)
	ctx := context.Background()
	floor, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.True(t, reflect.DeepEqual(accepted, floor), "graceful close and reopen must persist the exact accepted floor")
	history, err := reopened.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Len(t, history.Events, 1)
	require.True(t, reflect.DeepEqual(floor, history.Events[0].NewFloor), "the single history event must carry the exact reopened floor")
	require.Equal(t, floor.Revision, history.NextRevision)
	afterReopen := readPublicationMaterialPositionOnlyState(t, reopened)
	require.True(t, reflect.DeepEqual(accepted, afterReopen.floor), "public history readback must preserve the exact reopened floor")
	requirePublicationMaterialPositionOnlyLink(t, afterReopen, f.expectedRecord)
	f.requireLocalFiles(t, publicationReconcileInitial)

	material, err := reopened.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(floor, material.Floor), "reader floor must match the exact reopened floor")
	require.True(t, bytes.Equal(f.expectedRecord, material.SnapshotRecord), "reader record must match the assertions-only setup oracle")
	require.True(t, bytes.Equal(f.expectedPayload, material.Payload), "reader payload must match the assertions-only setup oracle")
	f.requireLocalFiles(t, publicationReconcileInitial)

	payloadDirectory := filepath.Join(f.storeDirectory, publicationIncomingPayloadDirectory)
	name := publicationIncomingPayloadBasename(t, f.expectedPayload)
	require.Equal(t, []string{name}, publicationIncomingDirectoryNames(t, payloadDirectory))
	payloadPath := filepath.Join(payloadDirectory, name)
	requirePublicationMaterialFile(t, payloadPath, f.expectedPayload, 0o600)
	require.NoError(t, os.Remove(payloadPath))
	damaged, readErr := reopened.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.True(t, reflect.DeepEqual(publicationstate.AcceptedMaterial{}, damaged), "damaged custody must not yield material for composition")
	requirePublicationIncomingError(t, readErr, publicationstate.ErrStorage, publicationstate.StageReadAcceptedMaterial, publicationstate.ReasonMaterialMissing)
	requirePublicationIncomingAcceptedState(t, reopened, accepted)
	f.requireLocalFiles(t, publicationReconcileInitial)
}

func requirePublicationIncomingError(t *testing.T, err error, class error, stage publicationstate.Stage, reason publicationstate.Reason) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, class)
	var classified *publicationstate.Error
	require.ErrorAs(t, err, &classified)
	require.Equal(t, class, classified.Class())
	require.Equal(t, stage, classified.Stage())
	require.Equal(t, reason, classified.Reason())
}

func requirePublicationIncomingNoAcceptedState(t *testing.T, store *publicationstate.Store) {
	t.Helper()
	ctx := context.Background()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.True(t, reflect.DeepEqual(publicationstate.Floor{}, floor), "a refusal must leave no accepted floor")
	history, err := store.History(ctx, 0, 1)
	require.NoError(t, err)
	require.Empty(t, history.Events)
	require.False(t, history.HasMore)
}

func requirePublicationIncomingAcceptedState(t *testing.T, store *publicationstate.Store, expected publicationstate.Floor) {
	t.Helper()
	ctx := context.Background()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.True(t, reflect.DeepEqual(expected, floor), "a refusal must preserve the exact accepted floor")
	history, err := store.History(ctx, expected.Revision-1, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Len(t, history.Events, 1)
	require.True(t, reflect.DeepEqual(expected, history.Events[0].NewFloor), "a refusal must preserve the exact accepted history")
}

func publicationIncomingPayloadBasename(t *testing.T, payload []byte) string {
	t.Helper()
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]) + ".payload"
}

func publicationIncomingDirectoryNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}
