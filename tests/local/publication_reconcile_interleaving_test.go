package local_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReconcileFloorAdvanceDuringLocalCapture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	target := config.Target{
		ID: publicationReconcileTargetID, Source: model.SourceFiles,
		Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory, Exclude: []string{"machine-only"}},
	}
	portable, err := target.Model()
	require.NoError(t, err)
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, configuration.Validate())

	home := newPublicationReconcileHome(t, publicationReconcileSentinelB)
	selectedPath := filepath.Join(home.selected, "settings.ini")
	writePublicationReconcileFile(t, selectedPath, publicationReconcileInitial, 0o600)
	initialEntries := capturePublicationReconcileSource(t, home, target, publicationReconcileInitial)
	initialSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: initialEntries}
	require.NoError(t, initialSnapshot.Validate())
	binding := publicationReconcileBinding()
	suppliedContext := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	initial := encodePublicationReconcileMaterial(t, binding, initialSnapshot, 0, nil, [16]byte{0x25, 0xa1})
	initialObservation := publicationReconcileObservation(binding, suppliedContext, initial)
	home.floor = acceptPublicationReconcilePosition(t, home.pubStore, publicationstate.ModeFirstUse, initialObservation, initial.payload)
	originalFloor := clonePublicationReconcilePreservationFloor(home.floor)
	originalRecord := bytes.Clone(initial.record)
	originalPayload := bytes.Clone(initial.payload)

	capture := &publicationReconcileInterleavingCapture{
		store: home.pubStore, payload: bytes.Clone(initial.payload),
		observation: publicationstate.Observation{
			Origin: binding, SuppliedContext: suppliedContext,
			Head:      bytes.Clone(initial.head),
			Snapshots: []publicationstate.SnapshotBlock{{Key: initial.key, Raw: bytes.Clone(initial.record)}},
		},
	}
	local, err := service.NewPublicationLocalContext(home.paths, capture, nil)
	require.NoError(t, err)
	home.local = local
	request := publicationReconcileRequest(home, binding, initial, configuration, local)
	base, err := service.EstablishLocalReconciliationBase(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, base)

	control, controlDisposition, err := service.PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, controlDisposition)
	assert.True(t, control.Complete)
	require.Len(t, control.Targets, 1)
	assert.Equal(t, publicationReconcileTargetID, control.Targets[0].ID)
	require.Len(t, control.Targets[0].Entries, 1)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, control.Targets[0].Entries[0].Key)
	assert.Equal(t, syncengine.ActionUnchanged, control.Targets[0].Entries[0].DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonEqual, control.Targets[0].Entries[0].Reason)
	assert.Equal(t, 0, capture.acceptanceCount)
	assert.Empty(t, capture.armedEvents)
	assertPublicationReconcileFile(t, selectedPath, publicationReconcileInitial, 0o600)
	assertPublicationReconcileFile(t, home.sentinel, publicationReconcileSentinelB, 0o640)

	currentRecord, err := publication.DecodeSnapshot(initial.record)
	require.NoError(t, err)
	nextSequence := originalFloor.Sequence + 1
	nextPublicationID := [16]byte{0x25, 0xa2}
	currentRecord.PublicationSeq = nextSequence
	currentRecord.PublicationID = nextPublicationID
	currentRecord.Parent = bytes.Clone(originalFloor.RecordCID)
	nextRecord, err := publication.EncodeSnapshot(currentRecord)
	require.NoError(t, err)
	nextRecordCID, err := publication.RecordCID(nextRecord)
	require.NoError(t, err)
	nextKey, err := publication.SequenceKey(nextSequence)
	require.NoError(t, err)
	nextHead, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: nextSequence,
		SnapshotCID: nextRecordCID, BlobCID: bytes.Clone(originalFloor.BlobCID),
	})
	require.NoError(t, err)
	successor := publicationReconcileMaterial{
		payload: bytes.Clone(originalPayload), key: nextKey, record: nextRecord,
		recordCID: nextRecordCID, head: nextHead,
	}
	successorObservation := publicationReconcileObservation(binding, suppliedContext, successor, initial)
	capture.observation = successorObservation
	capture.armed = true

	preview, disposition, previewErr := service.PreviewPublicationTarget(ctx, request, base)
	capture.armed = false
	require.NoError(t, capture.callbackErr)
	assert.Equal(t, []string{"capture-complete", "prepared", "accepted"}, capture.armedEvents)
	assert.Equal(t, 1, capture.armedCaptureCount)
	assert.Equal(t, 1, capture.prepareCount)
	assert.Equal(t, 1, capture.acceptanceCount)
	assert.Same(t, ctx, capture.advanceContext)
	assert.Equal(t, target, capture.callbackTarget)
	assert.Equal(t, home.selected, capture.callbackPath)
	require.Len(t, capture.captured.Observations, 1)
	captured := capture.captured.Observations[0]
	assert.Equal(t, model.ObservationPresent, captured.State)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, captured.Identity)
	require.NotNil(t, captured.Entry)
	require.NotNil(t, captured.Entry.File)
	assert.Equal(t, publicationReconcileInitial, captured.Entry.File.Content)
	assert.Equal(t, uint32(0o600), captured.Entry.File.Mode)
	require.Len(t, capture.captured.Skipped, 1)
	assert.Equal(t, "machine-only", capture.captured.Skipped[0].Path)
	assert.Equal(t, files.SkipExcluded, capture.captured.Skipped[0].Reason)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	require.ErrorIs(t, previewErr, service.ErrPublicationReconciliation)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, previewErr, &classified)
	assert.Equal(t, "position", classified.Stage())
	assert.Equal(t, "position_changed", classified.Reason())
	assert.Equal(t, originalFloor, request.ExpectedFloor)
	assert.Equal(t, originalRecord, request.SnapshotRecord)
	assert.Equal(t, originalPayload, request.Payload)
	assert.Equal(t, originalPayload, successor.payload)
	assertPublicationReconcileFile(t, selectedPath, publicationReconcileInitial, 0o600)
	assertPublicationReconcileFile(t, home.sentinel, publicationReconcileSentinelB, 0o640)

	acceptedFloor := capture.acceptedFloor
	loadedFloor, present, err := home.pubStore.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, acceptedFloor, loadedFloor)
	assert.NotEqual(t, [32]byte{}, loadedFloor.DatabaseID)
	assert.NotEqual(t, uint64(0), originalFloor.Generation)
	assert.Equal(t, originalFloor.DatabaseID, loadedFloor.DatabaseID)
	assert.Equal(t, originalFloor.Generation, loadedFloor.Generation)
	assert.Equal(t, originalFloor.Revision+1, loadedFloor.Revision)
	assert.Equal(t, originalFloor.Sequence+1, loadedFloor.Sequence)
	assert.NotEqual(t, originalFloor.PublicationID, loadedFloor.PublicationID)
	assert.Equal(t, nextPublicationID, loadedFloor.PublicationID)
	assert.Equal(t, nextKey, loadedFloor.SnapshotKey)
	assert.Equal(t, nextRecordCID, loadedFloor.RecordCID)
	assert.Equal(t, nextHead, loadedFloor.Head)
	assert.Equal(t, originalFloor.BlobCID, loadedFloor.BlobCID)
	assert.Equal(t, originalFloor.BlobSize, loadedFloor.BlobSize)
	assert.NotEqual(t, originalFloor.ObservationDigest, loadedFloor.ObservationDigest)
	assert.Equal(t, originalFloor.SuppliedContext, loadedFloor.SuppliedContext)

	page, err := home.pubStore.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 2)
	assert.False(t, page.HasMore)
	assert.Equal(t, uint64(2), page.NextRevision)
	firstEvent := page.Events[0]
	assert.Equal(t, originalFloor, firstEvent.NewFloor)
	assert.Nil(t, firstEvent.OldFloor)
	assert.Equal(t, firstEvent.NewFloor.AcceptedEventDigest, firstEvent.EventDigest)
	assert.Equal(t, originalFloor.ObservationDigest, firstEvent.ObservationDigest)
	secondEvent := page.Events[1]
	assert.Equal(t, publicationstate.ModeAdvance, secondEvent.Mode)
	assert.Equal(t, "joined", secondEvent.Stop)
	require.NotNil(t, secondEvent.OldFloor)
	assert.Equal(t, originalFloor, *secondEvent.OldFloor)
	assert.Equal(t, loadedFloor, secondEvent.NewFloor)
	assert.Equal(t, secondEvent.NewFloor.AcceptedEventDigest, secondEvent.EventDigest)
	assert.Equal(t, loadedFloor.ObservationDigest, secondEvent.ObservationDigest)
	require.Len(t, firstEvent.Trace, 1)
	assertPublicationReconcileInterleavingTraceHas(t, firstEvent.Trace, initial)
	require.Len(t, secondEvent.Trace, 1)
	assertPublicationReconcileInterleavingTraceHas(t, secondEvent.Trace, successor)
	assertPublicationReconcileInterleavingEvidenceHas(t, page.Records, initial)
	assertPublicationReconcileInterleavingEvidenceHas(t, page.Records, successor)
	assert.Equal(t, originalRecord, initial.record)
	assert.Equal(t, originalPayload, request.Payload)

	refreshedRequest := request
	refreshedRequest.ExpectedFloor = clonePublicationReconcilePreservationFloor(loadedFloor)
	refreshedRequest.SnapshotRecord = bytes.Clone(successor.record)
	refreshedRequest.Payload = bytes.Clone(originalPayload)
	refreshed, refreshedDisposition, err := service.PreviewPublicationTarget(ctx, refreshedRequest, base)
	require.NoError(t, err)
	assert.Equal(t, service.PublicationPreviewBaseEstablished, refreshedDisposition)
	assert.True(t, refreshed.Complete)
	require.Len(t, refreshed.Targets, 1)
	assert.Equal(t, publicationReconcileTargetID, refreshed.Targets[0].ID)
	require.Len(t, refreshed.Targets[0].Entries, 1)
	assert.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, refreshed.Targets[0].Entries[0].Key)
	assert.Equal(t, syncengine.ActionUnchanged, refreshed.Targets[0].Entries[0].DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonEqual, refreshed.Targets[0].Entries[0].Reason)
	assert.Equal(t, 1, capture.acceptanceCount)
	assert.Equal(t, []string{"capture-complete", "prepared", "accepted"}, capture.armedEvents)
	assertPublicationReconcileFile(t, selectedPath, publicationReconcileInitial, 0o600)
	assertPublicationReconcileFile(t, home.sentinel, publicationReconcileSentinelB, 0o640)
}

type publicationReconcileInterleavingCapture struct {
	store             *publicationstate.Store
	payload           []byte
	observation       publicationstate.Observation
	armed             bool
	armedCaptureCount int
	prepareCount      int
	acceptanceCount   int
	armedEvents       []string
	callbackTarget    config.Target
	callbackPath      string
	advanceContext    context.Context
	captured          files.Result
	acceptedFloor     publicationstate.Floor
	callbackErr       error
}

func (capture *publicationReconcileInterleavingCapture) Capture(ctx context.Context, target config.Target, path string) (files.Result, error) {
	result, err := (service.LocalFilesCapture{}).Capture(ctx, target, path)
	if err != nil {
		return files.Result{}, err
	}
	if !capture.armed {
		return result, nil
	}
	capture.armedCaptureCount++
	capture.callbackTarget = target
	capture.callbackPath = path
	capture.advanceContext = ctx
	capture.captured = result
	capture.armedEvents = append(capture.armedEvents, "capture-complete")
	proposal, err := capture.store.Prepare(ctx, publicationstate.ModeAdvance, capture.observation, capture.payload)
	if err != nil {
		capture.callbackErr = err
		return files.Result{}, err
	}
	capture.prepareCount++
	capture.armedEvents = append(capture.armedEvents, "prepared")
	floor, err := capture.store.Accept(ctx, publicationstate.ModeAdvance, proposal.StateToken, capture.observation, capture.payload, proposal.Confirmation)
	if err != nil {
		capture.callbackErr = err
		return files.Result{}, err
	}
	capture.acceptanceCount++
	capture.acceptedFloor = floor
	capture.armedEvents = append(capture.armedEvents, "accepted")
	return result, nil
}

func assertPublicationReconcileInterleavingTraceHas(t *testing.T, trace []publicationstate.RecordReference, material publicationReconcileMaterial) {
	t.Helper()
	sequence, err := publication.ParseSequenceKey(material.key)
	require.NoError(t, err)
	matches := 0
	for _, reference := range trace {
		if reference.Key == material.key && reference.Sequence == sequence && bytes.Equal(reference.CID, material.recordCID) {
			matches++
		}
	}
	assert.Equal(t, 1, matches)
}

func assertPublicationReconcileInterleavingEvidenceHas(t *testing.T, evidence []publicationstate.RecordEvidence, material publicationReconcileMaterial) {
	t.Helper()
	sequence, err := publication.ParseSequenceKey(material.key)
	require.NoError(t, err)
	matches := 0
	for _, record := range evidence {
		if record.Reference.Key == material.key && record.Reference.Sequence == sequence && bytes.Equal(record.Reference.CID, material.recordCID) {
			matches++
			assert.Equal(t, material.record, record.Raw)
		}
	}
	assert.Equal(t, 1, matches)
}
