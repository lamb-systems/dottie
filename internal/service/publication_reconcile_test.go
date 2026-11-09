package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type acceptedMaterialTestFixture struct {
	store     *publicationstate.Store
	directory string
	request   acceptedPublicationRequest
}

func newAcceptedMaterialTestFixture(t *testing.T, backend publicationstate.Backend) acceptedMaterialTestFixture {
	t.Helper()
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
		Backend:    backend,
		Vault:      [32]byte{0x41, 0x52, 0x63},
	}
	binding.Repository = "at://" + binding.AccountDID
	if backend == publicationstate.BackendSpaces {
		binding.Repository += "/systems.lamb.dottie.vaultSnapshotV2/record"
	}
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID:            "synthetic-files",
			Source:        model.SourceFiles,
			SourceVersion: model.SourceVersion,
			Root:          &model.FileRoot{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory},
		}},
		Entries: []model.Entry{{
			TargetID: "synthetic-files",
			File:     &model.FileEntry{Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic accepted publication"), Mode: 0o600},
		}},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion,
		Vault:         binding.Vault,
		PublicationID: [16]byte{0x25, 0x71},
		Parent:        []byte{},
		Blob:          publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))},
	}
	recordRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(recordRaw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: 0,
		SnapshotCID:    recordCID,
		BlobCID:        blobCID,
	})
	require.NoError(t, err)
	contextValue := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	if backend == publicationstate.BackendSpaces {
		contextValue.Policy = &publicationstate.Policy{Revision: "synthetic-policy", Identity: []byte{4, 5, 6}, OwnerOnly: true}
	}
	observation := publicationstate.Observation{
		Origin:          binding,
		SuppliedContext: contextValue,
		Head:            head,
		Snapshots:       []publicationstate.SnapshotBlock{{Key: "0000000000000000", Raw: bytes.Clone(recordRaw)}},
	}
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	proposal, err := store.Prepare(context.Background(), publicationstate.ModeFirstUse, observation, packed.Payload)
	require.NoError(t, err)
	floor, err := store.Accept(context.Background(), publicationstate.ModeFirstUse, proposal.StateToken, observation, packed.Payload, proposal.Confirmation)
	require.NoError(t, err)
	return acceptedMaterialTestFixture{
		store:     store,
		directory: directory,
		request: acceptedPublicationRequest{
			store:          store,
			binding:        binding,
			expectedFloor:  cloneServiceTestFloor(floor),
			snapshotRecord: bytes.Clone(recordRaw),
			payload:        bytes.Clone(packed.Payload),
		},
	}
}

func cloneServiceTestFloor(floor publicationstate.Floor) publicationstate.Floor {
	out := floor
	out.AnchorCID = bytes.Clone(floor.AnchorCID)
	out.SuppliedContext.RepositoryDigest = bytes.Clone(floor.SuppliedContext.RepositoryDigest)
	if floor.SuppliedContext.Policy != nil {
		policy := *floor.SuppliedContext.Policy
		policy.Identity = bytes.Clone(policy.Identity)
		out.SuppliedContext.Policy = &policy
	}
	out.Head = bytes.Clone(floor.Head)
	out.RecordCID = bytes.Clone(floor.RecordCID)
	out.BlobCID = bytes.Clone(floor.BlobCID)
	return out
}

func cloneAcceptedMaterialTestRequest(request acceptedPublicationRequest) acceptedPublicationRequest {
	out := request
	out.expectedFloor = cloneServiceTestFloor(request.expectedFloor)
	out.snapshotRecord = bytes.Clone(request.snapshotRecord)
	out.payload = bytes.Clone(request.payload)
	return out
}

func assertPublicationReconciliationError(t *testing.T, err error, stage, reason string) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublicationReconciliation)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, stage, classified.Stage())
	assert.Equal(t, reason, classified.Reason())
}

func TestValidateAcceptedPublicationMaterialForSyntheticBindings(t *testing.T) {
	for _, backend := range []publicationstate.Backend{publicationstate.BackendPublicRepo, publicationstate.BackendSpaces} {
		t.Run(string(backend), func(t *testing.T) {
			fixture := newAcceptedMaterialTestFixture(t, backend)
			result, err := validateAcceptedPublication(context.Background(), fixture.request)
			require.NoError(t, err)
			assert.Equal(t, fixture.request.expectedFloor, result.floor)
			assert.Equal(t, model.SnapshotVersion, result.snapshot.Version)
			require.Len(t, result.snapshot.Entries, 1)
			require.NotNil(t, result.snapshot.Entries[0].File)
			assert.Equal(t, []byte("synthetic accepted publication"), result.snapshot.Entries[0].File.Content)
		})
	}
}

func TestValidateAcceptedPublicationMaterialRefusesMissingAndUnavailableState(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	request := cloneAcceptedMaterialTestRequest(fixture.request)

	assertion := acceptedPublicationMaterial{}
	result, err := validateAcceptedPublication(context.Background(), acceptedPublicationRequest{})
	require.Error(t, err)
	assert.Equal(t, assertion, result)
	assertPublicationReconciliationError(t, err, "input", "request_invalid")

	nilStoreRequest := cloneAcceptedMaterialTestRequest(fixture.request)
	nilStoreRequest.store = nil
	result, err = validateAcceptedPublication(context.Background(), nilStoreRequest)
	require.Error(t, err)
	assert.Equal(t, assertion, result)
	assertPublicationReconciliationError(t, err, "input", "request_invalid")

	emptyDirectory := t.TempDir()
	require.NoError(t, os.Chmod(emptyDirectory, 0o700))
	emptyStore, err := publicationstate.Open(emptyDirectory, request.binding)
	require.NoError(t, err)
	defer func() { assert.NoError(t, emptyStore.Close()) }()
	request.store = emptyStore
	result, err = validateAcceptedPublication(context.Background(), request)
	require.Error(t, err)
	assert.Equal(t, assertion, result)
	assertPublicationReconciliationError(t, err, "load", "no_floor")

	request.store = fixture.store
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = validateAcceptedPublication(cancelled, request)
	require.Error(t, err)
	assert.Equal(t, assertion, result)
	require.ErrorIs(t, err, context.Canceled)
	assertPublicationReconciliationError(t, err, "input", "canceled")

	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	result, err = validateAcceptedPublication(deadline, request)
	require.Error(t, err)
	assert.Equal(t, assertion, result)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assertPublicationReconciliationError(t, err, "input", "canceled")

	closedDirectory := t.TempDir()
	require.NoError(t, os.Chmod(closedDirectory, 0o700))
	closedStore, err := publicationstate.Open(closedDirectory, request.binding)
	require.NoError(t, err)
	request.store = closedStore
	require.NoError(t, closedStore.Close())
	result, err = validateAcceptedPublication(context.Background(), request)
	require.Error(t, err)
	assert.Equal(t, assertion, result)
	assertPublicationReconciliationError(t, err, "load", "unavailable")
}

func TestValidateAcceptedPublicationMaterialChecksBindingAndWholeFloor(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	ctx := context.Background()
	wrongBindings := []struct {
		name   string
		change func(*publicationstate.Binding)
	}{
		{name: "account", change: func(binding *publicationstate.Binding) { binding.AccountDID = "did:plc:zyxwvutsrqponmlkjihgfedc" }},
		{name: "backend", change: func(binding *publicationstate.Binding) { binding.Backend = publicationstate.BackendSpaces }},
		{name: "repository", change: func(binding *publicationstate.Binding) { binding.Repository += "/other" }},
		{name: "vault", change: func(binding *publicationstate.Binding) { binding.Vault[0] ^= 0x80 }},
	}
	for _, test := range wrongBindings {
		t.Run(test.name, func(t *testing.T) {
			request := cloneAcceptedMaterialTestRequest(fixture.request)
			test.change(&request.binding)
			result, err := validateAcceptedPublication(ctx, request)
			require.Error(t, err)
			assert.Equal(t, acceptedPublicationMaterial{}, result)
			assertPublicationReconciliationError(t, err, "position", "binding_mismatch")
		})
	}

	wrongFloors := []struct {
		name   string
		change func(*publicationstate.Floor)
	}{
		{name: "event_digest", change: func(floor *publicationstate.Floor) { floor.AcceptedEventDigest[0] ^= 1 }},
		{name: "observation_digest", change: func(floor *publicationstate.Floor) { floor.ObservationDigest[0] ^= 1 }},
		{name: "context", change: func(floor *publicationstate.Floor) { floor.SuppliedContext.RepositoryRevision += "x" }},
		{name: "provenance", change: func(floor *publicationstate.Floor) { floor.Provenance = publicationstate.ProvenanceReplace }},
		{name: "anchor", change: func(floor *publicationstate.Floor) { floor.AnchorCID[0] ^= 1 }},
		{name: "snapshot_key", change: func(floor *publicationstate.Floor) { floor.SnapshotKey = "0000000000000001" }},
		{name: "record_identity", change: func(floor *publicationstate.Floor) { floor.RecordCID[0] ^= 1 }},
		{name: "database_id", change: func(floor *publicationstate.Floor) { floor.DatabaseID[0] ^= 1 }},
		{name: "generation", change: func(floor *publicationstate.Floor) { floor.Generation++ }},
	}
	for _, test := range wrongFloors {
		t.Run(test.name, func(t *testing.T) {
			request := cloneAcceptedMaterialTestRequest(fixture.request)
			test.change(&request.expectedFloor)
			result, err := validateAcceptedPublication(ctx, request)
			require.Error(t, err)
			assert.Equal(t, acceptedPublicationMaterial{}, result)
			assertPublicationReconciliationError(t, err, "position", "floor_mismatch")
		})
	}
}

func TestValidateAcceptedPublicationMaterialRefusesRecordAndPayloadSubstitution(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	canary := "private-record-canary"
	acceptedSnapshot, err := publication.DecodePayload(fixture.request.payload, publication.BlobReference{CID: fixture.request.expectedFloor.BlobCID, Size: fixture.request.expectedFloor.BlobSize})
	require.NoError(t, err)
	require.Len(t, acceptedSnapshot.Entries, 1)
	require.NotNil(t, acceptedSnapshot.Entries[0].File)
	alternateSnapshot, err := publication.DecodePayload(fixture.request.payload, publication.BlobReference{CID: fixture.request.expectedFloor.BlobCID, Size: fixture.request.expectedFloor.BlobSize})
	require.NoError(t, err)
	require.Len(t, alternateSnapshot.Entries, 1)
	require.NotNil(t, alternateSnapshot.Entries[0].File)
	alternateContent := []byte("synthetic rejected publication")
	require.Equal(t, len(acceptedSnapshot.Entries[0].File.Content), len(alternateContent))
	require.NotEqual(t, acceptedSnapshot.Entries[0].File.Content, alternateContent)
	alternateSnapshot.Entries[0].File.Content = bytes.Clone(alternateContent)
	alternatePacked, err := vault.Pack(alternateSnapshot)
	require.NoError(t, err)
	require.NotEqual(t, fixture.request.payload, alternatePacked.Payload)
	require.Equal(t, len(fixture.request.payload), len(alternatePacked.Payload))
	alternateCID, err := publication.RawPayloadCID(alternatePacked.Payload)
	require.NoError(t, err)
	decodedAlternate, err := publication.DecodePayload(alternatePacked.Payload, publication.BlobReference{CID: alternateCID, Size: uint64(len(alternatePacked.Payload))})
	require.NoError(t, err)
	require.Len(t, decodedAlternate.Entries, 1)
	require.NotNil(t, decodedAlternate.Entries[0].File)
	require.Equal(t, alternateContent, decodedAlternate.Entries[0].File.Content)
	require.NotEqual(t, acceptedSnapshot.Entries[0].File.Content, decodedAlternate.Entries[0].File.Content)
	alternatePayload := bytes.Clone(alternatePacked.Payload)

	mutations := []struct {
		name   string
		stage  string
		reason string
		change func(*testing.T, *acceptedPublicationRequest)
	}{
		{
			name:   "different_canonical_record",
			stage:  "history",
			reason: "evidence_mismatch",
			change: func(testT *testing.T, request *acceptedPublicationRequest) {
				record, err := publication.DecodeSnapshot(request.snapshotRecord)
				require.NoError(testT, err)
				record.PublicationID[0] ^= 0x80
				request.snapshotRecord, err = publication.EncodeSnapshot(record)
				require.NoError(testT, err)
			},
		},
		{
			name: "malformed_record", stage: "history", reason: "evidence_mismatch",
			change: func(_ *testing.T, request *acceptedPublicationRequest) { request.snapshotRecord = []byte(canary) },
		},
		{
			name: "oversized_record", stage: "input", reason: "request_invalid",
			change: func(_ *testing.T, request *acceptedPublicationRequest) {
				request.snapshotRecord = bytes.Repeat([]byte{0x44}, publication.MaxRecordBytes+1)
			},
		},
		{
			name: "missing_payload", stage: "input", reason: "request_invalid",
			change: func(_ *testing.T, request *acceptedPublicationRequest) { request.payload = nil },
		},
		{
			name: "same_size_corrupted_payload", stage: "payload", reason: "payload_invalid",
			change: func(_ *testing.T, request *acceptedPublicationRequest) { request.payload[0] ^= 1 },
		},
		{
			name: "record_payload_mismatch", stage: "payload", reason: "payload_invalid",
			change: func(_ *testing.T, request *acceptedPublicationRequest) {
				request.payload = bytes.Clone(alternatePayload)
			},
		},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			request := cloneAcceptedMaterialTestRequest(fixture.request)
			test.change(t, &request)
			if test.name == "record_payload_mismatch" {
				assert.Equal(t, fixture.request.snapshotRecord, request.snapshotRecord)
				assert.Equal(t, fixture.request.expectedFloor, request.expectedFloor)
				assert.Equal(t, fixture.request.binding, request.binding)
			}
			result, err := validateAcceptedPublication(context.Background(), request)
			require.Error(t, err)
			assert.Equal(t, acceptedPublicationMaterial{}, result)
			assertPublicationReconciliationError(t, err, test.stage, test.reason)
			assert.NotContains(t, err.Error(), canary)
			assert.NotContains(t, err.Error(), string(request.snapshotRecord))
		})
	}
}

func TestValidateAcceptedPublicationMaterialDetachesInputsAndOutputs(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	request := cloneAcceptedMaterialTestRequest(fixture.request)
	originalRecord := bytes.Clone(request.snapshotRecord)
	originalPayload := bytes.Clone(request.payload)
	originalFloor := cloneServiceTestFloor(request.expectedFloor)
	first, err := validateAcceptedPublication(context.Background(), request)
	require.NoError(t, err)
	require.Len(t, first.snapshot.Entries, 1)
	require.NotNil(t, first.snapshot.Entries[0].File)

	request.snapshotRecord[0] ^= 1
	request.payload[0] ^= 1
	request.expectedFloor.Head[0] ^= 1
	assert.Equal(t, originalFloor, first.floor)
	assert.Equal(t, []byte("synthetic accepted publication"), first.snapshot.Entries[0].File.Content)

	cleanRequest := cloneAcceptedMaterialTestRequest(fixture.request)
	cleanRecord := bytes.Clone(cleanRequest.snapshotRecord)
	cleanPayload := bytes.Clone(cleanRequest.payload)
	second, err := validateAcceptedPublication(context.Background(), cleanRequest)
	require.NoError(t, err)
	require.Len(t, second.snapshot.Entries, 1)
	require.NotNil(t, second.snapshot.Entries[0].File)
	first.floor.Head[0] ^= 1
	first.snapshot.Entries[0].File.Content[0] ^= 1
	assert.Equal(t, cleanRecord, cleanRequest.snapshotRecord)
	assert.Equal(t, cleanPayload, cleanRequest.payload)
	assert.Equal(t, originalRecord, fixture.request.snapshotRecord)
	assert.Equal(t, originalPayload, fixture.request.payload)
	assert.Equal(t, originalFloor, second.floor)
	assert.Equal(t, []byte("synthetic accepted publication"), second.snapshot.Entries[0].File.Content)
	stored, present, err := fixture.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, originalFloor, stored)
}

func TestValidateAcceptedPublicationMaterialDoesNotPersistChanges(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	ctx := context.Background()
	beforeFloor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	beforeHistory, err := fixture.store.History(ctx, 0, 10)
	require.NoError(t, err)
	_, err = validateAcceptedPublication(ctx, fixture.request)
	require.NoError(t, err)
	afterFloor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	afterHistory, err := fixture.store.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, beforeFloor, afterFloor)
	assert.Equal(t, beforeHistory, afterHistory)
}

func TestValidateAcceptedPublicationMaterialAcrossSequentialAdvanceAndReopen(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	ctx := context.Background()
	require.NoError(t, checkAcceptedPublicationFloor(ctx, fixture.store, fixture.request.expectedFloor))

	oldRecord, err := publication.DecodeSnapshot(fixture.request.snapshotRecord)
	require.NoError(t, err)
	parentCID, err := publication.RecordCID(fixture.request.snapshotRecord)
	require.NoError(t, err)
	oldRecord.PublicationSeq = 1
	oldRecord.Parent = bytes.Clone(parentCID)
	oldRecord.PublicationID[15]++
	successorRaw, err := publication.EncodeSnapshot(oldRecord)
	require.NoError(t, err)
	successorCID, err := publication.RecordCID(successorRaw)
	require.NoError(t, err)
	successorKey, err := publication.SequenceKey(1)
	require.NoError(t, err)
	successorHead, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          fixture.request.binding.Vault,
		PublicationSeq: 1,
		SnapshotCID:    successorCID,
		BlobCID:        bytes.Clone(fixture.request.expectedFloor.BlobCID),
	})
	require.NoError(t, err)
	observation := publicationstate.Observation{
		Origin:          fixture.request.binding,
		SuppliedContext: fixture.request.expectedFloor.SuppliedContext,
		Head:            successorHead,
		Snapshots: []publicationstate.SnapshotBlock{
			{Key: fixture.request.expectedFloor.SnapshotKey, Raw: bytes.Clone(fixture.request.snapshotRecord)},
			{Key: successorKey, Raw: successorRaw},
		},
	}
	proposal, err := fixture.store.Prepare(ctx, publicationstate.ModeAdvance, observation, fixture.request.payload)
	require.NoError(t, err)
	successorFloor, err := fixture.store.Accept(ctx, publicationstate.ModeAdvance, proposal.StateToken, observation, fixture.request.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, fixture.request.expectedFloor.DatabaseID, successorFloor.DatabaseID)
	assert.Equal(t, fixture.request.expectedFloor.Generation, successorFloor.Generation)

	page, err := fixture.store.History(ctx, fixture.request.expectedFloor.Revision, 1)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.Equal(t, publicationstate.ModeAdvance, page.Events[0].Mode)
	require.NotNil(t, page.Events[0].OldFloor)
	assert.Equal(t, fixture.request.expectedFloor, *page.Events[0].OldFloor)
	assert.False(t, page.HasMore)
	assert.Equal(t, successorFloor, page.Events[0].NewFloor)
	require.Len(t, page.Records, 2)
	assert.ElementsMatch(t, []publicationstate.RecordEvidence{
		{
			Reference: publicationstate.RecordReference{Key: fixture.request.expectedFloor.SnapshotKey, CID: bytes.Clone(parentCID), Sequence: fixture.request.expectedFloor.Sequence},
			Raw:       bytes.Clone(fixture.request.snapshotRecord),
		},
		{
			Reference: publicationstate.RecordReference{Key: successorKey, CID: bytes.Clone(successorCID), Sequence: 1},
			Raw:       bytes.Clone(successorRaw),
		},
	}, page.Records)
	successorRequest := cloneAcceptedMaterialTestRequest(fixture.request)
	successorRequest.expectedFloor = cloneServiceTestFloor(successorFloor)
	successorRequest.snapshotRecord = bytes.Clone(successorRaw)
	successorResult, err := validateAcceptedPublication(ctx, successorRequest)
	require.NoError(t, err)
	assert.Equal(t, successorFloor, successorResult.floor)
	require.Len(t, successorResult.snapshot.Entries, 1)
	require.NotNil(t, successorResult.snapshot.Entries[0].File)
	assert.Equal(t, []byte("synthetic accepted publication"), successorResult.snapshot.Entries[0].File.Content)

	oldResult, err := validateAcceptedPublication(ctx, fixture.request)
	require.Error(t, err)
	assert.Equal(t, acceptedPublicationMaterial{}, oldResult)
	assertPublicationReconciliationError(t, err, "position", "floor_mismatch")
	err = checkAcceptedPublicationFloor(ctx, fixture.store, fixture.request.expectedFloor)
	require.Error(t, err)
	assertPublicationReconciliationError(t, err, "position", "position_changed")

	require.NoError(t, fixture.store.Close())
	reopened, err := publicationstate.Open(fixture.directory, fixture.request.binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	successorRequest.store = reopened
	reopenedResult, err := validateAcceptedPublication(ctx, successorRequest)
	require.NoError(t, err)
	assert.Equal(t, successorFloor, reopenedResult.floor)
	require.Len(t, reopenedResult.snapshot.Entries, 1)
	require.NotNil(t, reopenedResult.snapshot.Entries[0].File)
	assert.Equal(t, []byte("synthetic accepted publication"), reopenedResult.snapshot.Entries[0].File.Content)
}

func TestCheckAcceptedPublicationFloorRejectsNilAndMalformedRequests(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	var nilStore *publicationstate.Store
	err := checkAcceptedPublicationFloor(context.Background(), nilStore, fixture.request.expectedFloor)
	require.Error(t, err)
	assertPublicationReconciliationError(t, err, "input", "request_invalid")

	oversized := cloneServiceTestFloor(fixture.request.expectedFloor)
	oversized.Head = bytes.Repeat([]byte{0x55}, publication.MaxRecordBytes+1)
	err = checkAcceptedPublicationFloor(context.Background(), fixture.store, oversized)
	require.Error(t, err)
	assertPublicationReconciliationError(t, err, "input", "request_invalid")

	result, err := validateAcceptedPublication(context.Background(), acceptedPublicationRequest{
		store:          fixture.store,
		binding:        fixture.request.binding,
		expectedFloor:  cloneServiceTestFloor(fixture.request.expectedFloor),
		snapshotRecord: bytes.Clone(fixture.request.snapshotRecord),
		payload:        bytes.Clone(fixture.request.payload),
	})
	require.NoError(t, err)
	assert.NotEqual(t, acceptedPublicationMaterial{}, result)
}

func TestPublicationReconciliationErrorsRemainClosed(t *testing.T) {
	fixture := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	request := cloneAcceptedMaterialTestRequest(fixture.request)
	request.payload[0] ^= 1
	result, err := validateAcceptedPublication(context.Background(), request)
	require.Error(t, err)
	assert.Equal(t, acceptedPublicationMaterial{}, result)
	assert.True(t, errors.Is(err, ErrPublicationReconciliation))
	assert.NotContains(t, err.Error(), fixture.request.binding.AccountDID)
	assert.NotContains(t, err.Error(), fixture.request.binding.Repository)
	assert.NotContains(t, err.Error(), "synthetic accepted publication")
}
