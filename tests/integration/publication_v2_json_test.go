package integration

import (
	"context"
	"os"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationV2JSONCandidatePreflightLifecycle(t *testing.T) {
	ctx := context.Background()
	packed, err := vault.Pack(model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory}}},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic v2 JSON publication candidate"), Mode: 0o600}}},
	})
	require.NoError(t, err)

	accountDID := "did:plc:abcdefghijklmnopqrstuvwx"
	var vaultID [32]byte
	vaultID[0] = 0x72
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	genesisRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          vaultID,
		PublicationID:  [16]byte{0x51},
		PublicationSeq: 0,
		Parent:         []byte{},
		Blob:           publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))},
	})
	require.NoError(t, err)
	genesisCID, err := publication.RecordCID(genesisRecord)
	require.NoError(t, err)
	genesisHead, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          vaultID,
		PublicationSeq: 0,
		SnapshotCID:    genesisCID,
		BlobCID:        blobCID,
	})
	require.NoError(t, err)
	genesisKey, err := publication.SequenceKey(0)
	require.NoError(t, err)
	genesisObservation := publicationstate.Observation{
		SuppliedContext: publicationstate.SuppliedContext{RepositoryRevision: "synthetic-genesis-revision", RepositoryDigest: []byte{1, 2, 3}},
		Head:            genesisHead,
		Snapshots:       []publicationstate.SnapshotBlock{{Key: genesisKey, Raw: genesisRecord}},
	}

	successorRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          vaultID,
		PublicationID:  [16]byte{0x52},
		PublicationSeq: 1,
		Parent:         genesisCID,
		Blob:           publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))},
	})
	require.NoError(t, err)
	successorCID, err := publication.RecordCID(successorRecord)
	require.NoError(t, err)
	successorHead, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          vaultID,
		PublicationSeq: 1,
		SnapshotCID:    successorCID,
		BlobCID:        blobCID,
	})
	require.NoError(t, err)
	successorKey, err := publication.SequenceKey(1)
	require.NoError(t, err)
	require.NoError(t, publication.VerifySuccessor(genesisRecord, successorRecord, successorKey))
	require.NoError(t, publication.VerifyHeadBinding(successorHead, successorRecord, successorKey))
	candidate := publicationstate.CandidateInput{SnapshotKey: successorKey, SnapshotRecord: successorRecord, HeadRecord: successorHead, Payload: packed.Payload}
	review := publicationstate.LocalReviewContext{SelectionDigest: [32]byte{1}, SelectionRevision: 1, ApprovalDigest: [32]byte{2}, ApprovalRevision: 1}

	bindings := []struct {
		name    string
		binding publicationstate.Binding
		scope   publicationstate.ViewScope
	}{
		{
			name: "synthetic-public-repository",
			binding: publicationstate.Binding{
				AccountDID: accountDID,
				Backend:    publicationstate.BackendPublicRepo,
				Repository: "at://" + accountDID,
				Vault:      vaultID,
			},
			scope: publicationstate.ViewScopeWholeRepository,
		},
		{
			name: "synthetic-spaces-binding",
			binding: publicationstate.Binding{
				AccountDID: accountDID,
				Backend:    publicationstate.BackendSpaces,
				Repository: "at://" + accountDID + "/systems.lamb.dottie.vaultHeadV2/self",
				Vault:      vaultID,
			},
			scope: publicationstate.ViewScopeDedicatedSpace,
		},
	}

	var outputs [2]candidateRecordJSON
	for index, test := range bindings {
		t.Run(test.name, func(t *testing.T) {
			outputs[index] = exerciseCandidateRecordJSONPreflight(t, ctx, packed.Payload, genesisRecord, genesisHead, genesisObservation, candidate, review, test.binding, test.scope)
		})
	}
	assert.Equal(t, outputs[0], outputs[1])
}

type candidateRecordJSON struct {
	snapshot []byte
	head     []byte
}

func exerciseCandidateRecordJSONPreflight(t *testing.T, ctx context.Context, payload, genesisRecord, genesisHead []byte, genesisObservation publicationstate.Observation, candidate publicationstate.CandidateInput, review publicationstate.LocalReviewContext, binding publicationstate.Binding, scope publicationstate.ViewScope) candidateRecordJSON {
	t.Helper()
	contextValue := genesisObservation.SuppliedContext
	contextValue.Policy = nil
	if binding.Backend == publicationstate.BackendSpaces {
		contextValue.Policy = &publicationstate.Policy{Revision: "synthetic-policy-revision", Identity: []byte{4, 5, 6}, OwnerOnly: true}
	}
	genesisObservation.Origin = binding
	genesisObservation.SuppliedContext = contextValue

	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	defer func() {
		if store != nil {
			assert.NoError(t, store.Close())
		}
	}()

	position, err := store.Prepare(ctx, publicationstate.ModeFirstUse, genesisObservation, payload)
	require.NoError(t, err)
	genesisFloor, err := store.Accept(ctx, publicationstate.ModeFirstUse, position.StateToken, genesisObservation, payload, position.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), genesisFloor.Sequence)
	assert.Equal(t, uint64(1), genesisFloor.Generation)

	view := publicationstate.SuppliedRepositoryView{
		Origin:          binding,
		Scope:           scope,
		SuppliedContext: contextValue,
		Head:            genesisHead,
		Snapshots:       []publicationstate.SnapshotBlock{{Key: "0000000000000000", Raw: genesisRecord}},
	}
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptSuccessor, attempt.Kind)
	require.NotNil(t, attempt.CapturedFloor)
	assert.Equal(t, genesisFloor.RecordCID, attempt.CapturedFloor.RecordCID)
	assert.Equal(t, publicationstate.AttemptPrepared, attempt.Lifecycle)

	retained, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidate.SnapshotRecord, retained.SnapshotRecord)
	assert.Equal(t, candidate.HeadRecord, retained.HeadRecord)
	assert.Equal(t, candidate.Payload, retained.Payload)
	beforeFloor, beforeAttempt := loadCandidateJSONState(t, store, attempt.ID)
	preflight := encodeRetainedCandidateRecords(t, retained)
	afterFloor, afterAttempt := loadCandidateJSONState(t, store, attempt.ID)
	assert.Equal(t, beforeFloor, afterFloor)
	assert.Equal(t, beforeAttempt, afterAttempt)

	require.NoError(t, store.Close())
	store = nil
	store, err = publicationstate.Open(directory, binding)
	require.NoError(t, err)
	loadedFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, genesisFloor, loadedFloor)
	loadedAttempt, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptPrepared, loadedAttempt.Lifecycle)
	retained, err = store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidate.SnapshotRecord, retained.SnapshotRecord)
	assert.Equal(t, candidate.HeadRecord, retained.HeadRecord)
	assert.Equal(t, candidate.Payload, retained.Payload)
	beforeFloor, beforeAttempt = loadCandidateJSONState(t, store, attempt.ID)
	reopenedPreflight := encodeRetainedCandidateRecords(t, retained)
	afterFloor, afterAttempt = loadCandidateJSONState(t, store, attempt.ID)
	assert.Equal(t, beforeFloor, afterFloor)
	assert.Equal(t, beforeAttempt, afterAttempt)
	assert.Equal(t, preflight, reopenedPreflight)

	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchUpload, view, review)
	require.NoError(t, err)
	upload, err := store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, payload, upload.Payload)
	uploadedAttempt, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptUploadStarted, uploadedAttempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeNotSubmitted, uploadedAttempt.Outcome)

	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchSubmission, view, review)
	require.NoError(t, err)
	submission, err := store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, attempt.ID, submission.AttemptID)
	assert.Equal(t, candidate.SnapshotRecord, submission.SnapshotRecord)
	assert.Equal(t, candidate.HeadRecord, submission.HeadRecord)
	assert.Equal(t, candidate.SnapshotKey, submission.SnapshotKey)
	assert.Equal(t, contextValue, submission.ExpectedContext)
	assert.Equal(t, publication.SnapshotNSID, submission.SnapshotCollection)
	assert.Equal(t, publication.HeadNSID, submission.HeadCollection)
	assert.Equal(t, "self", submission.HeadKey)
	assert.True(t, submission.SnapshotCreateOnly)
	assert.False(t, submission.HeadCreate)
	assert.True(t, submission.RequiresAtomicBatch)
	assert.True(t, submission.RequiresCreateExclude)
	assert.Equal(t, binding.Backend == publicationstate.BackendSpaces, submission.RequiresPolicyCheck)
	require.NotNil(t, submission.ExpectedPredecessor)
	assert.Equal(t, "0000000000000000", submission.ExpectedPredecessor.Key)
	assert.Equal(t, genesisFloor.RecordCID, submission.ExpectedPredecessor.CID)
	assert.Equal(t, uint64(0), submission.ExpectedPredecessor.Sequence)

	reconstructedSnapshot := reconstructCandidateRecordJSON(t, preflight.snapshot)
	reconstructedHead := reconstructCandidateRecordJSON(t, preflight.head)
	assert.Equal(t, submission.SnapshotRecord, reconstructedSnapshot)
	assert.Equal(t, submission.HeadRecord, reconstructedHead)
	expectedCID, err := publication.RecordCID(submission.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, expectedCID, submission.ExpectedSnapshotCID)
	preflightCID, err := publication.RecordCID(reconstructedSnapshot)
	require.NoError(t, err)
	assert.Equal(t, submission.ExpectedSnapshotCID, preflightCID)
	require.NoError(t, publication.VerifySuccessor(genesisRecord, submission.SnapshotRecord, submission.SnapshotKey))
	require.NoError(t, publication.VerifyHeadBinding(submission.HeadRecord, submission.SnapshotRecord, submission.SnapshotKey))

	submittedAttempt, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, submittedAttempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeUnresolved, submittedAttempt.Outcome)
	finalFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, genesisFloor, finalFloor)

	return reopenedPreflight
}

func loadCandidateJSONState(t *testing.T, store *publicationstate.Store, attemptID [16]byte) (publicationstate.Floor, publicationstate.Attempt) {
	t.Helper()
	floor, present, err := store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	attempt, err := store.LoadAttempt(context.Background(), attemptID)
	require.NoError(t, err)
	return floor, attempt
}

func encodeRetainedCandidateRecords(t *testing.T, retained publicationstate.CandidateMaterial) candidateRecordJSON {
	t.Helper()
	snapshotJSON, err := publication.RecordToJSON(retained.SnapshotRecord)
	require.NoError(t, err)
	headJSON, err := publication.RecordToJSON(retained.HeadRecord)
	require.NoError(t, err)
	snapshotCBOR := reconstructCandidateRecordJSON(t, snapshotJSON)
	headCBOR := reconstructCandidateRecordJSON(t, headJSON)
	assert.Equal(t, retained.SnapshotRecord, snapshotCBOR)
	assert.Equal(t, retained.HeadRecord, headCBOR)
	snapshotCID, err := publication.RecordCID(snapshotCBOR)
	require.NoError(t, err)
	snapshot, err := publication.DecodeSnapshot(snapshotCBOR)
	require.NoError(t, err)
	head, err := publication.DecodeHead(headCBOR)
	require.NoError(t, err)
	assert.Equal(t, retained.Blob.CID, snapshot.Blob.CID)
	assert.Equal(t, snapshotCID, head.SnapshotCID)
	assert.Equal(t, retained.Blob.CID, head.BlobCID)
	assert.NotEqual(t, snapshotCID, snapshot.Blob.CID)
	return candidateRecordJSON{snapshot: snapshotJSON, head: headJSON}
}

func reconstructCandidateRecordJSON(t *testing.T, encoded []byte) []byte {
	t.Helper()
	object, err := atdata.UnmarshalJSON(encoded)
	require.NoError(t, err)
	reconstructed, err := atdata.MarshalCBOR(object)
	require.NoError(t, err)
	return reconstructed
}
