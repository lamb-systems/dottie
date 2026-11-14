package service

import (
	"bytes"
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
)

var ErrPublishMaterial = errors.New("publication material refused")

type publishMaterialStage string
type publishMaterialReason string

type publishMaterialError struct {
	stage  publishMaterialStage
	reason publishMaterialReason
	cause  error
}

func (e *publishMaterialError) Error() string {
	return "publication material: " + string(e.stage) + "/" + string(e.reason)
}

func (e *publishMaterialError) Is(target error) bool { return target == ErrPublishMaterial }
func (e *publishMaterialError) Unwrap() error        { return e.cause }
func (e *publishMaterialError) Stage() string        { return string(e.stage) }
func (e *publishMaterialError) Reason() string       { return string(e.reason) }

const (
	publishMaterialStageInput      publishMaterialStage = "input"
	publishMaterialStagePosition   publishMaterialStage = "position"
	publishMaterialStageView       publishMaterialStage = "view"
	publishMaterialStageBatch      publishMaterialStage = "batch"
	publishMaterialStageConsent    publishMaterialStage = "consent"
	publishMaterialStageUpload     publishMaterialStage = "upload"
	publishMaterialStageSubmission publishMaterialStage = "submission"
	publishMaterialStageOutcome    publishMaterialStage = "outcome"

	publishMaterialReasonRequestInvalid publishMaterialReason = "request_invalid"
	publishMaterialReasonCanceled       publishMaterialReason = "canceled"
	publishMaterialReasonPosition       publishMaterialReason = "position_invalid"
	publishMaterialReasonView           publishMaterialReason = "view_invalid"
	publishMaterialReasonObservation    publishMaterialReason = "observation_stale"
	publishMaterialReasonBatch          publishMaterialReason = "batch_invalid"
	publishMaterialReasonConfirmation   publishMaterialReason = "confirmation_mismatch"
	publishMaterialReasonBlob           publishMaterialReason = "blob_mismatch"
	publishMaterialReasonSubmission     publishMaterialReason = "submission_mismatch"
	publishMaterialReasonUpload         publishMaterialReason = "upload_failed"
	publishMaterialReasonUnresolved     publishMaterialReason = "submission_unresolved"
	publishMaterialReasonOutcome        publishMaterialReason = "outcome_not_current"
)

const materialHeadKey = "self"

type MaterialTransport interface {
	UploadPayload(ctx context.Context, payload []byte) (publication.BlobReference, error)
	ApplyWrites(ctx context.Context, batch MaterialWriteBatch) (MaterialWriteOutcome, error)
	ReadView(ctx context.Context) (publicationstate.SuppliedRepositoryView, error)
}

type MaterialWriteBatch struct {
	SnapshotCollection    string
	SnapshotKey           string
	SnapshotRecord        []byte
	ExpectedSnapshotCID   []byte
	SnapshotCreateOnly    bool
	HeadCollection        string
	HeadKey               string
	HeadRecord            []byte
	HeadCreate            bool
	ExpectedPredecessor   *publicationstate.RecordReference
	ExpectedContext       publicationstate.SuppliedContext
	RequiresAtomicBatch   bool
	RequiresCreateExclude bool
	RequiresPolicyCheck   bool
}

type MaterialWriteOutcome struct {
	Committed bool
}

type MaterialPublishRequest struct {
	Store         *publicationstate.Store
	Transport     MaterialTransport
	Binding       publicationstate.Binding
	Snapshot      model.Snapshot
	PublicationID [16]byte
	Review        publicationstate.LocalReviewContext
}

type MaterialPublishProposal struct {
	Store        *publicationstate.Store
	Transport    MaterialTransport
	Binding      publicationstate.Binding
	Review       publicationstate.LocalReviewContext
	View         publicationstate.SuppliedRepositoryView
	Candidate    publicationstate.CandidateInput
	Proposal     publicationstate.AttemptProposal
	Batch        MaterialWriteBatch
	Blob         publication.BlobReference
	Confirmation [32]byte
}

type MaterialPublishResult struct {
	Floor   publicationstate.Floor
	Attempt publicationstate.Attempt
	Outcome publicationstate.AttemptOutcome
}

func (coordinator *Coordinator) PreparePublishMaterial(ctx context.Context, request MaterialPublishRequest) (MaterialPublishProposal, error) {
	if err := coordinator.lock(ctx); err != nil {
		return MaterialPublishProposal{}, err
	}
	defer coordinator.mu.Unlock()
	if !validMaterialPublishRequest(request) {
		return MaterialPublishProposal{}, publishMaterialFailure(ctx, publishMaterialStageInput, publishMaterialReasonRequestInvalid, nil)
	}
	if err := ctx.Err(); err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(ctx, publishMaterialStageInput, publishMaterialReasonCanceled, err)
	}
	floor, present, err := request.Store.Load(ctx)
	if err != nil {
		return MaterialPublishProposal{}, err
	}
	if present && floor.Binding != request.Binding {
		return MaterialPublishProposal{}, publishMaterialFailure(ctx, publishMaterialStagePosition, publishMaterialReasonPosition, nil)
	}
	view, err := request.Transport.ReadView(ctx)
	if err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(ctx, publishMaterialStageView, publishMaterialReasonView, err)
	}
	if view.Origin != request.Binding {
		return MaterialPublishProposal{}, publishMaterialFailure(ctx, publishMaterialStageView, publishMaterialReasonView, nil)
	}
	candidate, blob, err := newMaterialCandidate(request, floor, present)
	if err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(ctx, publishMaterialStageBatch, publishMaterialReasonBatch, err)
	}
	var captured *publicationstate.Floor
	if present {
		cloned := cloneMaterialFloor(floor)
		captured = &cloned
	}
	batch, err := newMaterialWriteBatch(request.Binding, captured, view, candidate)
	if err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(ctx, publishMaterialStageBatch, publishMaterialReasonBatch, err)
	}
	attemptProposal, err := request.Store.PrepareAttempt(ctx, candidate, view, request.Review)
	if err != nil {
		return MaterialPublishProposal{}, err
	}
	return MaterialPublishProposal{
		Store: request.Store, Transport: request.Transport, Binding: request.Binding,
		Review: request.Review, View: cloneMaterialView(view), Candidate: cloneMaterialCandidate(candidate),
		Proposal: attemptProposal, Batch: batch, Blob: blob, Confirmation: attemptProposal.Confirmation,
	}, nil
}

func (coordinator *Coordinator) PublishMaterial(ctx context.Context, proposal MaterialPublishProposal, confirmation [32]byte) (MaterialPublishResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return MaterialPublishResult{}, err
	}
	defer coordinator.mu.Unlock()
	if !validMaterialPublishProposal(proposal) {
		return MaterialPublishResult{}, publishMaterialFailure(ctx, publishMaterialStageInput, publishMaterialReasonRequestInvalid, nil)
	}
	if err := ctx.Err(); err != nil {
		return MaterialPublishResult{}, publishMaterialFailure(ctx, publishMaterialStageInput, publishMaterialReasonCanceled, err)
	}
	if !bytes.Equal(confirmation[:], proposal.Confirmation[:]) || !bytes.Equal(confirmation[:], proposal.Proposal.Confirmation[:]) {
		return MaterialPublishResult{}, publishMaterialFailure(ctx, publishMaterialStageConsent, publishMaterialReasonConfirmation, nil)
	}
	expected, err := newMaterialWriteBatch(proposal.Binding, proposal.Proposal.CapturedFloor, proposal.View, proposal.Candidate)
	if err != nil || !sameMaterialWriteBatch(expected, proposal.Batch) {
		return MaterialPublishResult{}, publishMaterialFailure(ctx, publishMaterialStageBatch, publishMaterialReasonBatch, err)
	}
	payloadCID, err := publication.RawPayloadCID(proposal.Candidate.Payload)
	if err != nil || !bytes.Equal(payloadCID, proposal.Blob.CID) || uint64(len(proposal.Candidate.Payload)) != proposal.Blob.Size {
		return MaterialPublishResult{}, publishMaterialFailure(ctx, publishMaterialStageBatch, publishMaterialReasonBlob, err)
	}
	observation, err := proposal.Transport.ReadView(ctx)
	if err != nil {
		return MaterialPublishResult{}, publishMaterialFailure(ctx, publishMaterialStageView, publishMaterialReasonView, err)
	}
	if observation.Origin != proposal.Binding || observation.Scope != proposal.View.Scope || !sameMaterialContext(observation.SuppliedContext, proposal.Batch.ExpectedContext) {
		return MaterialPublishResult{}, publishMaterialFailure(ctx, publishMaterialStageView, publishMaterialReasonObservation, nil)
	}

	id := proposal.Proposal.AttemptID
	attempt, err := proposal.Store.CreateAttempt(ctx, proposal.Proposal.StateToken, proposal.Candidate, proposal.View, proposal.Review, confirmation)
	if err != nil {
		return MaterialPublishResult{}, err
	}
	if attempt.ID != id {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageSubmission, publishMaterialReasonSubmission, nil)
	}
	uploadProposal, err := proposal.Store.PrepareDispatch(ctx, id, publicationstate.DispatchUpload, proposal.View, proposal.Review)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	upload, err := proposal.Store.BeginUpload(ctx, id, uploadProposal.StateToken, proposal.View, proposal.Review, uploadProposal.Confirmation)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	if !sameMaterialBlob(upload.Blob, proposal.Blob) || !bytes.Equal(upload.Payload, proposal.Candidate.Payload) {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageUpload, publishMaterialReasonBlob, nil)
	}
	uploaded, err := proposal.Transport.UploadPayload(ctx, upload.Payload)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageUpload, publishMaterialReasonUpload, err)
	}
	if !sameMaterialBlob(uploaded, proposal.Blob) {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageUpload, publishMaterialReasonBlob, nil)
	}
	submissionProposal, err := proposal.Store.PrepareDispatch(ctx, id, publicationstate.DispatchSubmission, proposal.View, proposal.Review)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	submission, err := proposal.Store.BeginSubmission(ctx, id, submissionProposal.StateToken, proposal.View, proposal.Review, submissionProposal.Confirmation)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	if !sameMaterialWriteBatch(proposal.Batch, materialWriteBatchFromSubmission(submission)) {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageSubmission, publishMaterialReasonSubmission, nil)
	}
	outcome, err := proposal.Transport.ApplyWrites(ctx, cloneMaterialWriteBatch(proposal.Batch))
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageSubmission, publishMaterialReasonUnresolved, err)
	}
	if !outcome.Committed {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageSubmission, publishMaterialReasonUnresolved, nil)
	}
	resolved, err := proposal.Transport.ReadView(ctx)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, publishMaterialFailure(ctx, publishMaterialStageOutcome, publishMaterialReasonView, err)
	}
	loaded, err := proposal.Store.LoadAttempt(ctx, id)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	resolution, err := proposal.Store.ResolveAttempt(ctx, id, loaded.StateDigest, resolved)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	if resolution.Outcome != publicationstate.OutcomeCurrent || resolution.Attempt.ID != id {
		return MaterialPublishResult{Attempt: resolution.Attempt, Outcome: resolution.Outcome}, publishMaterialFailure(ctx, publishMaterialStageOutcome, publishMaterialReasonOutcome, nil)
	}
	finalization, err := proposal.Store.FinalizeAttempt(ctx, id, resolution.Attempt.StateDigest, resolved)
	if err != nil {
		return MaterialPublishResult{Attempt: resolution.Attempt, Outcome: resolution.Outcome}, err
	}
	return MaterialPublishResult{Floor: finalization.Floor, Attempt: finalization.Attempt, Outcome: resolution.Outcome}, nil
}

func newMaterialCandidate(request MaterialPublishRequest, floor publicationstate.Floor, present bool) (publicationstate.CandidateInput, publication.BlobReference, error) {
	packed, err := vault.Pack(request.Snapshot)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	blob := publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))}
	var sequence uint64
	parent := []byte{}
	if present {
		sequence = floor.Sequence + 1
		parent = bytes.Clone(floor.RecordCID)
	}
	key, err := publication.SequenceKey(sequence)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	snapshotRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: request.Binding.Vault, PublicationID: request.PublicationID,
		PublicationSeq: sequence, Parent: parent, Blob: blob,
	})
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	snapshotCID, err := publication.RecordCID(snapshotRecord)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	headRecord, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: request.Binding.Vault, PublicationSeq: sequence,
		SnapshotCID: snapshotCID, BlobCID: blobCID,
	})
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	return publicationstate.CandidateInput{SnapshotKey: key, SnapshotRecord: snapshotRecord, HeadRecord: headRecord, Payload: packed.Payload}, blob, nil
}

func newMaterialWriteBatch(binding publicationstate.Binding, captured *publicationstate.Floor, view publicationstate.SuppliedRepositoryView, candidate publicationstate.CandidateInput) (MaterialWriteBatch, error) {
	snapshot, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	if err != nil {
		return MaterialWriteBatch{}, err
	}
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	if err != nil || key != candidate.SnapshotKey {
		return MaterialWriteBatch{}, errors.New("publication material candidate key does not match its sequence")
	}
	if err := publication.VerifyPayload(candidate.Payload, snapshot.Blob); err != nil {
		return MaterialWriteBatch{}, err
	}
	if err := publication.VerifyHeadBinding(candidate.HeadRecord, candidate.SnapshotRecord, candidate.SnapshotKey); err != nil {
		return MaterialWriteBatch{}, err
	}
	snapshotCID, err := publication.RecordCID(candidate.SnapshotRecord)
	if err != nil {
		return MaterialWriteBatch{}, err
	}
	batch := MaterialWriteBatch{
		SnapshotCollection: publication.SnapshotNSID, SnapshotKey: candidate.SnapshotKey,
		SnapshotRecord: bytes.Clone(candidate.SnapshotRecord), ExpectedSnapshotCID: snapshotCID, SnapshotCreateOnly: true,
		HeadCollection: publication.HeadNSID, HeadKey: materialHeadKey, HeadRecord: bytes.Clone(candidate.HeadRecord), HeadCreate: captured == nil,
		ExpectedContext:     cloneMaterialContext(view.SuppliedContext),
		RequiresAtomicBatch: true, RequiresCreateExclude: true,
		RequiresPolicyCheck: binding.Backend == publicationstate.BackendSpaces,
	}
	if captured == nil {
		if snapshot.PublicationSeq != 0 || len(snapshot.Parent) != 0 {
			return MaterialWriteBatch{}, errors.New("publication material candidate is not a genesis record")
		}
		return batch, nil
	}
	if snapshot.PublicationSeq != captured.Sequence+1 || !bytes.Equal(snapshot.Parent, captured.RecordCID) {
		return MaterialWriteBatch{}, errors.New("publication material candidate does not extend the captured floor")
	}
	batch.ExpectedPredecessor = &publicationstate.RecordReference{Key: captured.SnapshotKey, CID: bytes.Clone(captured.RecordCID), Sequence: captured.Sequence}
	return batch, nil
}

func materialWriteBatchFromSubmission(material publicationstate.SubmissionMaterial) MaterialWriteBatch {
	return MaterialWriteBatch{
		SnapshotCollection: material.SnapshotCollection, SnapshotKey: material.SnapshotKey,
		SnapshotRecord: bytes.Clone(material.SnapshotRecord), ExpectedSnapshotCID: bytes.Clone(material.ExpectedSnapshotCID),
		SnapshotCreateOnly: material.SnapshotCreateOnly,
		HeadCollection:     material.HeadCollection, HeadKey: material.HeadKey,
		HeadRecord: bytes.Clone(material.HeadRecord), HeadCreate: material.HeadCreate,
		ExpectedPredecessor: cloneMaterialPredecessor(material.ExpectedPredecessor),
		ExpectedContext:     cloneMaterialContext(material.ExpectedContext),
		RequiresAtomicBatch: material.RequiresAtomicBatch, RequiresCreateExclude: material.RequiresCreateExclude,
		RequiresPolicyCheck: material.RequiresPolicyCheck,
	}
}

func sameMaterialWriteBatch(left, right MaterialWriteBatch) bool {
	return left.SnapshotCollection == right.SnapshotCollection &&
		left.SnapshotKey == right.SnapshotKey &&
		bytes.Equal(left.SnapshotRecord, right.SnapshotRecord) &&
		bytes.Equal(left.ExpectedSnapshotCID, right.ExpectedSnapshotCID) &&
		left.SnapshotCreateOnly == right.SnapshotCreateOnly &&
		left.HeadCollection == right.HeadCollection &&
		left.HeadKey == right.HeadKey &&
		bytes.Equal(left.HeadRecord, right.HeadRecord) &&
		left.HeadCreate == right.HeadCreate &&
		sameMaterialPredecessor(left.ExpectedPredecessor, right.ExpectedPredecessor) &&
		sameMaterialContext(left.ExpectedContext, right.ExpectedContext) &&
		left.RequiresAtomicBatch == right.RequiresAtomicBatch &&
		left.RequiresCreateExclude == right.RequiresCreateExclude &&
		left.RequiresPolicyCheck == right.RequiresPolicyCheck
}

func sameMaterialBlob(left, right publication.BlobReference) bool {
	return left.Size == right.Size && bytes.Equal(left.CID, right.CID)
}

func sameMaterialContext(left, right publicationstate.SuppliedContext) bool {
	if left.RepositoryRevision != right.RepositoryRevision || !bytes.Equal(left.RepositoryDigest, right.RepositoryDigest) {
		return false
	}
	if left.Policy == nil || right.Policy == nil {
		return left.Policy == nil && right.Policy == nil
	}
	return left.Policy.Revision == right.Policy.Revision && left.Policy.OwnerOnly == right.Policy.OwnerOnly && bytes.Equal(left.Policy.Identity, right.Policy.Identity)
}

func sameMaterialPredecessor(left, right *publicationstate.RecordReference) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Key == right.Key && left.Sequence == right.Sequence && bytes.Equal(left.CID, right.CID)
}

func cloneMaterialWriteBatch(batch MaterialWriteBatch) MaterialWriteBatch {
	out := batch
	out.SnapshotRecord = bytes.Clone(batch.SnapshotRecord)
	out.ExpectedSnapshotCID = bytes.Clone(batch.ExpectedSnapshotCID)
	out.HeadRecord = bytes.Clone(batch.HeadRecord)
	out.ExpectedPredecessor = cloneMaterialPredecessor(batch.ExpectedPredecessor)
	out.ExpectedContext = cloneMaterialContext(batch.ExpectedContext)
	return out
}

func cloneMaterialPredecessor(reference *publicationstate.RecordReference) *publicationstate.RecordReference {
	if reference == nil {
		return nil
	}
	return &publicationstate.RecordReference{Key: reference.Key, CID: bytes.Clone(reference.CID), Sequence: reference.Sequence}
}

func cloneMaterialContext(context publicationstate.SuppliedContext) publicationstate.SuppliedContext {
	out := publicationstate.SuppliedContext{RepositoryRevision: context.RepositoryRevision, RepositoryDigest: bytes.Clone(context.RepositoryDigest)}
	if context.Policy != nil {
		out.Policy = &publicationstate.Policy{Revision: context.Policy.Revision, Identity: bytes.Clone(context.Policy.Identity), OwnerOnly: context.Policy.OwnerOnly}
	}
	return out
}

func cloneMaterialView(view publicationstate.SuppliedRepositoryView) publicationstate.SuppliedRepositoryView {
	out := publicationstate.SuppliedRepositoryView{Origin: view.Origin, Scope: view.Scope, SuppliedContext: cloneMaterialContext(view.SuppliedContext), Head: bytes.Clone(view.Head)}
	out.Snapshots = make([]publicationstate.SnapshotBlock, len(view.Snapshots))
	for index, block := range view.Snapshots {
		out.Snapshots[index] = publicationstate.SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)}
	}
	return out
}

func cloneMaterialCandidate(candidate publicationstate.CandidateInput) publicationstate.CandidateInput {
	return publicationstate.CandidateInput{
		SnapshotKey: candidate.SnapshotKey, SnapshotRecord: bytes.Clone(candidate.SnapshotRecord),
		HeadRecord: bytes.Clone(candidate.HeadRecord), Payload: bytes.Clone(candidate.Payload),
	}
}

func cloneMaterialFloor(floor publicationstate.Floor) publicationstate.Floor {
	out := floor
	out.AnchorCID = bytes.Clone(floor.AnchorCID)
	out.SuppliedContext = cloneMaterialContext(floor.SuppliedContext)
	out.Head = bytes.Clone(floor.Head)
	out.RecordCID = bytes.Clone(floor.RecordCID)
	out.BlobCID = bytes.Clone(floor.BlobCID)
	return out
}

func validMaterialPublishRequest(request MaterialPublishRequest) bool {
	if request.Store == nil || request.Transport == nil || !validMaterialBinding(request.Binding) {
		return false
	}
	if request.PublicationID == ([16]byte{}) || request.Snapshot.Validate() != nil {
		return false
	}
	return true
}

func validMaterialPublishProposal(proposal MaterialPublishProposal) bool {
	if proposal.Store == nil || proposal.Transport == nil || !validMaterialBinding(proposal.Binding) {
		return false
	}
	if allZeroMaterial(proposal.Proposal.StateToken[:]) || proposal.Proposal.AttemptID == ([16]byte{}) || allZeroMaterial(proposal.Confirmation[:]) {
		return false
	}
	if proposal.Candidate.SnapshotKey == "" || len(proposal.Candidate.SnapshotRecord) == 0 || len(proposal.Candidate.HeadRecord) == 0 || len(proposal.Candidate.Payload) == 0 {
		return false
	}
	if len(proposal.Batch.SnapshotRecord) == 0 || len(proposal.Batch.ExpectedSnapshotCID) == 0 || len(proposal.Batch.HeadRecord) == 0 {
		return false
	}
	return len(proposal.Blob.CID) != 0 && proposal.Blob.Size != 0
}

func validMaterialBinding(binding publicationstate.Binding) bool {
	if binding.AccountDID == "" || binding.Repository == "" || binding.Vault == ([32]byte{}) {
		return false
	}
	return binding.Backend == publicationstate.BackendPublicRepo || binding.Backend == publicationstate.BackendSpaces
}

func allZeroMaterial(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func publishMaterialFailure(ctx context.Context, stage publishMaterialStage, reason publishMaterialReason, cause error) error {
	if stage == publishMaterialStageInput && ctx != nil && ctx.Err() != nil {
		reason = publishMaterialReasonCanceled
	}
	return &publishMaterialError{stage: stage, reason: reason, cause: cause}
}
