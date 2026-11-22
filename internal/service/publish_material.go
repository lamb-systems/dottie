package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/vault"
)

var (
	ErrPublishMaterial           = errors.New("publication material refused")
	ErrConfigChangedSincePrepare = errors.New("configuration changed since the publication was prepared")
	ErrReviewMismatch            = errors.New("publication review identity does not match the configuration")
)

const (
	materialProposalTag         = "dottie/material-proposal/v1"
	materialManifestProposalTag = "dottie/material-proposal/manifest/v1"
)

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
	publishMaterialReasonRejected       publishMaterialReason = "submission_rejected"
	publishMaterialReasonOutcome        publishMaterialReason = "outcome_not_current"
	publishMaterialReasonReview         publishMaterialReason = "review_changed"
	publishMaterialReasonReviewMismatch publishMaterialReason = "review_mismatch"
)

const materialHeadKey = "self"

type MaterialTransport interface {
	UploadPayload(ctx context.Context, payload []byte) (publication.BlobReference, error)
	PrepareWrites(ctx context.Context, batch MaterialWriteBatch) (MaterialPreparedWrites, error)
	SendWrites(ctx context.Context, prepared MaterialPreparedWrites) (MaterialWriteOutcome, error)
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

type MaterialPreparedWrites struct {
	Secret   string
	Dispatch int
}

type materialWriteDispatch struct {
	prepared MaterialPreparedWrites
	sent     bool
}

func (dispatch *materialWriteDispatch) ready() bool {
	return !dispatch.sent && dispatch.prepared.Secret != "" && dispatch.prepared.Dispatch == 1
}

func (dispatch *materialWriteDispatch) send(
	ctx context.Context,
	transport MaterialTransport,
) error {
	if !dispatch.ready() {
		return publishMaterialFailure(
			ctx,
			publishMaterialStageSubmission,
			publishMaterialReasonSubmission,
			nil,
		)
	}
	dispatch.sent = true
	outcome, err := transport.SendWrites(ctx, dispatch.prepared)
	if err != nil {
		return publishMaterialFailure(
			ctx,
			publishMaterialStageSubmission,
			publishMaterialReasonUnresolved,
			err,
		)
	}
	if !outcome.Committed {
		return publishMaterialFailure(
			ctx,
			publishMaterialStageSubmission,
			publishMaterialReasonUnresolved,
			nil,
		)
	}
	return nil
}

type MaterialPublishRequest struct {
	Store         *publicationstate.Store
	Transport     MaterialTransport
	Binding       publicationstate.Binding
	Form          publication.PayloadForm
	Snapshot      model.Snapshot
	PublicationID [16]byte
	Reviews       ReviewSource
}

type MaterialPublishProposal struct {
	Store         *publicationstate.Store
	Transport     MaterialTransport
	Binding       publicationstate.Binding
	Form          publication.PayloadForm
	Review        publicationstate.LocalReviewContext
	ConfigToken   config.Token
	ProposalToken [32]byte
	Reviews       ReviewSource
	PublicationID [16]byte
	View          publicationstate.SuppliedRepositoryView
	Candidate     publicationstate.CandidateInput
	Proposal      publicationstate.AttemptProposal
	Batch         MaterialWriteBatch
	Blob          publication.BlobReference
	Confirmation  [32]byte
}

type MaterialPublishResult struct {
	Floor   publicationstate.Floor
	Attempt publicationstate.Attempt
	Outcome publicationstate.AttemptOutcome
}

func (coordinator *Coordinator) PreparePublishMaterial(
	ctx context.Context,
	request MaterialPublishRequest,
) (MaterialPublishProposal, error) {
	if err := coordinator.lock(ctx); err != nil {
		return MaterialPublishProposal{}, err
	}
	defer coordinator.mu.Unlock()
	if !validMaterialPublishRequest(request) {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStageInput,
			publishMaterialReasonRequestInvalid,
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStageInput,
			publishMaterialReasonCanceled,
			err,
		)
	}
	review, configToken, guard, err := request.Reviews.Acquire(ctx)
	if err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStageConsent,
			publishMaterialReasonReview,
			err,
		)
	}
	defer guard.Release()
	floor, present, err := request.Store.Load(ctx)
	if err != nil {
		return MaterialPublishProposal{}, err
	}
	if present && floor.Binding != request.Binding {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStagePosition,
			publishMaterialReasonPosition,
			nil,
		)
	}
	view, err := request.Transport.ReadView(ctx)
	if err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStageView,
			publishMaterialReasonView,
			err,
		)
	}
	if view.Origin != request.Binding {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStageView,
			publishMaterialReasonView,
			nil,
		)
	}
	form := request.Form
	if form == "" {
		form = publication.PayloadFormPacked
	}
	candidate, blob, batch, err := buildPublicationMaterial(
		request.Binding,
		form,
		request.Snapshot,
		floor,
		present,
		view,
		request.PublicationID,
	)
	if err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStageBatch,
			publishMaterialReasonBatch,
			err,
		)
	}
	attemptProposal, err := request.Store.PrepareAttempt(ctx, candidate, view, review)
	if err != nil {
		return MaterialPublishProposal{}, err
	}
	proposalToken, err := materialProposalToken(review, candidate, request.PublicationID)
	if err != nil {
		return MaterialPublishProposal{}, publishMaterialFailure(
			ctx,
			publishMaterialStageBatch,
			publishMaterialReasonBatch,
			err,
		)
	}
	return MaterialPublishProposal{
		Store:         request.Store,
		Transport:     request.Transport,
		Binding:       request.Binding,
		Form:          form,
		Review:        review,
		ConfigToken:   configToken,
		ProposalToken: proposalToken,
		Reviews:       request.Reviews,
		PublicationID: request.PublicationID,
		View:          cloneMaterialView(view),
		Candidate:     cloneMaterialCandidate(candidate),
		Proposal:      attemptProposal,
		Batch:         batch,
		Blob:          blob,
		Confirmation:  attemptProposal.Confirmation,
	}, nil
}

func (coordinator *Coordinator) PublishMaterial(
	ctx context.Context,
	proposal MaterialPublishProposal,
	confirmation [32]byte,
) (MaterialPublishResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return MaterialPublishResult{}, err
	}
	defer coordinator.mu.Unlock()
	if !validMaterialPublishProposal(proposal) {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageInput,
			publishMaterialReasonRequestInvalid,
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageInput,
			publishMaterialReasonCanceled,
			err,
		)
	}
	if !bytes.Equal(confirmation[:], proposal.Confirmation[:]) ||
		!bytes.Equal(confirmation[:], proposal.Proposal.Confirmation[:]) {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageConsent,
			publishMaterialReasonConfirmation,
			nil,
		)
	}
	bound, err := materialProposalToken(proposal.Review, proposal.Candidate, proposal.PublicationID)
	if err != nil || bound != proposal.ProposalToken {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageConsent,
			publishMaterialReasonReviewMismatch,
			ErrReviewMismatch,
		)
	}
	expected, err := newMaterialWriteBatch(
		proposal.Binding,
		proposal.Proposal.CapturedFloor,
		proposal.View,
		proposal.Candidate,
	)
	if err != nil || !sameMaterialWriteBatch(expected, proposal.Batch) {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageBatch,
			publishMaterialReasonBatch,
			err,
		)
	}
	sealed, err := publication.DecodeSnapshot(proposal.Batch.SnapshotRecord)
	if err != nil || sealed.PayloadForm() != proposal.Form {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageBatch,
			publishMaterialReasonBlob,
			err,
		)
	}
	switch proposal.Form {
	case publication.PayloadFormPacked:
		payloadCID, err := publication.RawPayloadCID(proposal.Candidate.Payload)
		if err != nil || !bytes.Equal(payloadCID, proposal.Blob.CID) ||
			uint64(len(proposal.Candidate.Payload)) != proposal.Blob.Size ||
			sealed.Blob.MIMEType != proposal.Blob.MIMEType ||
			!bytes.Equal(sealed.Blob.CID, proposal.Blob.CID) ||
			sealed.Blob.Size != proposal.Blob.Size {
			return MaterialPublishResult{}, publishMaterialFailure(
				ctx,
				publishMaterialStageBatch,
				publishMaterialReasonBlob,
				err,
			)
		}
	case publication.PayloadFormManifest:
		if !manifestCandidateEntriesMatch(proposal.Candidate.Entries, sealed.Entries) {
			return MaterialPublishResult{}, publishMaterialFailure(
				ctx,
				publishMaterialStageBatch,
				publishMaterialReasonBlob,
				nil,
			)
		}
	default:
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageBatch,
			publishMaterialReasonBlob,
			nil,
		)
	}
	observation, err := proposal.Transport.ReadView(ctx)
	if err != nil {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageView,
			publishMaterialReasonView,
			err,
		)
	}
	if observation.Origin != proposal.Binding || observation.Scope != proposal.View.Scope ||
		!sameMaterialContext(observation.SuppliedContext, proposal.Batch.ExpectedContext) {
		return MaterialPublishResult{}, publishMaterialFailure(
			ctx,
			publishMaterialStageView,
			publishMaterialReasonObservation,
			nil,
		)
	}

	id := proposal.Proposal.AttemptID
	attempt, err := proposal.Store.CreateAttempt(
		ctx,
		proposal.Proposal.StateToken,
		proposal.Candidate,
		proposal.View,
		proposal.Review,
		confirmation,
	)
	if err != nil {
		return MaterialPublishResult{}, err
	}
	if attempt.ID != id {
		return MaterialPublishResult{
			Attempt: attempt,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageSubmission,
			publishMaterialReasonSubmission,
			nil,
		)
	}
	uploadProposal, err := proposal.Store.PrepareDispatch(
		ctx,
		id,
		publicationstate.DispatchUpload,
		proposal.View,
		proposal.Review,
	)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	upload, err := proposal.Store.BeginUpload(
		ctx,
		id,
		uploadProposal.StateToken,
		proposal.View,
		proposal.Review,
		uploadProposal.Confirmation,
	)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	var uploadedRefs []publicationstate.PayloadEntryReference
	switch proposal.Form {
	case publication.PayloadFormPacked:
		if !sameMaterialBlob(upload.Blob, proposal.Blob) ||
			!bytes.Equal(upload.Payload, proposal.Candidate.Payload) ||
			len(upload.Entries) != 0 {
			return MaterialPublishResult{
				Attempt: attempt,
			}, publishMaterialFailure(
				ctx,
				publishMaterialStageUpload,
				publishMaterialReasonBlob,
				nil,
			)
		}
		uploaded, err := proposal.Transport.UploadPayload(ctx, upload.Payload)
		if err != nil {
			return MaterialPublishResult{
				Attempt: attempt,
			}, publishMaterialFailure(
				ctx,
				publishMaterialStageUpload,
				publishMaterialReasonUpload,
				err,
			)
		}
		if !sameMaterialBlob(uploaded, proposal.Blob) || uploaded.MIMEType != sealed.Blob.MIMEType {
			return MaterialPublishResult{
				Attempt: attempt,
			}, publishMaterialFailure(
				ctx,
				publishMaterialStageUpload,
				publishMaterialReasonBlob,
				nil,
			)
		}
	case publication.PayloadFormManifest:
		if len(upload.Payload) != 0 || len(upload.Entries) != len(proposal.Candidate.Entries) ||
			len(upload.Entries) != len(sealed.Entries) {
			return MaterialPublishResult{
				Attempt: attempt,
			}, publishMaterialFailure(
				ctx,
				publishMaterialStageUpload,
				publishMaterialReasonBlob,
				nil,
			)
		}
		uploadedRefs = make([]publicationstate.PayloadEntryReference, 0, len(upload.Entries))
		for index, entry := range upload.Entries {
			want := sealed.Entries[index]
			candidate := proposal.Candidate.Entries[index]
			if entry.Path != want.Path || entry.Path != candidate.Path ||
				!sameMaterialBlob(entry.Blob, want.Blob) ||
				!bytes.Equal(entry.Payload, candidate.Content) {
				return MaterialPublishResult{
					Attempt: attempt,
				}, publishMaterialFailure(
					ctx,
					publishMaterialStageUpload,
					publishMaterialReasonBlob,
					nil,
				)
			}
			uploaded, err := proposal.Transport.UploadPayload(ctx, entry.Payload)
			if err != nil {
				return MaterialPublishResult{
					Attempt: attempt,
				}, publishMaterialFailure(
					ctx,
					publishMaterialStageUpload,
					publishMaterialReasonUpload,
					err,
				)
			}
			if !sameMaterialBlob(uploaded, entry.Blob) {
				return MaterialPublishResult{
					Attempt: attempt,
				}, publishMaterialFailure(
					ctx,
					publishMaterialStageUpload,
					publishMaterialReasonBlob,
					nil,
				)
			}
			uploadedRefs = append(uploadedRefs, publicationstate.PayloadEntryReference{
				Path: entry.Path,
				CID:  bytes.Clone(uploaded.CID),
				Size: uploaded.Size,
			})
		}
	}
	review, configToken, guard, err := proposal.Reviews.Acquire(ctx)
	if err != nil {
		return MaterialPublishResult{
			Attempt: attempt,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageConsent,
			publishMaterialReasonReview,
			err,
		)
	}
	defer guard.Release()
	if review != proposal.Review {
		if configToken == proposal.ConfigToken {
			return MaterialPublishResult{
				Attempt: attempt,
			}, publishMaterialFailure(
				ctx,
				publishMaterialStageConsent,
				publishMaterialReasonReviewMismatch,
				ErrReviewMismatch,
			)
		}
		return MaterialPublishResult{
			Attempt: attempt,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageConsent,
			publishMaterialReasonReview,
			ErrConfigChangedSincePrepare,
		)
	}
	prepared, err := proposal.Transport.PrepareWrites(ctx, cloneMaterialWriteBatch(proposal.Batch))
	if err != nil {
		return MaterialPublishResult{
			Attempt: attempt,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageBatch,
			publishMaterialReasonBatch,
			err,
		)
	}
	dispatch := materialWriteDispatch{prepared: prepared}
	if !dispatch.ready() {
		return MaterialPublishResult{
			Attempt: attempt,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageSubmission,
			publishMaterialReasonSubmission,
			nil,
		)
	}
	submissionProposal, err := proposal.Store.PrepareDispatch(
		ctx,
		id,
		publicationstate.DispatchSubmission,
		proposal.View,
		proposal.Review,
	)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	var submission publicationstate.SubmissionMaterial
	if proposal.Form == publication.PayloadFormManifest {
		submission, err = proposal.Store.BeginManifestSubmission(
			ctx,
			id,
			submissionProposal.StateToken,
			proposal.View,
			proposal.Review,
			submissionProposal.Confirmation,
			uploadedRefs,
		)
	} else {
		submission, err = proposal.Store.BeginSubmission(
			ctx,
			id,
			submissionProposal.StateToken,
			proposal.View,
			proposal.Review,
			submissionProposal.Confirmation,
		)
	}
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, err
	}
	if !sameMaterialWriteBatch(proposal.Batch, materialWriteBatchFromSubmission(submission)) {
		return MaterialPublishResult{
			Attempt: attempt,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageSubmission,
			publishMaterialReasonSubmission,
			nil,
		)
	}
	if err := dispatch.send(ctx, proposal.Transport); err != nil {
		if !errors.Is(err, ErrMaterialSubmissionRejected) {
			return MaterialPublishResult{Attempt: attempt}, err
		}
		return coordinator.retireRejectedMaterialSubmission(ctx, proposal, attempt, err)
	}
	resolved, err := proposal.Transport.ReadView(ctx)
	if err != nil {
		return MaterialPublishResult{
			Attempt: attempt,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageOutcome,
			publishMaterialReasonView,
			err,
		)
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
		return MaterialPublishResult{
			Attempt: resolution.Attempt,
			Outcome: resolution.Outcome,
		}, publishMaterialFailure(
			ctx,
			publishMaterialStageOutcome,
			publishMaterialReasonOutcome,
			nil,
		)
	}
	finalization, err := proposal.Store.FinalizeAttempt(ctx, id, resolution.Attempt.StateDigest, resolved)
	if err != nil {
		return MaterialPublishResult{Attempt: resolution.Attempt, Outcome: resolution.Outcome}, err
	}
	return MaterialPublishResult{
		Floor:   finalization.Floor,
		Attempt: finalization.Attempt,
		Outcome: resolution.Outcome,
	}, nil
}

func (coordinator *Coordinator) retireRejectedMaterialSubmission(
	ctx context.Context,
	proposal MaterialPublishProposal,
	attempt publicationstate.Attempt,
	cause error,
) (MaterialPublishResult, error) {
	refusal := publishMaterialFailure(ctx, publishMaterialStageSubmission, publishMaterialReasonRejected, cause)
	submitted, err := proposal.Store.LoadAttempt(ctx, attempt.ID)
	if err != nil {
		return MaterialPublishResult{Attempt: attempt}, errors.Join(refusal, err)
	}
	rejected, err := proposal.Store.RejectAttempt(ctx, submitted.ID, submitted.StateDigest)
	if err != nil {
		return MaterialPublishResult{Attempt: submitted}, errors.Join(refusal, err)
	}
	return MaterialPublishResult{Attempt: rejected, Outcome: publicationstate.OutcomeRejected}, refusal
}

func manifestCandidateEntriesMatch(entries []publication.PayloadEntry, record []publication.SnapshotEntry) bool {
	if len(entries) != len(record) {
		return false
	}
	for index, entry := range entries {
		want := record[index]
		if entry.Path != want.Path || entry.Mode != want.Mode || entry.Size != want.Size ||
			uint64(len(entry.Content)) != want.Size {
			return false
		}
		cid, err := publication.RawPayloadCID(entry.Content)
		if err != nil || !bytes.Equal(cid, want.Blob.CID) {
			return false
		}
	}
	return true
}

func newMaterialWriteBatch(
	binding publicationstate.Binding,
	captured *publicationstate.Floor,
	view publicationstate.SuppliedRepositoryView,
	candidate publicationstate.CandidateInput,
) (MaterialWriteBatch, error) {
	snapshot, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	if err != nil {
		return MaterialWriteBatch{}, err
	}
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	if err != nil || key != candidate.SnapshotKey {
		return MaterialWriteBatch{}, errors.New("publication material candidate key does not match its sequence")
	}
	if snapshot.PayloadForm() == publication.PayloadFormManifest {
		if len(candidate.Payload) != 0 || !manifestCandidateEntriesMatch(candidate.Entries, snapshot.Entries) {
			return MaterialWriteBatch{}, publication.ErrPayloadFormMismatch
		}
	} else {
		if len(candidate.Entries) != 0 {
			return MaterialWriteBatch{}, publication.ErrPayloadFormMismatch
		}
		if err := publication.VerifyPayload(candidate.Payload, snapshot.Blob); err != nil {
			return MaterialWriteBatch{}, err
		}
	}
	if err := publication.VerifyHeadBinding(
		candidate.HeadRecord,
		candidate.SnapshotRecord,
		candidate.SnapshotKey,
	); err != nil {
		return MaterialWriteBatch{}, err
	}
	snapshotCID, err := publication.RecordCID(candidate.SnapshotRecord)
	if err != nil {
		return MaterialWriteBatch{}, err
	}
	batch := MaterialWriteBatch{
		SnapshotCollection: publication.SnapshotNSID,
		SnapshotKey:        candidate.SnapshotKey,
		SnapshotRecord: bytes.Clone(
			candidate.SnapshotRecord,
		),
		ExpectedSnapshotCID:   snapshotCID,
		SnapshotCreateOnly:    true,
		HeadCollection:        publication.HeadNSID,
		HeadKey:               materialHeadKey,
		HeadRecord:            bytes.Clone(candidate.HeadRecord),
		HeadCreate:            captured == nil,
		ExpectedContext:       cloneMaterialContext(view.SuppliedContext),
		RequiresAtomicBatch:   true,
		RequiresCreateExclude: true,
		RequiresPolicyCheck:   binding.Backend == publicationstate.BackendSpaces,
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
	batch.ExpectedPredecessor = &publicationstate.RecordReference{
		Key:      captured.SnapshotKey,
		CID:      bytes.Clone(captured.RecordCID),
		Sequence: captured.Sequence,
	}
	return batch, nil
}

func cloneManifestPayloadReference(payload *publicationstate.ManifestPayload) *publicationstate.ManifestPayload {
	if payload == nil {
		return nil
	}
	entries := make([]publicationstate.PayloadEntryReference, 0, len(payload.Entries))
	for _, entry := range payload.Entries {
		entries = append(entries, publicationstate.PayloadEntryReference{
			Path: entry.Path, CID: bytes.Clone(entry.CID), Size: entry.Size,
		})
	}
	return &publicationstate.ManifestPayload{Entries: entries}
}

func materialWriteBatchFromSubmission(material publicationstate.SubmissionMaterial) MaterialWriteBatch {
	return MaterialWriteBatch{
		SnapshotCollection: material.SnapshotCollection,
		SnapshotKey:        material.SnapshotKey,
		SnapshotRecord: bytes.Clone(
			material.SnapshotRecord,
		),
		ExpectedSnapshotCID:   bytes.Clone(material.ExpectedSnapshotCID),
		SnapshotCreateOnly:    material.SnapshotCreateOnly,
		HeadCollection:        material.HeadCollection,
		HeadKey:               material.HeadKey,
		HeadRecord:            bytes.Clone(material.HeadRecord),
		HeadCreate:            material.HeadCreate,
		ExpectedPredecessor:   cloneMaterialPredecessor(material.ExpectedPredecessor),
		ExpectedContext:       cloneMaterialContext(material.ExpectedContext),
		RequiresAtomicBatch:   material.RequiresAtomicBatch,
		RequiresCreateExclude: material.RequiresCreateExclude,
		RequiresPolicyCheck:   material.RequiresPolicyCheck,
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
	if left.RepositoryRevision != right.RepositoryRevision ||
		!bytes.Equal(left.RepositoryDigest, right.RepositoryDigest) {
		return false
	}
	if left.Policy == nil || right.Policy == nil {
		return left.Policy == nil && right.Policy == nil
	}
	return left.Policy.Revision == right.Policy.Revision && left.Policy.OwnerOnly == right.Policy.OwnerOnly &&
		bytes.Equal(left.Policy.Identity, right.Policy.Identity)
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
	return &publicationstate.RecordReference{
		Key:      reference.Key,
		CID:      bytes.Clone(reference.CID),
		Sequence: reference.Sequence,
	}
}

func cloneMaterialContext(context publicationstate.SuppliedContext) publicationstate.SuppliedContext {
	out := publicationstate.SuppliedContext{
		RepositoryRevision: context.RepositoryRevision,
		RepositoryDigest:   bytes.Clone(context.RepositoryDigest),
	}
	if context.Policy != nil {
		out.Policy = &publicationstate.Policy{
			Revision:  context.Policy.Revision,
			Identity:  bytes.Clone(context.Policy.Identity),
			OwnerOnly: context.Policy.OwnerOnly,
		}
	}
	return out
}

func cloneMaterialView(view publicationstate.SuppliedRepositoryView) publicationstate.SuppliedRepositoryView {
	out := publicationstate.SuppliedRepositoryView{
		Origin:          view.Origin,
		Scope:           view.Scope,
		SuppliedContext: cloneMaterialContext(view.SuppliedContext),
		Head:            bytes.Clone(view.Head),
	}
	out.Snapshots = make([]publicationstate.SnapshotBlock, len(view.Snapshots))
	for index, block := range view.Snapshots {
		out.Snapshots[index] = publicationstate.SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)}
	}
	return out
}

func cloneMaterialCandidate(candidate publicationstate.CandidateInput) publicationstate.CandidateInput {
	cloned := publicationstate.CandidateInput{
		SnapshotKey: candidate.SnapshotKey, SnapshotRecord: bytes.Clone(candidate.SnapshotRecord),
		HeadRecord: bytes.Clone(candidate.HeadRecord), Payload: bytes.Clone(candidate.Payload),
	}
	if len(candidate.Entries) != 0 {
		cloned.Entries = make([]publication.PayloadEntry, 0, len(candidate.Entries))
		for _, entry := range candidate.Entries {
			cloned.Entries = append(cloned.Entries, publication.PayloadEntry{
				Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: bytes.Clone(entry.Content),
			})
		}
	}
	return cloned
}

func sameManifestSnapshotEntries(left, right []publication.SnapshotEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index, entry := range left {
		other := right[index]
		if entry.Path != other.Path || entry.Mode != other.Mode || entry.Size != other.Size ||
			entry.Kind != other.Kind || !bytes.Equal(entry.Blob.CID, other.Blob.CID) ||
			entry.Blob.Size != other.Blob.Size || entry.Blob.MIMEType != other.Blob.MIMEType {
			return false
		}
	}
	return true
}

func materialProposalToken(
	review publicationstate.LocalReviewContext,
	candidate publicationstate.CandidateInput,
	publicationID [16]byte,
) ([32]byte, error) {
	snapshotCID, err := publication.RecordCID(candidate.SnapshotRecord)
	if err != nil {
		return [32]byte{}, err
	}
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	if err != nil {
		return [32]byte{}, err
	}
	message := make([]byte, 0, len(materialProposalTag)+3*32+16+16+16)
	if record.PayloadForm() == publication.PayloadFormManifest {
		if len(candidate.Payload) != 0 || !manifestCandidateEntriesMatch(candidate.Entries, record.Entries) {
			return [32]byte{}, publication.ErrPayloadFormMismatch
		}
		message = append(message, materialManifestProposalTag...)
		message = append(message, review.SelectionDigest[:]...)
		var revisions [16]byte
		binary.BigEndian.PutUint64(revisions[0:8], review.SelectionRevision)
		binary.BigEndian.PutUint64(revisions[8:16], review.ApprovalRevision)
		message = append(message, revisions[:]...)
		message = append(message, review.ApprovalDigest[:]...)
		message = append(message, snapshotCID...)
		message = append(message, publicationID[:]...)
		var count [8]byte
		binary.BigEndian.PutUint64(count[:], uint64(len(record.Entries)))
		message = append(message, count[:]...)
		entryDigest := manifestEntrySetDigest(record.Entries)
		message = append(message, entryDigest[:]...)
		return sha256.Sum256(message), nil
	}
	if len(candidate.Entries) != 0 {
		return [32]byte{}, publication.ErrPayloadFormMismatch
	}
	payloadCID, err := publication.RawPayloadCID(candidate.Payload)
	if err != nil {
		return [32]byte{}, err
	}
	message = append(message, materialProposalTag...)
	message = append(message, review.SelectionDigest[:]...)
	var revisions [16]byte
	binary.BigEndian.PutUint64(revisions[0:8], review.SelectionRevision)
	binary.BigEndian.PutUint64(revisions[8:16], review.ApprovalRevision)
	message = append(message, revisions[:]...)
	message = append(message, review.ApprovalDigest[:]...)
	message = append(message, snapshotCID...)
	message = append(message, payloadCID...)
	message = append(message, publicationID[:]...)
	return sha256.Sum256(message), nil
}

func validMaterialPublishRequest(request MaterialPublishRequest) bool {
	if request.Store == nil || request.Transport == nil || request.Reviews == nil ||
		!validMaterialBinding(request.Binding) {
		return false
	}
	if request.PublicationID == ([16]byte{}) || request.Snapshot.Validate() != nil {
		return false
	}
	return request.Form == "" || request.Form == publication.PayloadFormPacked ||
		request.Form == publication.PayloadFormManifest
}

func validMaterialPublishProposal(proposal MaterialPublishProposal) bool {
	if proposal.Store == nil || proposal.Transport == nil || proposal.Reviews == nil ||
		!validMaterialBinding(proposal.Binding) {
		return false
	}
	if allZeroMaterial(proposal.Proposal.StateToken[:]) || proposal.Proposal.AttemptID == ([16]byte{}) ||
		allZeroMaterial(proposal.Confirmation[:]) {
		return false
	}
	if allZeroMaterial(proposal.ProposalToken[:]) {
		return false
	}
	if proposal.Candidate.SnapshotKey == "" || len(proposal.Candidate.SnapshotRecord) == 0 ||
		len(proposal.Candidate.HeadRecord) == 0 {
		return false
	}
	if len(proposal.Batch.SnapshotRecord) == 0 || len(proposal.Batch.ExpectedSnapshotCID) == 0 ||
		len(proposal.Batch.HeadRecord) == 0 {
		return false
	}
	switch proposal.Form {
	case publication.PayloadFormPacked:
		if len(proposal.Candidate.Payload) == 0 || len(proposal.Candidate.Entries) != 0 ||
			len(proposal.Blob.CID) == 0 || proposal.Blob.Size == 0 || proposal.Blob.MIMEType == "" {
			return false
		}
	case publication.PayloadFormManifest:
		if len(proposal.Candidate.Payload) != 0 || len(proposal.Candidate.Entries) == 0 ||
			len(proposal.Blob.CID) != 0 || proposal.Blob.Size != 0 || proposal.Blob.MIMEType != "" {
			return false
		}
	default:
		return false
	}
	return true
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

func publishMaterialFailure(
	ctx context.Context,
	stage publishMaterialStage,
	reason publishMaterialReason,
	cause error,
) error {
	if stage == publishMaterialStageInput && ctx != nil && ctx.Err() != nil {
		reason = publishMaterialReasonCanceled
	}
	return &publishMaterialError{stage: stage, reason: reason, cause: cause}
}

var (
	ErrPublicationProposal         = errors.New("publication proposal refused")
	ErrPublicationProposalAbsent   = errors.New("no retained publication proposal matches the reviewed confirmation")
	ErrPublicationProposalConsumed = errors.New(
		"the retained publication proposal was already consumed; re-run dottie push without --confirm to review a new proposal",
	)
	ErrPublicationProposalStale = errors.New(
		"the publication proposal is stale; state changed since review, re-run dottie push",
	)
	ErrPublicationProposalActive = errors.New(
		"a publication attempt is already active past submission and is unresolved; resolve it before preparing again",
	)
	ErrPublicationProposalUnresolved = errors.New(
		"the publication attempt passed submission and has an unresolved outcome; there is no abandonment and no retry; resolve it through the publication store readback",
	)
)

const publicationProposalRecordVersion uint64 = 1

type PublicationProposalRecord struct {
	Version              uint64
	Binding              publicationstate.Binding
	DatabaseID           [32]byte
	Generation           uint64
	FloorRevision        uint64
	CandidateRecordCID   []byte
	Form                 publication.PayloadForm
	CandidatePayloadCID  []byte
	CandidatePayloadSize uint64
	CandidateEntryCount  int
	CandidateEntryDigest [32]byte
	Review               publicationstate.LocalReviewContext
	PublicationID        [16]byte
	Lifecycle            publicationstate.AttemptLifecycle
	Consumed             bool
	Confirmation         [32]byte
}

type PublicationProposalStore interface {
	List(context.Context) ([]PublicationProposalRecord, error)
	Issue(context.Context, PublicationProposalRecord) error
	Consume(context.Context, [16]byte) error
	Delete(context.Context, [16]byte) error
}

type PublicationAcceptedSource interface {
	ReadAcceptedPayload(context.Context) (AcceptedPublication, error)
}

type PublicationPushRequest struct {
	Store         *publicationstate.Store
	Transport     MaterialTransport
	Reader        PublicationAcceptedSource
	Records       PublicationProposalStore
	Binding       publicationstate.Binding
	Configuration config.Config
	Reviews       ReviewSource
	PublicationID [16]byte
	Record        *PublicationProposalRecord
}

type PublicationPushPreparation struct {
	Proposal MaterialPublishProposal
	Record   PublicationProposalRecord
	Issued   bool
	NoOp     bool
	Present  bool
	Floor    publicationstate.Floor
	Form     publication.PayloadForm
	Targets  int
	Entries  int
}

func VerifyPublicationProposalRecord(record PublicationProposalRecord) error {
	form := record.Form
	if form == "" {
		form = publication.PayloadFormPacked
	}
	if record.Version != publicationProposalRecordVersion || record.PublicationID == ([16]byte{}) ||
		allZeroMaterial(record.Confirmation[:]) ||
		allZeroMaterial(record.Review.SelectionDigest[:]) ||
		allZeroMaterial(record.Review.ApprovalDigest[:]) ||
		record.Review.SelectionRevision == 0 ||
		record.Review.ApprovalRevision == 0 ||
		!validMaterialBinding(record.Binding) ||
		len(record.CandidateRecordCID) == 0 {
		return ErrPublicationProposal
	}
	switch form {
	case publication.PayloadFormPacked:
		if len(record.CandidatePayloadCID) == 0 || record.CandidatePayloadSize == 0 ||
			record.CandidateEntryCount != 0 || !allZeroMaterial(record.CandidateEntryDigest[:]) {
			return ErrPublicationProposal
		}
	case publication.PayloadFormManifest:
		if len(record.CandidatePayloadCID) != 0 || record.CandidatePayloadSize != 0 ||
			record.CandidateEntryCount <= 0 || record.CandidateEntryCount > publication.MaxSnapshotEntries ||
			allZeroMaterial(record.CandidateEntryDigest[:]) {
			return ErrPublicationProposal
		}
	default:
		return ErrPublicationProposal
	}
	return nil
}

func (coordinator *Coordinator) PreparePublicationPush(
	ctx context.Context,
	request PublicationPushRequest,
) (PublicationPushPreparation, error) {
	if err := ctx.Err(); err != nil {
		return PublicationPushPreparation{}, err
	}
	if !validPublicationPushRequest(request) {
		return PublicationPushPreparation{}, ErrPublicationProposal
	}
	if request.Record != nil {
		if err := VerifyPublicationProposalRecord(*request.Record); err != nil {
			return PublicationPushPreparation{}, err
		}
		if request.Record.Consumed {
			return PublicationPushPreparation{}, ErrPublicationProposalConsumed
		}
		if request.Record.PublicationID != request.PublicationID || request.Record.Binding != request.Binding {
			return PublicationPushPreparation{}, ErrPublicationProposal
		}
	}
	floor, present, err := request.Store.Load(ctx)
	if err != nil {
		return PublicationPushPreparation{}, err
	}
	if present && floor.Binding != request.Binding {
		return PublicationPushPreparation{}, ErrPublicationProposal
	}
	base := model.Snapshot{}
	baseForm := publication.PayloadFormPacked
	var acceptedMaterial publicationstate.AcceptedMaterial
	if present {
		acceptedMaterial, err = request.Store.ReadAcceptedMaterial(ctx, request.Binding, floor)
		if err != nil {
			return PublicationPushPreparation{}, err
		}
		base, baseForm, err = acceptedPublicationSnapshot(acceptedMaterial, request.Configuration)
		if err != nil {
			return PublicationPushPreparation{}, err
		}
	}
	remote := model.Snapshot{}
	accepted, err := request.Reader.ReadAcceptedPayload(ctx)
	switch {
	case err == nil:
		remote, err = publicationPayloadSnapshot(accepted.Payload, request.Configuration)
		if err != nil {
			return PublicationPushPreparation{}, err
		}
	case errors.Is(err, atproto.ErrReadRecordMissing) && !present:
	default:
		return PublicationPushPreparation{}, err
	}
	snapshot, err := coordinator.buildPublicationSnapshot(ctx, PublicationCandidateRequest{
		Configuration: request.Configuration, BaseSnapshot: base,
		RemoteSnapshot: remote, PublicationID: request.PublicationID,
	})
	if err != nil {
		return PublicationPushPreparation{}, err
	}
	form, candidateSnapshot, err := selectPublicationForm(request.Configuration, snapshot, base)
	if err != nil {
		return PublicationPushPreparation{}, err
	}
	counts := PublicationPushPreparation{
		Present: present,
		Floor:   floor,
		Form:    form,
		Targets: len(candidateSnapshot.Targets),
		Entries: len(candidateSnapshot.Entries),
	}
	if present {
		switch form {
		case publication.PayloadFormPacked:
			if baseForm == publication.PayloadFormPacked {
				packed, err := vault.Pack(candidateSnapshot)
				if err != nil {
					return PublicationPushPreparation{}, err
				}
				if bytes.Equal(packed.Payload, acceptedMaterial.Payload) {
					counts.NoOp = true
					return coordinator.preparePublicationPushNoOp(ctx, request, counts)
				}
			}
		case publication.PayloadFormManifest:
			if baseForm == publication.PayloadFormManifest {
				baseRecord, err := publication.DecodeSnapshot(acceptedMaterial.SnapshotRecord)
				if err != nil {
					return PublicationPushPreparation{}, err
				}
				candidateEntries, err := publication.SnapshotEntries(candidateSnapshot)
				if err != nil {
					return PublicationPushPreparation{}, err
				}
				if sameManifestSnapshotEntries(baseRecord.Entries, candidateEntries) {
					counts.NoOp = true
					return coordinator.preparePublicationPushNoOp(ctx, request, counts)
				}
			}
		}
	}
	proposal, err := coordinator.PreparePublishMaterial(ctx, MaterialPublishRequest{
		Store: request.Store, Transport: request.Transport, Binding: request.Binding,
		Form: form, Snapshot: candidateSnapshot, PublicationID: request.PublicationID,
		Reviews: request.Reviews,
	})
	if err != nil {
		return PublicationPushPreparation{}, coordinator.publicationPushRefusal(ctx, request, err)
	}
	record := newPublicationProposalRecord(proposal)
	counts.Proposal = proposal
	counts.Record = record
	if request.Record != nil {
		return counts, nil
	}
	if err := request.Records.Issue(ctx, record); err != nil {
		return PublicationPushPreparation{}, err
	}
	counts.Issued = true
	return counts, nil
}

func (coordinator *Coordinator) ConfirmPublicationPush(
	ctx context.Context,
	request PublicationPushRequest,
	preparation PublicationPushPreparation,
	confirmation [32]byte,
) (MaterialPublishResult, error) {
	if err := ctx.Err(); err != nil {
		return MaterialPublishResult{}, err
	}
	if preparation.NoOp || preparation.Proposal.Proposal.AttemptID == ([16]byte{}) {
		return MaterialPublishResult{}, ErrPublicationProposal
	}
	if !bytes.Equal(confirmation[:], preparation.Proposal.Confirmation[:]) {
		return MaterialPublishResult{}, ErrPublicationProposalStale
	}
	if err := request.Records.Consume(ctx, preparation.Proposal.PublicationID); err != nil {
		return MaterialPublishResult{}, err
	}
	result, err := coordinator.PublishMaterial(ctx, preparation.Proposal, confirmation)
	if err != nil {
		coordinator.cleanStrandedPublication(ctx, request, preparation.Proposal.PublicationID)
		return result, err
	}
	if err := request.Records.Delete(ctx, preparation.Proposal.PublicationID); err != nil {
		return result, err
	}
	return result, nil
}

func (coordinator *Coordinator) AbandonPublicationPush(
	ctx context.Context,
	request PublicationPushRequest,
) (publicationstate.Attempt, error) {
	if err := coordinator.lock(ctx); err != nil {
		return publicationstate.Attempt{}, err
	}
	defer coordinator.mu.Unlock()
	if request.Store == nil || request.Records == nil || request.PublicationID == ([16]byte{}) {
		return publicationstate.Attempt{}, ErrPublicationProposal
	}
	active, has, err := request.Store.ActiveAttempt(ctx)
	if err != nil {
		return publicationstate.Attempt{}, err
	}
	if !has {
		if err := request.Records.Consume(ctx, request.PublicationID); err != nil {
			return publicationstate.Attempt{}, err
		}
		return publicationstate.Attempt{}, request.Records.Delete(ctx, request.PublicationID)
	}
	if active.ID != request.PublicationID ||
		(active.Lifecycle != publicationstate.AttemptPrepared && active.Lifecycle != publicationstate.AttemptUploadStarted) {
		return publicationstate.Attempt{}, ErrPublicationProposalUnresolved
	}
	proposal, err := request.Store.PrepareAbandon(ctx, request.PublicationID, nil)
	if err != nil {
		return publicationstate.Attempt{}, err
	}
	attempt, err := request.Store.AbandonAttempt(
		ctx,
		request.PublicationID,
		proposal.StateToken,
		nil,
		proposal.Confirmation,
	)
	if err != nil {
		return publicationstate.Attempt{}, err
	}
	if err := request.Records.Consume(ctx, request.PublicationID); err != nil {
		return attempt, err
	}
	return attempt, request.Records.Delete(ctx, request.PublicationID)
}

func (coordinator *Coordinator) cleanStrandedPublication(
	ctx context.Context,
	request PublicationPushRequest,
	publicationID [16]byte,
) {
	active, present, activeErr := request.Store.ActiveAttempt(ctx)
	if activeErr != nil || !present || active.ID != publicationID {
		return
	}
	if active.Lifecycle != publicationstate.AttemptPrepared &&
		active.Lifecycle != publicationstate.AttemptUploadStarted {
		return
	}
	proposal, abandonErr := request.Store.PrepareAbandon(ctx, publicationID, nil)
	if abandonErr != nil {
		return
	}
	if _, abandonErr := request.Store.AbandonAttempt(
		ctx,
		publicationID,
		proposal.StateToken,
		nil,
		proposal.Confirmation,
	); abandonErr != nil {
		return
	}
	_ = request.Records.Consume(ctx, publicationID)
	_ = request.Records.Delete(ctx, publicationID)
}

func (coordinator *Coordinator) preparePublicationPushNoOp(
	ctx context.Context,
	request PublicationPushRequest,
	preparation PublicationPushPreparation,
) (PublicationPushPreparation, error) {
	if request.Record != nil {
		if err := request.Records.Consume(ctx, request.PublicationID); err != nil {
			return PublicationPushPreparation{}, err
		}
		if err := request.Records.Delete(ctx, request.PublicationID); err != nil {
			return PublicationPushPreparation{}, err
		}
	}
	return preparation, nil
}

func (coordinator *Coordinator) publicationPushRefusal(
	ctx context.Context,
	request PublicationPushRequest,
	err error,
) error {
	if stateError, ok := errors.AsType[*publicationstate.Error](err); ok {
		switch stateError.Reason() {
		case publicationstate.ReasonActiveAttempt:
			return ErrPublicationProposalActive
		case publicationstate.ReasonStale:
			if request.Record != nil {
				if consumeErr := request.Records.Consume(ctx, request.PublicationID); consumeErr != nil {
					return consumeErr
				}
			}
			return ErrPublicationProposalStale
		default:
			// Any other store reason is already the caller-visible refusal.
			return err
		}
	}
	return err
}

func newPublicationProposalRecord(proposal MaterialPublishProposal) PublicationProposalRecord {
	record := PublicationProposalRecord{
		Version: publicationProposalRecordVersion, Binding: proposal.Binding,
		Generation:           proposal.Proposal.CapturedGeneration,
		CandidateRecordCID:   bytes.Clone(proposal.Proposal.CandidateRecordCID),
		Form:                 proposal.Form,
		CandidatePayloadCID:  bytes.Clone(proposal.Proposal.CandidateBlobCID),
		CandidatePayloadSize: proposal.Proposal.CandidateBlobSize,
		Review:               proposal.Review, PublicationID: proposal.PublicationID,
		Lifecycle: publicationstate.AttemptPrepared, Confirmation: proposal.Confirmation,
	}
	if proposal.Form == publication.PayloadFormManifest {
		if snapshot, err := publication.DecodeSnapshot(proposal.Batch.SnapshotRecord); err == nil {
			record.CandidateEntryCount = len(snapshot.Entries)
			record.CandidateEntryDigest = manifestEntrySetDigest(snapshot.Entries)
		}
	}
	if proposal.Proposal.CapturedFloor != nil {
		record.DatabaseID = proposal.Proposal.CapturedFloor.DatabaseID
		record.FloorRevision = proposal.Proposal.CapturedFloor.Revision
	}
	return record
}

func validPublicationPushRequest(request PublicationPushRequest) bool {
	if request.Store == nil || request.Transport == nil || request.Reader == nil || request.Records == nil ||
		request.Reviews == nil ||
		!validMaterialBinding(request.Binding) {
		return false
	}
	if request.PublicationID == ([16]byte{}) || request.Configuration.Validate() != nil {
		return false
	}
	return true
}
