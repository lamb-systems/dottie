package service

import (
	"bytes"
	"context"
	"errors"
	"reflect"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

var ErrPublicationReconciliation = errors.New("publication reconciliation refused")

type publicationReconciliationStage string
type publicationReconciliationReason string

type publicationReconciliationError struct {
	stage        publicationReconciliationStage
	reason       publicationReconciliationReason
	cancellation error
}

func (e *publicationReconciliationError) Error() string {
	return "publication reconciliation: " + string(e.stage) + "/" + string(e.reason)
}

func (e *publicationReconciliationError) Is(target error) bool {
	return target == ErrPublicationReconciliation || target != nil && target == e.cancellation
}

func (e *publicationReconciliationError) Stage() string  { return string(e.stage) }
func (e *publicationReconciliationError) Reason() string { return string(e.reason) }

type acceptedPublicationRequest struct {
	store          *publicationstate.Store
	binding        publicationstate.Binding
	expectedFloor  publicationstate.Floor
	snapshotRecord []byte
	payload        []byte
}

type acceptedPublicationMaterial struct {
	floor    publicationstate.Floor
	snapshot model.Snapshot
}

const (
	publicationStageInput    publicationReconciliationStage = "input"
	publicationStageLoad     publicationReconciliationStage = "load"
	publicationStageHistory  publicationReconciliationStage = "history"
	publicationStageRecord   publicationReconciliationStage = "record"
	publicationStagePayload  publicationReconciliationStage = "payload"
	publicationStagePosition publicationReconciliationStage = "position"

	publicationReasonRequestInvalid publicationReconciliationReason = "request_invalid"
	publicationReasonCanceled       publicationReconciliationReason = "canceled"
	publicationReasonNoFloor        publicationReconciliationReason = "no_floor"
	publicationReasonUnavailable    publicationReconciliationReason = "unavailable"
	publicationReasonBinding        publicationReconciliationReason = "binding_mismatch"
	publicationReasonFloor          publicationReconciliationReason = "floor_mismatch"
	publicationReasonEvidence       publicationReconciliationReason = "evidence_mismatch"
	publicationReasonRecord         publicationReconciliationReason = "record_invalid"
	publicationReasonPayload        publicationReconciliationReason = "payload_invalid"
	publicationReasonPosition       publicationReconciliationReason = "position_changed"
)

func validateAcceptedPublication(ctx context.Context, request acceptedPublicationRequest) (acceptedPublicationMaterial, error) {
	if ctx == nil || !validAcceptedPublicationRequest(request) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageInput, publicationReasonRequestInvalid, nil)
	}
	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageInput, publicationReasonCanceled, err)
	}

	floor, present, err := request.store.Load(ctx)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageLoad, publicationReasonUnavailable, err)
	}
	if !present {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageLoad, publicationReasonNoFloor, nil)
	}
	if floor.Binding != request.binding {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStagePosition, publicationReasonBinding, nil)
	}
	if !reflect.DeepEqual(floor, request.expectedFloor) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStagePosition, publicationReasonFloor, nil)
	}
	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageHistory, publicationReasonCanceled, err)
	}

	page, err := request.store.History(ctx, floor.Revision-1, 1)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageHistory, publicationReasonUnavailable, err)
	}
	if len(page.Events) != 1 || page.HasMore || page.NextRevision != floor.Revision {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageHistory, publicationReasonEvidence, nil)
	}
	event := page.Events[0]
	if event.Revision != floor.Revision || !reflect.DeepEqual(event.NewFloor, floor) || event.EventDigest != floor.AcceptedEventDigest || event.ObservationDigest != floor.ObservationDigest {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageHistory, publicationReasonEvidence, nil)
	}
	if !hasAcceptedRecordReference(event.Trace, floor) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageHistory, publicationReasonEvidence, nil)
	}
	if !hasAcceptedRecordEvidence(page.Records, request.snapshotRecord, floor) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageHistory, publicationReasonEvidence, nil)
	}

	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageRecord, publicationReasonCanceled, err)
	}
	record, err := publication.DecodeSnapshot(request.snapshotRecord)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageRecord, publicationReasonRecord, err)
	}
	recordCID, err := publication.RecordCID(request.snapshotRecord)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageRecord, publicationReasonRecord, err)
	}
	if !bytes.Equal(recordCID, floor.RecordCID) ||
		record.Vault != floor.Binding.Vault ||
		record.PublicationID != floor.PublicationID ||
		record.PublicationSeq != floor.Sequence ||
		!bytes.Equal(record.Blob.CID, floor.BlobCID) ||
		record.Blob.Size != floor.BlobSize {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageRecord, publicationReasonRecord, nil)
	}
	if keySequence, keyErr := publication.ParseSequenceKey(floor.SnapshotKey); keyErr != nil || keySequence != floor.Sequence {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageRecord, publicationReasonRecord, nil)
	}
	if err := publication.VerifyHeadBinding(floor.Head, request.snapshotRecord, floor.SnapshotKey); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageRecord, publicationReasonRecord, err)
	}
	head, err := publication.DecodeHead(floor.Head)
	if err != nil || head.Vault != floor.Binding.Vault || head.PublicationSeq != floor.Sequence || !bytes.Equal(head.SnapshotCID, floor.RecordCID) || !bytes.Equal(head.BlobCID, floor.BlobCID) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStageRecord, publicationReasonRecord, err)
	}

	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStagePayload, publicationReasonCanceled, err)
	}
	snapshot, err := publication.DecodePayload(request.payload, record.Blob)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(ctx, publicationStagePayload, publicationReasonPayload, err)
	}

	if err := checkAcceptedPublicationFloor(ctx, request.store, floor); err != nil {
		return acceptedPublicationMaterial{}, err
	}
	return acceptedPublicationMaterial{floor: clonePublicationFloor(floor), snapshot: clonePublicationSnapshot(snapshot)}, nil
}

func checkAcceptedPublicationFloor(ctx context.Context, store *publicationstate.Store, expected publicationstate.Floor) error {
	if ctx == nil || store == nil || !validPublicationFloorInput(expected) {
		return publicationReconciliationFailure(ctx, publicationStageInput, publicationReasonRequestInvalid, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationReconciliationFailure(ctx, publicationStagePosition, publicationReasonCanceled, err)
	}
	floor, present, err := store.Load(ctx)
	if err != nil {
		return publicationReconciliationFailure(ctx, publicationStagePosition, publicationReasonUnavailable, err)
	}
	if !present || !reflect.DeepEqual(floor, expected) {
		return publicationReconciliationFailure(ctx, publicationStagePosition, publicationReasonPosition, nil)
	}
	return nil
}

func validAcceptedPublicationRequest(request acceptedPublicationRequest) bool {
	return request.store != nil &&
		validPublicationBindingInput(request.binding) &&
		validPublicationFloorInput(request.expectedFloor) &&
		len(request.snapshotRecord) > 0 &&
		len(request.snapshotRecord) <= publication.MaxRecordBytes &&
		len(request.payload) > 0 &&
		uint64(len(request.payload)) <= publication.MaxBlobBytes
}

func validPublicationBindingInput(binding publicationstate.Binding) bool {
	return len(binding.AccountDID) > 0 && len(binding.AccountDID) <= 2048 && len(binding.Repository) > 0 && len(binding.Repository) <= 8192
}

func validPublicationFloorInput(floor publicationstate.Floor) bool {
	if floor.Revision == 0 || floor.Revision > publication.MaxSequence || floor.Generation == 0 || floor.Generation > publication.MaxSequence || floor.Sequence > publication.MaxSequence {
		return false
	}
	if len(floor.SnapshotKey) != publication.SequenceKeyLength || len(floor.AnchorCID) == 0 || len(floor.AnchorCID) > publication.MaxCIDBytes {
		return false
	}
	if len(floor.RecordCID) == 0 || len(floor.RecordCID) > publication.MaxCIDBytes || len(floor.BlobCID) == 0 || len(floor.BlobCID) > publication.MaxCIDBytes {
		return false
	}
	if floor.BlobSize == 0 || floor.BlobSize > publication.MaxBlobBytes || len(floor.Head) == 0 || len(floor.Head) > publication.MaxRecordBytes || !validPublicationBindingInput(floor.Binding) {
		return false
	}
	context := floor.SuppliedContext
	if len(context.RepositoryRevision) > 1024 || len(context.RepositoryDigest) > 128 {
		return false
	}
	if context.Policy != nil && (len(context.Policy.Revision) > 1024 || len(context.Policy.Identity) > 128) {
		return false
	}
	return true
}

func hasAcceptedRecordReference(references []publicationstate.RecordReference, floor publicationstate.Floor) bool {
	for _, reference := range references {
		if reference.Key == floor.SnapshotKey && reference.Sequence == floor.Sequence && bytes.Equal(reference.CID, floor.RecordCID) {
			return true
		}
	}
	return false
}

func hasAcceptedRecordEvidence(records []publicationstate.RecordEvidence, raw []byte, floor publicationstate.Floor) bool {
	matches := 0
	for _, evidence := range records {
		if evidence.Reference.Key != floor.SnapshotKey || evidence.Reference.Sequence != floor.Sequence || !bytes.Equal(evidence.Reference.CID, floor.RecordCID) {
			continue
		}
		matches++
		if !bytes.Equal(evidence.Raw, raw) {
			return false
		}
	}
	return matches == 1
}

func publicationReconciliationFailure(ctx context.Context, stage publicationReconciliationStage, reason publicationReconciliationReason, cause error) error {
	cancellation := error(nil)
	if ctx != nil {
		if err := ctx.Err(); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			cancellation = err
		}
	}
	if cancellation == nil {
		if errors.Is(cause, context.Canceled) {
			cancellation = context.Canceled
		} else if errors.Is(cause, context.DeadlineExceeded) {
			cancellation = context.DeadlineExceeded
		}
	}
	if cancellation != nil {
		reason = publicationReasonCanceled
	}
	return &publicationReconciliationError{stage: stage, reason: reason, cancellation: cancellation}
}

func clonePublicationFloor(floor publicationstate.Floor) publicationstate.Floor {
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

func clonePublicationSnapshot(snapshot model.Snapshot) model.Snapshot {
	out := model.Snapshot{Version: snapshot.Version}
	if snapshot.Targets != nil {
		out.Targets = make([]model.Target, len(snapshot.Targets))
	}
	if snapshot.Entries != nil {
		out.Entries = make([]model.Entry, len(snapshot.Entries))
	}
	for index, target := range snapshot.Targets {
		out.Targets[index] = target
		if target.Root != nil {
			root := *target.Root
			out.Targets[index].Root = &root
		}
	}
	for index, entry := range snapshot.Entries {
		out.Entries[index] = entry
		if entry.File != nil {
			file := *entry.File
			file.Content = bytes.Clone(entry.File.Content)
			out.Entries[index].File = &file
		}
		if entry.Setting != nil {
			setting := *entry.Setting
			if entry.Setting.Value != nil {
				value := *entry.Setting.Value
				setting.Value = &value
			}
			out.Entries[index].Setting = &setting
		}
	}
	return out
}
