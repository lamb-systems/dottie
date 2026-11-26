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
	payloads       [][]byte
	entries        []publication.PayloadEntry
}

type acceptedPublicationMaterial struct {
	floor    publicationstate.Floor
	form     publication.PayloadForm
	snapshot model.Snapshot
}

func (material acceptedPublicationMaterial) snapshotFor(portable model.Target) (model.Snapshot, error) {
	for _, target := range material.snapshot.Targets {
		if target.ID == portable.ID {
			return material.snapshot, nil
		}
	}
	return model.Snapshot{}, publication.ErrInvalidRecord
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

func validateAcceptedPublication(
	ctx context.Context,
	request acceptedPublicationRequest,
) (acceptedPublicationMaterial, error) {
	if ctx == nil || !validAcceptedPublicationRequest(request) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageInput,
			publicationReasonRequestInvalid,
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageInput,
			publicationReasonCanceled,
			err,
		)
	}

	floor, present, err := request.store.Load(ctx)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageLoad,
			publicationReasonUnavailable,
			err,
		)
	}
	if !present {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageLoad,
			publicationReasonNoFloor,
			nil,
		)
	}
	if floor.Binding != request.binding {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStagePosition,
			publicationReasonBinding,
			nil,
		)
	}
	if !reflect.DeepEqual(floor, request.expectedFloor) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStagePosition,
			publicationReasonFloor,
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageHistory,
			publicationReasonCanceled,
			err,
		)
	}

	page, err := request.store.History(ctx, floor.Revision-1, 1)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageHistory,
			publicationReasonUnavailable,
			err,
		)
	}
	if len(page.Events) != 1 || page.HasMore || page.NextRevision != floor.Revision {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageHistory,
			publicationReasonEvidence,
			nil,
		)
	}
	event := page.Events[0]
	if event.Revision != floor.Revision || !reflect.DeepEqual(event.NewFloor, floor) ||
		event.EventDigest != floor.AcceptedEventDigest ||
		event.ObservationDigest != floor.ObservationDigest {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageHistory,
			publicationReasonEvidence,
			nil,
		)
	}
	if !hasAcceptedRecordReference(event.Trace, floor) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageHistory,
			publicationReasonEvidence,
			nil,
		)
	}
	if !hasAcceptedRecordEvidence(page.Records, request.snapshotRecord, floor) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageHistory,
			publicationReasonEvidence,
			nil,
		)
	}

	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonCanceled,
			err,
		)
	}
	record, err := publication.DecodeSnapshot(request.snapshotRecord)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonRecord,
			err,
		)
	}
	recordCID, err := publication.RecordCID(request.snapshotRecord)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonRecord,
			err,
		)
	}
	if !bytes.Equal(recordCID, floor.RecordCID) ||
		record.Vault != floor.Binding.Vault ||
		record.PublicationID != floor.PublicationID ||
		record.PublicationSeq != floor.Sequence {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonRecord,
			nil,
		)
	}
	if !publicationFloorMatchesRecord(floor, record) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonRecord,
			nil,
		)
	}
	if keySequence, keyErr := publication.ParseSequenceKey(
		floor.SnapshotKey,
	); keyErr != nil ||
		keySequence != floor.Sequence {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonRecord,
			nil,
		)
	}
	if err := publication.VerifyHeadBinding(floor.Head, request.snapshotRecord, floor.SnapshotKey); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonRecord,
			err,
		)
	}
	head, err := publication.DecodeHead(floor.Head)
	if err != nil || head.Vault != floor.Binding.Vault || head.PublicationSeq != floor.Sequence ||
		!bytes.Equal(head.SnapshotCID, floor.RecordCID) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStageRecord,
			publicationReasonRecord,
			err,
		)
	}

	if err := ctx.Err(); err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStagePayload,
			publicationReasonCanceled,
			err,
		)
	}
	material := acceptedPublicationMaterial{form: record.PayloadForm()}
	payloads := request.payloads
	if len(payloads) == 0 {
		payloads = make([][]byte, len(record.Segments))
	}
	if len(payloads) != len(record.Segments) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStagePayload,
			publicationReasonPayload,
			nil,
		)
	}
	accepted := publicationstate.AcceptedMaterial{SnapshotRecord: bytes.Clone(request.snapshotRecord)}
	entryIndex := 0
	for index, segment := range record.Segments {
		item := publicationstate.AcceptedMaterialSegment{
			Summary: publicationstate.SegmentSummary{TargetID: segment.Target.ID},
		}
		switch segment.Form {
		case publication.SegmentFormPacked:
			item.Blob = bytes.Clone(payloads[index])
		case publication.SegmentFormEntries:
			count := len(segment.Entries)
			if entryIndex+count > len(request.entries) ||
				!fileSetPayloadEntriesMatch(segment.Entries, request.entries[entryIndex:entryIndex+count]) {
				return acceptedPublicationMaterial{}, publicationReconciliationFailure(
					ctx,
					publicationStagePayload,
					publicationReasonPayload,
					nil,
				)
			}
			for _, entry := range request.entries[entryIndex : entryIndex+count] {
				item.Entries = append(item.Entries, publicationstate.AcceptedMaterialEntry{
					Path: entry.Path, Mode: entry.Mode, Content: bytes.Clone(entry.Content),
				})
			}
			entryIndex += count
		case publication.SegmentFormSettings:
		default:
			return acceptedPublicationMaterial{}, publicationReconciliationFailure(
				ctx,
				publicationStageRecord,
				publicationReasonRecord,
				nil,
			)
		}
		accepted.Segments = append(accepted.Segments, item)
	}
	if entryIndex != len(request.entries) {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStagePayload,
			publicationReasonPayload,
			nil,
		)
	}
	snapshot, err := acceptedSnapshotFromSegments(record, accepted)
	if err != nil {
		return acceptedPublicationMaterial{}, publicationReconciliationFailure(
			ctx,
			publicationStagePayload,
			publicationReasonPayload,
			err,
		)
	}
	material.snapshot = snapshot

	if err := checkAcceptedPublicationFloor(ctx, request.store, floor); err != nil {
		return acceptedPublicationMaterial{}, err
	}
	material.floor = clonePublicationFloor(floor)
	return material, nil
}

func checkAcceptedPublicationFloor(
	ctx context.Context,
	store *publicationstate.Store,
	expected publicationstate.Floor,
) error {
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
	if request.store == nil || !validPublicationBindingInput(request.binding) ||
		!validPublicationFloorInput(request.expectedFloor) ||
		len(request.snapshotRecord) == 0 ||
		len(request.snapshotRecord) > publication.MaxFileSetRecordBytes {
		return false
	}
	if !validAcceptedPublicationMaterial(request.snapshotRecord, request.payloads, request.entries) {
		return false
	}
	return true
}

func validAcceptedPublicationMaterial(
	snapshotRecord []byte,
	payloads [][]byte,
	materialEntries []publication.PayloadEntry,
) bool {
	record, err := publication.DecodeSnapshot(snapshotRecord)
	if err != nil {
		return false
	}
	entries := 0
	if len(payloads) == 0 {
		payloads = make([][]byte, len(record.Segments))
	}
	if len(payloads) != len(record.Segments) {
		return false
	}
	var payloadBytes uint64
	for index, segment := range record.Segments {
		payload := payloads[index]
		switch segment.Form {
		case publication.SegmentFormPacked:
			size := uint64(len(payload))
			if size == 0 || size > publication.MaxBlobBytes || size > publication.MaxBlobBytes-payloadBytes {
				return false
			}
			payloadBytes += size
		case publication.SegmentFormEntries:
			if len(payload) != 0 {
				return false
			}
			entries += len(segment.Entries)
		case publication.SegmentFormSettings:
			if len(payload) != 0 {
				return false
			}
		}
	}
	if len(materialEntries) != entries {
		return false
	}
	var total uint64
	for _, entry := range materialEntries {
		size := uint64(len(entry.Content))
		if entry.Path == "" || entry.Mode != 0o600 && entry.Mode != 0o644 ||
			size == 0 || size > publication.MaxBlobBytes ||
			size > publication.MaxBlobBytes-total {
			return false
		}
		total += size
	}
	return true
}

func validPublicationBindingInput(binding publicationstate.Binding) bool {
	return len(binding.AccountDID) > 0 && len(binding.AccountDID) <= 2048 && len(binding.Repository) > 0 &&
		len(binding.Repository) <= 8192
}

func validPublicationFloorInput(floor publicationstate.Floor) bool {
	if floor.Revision == 0 || floor.Revision > publication.MaxSequence || floor.Generation == 0 ||
		floor.Generation > publication.MaxSequence ||
		floor.Sequence > publication.MaxSequence {
		return false
	}
	if len(floor.SnapshotKey) != publication.SequenceKeyLength || len(floor.AnchorCID) == 0 ||
		len(floor.AnchorCID) > publication.MaxCIDBytes {
		return false
	}
	if len(floor.RecordCID) == 0 || len(floor.RecordCID) > publication.MaxCIDBytes {
		return false
	}
	if len(floor.Segments) == 0 || len(floor.Segments) > publication.MaxSnapshotSettings {
		return false
	}
	if len(floor.Head) == 0 ||
		len(floor.Head) > publication.MaxRecordBytes ||
		!validPublicationBindingInput(floor.Binding) {
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
		if reference.Key == floor.SnapshotKey && reference.Sequence == floor.Sequence &&
			bytes.Equal(reference.CID, floor.RecordCID) {
			return true
		}
	}
	return false
}

func hasAcceptedRecordEvidence(
	records []publicationstate.RecordEvidence,
	raw []byte,
	floor publicationstate.Floor,
) bool {
	matches := 0
	for _, evidence := range records {
		if evidence.Reference.Key != floor.SnapshotKey || evidence.Reference.Sequence != floor.Sequence ||
			!bytes.Equal(evidence.Reference.CID, floor.RecordCID) {
			continue
		}
		matches++
		if !bytes.Equal(evidence.Raw, raw) {
			return false
		}
	}
	return matches == 1
}

func publicationReconciliationFailure(
	ctx context.Context,
	stage publicationReconciliationStage,
	reason publicationReconciliationReason,
	cause error,
) error {
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
	out.Segments = cloneSegmentSummariesService(floor.Segments)
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
