package service

import (
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

var ErrPublicationAccept = errors.New("publication accept refused")

var errPublicationAcceptRevision = errors.New("the accepted floor revision moved")

var errPublicationAcceptManifestPayload = &publication.ManifestPayloadError{
	Reason: publication.ManifestReasonPackedRequired,
}

type publicationAcceptStage string
type publicationAcceptReason string

type publicationAcceptError struct {
	stage        publicationAcceptStage
	reason       publicationAcceptReason
	cancellation error
	cause        error
}

func (e *publicationAcceptError) Error() string {
	return "publication accept: " + string(e.stage) + "/" + string(e.reason)
}

func (e *publicationAcceptError) Is(target error) bool {
	return target == ErrPublicationAccept || (target != nil && target == e.cancellation)
}

func (e *publicationAcceptError) Unwrap() error { return e.cause }

func (e *publicationAcceptError) Stage() string  { return string(e.stage) }
func (e *publicationAcceptError) Reason() string { return string(e.reason) }

const (
	publicationAcceptStageInput    publicationAcceptStage = "accept-input"
	publicationAcceptStagePosition publicationAcceptStage = "accept-position"
	publicationAcceptStagePrepare  publicationAcceptStage = "accept-prepare"
	publicationAcceptStageMaterial publicationAcceptStage = "accept-material"

	publicationAcceptReasonRequestInvalid publicationAcceptReason = "request_invalid"
	publicationAcceptReasonCanceled       publicationAcceptReason = "canceled"
	publicationAcceptReasonUnavailable    publicationAcceptReason = "unavailable"
	publicationAcceptReasonPositionAbsent publicationAcceptReason = "position_absent"
	publicationAcceptReasonRevision       publicationAcceptReason = "revision_moved"
	publicationAcceptReasonMode           publicationAcceptReason = "mode_refused"
	publicationAcceptReasonPrepare        publicationAcceptReason = "proposal_refused"
	publicationAcceptReasonMaterial       publicationAcceptReason = "material_refused"
	publicationAcceptReasonPayloadForm    publicationAcceptReason = "payload_form"
)

type PublicationAcceptStageRequest struct {
	Directory     string
	Binding       publicationstate.Binding
	FloorRevision uint64
	Observation   publicationstate.Observation
	Payload       []byte
}

type PublicationAcceptProposal struct {
	Mode              publicationstate.Mode
	StateToken        [32]byte
	Confirmation      [32]byte
	ObservationDigest [32]byte
}

type PublicationAcceptRequest struct {
	Directory     string
	Binding       publicationstate.Binding
	Mode          publicationstate.Mode
	FloorRevision uint64
	StateToken    [32]byte
	Confirmation  [32]byte
	Observation   publicationstate.Observation
	Payload       []byte
}

func StagePublicationAccept(
	ctx context.Context,
	request PublicationAcceptStageRequest,
) (PublicationAcceptProposal, error) {
	if ctx == nil || request.Directory == "" || len(request.Payload) == 0 {
		return PublicationAcceptProposal{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageInput,
			publicationAcceptReasonRequestInvalid,
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return PublicationAcceptProposal{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageInput,
			publicationAcceptReasonCanceled,
			err,
		)
	}
	if publicationAcceptObservationPayloadForm(request.Observation) == publication.PayloadFormManifest {
		return PublicationAcceptProposal{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageInput,
			publicationAcceptReasonPayloadForm,
			errPublicationAcceptManifestPayload,
		)
	}
	if _, err := publicationstate.Inspect(ctx, request.Directory, request.Binding); err != nil {
		return PublicationAcceptProposal{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStagePosition,
			publicationAcceptPositionReason(err),
			err,
		)
	}
	store, err := publicationstate.Open(request.Directory, request.Binding)
	if err != nil {
		return PublicationAcceptProposal{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStagePosition,
			publicationAcceptReasonUnavailable,
			err,
		)
	}
	defer func() { _ = store.Close() }()
	mode, err := publicationAcceptMode(ctx, store, request.FloorRevision)
	if err != nil {
		return PublicationAcceptProposal{}, err
	}
	proposal, err := store.Prepare(ctx, mode, request.Observation, request.Payload)
	if err != nil {
		return PublicationAcceptProposal{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStagePrepare,
			publicationAcceptReasonPrepare,
			err,
		)
	}
	return PublicationAcceptProposal{
		Mode: proposal.Mode, StateToken: proposal.StateToken,
		Confirmation: proposal.Confirmation, ObservationDigest: proposal.ObservationDigest,
	}, nil
}

func AcceptPublication(ctx context.Context, request PublicationAcceptRequest) (publicationstate.Floor, error) {
	if ctx == nil || request.Directory == "" || len(request.Payload) == 0 {
		return publicationstate.Floor{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageInput,
			publicationAcceptReasonRequestInvalid,
			nil,
		)
	}
	if publicationAcceptModeRefused(request.Mode) {
		return publicationstate.Floor{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageInput,
			publicationAcceptReasonMode,
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return publicationstate.Floor{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageInput,
			publicationAcceptReasonCanceled,
			err,
		)
	}
	if publicationAcceptObservationPayloadForm(request.Observation) == publication.PayloadFormManifest {
		return publicationstate.Floor{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageInput,
			publicationAcceptReasonPayloadForm,
			errPublicationAcceptManifestPayload,
		)
	}
	store, err := publicationstate.Open(request.Directory, request.Binding)
	if err != nil {
		return publicationstate.Floor{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStagePosition,
			publicationAcceptReasonUnavailable,
			err,
		)
	}
	defer func() { _ = store.Close() }()
	observed, err := publicationAcceptMode(ctx, store, request.FloorRevision)
	if err != nil {
		return publicationstate.Floor{}, err
	}
	if observed != request.Mode {
		return publicationstate.Floor{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStagePosition,
			publicationAcceptReasonMode,
			nil,
		)
	}
	accepted, err := store.AcceptMaterial(
		ctx,
		request.Mode,
		request.StateToken,
		request.Observation,
		request.Payload,
		request.Confirmation,
	)
	if err != nil {
		return publicationstate.Floor{}, publicationAcceptFailure(
			ctx,
			publicationAcceptStageMaterial,
			publicationAcceptReasonMaterial,
			err,
		)
	}
	return accepted, nil
}

func publicationAcceptMode(
	ctx context.Context,
	store *publicationstate.Store,
	floorRevision uint64,
) (publicationstate.Mode, error) {
	floor, present, err := store.Load(ctx)
	if err != nil {
		return "", publicationAcceptFailure(
			ctx,
			publicationAcceptStagePosition,
			publicationAcceptReasonUnavailable,
			err,
		)
	}
	if !present {
		if floorRevision != 0 {
			return "", publicationAcceptFailure(
				ctx,
				publicationAcceptStagePosition,
				publicationAcceptReasonRevision,
				errPublicationAcceptRevision,
			)
		}
		return publicationstate.ModeFirstUse, nil
	}
	if floor.Revision != floorRevision {
		return "", publicationAcceptFailure(
			ctx,
			publicationAcceptStagePosition,
			publicationAcceptReasonRevision,
			errPublicationAcceptRevision,
		)
	}
	return publicationstate.ModeAdvance, nil
}

func publicationAcceptPositionReason(err error) publicationAcceptReason {
	var stateError *publicationstate.Error
	if errors.As(err, &stateError) && stateError.Reason() == publicationstate.ReasonPositionAbsent {
		return publicationAcceptReasonPositionAbsent
	}
	return publicationAcceptReasonUnavailable
}

func publicationAcceptModeRefused(mode publicationstate.Mode) bool {
	return mode != publicationstate.ModeFirstUse && mode != publicationstate.ModeAdvance
}

func publicationAcceptObservationPayloadForm(observation publicationstate.Observation) publication.PayloadForm {
	if len(observation.Snapshots) == 0 {
		return publication.PayloadFormPacked
	}
	record, err := publication.DecodeSnapshot(observation.Snapshots[len(observation.Snapshots)-1].Raw)
	if err != nil {
		return publication.PayloadFormPacked
	}
	return record.PayloadForm()
}

func publicationAcceptFailure(
	ctx context.Context,
	stage publicationAcceptStage,
	reason publicationAcceptReason,
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
		reason = publicationAcceptReasonCanceled
	}
	return &publicationAcceptError{stage: stage, reason: reason, cancellation: cancellation, cause: cause}
}
