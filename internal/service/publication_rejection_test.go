package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

func TestATProtoMaterialApplyStatusMarksOnlyADefiniteProviderRefusal(t *testing.T) {
	ambiguous := map[string]struct {
		status   int
		response []byte
	}{
		"no body":           {status: 400},
		"empty body":        {status: 400, response: []byte("")},
		"unparseable body":  {status: 400, response: []byte("synthetic refusal")},
		"no error field":    {status: 400, response: []byte(`{"message":"synthetic refusal"}`)},
		"unsafe error name": {status: 400, response: []byte(`{"error":"not a code"}`)},
		"oversized name":    {status: 400, response: []byte(`{"error":"` + strings.Repeat("A", 65) + `"}`)},
		"foreign account":   {status: 401, response: []byte(`{"error":"AuthRequired"}`)},
		"forbidden":         {status: 403, response: []byte(`{"error":"AuthRequired"}`)},
		"server fault":      {status: 500, response: []byte(`{"error":"QuotaExceeded"}`)},
		"gateway fault":     {status: 502, response: []byte(`{"error":"QuotaExceeded"}`)},
	}
	for name, value := range ambiguous {
		t.Run(name, func(t *testing.T) {
			failure := atprotoMaterialApplyStatus(value.status, value.response)
			require.NotErrorIs(t, failure, ErrMaterialSubmissionRejected)
			assert.ErrorIs(t, failure, atproto.ErrCandidateMayBeDisclosed)
		})
	}

	definite := map[string]struct {
		status   int
		response []byte
		class    error
	}{
		"quota": {
			status:   400,
			response: []byte(`{"error":"QuotaExceeded"}`),
			class:    atproto.ErrPublicationQuota,
		},
		"storage quota": {
			status:   400,
			response: []byte(`{"error":"StorageQuotaExceeded"}`),
			class:    atproto.ErrPublicationQuota,
		},
		"rate limited": {
			status:   429,
			response: []byte(`{"error":"RateLimitExceeded"}`),
			class:    atproto.ErrPublicationRateLimited,
		},
		"payload too large": {
			status:   400,
			response: []byte(`{"error":"PayloadTooLarge"}`),
			class:    atproto.ErrPublicationBatchTooLarge,
		},
		"request too large": {
			status:   413,
			response: []byte(`{"error":"RequestTooLarge"}`),
			class:    atproto.ErrPublicationBatchTooLarge,
		},
		"fence lost": {status: 409, response: []byte(`{"error":"InvalidSwap"}`), class: atproto.ErrFenceLost},
		"auth required": {
			status:   400,
			response: []byte(`{"error":"AuthRequired"}`),
			class:    atproto.ErrBatchRejected,
		},
		"unrecognised code": {
			status:   400,
			response: []byte(`{"error":"InvalidRecord"}`),
			class:    atproto.ErrBatchRejected,
		},
		"provider rejection": {
			status:   400,
			response: []byte(`{"error":"ApplyWritesRejected"}`),
			class:    atproto.ErrBatchRejected,
		},
		"untyped list": {
			status:   422,
			response: []byte(`{"error":"SomethingElse"}`),
			class:    atproto.ErrBatchRejected,
		},
	}
	for name, value := range definite {
		t.Run(name, func(t *testing.T) {
			failure := atprotoMaterialApplyStatus(value.status, value.response)
			require.ErrorIs(t, failure, ErrMaterialSubmissionRejected)
			require.ErrorIs(t, failure, value.class)
			require.ErrorIs(t, failure, atproto.ErrCandidateMayBeDisclosed)
			assert.NotErrorIs(t, failure, atproto.ErrAmbiguousTransport)
		})
	}
	assert.Equal(
		t,
		"dispatch_rejected:400:QuotaExceeded",
		atprotoMaterialDispatchReason(400, []byte(`{"error":"QuotaExceeded"}`)),
	)
	assert.Equal(
		t,
		"dispatch_rejected:400:InvalidRecord",
		atprotoMaterialDispatchReason(400, []byte(`{"error":"InvalidRecord"}`)),
	)
}

func TestDefiniteSubmissionRejectionRetiresTheAttemptAndAmbiguityDoesNot(t *testing.T) {
	cases := map[string]struct {
		failure   error
		outcome   publicationstate.AttemptOutcome
		lifecycle publicationstate.AttemptLifecycle
		blocking  bool
	}{
		"definite refusal": {
			failure:   atprotoMaterialApplyStatus(400, []byte(`{"error":"QuotaExceeded"}`)),
			outcome:   publicationstate.OutcomeRejected,
			lifecycle: publicationstate.AttemptRetiredAbandoned,
			blocking:  false,
		},
		"ambiguous outcome": {
			failure:   errors.Join(atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed),
			outcome:   publicationstate.OutcomeUnresolved,
			lifecycle: publicationstate.AttemptMayHaveSubmitted,
			blocking:  true,
		},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newPublicationPushFixture(t)
			preparation, err := fixture.coordinator.PreparePublicationPush(
				ctx,
				fixture.request(fixture.publicationID, nil),
			)
			require.NoError(t, err)
			fixture.transport.setSendError(value.failure)
			_, err = fixture.coordinator.ConfirmPublicationPush(
				ctx,
				fixture.request(fixture.publicationID, nil),
				preparation,
				preparation.Proposal.Confirmation,
			)
			require.Error(t, err)
			if value.blocking {
				require.NotErrorIs(t, err, ErrMaterialSubmissionRejected)
			} else {
				require.ErrorIs(t, err, ErrMaterialSubmissionRejected)
			}

			failed, err := fixture.store.LoadAttempt(ctx, preparation.Proposal.Proposal.AttemptID)
			require.NoError(t, err)
			assert.Equal(t, value.outcome, failed.Outcome)
			assert.Equal(t, value.lifecycle, failed.Lifecycle)
			_, blocking, err := fixture.store.ActiveAttempt(ctx)
			require.NoError(t, err)
			assert.Equal(t, value.blocking, blocking)

			_, prepareErr := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x75, 0x76}, nil))
			if value.blocking {
				assert.ErrorIs(t, prepareErr, ErrPublicationProposalActive)
				return
			}
			require.NoError(t, prepareErr, "a retired rejection still blocks the next review")
			assert.Equal(t, 1, fixture.transport.sendCount(), "a definite refusal dispatched more than one submission")
		})
	}
}

func TestDefiniteSubmissionRejectionKeepsTheDisclosureWarningAndReleasesCustody(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	fixture.transport.setSendError(atprotoMaterialApplyStatus(400, []byte(`{"error":"QuotaExceeded"}`)))
	result, err := fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMaterialSubmissionRejected)
	require.ErrorIs(t, err, atproto.ErrCandidateMayBeDisclosed)
	require.ErrorIs(t, err, atproto.ErrPublicationQuota)
	require.NotErrorIs(t, err, atproto.ErrAmbiguousTransport)
	var staged interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &staged)
	assert.Equal(t, "submission", staged.Stage())
	assert.Equal(t, "submission_rejected", staged.Reason())
	assert.Equal(t, publicationstate.AttemptRetiredAbandoned, result.Attempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeRejected, result.Attempt.Outcome)
	record, found := fixture.records.has(fixture.publicationID)
	require.True(t, found)
	assert.True(t, record.Consumed, "the refused submission rewrote the retained proposal record")
	assert.Equal(t, 1, fixture.transport.sendCount())

	next, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request([16]byte{0x7d, 0x7e}, nil))
	require.NoError(t, err)
	assert.True(t, next.Issued, "the next review reused a retired proposal")
}

func TestDefiniteSubmissionRejectionDoesNotPublishOrRetainAFloor(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, fixture.request(fixture.publicationID, nil))
	require.NoError(t, err)
	fixture.transport.setSendError(ErrMaterialSubmissionRejected)
	_, err = fixture.coordinator.ConfirmPublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
		preparation,
		preparation.Proposal.Confirmation,
	)
	require.Error(t, err)

	_, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present, "a refused submission advanced the accepted floor")
	page, err := fixture.store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.Len(t, page.Attempts, 1)
	assert.Equal(t, publicationstate.AttemptRetiredAbandoned, page.Attempts[0].Lifecycle)
	assert.Equal(t, publicationstate.OutcomeRejected, page.Attempts[0].Outcome)
}
