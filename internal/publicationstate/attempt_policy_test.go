package publicationstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNeverSubmittedAbandonmentDoesNotRequireCurrentPublicationPolicy(t *testing.T) {
	for _, lifecycle := range []string{"prepared", "upload-started", "may-have-submitted"} {
		t.Run(lifecycle, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendSpaces)
			f.appendRecord(t, 0)
			store, _ := newStore(t, f)
			defer store.Close()
			candidate := attemptCandidate(f, 0)
			empty := attemptView(f, f.observation(1), true)
			review := attemptReview()
			proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
			require.NoError(t, err)
			attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
			require.NoError(t, err)
			if lifecycle != "prepared" {
				uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, empty, review)
				require.NoError(t, err)
				_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, empty, review, uploadProposal.Confirmation)
				require.NoError(t, err)
			}
			if lifecycle == "may-have-submitted" {
				submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
				require.NoError(t, err)
				_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, empty, review, submissionProposal.Confirmation)
				require.NoError(t, err)
			}
			broadened := cloneSuppliedView(empty)
			broadened.SuppliedContext.Policy.OwnerOnly = false
			_, err = store.PrepareAbandon(ctx, attempt.ID, &broadened)
			require.ErrorIs(t, err, ErrInvalid)
			if lifecycle == "may-have-submitted" {
				policyChanged := cloneSuppliedView(empty)
				policyChanged.SuppliedContext.Policy.Revision = "new-policy-revision"
				loaded, err := store.LoadAttempt(ctx, attempt.ID)
				require.NoError(t, err)
				_, err = store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, policyChanged)
				requireErrorMetadata(t, err, ErrContinuity, StageResolve, ReasonContext)
				_, err = store.PrepareAbandon(ctx, attempt.ID, nil)
				requireErrorMetadata(t, err, ErrContinuity, StageAbandon, ReasonSubmittedUnknown)
				return
			}
			abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
			require.NoError(t, err)
			retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
		})
	}
}
