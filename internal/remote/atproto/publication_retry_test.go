package atproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type retryApplyResult struct {
	write     bool
	commitCID string
	err       error
}

type publicationRetryTestIO struct {
	predecessor  vault.Predecessor
	current      *Revision
	readErrors   map[int]error
	readCount    int
	stageCount   int
	stageErrors  []error
	stageCIDs    []string
	stageBytes   [][]byte
	applyCount   int
	applyResults []retryApplyResult
	stageEntered chan struct{}
	stageRelease <-chan struct{}
	stageOnce    sync.Once
}

func newPublicationRetryTestIO(predecessor vault.Predecessor) *publicationRetryTestIO {
	return &publicationRetryTestIO{predecessor: predecessor, readErrors: make(map[int]error)}
}

func (io *publicationRetryTestIO) ReadCurrent(_ context.Context) (*Revision, vault.Predecessor, error) {
	io.readCount++
	if err := io.readErrors[io.readCount]; err != nil {
		return nil, vault.Predecessor{}, err
	}
	if io.current != nil {
		return cloneTransitionTestRevision(io.current), io.predecessor, nil
	}
	revision, err := publicationRevisionForPredecessor(io.predecessor)
	return revision, io.predecessor, err
}

func (io *publicationRetryTestIO) StageCandidate(_ context.Context, data []byte, _ vault.Policy, _ [][]byte) (json.RawMessage, string, error) {
	io.stageCount++
	io.stageBytes = append(io.stageBytes, bytes.Clone(data))
	blobCID := cid.NewCidV1(cid.Raw, mustTransitionMultihash(data)).String()
	io.stageCIDs = append(io.stageCIDs, blobCID)
	if len(io.stageErrors) > 0 {
		err := io.stageErrors[0]
		io.stageErrors = io.stageErrors[1:]
		return nil, "", err
	}
	if io.stageEntered != nil {
		io.stageOnce.Do(func() {
			close(io.stageEntered)
			<-io.stageRelease
		})
	}
	blob, err := json.Marshal(atdata.Blob{Ref: atdata.CIDLink(cid.NewCidV1(cid.Raw, mustTransitionMultihash(data))), MimeType: "application/octet-stream", Size: int64(len(data))})
	return blob, blobCID, err
}

func (io *publicationRetryTestIO) applyPublication(_ context.Context, _ *Revision, publication FencedSnapshotPublication) (string, error) {
	io.applyCount++
	outcome := retryApplyResult{write: true, commitCID: "bafy-commit-result"}
	if len(io.applyResults) > 0 {
		outcome = io.applyResults[0]
		io.applyResults = io.applyResults[1:]
	}
	if outcome.write {
		io.current = publicationResolutionRevision(publication)
	}
	return outcome.commitCID, outcome.err
}

func retryTestOptions(store TransitionAttemptStore) PublicationRetryOptions {
	return PublicationRetryOptions{
		Store:  store,
		Policy: RetryPolicy{MaxAttempts: 3, BaseDelay: 0, MaxDelay: 0, MaxElapsed: time.Minute},
		Clock:  func() time.Time { return time.Unix(1000, 0) },
		Sleep:  func(context.Context, time.Duration) error { return nil },
		Jitter: func(limit time.Duration) time.Duration { return limit },
	}
}

func currentPublicationRevision(t *testing.T, publication vault.Publication, signer ed25519.PrivateKey, predecessor vault.Predecessor) *Revision {
	t.Helper()
	base, err := publicationRevisionForPredecessor(predecessor)
	require.NoError(t, err)
	candidate, err := snapshotPublication(publication, signer, blobJSONFromCID(publication.SnapshotCID, len(publication.Snapshot)), base, predecessor)
	require.NoError(t, err)
	revision := publicationResolutionRevision(candidate)
	require.NotNil(t, revision)
	return revision
}

func retryAttemptFor(t *testing.T, publication vault.Publication, signer ed25519.PrivateKey, outcome, disposition string) state.TransitionAttempt {
	t.Helper()
	marker, recordCID, err := publicationMarker(publication, signer)
	require.NoError(t, err)
	evidence, err := json.Marshal(publicationAttemptEvidence{
		Version: 1, Kind: "publication", HeadRecordCID: "bafy-head", PreparedRevision: "bafy-revision",
		RetryDisposition: &retryDispositionEvidence{Version: 1, Value: disposition},
	})
	require.NoError(t, err)
	return state.TransitionAttempt{
		ID: "retry-attempt", MarkerCollection: marker.Collection, MarkerRKey: marker.RKey,
		ExpectedRecordCID: recordCID, CandidateBlobCID: cid.NewCidV1(cid.Raw, mustTransitionMultihash(publication.Snapshot)).String(),
		EpochSeq: publication.Predecessor.EpochSeq, PolicyDigest: hex.EncodeToString(publication.PolicyDigest[:]),
		Outcome: outcome, Evidence: string(evidence), CreatedAt: 1,
	}
}

func addRetryAttempt(t *testing.T, store *transitionTestStore, attempt state.TransitionAttempt) {
	t.Helper()
	require.NoError(t, store.BeginTransitionAttempt(context.Background(), attempt))
}

func TestPublicationMarkerIsStableAndDoesNotUpload(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	marker, recordCID, err := publicationMarker(publication, signer.Signing)
	require.NoError(t, err)
	markerAgain, recordCIDAgain, err := publicationMarker(publication, signer.Signing)
	require.NoError(t, err)
	assert.Equal(t, marker, markerAgain)
	assert.Equal(t, recordCID, recordCIDAgain)
	assert.Equal(t, 0, io.stageCount)

	_, _, _, different := newAtprotoPublicationFixture(t)
	differentMarker, differentRecordCID, err := publicationMarker(different, signer.Signing)
	require.NoError(t, err)
	assert.NotEqual(t, marker, differentMarker)
	assert.NotEqual(t, recordCID, differentRecordCID)
	assert.Equal(t, 0, io.stageCount)
}

func TestPublishWithRetryCurrentMarkerOutcomesDoNotWrite(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(*testing.T, *Revision, string)
		wantStatus PublicationRetryStatus
		wantErr    error
		wantNoOp   bool
	}{
		{name: "no-op", wantStatus: PublicationCommitted, wantNoOp: true},
		{name: "ID reuse", mutate: func(_ *testing.T, revision *Revision, markerRKey string) {
			revision.membership[RecordKey{Collection: VaultSnapshotNSID, RKey: markerRKey}] = "bafy-different-record"
		}, wantStatus: PublicationRejected, wantErr: ErrPublicationIDReuse},
		{name: "superseded", mutate: func(t *testing.T, revision *Revision, _ string) {
			key := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
			decoded, err := DecodeRecord(revision.records[key].Data)
			require.NoError(t, err)
			head, ok := decoded.(HeadRecord)
			require.True(t, ok)
			head.SnapshotCID = []byte("different-snapshot")
			head.BlobCID = []byte("different-snapshot")
			require.NoError(t, addPublicationTestRecord(revision, key, head))
		}, wantStatus: PublicationSuperseded, wantErr: ErrPublicationSuperseded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			marker, _, err := publicationMarker(publication, signer.Signing)
			require.NoError(t, err)
			io := newPublicationRetryTestIO(predecessor)
			io.current = currentPublicationRevision(t, publication, signer.Signing, predecessor)
			if tc.mutate != nil {
				tc.mutate(t, io.current, marker.RKey)
			}
			store := newTransitionTestStore()
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
			assert.Equal(t, tc.wantStatus, result.Status)
			assert.Equal(t, tc.wantNoOp, result.NoOp)
			if tc.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.wantErr)
			}
			assert.Zero(t, io.stageCount)
			assert.Zero(t, io.applyCount)
		})
	}
}

func TestPublishWithRetryHistoricalRowsAndDispositionPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		disposition string
		status      PublicationRetryStatus
		wantErr     error
	}{
		{name: "rejected", disposition: retryDispositionRejected, status: PublicationRejected, wantErr: ErrPublicationRejected},
		{name: "quota", disposition: retryDispositionQuota, status: PublicationQueued, wantErr: ErrPublicationQueued},
		{name: "rate limited", disposition: retryDispositionRateLimited, status: PublicationQueued, wantErr: ErrPublicationQueued},
		{name: "upload too large", disposition: retryDispositionUploadTooLarge, status: PublicationRejected, wantErr: ErrPublicationRejected},
		{name: "batch too large", disposition: retryDispositionBatchTooLarge, status: PublicationRejected, wantErr: ErrPublicationRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			io := newPublicationRetryTestIO(predecessor)
			store := newTransitionTestStore()
			addRetryAttempt(t, store, retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeNotLanded, tc.disposition))
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
			assert.Equal(t, tc.status, result.Status)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Zero(t, io.stageCount)
			assert.Zero(t, io.applyCount)
		})
	}
}

func TestPublishWithRetryHistoricalRowWithDifferentRecordCIDIsIDReuse(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	store := newTransitionTestStore()
	attempt := retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeNotLanded, retryDispositionAmbiguous)
	attempt.ExpectedRecordCID = "bafy-different-record"
	addRetryAttempt(t, store, attempt)
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	assert.Equal(t, PublicationRejected, result.Status)
	assert.ErrorIs(t, err, ErrPublicationIDReuse)
	assert.Zero(t, io.stageCount)
	assert.Zero(t, io.applyCount)
}

func TestPublishWithRetryCommittedAndUnavailableRowsUseCurrentEvidenceReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outcome  string
		moveHead bool
		status   PublicationRetryStatus
		wantErr  error
	}{
		{name: "committed row marker absent", outcome: TransitionOutcomeCommitted, status: PublicationUnavailable, wantErr: ErrPublicationUnavailable},
		{name: "committed row current head moved", outcome: TransitionOutcomeCommitted, moveHead: true, status: PublicationSuperseded, wantErr: ErrPublicationSuperseded},
		{name: "unavailable row later committed", outcome: TransitionOutcomeUnavailable, status: PublicationCommitted},
		{name: "unavailable row later superseded", outcome: TransitionOutcomeUnavailable, moveHead: true, status: PublicationSuperseded, wantErr: ErrPublicationSuperseded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			io := newPublicationRetryTestIO(predecessor)
			store := newTransitionTestStore()
			addRetryAttempt(t, store, retryAttemptFor(t, publication, signer.Signing, tc.outcome, retryDispositionAmbiguous))
			if tc.outcome == TransitionOutcomeUnavailable || tc.moveHead {
				io.current = currentPublicationRevision(t, publication, signer.Signing, predecessor)
				if tc.moveHead {
					headKey := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
					head := io.current.records[headKey]
					decoded, err := DecodeRecord(head.Data)
					require.NoError(t, err)
					headRecord := decoded.(HeadRecord)
					headRecord.SnapshotCID = []byte("other-snapshot")
					headRecord.BlobCID = []byte("other-snapshot")
					require.NoError(t, addPublicationTestRecord(io.current, headKey, headRecord))
				}
			}
			before, err := store.TransitionAttemptsByMarker(context.Background(), VaultSnapshotNSID, publicationMarkerRKey(mustPublicationID(t, publication)))
			require.NoError(t, err)
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
			assert.Equal(t, tc.status, result.Status)
			if tc.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.wantErr)
			}
			assert.Zero(t, io.stageCount)
			assert.Zero(t, io.applyCount)
			after, queryErr := store.TransitionAttemptsByMarker(context.Background(), VaultSnapshotNSID, publicationMarkerRKey(mustPublicationID(t, publication)))
			require.NoError(t, queryErr)
			assert.Equal(t, before, after, "read-only terminal recovery must not rewrite attempt rows")
		})
	}
}

func TestResolveSubmittedPublicationPreservesReadCause(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	cause := ErrAuthMethodSession
	io.readErrors[1] = cause
	store := newTransitionTestStore()
	attempt := retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeSubmitted, retryDispositionAmbiguous)
	addRetryAttempt(t, store, attempt)
	_, err := resolveSubmittedPublication(context.Background(), io, store, attempt, attempt.Evidence)
	require.ErrorIs(t, err, ErrTransitionUnavailable)
	assert.ErrorIs(t, err, cause)
}

func TestPublishWithRetryMissingOrUnknownDispositionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		outcome     string
		disposition string
		remove      bool
		wantStatus  PublicationRetryStatus
	}{
		{name: "missing not-landed", outcome: TransitionOutcomeNotLanded, remove: true, wantStatus: PublicationQueued},
		{name: "unknown value", outcome: TransitionOutcomeNotLanded, disposition: "future-value", wantStatus: PublicationQueued},
		{name: "unknown version", outcome: TransitionOutcomeUnavailable, disposition: retryDispositionAmbiguous, wantStatus: PublicationUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			io := newPublicationRetryTestIO(predecessor)
			store := newTransitionTestStore()
			attempt := retryAttemptFor(t, publication, signer.Signing, tc.outcome, tc.disposition)
			if tc.remove {
				var evidence map[string]json.RawMessage
				require.NoError(t, json.Unmarshal([]byte(attempt.Evidence), &evidence))
				delete(evidence, "retryDisposition")
				encoded, err := json.Marshal(evidence)
				require.NoError(t, err)
				attempt.Evidence = string(encoded)
			}
			if tc.name == "unknown version" {
				var evidence map[string]json.RawMessage
				require.NoError(t, json.Unmarshal([]byte(attempt.Evidence), &evidence))
				var disposition retryDispositionEvidence
				require.NoError(t, json.Unmarshal(evidence["retryDisposition"], &disposition))
				disposition.Version = 2
				encodedDisposition, err := json.Marshal(disposition)
				require.NoError(t, err)
				evidence["retryDisposition"] = encodedDisposition
				encoded, err := json.Marshal(evidence)
				require.NoError(t, err)
				attempt.Evidence = string(encoded)
			}
			addRetryAttempt(t, store, attempt)
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
			assert.Equal(t, tc.wantStatus, result.Status)
			assert.Error(t, err)
			assert.Zero(t, io.stageCount)
			assert.Zero(t, io.applyCount)
		})
	}
}

func TestPublishWithRetryPendingAttemptsAndReadErrorStrata(t *testing.T) {
	for _, outcome := range []string{TransitionOutcomePrepared, TransitionOutcomeStaged, TransitionOutcomeSubmitted} {
		t.Run(outcome, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			io := newPublicationRetryTestIO(predecessor)
			store := newTransitionTestStore()
			attempt := retryAttemptFor(t, publication, signer.Signing, outcome, retryDispositionAmbiguous)
			addRetryAttempt(t, store, attempt)
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
			require.NoError(t, err)
			assert.Equal(t, PublicationCommitted, result.Status)
			attempts, err := store.TransitionAttemptsByMarker(context.Background(), attempt.MarkerCollection, attempt.MarkerRKey)
			require.NoError(t, err)
			assert.Equal(t, TransitionOutcomeNotLanded, attempts[0].Outcome)
			assert.Equal(t, 1, io.stageCount)
		})
	}

	for _, tc := range []struct {
		name      string
		readError error
		status    PublicationRetryStatus
		wantErr   error
		reads     int
	}{
		{name: "transient read retries", readError: ErrAmbiguousTransport, status: PublicationCommitted, reads: 2},
		{name: "permanent proof failure", readError: ErrSignature, status: PublicationUnavailable, wantErr: ErrPublicationUnavailable, reads: 1},
		{name: "read auth", readError: &ReadStatusError{StatusCode: 401}, status: PublicationQueued, wantErr: ErrPublicationQueued, reads: 1},
		{name: "read rate limited", readError: &ReadStatusError{StatusCode: 429, Code: "RateLimitExceeded"}, status: PublicationQueued, wantErr: ErrPublicationRateLimited, reads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			io := newPublicationRetryTestIO(predecessor)
			io.readErrors[1] = tc.readError
			store := newTransitionTestStore()
			options := retryTestOptions(store)
			var sleeps int
			options.Sleep = func(context.Context, time.Duration) error { sleeps++; return nil }
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, options)
			assert.Equal(t, tc.status, result.Status)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.reads, result.Attempts)
			if tc.name == "transient read retries" {
				assert.Equal(t, 1, sleeps)
			} else {
				assert.Zero(t, sleeps)
			}
		})
	}
}

func TestPublishWithRetryLocalUploadLimitDoesNotSignalDisclosure(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.stageErrors = []error{ErrCandidateExceedsBlobUploadLimit}
	store := newTransitionTestStore()
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.ErrorIs(t, err, ErrPublicationRejected)
	assert.Equal(t, PublicationRejected, result.Status)
	assert.NotErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.Zero(t, io.applyCount)
}

func TestPublishWithRetryAmbiguousAbsenceRetriesSameCandidate(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.applyResults = []retryApplyResult{{write: false, err: errors.Join(ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)}, {write: true}}
	store := newTransitionTestStore()
	addRetryAttempt(t, store, retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeNotLanded, retryDispositionAmbiguous))
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.NoError(t, err)
	assert.Equal(t, PublicationCommitted, result.Status)
	assert.Equal(t, 2, result.Attempts)
	assert.Equal(t, 2, io.stageCount)
	assert.Equal(t, 2, io.applyCount)
	require.Len(t, io.stageCIDs, 2)
	assert.Equal(t, io.stageCIDs[0], io.stageCIDs[1])
	assert.Equal(t, publication.Snapshot, io.stageBytes[0])
	assert.Equal(t, publication.Snapshot, io.stageBytes[1])
}

func TestPublishWithRetryUnavailableAmbiguousAbsenceRetries(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	store := newTransitionTestStore()
	addRetryAttempt(t, store, retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeUnavailable, retryDispositionAmbiguous))
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.NoError(t, err)
	assert.Equal(t, PublicationCommitted, result.Status)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 1, io.applyCount)
}

func TestPublishWithRetryExpiredTemporaryUploadReuploadsSameCID(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.applyResults = []retryApplyResult{{write: false, err: errors.Join(ErrAmbiguousTransport, errors.New("temporary blob expired"))}, {write: true}}
	store := newTransitionTestStore()
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.NoError(t, err)
	assert.Equal(t, PublicationCommitted, result.Status)
	assert.Equal(t, 2, io.stageCount)
	assert.Equal(t, 2, io.applyCount)
	assert.Equal(t, io.stageCIDs[0], io.stageCIDs[1])
}

func TestPublishWithRetryQueuedProviderOutcomesDoNotApplyOrRetry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stageError error
		applyError error
		want       error
		applyCount int
	}{
		{name: "upload quota", stageError: errors.Join(ErrPublicationQuota, ErrCandidateMayBeDisclosed), want: ErrPublicationQuota},
		{name: "upload rate limited", stageError: errors.Join(ErrPublicationRateLimited, ErrCandidateMayBeDisclosed), want: ErrPublicationRateLimited},
		{name: "upload auth transport", stageError: errors.Join(ErrAmbiguousTransport, ErrAuthMethodSession, ErrCandidateMayBeDisclosed), want: ErrAuthMethodSession},
		{name: "apply quota", applyError: errors.Join(ErrPublicationQuota, ErrCandidateMayBeDisclosed), want: ErrPublicationQuota, applyCount: 1},
		{name: "apply rate limited", applyError: errors.Join(ErrPublicationRateLimited, ErrCandidateMayBeDisclosed), want: ErrPublicationRateLimited, applyCount: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			io := newPublicationRetryTestIO(predecessor)
			if tc.stageError != nil {
				io.stageErrors = []error{tc.stageError}
			}
			if tc.applyError != nil {
				io.applyResults = []retryApplyResult{{write: false, err: tc.applyError}}
			}
			store := newTransitionTestStore()
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
			require.ErrorIs(t, err, ErrPublicationQueued)
			assert.ErrorIs(t, err, tc.want)
			assert.Equal(t, PublicationQueued, result.Status)
			assert.Equal(t, tc.applyCount, io.applyCount)
			assert.Equal(t, 1, io.stageCount)
		})
	}
}

func TestPublishWithRetryTimeoutAfterCommitUsesCurrentEvidence(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.applyResults = []retryApplyResult{{write: true, err: errors.Join(ErrAmbiguousTransport, context.DeadlineExceeded)}}
	store := newTransitionTestStore()
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.NoError(t, err)
	assert.Equal(t, PublicationCommitted, result.Status)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 1, io.applyCount)
}

func TestPublishWithRetryAmbiguousExhaustionIsStarved(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.applyResults = []retryApplyResult{
		{write: false, err: errors.Join(ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)},
		{write: false, err: errors.Join(ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)},
		{write: false, err: errors.Join(ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)},
	}
	store := newTransitionTestStore()
	options := retryTestOptions(store)
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, options)
	require.ErrorIs(t, err, ErrPublicationStarved)
	assert.Equal(t, PublicationStarved, result.Status)
	assert.Equal(t, 3, result.Attempts)
	assert.Equal(t, 3, io.stageCount)
	assert.Equal(t, 3, io.applyCount)
	assert.NotEmpty(t, result.LastError)
}

func TestPublishWithRetryDefinitiveRejectionDoesNotRetry(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.applyResults = []retryApplyResult{{write: false, err: errors.Join(ErrBatchRejected, ErrCandidateMayBeDisclosed)}}
	store := newTransitionTestStore()
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	assert.Equal(t, PublicationRejected, result.Status)
	assert.ErrorIs(t, err, ErrPublicationRejected)
	assert.ErrorIs(t, err, ErrBatchRejected)
	assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 1, io.applyCount)
}

func TestPublishWithRetryInvalidSwapIsFenceLost(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.applyResults = []retryApplyResult{{write: false, err: ErrFenceLost}}
	store := newTransitionTestStore()
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.ErrorIs(t, err, ErrPublicationRetryFenceLost)
	assert.ErrorIs(t, err, ErrFenceLost)
	assert.Equal(t, PublicationFenceLost, result.Status)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 1, io.applyCount)
}

func TestPublishWithRetryTwoXxWithoutCommitCIDUsesCurrentEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		write      bool
		commitCID  string
		wantStatus PublicationRetryStatus
		wantStages int
	}{
		{name: "marker absent retries", write: false, wantStatus: PublicationCommitted, wantStages: 2},
		{name: "marker absent with unrelated commit CID retries", write: false, commitCID: "bafy-unrelated-result", wantStatus: PublicationCommitted, wantStages: 2},
		{name: "marker present commits by proof", write: true, wantStatus: PublicationCommitted, wantStages: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
			io := newPublicationRetryTestIO(predecessor)
			io.applyResults = []retryApplyResult{{write: tc.write, commitCID: tc.commitCID}, {write: true}}
			store := newTransitionTestStore()
			result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, result.Status)
			assert.Equal(t, tc.wantStages, io.stageCount)
		})
	}
}

func TestPublishWithRetryPersistsDispositionBeforeFailedOutcomeUpdate(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	store := &failPublicationOutcomeStore{transitionTestStore: newTransitionTestStore(), failOutcome: TransitionOutcomeCommitted}
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.ErrorIs(t, err, ErrPublicationState)
	assert.Equal(t, PublicationQueued, result.Status)
	marker, _, markerErr := publicationMarker(publication, signer.Signing)
	require.NoError(t, markerErr)
	attempts, err := store.TransitionAttemptsByMarker(context.Background(), marker.Collection, marker.RKey)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	disposition, valid := parseRetryDisposition(attempts[0].Evidence)
	assert.True(t, valid)
	assert.Equal(t, retryDispositionAmbiguous, disposition)
	assert.Equal(t, TransitionOutcomeSubmitted, attempts[0].Outcome)
}

type failPublicationDispositionStore struct {
	*transitionTestStore
	failValue string
	failed    bool
}

func (s *failPublicationDispositionStore) UpdateTransitionAttempt(ctx context.Context, id, outcome, evidence string) error {
	if !s.failed {
		var parsed struct {
			RetryDisposition *retryDispositionEvidence `json:"retryDisposition"`
		}
		if json.Unmarshal([]byte(evidence), &parsed) == nil && parsed.RetryDisposition != nil && parsed.RetryDisposition.Value == s.failValue {
			s.failed = true
			return errors.New("synthetic disposition persistence failure")
		}
	}
	return s.transitionTestStore.UpdateTransitionAttempt(ctx, id, outcome, evidence)
}

type failPublicationOutcomeStore struct {
	*transitionTestStore
	failOutcome string
	failed      bool
}

func (s *failPublicationOutcomeStore) UpdateTransitionAttempt(ctx context.Context, id, outcome, evidence string) error {
	if !s.failed && outcome == s.failOutcome {
		s.failed = true
		return errors.New("synthetic outcome update failure")
	}
	return s.transitionTestStore.UpdateTransitionAttempt(ctx, id, outcome, evidence)
}

func TestResolvePublicationAttemptWaitsForMarkerLock(t *testing.T) {
	_, signer, _, publication := newAtprotoPublicationFixture(t)
	marker, _, err := publicationMarker(publication, signer.Signing)
	require.NoError(t, err)
	store := newTransitionTestStore()
	attempt := retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeSubmitted, retryDispositionAmbiguous)
	addRetryAttempt(t, store, attempt)
	release, err := acquirePublicationMarker(context.Background(), marker)
	require.NoError(t, err)
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = ResolvePublicationAttempt(ctx, ATProtoPublicationIO{Reader: RevisionReader{Transport: &proofTransport{}}, DID: testDID}, store, attempt.ID)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestPublishWithRetryDispositionWriteFailureStopsWithoutRetry(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.applyResults = []retryApplyResult{{write: false, err: errors.Join(ErrBatchRejected, ErrCandidateMayBeDisclosed)}}
	store := &failPublicationDispositionStore{transitionTestStore: newTransitionTestStore(), failValue: retryDispositionRejected}
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.ErrorIs(t, err, ErrPublicationState)
	require.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.Equal(t, PublicationQueued, result.Status)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 1, io.applyCount)
	marker, _, markerErr := publicationMarker(publication, signer.Signing)
	require.NoError(t, markerErr)
	attempts, queryErr := store.TransitionAttemptsByMarker(context.Background(), marker.Collection, marker.RKey)
	require.NoError(t, queryErr)
	require.Len(t, attempts, 1)
	assert.Equal(t, TransitionOutcomeSubmitted, attempts[0].Outcome)
	disposition, valid := parseRetryDisposition(attempts[0].Evidence)
	assert.True(t, valid)
	assert.Equal(t, retryDispositionAmbiguous, disposition)
}

func TestPublishWithRetryPreDispatchDispositionFailureStops(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	store := &failPublicationDispositionStore{transitionTestStore: newTransitionTestStore(), failValue: retryDispositionAmbiguous}
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, retryTestOptions(store))
	require.ErrorIs(t, err, ErrPublicationState)
	assert.Equal(t, PublicationQueued, result.Status)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 0, io.applyCount)
}

func TestResolveSubmittedPublicationClassifiesReadVsStateFailure(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.readErrors[1] = ErrAmbiguousTransport
	store := newTransitionTestStore()
	attempt := retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeSubmitted, retryDispositionAmbiguous)
	addRetryAttempt(t, store, attempt)
	_, err := resolveSubmittedPublication(context.Background(), io, store, attempt, attempt.Evidence)
	require.ErrorIs(t, err, ErrTransitionUnavailable)
	assert.NotErrorIs(t, err, ErrPublicationState)

	io = newPublicationRetryTestIO(predecessor)
	io.readErrors[1] = ErrAmbiguousTransport
	failingStore := &failPublicationOutcomeStore{transitionTestStore: newTransitionTestStore(), failOutcome: TransitionOutcomeUnavailable}
	attempt = retryAttemptFor(t, publication, signer.Signing, TransitionOutcomeSubmitted, retryDispositionAmbiguous)
	addRetryAttempt(t, failingStore.transitionTestStore, attempt)
	_, err = resolveSubmittedPublication(context.Background(), io, failingStore, attempt, attempt.Evidence)
	require.ErrorIs(t, err, ErrPublicationState)
}

func TestPublishWithRetrySerializesSameMarker(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	io := newPublicationRetryTestIO(predecessor)
	io.stageEntered = make(chan struct{})
	releaseStage := make(chan struct{})
	io.stageRelease = releaseStage
	store := newTransitionTestStore()
	options := retryTestOptions(store)
	first := make(chan struct {
		result PublicationRetryResult
		err    error
	}, 1)
	second := make(chan struct {
		result PublicationRetryResult
		err    error
	}, 1)
	go func() {
		result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, options)
		first <- struct {
			result PublicationRetryResult
			err    error
		}{result: result, err: err}
	}()
	<-io.stageEntered
	marker, _, err := publicationMarker(publication, signer.Signing)
	require.NoError(t, err)
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, options)
		second <- struct {
			result PublicationRetryResult
			err    error
		}{result: result, err: err}
	}()
	<-secondStarted
	waitForPublicationLockUsers(t, marker, 2)
	close(releaseStage)
	firstResult := <-first
	secondResult := <-second
	require.NoError(t, firstResult.err)
	require.NoError(t, secondResult.err)
	assert.Equal(t, PublicationCommitted, firstResult.result.Status)
	assert.Equal(t, PublicationCommitted, secondResult.result.Status)
	assert.True(t, secondResult.result.NoOp)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 1, io.applyCount)
}

func waitForPublicationLockUsers(t *testing.T, marker RecordKey, users int) {
	t.Helper()
	for range 100000 {
		publicationMarkerLocks.Lock()
		lock := publicationMarkerLocks.locks[marker]
		found := lock != nil && lock.users >= users
		publicationMarkerLocks.Unlock()
		if found {
			return
		}
		runtime.Gosched()
	}
	assert.Fail(t, "same-marker caller did not join the process-local lock")
}

func mustPublicationID(t *testing.T, publication vault.Publication) [16]byte {
	t.Helper()
	envelope, err := vault.DecodeEnvelope(publication.Snapshot)
	require.NoError(t, err)
	return envelope.PublicationID
}

func TestPublishWithRetryPolicyDefaultsAndDelayBounds(t *testing.T) {
	assert.Equal(t, RetryPolicy{MaxAttempts: 3, BaseDelay: 250 * time.Millisecond, MaxDelay: 5 * time.Second, MaxElapsed: 10 * time.Second}, DefaultRetryPolicy())
	policy := RetryPolicy{MaxAttempts: 3, BaseDelay: 250 * time.Millisecond, MaxDelay: 400 * time.Millisecond, MaxElapsed: time.Second}
	started := time.Unix(1, 0)
	clock := func() time.Time { return started }
	var sleeps []time.Duration
	var jitterLimits []time.Duration
	for cycle := 1; cycle <= policy.MaxAttempts; cycle++ {
		err := retryWait(context.Background(), policy, cycle, started, clock, func(limit time.Duration) time.Duration {
			jitterLimits = append(jitterLimits, limit)
			return limit + time.Second
		}, func(_ context.Context, delay time.Duration) error {
			sleeps = append(sleeps, delay)
			return nil
		})
		require.NoError(t, err)
	}
	assert.Equal(t, []time.Duration{250 * time.Millisecond, 400 * time.Millisecond}, jitterLimits)
	assert.Equal(t, []time.Duration{250 * time.Millisecond, 400 * time.Millisecond}, sleeps)
	for index, delay := range sleeps {
		assert.GreaterOrEqual(t, delay, time.Duration(0))
		assert.LessOrEqual(t, delay, policy.MaxDelay)
		if index > 0 {
			assert.GreaterOrEqual(t, delay, sleeps[index-1])
		}
	}
}

func TestPublicationRetryMaxElapsedCancelsRead(t *testing.T) {
	_, signer, predecessor, publication := newAtprotoPublicationFixture(t)
	entered := make(chan struct{})
	io := &blockingPublicationReadIO{publicationRetryTestIO: newPublicationRetryTestIO(predecessor), entered: entered}
	store := newTransitionTestStore()
	options := retryTestOptions(store)
	options.Policy.MaxElapsed = 20 * time.Millisecond
	result, err := publishWithRetry(context.Background(), publication, signer.Signing, io, store, options)
	require.ErrorIs(t, err, ErrPublicationUnavailable)
	assert.Equal(t, PublicationUnavailable, result.Status)
	<-entered
	assert.Equal(t, 0, io.stageCount)
	assert.Equal(t, 0, io.applyCount)
}

type blockingPublicationReadIO struct {
	*publicationRetryTestIO
	entered chan struct{}
}

func (io *blockingPublicationReadIO) ReadCurrent(ctx context.Context) (*Revision, vault.Predecessor, error) {
	select {
	case <-io.entered:
	default:
		close(io.entered)
	}
	<-ctx.Done()
	return nil, vault.Predecessor{}, ctx.Err()
}
