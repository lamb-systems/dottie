package atproto

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	MaxElapsed  time.Duration
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 3, BaseDelay: 250 * time.Millisecond, MaxDelay: 5 * time.Second, MaxElapsed: 10 * time.Second}
}

type PublicationRetryStatus string

const (
	PublicationCommitted   PublicationRetryStatus = "committed"
	PublicationQueued      PublicationRetryStatus = "queued"
	PublicationStarved     PublicationRetryStatus = "starved"
	PublicationFenceLost   PublicationRetryStatus = "fence-lost"
	PublicationSuperseded  PublicationRetryStatus = "committed-but-superseded"
	PublicationUnavailable PublicationRetryStatus = "unavailable"
	PublicationRejected    PublicationRetryStatus = "rejected"
)

type PublicationRetryResult struct {
	Status      PublicationRetryStatus
	Attempts    int
	NoOp        bool
	Marker      RecordKey
	RecordCID   string
	BlobCID     string
	Revision    *Revision
	Predecessor *vault.Predecessor
	Evidence    string
	LastError   string
}

type PublicationRetryOptions struct {
	IO     ATProtoPublicationIO
	Store  TransitionAttemptStore
	Policy RetryPolicy
	Sleep  func(context.Context, time.Duration) error
	Clock  func() time.Time
	Jitter func(time.Duration) time.Duration
}

type publicationMarkerLock struct {
	token chan struct{}
	users int
}

var publicationMarkerLocks = struct {
	sync.Mutex
	locks map[RecordKey]*publicationMarkerLock
}{locks: make(map[RecordKey]*publicationMarkerLock)}

func acquirePublicationMarker(ctx context.Context, marker RecordKey) (func(), error) {
	publicationMarkerLocks.Lock()
	lock := publicationMarkerLocks.locks[marker]
	if lock == nil {
		lock = &publicationMarkerLock{token: make(chan struct{}, 1)}
		lock.token <- struct{}{}
		publicationMarkerLocks.locks[marker] = lock
	}
	lock.users++
	publicationMarkerLocks.Unlock()

	select {
	case <-ctx.Done():
		releasePublicationMarkerRef(marker, lock)
		return nil, ctx.Err()
	case <-lock.token:
	}
	return func() {
		lock.token <- struct{}{}
		releasePublicationMarkerRef(marker, lock)
	}, nil
}

func releasePublicationMarkerRef(marker RecordKey, lock *publicationMarkerLock) {
	publicationMarkerLocks.Lock()
	lock.users--
	if lock.users == 0 {
		delete(publicationMarkerLocks.locks, marker)
	}
	publicationMarkerLocks.Unlock()
}

func PublishWithRetry(ctx context.Context, publication vault.Publication, signer ed25519.PrivateKey, options PublicationRetryOptions) (PublicationRetryResult, error) {
	return publishWithRetry(ctx, publication, signer, options.IO, options.Store, options)
}

func publishWithRetry(ctx context.Context, publication vault.Publication, signer ed25519.PrivateKey, io publicationIO, store TransitionAttemptStore, options PublicationRetryOptions) (PublicationRetryResult, error) {
	if ctx == nil || io == nil || store == nil {
		return PublicationRetryResult{}, publicationRetryError(PublicationUnavailable, errors.New("publication retry context, I/O and store are required"))
	}
	marker, recordCID, err := publicationMarker(publication, signer)
	if err != nil {
		return PublicationRetryResult{}, publicationRetryError(PublicationRejected, err)
	}
	policy := options.Policy
	if policy == (RetryPolicy{}) {
		policy = DefaultRetryPolicy()
	}
	if policy.MaxAttempts < 1 || policy.BaseDelay < 0 || policy.MaxDelay < 0 || policy.MaxElapsed <= 0 {
		return retryResult(PublicationRetryResult{Marker: marker, RecordCID: recordCID}, PublicationRejected, errors.New("invalid publication retry policy"))
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	sleep := options.Sleep
	if sleep == nil {
		sleep = retrySleep
	}
	jitter := options.Jitter
	if jitter == nil {
		jitter = func(limit time.Duration) time.Duration {
			if limit <= 0 {
				return 0
			}
			return time.Duration(rand.Int63n(int64(limit) + 1))
		}
	}

	operationCtx, cancel := context.WithTimeout(ctx, policy.MaxElapsed)
	defer cancel()
	startedAt := clock()
	unlock, err := acquirePublicationMarker(operationCtx, marker)
	if err != nil {
		return retryResult(retryBaseResult(marker, recordCID, publication), PublicationQueued, err)
	}
	defer unlock()

	result := retryBaseResult(marker, recordCID, publication)
	var lastErr error
	ambiguousNotLanded := false
	for result.Attempts < policy.MaxAttempts {
		if err := operationCtx.Err(); err != nil {
			if ambiguousNotLanded {
				return retryResult(result, PublicationStarved, errors.Join(ErrPublicationStarved, err))
			}
			return retryResult(result, PublicationQueued, err)
		}
		result.Attempts++
		revision, predecessor, readErr := io.ReadCurrent(operationCtx)
		if readErr != nil {
			lastErr = readErr
			if isPublicationQueuedError(readErr) {
				return retryResult(result, PublicationQueued, readErr)
			}
			if isTransientPublicationReadError(readErr) {
				if result.Attempts >= policy.MaxAttempts {
					return retryResult(result, PublicationUnavailable, readErr)
				}
				if err := retryWait(operationCtx, policy, result.Attempts, startedAt, clock, jitter, sleep); err != nil {
					return retryResult(result, PublicationUnavailable, errors.Join(readErr, err))
				}
				continue
			}
			return retryResult(result, PublicationUnavailable, readErr)
		}
		result.Revision = revision
		result.Predecessor = &predecessor
		current, currentErr := currentPublicationOutcome(revision, marker, recordCID, publication.SnapshotCID)
		result.Evidence = publicationObservationEvidence(result.Evidence, revision, marker, current)
		if errors.Is(currentErr, ErrPublicationIDReuse) {
			return retryResult(result, PublicationRejected, currentErr)
		}
		if currentErr != nil {
			return retryResult(result, PublicationUnavailable, currentErr)
		}
		switch current {
		case publicationCurrentCommitted:
			result.NoOp = true
			return retryResult(result, PublicationCommitted, nil)
		case publicationCurrentSuperseded:
			return retryResult(result, PublicationSuperseded, ErrPublicationSuperseded)
		case publicationCurrentNotLanded:
		default:
			return retryResult(result, PublicationUnavailable, ErrUnprovenMembership)
		}

		attempts, err := store.TransitionAttemptsByMarker(operationCtx, marker.Collection, marker.RKey)
		if err != nil {
			return retryResult(result, PublicationUnavailable, err)
		}
		eligible, stopStatus, stopErr, err := authorizePublicationRetry(operationCtx, store, attempts, revision, recordCID)
		if err != nil {
			return retryResult(result, PublicationUnavailable, err)
		}
		if !eligible {
			return retryResult(result, stopStatus, stopErr)
		}

		commitResult, commitErr := commitPublication(operationCtx, io, store, publication, signer, clock())
		result = mergePublicationCommitResult(result, commitResult)
		if errors.Is(commitErr, ErrPublicationState) {
			return retryResult(result, PublicationQueued, commitErr)
		}
		if commitResult.Outcome == TransitionOutcomeCommitted {
			result.NoOp = false
			return retryResult(result, PublicationCommitted, nil)
		}
		if commitResult.Outcome == TransitionOutcomeSuperseded {
			return retryResult(result, PublicationSuperseded, ErrPublicationSuperseded)
		}
		if errors.Is(commitErr, ErrFenceLost) {
			return retryResult(result, PublicationFenceLost, commitErr)
		}
		if commitErr != nil && isPublicationQueuedError(commitErr) {
			return retryResult(result, PublicationQueued, commitErr)
		}
		if commitErr != nil && isDefinitivePublicationRejection(commitErr) {
			return retryResult(result, PublicationRejected, commitErr)
		}

		observed, observedPredecessor, observeErr := io.ReadCurrent(operationCtx)
		if observeErr != nil {
			lastErr = observeErr
			if isPublicationQueuedError(observeErr) {
				return retryResult(result, PublicationQueued, errors.Join(commitErr, observeErr))
			}
			if isTransientPublicationReadError(observeErr) && result.Attempts < policy.MaxAttempts {
				if err := retryWait(operationCtx, policy, result.Attempts, startedAt, clock, jitter, sleep); err != nil {
					return retryResult(result, PublicationUnavailable, errors.Join(commitErr, observeErr, err))
				}
				continue
			}
			return retryResult(result, PublicationUnavailable, errors.Join(commitErr, observeErr))
		}
		result.Revision = observed
		result.Predecessor = &observedPredecessor
		current, currentErr = currentPublicationOutcome(observed, marker, recordCID, publication.SnapshotCID)
		result.Evidence = publicationObservationEvidence(result.Evidence, observed, marker, current)
		if errors.Is(currentErr, ErrPublicationIDReuse) {
			return retryResult(result, PublicationRejected, currentErr)
		}
		if currentErr != nil {
			return retryResult(result, PublicationUnavailable, errors.Join(commitErr, currentErr))
		}
		switch current {
		case publicationCurrentCommitted:
			result.NoOp = false
			return retryResult(result, PublicationCommitted, nil)
		case publicationCurrentSuperseded:
			return retryResult(result, PublicationSuperseded, ErrPublicationSuperseded)
		case publicationCurrentNotLanded:
		}

		if commitErr != nil && isPublicationQueuedError(commitErr) {
			return retryResult(result, PublicationQueued, commitErr)
		}
		latestAttempts, err := store.TransitionAttemptsByMarker(operationCtx, marker.Collection, marker.RKey)
		if err != nil {
			return retryResult(result, PublicationUnavailable, errors.Join(commitErr, err))
		}
		eligible, stopStatus, stopErr, err = authorizePublicationRetry(operationCtx, store, latestAttempts, observed, recordCID)
		if err != nil {
			return retryResult(result, PublicationUnavailable, errors.Join(commitErr, err))
		}
		if !eligible {
			return retryResult(result, stopStatus, errors.Join(commitErr, stopErr))
		}
		ambiguousNotLanded = true
		lastErr = commitErr
		if result.Attempts >= policy.MaxAttempts {
			return retryResult(result, PublicationStarved, errors.Join(ErrPublicationStarved, commitErr, ErrTransitionNotLanded))
		}
		if err := retryWait(operationCtx, policy, result.Attempts, startedAt, clock, jitter, sleep); err != nil {
			return retryResult(result, PublicationStarved, errors.Join(ErrPublicationStarved, commitErr, err))
		}
	}
	if ambiguousNotLanded {
		return retryResult(result, PublicationStarved, errors.Join(ErrPublicationStarved, lastErr))
	}
	return retryResult(result, PublicationUnavailable, lastErr)
}

func publicationObservationEvidence(existing string, revision *Revision, marker RecordKey, outcome publicationCurrentState) string {
	evidence := evidenceWith(existing, "currentRevision", revisionCommit(revision))
	evidence = evidenceWith(evidence, "currentOutcome", string(outcome))
	evidence = evidenceWith(evidence, "markerRecordCID", revision.membership[marker])
	evidence = evidenceWith(evidence, "currentHeadRecordCID", revision.membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}])
	return evidence
}

func retryBaseResult(marker RecordKey, recordCID string, publication vault.Publication) PublicationRetryResult {
	blobCID := cid.NewCidV1(cid.Raw, mustTransitionMultihash(publication.Snapshot)).String()
	return PublicationRetryResult{Marker: marker, RecordCID: recordCID, BlobCID: blobCID}
}

func mergePublicationCommitResult(result PublicationRetryResult, committed PublicationCommitResult) PublicationRetryResult {
	if committed.AttemptID != "" {
		result.Evidence = committed.Evidence
	}
	if committed.Revision != nil {
		result.Revision = committed.Revision
	}
	if committed.Predecessor != nil {
		result.Predecessor = committed.Predecessor
	}
	if committed.Marker.Collection != "" {
		result.Marker = committed.Marker
	}
	if committed.RecordCID != "" {
		result.RecordCID = committed.RecordCID
	}
	if committed.BlobCID != "" {
		result.BlobCID = committed.BlobCID
	}
	return result
}

func authorizePublicationRetry(ctx context.Context, store TransitionAttemptStore, attempts []state.TransitionAttempt, current *Revision, expectedRecordCID string) (bool, PublicationRetryStatus, error, error) {
	if len(attempts) == 0 {
		return true, "", nil, nil
	}
	missingDisposition := false
	unavailableOutcome := false
	fenceLost := false
	queuedDisposition := false
	rejectedDisposition := false
	committedHistory := false
	for _, attempt := range attempts {
		if attempt.ExpectedRecordCID != "" && attempt.ExpectedRecordCID != expectedRecordCID {
			return false, PublicationRejected, ErrPublicationIDReuse, nil
		}
		if attempt.Outcome == TransitionOutcomeFenceLost {
			fenceLost = true
		}
		if attempt.Outcome == TransitionOutcomeCommitted || attempt.Outcome == TransitionOutcomeSuperseded {
			committedHistory = true
		}
		if attempt.Outcome == TransitionOutcomeUnavailable {
			unavailableOutcome = true
		}
		disposition, valid := parseRetryDisposition(attempt.Evidence)
		if !valid {
			missingDisposition = true
			continue
		}
		switch disposition {
		case retryDispositionFenceLost:
			fenceLost = true
		case retryDispositionQuota, retryDispositionRateLimited:
			queuedDisposition = true
		case retryDispositionRejected, retryDispositionUploadTooLarge, retryDispositionBatchTooLarge:
			rejectedDisposition = true
		case retryDispositionCommitted:
			committedHistory = true
		}
	}
	if rejectedDisposition {
		return false, PublicationRejected, ErrPublicationRejected, nil
	}
	if queuedDisposition {
		return false, PublicationQueued, ErrPublicationQueued, nil
	}
	if fenceLost {
		return false, PublicationFenceLost, ErrPublicationRetryFenceLost, nil
	}
	if committedHistory {
		return false, PublicationUnavailable, ErrPublicationUnavailable, nil
	}
	if missingDisposition {
		if unavailableOutcome {
			return false, PublicationUnavailable, ErrPublicationUnavailable, nil
		}
		return false, PublicationQueued, ErrPublicationQueued, nil
	}
	for _, attempt := range attempts {
		disposition, _ := parseRetryDisposition(attempt.Evidence)
		if disposition != retryDispositionAmbiguous {
			return false, PublicationUnavailable, ErrPublicationUnavailable, nil
		}
		switch attempt.Outcome {
		case TransitionOutcomePrepared, TransitionOutcomeStaged, TransitionOutcomeSubmitted:
			if current == nil {
				return false, PublicationUnavailable, ErrPublicationUnavailable, nil
			}
			updatedEvidence := evidenceWith(attempt.Evidence, "retryObservationRevision", current.CommitCID())
			if err := store.UpdateTransitionAttempt(ctx, attempt.ID, TransitionOutcomeNotLanded, updatedEvidence); err != nil {
				return false, PublicationUnavailable, nil, publicationStateError(err)
			}
		case TransitionOutcomeNotLanded, TransitionOutcomeUnavailable:
		default:
			return false, PublicationUnavailable, ErrPublicationUnavailable, nil
		}
	}
	return true, "", nil, nil
}

func retryWait(ctx context.Context, policy RetryPolicy, completedCycles int, startedAt time.Time, clock func() time.Time, jitter func(time.Duration) time.Duration, sleep func(context.Context, time.Duration) error) error {
	if completedCycles >= policy.MaxAttempts {
		return nil
	}
	delay := policy.BaseDelay
	for cycle := 1; cycle < completedCycles && delay < policy.MaxDelay; cycle++ {
		if delay > policy.MaxDelay/2 {
			delay = policy.MaxDelay
			break
		}
		delay *= 2
	}
	if delay > policy.MaxDelay {
		delay = policy.MaxDelay
	}
	actual := jitter(delay)
	if actual < 0 {
		actual = 0
	}
	if actual > delay {
		actual = delay
	}
	if actual > policy.MaxDelay {
		actual = policy.MaxDelay
	}
	remaining := policy.MaxElapsed - clock().Sub(startedAt)
	if remaining <= 0 || actual >= remaining {
		return context.DeadlineExceeded
	}
	return sleep(ctx, actual)
}

func retrySleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isPublicationQueuedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrPublicationQueued) || errors.Is(err, ErrPublicationQuota) || errors.Is(err, ErrPublicationRateLimited) || errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, ErrAuthMethodSession) || errors.Is(err, ErrAuthMethodNonce) || errors.Is(err, ErrAuthMethodToken) || errors.Is(err, ErrAuthMethodRelocated) || errors.Is(err, ErrAuthMethodTransport) || errors.Is(err, ErrSessionUnavailable) || errors.Is(err, ErrSessionRefreshPending) {
		return true
	}
	var readStatus *ReadStatusError
	if errors.As(err, &readStatus) && (readStatus.StatusCode == 401 || readStatus.StatusCode == 403 || readStatus.StatusCode == 429 || readStatus.Code == "RateLimitExceeded") {
		return true
	}
	var providerStatus *ProviderStatusError
	if errors.As(err, &providerStatus) && (providerStatus.StatusCode == 401 || providerStatus.StatusCode == 403 || providerStatus.StatusCode == 429 || providerStatus.Code == "RateLimitExceeded") {
		return true
	}
	return false
}

func isRateLimitedStatusError(err error) bool {
	var readStatus *ReadStatusError
	if errors.As(err, &readStatus) && (readStatus.StatusCode == 429 || readStatus.Code == "RateLimitExceeded") {
		return true
	}
	var providerStatus *ProviderStatusError
	return errors.As(err, &providerStatus) && (providerStatus.StatusCode == 429 || providerStatus.Code == "RateLimitExceeded")
}

func isTransientPublicationReadError(err error) bool {
	if errors.Is(err, ErrAmbiguousTransport) || errors.Is(err, ErrRevisionMoving) {
		return true
	}
	var status *ReadStatusError
	return errors.As(err, &status) && status.StatusCode >= 500
}

func isDefinitivePublicationRejection(err error) bool {
	return errors.Is(err, ErrBatchRejected) || errors.Is(err, ErrPublicationBatchTooLarge) || errors.Is(err, ErrCandidateExceedsBlobUploadLimit) || errors.Is(err, ErrPreparedPolicyMismatch) || errors.Is(err, vault.ErrAuthorization) || errors.Is(err, vault.ErrSignature) || errors.Is(err, ErrCandidateUnauthenticated) || errors.Is(err, ErrCandidateContextMismatch) || errors.Is(err, ErrPublicationIDReuse)
}

func retryResult(result PublicationRetryResult, status PublicationRetryStatus, err error) (PublicationRetryResult, error) {
	result.Status = status
	if err == nil && status == PublicationCommitted {
		result.LastError = ""
		return result, nil
	}
	if err == nil {
		err = ErrPublicationUnavailable
	}
	result.LastError = sanitizedPublicationError(err)
	return result, publicationRetryError(status, err)
}

func publicationRetryError(status PublicationRetryStatus, err error) error {
	var statusError error
	switch status {
	case PublicationQueued:
		statusError = ErrPublicationQueued
		if errors.Is(err, ErrPublicationRateLimited) || isRateLimitedStatusError(err) {
			statusError = errors.Join(statusError, ErrPublicationRateLimited)
		}
	case PublicationStarved:
		statusError = ErrPublicationStarved
	case PublicationFenceLost:
		statusError = ErrPublicationRetryFenceLost
	case PublicationSuperseded:
		statusError = ErrPublicationSuperseded
	case PublicationUnavailable:
		statusError = ErrPublicationUnavailable
	case PublicationRejected:
		statusError = ErrPublicationRejected
	default:
		statusError = ErrPublicationUnavailable
	}
	return errors.Join(statusError, err)
}

func sanitizedPublicationError(err error) string {
	if errors.Is(err, ErrPublicationIDReuse) {
		return ErrPublicationIDReuse.Error()
	}
	if errors.Is(err, ErrPublicationQuota) {
		return ErrPublicationQuota.Error()
	}
	if errors.Is(err, ErrPublicationRateLimited) {
		return ErrPublicationRateLimited.Error()
	}
	if errors.Is(err, ErrPublicationQueued) {
		return ErrPublicationQueued.Error()
	}
	if errors.Is(err, ErrPublicationStarved) {
		return ErrPublicationStarved.Error()
	}
	if errors.Is(err, ErrPublicationSuperseded) {
		return ErrPublicationSuperseded.Error()
	}
	if errors.Is(err, ErrPublicationUnavailable) {
		return ErrPublicationUnavailable.Error()
	}
	if errors.Is(err, ErrCandidateExceedsBlobUploadLimit) {
		return ErrCandidateExceedsBlobUploadLimit.Error()
	}
	if errors.Is(err, ErrPublicationBatchTooLarge) {
		return ErrPublicationBatchTooLarge.Error()
	}
	if errors.Is(err, ErrFenceLost) {
		return ErrFenceLost.Error()
	}
	if errors.Is(err, ErrBatchRejected) || errors.Is(err, ErrPublicationRejected) {
		return ErrPublicationRejected.Error()
	}
	var readStatus *ReadStatusError
	if errors.As(err, &readStatus) {
		return readStatus.Error()
	}
	var providerStatus *ProviderStatusError
	if errors.As(err, &providerStatus) {
		return providerStatus.Error()
	}
	if errors.Is(err, ErrAmbiguousTransport) {
		return ErrAmbiguousTransport.Error()
	}
	if errors.Is(err, ErrRevisionMoving) || errors.Is(err, ErrUnprovenMembership) {
		return ErrPublicationUnavailable.Error()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "publication retry operation was canceled or timed out"
	}
	return ErrPublicationUnavailable.Error()
}
