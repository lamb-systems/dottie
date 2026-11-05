package atproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const (
	RecordCreate = "create"
	RecordUpdate = "update"
)

type RecordWrite struct {
	Action     string
	Collection string
	RKey       string
	Record     json.RawMessage
}

type FencedPublication struct {
	FirstBlobReference RecordWrite
	VaultHead          RecordWrite
	VaultControl       RecordWrite
	Additional         []RecordWrite
}

type FencedSnapshotPublication struct {
	SnapshotReference RecordWrite
	VaultHead         RecordWrite
}

type PublishResult struct {
	CommitCID string
	Submitted bool
}

type PublicationCommitResult struct {
	Outcome     TransitionOutcome
	AttemptID   string
	Marker      RecordKey
	RecordCID   string
	BlobCID     string
	Revision    *Revision
	Predecessor *vault.Predecessor
	Evidence    string
}

type PreparedPolicyMismatchError struct {
	Prepared [32]byte
	Current  [32]byte
}

func (e *PreparedPolicyMismatchError) Error() string {
	return fmt.Sprintf("%v: prepared=%x current=%x", ErrPreparedPolicyMismatch, e.Prepared, e.Current)
}

func (e *PreparedPolicyMismatchError) Unwrap() error { return ErrPreparedPolicyMismatch }

var ErrPreparedPolicyMismatch = errors.New("prepared candidate policy differs from current policy")

type PublicationFenceLostError struct {
	Result PublicationCommitResult
}

func (e *PublicationFenceLostError) Error() string {
	return fmt.Sprintf("%v: attempt=%s", ErrTransitionDiscarded, e.Result.AttemptID)
}

func (e *PublicationFenceLostError) Unwrap() error { return ErrFenceLost }

func (e *PublicationFenceLostError) Is(target error) bool { return target == ErrTransitionDiscarded }

type applyWritesInput struct {
	Repo       string            `json:"repo"`
	SwapCommit string            `json:"swapCommit"`
	Writes     []json.RawMessage `json:"writes"`
}

type applyWritesOutput struct {
	Commit struct {
		CID string `json:"cid"`
	} `json:"commit"`
}

type applyWritesError struct {
	Error string `json:"error"`
}

func applyWritesStatusError(status int, response []byte) error {
	code := safeProviderCode(response)
	statusErr := &ProviderStatusError{StatusCode: status, Code: code}
	switch {
	case status >= 400 && status < 500 && code == "InvalidSwap":
		return errors.Join(ErrFenceLost, statusErr)
	case status == 429:
		return errors.Join(ErrPublicationRateLimited, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500 && (code == "QuotaExceeded" || code == "StorageQuotaExceeded"):
		return errors.Join(ErrPublicationQuota, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500 && code == "RateLimitExceeded":
		return errors.Join(ErrPublicationRateLimited, ErrCandidateMayBeDisclosed, statusErr)
	case status == 401 || status == 403:
		return errors.Join(ErrPublicationQueued, ErrBatchRejected, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500 && (status == 413 || code == "RequestTooLarge" || code == "PayloadTooLarge"):
		return errors.Join(ErrPublicationBatchTooLarge, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500:
		return errors.Join(ErrBatchRejected, ErrCandidateMayBeDisclosed, statusErr)
	default:
		return errors.Join(ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, statusErr)
	}
}

func uploadBlobStatusError(status int, response []byte) error {
	code := safeProviderCode(response)
	statusErr := &ProviderStatusError{StatusCode: status, Code: code}
	switch {
	case status == 429:
		return errors.Join(ErrPublicationRateLimited, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500 && (code == "QuotaExceeded" || code == "StorageQuotaExceeded"):
		return errors.Join(ErrPublicationQuota, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500 && code == "RateLimitExceeded":
		return errors.Join(ErrPublicationRateLimited, ErrCandidateMayBeDisclosed, statusErr)
	case status == 401 || status == 403:
		return errors.Join(ErrPublicationQueued, ErrBatchRejected, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500 && (status == 413 || code == "BlobTooLarge"):
		return errors.Join(ErrCandidateExceedsBlobUploadLimit, ErrCandidateMayBeDisclosed, statusErr)
	case status >= 400 && status < 500:
		return errors.Join(ErrBatchRejected, ErrCandidateMayBeDisclosed, statusErr)
	default:
		return errors.Join(ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, statusErr)
	}
}

func publishFenced(ctx context.Context, transport Transport, revision *Revision, publication FencedPublication) (PublishResult, error) {
	if transport == nil || revision == nil || !validDID(revision.did) || revision.commitCID == "" {
		return PublishResult{}, fmt.Errorf("%w: verified revision and transport are required", ErrBatchRejected)
	}
	if _, err := syntax.ParseCID(revision.commitCID); err != nil {
		return PublishResult{}, fmt.Errorf("%w: verified revision commit CID is invalid", ErrBatchRejected)
	}
	if publication.FirstBlobReference.Action != RecordCreate || !containsBlobReference(publication.FirstBlobReference.Record) {
		return PublishResult{}, fmt.Errorf("%w: first reference must create a record containing a blob reference", ErrBatchRejected)
	}
	writes := []RecordWrite{publication.FirstBlobReference, publication.VaultHead, publication.VaultControl}
	writes = append(writes, publication.Additional...)
	if len(writes) < 3 {
		return PublishResult{}, fmt.Errorf("%w: first reference, head and control writes are required", ErrBatchRejected)
	}
	input := applyWritesInput{Repo: revision.did, SwapCommit: revision.commitCID, Writes: make([]json.RawMessage, 0, len(writes))}
	seen := make(map[RecordKey]struct{}, len(writes))
	for _, write := range writes {
		encoded, err := encodeRecordWrite(write)
		if err != nil {
			return PublishResult{}, err
		}
		key := RecordKey{Collection: write.Collection, RKey: write.RKey}
		if _, exists := seen[key]; exists {
			return PublishResult{}, fmt.Errorf("%w: duplicate record target %s/%s", ErrBatchRejected, key.Collection, key.RKey)
		}
		seen[key] = struct{}{}
		input.Writes = append(input.Writes, encoded)
	}
	body, err := json.Marshal(input)
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: could not encode applyWrites batch", ErrBatchRejected)
	}
	status, response, err := transport.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, body, "application/json")
	submitted := true
	if err != nil {
		if status >= 400 && status < 500 {
			return PublishResult{Submitted: submitted}, applyWritesStatusError(status, response)
		}
		return PublishResult{Submitted: submitted}, fmt.Errorf("%w: %w: applyWrites request outcome is unknown: %w", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, safeTransportCause(err))
	}
	if status < 200 || status >= 300 {
		return PublishResult{Submitted: submitted}, applyWritesStatusError(status, response)
	}
	var output applyWritesOutput
	if len(response) != 0 {
		if json.Unmarshal(response, &output) != nil {
			return PublishResult{Submitted: submitted}, fmt.Errorf("%w: %w: applyWrites response is malformed after submission", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)
		}
	}
	return PublishResult{CommitCID: output.Commit.CID, Submitted: submitted}, nil
}

type publicationIO interface {
	ReadCurrent(context.Context) (*Revision, vault.Predecessor, error)
	StageCandidate(context.Context, []byte, vault.Policy, [][]byte) (json.RawMessage, string, error)
	applyPublication(context.Context, *Revision, FencedSnapshotPublication) (string, error)
}

type ATProtoPublicationIO struct {
	Reader           RevisionReader
	Transport        Transport
	BlobUploadLimit  int64
	DID              string
	TrustAnchor      [32]byte
	PreviousPolicies [][]byte
	PreviousControls [][]byte
	ObservationStore PublicationObservationStore
	Clock            func() time.Time
}

func (io ATProtoPublicationIO) ReadCurrent(ctx context.Context) (*Revision, vault.Predecessor, error) {
	return (ATProtoTransitionIO{
		Reader: io.Reader, Transport: io.Transport, DID: io.DID, TrustAnchor: io.TrustAnchor,
		PreviousPolicies: io.PreviousPolicies, PreviousControls: io.PreviousControls, ObservationStore: io.ObservationStore, Clock: io.Clock,
	}).ReadCurrent(ctx)
}

func (io ATProtoPublicationIO) StageCandidate(ctx context.Context, data []byte, expectedPolicy vault.Policy, certificates [][]byte) (json.RawMessage, string, error) {
	return (ATProtoTransitionIO{Transport: io.Transport, BlobUploadLimit: io.BlobUploadLimit}).StageCandidate(ctx, data, expectedPolicy, certificates)
}

func (io ATProtoPublicationIO) applyPublication(ctx context.Context, revision *Revision, publication FencedSnapshotPublication) (string, error) {
	result, err := publishSnapshotFenced(ctx, io.Transport, revision, publication)
	return result.CommitCID, err
}

func publishSnapshotFenced(ctx context.Context, transport Transport, revision *Revision, publication FencedSnapshotPublication) (PublishResult, error) {
	if transport == nil || revision == nil || !validDID(revision.did) || revision.commitCID == "" {
		return PublishResult{}, fmt.Errorf("%w: verified revision and transport are required", ErrBatchRejected)
	}
	if _, err := syntax.ParseCID(revision.commitCID); err != nil {
		return PublishResult{}, fmt.Errorf("%w: verified revision commit CID is invalid", ErrBatchRejected)
	}
	if err := validateSnapshotPublication(publication, revision); err != nil {
		return PublishResult{}, err
	}
	writes := []RecordWrite{publication.SnapshotReference, publication.VaultHead}
	input := applyWritesInput{Repo: revision.did, SwapCommit: revision.commitCID, Writes: make([]json.RawMessage, 0, len(writes))}
	seen := make(map[RecordKey]struct{}, len(writes))
	for _, write := range writes {
		encoded, err := encodeRecordWrite(write)
		if err != nil {
			return PublishResult{}, err
		}
		key := RecordKey{Collection: write.Collection, RKey: write.RKey}
		if _, exists := seen[key]; exists {
			return PublishResult{}, fmt.Errorf("%w: duplicate record target %s/%s", ErrBatchRejected, key.Collection, key.RKey)
		}
		seen[key] = struct{}{}
		input.Writes = append(input.Writes, encoded)
	}
	body, err := json.Marshal(input)
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: could not encode applyWrites batch", ErrBatchRejected)
	}
	status, response, err := transport.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, body, "application/json")
	if err != nil {
		if status >= 400 && status < 500 {
			return PublishResult{}, applyWritesStatusError(status, response)
		}
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites request outcome is unknown: %w", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, safeTransportCause(err))
	}
	if status < 200 || status >= 300 {
		return PublishResult{}, applyWritesStatusError(status, response)
	}
	var output applyWritesOutput
	if len(response) != 0 {
		if json.Unmarshal(response, &output) != nil {
			return PublishResult{}, fmt.Errorf("%w: %w: applyWrites response is malformed after submission", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)
		}
	}
	return PublishResult{CommitCID: output.Commit.CID}, nil
}

func validateSnapshotPublication(publication FencedSnapshotPublication, revision *Revision) error {
	snapshotWrite := publication.SnapshotReference
	headWrite := publication.VaultHead
	if snapshotWrite.Action != RecordCreate || snapshotWrite.Collection != VaultSnapshotNSID || !strings.HasPrefix(snapshotWrite.RKey, "publish-") || !containsBlobReference(snapshotWrite.Record) {
		return fmt.Errorf("%w: publication must create a snapshot reference with a blob", ErrBatchRejected)
	}
	if revision.HasRecord(RecordKey{Collection: snapshotWrite.Collection, RKey: snapshotWrite.RKey}) {
		return fmt.Errorf("%w: snapshot marker already exists", ErrBatchRejected)
	}
	expectedHeadAction := RecordCreate
	if revision.HasRecord(RecordKey{Collection: VaultHeadNSID, RKey: "self"}) {
		expectedHeadAction = RecordUpdate
	}
	if headWrite.Action != expectedHeadAction || headWrite.Collection != VaultHeadNSID || headWrite.RKey != "self" {
		return fmt.Errorf("%w: publication must write the head at its current action", ErrBatchRejected)
	}
	snapshotValue, err := decodeRecordJSON(snapshotWrite.Record)
	snapshot, snapshotOK := snapshotValue.(SnapshotRecord)
	if err != nil || !snapshotOK || len(snapshot.Vault) != 32 || len(snapshot.PolicyDigest) != 32 || len(snapshot.PublicationID) != 16 || !snapshot.Blob.Ref.IsDefined() {
		return fmt.Errorf("%w: snapshot record is malformed", ErrBatchRejected)
	}
	headValue, err := decodeRecordJSON(headWrite.Record)
	head, headOK := headValue.(HeadRecord)
	if err != nil || !headOK || len(head.Vault) != 32 || len(head.PolicyDigest) != 32 || head.PublicationCount == 0 {
		return fmt.Errorf("%w: head record is malformed", ErrBatchRejected)
	}
	snapshotCID := cid.Cid(snapshot.Blob.Ref).Bytes()
	if !bytes.Equal(head.Vault, snapshot.Vault) || head.EpochSeq != snapshot.EpochSeq || !bytes.Equal(head.PolicyDigest, snapshot.PolicyDigest) || !bytes.Equal(head.SnapshotCID, snapshotCID) || !bytes.Equal(head.BlobCID, snapshotCID) {
		return fmt.Errorf("%w: snapshot and head references are not contained in the same fence", ErrBatchRejected)
	}
	return nil
}

func publicationPredecessorMatchesRevision(revision *Revision, predecessor vault.Predecessor) error {
	if revision == nil {
		return ErrUntrustedCar
	}
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	controlRecord, exists := revision.records[controlKey]
	if !exists || revision.membership[controlKey] == "" || revision.membership[controlKey] != controlRecord.CID {
		return ErrUnprovenMembership
	}
	decodedControl, err := DecodeRecord(controlRecord.Data)
	if err != nil {
		return err
	}
	control, ok := decodedControl.(ControlRecord)
	if !ok {
		return ErrRecord
	}
	controlBytes, err := vault.EncodeControl(controlFromRecord(control))
	if err != nil {
		return err
	}
	if !bytes.Equal(controlBytes, predecessor.Control) {
		return ErrBatchRejected
	}

	headKey := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
	headRecord, hasHeadRecord := revision.records[headKey]
	headCID, hasHeadMembership := revision.membership[headKey]
	if len(predecessor.HeadCID) == 0 {
		if len(predecessor.Head) != 0 || hasHeadRecord || hasHeadMembership {
			return ErrBatchRejected
		}
		return nil
	}
	if !hasHeadRecord || !hasHeadMembership || headCID == "" || headCID != headRecord.CID {
		return ErrUnprovenMembership
	}
	decodedHead, err := DecodeRecord(headRecord.Data)
	if err != nil {
		return err
	}
	head, ok := decodedHead.(HeadRecord)
	if !ok {
		return ErrRecord
	}
	headBytes, err := vault.EncodeHead(headFromRecord(head))
	if err != nil {
		return err
	}
	if !bytes.Equal(headBytes, predecessor.Head) || !bytes.Equal(head.SnapshotCID, predecessor.HeadCID) {
		return ErrBatchRejected
	}
	return nil
}

func CommitPublication(ctx context.Context, io ATProtoPublicationIO, store TransitionAttemptStore, publication vault.Publication, signer ed25519.PrivateKey, now time.Time) (PublicationCommitResult, error) {
	marker, _, err := publicationMarker(publication, signer)
	if err != nil {
		return PublicationCommitResult{}, err
	}
	release, err := acquirePublicationMarker(ctx, marker)
	if err != nil {
		return PublicationCommitResult{}, err
	}
	defer release()
	return commitPublication(ctx, io, store, publication, signer, now)
}

func commitPublication(ctx context.Context, io publicationIO, store TransitionAttemptStore, publication vault.Publication, signer ed25519.PrivateKey, now time.Time) (PublicationCommitResult, error) {
	if io == nil || store == nil || len(signer) != ed25519.PrivateKeySize || now.IsZero() {
		return PublicationCommitResult{}, fmt.Errorf("%w: publication I/O, store, signer and timestamp are required", ErrBatchRejected)
	}
	initialRevision, initialPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		return PublicationCommitResult{}, fmt.Errorf("read current publication predecessor: %w", err)
	}
	if err := publicationPredecessorMatchesRevision(initialRevision, initialPredecessor); err != nil {
		return PublicationCommitResult{Predecessor: &initialPredecessor}, fmt.Errorf("%w: predecessor does not match verified revision: %w", ErrBatchRejected, err)
	}
	if publication.PolicyDigest != initialPredecessor.PolicyDigest {
		return PublicationCommitResult{Predecessor: &initialPredecessor}, &PreparedPolicyMismatchError{Prepared: publication.PolicyDigest, Current: initialPredecessor.PolicyDigest}
	}
	if err := vault.ValidatePublication(publication, initialPredecessor); err != nil {
		return PublicationCommitResult{}, err
	}
	if len(publication.BlobCID) == 0 || !bytes.Equal(publication.BlobCID, publication.SnapshotCID) || !bytes.Equal(publication.SnapshotCID, rawTransitionCID(publication.Snapshot)) {
		return PublicationCommitResult{}, fmt.Errorf("%w: publication snapshot CID is invalid", ErrBatchRejected)
	}
	preview, err := snapshotPublication(publication, signer, blobJSONFromCID(publication.SnapshotCID, len(publication.Snapshot)), initialRevision, initialPredecessor)
	if err != nil {
		return PublicationCommitResult{}, err
	}
	marker, markerCID, err := publicationMarker(publication, signer)
	if err != nil {
		return PublicationCommitResult{}, err
	}
	if marker.RKey != preview.SnapshotReference.RKey {
		return PublicationCommitResult{}, fmt.Errorf("%w: publication marker identity disagrees with its record", ErrBatchRejected)
	}
	previewCID, err := recordCIDText(preview.SnapshotReference.Record)
	if err != nil || previewCID != markerCID {
		return PublicationCommitResult{}, fmt.Errorf("%w: publication marker CID disagrees with its record", ErrBatchRejected)
	}
	headCID, err := recordCIDText(preview.VaultHead.Record)
	if err != nil {
		return PublicationCommitResult{}, err
	}
	attemptID, err := newTransitionAttemptID()
	if err != nil {
		return PublicationCommitResult{}, err
	}
	blobCID := cid.NewCidV1(cid.Raw, mustTransitionMultihash(publication.Snapshot)).String()
	evidence, err := json.Marshal(publicationAttemptEvidence{Version: 1, Kind: "publication", HeadRecordCID: headCID, PreparedRevision: initialRevision.CommitCID()})
	if err != nil {
		return PublicationCommitResult{}, err
	}
	attempt := state.TransitionAttempt{
		ID: attemptID, MarkerCollection: marker.Collection, MarkerRKey: marker.RKey,
		ExpectedRecordCID: markerCID, CandidateBlobCID: blobCID, EpochSeq: publication.Predecessor.EpochSeq,
		PolicyDigest: hex.EncodeToString(publication.PolicyDigest[:]), Outcome: TransitionOutcomePrepared, Evidence: string(evidence), CreatedAt: now.Unix(),
	}
	if err := store.BeginTransitionAttempt(ctx, attempt); err != nil {
		return PublicationCommitResult{}, err
	}
	persistDisposition := func(evidence, disposition string) (string, error) {
		updated, err := persistRetryDisposition(ctx, store, attempt, evidence, disposition)
		if err == nil {
			attempt.Evidence = updated
		}
		return updated, err
	}
	updateOutcome := func(outcome string, evidence string) error {
		if err := store.UpdateTransitionAttempt(ctx, attemptID, outcome, evidence); err != nil {
			return err
		}
		attempt.Outcome = outcome
		attempt.Evidence = evidence
		return nil
	}
	currentPolicy, err := vault.DecodePolicy(initialPredecessor.Policy)
	if err != nil {
		return PublicationCommitResult{}, fmt.Errorf("%w: current publication policy", ErrBatchRejected)
	}
	blobReference, uploadedCID, err := io.StageCandidate(ctx, publication.Snapshot, currentPolicy, initialPredecessor.Certificates)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "stageError", err.Error())
		updatedEvidence, dispositionErr := persistDisposition(updatedEvidence, publicationDispositionForError(err))
		if dispositionErr == nil {
			dispositionErr = updateOutcome(TransitionOutcomeNotLanded, updatedEvidence)
		}
		return publicationResult(attempt, TransitionOutcomeNotLanded, initialRevision, updatedEvidence), errors.Join(err, publicationStateError(dispositionErr))
	}
	if uploadedCID != blobCID {
		mismatch := fmt.Errorf("%w: uploaded candidate CID differs from the sealed publication", ErrBatchRejected)
		updatedEvidence := evidenceWith(string(evidence), "uploadedCID", uploadedCID)
		updatedEvidence, dispositionErr := persistDisposition(updatedEvidence, retryDispositionRejected)
		if dispositionErr == nil {
			dispositionErr = updateOutcome(TransitionOutcomeNotLanded, updatedEvidence)
		}
		return publicationResult(attempt, TransitionOutcomeNotLanded, initialRevision, updatedEvidence), errors.Join(mismatch, publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	updatedEvidence, dispositionErr := persistDisposition(string(evidence), retryDispositionAmbiguous)
	if dispositionErr != nil {
		return publicationResult(attempt, TransitionOutcomeNotLanded, initialRevision, attempt.Evidence), errors.Join(publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	if err := updateOutcome(TransitionOutcomeStaged, updatedEvidence); err != nil {
		return publicationResult(attempt, TransitionOutcomeNotLanded, initialRevision, updatedEvidence), errors.Join(publicationStateError(err), ErrCandidateMayBeDisclosed)
	}
	evidence = json.RawMessage(updatedEvidence)
	currentRevision, currentPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "revalidationReadError", err.Error())
		updatedEvidence, dispositionErr := persistDisposition(updatedEvidence, retryDispositionAmbiguous)
		if dispositionErr == nil {
			dispositionErr = updateOutcome(TransitionOutcomeNotLanded, updatedEvidence)
		}
		return publicationResult(attempt, TransitionOutcomeNotLanded, nil, updatedEvidence), errors.Join(err, publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	if err := publicationPredecessorMatchesRevision(currentRevision, currentPredecessor); err != nil {
		updatedEvidence := evidenceWith(string(evidence), "revalidationError", err.Error())
		updatedEvidence, dispositionErr := persistDisposition(updatedEvidence, retryDispositionRejected)
		if dispositionErr == nil {
			dispositionErr = updateOutcome(TransitionOutcomeNotLanded, updatedEvidence)
		}
		return publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence), errors.Join(fmt.Errorf("%w: predecessor does not match verified revision: %w", ErrBatchRejected, err), publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	if publication.PolicyDigest != currentPredecessor.PolicyDigest {
		mismatch := &PreparedPolicyMismatchError{Prepared: publication.PolicyDigest, Current: currentPredecessor.PolicyDigest}
		updatedEvidence := evidenceWith(string(evidence), "revalidationError", mismatch.Error())
		updatedEvidence, dispositionErr := persistDisposition(updatedEvidence, retryDispositionRejected)
		if dispositionErr == nil {
			dispositionErr = updateOutcome(TransitionOutcomeNotLanded, updatedEvidence)
		}
		result := publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence)
		result.Predecessor = &currentPredecessor
		return result, errors.Join(mismatch, publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	if err := vault.ValidatePublication(publication, currentPredecessor); err != nil {
		updatedEvidence := evidenceWith(string(evidence), "revalidationError", err.Error())
		updatedEvidence, dispositionErr := persistDisposition(updatedEvidence, retryDispositionRejected)
		if dispositionErr == nil {
			dispositionErr = updateOutcome(TransitionOutcomeNotLanded, updatedEvidence)
		}
		result := publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence)
		result.Predecessor = &currentPredecessor
		return result, errors.Join(err, publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	fencedPublication, err := snapshotPublication(publication, signer, blobReference, currentRevision, currentPredecessor)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "recordError", err.Error())
		updatedEvidence, dispositionErr := persistDisposition(updatedEvidence, retryDispositionRejected)
		if dispositionErr == nil {
			dispositionErr = updateOutcome(TransitionOutcomeNotLanded, updatedEvidence)
		}
		return publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence), errors.Join(err, publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	updatedEvidence, dispositionErr = persistDisposition(string(evidence), retryDispositionAmbiguous)
	if dispositionErr != nil {
		return publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, attempt.Evidence), errors.Join(publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	if err := updateOutcome(TransitionOutcomeSubmitted, updatedEvidence); err != nil {
		return publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence), errors.Join(publicationStateError(err), ErrCandidateMayBeDisclosed)
	}
	evidence = json.RawMessage(updatedEvidence)
	commitCID, applyErr := io.applyPublication(ctx, currentRevision, fencedPublication)
	if errors.Is(applyErr, ErrFenceLost) {
		updatedEvidence, dispositionErr = persistDisposition(string(evidence), retryDispositionFenceLost)
		if dispositionErr != nil {
			return publicationResult(attempt, TransitionOutcomeUnavailable, nil, attempt.Evidence), errors.Join(applyErr, publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
		}
		latest, latestPredecessor, readErr := io.ReadCurrent(ctx)
		updatedEvidence = evidenceWith(updatedEvidence, "fenceLostRevision", revisionCommit(latest))
		if readErr != nil {
			updatedEvidence = evidenceWith(updatedEvidence, "fenceLostReadError", readErr.Error())
		}
		updateErr := updateOutcome(TransitionOutcomeFenceLost, updatedEvidence)
		result := publicationResult(attempt, TransitionOutcomeFenceLost, latest, updatedEvidence)
		if readErr == nil {
			result.Predecessor = &latestPredecessor
		}
		return result, errors.Join(&PublicationFenceLostError{Result: result}, readErr, publicationStateError(updateErr))
	}
	disposition := publicationDispositionForError(applyErr)
	if applyErr == nil && commitCID == "" {
		disposition = retryDispositionAmbiguous
	}
	updatedEvidence, dispositionErr = persistDisposition(string(evidence), disposition)
	if dispositionErr != nil {
		return publicationResult(attempt, TransitionOutcomeUnavailable, nil, attempt.Evidence), errors.Join(applyErr, publicationStateError(dispositionErr), ErrCandidateMayBeDisclosed)
	}
	evidence = json.RawMessage(updatedEvidence)
	resolved, resolveErr := resolveSubmittedPublication(ctx, io, store, attempt, string(evidence))
	if resolveErr != nil {
		return resolved, errors.Join(applyErr, resolveErr, ErrCandidateMayBeDisclosed)
	}
	if resolved.Outcome == TransitionOutcomeCommitted {
		return resolved, nil
	}
	return resolved, errors.Join(applyErr, outcomeError(resolved.Outcome), ErrCandidateMayBeDisclosed)
}

func ResolvePublicationAttempt(ctx context.Context, io ATProtoPublicationIO, store TransitionAttemptStore, attemptID string) (PublicationCommitResult, error) {
	attempt, err := store.TransitionAttempt(ctx, attemptID)
	if err != nil {
		return PublicationCommitResult{}, err
	}
	release, err := acquirePublicationMarker(ctx, RecordKey{Collection: attempt.MarkerCollection, RKey: attempt.MarkerRKey})
	if err != nil {
		return PublicationCommitResult{}, err
	}
	defer release()
	return resolvePublicationAttempt(ctx, io, store, attemptID)
}

func resolvePublicationAttempt(ctx context.Context, io publicationIO, store TransitionAttemptStore, attemptID string) (PublicationCommitResult, error) {
	if io == nil || store == nil {
		return PublicationCommitResult{}, fmt.Errorf("%w: publication I/O and store are required", ErrBatchRejected)
	}
	attempt, err := store.TransitionAttempt(ctx, attemptID)
	if err != nil {
		return PublicationCommitResult{}, err
	}
	switch attempt.Outcome {
	case TransitionOutcomeCommitted:
		return publicationResult(attempt, TransitionOutcomeCommitted, nil, attempt.Evidence), nil
	case TransitionOutcomeFenceLost:
		result := publicationResult(attempt, TransitionOutcomeFenceLost, nil, attempt.Evidence)
		return result, &PublicationFenceLostError{Result: result}
	case TransitionOutcomeSuperseded:
		result := publicationResult(attempt, TransitionOutcomeSuperseded, nil, attempt.Evidence)
		return result, errors.Join(ErrTransitionSuperseded, ErrCandidateMayBeDisclosed)
	case TransitionOutcomeNotLanded:
		result := publicationResult(attempt, TransitionOutcomeNotLanded, nil, attempt.Evidence)
		return result, errors.Join(ErrTransitionNotLanded, ErrCandidateMayBeDisclosed)
	case TransitionOutcomeUnavailable:
		result := publicationResult(attempt, TransitionOutcomeUnavailable, nil, attempt.Evidence)
		return result, errors.Join(ErrTransitionUnavailable, ErrCandidateMayBeDisclosed)
	}
	result, err := resolveSubmittedPublication(ctx, io, store, attempt, attempt.Evidence)
	if err != nil {
		return result, errors.Join(err, ErrCandidateMayBeDisclosed)
	}
	if result.Outcome == TransitionOutcomeCommitted {
		return result, nil
	}
	return result, errors.Join(outcomeError(result.Outcome), ErrCandidateMayBeDisclosed)
}

type publicationAttemptEvidence struct {
	Version          int                       `json:"version"`
	Kind             string                    `json:"kind"`
	HeadRecordCID    string                    `json:"headRecordCid"`
	PreparedRevision string                    `json:"preparedRevision"`
	RetryDisposition *retryDispositionEvidence `json:"retryDisposition,omitempty"`
}

type retryDispositionEvidence struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}

const (
	retryDispositionAmbiguous      = "ambiguous"
	retryDispositionRejected       = "rejected"
	retryDispositionQuota          = "quota"
	retryDispositionRateLimited    = "rate-limited"
	retryDispositionUploadTooLarge = "upload-too-large"
	retryDispositionBatchTooLarge  = "batch-too-large"
	retryDispositionFenceLost      = "fence-lost"
	retryDispositionCommitted      = "committed"
)

func validRetryDisposition(value string) bool {
	switch value {
	case retryDispositionAmbiguous, retryDispositionRejected, retryDispositionQuota, retryDispositionRateLimited, retryDispositionUploadTooLarge, retryDispositionBatchTooLarge, retryDispositionFenceLost, retryDispositionCommitted:
		return true
	default:
		return false
	}
}

func setRetryDisposition(evidence string, value string) (string, error) {
	if !validRetryDisposition(value) {
		return "", fmt.Errorf("invalid publication retry disposition")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(evidence), &fields) != nil || fields == nil {
		return "", fmt.Errorf("publication attempt evidence is malformed")
	}
	disposition, err := json.Marshal(retryDispositionEvidence{Version: 1, Value: value})
	if err != nil {
		return "", err
	}
	fields["retryDisposition"] = disposition
	updated, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return string(updated), nil
}

func parseRetryDisposition(evidence string) (string, bool) {
	var parsed struct {
		RetryDisposition *retryDispositionEvidence `json:"retryDisposition"`
	}
	if json.Unmarshal([]byte(evidence), &parsed) != nil || parsed.RetryDisposition == nil || parsed.RetryDisposition.Version != 1 || !validRetryDisposition(parsed.RetryDisposition.Value) {
		return "", false
	}
	return parsed.RetryDisposition.Value, true
}

func persistRetryDisposition(ctx context.Context, store TransitionAttemptStore, attempt state.TransitionAttempt, evidence, value string) (string, error) {
	updated, err := setRetryDisposition(evidence, value)
	if err != nil {
		return "", err
	}
	if err := store.UpdateTransitionAttempt(ctx, attempt.ID, attempt.Outcome, updated); err != nil {
		return "", err
	}
	return updated, nil
}

func publicationStateError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPublicationState, err)
}

func publicationDispositionForError(err error) string {
	switch {
	case errors.Is(err, ErrFenceLost):
		return retryDispositionFenceLost
	case errors.Is(err, ErrPublicationQuota):
		return retryDispositionQuota
	case errors.Is(err, ErrPublicationRateLimited):
		return retryDispositionRateLimited
	case errors.Is(err, ErrCandidateExceedsBlobUploadLimit):
		return retryDispositionUploadTooLarge
	case errors.Is(err, ErrPublicationBatchTooLarge):
		return retryDispositionBatchTooLarge
	case errors.Is(err, ErrAmbiguousTransport), errors.Is(err, ErrRevisionMoving), errors.Is(err, ErrPublicationQueued):
		return retryDispositionAmbiguous
	case err == nil:
		return retryDispositionAmbiguous
	default:
		return retryDispositionRejected
	}
}

func snapshotPublication(publication vault.Publication, signer ed25519.PrivateKey, blobReference json.RawMessage, revision *Revision, predecessor vault.Predecessor) (FencedSnapshotPublication, error) {
	if revision == nil {
		return FencedSnapshotPublication{}, fmt.Errorf("%w: verified revision is required", ErrBatchRejected)
	}
	envelope, err := vault.DecodeEnvelope(publication.Snapshot)
	if err != nil {
		return FencedSnapshotPublication{}, fmt.Errorf("%w: publication snapshot envelope", ErrBatchRejected)
	}
	if len(signer) != ed25519.PrivateKeySize || !publicationSignerKeyMatches(signer, predecessor, envelope) {
		return FencedSnapshotPublication{}, fmt.Errorf("%w: publication signer key does not match the authorized certificate", ErrBatchRejected)
	}
	candidateCID := rawTransitionCID(publication.Snapshot)
	if !bytes.Equal(publication.BlobCID, candidateCID) || !bytes.Equal(publication.SnapshotCID, candidateCID) {
		return FencedSnapshotPublication{}, fmt.Errorf("%w: snapshot blob CID", ErrBatchRejected)
	}
	if len(blobReference) == 0 {
		blobReference = blobJSONFromCID(candidateCID, len(publication.Snapshot))
	}
	var blob atdata.Blob
	if err := json.Unmarshal(blobReference, &blob); err != nil || !blob.Ref.IsDefined() || !bytes.Equal(blob.Ref.CID().Bytes(), candidateCID) || blob.MimeType != "application/octet-stream" || blob.Size != int64(len(publication.Snapshot)) {
		return FencedSnapshotPublication{}, fmt.Errorf("%w: uploaded blob reference does not match the sealed snapshot", ErrBatchRejected)
	}
	snapshot, err := snapshotRecordForPublication(publication, blob, signer)
	if err != nil {
		return FencedSnapshotPublication{}, err
	}
	snapshotJSON, err := marshalRecord(snapshot)
	if err != nil {
		return FencedSnapshotPublication{}, fmt.Errorf("%w: encode snapshot record", ErrBatchRejected)
	}
	headObject, err := vault.DecodeHead(publication.Head)
	if err != nil || headObject.Signer.DeviceID != envelope.DeviceID || !bytes.Equal(headObject.Signer.KeyID, envelope.KeyID) {
		return FencedSnapshotPublication{}, fmt.Errorf("%w: publication head signer differs from the snapshot", ErrBatchRejected)
	}
	headJSON, err := marshalRecord(toHeadRecord(headObject))
	if err != nil {
		return FencedSnapshotPublication{}, err
	}
	return FencedSnapshotPublication{
		SnapshotReference: RecordWrite{Action: RecordCreate, Collection: VaultSnapshotNSID, RKey: publicationMarkerRKey(envelope.PublicationID), Record: snapshotJSON},
		VaultHead:         RecordWrite{Action: transitionRecordAction(revision, VaultHeadNSID, "self"), Collection: VaultHeadNSID, RKey: "self", Record: headJSON},
	}, nil
}

func publicationSignerKeyMatches(signer ed25519.PrivateKey, predecessor vault.Predecessor, envelope vault.Envelope) bool {
	certificate, found := certificateForVaultSigner(predecessor.Certificates, envelope.DeviceID, envelope.KeyID)
	return found && bytes.Equal(certificate.SigningPublicKey[:], signer.Public().(ed25519.PublicKey))
}

func snapshotRecordForPublication(publication vault.Publication, blob atdata.Blob, signer ed25519.PrivateKey) (SnapshotRecord, error) {
	envelope, err := vault.DecodeEnvelope(publication.Snapshot)
	if err != nil {
		return SnapshotRecord{}, err
	}
	digest := sha256.Sum256(envelope.Signature[:])
	record := SnapshotRecord{
		SchemaVersion: 1, Vault: bytes.Clone(envelope.Vault[:]), PublicationID: bytes.Clone(envelope.PublicationID[:]),
		EpochSeq: envelope.EpochSeq, PolicyDigest: bytes.Clone(envelope.PolicyDigest[:]), Parent: bytes.Clone(envelope.Parent),
		Blob: blob, SignerDeviceID: envelope.DeviceID, SignerKeyID: bytes.Clone(envelope.KeyID),
		EnvelopeSignatureDigest: bytes.Clone(digest[:]), Signature: make([]byte, ed25519.SignatureSize),
	}
	return SignSnapshotRecord(record, signer)
}

func publicationMarkerRKey(publicationID [16]byte) string {
	return "publish-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicationID[:]))
}

func publicationMarker(publication vault.Publication, signer ed25519.PrivateKey) (RecordKey, string, error) {
	if len(signer) != ed25519.PrivateKeySize || len(publication.Snapshot) == 0 {
		return RecordKey{}, "", fmt.Errorf("%w: sealed snapshot and signing key are required", ErrBatchRejected)
	}
	envelope, err := vault.DecodeEnvelope(publication.Snapshot)
	if err != nil {
		return RecordKey{}, "", fmt.Errorf("%w: publication snapshot envelope", ErrBatchRejected)
	}
	candidateCID := rawTransitionCID(publication.Snapshot)
	if len(candidateCID) == 0 || !bytes.Equal(publication.SnapshotCID, candidateCID) || !bytes.Equal(publication.BlobCID, candidateCID) {
		return RecordKey{}, "", fmt.Errorf("%w: publication snapshot CID is invalid", ErrBatchRejected)
	}
	blobJSON := blobJSONFromCID(candidateCID, len(publication.Snapshot))
	if len(blobJSON) == 0 {
		return RecordKey{}, "", fmt.Errorf("%w: publication blob reference is invalid", ErrBatchRejected)
	}
	var blob atdata.Blob
	if err := json.Unmarshal(blobJSON, &blob); err != nil || !blob.Ref.IsDefined() {
		return RecordKey{}, "", fmt.Errorf("%w: publication blob reference is invalid", ErrBatchRejected)
	}
	record, err := snapshotRecordForPublication(publication, blob, signer)
	if err != nil {
		return RecordKey{}, "", err
	}
	recordJSON, err := marshalRecord(record)
	if err != nil {
		return RecordKey{}, "", fmt.Errorf("%w: encode snapshot marker", ErrBatchRejected)
	}
	recordCID, err := recordCIDText(recordJSON)
	if err != nil {
		return RecordKey{}, "", err
	}
	return RecordKey{Collection: VaultSnapshotNSID, RKey: publicationMarkerRKey(envelope.PublicationID)}, recordCID, nil
}

type publicationCurrentState string

const (
	publicationCurrentNotLanded  publicationCurrentState = "not-landed"
	publicationCurrentCommitted  publicationCurrentState = "committed"
	publicationCurrentSuperseded publicationCurrentState = "committed-but-superseded"
)

func currentPublicationOutcome(revision *Revision, marker RecordKey, expectedRecordCID string, snapshotCID []byte) (publicationCurrentState, error) {
	if revision == nil || marker.Collection == "" || marker.RKey == "" || expectedRecordCID == "" || len(snapshotCID) == 0 {
		return "", ErrUnprovenMembership
	}
	membership := revision.membership
	markerCID, present := membership[marker]
	if !present {
		return publicationCurrentNotLanded, nil
	}
	if markerCID != expectedRecordCID {
		return "", ErrPublicationIDReuse
	}
	headKey := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
	headCID, headPresent := membership[headKey]
	headRecord, recordPresent := revision.records[headKey]
	if !headPresent || !recordPresent || headCID == "" || headRecord.CID != headCID {
		return "", ErrUnprovenMembership
	}
	decoded, err := DecodeRecord(headRecord.Data)
	if err != nil {
		return "", fmt.Errorf("%w: current head record cannot be decoded", ErrUnprovenMembership)
	}
	head, ok := decoded.(HeadRecord)
	if !ok {
		return "", ErrUnprovenMembership
	}
	if bytes.Equal(head.SnapshotCID, snapshotCID) && bytes.Equal(head.BlobCID, snapshotCID) {
		return publicationCurrentCommitted, nil
	}
	return publicationCurrentSuperseded, nil
}

func publicationResult(attempt state.TransitionAttempt, outcome TransitionOutcome, revision *Revision, evidence string) PublicationCommitResult {
	return PublicationCommitResult{
		Outcome: outcome, AttemptID: attempt.ID,
		Marker:    RecordKey{Collection: attempt.MarkerCollection, RKey: attempt.MarkerRKey},
		RecordCID: attempt.ExpectedRecordCID, BlobCID: attempt.CandidateBlobCID, Revision: revision, Evidence: evidence,
	}
}

func resolveSubmittedPublication(ctx context.Context, io publicationIO, store TransitionAttemptStore, attempt state.TransitionAttempt, evidence string) (PublicationCommitResult, error) {
	latest, latestPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		updatedEvidence := evidenceWith(evidence, "resolutionError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attempt.ID, TransitionOutcomeUnavailable, updatedEvidence)
		return publicationResult(attempt, TransitionOutcomeUnavailable, nil, updatedEvidence), errors.Join(fmt.Errorf("%w: %w", ErrTransitionUnavailable, err), publicationStateError(updateErr))
	}
	var expected publicationAttemptEvidence
	if err := json.Unmarshal([]byte(evidence), &expected); err != nil || expected.Version != 1 || expected.Kind != "publication" || expected.HeadRecordCID == "" {
		updatedEvidence := evidenceWith(evidence, "resolutionEvidenceError", "missing expected head record CID")
		updateErr := store.UpdateTransitionAttempt(ctx, attempt.ID, TransitionOutcomeUnavailable, updatedEvidence)
		result := publicationResult(attempt, TransitionOutcomeUnavailable, latest, updatedEvidence)
		result.Predecessor = &latestPredecessor
		return result, errors.Join(ErrTransitionUnavailable, publicationStateError(updateErr))
	}
	membership := latest.Membership()
	marker := RecordKey{Collection: attempt.MarkerCollection, RKey: attempt.MarkerRKey}
	outcome := TransitionOutcome(TransitionOutcomeNotLanded)
	if membership[marker] == attempt.ExpectedRecordCID {
		if membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}] == expected.HeadRecordCID {
			outcome = TransitionOutcomeCommitted
		} else {
			outcome = TransitionOutcomeSuperseded
		}
	}
	updatedEvidence := evidenceWith(evidence, "resolutionCommit", latest.CommitCID())
	updatedEvidence = evidenceWith(updatedEvidence, "resolutionOutcome", string(outcome))
	updatedEvidence = evidenceWith(updatedEvidence, "markerRecordCID", membership[marker])
	updatedEvidence = evidenceWith(updatedEvidence, "currentHeadRecordCID", membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}])
	result := publicationResult(attempt, outcome, latest, updatedEvidence)
	result.Predecessor = &latestPredecessor
	if err := store.UpdateTransitionAttempt(ctx, attempt.ID, string(outcome), updatedEvidence); err != nil {
		return result, publicationStateError(err)
	}
	return result, nil
}

func encodeRecordWrite(write RecordWrite) (json.RawMessage, error) {
	if write.Action != RecordCreate && write.Action != RecordUpdate {
		return nil, fmt.Errorf("%w: record action must be create or update", ErrBatchRejected)
	}
	collection, err := syntax.ParseNSID(write.Collection)
	if err != nil || collection.String() != write.Collection {
		return nil, fmt.Errorf("%w: invalid record collection", ErrBatchRejected)
	}
	rkey, err := syntax.ParseRecordKey(write.RKey)
	if err != nil || rkey.String() != write.RKey {
		return nil, fmt.Errorf("%w: invalid record key", ErrBatchRejected)
	}
	if len(write.Record) == 0 || !json.Valid(write.Record) {
		return nil, fmt.Errorf("%w: record value must be valid JSON", ErrBatchRejected)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(write.Record, &value); err != nil || value == nil {
		return nil, fmt.Errorf("%w: record value must be an object", ErrBatchRejected)
	}
	var recordType string
	if raw, ok := value["$type"]; !ok || json.Unmarshal(raw, &recordType) != nil || strings.TrimSpace(recordType) == "" {
		return nil, fmt.Errorf("%w: record value requires a non-empty $type", ErrBatchRejected)
	}
	var typeName string
	if write.Action == RecordCreate {
		typeName = "com.atproto.repo.applyWrites#create"
	} else {
		typeName = "com.atproto.repo.applyWrites#update"
	}
	return json.Marshal(struct {
		Type       string          `json:"$type"`
		Collection string          `json:"collection"`
		RKey       string          `json:"rkey"`
		Value      json.RawMessage `json:"value"`
	}{Type: typeName, Collection: write.Collection, RKey: write.RKey, Value: write.Record})
}

func containsBlobReference(record json.RawMessage) bool {
	var value map[string]json.RawMessage
	if json.Unmarshal(record, &value) != nil {
		return false
	}
	var blob map[string]json.RawMessage
	if json.Unmarshal(value["blob"], &blob) != nil {
		return false
	}
	var blobType string
	if json.Unmarshal(blob["$type"], &blobType) != nil || blobType != "blob" {
		return false
	}
	var reference map[string]json.RawMessage
	if json.Unmarshal(blob["ref"], &reference) != nil {
		return false
	}
	var link string
	if json.Unmarshal(reference["$link"], &link) != nil || link == "" {
		return false
	}
	parsed, err := cid.Parse(link)
	return err == nil && parsed.String() == link
}

func ParseInvalidSwapError(body []byte) bool {
	var response applyWritesError
	return json.Unmarshal(body, &response) == nil && response.Error == "InvalidSwap"
}
