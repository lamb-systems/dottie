package atproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
)

var (
	ErrTransitionDiscarded   = errors.New("prepared transition was discarded after a lost fence")
	ErrTransitionNotLanded   = errors.New("transition marker is absent from the verified revision")
	ErrTransitionSuperseded  = errors.New("transition committed but has been superseded")
	ErrTransitionUnavailable = errors.New("transition outcome could not be verified")
)

const (
	TransitionOutcomePrepared    = "prepared"
	TransitionOutcomeStaged      = "staged"
	TransitionOutcomeSubmitted   = "submitted"
	TransitionOutcomeCommitted   = "committed"
	TransitionOutcomeSuperseded  = "committed-but-superseded"
	TransitionOutcomeNotLanded   = "not-landed"
	TransitionOutcomeUnavailable = "unavailable"
	TransitionOutcomeFenceLost   = "fence-lost"
)

type TransitionOutcome string

type TransitionCommitResult struct {
	Outcome     TransitionOutcome
	AttemptID   string
	Marker      RecordKey
	RecordCID   string
	BlobCID     string
	Revision    *Revision
	Predecessor *vault.Predecessor
	Evidence    string
}

type TransitionFenceLostError struct {
	Result TransitionCommitResult
}

func (e *TransitionFenceLostError) Error() string {
	return fmt.Sprintf("%v: attempt=%s", ErrTransitionDiscarded, e.Result.AttemptID)
}

func (e *TransitionFenceLostError) Unwrap() error {
	return ErrFenceLost
}

func (e *TransitionFenceLostError) Is(target error) bool {
	return target == ErrTransitionDiscarded
}

type TransitionIO interface {
	ReadCurrent(context.Context) (*Revision, vault.Predecessor, error)
	StageCandidate(context.Context, []byte) (json.RawMessage, string, error)
	ApplyTransition(context.Context, *Revision, FencedPublication) error
}

type TransitionAttemptStore interface {
	BeginTransitionAttempt(context.Context, state.TransitionAttempt) error
	UpdateTransitionAttempt(context.Context, string, string, string) error
	TransitionAttempt(context.Context, string) (state.TransitionAttempt, error)
	TransitionAttempts(context.Context) ([]state.TransitionAttempt, error)
}

type ATProtoTransitionIO struct {
	Reader           RevisionReader
	Transport        Transport
	DID              string
	TrustAnchor      [32]byte
	PreviousPolicies [][]byte
	ObservationStore PublicationObservationStore
}

func (io ATProtoTransitionIO) ReadCurrent(ctx context.Context) (*Revision, vault.Predecessor, error) {
	if io.Transport == nil || io.Reader.Transport == nil || io.DID == "" {
		return nil, vault.Predecessor{}, fmt.Errorf("%w: transition reader is not configured", ErrBatchRejected)
	}
	revision, err := io.Reader.Read(ctx, io.DID)
	if err != nil {
		return nil, vault.Predecessor{}, err
	}
	predecessor, err := predecessorFromRevision(revision, io.TrustAnchor, io.PreviousPolicies)
	if err != nil {
		return nil, vault.Predecessor{}, err
	}
	if len(predecessor.HeadCID) != 0 {
		proven, exists := revision.records[RecordKey{Collection: VaultHeadNSID, RKey: "self"}]
		if !exists {
			return nil, vault.Predecessor{}, ErrUnprovenMembership
		}
		record, err := DecodeRecord(proven.Data)
		if err != nil {
			return nil, vault.Predecessor{}, err
		}
		headRecord, ok := record.(HeadRecord)
		if !ok {
			return nil, vault.Predecessor{}, ErrRecord
		}
		predecessor.Head, err = vault.EncodeHead(headFromRecord(headRecord))
		if err != nil {
			return nil, vault.Predecessor{}, err
		}
		head := headFromRecord(headRecord)
		control, decodeErr := vault.DecodeControl(predecessor.Control)
		if decodeErr != nil {
			return nil, vault.Predecessor{}, decodeErr
		}
		if err := CheckPublicationCount(ctx, io.ObservationStore, head.Vault, ReadResult{
			Control: toControlRecord(control), Head: headRecord, PublicationCount: head.PublicationCount,
			PublicationCountBaseline: 0, HeadCID: bytes.Clone(head.SnapshotCID), EpochSeq: head.EpochSeq,
		}, PublicationCountOptions{PrevHeadCID: head.PrevHeadCID, EnforceParent: false}); err != nil {
			return nil, vault.Predecessor{}, err
		}
	}
	return revision, predecessor, nil
}

func (io ATProtoTransitionIO) StageCandidate(ctx context.Context, data []byte) (json.RawMessage, string, error) {
	status, body, err := io.Transport.Do(ctx, "POST", "com.atproto.repo.uploadBlob", nil, data, "application/octet-stream")
	if err != nil {
		return nil, "", fmt.Errorf("%w: candidate blob upload outcome is unknown", ErrAmbiguousTransport)
	}
	if status < 200 || status >= 300 {
		return nil, "", fmt.Errorf("candidate blob upload returned HTTP %d", status)
	}
	var response struct {
		Blob json.RawMessage `json:"blob"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Blob) == 0 {
		return nil, "", fmt.Errorf("%w: candidate blob upload response is malformed", ErrAmbiguousTransport)
	}
	var blob atdata.Blob
	if err := json.Unmarshal(response.Blob, &blob); err != nil || !blob.Ref.IsDefined() {
		return nil, "", fmt.Errorf("%w: candidate blob reference is malformed", ErrAmbiguousTransport)
	}
	return bytes.Clone(response.Blob), blob.Ref.CID().String(), nil
}

func (io ATProtoTransitionIO) ApplyTransition(ctx context.Context, revision *Revision, publication FencedPublication) error {
	_, err := PublishFenced(ctx, io.Transport, revision, publication)
	return err
}

func CommitTransition(ctx context.Context, io TransitionIO, store TransitionAttemptStore, transition vault.Transition, signer ed25519.PrivateKey, now time.Time) (TransitionCommitResult, error) {
	if io == nil || store == nil || len(signer) != ed25519.PrivateKeySize || now.IsZero() {
		return TransitionCommitResult{}, fmt.Errorf("%w: transition I/O, store, signer and timestamp are required", ErrBatchRejected)
	}
	if transition.Kind != vault.TransitionEnroll && transition.Kind != vault.TransitionRevoke {
		return TransitionCommitResult{}, fmt.Errorf("%w: kind", vault.ErrUnsupportedTransition)
	}
	initialRevision, initialPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		return TransitionCommitResult{}, fmt.Errorf("read current transition predecessor: %w", err)
	}
	if transition.Predecessor.PolicyDigest != initialPredecessor.PolicyDigest {
		return TransitionCommitResult{}, &PreparedPolicyMismatchError{Prepared: transition.Predecessor.PolicyDigest, Current: initialPredecessor.PolicyDigest}
	}
	if err := vault.ValidateTransition(transition, initialPredecessor); err != nil {
		return TransitionCommitResult{}, err
	}
	if len(transition.BlobCID) == 0 || !bytes.Equal(transition.BlobCID, transition.SnapshotCID) || !bytes.Equal(transition.SnapshotCID, rawTransitionCID(transition.Snapshot)) {
		return TransitionCommitResult{}, fmt.Errorf("%w: transition snapshot CID is invalid", ErrBatchRejected)
	}
	preview, err := transitionPublication(transition, signer, blobJSONFromCID(transition.SnapshotCID, len(transition.Snapshot)), initialRevision)
	if err != nil {
		return TransitionCommitResult{}, err
	}
	marker := RecordKey{Collection: VaultSnapshotNSID, RKey: preview.FirstBlobReference.RKey}
	markerCID, err := recordCIDText(preview.FirstBlobReference.Record)
	if err != nil {
		return TransitionCommitResult{}, err
	}
	headCID, err := recordCIDText(preview.VaultHead.Record)
	if err != nil {
		return TransitionCommitResult{}, err
	}
	controlCID, err := recordCIDText(preview.VaultControl.Record)
	if err != nil {
		return TransitionCommitResult{}, err
	}
	attemptID, err := newTransitionAttemptID()
	if err != nil {
		return TransitionCommitResult{}, err
	}
	blobCID := cid.NewCidV1(cid.Raw, mustTransitionMultihash(transition.Snapshot)).String()
	evidence, err := json.Marshal(transitionAttemptEvidence{Version: 1, HeadRecordCID: headCID, ControlRecordCID: controlCID, PreparedRevision: initialRevision.CommitCID()})
	if err != nil {
		return TransitionCommitResult{}, err
	}
	attempt := state.TransitionAttempt{
		ID: attemptID, MarkerCollection: marker.Collection, MarkerRKey: marker.RKey,
		ExpectedRecordCID: markerCID, CandidateBlobCID: blobCID,
		EpochSeq: transitionEpoch(transition), PolicyDigest: hex.EncodeToString(transitionPolicyDigest(transition)),
		Outcome: TransitionOutcomePrepared, Evidence: string(evidence), CreatedAt: now.Unix(),
	}
	if err := store.BeginTransitionAttempt(ctx, attempt); err != nil {
		return TransitionCommitResult{}, err
	}
	blobReference, uploadedCID, err := io.StageCandidate(ctx, transition.Snapshot)
	if err != nil {
		return transitionResult(attempt, TransitionOutcomeNotLanded, initialRevision, evidenceWith(string(evidence), "stageError", err.Error())), errors.Join(err, store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, evidenceWith(string(evidence), "stageError", err.Error())), ErrCandidateMayBeDisclosed)
	}
	if uploadedCID != blobCID {
		mismatch := fmt.Errorf("%w: uploaded candidate CID differs from the sealed transition", ErrBatchRejected)
		updatedEvidence := evidenceWith(string(evidence), "uploadedCID", uploadedCID)
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return transitionResult(attempt, TransitionOutcomeNotLanded, initialRevision, updatedEvidence), errors.Join(mismatch, updateErr, ErrCandidateMayBeDisclosed)
	}
	if err := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeStaged, string(evidence)); err != nil {
		return transitionResult(attempt, TransitionOutcomeNotLanded, initialRevision, string(evidence)), errors.Join(err, ErrCandidateMayBeDisclosed)
	}
	currentRevision, currentPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "revalidationReadError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return transitionResult(attempt, TransitionOutcomeNotLanded, nil, updatedEvidence), errors.Join(err, updateErr, ErrCandidateMayBeDisclosed)
	}
	if transition.Predecessor.PolicyDigest != currentPredecessor.PolicyDigest {
		mismatch := &PreparedPolicyMismatchError{Prepared: transition.Predecessor.PolicyDigest, Current: currentPredecessor.PolicyDigest}
		updatedEvidence := evidenceWith(string(evidence), "revalidationError", mismatch.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return transitionResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence), errors.Join(mismatch, updateErr, ErrCandidateMayBeDisclosed)
	}
	if err := vault.ValidateTransition(transition, currentPredecessor); err != nil {
		updatedEvidence := evidenceWith(string(evidence), "revalidationError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return transitionResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence), errors.Join(err, updateErr, ErrCandidateMayBeDisclosed)
	}
	publication, err := transitionPublication(transition, signer, blobReference, currentRevision)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "recordError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return transitionResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence), errors.Join(err, updateErr, ErrCandidateMayBeDisclosed)
	}
	if err := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeSubmitted, string(evidence)); err != nil {
		return transitionResult(attempt, TransitionOutcomeNotLanded, currentRevision, string(evidence)), errors.Join(err, ErrCandidateMayBeDisclosed)
	}
	applyErr := io.ApplyTransition(ctx, currentRevision, publication)
	if errors.Is(applyErr, ErrFenceLost) {
		latest, latestPredecessor, readErr := io.ReadCurrent(ctx)
		updatedEvidence := evidenceWith(string(evidence), "fenceLostRevision", revisionCommit(latest))
		if readErr != nil {
			updatedEvidence = evidenceWith(updatedEvidence, "fenceLostReadError", readErr.Error())
		}
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeFenceLost, updatedEvidence)
		result := transitionResult(attempt, TransitionOutcomeFenceLost, latest, updatedEvidence)
		if readErr == nil {
			result.Predecessor = &latestPredecessor
		}
		return result, errors.Join(&TransitionFenceLostError{Result: result}, updateErr)
	}
	resolved, resolveErr := resolveSubmittedTransition(ctx, io, store, attempt, string(evidence))
	if resolveErr != nil {
		return resolved, errors.Join(applyErr, resolveErr, ErrCandidateMayBeDisclosed)
	}
	if resolved.Outcome == TransitionOutcomeCommitted {
		return resolved, nil
	}
	return resolved, errors.Join(applyErr, outcomeError(resolved.Outcome), ErrCandidateMayBeDisclosed)
}

func ResolveTransitionAttempt(ctx context.Context, io TransitionIO, store TransitionAttemptStore, attemptID string) (TransitionCommitResult, error) {
	if io == nil || store == nil {
		return TransitionCommitResult{}, fmt.Errorf("%w: transition I/O and store are required", ErrBatchRejected)
	}
	attempt, err := store.TransitionAttempt(ctx, attemptID)
	if err != nil {
		return TransitionCommitResult{}, err
	}
	switch attempt.Outcome {
	case TransitionOutcomeCommitted:
		return transitionResult(attempt, TransitionOutcomeCommitted, nil, attempt.Evidence), nil
	case TransitionOutcomeFenceLost:
		result := transitionResult(attempt, TransitionOutcomeFenceLost, nil, attempt.Evidence)
		return result, &TransitionFenceLostError{Result: result}
	case TransitionOutcomeSuperseded:
		result := transitionResult(attempt, TransitionOutcomeSuperseded, nil, attempt.Evidence)
		return result, errors.Join(ErrTransitionSuperseded, ErrCandidateMayBeDisclosed)
	case TransitionOutcomeNotLanded:
		result := transitionResult(attempt, TransitionOutcomeNotLanded, nil, attempt.Evidence)
		return result, errors.Join(ErrTransitionNotLanded, ErrCandidateMayBeDisclosed)
	case TransitionOutcomeUnavailable:
		result := transitionResult(attempt, TransitionOutcomeUnavailable, nil, attempt.Evidence)
		return result, errors.Join(ErrTransitionUnavailable, ErrCandidateMayBeDisclosed)
	}
	result, err := resolveSubmittedTransition(ctx, io, store, attempt, attempt.Evidence)
	if err != nil {
		return result, errors.Join(err, ErrCandidateMayBeDisclosed)
	}
	if result.Outcome == TransitionOutcomeCommitted {
		return result, nil
	}
	return result, errors.Join(outcomeError(result.Outcome), ErrCandidateMayBeDisclosed)
}

type transitionAttemptEvidence struct {
	Version          int    `json:"version"`
	HeadRecordCID    string `json:"headRecordCid"`
	ControlRecordCID string `json:"controlRecordCid"`
	PreparedRevision string `json:"preparedRevision"`
}

func resolveSubmittedTransition(ctx context.Context, io TransitionIO, store TransitionAttemptStore, attempt state.TransitionAttempt, evidence string) (TransitionCommitResult, error) {
	latest, _, err := io.ReadCurrent(ctx)
	if err != nil {
		updatedEvidence := evidenceWith(evidence, "resolutionError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attempt.ID, TransitionOutcomeUnavailable, updatedEvidence)
		return transitionResult(attempt, TransitionOutcomeUnavailable, nil, updatedEvidence), errors.Join(fmt.Errorf("%w: %v", ErrTransitionUnavailable, err), updateErr)
	}
	var expected transitionAttemptEvidence
	if err := json.Unmarshal([]byte(evidence), &expected); err != nil || expected.Version != 1 || expected.HeadRecordCID == "" || expected.ControlRecordCID == "" {
		updatedEvidence := evidenceWith(evidence, "resolutionEvidenceError", "missing expected head/control record CIDs")
		updateErr := store.UpdateTransitionAttempt(ctx, attempt.ID, TransitionOutcomeUnavailable, updatedEvidence)
		return transitionResult(attempt, TransitionOutcomeUnavailable, latest, updatedEvidence), errors.Join(ErrTransitionUnavailable, updateErr)
	}
	membership := latest.Membership()
	marker := RecordKey{Collection: attempt.MarkerCollection, RKey: attempt.MarkerRKey}
	outcome := TransitionOutcome(TransitionOutcomeNotLanded)
	if membership[marker] == attempt.ExpectedRecordCID {
		if membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}] == expected.HeadRecordCID && membership[RecordKey{Collection: VaultControlNSID, RKey: "self"}] == expected.ControlRecordCID {
			outcome = TransitionOutcomeCommitted
		} else {
			outcome = TransitionOutcomeSuperseded
		}
	}
	updatedEvidence := evidenceWith(evidence, "resolutionCommit", latest.CommitCID())
	updatedEvidence = evidenceWith(updatedEvidence, "resolutionOutcome", string(outcome))
	updatedEvidence = evidenceWith(updatedEvidence, "markerRecordCID", membership[marker])
	updatedEvidence = evidenceWith(updatedEvidence, "currentHeadRecordCID", membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}])
	updatedEvidence = evidenceWith(updatedEvidence, "currentControlRecordCID", membership[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	if err := store.UpdateTransitionAttempt(ctx, attempt.ID, string(outcome), updatedEvidence); err != nil {
		return transitionResult(attempt, outcome, latest, updatedEvidence), err
	}
	return transitionResult(attempt, outcome, latest, updatedEvidence), nil
}

func outcomeError(outcome TransitionOutcome) error {
	switch outcome {
	case TransitionOutcomeSuperseded:
		return ErrTransitionSuperseded
	case TransitionOutcomeNotLanded:
		return ErrTransitionNotLanded
	case TransitionOutcomeUnavailable:
		return ErrTransitionUnavailable
	default:
		return nil
	}
}

func transitionResult(attempt state.TransitionAttempt, outcome TransitionOutcome, revision *Revision, evidence string) TransitionCommitResult {
	return TransitionCommitResult{
		Outcome: outcome, AttemptID: attempt.ID,
		Marker:    RecordKey{Collection: attempt.MarkerCollection, RKey: attempt.MarkerRKey},
		RecordCID: attempt.ExpectedRecordCID, BlobCID: attempt.CandidateBlobCID,
		Revision: revision, Evidence: evidence,
	}
}

func transitionPublication(transition vault.Transition, signer ed25519.PrivateKey, blobReference json.RawMessage, revision *Revision) (FencedPublication, error) {
	if revision == nil {
		return FencedPublication{}, fmt.Errorf("%w: verified revision is required", ErrBatchRejected)
	}
	envelope, err := vault.DecodeEnvelope(transition.Snapshot)
	if err != nil {
		return FencedPublication{}, fmt.Errorf("%w: snapshot envelope", ErrBatchRejected)
	}
	if len(signer) != ed25519.PrivateKeySize || !transitionSignerKeyMatches(transition, signer, envelope) {
		return FencedPublication{}, fmt.Errorf("%w: transition signer key does not match the signed snapshot", ErrBatchRejected)
	}
	candidateCID := rawTransitionCID(transition.Snapshot)
	if !bytes.Equal(transition.BlobCID, candidateCID) || !bytes.Equal(transition.SnapshotCID, candidateCID) {
		return FencedPublication{}, fmt.Errorf("%w: snapshot blob CID", ErrBatchRejected)
	}
	if len(blobReference) == 0 {
		blobReference = blobJSONFromCID(candidateCID, len(transition.Snapshot))
	}
	var blob atdata.Blob
	if err := json.Unmarshal(blobReference, &blob); err != nil || !blob.Ref.IsDefined() || !bytes.Equal(blob.Ref.CID().Bytes(), candidateCID) || blob.MimeType != "application/octet-stream" || blob.Size != int64(len(transition.Snapshot)) {
		return FencedPublication{}, fmt.Errorf("%w: uploaded blob reference does not match the sealed snapshot", ErrBatchRejected)
	}
	snapshotRecord, err := snapshotRecordForTransition(transition, blob, signer)
	if err != nil {
		return FencedPublication{}, err
	}
	snapshotJSON, err := marshalRecord(snapshotRecord)
	if err != nil {
		return FencedPublication{}, fmt.Errorf("%w: encode snapshot record", ErrBatchRejected)
	}
	policy, err := vault.DecodePolicy(transition.Policy)
	if err != nil {
		return FencedPublication{}, fmt.Errorf("%w: successor policy", ErrBatchRejected)
	}
	control, err := vault.DecodeControl(transition.Control)
	if err != nil {
		return FencedPublication{}, fmt.Errorf("%w: successor control", ErrBatchRejected)
	}
	head, err := vault.DecodeHead(transition.Head)
	if err != nil {
		return FencedPublication{}, fmt.Errorf("%w: successor head", ErrBatchRejected)
	}
	var certificateObject vault.Certificate
	if transition.Kind != vault.TransitionRevoke {
		certificateObject, err = vault.DecodeCertificate(transition.Certificate)
		if err != nil {
			return FencedPublication{}, fmt.Errorf("%w: successor certificate", ErrBatchRejected)
		}
	}
	policyJSON, err := marshalRecord(toPolicyRecord(policy))
	if err != nil {
		return FencedPublication{}, err
	}
	controlJSON, err := marshalRecord(toControlRecord(control))
	if err != nil {
		return FencedPublication{}, err
	}
	headJSON, err := marshalRecord(toHeadRecord(head))
	if err != nil {
		return FencedPublication{}, err
	}
	var certificateJSON json.RawMessage
	certificateRKey := ""
	if transition.Kind != vault.TransitionRevoke {
		certificateJSON, err = marshalRecord(toCertificateRecord(certificateObject))
		if err != nil {
			return FencedPublication{}, err
		}
		certificateRKey = transitionCertificateRKey(certificateObject)
		if revision.HasRecord(RecordKey{Collection: VaultCertificateNSID, RKey: certificateRKey}) {
			return FencedPublication{}, fmt.Errorf("%w: certificate record target already exists", ErrBatchRejected)
		}
	}
	policyAction := transitionRecordAction(revision, VaultPolicyNSID, "self")
	controlAction := transitionRecordAction(revision, VaultControlNSID, "self")
	headAction := transitionRecordAction(revision, VaultHeadNSID, "self")
	additional := []RecordWrite{{Action: policyAction, Collection: VaultPolicyNSID, RKey: "self", Record: policyJSON}}
	if transition.Kind != vault.TransitionRevoke {
		additional = append(additional, RecordWrite{Action: RecordCreate, Collection: VaultCertificateNSID, RKey: certificateRKey, Record: certificateJSON})
	}
	return FencedPublication{
		FirstBlobReference: RecordWrite{Action: RecordCreate, Collection: VaultSnapshotNSID, RKey: transitionMarkerRKey(transition.Kind, envelope.PublicationID), Record: snapshotJSON},
		VaultHead:          RecordWrite{Action: headAction, Collection: VaultHeadNSID, RKey: "self", Record: headJSON},
		VaultControl:       RecordWrite{Action: controlAction, Collection: VaultControlNSID, RKey: "self", Record: controlJSON},
		Additional:         additional,
	}, nil
}

func transitionSignerKeyMatches(transition vault.Transition, signer ed25519.PrivateKey, envelope vault.Envelope) bool {
	for _, encoded := range transition.Recipients {
		certificate, err := vault.DecodeCertificate(encoded)
		if err == nil && certificate.DeviceID == envelope.DeviceID && bytes.Equal(certificate.KeyID, envelope.KeyID) {
			return bytes.Equal(certificate.SigningPublicKey[:], signer.Public().(ed25519.PublicKey))
		}
	}
	return false
}

func snapshotRecordForTransition(transition vault.Transition, blob atdata.Blob, signer ed25519.PrivateKey) (SnapshotRecord, error) {
	envelope, err := vault.DecodeEnvelope(transition.Snapshot)
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

func marshalRecord(record Record) (json.RawMessage, error) {
	object, err := recordMap(record)
	if err != nil {
		return nil, fmt.Errorf("%w: encode vault record", ErrBatchRejected)
	}
	encoded, err := json.Marshal(normalizeRecordJSONMap(object))
	if err != nil || !json.Valid(encoded) {
		return nil, fmt.Errorf("%w: encode vault record", ErrBatchRejected)
	}
	return encoded, nil
}

func normalizeRecordJSONMap(object map[string]any) map[string]any {
	normalized := make(map[string]any, len(object))
	for key, value := range object {
		normalized[key] = normalizeRecordJSONValue(value)
	}
	return normalized
}

func normalizeRecordJSONValue(value any) any {
	switch item := value.(type) {
	case []byte:
		return atdata.Bytes(item)
	case atdata.Bytes:
		return item
	case []any:
		normalized := make([]any, len(item))
		for index := range item {
			normalized[index] = normalizeRecordJSONValue(item[index])
		}
		return normalized
	case map[string]any:
		return normalizeRecordJSONMap(item)
	default:
		return value
	}
}

func recordCIDText(encodedJSON []byte) (string, error) {
	object, err := atdata.UnmarshalJSON(encodedJSON)
	if err != nil {
		return "", fmt.Errorf("%w: decode AT Protocol record JSON", ErrBatchRejected)
	}
	dagCBOR, err := atdata.MarshalCBOR(normalizeRecordMap(object))
	if err != nil {
		return "", fmt.Errorf("%w: encode AT Protocol record DAG-CBOR", ErrBatchRejected)
	}
	prefix := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	computed, err := prefix.Sum(dagCBOR)
	if err != nil {
		return "", fmt.Errorf("%w: compute record CID", ErrBatchRejected)
	}
	return computed.String(), nil
}

func newTransitionAttemptID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate transition attempt id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func transitionMarkerRKey(kind vault.TransitionKind, publicationID [16]byte) string {
	prefix := "enroll-"
	if kind == vault.TransitionRevoke {
		prefix = "revoke-"
	}
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicationID[:]))
}

func transitionCertificateRKey(certificate vault.Certificate) string {
	identity := append([]byte(certificate.DeviceID+"\x00"), certificate.KeyID...)
	digest := sha256.Sum256(identity)
	return hex.EncodeToString(digest[:])
}

func transitionRecordAction(revision *Revision, collection, rkey string) string {
	if revision.HasRecord(RecordKey{Collection: collection, RKey: rkey}) {
		return RecordUpdate
	}
	return RecordCreate
}

func transitionPolicyDigest(transition vault.Transition) []byte {
	digest, _ := vault.ComputePolicyDigest(transition.Policy)
	return digest[:]
}

func transitionEpoch(transition vault.Transition) uint64 {
	envelope, err := vault.DecodeEnvelope(transition.Snapshot)
	if err != nil {
		return 0
	}
	return envelope.EpochSeq
}

func blobJSONFromCID(rawCID []byte, size int) json.RawMessage {
	parsed, err := cid.Cast(rawCID)
	if err != nil {
		return nil
	}
	encoded, _ := json.Marshal(atdata.Blob{Ref: atdata.CIDLink(parsed), MimeType: "application/octet-stream", Size: int64(size)})
	return encoded
}

func rawTransitionCID(data []byte) []byte {
	hash, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return nil
	}
	return cid.NewCidV1(cid.Raw, hash).Bytes()
}

func mustTransitionMultihash(data []byte) []byte {
	hash, _ := multihash.Sum(data, multihash.SHA2_256, -1)
	return hash
}

func evidenceWith(encoded, key, value string) string {
	var evidence map[string]any
	if json.Unmarshal([]byte(encoded), &evidence) != nil || evidence == nil {
		evidence = make(map[string]any)
	}
	evidence[key] = value
	updated, err := json.Marshal(evidence)
	if err != nil {
		return encoded
	}
	return string(updated)
}

func revisionCommit(revision *Revision) string {
	if revision == nil {
		return ""
	}
	return revision.CommitCID()
}

func predecessorPolicyEvidence(current vault.Policy, candidates [][]byte) ([]byte, error) {
	if allZero(current.PrevPolicyDigest[:]) {
		return nil, nil
	}
	var selected []byte
	for _, candidate := range candidates {
		decoded, err := DecodeRecord(candidate)
		if err != nil {
			continue
		}
		record, ok := decoded.(PolicyRecord)
		if !ok {
			continue
		}
		object, err := vault.EncodePolicy(policyFromRecord(record))
		if err != nil {
			continue
		}
		digest, err := vault.ComputePolicyDigest(object)
		if err != nil || digest != current.PrevPolicyDigest {
			continue
		}
		if err := VerifyRecordBinding(candidate, object); err != nil {
			return nil, err
		}
		if selected != nil && !bytes.Equal(selected, candidate) {
			return nil, fmt.Errorf("%w: predecessor policy evidence is ambiguous", ErrReadVaultAuthentication)
		}
		selected = bytes.Clone(candidate)
	}
	if selected == nil {
		return nil, ErrReadPreviousPolicyRequired
	}
	return selected, nil
}

func predecessorFromRevision(revision *Revision, trustAnchor [32]byte, previousPolicies [][]byte) (vault.Predecessor, error) {
	if revision == nil {
		return vault.Predecessor{}, fmt.Errorf("%w: verified revision is required", ErrUntrustedCar)
	}
	policyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	policyProven, policyOK := revision.records[policyKey]
	controlProven, controlOK := revision.records[controlKey]
	if !policyOK || !controlOK {
		return vault.Predecessor{}, fmt.Errorf("%w: policy and control self records are required", ErrUnprovenMembership)
	}
	policyDecoded, err := DecodeRecord(policyProven.Data)
	if err != nil {
		return vault.Predecessor{}, err
	}
	policyRecord, ok := policyDecoded.(PolicyRecord)
	if !ok {
		return vault.Predecessor{}, fmt.Errorf("%w: policy/self has wrong record type", ErrRecord)
	}
	controlDecoded, err := DecodeRecord(controlProven.Data)
	if err != nil {
		return vault.Predecessor{}, err
	}
	controlRecord, ok := controlDecoded.(ControlRecord)
	if !ok {
		return vault.Predecessor{}, fmt.Errorf("%w: control/self has wrong record type", ErrRecord)
	}
	policyObject := policyFromRecord(policyRecord)
	controlObject := controlFromRecord(controlRecord)
	policyBytes, err := vault.EncodePolicy(policyObject)
	if err != nil {
		return vault.Predecessor{}, err
	}
	controlBytes, err := vault.EncodeControl(controlObject)
	if err != nil {
		return vault.Predecessor{}, err
	}
	if err := VerifyRecordBinding(policyProven.Data, policyBytes); err != nil {
		return vault.Predecessor{}, err
	}
	if err := VerifyRecordBinding(controlProven.Data, controlBytes); err != nil {
		return vault.Predecessor{}, err
	}
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	if err != nil {
		return vault.Predecessor{}, err
	}
	controlHash, err := multihash.Sum(controlBytes, multihash.SHA2_256, -1)
	if err != nil {
		return vault.Predecessor{}, fmt.Errorf("%w: control object CID", ErrRecord)
	}
	controlCID := cid.NewCidV1(cid.Raw, controlHash).Bytes()
	certificateRecords := make(map[string]CertificateRecord)
	certificateData := make(map[string][]byte)
	for key, proven := range revision.records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		decoded, err := DecodeRecord(proven.Data)
		if err != nil {
			return vault.Predecessor{}, err
		}
		certificate, ok := decoded.(CertificateRecord)
		if !ok {
			return vault.Predecessor{}, fmt.Errorf("%w: certificate collection contains another record type", ErrRecord)
		}
		if _, exists := certificateRecords[certificate.DeviceID]; exists {
			return vault.Predecessor{}, fmt.Errorf("%w: duplicate certificate device", ErrRecord)
		}
		certificateRecords[certificate.DeviceID] = certificate
		certificateData[certificate.DeviceID] = proven.Data
	}
	certificates := make([][]byte, 0, len(policyObject.Recipients))
	for _, recipient := range policyObject.Recipients {
		record, exists := certificateRecords[recipient.DeviceID]
		if !exists {
			return vault.Predecessor{}, fmt.Errorf("%w: active recipient certificate is absent", ErrUnprovenMembership)
		}
		certificate := certificateFromRecord(record)
		encoded, err := vault.EncodeCertificate(certificate)
		if err != nil {
			return vault.Predecessor{}, err
		}
		if err := VerifyRecordBinding(certificateData[recipient.DeviceID], encoded); err != nil {
			return vault.Predecessor{}, err
		}
		certificates = append(certificates, encoded)
	}
	if err := verifyPredecessorAuthority(policyObject, controlObject, certificates, trustAnchor); err != nil {
		return vault.Predecessor{}, err
	}
	var headCID []byte
	var currentSnapshot []byte
	headKey := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
	if headProven, exists := revision.records[headKey]; exists {
		headDecoded, err := DecodeRecord(headProven.Data)
		if err != nil {
			return vault.Predecessor{}, err
		}
		headRecord, ok := headDecoded.(HeadRecord)
		if !ok {
			return vault.Predecessor{}, fmt.Errorf("%w: head/self has wrong record type", ErrRecord)
		}
		headObject := headFromRecord(headRecord)
		headBytes, err := vault.EncodeHead(headObject)
		if err != nil {
			return vault.Predecessor{}, err
		}
		if err := VerifyRecordBinding(headProven.Data, headBytes); err != nil {
			return vault.Predecessor{}, err
		}
		if headObject.EpochSeq != controlObject.EpochSeq || headObject.PolicyDigest != controlObject.PolicyDigest || !bytes.Equal(headObject.BlobCID, headObject.SnapshotCID) {
			return vault.Predecessor{}, fmt.Errorf("%w: current head does not match control", ErrRecord)
		}
		signerCertificate, exists := certificateForVaultSigner(certificates, headObject.Signer.DeviceID, headObject.Signer.KeyID)
		if !exists {
			return vault.Predecessor{}, fmt.Errorf("%w: current head signer certificate is absent", vault.ErrAuthorization)
		}
		if err := verifyVaultObjectSignature(headBytes, "dottie/v1/sig-head", headObject.Signature[:], signerCertificate.SigningPublicKey[:]); err != nil {
			return vault.Predecessor{}, err
		}
		for key, proven := range revision.records {
			if key.Collection != VaultSnapshotNSID {
				continue
			}
			decoded, err := DecodeRecord(proven.Data)
			if err != nil {
				return vault.Predecessor{}, err
			}
			snapshot, ok := decoded.(SnapshotRecord)
			if ok && bytes.Equal(cid.Cid(snapshot.Blob.Ref).Bytes(), headObject.SnapshotCID) {
				if currentSnapshot != nil {
					return vault.Predecessor{}, fmt.Errorf("%w: current snapshot is not unique", ErrRecord)
				}
				currentSnapshot = bytes.Clone(proven.Data)
			}
		}
		if currentSnapshot == nil {
			return vault.Predecessor{}, fmt.Errorf("%w: current snapshot record is absent", ErrUnprovenMembership)
		}
		snapshotDecoded, err := DecodeRecord(currentSnapshot)
		if err != nil {
			return vault.Predecessor{}, err
		}
		snapshotRecord, ok := snapshotDecoded.(SnapshotRecord)
		if !ok {
			return vault.Predecessor{}, fmt.Errorf("%w: current snapshot record has wrong type", ErrRecord)
		}
		snapshotSigner, exists := certificateForVaultSigner(certificates, snapshotRecord.SignerDeviceID, snapshotRecord.SignerKeyID)
		if !exists {
			return vault.Predecessor{}, fmt.Errorf("%w: snapshot signer certificate is absent", vault.ErrAuthorization)
		}
		if err := VerifySnapshotRecordSignature(snapshotRecord, ed25519.PublicKey(snapshotSigner.SigningPublicKey[:])); err != nil {
			return vault.Predecessor{}, err
		}
		if err := VerifyRecordContext(currentSnapshot, RecordContext{Policy: policyProven.Data, Certificate: certificateData[snapshotRecord.SignerDeviceID]}); err != nil {
			return vault.Predecessor{}, err
		}
		headCID = bytes.Clone(headObject.SnapshotCID)
	}
	if len(headCID) == 0 && len(controlObject.HeadSnapshotCID) != 0 {
		return vault.Predecessor{}, fmt.Errorf("%w: control and current head disagree", ErrRecord)
	}
	if len(headCID) > 0 {
		headProven := revision.records[headKey]
		if err := VerifyRecordContext(headProven.Data, RecordContext{Policy: policyProven.Data, Snapshot: currentSnapshot}); err != nil {
			return vault.Predecessor{}, err
		}
		if err := VerifyRecordContext(controlProven.Data, RecordContext{Policy: policyProven.Data, Snapshot: currentSnapshot}); err != nil {
			return vault.Predecessor{}, err
		}
	} else if err := VerifyRecordContext(controlProven.Data, RecordContext{Policy: policyProven.Data, Snapshot: []byte{}}); err != nil {
		return vault.Predecessor{}, err
	}
	rootRecord, exists := certificateRecords[policyRecord.SignerDeviceID]
	if !exists {
		return vault.Predecessor{}, fmt.Errorf("%w: policy signer certificate is absent", vault.ErrAuthorization)
	}
	previousPolicy, err := predecessorPolicyEvidence(policyObject, previousPolicies)
	if err != nil {
		return vault.Predecessor{}, err
	}
	storedCertificates := make(map[string]storedCertificate, len(certificates))
	for _, encoded := range certificates {
		certificate, decodeErr := vault.DecodeCertificate(encoded)
		if decodeErr != nil {
			return vault.Predecessor{}, decodeErr
		}
		storedCertificates[certificateIdentity(certificate.DeviceID, certificate.KeyID)] = storedCertificate{
			recordBytes: bytes.Clone(certificateData[certificate.DeviceID]), objectBytes: bytes.Clone(encoded), object: certificate,
		}
	}
	policySigner, exists := storedCertificates[certificateIdentity(policyObject.Signer.DeviceID, policyObject.Signer.KeyID)]
	if !exists {
		return vault.Predecessor{}, fmt.Errorf("%w: policy signer certificate is absent", vault.ErrAuthorization)
	}
	request := ReadRequest{Vault: policyObject.Vault, TrustAnchor: trustAnchor, PreviousPolicy: previousPolicy}
	if err := authorizePolicyPredecessor(request, policyObject, policyBytes, policySigner, storedCertificates); err != nil {
		return vault.Predecessor{}, fmt.Errorf("%w: predecessor policy authentication: %w", ErrReadVaultAuthentication, err)
	}
	if err := VerifyRecordContext(policyProven.Data, RecordContext{
		Certificate: certificateData[rootRecord.DeviceID], PreviousPolicy: previousPolicy, TrustAnchor: trustAnchor,
	}); err != nil {
		return vault.Predecessor{}, err
	}
	return vault.Predecessor{
		ControlCID: controlCID, PolicyDigest: policyDigest, EpochSeq: controlObject.EpochSeq,
		HeadCID: headCID, Control: controlBytes, Policy: policyBytes, Certificates: certificates,
		TrustAnchor: trustAnchor,
	}, nil
}

func verifyPredecessorAuthority(policy vault.Policy, control vault.Control, certificates [][]byte, trustAnchor [32]byte) error {
	policyBytes, err := vault.EncodePolicy(policy)
	if err != nil {
		return err
	}
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	if err != nil {
		return err
	}
	controlBytes, err := vault.EncodeControl(control)
	if err != nil {
		return err
	}
	if len(policy.Roles) != len(certificates) || len(policy.Recipients) != len(certificates) || policy.Vault != control.Vault || policy.EpochSeq != control.EpochSeq || policy.EpochSeq > uint64(^uint64(0)>>1) || control.PolicyDigest != policyDigest {
		return fmt.Errorf("%w: current policy/control state disagrees", vault.ErrAuthorization)
	}
	if policy.Signer.DeviceID != control.Signer.DeviceID || !bytes.Equal(policy.Signer.KeyID, control.Signer.KeyID) {
		return fmt.Errorf("%w: current policy/control signer disagrees", vault.ErrAuthorization)
	}
	roleDevices := make(map[string]bool, len(policy.Roles))
	for _, binding := range policy.Roles {
		if roleDevices[binding.DeviceID] {
			return fmt.Errorf("%w: current policy has duplicate role bindings", vault.ErrAuthorization)
		}
		roleDevices[binding.DeviceID] = true
	}
	recipientDevices := make(map[string]bool, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		if recipientDevices[recipient.DeviceID] {
			return fmt.Errorf("%w: current policy has duplicate recipients", vault.ErrAuthorization)
		}
		recipientDevices[recipient.DeviceID] = true
	}
	byDevice := make(map[string]vault.Certificate, len(certificates))
	keyIDs := make(map[string]bool, len(certificates))
	for _, encoded := range certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		if err != nil {
			return err
		}
		if certificate.Vault != policy.Vault || certificate.CertEpoch > policy.EpochSeq || keyIDs[string(certificate.KeyID)] || byDevice[certificate.DeviceID].DeviceID != "" {
			return fmt.Errorf("%w: current certificate set is inconsistent", vault.ErrAuthorization)
		}
		byDevice[certificate.DeviceID] = certificate
		keyIDs[string(certificate.KeyID)] = true
		role, exists := currentPolicyRole(policy, certificate.DeviceID)
		if !exists || role != certificate.Role || currentDeviceRevoked(control, certificate) {
			return fmt.Errorf("%w: active certificate role or revocation is inconsistent", vault.ErrAuthorization)
		}
		recipient, exists := currentPolicyRecipient(policy, certificate.DeviceID)
		if !exists || !bytes.Equal(recipient.KeyID, certificate.KeyID) || !bytes.Equal(recipient.PublicKey[:], certificate.EncryptionPublicKey[:]) {
			return fmt.Errorf("%w: active certificate recipient is inconsistent", vault.ErrAuthorization)
		}
	}
	policySigner, exists := byDevice[policy.Signer.DeviceID]
	if !exists || !bytes.Equal(policySigner.KeyID, policy.Signer.KeyID) || policySigner.Role != vault.RoleRoot {
		return fmt.Errorf("%w: policy signer certificate is absent", vault.ErrAuthorization)
	}
	controlSigner, exists := byDevice[control.Signer.DeviceID]
	if !exists || !bytes.Equal(controlSigner.KeyID, control.Signer.KeyID) || controlSigner.Role != vault.RoleRoot {
		return fmt.Errorf("%w: control signer certificate is absent", vault.ErrAuthorization)
	}
	if err := verifyVaultObjectSignature(policyBytes, "dottie/v1/sig-policy", policy.Signature[:], policySigner.SigningPublicKey[:]); err != nil {
		return err
	}
	if err := verifyVaultObjectSignature(controlBytes, "dottie/v1/sig-control", control.Signature[:], controlSigner.SigningPublicKey[:]); err != nil {
		return err
	}
	for _, certificate := range byDevice {
		if err := verifyCurrentCertificateChain(certificate, byDevice, trustAnchor, policy.Vault, policy.EpochSeq, 1, make(map[string]bool)); err != nil {
			return err
		}
	}
	return nil
}

func verifyCurrentCertificateChain(certificate vault.Certificate, certificates map[string]vault.Certificate, trustAnchor [32]byte, vaultID [32]byte, epoch uint64, depth int, visited map[string]bool) error {
	if depth > 3 || certificate.Vault != vaultID || certificate.CertEpoch > epoch || visited[certificate.DeviceID] {
		return fmt.Errorf("%w: current certificate chain is invalid", vault.ErrAuthorization)
	}
	visited[certificate.DeviceID] = true
	defer delete(visited, certificate.DeviceID)
	encoded, err := vault.EncodeCertificate(certificate)
	if err != nil {
		return err
	}
	if certificate.Issuer == certificate.DeviceID {
		fingerprint := sha256.Sum256(certificate.SigningPublicKey[:])
		if certificate.Role != vault.RoleRoot || certificate.Signer.DeviceID != certificate.DeviceID || !bytes.Equal(certificate.Signer.KeyID, certificate.KeyID) || fingerprint != trustAnchor {
			return fmt.Errorf("%w: current root certificate is not anchored", vault.ErrAuthorization)
		}
		return verifyVaultObjectSignature(encoded, "dottie/v1/sig-certificate", certificate.Signature[:], certificate.SigningPublicKey[:])
	}
	issuer, exists := certificates[certificate.Issuer]
	if !exists || issuer.Role != vault.RoleRoot || certificate.Signer.DeviceID != issuer.DeviceID || !bytes.Equal(certificate.Signer.KeyID, issuer.KeyID) {
		return fmt.Errorf("%w: current certificate issuer is invalid", vault.ErrAuthorization)
	}
	if err := verifyCurrentCertificateChain(issuer, certificates, trustAnchor, vaultID, epoch, depth+1, visited); err != nil {
		return err
	}
	return verifyVaultObjectSignature(encoded, "dottie/v1/sig-certificate", certificate.Signature[:], issuer.SigningPublicKey[:])
}

func currentPolicyRole(policy vault.Policy, deviceID string) (vault.Role, bool) {
	for _, binding := range policy.Roles {
		if binding.DeviceID == deviceID {
			return binding.Role, true
		}
	}
	return 0, false
}

func currentPolicyRecipient(policy vault.Policy, deviceID string) (vault.PolicyRecipient, bool) {
	for _, recipient := range policy.Recipients {
		if recipient.DeviceID == deviceID {
			return recipient, true
		}
	}
	return vault.PolicyRecipient{}, false
}

func currentDeviceRevoked(control vault.Control, certificate vault.Certificate) bool {
	for _, revoked := range control.Revoked {
		if revoked.DeviceID == certificate.DeviceID && revoked.CertEpoch >= certificate.CertEpoch {
			return true
		}
	}
	return false
}

func certificateForVaultSigner(certificates [][]byte, deviceID string, keyID []byte) (vault.Certificate, bool) {
	for _, encoded := range certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		if err == nil && certificate.DeviceID == deviceID && bytes.Equal(certificate.KeyID, keyID) {
			return certificate, true
		}
	}
	return vault.Certificate{}, false
}

func verifyVaultObjectSignature(encoded []byte, context string, signature []byte, key []byte) error {
	if len(encoded) < ed25519.SignatureSize || len(signature) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize {
		return ErrSignature
	}
	preimage := append([]byte("dottie/v1/sig"), encoded[:len(encoded)-ed25519.SignatureSize]...)
	return vault.Verify(context, preimage, signature, ed25519.PublicKey(key))
}

func toPolicyRecord(value vault.Policy) PolicyRecord {
	roles := make([]PolicyRoleRecord, len(value.Roles))
	for index, role := range value.Roles {
		roles[index] = PolicyRoleRecord{DeviceID: role.DeviceID, Role: uint8(role.Role)}
	}
	recipients := make([]PolicyRecipientRecord, len(value.Recipients))
	for index, recipient := range value.Recipients {
		recipients[index] = PolicyRecipientRecord{DeviceID: recipient.DeviceID, KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:])}
	}
	return PolicyRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), EpochSeq: value.EpochSeq, Roles: roles, Recipients: recipients,
		PolicyRetentionFloor: value.PolicyRetentionFloor, RetainedRecoveryPoints: value.RetainedRecoveryPoints,
		MaxPublications: value.MaxPublications, MaxEpochAge: value.MaxEpochAge, RecoveryAnchor: bytes.Clone(value.RecoveryAnchor[:]),
		PrevPolicyDigest: bytes.Clone(value.PrevPolicyDigest[:]), SignerDeviceID: value.Signer.DeviceID,
		SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func toControlRecord(value vault.Control) ControlRecord {
	revoked := make([]RevokedDeviceRecord, len(value.Revoked))
	for index, entry := range value.Revoked {
		revoked[index] = RevokedDeviceRecord{DeviceID: entry.DeviceID, CertEpoch: entry.CertEpoch}
	}
	return ControlRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), EpochSeq: value.EpochSeq, PolicyDigest: bytes.Clone(value.PolicyDigest[:]),
		HeadSnapshotCID: bytes.Clone(value.HeadSnapshotCID), Revoked: revoked, PrevControlCID: bytes.Clone(value.PrevControlCID),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func toHeadRecord(value vault.Head) HeadRecord {
	return HeadRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), EpochSeq: value.EpochSeq, PolicyDigest: bytes.Clone(value.PolicyDigest[:]),
		SnapshotCID: bytes.Clone(value.SnapshotCID), BlobCID: bytes.Clone(value.BlobCID), PublicationCount: value.PublicationCount,
		PrevHeadCID: bytes.Clone(value.PrevHeadCID), SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID),
		Signature: bytes.Clone(value.Signature[:]),
	}
}

func toCertificateRecord(value vault.Certificate) CertificateRecord {
	return CertificateRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), DeviceID: value.DeviceID, KeyID: bytes.Clone(value.KeyID),
		SigningPublicKey: bytes.Clone(value.SigningPublicKey[:]), EncryptionPublicKey: bytes.Clone(value.EncryptionPublicKey[:]),
		Role: uint8(value.Role), CertEpoch: value.CertEpoch, Issuer: value.Issuer, RevocationRef: bytes.Clone(value.RevocationRef),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func controlFromRecord(record ControlRecord) vault.Control {
	revoked := make([]vault.RevokedDevice, len(record.Revoked))
	for index, value := range record.Revoked {
		revoked[index] = vault.RevokedDevice{DeviceID: value.DeviceID, CertEpoch: value.CertEpoch}
	}
	return vault.Control{
		Vault: [32]byte(record.Vault), EpochSeq: record.EpochSeq, PolicyDigest: [32]byte(record.PolicyDigest),
		HeadSnapshotCID: bytes.Clone(record.HeadSnapshotCID), Revoked: revoked, PrevControlCID: bytes.Clone(record.PrevControlCID),
		Signer: vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)}, Signature: [ed25519.SignatureSize]byte(record.Signature),
	}
}

func headFromRecord(record HeadRecord) vault.Head {
	return vault.Head{
		Vault: [32]byte(record.Vault), EpochSeq: record.EpochSeq, PolicyDigest: [32]byte(record.PolicyDigest),
		SnapshotCID: bytes.Clone(record.SnapshotCID), BlobCID: bytes.Clone(record.BlobCID), PublicationCount: record.PublicationCount,
		PrevHeadCID: bytes.Clone(record.PrevHeadCID), Signer: vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)},
		Signature: [ed25519.SignatureSize]byte(record.Signature),
	}
}

func certificateFromRecord(record CertificateRecord) vault.Certificate {
	return vault.Certificate{
		Vault: [32]byte(record.Vault), DeviceID: record.DeviceID, KeyID: bytes.Clone(record.KeyID),
		SigningPublicKey: [ed25519.PublicKeySize]byte(record.SigningPublicKey), EncryptionPublicKey: [32]byte(record.EncryptionPublicKey),
		Role: vault.Role(record.Role), CertEpoch: record.CertEpoch, Issuer: record.Issuer, RevocationRef: bytes.Clone(record.RevocationRef),
		Signer: vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)}, Signature: [ed25519.SignatureSize]byte(record.Signature),
	}
}
