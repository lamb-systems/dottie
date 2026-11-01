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

func PublishFenced(ctx context.Context, transport Transport, revision *Revision, publication FencedPublication) (PublishResult, error) {
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
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites request outcome is unknown", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)
	}
	if status >= 500 {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, status)
	}
	if status >= 400 && status < 500 {
		var remoteError applyWritesError
		if json.Unmarshal(response, &remoteError) == nil && remoteError.Error == "InvalidSwap" {
			return PublishResult{}, ErrFenceLost
		}
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrBatchRejected, ErrCandidateMayBeDisclosed, status)
	}
	if status < 200 || status >= 300 {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, status)
	}
	var output applyWritesOutput
	if len(response) != 0 {
		if err := json.Unmarshal(response, &output); err != nil {
			return PublishResult{}, fmt.Errorf("%w: %w: applyWrites response is malformed after submission", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)
		}
	}
	return PublishResult{CommitCID: output.Commit.CID}, nil
}

type PublicationIO interface {
	ReadCurrent(context.Context) (*Revision, vault.Predecessor, error)
	StageCandidate(context.Context, []byte) (json.RawMessage, string, error)
	ApplyPublication(context.Context, *Revision, FencedSnapshotPublication) error
}

type ATProtoPublicationIO struct {
	Reader      RevisionReader
	Transport   Transport
	DID         string
	TrustAnchor [32]byte
}

func (io ATProtoPublicationIO) ReadCurrent(ctx context.Context) (*Revision, vault.Predecessor, error) {
	return (ATProtoTransitionIO{Reader: io.Reader, Transport: io.Transport, DID: io.DID, TrustAnchor: io.TrustAnchor}).ReadCurrent(ctx)
}

func (io ATProtoPublicationIO) StageCandidate(ctx context.Context, data []byte) (json.RawMessage, string, error) {
	return (ATProtoTransitionIO{Transport: io.Transport}).StageCandidate(ctx, data)
}

func (io ATProtoPublicationIO) ApplyPublication(ctx context.Context, revision *Revision, publication FencedSnapshotPublication) error {
	_, err := PublishSnapshotFenced(ctx, io.Transport, revision, publication)
	return err
}

func PublishSnapshotFenced(ctx context.Context, transport Transport, revision *Revision, publication FencedSnapshotPublication) (PublishResult, error) {
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
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites request outcome is unknown", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)
	}
	if status >= 500 {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, status)
	}
	if status >= 400 && status < 500 {
		var remoteError applyWritesError
		if json.Unmarshal(response, &remoteError) == nil && remoteError.Error == "InvalidSwap" {
			return PublishResult{}, ErrFenceLost
		}
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrBatchRejected, ErrCandidateMayBeDisclosed, status)
	}
	if status < 200 || status >= 300 {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, status)
	}
	var output applyWritesOutput
	if len(response) != 0 {
		if err := json.Unmarshal(response, &output); err != nil {
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
	var snapshot SnapshotRecord
	if err := json.Unmarshal(snapshotWrite.Record, &snapshot); err != nil || len(snapshot.Vault) != 32 || len(snapshot.PolicyDigest) != 32 || len(snapshot.PublicationID) != 16 || !snapshot.Blob.Ref.IsDefined() {
		return fmt.Errorf("%w: snapshot record is malformed", ErrBatchRejected)
	}
	var head HeadRecord
	if err := json.Unmarshal(headWrite.Record, &head); err != nil || len(head.Vault) != 32 || len(head.PolicyDigest) != 32 || head.PublicationCount == 0 {
		return fmt.Errorf("%w: head record is malformed", ErrBatchRejected)
	}
	snapshotCID := cid.Cid(snapshot.Blob.Ref).Bytes()
	if !bytes.Equal(head.Vault, snapshot.Vault) || head.EpochSeq != snapshot.EpochSeq || !bytes.Equal(head.PolicyDigest, snapshot.PolicyDigest) || !bytes.Equal(head.SnapshotCID, snapshotCID) || !bytes.Equal(head.BlobCID, snapshotCID) {
		return fmt.Errorf("%w: snapshot and head references are not contained in the same fence", ErrBatchRejected)
	}
	return nil
}

func CommitPublication(ctx context.Context, io PublicationIO, store TransitionAttemptStore, publication vault.Publication, signer ed25519.PrivateKey, now time.Time) (PublicationCommitResult, error) {
	if io == nil || store == nil || len(signer) != ed25519.PrivateKeySize || now.IsZero() {
		return PublicationCommitResult{}, fmt.Errorf("%w: publication I/O, store, signer and timestamp are required", ErrBatchRejected)
	}
	initialRevision, initialPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		return PublicationCommitResult{}, fmt.Errorf("read current publication predecessor: %w", err)
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
	marker := RecordKey{Collection: VaultSnapshotNSID, RKey: preview.SnapshotReference.RKey}
	markerCID, err := recordCIDText(preview.SnapshotReference.Record)
	if err != nil {
		return PublicationCommitResult{}, err
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
	blobReference, uploadedCID, err := io.StageCandidate(ctx, publication.Snapshot)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "stageError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return publicationResult(attempt, TransitionOutcomeNotLanded, initialRevision, updatedEvidence), errors.Join(err, updateErr, ErrCandidateMayBeDisclosed)
	}
	if uploadedCID != blobCID {
		mismatch := fmt.Errorf("%w: uploaded candidate CID differs from the sealed publication", ErrBatchRejected)
		updatedEvidence := evidenceWith(string(evidence), "uploadedCID", uploadedCID)
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return publicationResult(attempt, TransitionOutcomeNotLanded, initialRevision, updatedEvidence), errors.Join(mismatch, updateErr, ErrCandidateMayBeDisclosed)
	}
	if err := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeStaged, string(evidence)); err != nil {
		return publicationResult(attempt, TransitionOutcomeNotLanded, initialRevision, string(evidence)), errors.Join(err, ErrCandidateMayBeDisclosed)
	}
	currentRevision, currentPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "revalidationReadError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return publicationResult(attempt, TransitionOutcomeNotLanded, nil, updatedEvidence), errors.Join(err, updateErr, ErrCandidateMayBeDisclosed)
	}
	if publication.PolicyDigest != currentPredecessor.PolicyDigest {
		mismatch := &PreparedPolicyMismatchError{Prepared: publication.PolicyDigest, Current: currentPredecessor.PolicyDigest}
		updatedEvidence := evidenceWith(string(evidence), "revalidationError", mismatch.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		result := publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence)
		result.Predecessor = &currentPredecessor
		return result, errors.Join(mismatch, updateErr, ErrCandidateMayBeDisclosed)
	}
	if err := vault.ValidatePublication(publication, currentPredecessor); err != nil {
		updatedEvidence := evidenceWith(string(evidence), "revalidationError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		result := publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence)
		result.Predecessor = &currentPredecessor
		return result, errors.Join(err, updateErr, ErrCandidateMayBeDisclosed)
	}
	fencedPublication, err := snapshotPublication(publication, signer, blobReference, currentRevision, currentPredecessor)
	if err != nil {
		updatedEvidence := evidenceWith(string(evidence), "recordError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeNotLanded, updatedEvidence)
		return publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, updatedEvidence), errors.Join(err, updateErr, ErrCandidateMayBeDisclosed)
	}
	if err := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeSubmitted, string(evidence)); err != nil {
		return publicationResult(attempt, TransitionOutcomeNotLanded, currentRevision, string(evidence)), errors.Join(err, ErrCandidateMayBeDisclosed)
	}
	applyErr := io.ApplyPublication(ctx, currentRevision, fencedPublication)
	if errors.Is(applyErr, ErrFenceLost) {
		latest, latestPredecessor, readErr := io.ReadCurrent(ctx)
		updatedEvidence := evidenceWith(string(evidence), "fenceLostRevision", revisionCommit(latest))
		if readErr != nil {
			updatedEvidence = evidenceWith(updatedEvidence, "fenceLostReadError", readErr.Error())
		}
		updateErr := store.UpdateTransitionAttempt(ctx, attemptID, TransitionOutcomeFenceLost, updatedEvidence)
		result := publicationResult(attempt, TransitionOutcomeFenceLost, latest, updatedEvidence)
		if readErr == nil {
			result.Predecessor = &latestPredecessor
		}
		return result, errors.Join(&PublicationFenceLostError{Result: result}, updateErr)
	}
	resolved, resolveErr := resolveSubmittedPublication(ctx, io, store, attempt, string(evidence))
	if resolveErr != nil {
		return resolved, errors.Join(applyErr, resolveErr, ErrCandidateMayBeDisclosed)
	}
	if resolved.Outcome == TransitionOutcomeCommitted {
		return resolved, nil
	}
	return resolved, errors.Join(applyErr, outcomeError(resolved.Outcome), ErrCandidateMayBeDisclosed)
}

func ResolvePublicationAttempt(ctx context.Context, io PublicationIO, store TransitionAttemptStore, attemptID string) (PublicationCommitResult, error) {
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
	Version          int    `json:"version"`
	Kind             string `json:"kind"`
	HeadRecordCID    string `json:"headRecordCid"`
	PreparedRevision string `json:"preparedRevision"`
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

func publicationResult(attempt state.TransitionAttempt, outcome TransitionOutcome, revision *Revision, evidence string) PublicationCommitResult {
	return PublicationCommitResult{
		Outcome: outcome, AttemptID: attempt.ID,
		Marker:    RecordKey{Collection: attempt.MarkerCollection, RKey: attempt.MarkerRKey},
		RecordCID: attempt.ExpectedRecordCID, BlobCID: attempt.CandidateBlobCID, Revision: revision, Evidence: evidence,
	}
}

func resolveSubmittedPublication(ctx context.Context, io PublicationIO, store TransitionAttemptStore, attempt state.TransitionAttempt, evidence string) (PublicationCommitResult, error) {
	latest, latestPredecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		updatedEvidence := evidenceWith(evidence, "resolutionError", err.Error())
		updateErr := store.UpdateTransitionAttempt(ctx, attempt.ID, TransitionOutcomeUnavailable, updatedEvidence)
		return publicationResult(attempt, TransitionOutcomeUnavailable, nil, updatedEvidence), errors.Join(fmt.Errorf("%w: %v", ErrTransitionUnavailable, err), updateErr)
	}
	var expected publicationAttemptEvidence
	if err := json.Unmarshal([]byte(evidence), &expected); err != nil || expected.Version != 1 || expected.Kind != "publication" || expected.HeadRecordCID == "" {
		updatedEvidence := evidenceWith(evidence, "resolutionEvidenceError", "missing expected head record CID")
		updateErr := store.UpdateTransitionAttempt(ctx, attempt.ID, TransitionOutcomeUnavailable, updatedEvidence)
		result := publicationResult(attempt, TransitionOutcomeUnavailable, latest, updatedEvidence)
		result.Predecessor = &latestPredecessor
		return result, errors.Join(ErrTransitionUnavailable, updateErr)
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
		return result, err
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
