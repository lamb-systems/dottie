package atproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/vault"
)

type AttestationRelayCommitter interface {
	CommitAttestation(context.Context, *Revision, []byte) error
}

type ATProtoAttestationRelay struct {
	Reader           RevisionReader
	Transport        Transport
	DID              string
	TrustAnchor      [32]byte
	PreviousPolicies [][]byte
	PreviousControls [][]byte
	ObservationStore PublicationObservationStore
	Clock            func() time.Time
	RKey             string
}

type AttestationPublishResult struct {
	RKey       string
	RecordCID  string
	CommitCID  string
	Revision   *Revision
	Idempotent bool
}

var (
	ErrAttestationConflict    = errors.New("attestation record conflicts with its deterministic key")
	ErrAttestationNotLanded   = errors.New("attestation is absent from the verified repository revision")
	ErrAttestationUnavailable = errors.New("attestation publication could not be verified")
)

func PrepareAttestationRecordWrite(rkey string, signedBytes []byte) (RecordWrite, error) {
	attestation, err := vault.DecodeAttestation(signedBytes)
	if err != nil {
		return RecordWrite{}, fmt.Errorf("%w: attestation object", ErrBatchRejected)
	}
	if attestation.DeviceID != attestation.Signer.DeviceID {
		return RecordWrite{}, fmt.Errorf("%w: attestation subject does not match signer", ErrBatchRejected)
	}
	expectedRKey, err := AttestationRecordRKey(signedBytes)
	if err != nil {
		return RecordWrite{}, err
	}
	if rkey != expectedRKey {
		return RecordWrite{}, fmt.Errorf("%w: rkey differs from deterministic attestation key", ErrBatchRejected)
	}
	record, err := marshalRecord(attestationRecordFromVault(attestation))
	if err != nil {
		return RecordWrite{}, err
	}
	return RecordWrite{Action: RecordCreate, Collection: VaultAttestationNSID, RKey: rkey, Record: record}, nil
}

func PublishAttestationFenced(ctx context.Context, transport Transport, revision *Revision, rkey string, signedBytes []byte, verification vault.AttestationVerificationRequest) (PublishResult, error) {
	if transport == nil || revision == nil || !validDID(revision.did) || revision.commitCID == "" {
		return PublishResult{}, fmt.Errorf("%w: verified revision and transport are required", ErrBatchRejected)
	}
	if _, err := syntax.ParseCID(revision.commitCID); err != nil {
		return PublishResult{}, fmt.Errorf("%w: verified revision commit CID is invalid", ErrBatchRejected)
	}
	if _, err := vault.VerifyAttestation(signedBytes, verification); err != nil {
		return PublishResult{}, fmt.Errorf("%w: attestation signature or context", ErrBatchRejected)
	}
	if err := verifyAttestationContextRevision(revision, verification); err != nil {
		return PublishResult{}, fmt.Errorf("%w: attestation context is not present in the fenced revision: %w", ErrBatchRejected, err)
	}
	write, err := PrepareAttestationRecordWrite(rkey, signedBytes)
	if err != nil {
		return PublishResult{}, err
	}
	if write.Action != RecordCreate || write.Collection != VaultAttestationNSID || write.RKey == "" ||
		revision.HasRecord(RecordKey{Collection: VaultAttestationNSID, RKey: write.RKey}) {
		return PublishResult{}, fmt.Errorf("%w: attestation must create a new attestation record", ErrBatchRejected)
	}
	decoded, err := decodeRecordJSON(write.Record)
	attestationRecord, ok := decoded.(AttestationRecord)
	if err != nil || !ok || attestationRecord.DeviceID != attestationRecord.SignerDeviceID {
		return PublishResult{}, fmt.Errorf("%w: attestation record is malformed or has mismatched subject", ErrBatchRejected)
	}
	canonicalRecord, err := EncodeRecord(attestationRecord)
	if err != nil || VerifyRecordBinding(canonicalRecord, signedBytes) != nil ||
		verifyAttestationRecordContext(canonicalRecord, verification) != nil {
		return PublishResult{}, fmt.Errorf("%w: attestation record binding or context", ErrBatchRejected)
	}
	if _, err := VerifyAttestationRecord(canonicalRecord, verification); err != nil {
		return PublishResult{}, fmt.Errorf("%w: attestation record signature", ErrBatchRejected)
	}
	encoded, err := encodeRecordWrite(write)
	if err != nil {
		return PublishResult{}, err
	}
	body, err := json.Marshal(applyWritesInput{
		Repo: revision.did, SwapCommit: revision.commitCID, Writes: []json.RawMessage{encoded},
	})
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: could not encode applyWrites batch", ErrBatchRejected)
	}
	status, response, err := transport.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, body, "application/json")
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: applyWrites request outcome is unknown", ErrAmbiguousTransport)
	}
	if status >= 500 {
		return PublishResult{}, fmt.Errorf("%w: applyWrites returned HTTP %d", ErrAmbiguousTransport, status)
	}
	if status >= 400 && status < 500 {
		var remoteError applyWritesError
		if json.Unmarshal(response, &remoteError) == nil && remoteError.Error == "InvalidSwap" {
			return PublishResult{}, ErrFenceLost
		}
		return PublishResult{}, fmt.Errorf("%w: applyWrites returned HTTP %d", ErrBatchRejected, status)
	}
	if status < 200 || status >= 300 {
		return PublishResult{}, fmt.Errorf("%w: applyWrites returned HTTP %d", ErrAmbiguousTransport, status)
	}
	var output applyWritesOutput
	if len(response) != 0 {
		if err := json.Unmarshal(response, &output); err != nil {
			return PublishResult{}, fmt.Errorf("%w: applyWrites response is malformed after submission", ErrAmbiguousTransport)
		}
	}
	return PublishResult{CommitCID: output.Commit.CID}, nil
}

func RelayAttestation(ctx context.Context, committer AttestationRelayCommitter, revision *Revision, signedBytes []byte, verification vault.AttestationVerificationRequest) error {
	if committer == nil || revision == nil || len(signedBytes) == 0 {
		return fmt.Errorf("%w: attestation relay requires signed bytes, target revision, and committer", ErrBatchRejected)
	}
	if _, err := vault.VerifyAttestation(signedBytes, verification); err != nil {
		return fmt.Errorf("%w: attestation signature or context", ErrBatchRejected)
	}
	return committer.CommitAttestation(ctx, revision, bytes.Clone(signedBytes))
}

func (relay ATProtoAttestationRelay) CommitAttestation(ctx context.Context, revision *Revision, signedBytes []byte) error {
	if revision == nil || relay.DID == "" || revision.DID() != relay.DID {
		return fmt.Errorf("%w: relay revision and repository DID must match", ErrBatchRejected)
	}
	attestation, err := vault.DecodeAttestation(signedBytes)
	if err != nil {
		return fmt.Errorf("%w: attestation object", ErrBatchRejected)
	}
	rkey, err := AttestationRecordRKey(signedBytes)
	if err != nil {
		return err
	}
	if relay.RKey != "" && relay.RKey != rkey {
		return fmt.Errorf("%w: relay rkey differs from deterministic attestation key", ErrBatchRejected)
	}
	result, err := PublishAttestation(ctx, ATProtoPublicationIO{
		Reader: relay.Reader, Transport: relay.Transport, DID: relay.DID, TrustAnchor: relay.TrustAnchor,
		PreviousPolicies: relay.PreviousPolicies, PreviousControls: relay.PreviousControls,
		ObservationStore: relay.ObservationStore, Clock: relay.Clock,
	}, attestation.DeviceID, attestation.Signer.KeyID, signedBytes)
	if err != nil {
		return err
	}
	if result.RKey != rkey {
		return fmt.Errorf("%w: relay result differs from deterministic attestation key", ErrAttestationConflict)
	}
	return nil
}

func VerifyAttestationRecord(recordBytes []byte, request vault.AttestationVerificationRequest) (vault.AttestationJudgement, error) {
	decoded, err := DecodeRecord(recordBytes)
	if err != nil {
		return vault.AttestationJudgement{}, err
	}
	record, ok := decoded.(AttestationRecord)
	if !ok {
		return vault.AttestationJudgement{}, &RecordDecodeError{Field: "$type", Reason: "not an attestation record"}
	}
	if record.DeviceID != record.SignerDeviceID {
		return vault.AttestationJudgement{}, fmt.Errorf("%w: attestation subject does not match signer", vault.ErrAuthorization)
	}
	attestation := vault.Attestation{
		SchemaVersion: uint8(record.SchemaVersion), Vault: [32]byte(record.Vault), DeviceID: record.DeviceID,
		PolicyDigest: [32]byte(record.PolicyDigest), RetentionFloor: record.RetentionFloor,
		RetainedRecoveryPoints: record.RetainedRecoveryPoints, ControlCID: bytes.Clone(record.ControlCID),
		Signer:    vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)},
		Signature: [ed25519.SignatureSize]byte(record.Signature),
	}
	attestation.RecoveryPoints = make([]vault.RetentionRecoveryPoint, len(record.RecoveryPoints))
	for index, point := range record.RecoveryPoints {
		attestation.RecoveryPoints[index] = vault.RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)}
	}
	encoded, err := vault.EncodeAttestation(attestation)
	if err != nil {
		return vault.AttestationJudgement{}, err
	}
	return vault.VerifyAttestation(encoded, request)
}

func AttestationRecordRKey(signedBytes []byte) (string, error) {
	attestation, err := vault.DecodeAttestation(signedBytes)
	if err != nil {
		return "", fmt.Errorf("%w: attestation object", ErrBatchRejected)
	}
	if attestation.DeviceID != attestation.Signer.DeviceID || len(attestation.ControlCID) == 0 {
		return "", fmt.Errorf("%w: attestation subject or control context", ErrBatchRejected)
	}
	var input bytes.Buffer
	input.Write(attestation.Vault[:])
	_ = binary.Write(&input, binary.BigEndian, uint16(len(attestation.DeviceID)))
	input.WriteString(attestation.DeviceID)
	_ = binary.Write(&input, binary.BigEndian, uint16(len(attestation.ControlCID)))
	input.Write(attestation.ControlCID)
	digest := sha256.Sum256(input.Bytes())
	return "attest-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])), nil
}

func PublishAttestation(ctx context.Context, io ATProtoPublicationIO, localDeviceID string, localKeyID, signedBytes []byte) (AttestationPublishResult, error) {
	if io.Transport == nil || io.Reader.Transport == nil || io.DID == "" || localDeviceID == "" || len(localKeyID) == 0 || len(signedBytes) == 0 {
		return AttestationPublishResult{}, fmt.Errorf("%w: attestation publication inputs are required", ErrBatchRejected)
	}
	revision, predecessor, err := io.ReadCurrent(ctx)
	if err != nil {
		return AttestationPublishResult{}, fmt.Errorf("%w: %w", ErrAttestationUnavailable, err)
	}
	verification, err := attestationVerificationForPredecessor(predecessor)
	if err != nil {
		return AttestationPublishResult{}, fmt.Errorf("%w: verified attestation context: %w", ErrBatchRejected, err)
	}
	attestation, err := vault.DecodeAttestation(signedBytes)
	if err != nil {
		return AttestationPublishResult{}, fmt.Errorf("%w: attestation object", ErrBatchRejected)
	}
	if attestation.DeviceID != localDeviceID || attestation.Signer.DeviceID != localDeviceID || !bytes.Equal(attestation.Signer.KeyID, localKeyID) {
		return AttestationPublishResult{}, fmt.Errorf("%w: attestation is not signed for the selected local device", ErrBatchRejected)
	}
	if _, err := vault.VerifyAttestation(signedBytes, verification); err != nil {
		return AttestationPublishResult{}, fmt.Errorf("%w: attestation signature or context", ErrBatchRejected)
	}
	rkey, err := AttestationRecordRKey(signedBytes)
	if err != nil {
		return AttestationPublishResult{}, err
	}
	write, err := PrepareAttestationRecordWrite(rkey, signedBytes)
	if err != nil {
		return AttestationPublishResult{}, err
	}
	expectedRecordCID, err := recordCIDText(write.Record)
	if err != nil {
		return AttestationPublishResult{}, err
	}
	key := RecordKey{Collection: VaultAttestationNSID, RKey: rkey}
	if revision.HasRecord(key) {
		result, verifyErr := verifyPublishedAttestation(revision, key, expectedRecordCID, write.Record, signedBytes, verification)
		if verifyErr != nil {
			return AttestationPublishResult{}, errors.Join(ErrAttestationConflict, verifyErr)
		}
		result.Idempotent = true
		return result, nil
	}
	_, publishErr := PublishAttestationFenced(ctx, io.Transport, revision, rkey, signedBytes, verification)
	readBack, _, readErr := io.ReadCurrent(ctx)
	if readErr != nil {
		return AttestationPublishResult{}, errors.Join(ErrAttestationUnavailable, publishErr, readErr)
	}
	result, verifyErr := verifyPublishedAttestation(readBack, key, expectedRecordCID, write.Record, signedBytes, verification)
	if verifyErr == nil {
		result.CommitCID = readBack.CommitCID()
		return result, nil
	}
	if publishErr != nil {
		return AttestationPublishResult{}, errors.Join(publishErr, ErrAttestationNotLanded, verifyErr)
	}
	return AttestationPublishResult{}, errors.Join(ErrAttestationNotLanded, verifyErr)
}

func attestationVerificationForPredecessor(predecessor vault.Predecessor) (vault.AttestationVerificationRequest, error) {
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil {
		return vault.AttestationVerificationRequest{}, err
	}
	if _, err := vault.DecodeControl(predecessor.Control); err != nil {
		return vault.AttestationVerificationRequest{}, err
	}
	return vault.AttestationVerificationRequest{
		VaultID: policy.Vault, TrustAnchor: predecessor.TrustAnchor,
		State: vault.ControlEvidence{Policy: bytes.Clone(predecessor.Policy), Control: bytes.Clone(predecessor.Control), Certificates: predecessor.Certificates},
	}, nil
}

func verifyPublishedAttestation(revision *Revision, key RecordKey, expectedCID string, expectedJSON, signedBytes []byte, verification vault.AttestationVerificationRequest) (AttestationPublishResult, error) {
	if revision == nil {
		return AttestationPublishResult{}, ErrUnprovenMembership
	}
	membership := revision.Membership()
	proven, hasRecord := revision.Records()[key]
	if !hasRecord || membership[key] == "" || membership[key] != expectedCID || proven.CID != expectedCID {
		return AttestationPublishResult{}, ErrUnprovenMembership
	}
	decoded, err := decodeRecordJSON(expectedJSON)
	if err != nil {
		return AttestationPublishResult{}, err
	}
	canonical, err := EncodeRecord(decoded)
	if err != nil || !bytes.Equal(proven.Data, canonical) {
		return AttestationPublishResult{}, ErrAttestationConflict
	}
	if err := VerifyRecordBinding(proven.Data, signedBytes); err != nil {
		return AttestationPublishResult{}, err
	}
	if err := verifyAttestationRecordContext(proven.Data, verification); err != nil {
		return AttestationPublishResult{}, err
	}
	if _, err := VerifyAttestationRecord(proven.Data, verification); err != nil {
		return AttestationPublishResult{}, err
	}
	return AttestationPublishResult{RKey: key.RKey, RecordCID: expectedCID, CommitCID: revision.CommitCID(), Revision: revision}, nil
}

func verifyAttestationRecordContext(recordBytes []byte, verification vault.AttestationVerificationRequest) error {
	policyRecord, controlRecord, err := attestationContextRecordBytes(verification)
	if err != nil {
		return err
	}
	return VerifyRecordContext(recordBytes, RecordContext{
		Policy: policyRecord, Control: controlRecord, TrustAnchor: verification.TrustAnchor,
	})
}

func verifyAttestationContextRevision(revision *Revision, verification vault.AttestationVerificationRequest) error {
	policyRecord, controlRecord, err := attestationContextRecordBytes(verification)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		key  RecordKey
		data []byte
	}{
		{key: RecordKey{Collection: VaultPolicyNSID, RKey: "self"}, data: policyRecord},
		{key: RecordKey{Collection: VaultControlNSID, RKey: "self"}, data: controlRecord},
	} {
		membership := revision.Membership()[entry.key]
		proven, exists := revision.Records()[entry.key]
		if !exists || membership == "" || proven.CID != membership {
			return ErrUnprovenMembership
		}
		encodedCID, err := recordCID(entry.data)
		if err != nil {
			return ErrUnprovenMembership
		}
		parsedCID, err := cid.Cast(encodedCID)
		if err != nil || parsedCID.String() != membership || !bytes.Equal(proven.Data, entry.data) {
			return ErrBatchRejected
		}
	}
	return nil
}

func attestationContextRecordBytes(verification vault.AttestationVerificationRequest) ([]byte, []byte, error) {
	policy, err := vault.DecodePolicy(verification.State.Policy)
	if err != nil {
		return nil, nil, err
	}
	control, err := vault.DecodeControl(verification.State.Control)
	if err != nil {
		return nil, nil, err
	}
	policyRecord, err := EncodeRecord(toPolicyRecord(policy))
	if err != nil {
		return nil, nil, err
	}
	controlRecord, err := EncodeRecord(toControlRecord(control))
	if err != nil {
		return nil, nil, err
	}
	return policyRecord, controlRecord, nil
}

func attestationRecordFromVault(value vault.Attestation) AttestationRecord {
	record := AttestationRecord{
		SchemaVersion: int64(value.SchemaVersion), Vault: bytes.Clone(value.Vault[:]), DeviceID: value.DeviceID,
		PolicyDigest: bytes.Clone(value.PolicyDigest[:]), RetentionFloor: value.RetentionFloor,
		RetainedRecoveryPoints: value.RetainedRecoveryPoints, ControlCID: bytes.Clone(value.ControlCID),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID),
		Signature: bytes.Clone(value.Signature[:]),
	}
	if value.SchemaVersion == 0 {
		if len(value.RecoveryPoints) == 0 {
			record.SchemaVersion = 1
		} else {
			record.SchemaVersion = 2
		}
	}
	record.RecoveryPoints = make([]AttestationRecoveryPointRecord, len(value.RecoveryPoints))
	for index, point := range value.RecoveryPoints {
		record.RecoveryPoints[index] = AttestationRecoveryPointRecord{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)}
	}
	return record
}
