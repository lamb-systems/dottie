package atproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/lamb-systems/dottie/internal/vault"
)

type AttestationRelayCommitter interface {
	CommitAttestation(context.Context, *Revision, []byte) error
}

type ATProtoAttestationRelay struct {
	Transport Transport
	RKey      string
}

func PrepareAttestationRecordWrite(rkey string, signedBytes []byte) (RecordWrite, error) {
	attestation, err := vault.DecodeAttestation(signedBytes)
	if err != nil {
		return RecordWrite{}, fmt.Errorf("%w: attestation object", ErrBatchRejected)
	}
	record, err := marshalRecord(attestationRecordFromVault(attestation))
	if err != nil {
		return RecordWrite{}, err
	}
	return RecordWrite{Action: RecordCreate, Collection: VaultAttestationNSID, RKey: rkey, Record: record}, nil
}

func PublishAttestationFenced(ctx context.Context, transport Transport, revision *Revision, rkey string, signedBytes []byte) (PublishResult, error) {
	if transport == nil || revision == nil || !validDID(revision.did) || revision.commitCID == "" {
		return PublishResult{}, fmt.Errorf("%w: verified revision and transport are required", ErrBatchRejected)
	}
	if _, err := syntax.ParseCID(revision.commitCID); err != nil {
		return PublishResult{}, fmt.Errorf("%w: verified revision commit CID is invalid", ErrBatchRejected)
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
	attestation, ok := decoded.(AttestationRecord)
	if err != nil || !ok || attestation.DeviceID != attestation.SignerDeviceID {
		return PublishResult{}, fmt.Errorf("%w: attestation record is malformed or has mismatched subject", ErrBatchRejected)
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

func RelayAttestation(ctx context.Context, committer AttestationRelayCommitter, revision *Revision, signedBytes []byte) error {
	if committer == nil || revision == nil || len(signedBytes) == 0 {
		return fmt.Errorf("%w: attestation relay requires signed bytes, target revision, and committer", ErrBatchRejected)
	}
	if _, err := vault.DecodeAttestation(signedBytes); err != nil {
		return fmt.Errorf("%w: attestation object", ErrBatchRejected)
	}
	return committer.CommitAttestation(ctx, revision, bytes.Clone(signedBytes))
}

func (relay ATProtoAttestationRelay) CommitAttestation(ctx context.Context, revision *Revision, signedBytes []byte) error {
	_, err := PublishAttestationFenced(ctx, relay.Transport, revision, relay.RKey, signedBytes)
	return err
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
		Vault: [32]byte(record.Vault), DeviceID: record.DeviceID, PolicyDigest: [32]byte(record.PolicyDigest),
		RetentionFloor: record.RetentionFloor, RetainedRecoveryPoints: record.RetainedRecoveryPoints,
		ControlCID: bytes.Clone(record.ControlCID),
		Signer:     vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)},
		Signature:  [ed25519.SignatureSize]byte(record.Signature),
	}
	encoded, err := vault.EncodeAttestation(attestation)
	if err != nil {
		return vault.AttestationJudgement{}, err
	}
	return vault.VerifyAttestation(encoded, request)
}

func attestationRecordFromVault(value vault.Attestation) AttestationRecord {
	return AttestationRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), DeviceID: value.DeviceID,
		PolicyDigest: bytes.Clone(value.PolicyDigest[:]), RetentionFloor: value.RetentionFloor,
		RetainedRecoveryPoints: value.RetainedRecoveryPoints, ControlCID: bytes.Clone(value.ControlCID),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID),
		Signature: bytes.Clone(value.Signature[:]),
	}
}
