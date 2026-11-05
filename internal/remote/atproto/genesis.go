package atproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/vault"
)

var (
	ErrGenesisRepositoryNotEmpty = errors.New("genesis requires an empty verified repository")
	ErrGenesisUnavailable        = errors.New("genesis outcome could not be verified")
	ErrGenesisNotLanded          = errors.New("genesis records are absent from the latest verified repository revision")
	ErrGenesisRecordMismatch     = errors.New("genesis repository records do not match the prepared set")
	ErrGenesisCheckpointMismatch = errors.New("genesis checkpoint membership or binding does not match")
	ErrGenesisReadbackRejected   = errors.New("genesis read-back did not authenticate the prepared position")
	ErrGenesisCandidateStage     = errors.New("genesis snapshot candidate could not be staged")
)

type GenesisIO struct {
	Reader           RevisionReader
	Transport        Transport
	BlobUploadLimit  int64
	DID              string
	ObservationStore PublicationObservationStore
	Clock            func() time.Time
}

type GenesisPhase string

const (
	GenesisNotSubmitted       GenesisPhase = "not-submitted"
	GenesisSubmitted          GenesisPhase = "submitted"
	GenesisMembershipVerified GenesisPhase = "membership-verified"
	GenesisVerified           GenesisPhase = "verified"
)

type GenesisRecordTarget struct {
	Collection string
	RKey       string
	CID        string
}

type GenesisCommitResult struct {
	Phase         GenesisPhase
	RecordTargets []GenesisRecordTarget
	Revision      *Revision
	ReadResult    ReadResult
	CommitCID     string
	CheckpointCID string
}

type genesisExpectedRecord struct {
	data   []byte
	cid    string
	object []byte
}

func CheckGenesisRepositoryEmpty(ctx context.Context, reader RevisionReader, transport Transport, did string) error {
	if transport == nil || did == "" || !validDID(did) || reader.DIDDocumentID != did {
		return fmt.Errorf("%w: authenticated revision reader and DID are required", ErrBatchRejected)
	}
	reader.Transport = transport
	revision, err := reader.Read(ctx, did)
	if err != nil {
		return fmt.Errorf("%w: cannot verify empty genesis repository: %w", ErrGenesisUnavailable, err)
	}
	if len(revision.Membership()) != 0 {
		return ErrGenesisRepositoryNotEmpty
	}
	return nil
}

func CommitGenesis(ctx context.Context, io GenesisIO, kit []byte, root vault.DeviceMaterial, genesis vault.Genesis) (GenesisCommitResult, error) {
	result := GenesisCommitResult{Phase: GenesisNotSubmitted}
	if io.Transport == nil || io.DID == "" || io.BlobUploadLimit <= 0 || io.ObservationStore == nil || root.Recipient == nil || len(root.Signing) != ed25519.PrivateKeySize {
		return result, fmt.Errorf("%w: genesis transport, DID, blob limit, observation store and root device are required", ErrBatchRejected)
	}
	if err := vault.ValidateGenesis(genesis, kit); err != nil {
		return result, fmt.Errorf("%w: %w", ErrBatchRejected, err)
	}
	certificate, err := vault.DecodeCertificate(genesis.Certificate)
	if err != nil || certificate.DeviceID != root.DeviceID || !bytes.Equal(certificate.KeyID, root.KeyID) || !bytes.Equal(certificate.SigningPublicKey[:], root.Signing.Public().(ed25519.PublicKey)) || !bytes.Equal(certificate.EncryptionPublicKey[:], root.Recipient.PublicKey().Bytes()) {
		return result, fmt.Errorf("%w: root device does not match genesis certificate", ErrBatchRejected)
	}
	reader := io.Reader
	reader.Transport = io.Transport
	if reader.DIDDocumentID != io.DID || !validDID(io.DID) {
		return result, fmt.Errorf("%w: revision reader DID binding is invalid", ErrBatchRejected)
	}
	initial, err := reader.Read(ctx, io.DID)
	if err != nil {
		return result, fmt.Errorf("%w: cannot verify empty genesis predecessor: %w", ErrGenesisUnavailable, err)
	}
	if len(initial.Membership()) != 0 {
		return result, ErrGenesisRepositoryNotEmpty
	}
	policy, err := vault.DecodePolicy(genesis.Policy)
	if err != nil {
		return result, fmt.Errorf("%w: genesis policy is invalid", ErrBatchRejected)
	}
	blobReference, uploadedCID, err := (ATProtoTransitionIO{Transport: io.Transport, BlobUploadLimit: io.BlobUploadLimit}).StageCandidate(ctx, genesis.Snapshot, policy, [][]byte{genesis.Certificate})
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrGenesisCandidateStage, err)
	}
	if uploadedCID != cid.NewCidV1(cid.Raw, mustTransitionMultihash(genesis.Snapshot)).String() {
		return result, fmt.Errorf("%w: uploaded genesis snapshot CID differs from the sealed snapshot", ErrBatchRejected)
	}
	publication, expected, err := genesisPublication(genesis, root.Signing, blobReference, initial)
	if err != nil {
		return result, err
	}
	result.RecordTargets = genesisTargets(expected)
	fencedResult, publishErr := publishFenced(ctx, io.Transport, initial, publication)
	if fencedResult.Submitted {
		result.Phase = GenesisSubmitted
	}
	if publishErr != nil && errors.Is(publishErr, ErrBatchRejected) {
		return result, publishErr
	}
	var verified *Revision
	var readErr error
	for attempt := 0; attempt < 3; attempt++ {
		verified, readErr = reader.Read(ctx, io.DID)
		if readErr == nil {
			break
		}
		if attempt < 2 {
			if err := waitGenesisRead(ctx, time.Duration(attempt+1)*10*time.Millisecond); err != nil {
				return result, fmt.Errorf("%w: verified genesis read-back failed: %w", ErrGenesisUnavailable, err)
			}
		}
	}
	if readErr != nil {
		return result, fmt.Errorf("%w: verified genesis read-back failed after retries: %w", ErrGenesisUnavailable, readErr)
	}
	result.Revision = verified
	if err := verifyGenesisRevision(verified, expected, genesis, kit); err != nil {
		return result, err
	}
	result.Phase = GenesisMembershipVerified
	for attempt := 0; attempt < 3; attempt++ {
		readResult, readErr := (VaultReader{
			Transport: io.Transport, ObservationStore: io.ObservationStore,
			Budgets: reader.Budgets, Clock: io.Clock,
		}).Read(ctx, ReadRequest{
			DID: io.DID, DIDDocumentID: reader.DIDDocumentID, VerificationMethods: reader.VerificationMethods,
			Vault: genesis.Vault, TrustAnchor: genesis.Anchor, DeviceKeyID: bytes.Clone(root.KeyID), DeviceKey: root.Recipient,
		})
		if readErr == nil {
			if verifyErr := verifyGenesisRevision(readResult.Revision, expected, genesis, kit); verifyErr != nil {
				return result, verifyErr
			}
			packed, packErr := vault.Pack(model.Snapshot{Version: model.SnapshotVersion})
			if packErr != nil || !bytes.Equal(readResult.Plaintext, packed.Payload) {
				return result, fmt.Errorf("%w: decrypted genesis snapshot is not the canonical empty snapshot", ErrGenesisReadbackRejected)
			}
			result.ReadResult = readResult
			result.Revision = readResult.Revision
			result.CommitCID = readResult.Revision.CommitCID()
			result.CheckpointCID = expectedRecordCID(expected, RecordKey{Collection: VaultCheckpointNSID, RKey: "self"})
			result.Phase = GenesisVerified
			return result, nil
		}
		if attempt == 2 {
			if errors.Is(readErr, ErrAmbiguousTransport) || errors.Is(readErr, ErrRevisionMoving) {
				return result, fmt.Errorf("%w: real vault read-back failed after retries: %w", ErrGenesisUnavailable, readErr)
			}
			return result, fmt.Errorf("%w: real vault read-back failed after retries: %w", ErrGenesisReadbackRejected, readErr)
		}
		if err := waitGenesisRead(ctx, time.Duration(attempt+1)*10*time.Millisecond); err != nil {
			return result, fmt.Errorf("%w: real vault read-back failed: %w", ErrGenesisUnavailable, err)
		}
	}
	return result, ErrGenesisUnavailable
}

func waitGenesisRead(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func genesisTargets(expected map[RecordKey]genesisExpectedRecord) []GenesisRecordTarget {
	targets := make([]GenesisRecordTarget, 0, len(expected))
	for key, record := range expected {
		targets = append(targets, GenesisRecordTarget{Collection: key.Collection, RKey: key.RKey, CID: record.cid})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Collection != targets[j].Collection {
			return targets[i].Collection < targets[j].Collection
		}
		return targets[i].RKey < targets[j].RKey
	})
	return targets
}

func genesisPublication(genesis vault.Genesis, signer ed25519.PrivateKey, blobReference []byte, revision *Revision) (FencedPublication, map[RecordKey]genesisExpectedRecord, error) {
	if revision == nil || len(signer) != ed25519.PrivateKeySize {
		return FencedPublication{}, nil, fmt.Errorf("%w: verified empty revision and root signer are required", ErrBatchRejected)
	}
	var blob atdata.Blob
	if err := json.Unmarshal(blobReference, &blob); err != nil || !blob.Ref.IsDefined() || blob.MimeType != "application/octet-stream" || blob.Size != int64(len(genesis.Snapshot)) || !bytes.Equal(blob.Ref.CID().Bytes(), genesis.SnapshotCID) {
		return FencedPublication{}, nil, fmt.Errorf("%w: uploaded genesis blob reference is invalid", ErrBatchRejected)
	}
	policy, err := vault.DecodePolicy(genesis.Policy)
	if err != nil {
		return FencedPublication{}, nil, fmt.Errorf("%w: genesis policy", ErrBatchRejected)
	}
	control, err := vault.DecodeControl(genesis.Control)
	if err != nil {
		return FencedPublication{}, nil, fmt.Errorf("%w: genesis control", ErrBatchRejected)
	}
	certificate, err := vault.DecodeCertificate(genesis.Certificate)
	if err != nil {
		return FencedPublication{}, nil, fmt.Errorf("%w: genesis certificate", ErrBatchRejected)
	}
	checkpoint, err := vault.DecodeCheckpoint(genesis.Checkpoint)
	if err != nil {
		return FencedPublication{}, nil, fmt.Errorf("%w: genesis checkpoint", ErrBatchRejected)
	}
	head, err := vault.DecodeHead(genesis.Head)
	if err != nil {
		return FencedPublication{}, nil, fmt.Errorf("%w: genesis head", ErrBatchRejected)
	}
	envelope, err := vault.DecodeEnvelope(genesis.Snapshot)
	if err != nil {
		return FencedPublication{}, nil, fmt.Errorf("%w: genesis snapshot", ErrBatchRejected)
	}
	envelopeSignatureDigest := sha256.Sum256(envelope.Signature[:])
	snapshot := SnapshotRecord{
		SchemaVersion: 1, Vault: bytes.Clone(envelope.Vault[:]), PublicationID: bytes.Clone(envelope.PublicationID[:]),
		EpochSeq: envelope.EpochSeq, PolicyDigest: bytes.Clone(envelope.PolicyDigest[:]), Parent: bytes.Clone(envelope.Parent),
		Blob: blob, SignerDeviceID: envelope.DeviceID, SignerKeyID: bytes.Clone(envelope.KeyID),
		EnvelopeSignatureDigest: bytes.Clone(envelopeSignatureDigest[:]), Signature: make([]byte, ed25519.SignatureSize),
	}
	snapshot, err = SignSnapshotRecord(snapshot, signer)
	if err != nil {
		return FencedPublication{}, nil, fmt.Errorf("%w: sign genesis snapshot record", ErrBatchRejected)
	}
	snapshotJSON, err := marshalRecord(snapshot)
	if err != nil {
		return FencedPublication{}, nil, err
	}
	policyJSON, err := marshalRecord(toPolicyRecord(policy))
	if err != nil {
		return FencedPublication{}, nil, err
	}
	controlJSON, err := marshalRecord(toControlRecord(control))
	if err != nil {
		return FencedPublication{}, nil, err
	}
	certificateJSON, err := marshalRecord(toCertificateRecord(certificate))
	if err != nil {
		return FencedPublication{}, nil, err
	}
	checkpointJSON, err := marshalRecord(CheckpointRecord{
		SchemaVersion: 1, Vault: bytes.Clone(checkpoint.Vault[:]), SnapshotCID: bytes.Clone(checkpoint.SnapshotCID),
		EpochSeq: checkpoint.EpochSeq, PolicyDigest: bytes.Clone(checkpoint.PolicyDigest[:]), Anchor: bytes.Clone(checkpoint.Anchor[:]),
		ControlCID: bytes.Clone(checkpoint.ControlCID), SignerDeviceID: checkpoint.Signer.DeviceID,
		SignerKeyID: bytes.Clone(checkpoint.Signer.KeyID), Signature: bytes.Clone(checkpoint.Signature[:]),
	})
	if err != nil {
		return FencedPublication{}, nil, err
	}
	headJSON, err := marshalRecord(toHeadRecord(head))
	if err != nil {
		return FencedPublication{}, nil, err
	}
	marker := genesisSnapshotRKey(envelope.PublicationID)
	publication := FencedPublication{
		FirstBlobReference: RecordWrite{Action: RecordCreate, Collection: VaultSnapshotNSID, RKey: marker, Record: snapshotJSON},
		VaultHead:          RecordWrite{Action: RecordCreate, Collection: VaultHeadNSID, RKey: "self", Record: headJSON},
		VaultControl:       RecordWrite{Action: RecordCreate, Collection: VaultControlNSID, RKey: "self", Record: controlJSON},
		Additional: []RecordWrite{
			{Action: RecordCreate, Collection: VaultPolicyNSID, RKey: "self", Record: policyJSON},
			{Action: RecordCreate, Collection: VaultCertificateNSID, RKey: transitionCertificateRKey(certificate), Record: certificateJSON},
			{Action: RecordCreate, Collection: VaultCheckpointNSID, RKey: "self", Record: checkpointJSON},
		},
	}
	writes := []RecordWrite{publication.FirstBlobReference, publication.VaultHead, publication.VaultControl}
	writes = append(writes, publication.Additional...)
	for _, write := range writes {
		if write.Action != RecordCreate || revision.HasRecord(RecordKey{Collection: write.Collection, RKey: write.RKey}) {
			return FencedPublication{}, nil, fmt.Errorf("%w: genesis write set must contain creates over an empty repository", ErrGenesisRepositoryNotEmpty)
		}
	}
	objects := map[RecordKey][]byte{
		{Collection: VaultSnapshotNSID, RKey: marker}:                                    genesis.Snapshot,
		{Collection: VaultHeadNSID, RKey: "self"}:                                        genesis.Head,
		{Collection: VaultControlNSID, RKey: "self"}:                                     genesis.Control,
		{Collection: VaultPolicyNSID, RKey: "self"}:                                      genesis.Policy,
		{Collection: VaultCertificateNSID, RKey: transitionCertificateRKey(certificate)}: genesis.Certificate,
		{Collection: VaultCheckpointNSID, RKey: "self"}:                                  genesis.Checkpoint,
	}
	expected := make(map[RecordKey]genesisExpectedRecord, 6)
	for _, write := range writes {
		key := RecordKey{Collection: write.Collection, RKey: write.RKey}
		recordCID, err := recordCIDText(write.Record)
		if err != nil {
			return FencedPublication{}, nil, err
		}
		recordData, err := recordDAGCBOR(write.Record)
		if err != nil {
			return FencedPublication{}, nil, err
		}
		if _, duplicate := expected[key]; duplicate {
			return FencedPublication{}, nil, fmt.Errorf("%w: duplicate genesis record target", ErrBatchRejected)
		}
		expected[key] = genesisExpectedRecord{data: recordData, cid: recordCID, object: bytes.Clone(objects[key])}
	}
	if len(expected) != 6 {
		return FencedPublication{}, nil, fmt.Errorf("%w: genesis write set is incomplete", ErrBatchRejected)
	}
	return publication, expected, nil
}

func verifyGenesisRevision(revision *Revision, expected map[RecordKey]genesisExpectedRecord, genesis vault.Genesis, kit []byte) error {
	if revision == nil {
		return fmt.Errorf("%w: verified revision is missing", ErrGenesisUnavailable)
	}
	hasExpectedRecord := false
	for key := range expected {
		if _, present := revision.membership[key]; present {
			hasExpectedRecord = true
			break
		}
	}
	if !hasExpectedRecord {
		return ErrGenesisNotLanded
	}
	checkpointKey := RecordKey{Collection: VaultCheckpointNSID, RKey: "self"}
	checkpointExpected, checkpointExists := expected[checkpointKey]
	if !checkpointExists || revision.membership[checkpointKey] != checkpointExpected.cid {
		return ErrGenesisCheckpointMismatch
	}
	anchor, err := vault.RecoveryKitCheckpointAnchor(kit, genesis.Vault, genesis.Checkpoint)
	checkpoint, decodeErr := vault.DecodeCheckpoint(genesis.Checkpoint)
	controlCID := rawTransitionCID(genesis.Control)
	if err != nil || decodeErr != nil || anchor != genesis.Anchor || checkpoint.Vault != genesis.Vault || checkpoint.EpochSeq != 0 || checkpoint.PolicyDigest != genesis.PolicyDigest || !bytes.Equal(checkpoint.ControlCID, controlCID) || !bytes.Equal(checkpoint.SnapshotCID, genesis.SnapshotCID) {
		return ErrGenesisCheckpointMismatch
	}
	for key, wanted := range expected {
		actualCID, present := revision.membership[key]
		if !present {
			if key == checkpointKey {
				return ErrGenesisCheckpointMismatch
			}
			return ErrGenesisNotLanded
		}
		if actualCID != wanted.cid {
			if key == checkpointKey {
				return ErrGenesisCheckpointMismatch
			}
			return ErrGenesisRecordMismatch
		}
		proven, exists := revision.records[key]
		if !exists || proven.CID != wanted.cid || !bytes.Equal(proven.Data, wanted.data) || len(wanted.object) == 0 || VerifyRecordBinding(proven.Data, wanted.object) != nil {
			return ErrGenesisRecordMismatch
		}
	}
	if len(revision.membership) != len(expected) {
		return ErrGenesisRecordMismatch
	}
	return nil
}

func expectedRecordCID(expected map[RecordKey]genesisExpectedRecord, key RecordKey) string {
	return expected[key].cid
}

func genesisSnapshotRKey(publicationID [16]byte) string {
	return "genesis-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicationID[:]))
}

func recordDAGCBOR(encodedJSON []byte) ([]byte, error) {
	object, err := atdata.UnmarshalJSON(encodedJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: decode AT Protocol record JSON", ErrBatchRejected)
	}
	encoded, err := atdata.MarshalCBOR(normalizeRecordMap(object))
	if err != nil {
		return nil, fmt.Errorf("%w: encode AT Protocol record DAG-CBOR", ErrBatchRejected)
	}
	return encoded, nil
}
