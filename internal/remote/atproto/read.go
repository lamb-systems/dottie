package atproto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const readAttempts = 3

var (
	ErrReadRecordMissing               = errors.New("required vault record is missing")
	ErrReadRecordType                  = errors.New("vault record has an unexpected type")
	ErrReadRecordInvalid               = errors.New("vault record is invalid")
	ErrReadSnapshotAmbiguous           = errors.New("multiple snapshot records match the head")
	ErrReadRecordBinding               = errors.New("vault record binding failed")
	ErrReadRecordContext               = errors.New("vault record context failed")
	ErrReadRecordSignature             = errors.New("vault snapshot record signature failed")
	ErrReadEnvelopeInvalid             = errors.New("snapshot envelope is invalid")
	ErrReadEnvelopeSignature           = errors.New("snapshot envelope signature failed")
	ErrReadBlobMissing                 = errors.New("snapshot blob is missing")
	ErrReadBlobTransport               = errors.New("snapshot blob transport failed")
	ErrReadBlobTooLarge                = errors.New("snapshot blob exceeds the read limit")
	ErrReadBlobTruncated               = errors.New("snapshot blob is truncated")
	ErrReadBlobSizeMismatch            = errors.New("snapshot blob size differs from its record")
	ErrReadBlobCIDMismatch             = errors.New("snapshot blob CID mismatch")
	ErrReadPreviousPolicyRequired      = errors.New("predecessor policy is required")
	ErrReadUnexpectedPrevious          = errors.New("predecessor policy is unexpected at genesis")
	ErrReadControlRequired             = errors.New("predecessor control is required")
	ErrReadControlType                 = errors.New("predecessor control record is invalid")
	ErrReadControlSignature            = errors.New("predecessor control signature failed")
	ErrReadControlSigner               = errors.New("predecessor control signer is invalid")
	ErrReadControlEpoch                = errors.New("predecessor control epoch is invalid")
	ErrReadControlPolicyDigest         = errors.New("predecessor control policy digest is invalid")
	ErrReadControlLinkage              = errors.New("control predecessor linkage is invalid")
	ErrPolicyAncestry                  = vault.ErrPolicyAncestry
	ErrReadVaultAuthentication         = errors.New("vault authentication failed")
	ErrReadHeadEnvelopeLinkage         = errors.New("head and envelope predecessor linkage disagree")
	ErrReadSignerMismatch              = errors.New("head and envelope signers disagree")
	ErrReadRecipientSet                = errors.New("envelope recipient set differs from policy")
	ErrReadDecryption                  = errors.New("snapshot decryption failed")
	ErrPublicationObservationRequired  = errors.New("durable publication observation store is required")
	ErrPublicationCountBackwards       = state.ErrVaultPublicationBackwards
	ErrPublicationCountGap             = state.ErrVaultPublicationGap
	ErrPublicationCountConflict        = state.ErrVaultPublicationConflict
	ErrVaultPublicationAncestry        = state.ErrPublicationAncestry
	ErrVaultPublicationControlAncestry = state.ErrVaultPublicationControlAncestry
)

type ReadStage string

const (
	ReadStageRevision          ReadStage = "revision"
	ReadStageRecord            ReadStage = "record"
	ReadStageRecordBinding     ReadStage = "record-binding"
	ReadStageRecordContext     ReadStage = "record-context"
	ReadStageBlob              ReadStage = "blob"
	ReadStageBlobCID           ReadStage = "blob-cid"
	ReadStageEnvelope          ReadStage = "envelope"
	ReadStageEnvelopeSignature ReadStage = "envelope-signature"
	ReadStageRecordSignature   ReadStage = "record-signature"
	ReadStageVaultAuth         ReadStage = "vault-authentication"
	ReadStageDecryption        ReadStage = "decryption"
)

type ReadError struct {
	Stage ReadStage
	Err   error
}

func (e *ReadError) Error() string {
	return fmt.Sprintf("vault read %s: %v", e.Stage, e.Err)
}

func (e *ReadError) Unwrap() error { return e.Err }

type FreshnessStatus string

const FreshnessUnverified FreshnessStatus = "freshness-unverified"

type ReadRequest struct {
	DID                 string
	DIDDocumentID       string
	VerificationMethods []VerificationMethod
	Vault               [32]byte
	TrustAnchor         [32]byte
	PreviousPolicy      []byte
	PreviousControl     []byte
	DeviceKeyID         []byte
	DeviceKey           *ecdh.PrivateKey
}

type ReadResult struct {
	Revision                 *Revision
	Policy                   PolicyRecord
	Control                  ControlRecord
	Head                     HeadRecord
	Snapshot                 SnapshotRecord
	Envelope                 vault.Envelope
	EnvelopeCID              string
	PublicationCount         uint64
	PublicationCountBaseline uint64
	HeadCID                  []byte
	ControlCID               []byte
	EpochSeq                 uint64
	Plaintext                []byte
	Ciphertext               []byte
	Freshness                FreshnessStatus
}

type VaultReader struct {
	Transport        Transport
	ObservationStore PublicationObservationStore
	Budgets          Budgets
	MaxBlobBytes     int64
	Clock            func() time.Time
}

type PublicationObservationStore interface {
	RecordVaultPublicationObservation(context.Context, state.VaultPublicationObservation) error
	VaultPublicationEpoch(context.Context, [32]byte) (uint64, bool, error)
	RecordVaultEpochFirstSeen(context.Context, [32]byte, uint64, int64) error
}

type PublicationCountOptions struct {
	MaxPublications uint64
	EnforceMaximum  bool
	PrevHeadCID     []byte
	ParentCID       []byte
	EnforceParent   bool
	FirstSeenAt     int64
	RecordFirstSeen bool
}

func CheckPublicationCount(ctx context.Context, store PublicationObservationStore, vaultID [32]byte, result ReadResult, options PublicationCountOptions) error {
	if options.EnforceMaximum && result.PublicationCount > options.MaxPublications {
		return vault.ErrPublicationCount
	}
	if store == nil {
		return ErrPublicationObservationRequired
	}
	if result.EpochSeq > uint64(^uint64(0)>>1) || result.PublicationCount > uint64(^uint64(0)>>1) || result.PublicationCount < result.PublicationCountBaseline {
		return ErrPublicationCountBackwards
	}
	if result.Head.PublicationCount != result.PublicationCount || result.Head.EpochSeq != result.EpochSeq || !bytes.Equal(result.Head.SnapshotCID, result.HeadCID) {
		return ErrReadVaultAuthentication
	}
	if result.PublicationCount == result.PublicationCountBaseline && !bytes.Equal(result.HeadCID, result.Control.HeadSnapshotCID) {
		return ErrReadVaultAuthentication
	}
	if _, err := cid.Cast(result.HeadCID); err != nil {
		return ErrReadVaultAuthentication
	}
	if _, err := cid.Cast(result.ControlCID); err != nil {
		return ErrReadVaultAuthentication
	}
	previousEpoch, hasPreviousEpoch, err := store.VaultPublicationEpoch(ctx, vaultID)
	if err != nil {
		return err
	}
	if err := store.RecordVaultPublicationObservation(ctx, state.VaultPublicationObservation{
		Vault: vaultID, Epoch: result.EpochSeq, PublicationCount: result.PublicationCount, HeadCID: bytes.Clone(result.HeadCID),
		ControlCID: bytes.Clone(result.ControlCID), PrevControlCID: bytes.Clone(result.Control.PrevControlCID),
		PrevHeadCID: bytes.Clone(options.PrevHeadCID), ParentCID: bytes.Clone(options.ParentCID), EnforceParent: options.EnforceParent,
	}); err != nil {
		return err
	}
	if options.RecordFirstSeen && (!hasPreviousEpoch || previousEpoch != result.EpochSeq) {
		return store.RecordVaultEpochFirstSeen(ctx, vaultID, result.EpochSeq, options.FirstSeenAt)
	}
	return nil
}

func currentTime(clock func() time.Time) time.Time {
	if clock != nil {
		return clock()
	}
	return time.Now()
}

type storedCertificate struct {
	recordBytes []byte
	objectBytes []byte
	object      vault.Certificate
}

func (r VaultReader) Read(ctx context.Context, request ReadRequest) (ReadResult, error) {
	if r.Transport == nil {
		return ReadResult{}, &ReadError{Stage: ReadStageRevision, Err: errors.New("transport is required")}
	}
	reader := RevisionReader{
		Transport: r.Transport, Budgets: r.Budgets,
		DIDDocumentID: request.DIDDocumentID, VerificationMethods: request.VerificationMethods,
	}
	for attempt := 0; attempt < readAttempts; attempt++ {
		revision, err := reader.Read(ctx, request.DID)
		if err != nil {
			return ReadResult{}, &ReadError{Stage: ReadStageRevision, Err: err}
		}
		result, readErr := r.readRevision(ctx, request, revision)
		latest, latestErr := reader.latest(ctx, request.DID)
		if latestErr != nil {
			return ReadResult{}, &ReadError{Stage: ReadStageRevision, Err: latestErr}
		}
		if latest.CID != revision.commitCID {
			continue
		}
		if readErr != nil {
			return ReadResult{}, readErr
		}
		result.Revision = revision
		result.Freshness = FreshnessUnverified
		if err := CheckPublicationCount(ctx, r.ObservationStore, request.Vault, result, PublicationCountOptions{
			MaxPublications: uint64(result.Policy.MaxPublications), EnforceMaximum: true,
			PrevHeadCID: result.Head.PrevHeadCID, ParentCID: result.Envelope.Parent, EnforceParent: true,
			FirstSeenAt: currentTime(r.Clock).Unix(), RecordFirstSeen: true,
		}); err != nil {
			return ReadResult{}, &ReadError{Stage: ReadStageVaultAuth, Err: err}
		}
		return result, nil
	}
	return ReadResult{}, &ReadError{Stage: ReadStageRevision, Err: ErrRevisionMoving}
}

func (r VaultReader) readRevision(ctx context.Context, request ReadRequest, revision *Revision) (ReadResult, error) {
	policyBytes, policyRecord, err := revisionRecord(revision, RecordKey{Collection: VaultPolicyNSID, RKey: "self"})
	if err != nil {
		return ReadResult{}, readRecordError(err)
	}
	policy, ok := policyRecord.(PolicyRecord)
	if !ok {
		return ReadResult{}, &ReadError{Stage: ReadStageRecord, Err: ErrReadRecordType}
	}
	policyObject, err := vault.EncodePolicy(policyFromRecord(policy))
	if err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageRecord, Err: err}
	}
	if err := VerifyRecordBinding(policyBytes, policyObject); err != nil {
		return ReadResult{}, readBindingError(err)
	}

	controlBytes, controlRecord, err := revisionRecord(revision, RecordKey{Collection: VaultControlNSID, RKey: "self"})
	if err != nil {
		return ReadResult{}, readRecordError(err)
	}
	control, ok := controlRecord.(ControlRecord)
	if !ok {
		return ReadResult{}, &ReadError{Stage: ReadStageRecord, Err: ErrReadRecordType}
	}
	controlObject, err := vault.EncodeControl(controlFromRecord(control))
	if err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageRecord, Err: err}
	}
	if err := VerifyRecordBinding(controlBytes, controlObject); err != nil {
		return ReadResult{}, readBindingError(err)
	}

	headBytes, headRecord, err := revisionRecord(revision, RecordKey{Collection: VaultHeadNSID, RKey: "self"})
	if err != nil {
		return ReadResult{}, readRecordError(err)
	}
	head, ok := headRecord.(HeadRecord)
	if !ok {
		return ReadResult{}, &ReadError{Stage: ReadStageRecord, Err: ErrReadRecordType}
	}
	headObject, err := vault.EncodeHead(headFromRecord(head))
	if err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageRecord, Err: err}
	}
	if err := VerifyRecordBinding(headBytes, headObject); err != nil {
		return ReadResult{}, readBindingError(err)
	}
	if len(head.SnapshotCID) == 0 {
		return ReadResult{}, &ReadError{Stage: ReadStageRecord, Err: ErrReadRecordMissing}
	}

	certificates, certificateRecords, err := loadCertificates(revision, request.Vault)
	if err != nil {
		return ReadResult{}, err
	}
	for _, certificate := range certificateRecords {
		if err := VerifyRecordBinding(certificate.recordBytes, certificate.objectBytes); err != nil {
			return ReadResult{}, readBindingError(err)
		}
	}

	snapshotBytes, snapshot, err := findSnapshotRecord(revision, head.SnapshotCID)
	if err != nil {
		return ReadResult{}, err
	}
	blob, err := r.fetchBlob(ctx, revision.did, cid.Cid(snapshot.Blob.Ref), snapshot.Blob.Size)
	if err != nil {
		return ReadResult{}, err
	}
	blobCID, err := rawBlobCID(blob)
	if err != nil || !bytes.Equal(blobCID, cid.Cid(snapshot.Blob.Ref).Bytes()) {
		return ReadResult{}, &ReadError{Stage: ReadStageBlobCID, Err: ErrReadBlobCIDMismatch}
	}
	envelope, err := vault.DecodeEnvelope(blob)
	if err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageEnvelope, Err: fmt.Errorf("%w: %w", ErrReadEnvelopeInvalid, err)}
	}
	snapshotCertificate, found := certificates[certificateIdentity(envelope.DeviceID, envelope.KeyID)]
	if !found {
		return ReadResult{}, &ReadError{Stage: ReadStageVaultAuth, Err: ErrReadVaultAuthentication}
	}
	if err := verifyEnvelopeSignature(blob, envelope, snapshotCertificate.object.SigningPublicKey[:]); err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageEnvelopeSignature, Err: fmt.Errorf("%w: %w", ErrReadEnvelopeSignature, err)}
	}
	if err := VerifySnapshotRecordSignature(snapshot, snapshotCertificate.object.SigningPublicKey[:]); err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageRecordSignature, Err: fmt.Errorf("%w: %w", ErrReadRecordSignature, err)}
	}
	if err := VerifyRecordBinding(snapshotBytes, blob); err != nil {
		return ReadResult{}, readBindingError(err)
	}

	selectedCertificateBytes := snapshotCertificate.recordBytes
	if err := VerifyRecordContext(policyBytes, RecordContext{
		Certificate: findPolicySignerRecord(policy, certificates), PreviousPolicy: request.PreviousPolicy,
		TrustAnchor: request.TrustAnchor,
	}); err != nil {
		return ReadResult{}, readContextError(err)
	}
	if err := VerifyRecordContext(controlBytes, RecordContext{Policy: policyBytes, Snapshot: snapshotBytes, TrustAnchor: request.TrustAnchor}); err != nil {
		return ReadResult{}, readContextError(err)
	}
	if err := VerifyRecordContext(headBytes, RecordContext{Policy: policyBytes, Snapshot: snapshotBytes, TrustAnchor: request.TrustAnchor}); err != nil {
		return ReadResult{}, readContextError(err)
	}
	if err := VerifyRecordContext(snapshotBytes, RecordContext{
		Policy: policyBytes, Certificate: selectedCertificateBytes, TrustAnchor: request.TrustAnchor,
	}); err != nil {
		return ReadResult{}, readContextError(err)
	}
	if err := verifySignerCertificateContexts([]vault.Signer{
		{DeviceID: policy.SignerDeviceID, KeyID: policy.SignerKeyID},
		{DeviceID: control.SignerDeviceID, KeyID: control.SignerKeyID},
		{DeviceID: head.SignerDeviceID, KeyID: head.SignerKeyID},
		{DeviceID: envelope.DeviceID, KeyID: envelope.KeyID},
	}, certificates, policyBytes, controlBytes, request.TrustAnchor); err != nil {
		return ReadResult{}, readContextError(err)
	}
	if err := authenticateVault(request, policy, policyObject, control, controlObject, head, headObject, envelope, blob, certificates); err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageVaultAuth, Err: fmt.Errorf("%w: %w", ErrReadVaultAuthentication, err)}
	}

	controlCID, err := rawBlobCID(controlObject)
	if err != nil {
		return ReadResult{}, &ReadError{Stage: ReadStageVaultAuth, Err: ErrReadVaultAuthentication}
	}
	result := ReadResult{
		Policy: policy, Control: control, Head: head, Snapshot: snapshot,
		Envelope: envelope, EnvelopeCID: cid.Cid(snapshot.Blob.Ref).String(), Freshness: FreshnessUnverified,
		PublicationCount: head.PublicationCount, PublicationCountBaseline: 0, HeadCID: bytes.Clone(head.SnapshotCID),
		ControlCID: bytes.Clone(controlCID), EpochSeq: head.EpochSeq, Ciphertext: bytes.Clone(blob),
	}
	if request.DeviceKey != nil {
		policyRecordObject, decodeErr := vault.DecodePolicy(policyObject)
		if decodeErr != nil {
			return ReadResult{}, &ReadError{Stage: ReadStageDecryption, Err: fmt.Errorf("%w: %w", ErrReadDecryption, decodeErr)}
		}
		policyDigest, digestErr := vault.ComputePolicyDigest(policyObject)
		if digestErr != nil {
			return ReadResult{}, &ReadError{Stage: ReadStageDecryption, Err: fmt.Errorf("%w: %w", ErrReadDecryption, digestErr)}
		}
		plaintext, openErr := vault.Open(envelope, vault.OpenRequest{
			Vault: policyRecordObject.Vault, EpochSeq: policyRecordObject.EpochSeq, PolicyDigest: policyDigest,
			Policy: policyObject, Control: controlObject, TrustAnchor: request.TrustAnchor,
			Certificates: certificateChainsForOpen(policyRecordObject, controlFromRecord(control), envelope, certificates), DeviceKeyID: bytes.Clone(request.DeviceKeyID), DeviceKey: request.DeviceKey,
		})
		if openErr != nil {
			return ReadResult{}, &ReadError{Stage: ReadStageDecryption, Err: fmt.Errorf("%w: %w", ErrReadDecryption, openErr)}
		}
		result.Plaintext = plaintext
	}
	return result, nil
}

func (r VaultReader) FetchBlob(ctx context.Context, did string, blobCID []byte, declaredSize int64) ([]byte, error) {
	if r.Transport == nil {
		return nil, &ReadError{Stage: ReadStageBlob, Err: errors.New("transport is required")}
	}
	parsed, err := cid.Cast(blobCID)
	if err != nil {
		return nil, &ReadError{Stage: ReadStageBlobCID, Err: ErrReadBlobCIDMismatch}
	}
	blob, err := r.fetchBlob(ctx, did, parsed, declaredSize)
	if err != nil {
		return nil, err
	}
	actual, err := rawBlobCID(blob)
	if err != nil || !bytes.Equal(actual, blobCID) {
		return nil, &ReadError{Stage: ReadStageBlobCID, Err: ErrReadBlobCIDMismatch}
	}
	return bytes.Clone(blob), nil
}

func (r VaultReader) fetchBlob(ctx context.Context, did string, blobCID cid.Cid, declaredSize int64) ([]byte, error) {
	maximum := r.MaxBlobBytes
	if maximum == 0 {
		maximum = vault.MaxEnvelopeBytes
	}
	if maximum < 0 || maximum > vault.MaxEnvelopeBytes {
		maximum = vault.MaxEnvelopeBytes
	}
	if declaredSize <= 0 || declaredSize > maximum {
		return nil, &ReadError{Stage: ReadStageBlob, Err: ErrReadBlobTooLarge}
	}
	status, stream, err := r.Transport.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {did}, "cid": {blobCID.String()}})
	if stream != nil {
		defer stream.Close()
	}
	if err != nil {
		return nil, &ReadError{Stage: ReadStageBlob, Err: fmt.Errorf("%w: %w", ErrReadBlobTransport, err)}
	}
	if status == 404 {
		return nil, &ReadError{Stage: ReadStageBlob, Err: ErrReadBlobMissing}
	}
	if status < 200 || status >= 300 || stream == nil {
		return nil, &ReadError{Stage: ReadStageBlob, Err: ErrReadBlobTransport}
	}
	limited := io.LimitReader(stream, declaredSize+1)
	blob, err := io.ReadAll(limited)
	if err != nil {
		return nil, &ReadError{Stage: ReadStageBlob, Err: fmt.Errorf("%w: %w", ErrReadBlobTransport, err)}
	}
	if int64(len(blob)) < declaredSize {
		return nil, &ReadError{Stage: ReadStageBlob, Err: ErrReadBlobTruncated}
	}
	if int64(len(blob)) > maximum {
		return nil, &ReadError{Stage: ReadStageBlob, Err: ErrReadBlobTooLarge}
	}
	if int64(len(blob)) > declaredSize {
		return nil, &ReadError{Stage: ReadStageBlob, Err: ErrReadBlobSizeMismatch}
	}
	return blob, nil
}

func revisionRecord(revision *Revision, key RecordKey) ([]byte, Record, error) {
	if revision == nil {
		return nil, nil, ErrReadRecordMissing
	}
	record, exists := revision.records[key]
	if !exists {
		return nil, nil, ErrReadRecordMissing
	}
	decoded, err := DecodeRecord(record.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrReadRecordInvalid, err)
	}
	return bytes.Clone(record.Data), decoded, nil
}

func readRecordError(err error) error {
	if errors.Is(err, ErrReadRecordMissing) {
		return &ReadError{Stage: ReadStageRecord, Err: err}
	}
	return &ReadError{Stage: ReadStageRecord, Err: fmt.Errorf("%w: %w", ErrReadRecordInvalid, err)}
}

func readBindingError(err error) error {
	return &ReadError{Stage: ReadStageRecordBinding, Err: fmt.Errorf("%w: %w", ErrReadRecordBinding, err)}
}

func readContextError(err error) error {
	var contextErr *RecordContextError
	if errors.As(err, &contextErr) && contextErr.Entry == "PreviousPolicy" && contextErr.Field == "required" {
		return &ReadError{Stage: ReadStageVaultAuth, Err: ErrReadPreviousPolicyRequired}
	}
	return &ReadError{Stage: ReadStageRecordContext, Err: fmt.Errorf("%w: %w", ErrReadRecordContext, err)}
}

func findSnapshotRecord(revision *Revision, expectedCID []byte) ([]byte, SnapshotRecord, error) {
	var selected []byte
	var result SnapshotRecord
	for key, proven := range revision.records {
		if key.Collection != VaultSnapshotNSID {
			continue
		}
		record, err := DecodeRecord(proven.Data)
		if err != nil {
			return nil, SnapshotRecord{}, &ReadError{Stage: ReadStageRecord, Err: err}
		}
		snapshot, ok := record.(SnapshotRecord)
		if !ok {
			return nil, SnapshotRecord{}, &ReadError{Stage: ReadStageRecord, Err: ErrReadRecordType}
		}
		if bytes.Equal(cid.Cid(snapshot.Blob.Ref).Bytes(), expectedCID) {
			if selected != nil {
				return nil, SnapshotRecord{}, &ReadError{Stage: ReadStageRecord, Err: ErrReadSnapshotAmbiguous}
			}
			selected = bytes.Clone(proven.Data)
			result = snapshot
		}
	}
	if selected == nil {
		return nil, SnapshotRecord{}, &ReadError{Stage: ReadStageRecord, Err: ErrReadRecordMissing}
	}
	return selected, result, nil
}

func loadCertificates(revision *Revision, expectedVault [32]byte) (map[string]storedCertificate, []storedCertificate, error) {
	keys := make([]RecordKey, 0)
	for key := range revision.records {
		if key.Collection == VaultCertificateNSID {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].RKey < keys[j].RKey })
	certificates := make(map[string]storedCertificate, len(keys))
	all := make([]storedCertificate, 0, len(keys))
	for _, key := range keys {
		proven := revision.records[key]
		record, err := DecodeRecord(proven.Data)
		if err != nil {
			return nil, nil, &ReadError{Stage: ReadStageRecord, Err: err}
		}
		value, ok := record.(CertificateRecord)
		if !ok {
			return nil, nil, &ReadError{Stage: ReadStageRecord, Err: ErrReadRecordType}
		}
		if !bytes.Equal(value.Vault, expectedVault[:]) {
			continue
		}
		object := certificateFromRecord(value)
		encoded, err := vault.EncodeCertificate(object)
		if err != nil {
			return nil, nil, &ReadError{Stage: ReadStageRecord, Err: err}
		}
		identity := certificateIdentity(value.DeviceID, value.KeyID)
		if _, duplicate := certificates[identity]; duplicate {
			return nil, nil, &ReadError{Stage: ReadStageVaultAuth, Err: ErrReadVaultAuthentication}
		}
		stored := storedCertificate{recordBytes: bytes.Clone(proven.Data), objectBytes: encoded, object: object}
		certificates[identity] = stored
		all = append(all, stored)
	}
	return certificates, all, nil
}

func certificateIdentity(deviceID string, keyID []byte) string {
	return deviceID + "\x00" + string(keyID)
}

func findPolicySignerRecord(policy PolicyRecord, certificates map[string]storedCertificate) []byte {
	certificate, found := certificates[certificateIdentity(policy.SignerDeviceID, policy.SignerKeyID)]
	if !found {
		return nil
	}
	return certificate.recordBytes
}

func verifySignerCertificateContexts(signers []vault.Signer, certificates map[string]storedCertificate, policy, control []byte, trustAnchor [32]byte) error {
	seen := make(map[string]bool, len(signers))
	for _, signer := range signers {
		identity := certificateIdentity(signer.DeviceID, signer.KeyID)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		certificate, found := certificates[identity]
		if !found {
			return &RecordContextError{Entry: "Certificate", Field: "required"}
		}
		if err := VerifyRecordContext(certificate.recordBytes, RecordContext{
			Policy: policy, Control: control, TrustAnchor: trustAnchor,
		}); err != nil {
			return err
		}
	}
	return nil
}

func authenticateVault(request ReadRequest, policyRecord PolicyRecord, policyBytes []byte, controlRecord ControlRecord, controlBytes []byte, headRecord HeadRecord, headBytes []byte, envelope vault.Envelope, envelopeBytes []byte, certificates map[string]storedCertificate) error {
	policy, err := vault.DecodePolicy(policyBytes)
	if err != nil {
		return err
	}
	control, err := vault.DecodeControl(controlBytes)
	if err != nil {
		return err
	}
	head, err := vault.DecodeHead(headBytes)
	if err != nil {
		return err
	}
	if policy.Vault != request.Vault || control.Vault != request.Vault || head.Vault != request.Vault || envelope.Vault != request.Vault {
		return errors.New("vault identifiers disagree")
	}
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	if err != nil {
		return err
	}
	if policy.EpochSeq != control.EpochSeq || policy.EpochSeq != head.EpochSeq || policy.EpochSeq != envelope.EpochSeq || control.PolicyDigest != policyDigest || head.PolicyDigest != policyDigest || envelope.PolicyDigest != policyDigest {
		return errors.New("epoch or policy digest disagrees")
	}
	if !bytes.Equal(head.SnapshotCID, cidBytes(envelopeBytes)) || !bytes.Equal(head.BlobCID, cidBytes(envelopeBytes)) || head.EpochSeq != control.EpochSeq || head.PolicyDigest != control.PolicyDigest {
		return errors.New("head and snapshot linkage disagrees")
	}
	if head.PublicationCount == 0 && !bytes.Equal(head.SnapshotCID, control.HeadSnapshotCID) {
		return errors.New("head publication count is below its epoch baseline")
	}
	policySigner, err := authorizedReadSigner(policy.Signer, policy.Roles, certificates, policy.Vault, policy.EpochSeq, request.TrustAnchor, control.Revoked, vault.RoleRoot)
	if err != nil {
		return err
	}
	if err := verifySignedObject(policyBytes, "dottie/v1/sig-policy", policy.Signature[:], policySigner.object.SigningPublicKey[:]); err != nil {
		return err
	}
	if policy.Signer.DeviceID != policyRecord.SignerDeviceID || !bytes.Equal(policy.Signer.KeyID, policyRecord.SignerKeyID) {
		return errors.New("policy signer mismatch")
	}
	if err := authorizePolicyPredecessor(request, policy, policyBytes, policySigner, certificates, control); err != nil {
		return err
	}
	controlSigner, err := authorizedReadSigner(control.Signer, policy.Roles, certificates, policy.Vault, policy.EpochSeq, request.TrustAnchor, control.Revoked, vault.RoleRoot)
	if err != nil {
		return err
	}
	if err := verifySignedObject(controlBytes, "dottie/v1/sig-control", control.Signature[:], controlSigner.object.SigningPublicKey[:]); err != nil {
		return err
	}
	if isReadGenesis(policy, control) {
		if len(request.PreviousControl) != 0 {
			return ErrReadUnexpectedPrevious
		}
	} else if policy.EpochSeq == 0 && allZero(policy.PrevPolicyDigest[:]) && len(control.PrevControlCID) != 0 {
		return ErrReadControlLinkage
	} else if err := authorizeControlPredecessor(request, policy, control, certificates); err != nil {
		return err
	}
	headSigner, err := authorizedReadSigner(head.Signer, policy.Roles, certificates, policy.Vault, policy.EpochSeq, request.TrustAnchor, control.Revoked, vault.RolePublisher)
	if err != nil {
		return err
	}
	if err := verifySignedObject(headBytes, "dottie/v1/sig-head", head.Signature[:], headSigner.object.SigningPublicKey[:]); err != nil {
		return err
	}
	snapshotSigner, err := authorizedReadSigner(vault.Signer{DeviceID: envelope.DeviceID, KeyID: envelope.KeyID}, policy.Roles, certificates, policy.Vault, policy.EpochSeq, request.TrustAnchor, control.Revoked, vault.RolePublisher)
	if err != nil {
		return err
	}
	if err := verifyEnvelopeSignature(envelopeBytes, envelope, snapshotSigner.object.SigningPublicKey[:]); err != nil {
		return err
	}
	if !bytes.Equal(head.PrevHeadCID, envelope.Parent) {
		return ErrReadHeadEnvelopeLinkage
	}
	if head.Signer.DeviceID != envelope.DeviceID || !bytes.Equal(head.Signer.KeyID, envelope.KeyID) {
		return ErrReadSignerMismatch
	}
	if len(policy.Recipients) != len(envelope.Recipients) {
		return ErrReadRecipientSet
	}
	recipientKeyIDs := make(map[string]struct{}, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		keyID := string(recipient.KeyID)
		if _, exists := recipientKeyIDs[keyID]; exists {
			return ErrReadRecipientSet
		}
		recipientKeyIDs[keyID] = struct{}{}
	}
	for _, recipient := range envelope.Recipients {
		keyID := string(recipient.KeyID)
		if _, exists := recipientKeyIDs[keyID]; !exists {
			return ErrReadRecipientSet
		}
		delete(recipientKeyIDs, keyID)
	}
	if len(recipientKeyIDs) != 0 {
		return ErrReadRecipientSet
	}
	if policy.EpochSeq != policyRecord.EpochSeq || control.EpochSeq != controlRecord.EpochSeq || head.EpochSeq != headRecord.EpochSeq {
		return errors.New("signed object epoch differs from its records")
	}
	return nil
}

func authorizePolicyPredecessor(request ReadRequest, current vault.Policy, currentBytes []byte, signer storedCertificate, certificates map[string]storedCertificate, controls ...vault.Control) error {
	zeroPredecessor := allZero(current.PrevPolicyDigest[:])
	if current.EpochSeq > 0 && zeroPredecessor || current.EpochSeq == 0 && !zeroPredecessor {
		return ErrPolicyAncestry
	}
	if zeroPredecessor {
		if current.Signer.DeviceID != signer.object.DeviceID || signer.object.Role != vault.RoleRoot {
			return errors.New("genesis policy signer is not an anchored root")
		}
		if len(controls) != 0 && len(controls[0].PrevControlCID) != 0 {
			return nil
		}
		if len(controls) != 0 && !sameReadSigner(controls[0].Signer, current.Signer) {
			return ErrPolicyAncestry
		}
		if len(request.PreviousPolicy) != 0 {
			return ErrReadUnexpectedPrevious
		}
		return nil
	}
	if len(request.PreviousPolicy) == 0 {
		return ErrReadPreviousPolicyRequired
	}
	previousRecord, err := DecodeRecord(request.PreviousPolicy)
	if err != nil {
		return err
	}
	previousValue, ok := previousRecord.(PolicyRecord)
	if !ok {
		return ErrReadRecordType
	}
	previousObject, err := vault.EncodePolicy(policyFromRecord(previousValue))
	if err != nil {
		return err
	}
	if err := VerifyRecordBinding(request.PreviousPolicy, previousObject); err != nil {
		return err
	}
	previous, err := vault.DecodePolicy(previousObject)
	if err != nil {
		return err
	}
	previousDigest, err := vault.ComputePolicyDigest(previousObject)
	if err != nil || !bytes.Equal(current.PrevPolicyDigest[:], previousDigest[:]) {
		return errors.New("predecessor policy digest does not match")
	}
	if previous.Vault != current.Vault || previous.EpochSeq == ^uint64(0) || previous.EpochSeq+1 != current.EpochSeq {
		return errors.New("predecessor policy identity or epoch is invalid")
	}
	previousSigner, err := authorizedReadSigner(previous.Signer, previous.Roles, certificates, previous.Vault, previous.EpochSeq, request.TrustAnchor, nil, vault.RoleRoot)
	if err != nil {
		return err
	}
	if err := verifySignedObject(previousObject, "dottie/v1/sig-policy", previous.Signature[:], previousSigner.object.SigningPublicKey[:]); err != nil {
		return err
	}
	if roleForDevice(previous.Roles, signer.object.DeviceID) != vault.RoleRoot || signer.object.Role != vault.RoleRoot {
		return errors.New("current policy signer was not a predecessor root")
	}
	currentDigest, err := vault.ComputePolicyDigest(currentBytes)
	if err != nil || currentDigest == previousDigest {
		return errors.New("current and predecessor policies are not distinct")
	}
	return nil
}

func isReadGenesis(policy vault.Policy, control vault.Control) bool {
	return policy.EpochSeq == 0 && allZero(policy.PrevPolicyDigest[:]) && len(control.PrevControlCID) == 0 && sameReadSigner(control.Signer, policy.Signer)
}

func sameReadSigner(left, right vault.Signer) bool {
	return left.DeviceID == right.DeviceID && bytes.Equal(left.KeyID, right.KeyID)
}

func authorizeControlPredecessor(request ReadRequest, policy vault.Policy, control vault.Control, certificates map[string]storedCertificate) error {
	if len(request.PreviousControl) == 0 {
		return ErrReadControlRequired
	}
	previousRecord, err := DecodeRecord(request.PreviousControl)
	if err != nil {
		return ErrReadControlType
	}
	previousRecordValue, ok := previousRecord.(ControlRecord)
	if !ok {
		return ErrReadControlType
	}
	previousObjectBytes, err := vault.EncodeControl(controlFromRecord(previousRecordValue))
	if err != nil {
		return ErrReadControlType
	}
	if err := VerifyRecordBinding(request.PreviousControl, previousObjectBytes); err != nil {
		return ErrReadControlType
	}
	previousCID, err := rawBlobCID(previousObjectBytes)
	if err != nil {
		return ErrReadControlType
	}
	previousControl, err := vault.DecodeControl(previousObjectBytes)
	if err != nil {
		return ErrReadControlSignature
	}
	previousPolicyRecord, err := DecodeRecord(request.PreviousPolicy)
	if err != nil {
		return ErrPolicyAncestry
	}
	previousPolicyRecordValue, ok := previousPolicyRecord.(PolicyRecord)
	if !ok {
		return ErrPolicyAncestry
	}
	previousPolicyBytes, err := vault.EncodePolicy(policyFromRecord(previousPolicyRecordValue))
	if err != nil || VerifyRecordBinding(request.PreviousPolicy, previousPolicyBytes) != nil {
		return ErrPolicyAncestry
	}
	previousPolicy, err := vault.DecodePolicy(previousPolicyBytes)
	if err != nil {
		return ErrPolicyAncestry
	}
	previousSigner, err := authorizedReadSigner(previousControl.Signer, previousPolicy.Roles, certificates, previousPolicy.Vault, previousPolicy.EpochSeq, request.TrustAnchor, nil, vault.RoleRoot)
	if err != nil || verifySignedObject(previousObjectBytes, "dottie/v1/sig-control", previousControl.Signature[:], previousSigner.object.SigningPublicKey[:]) != nil {
		return ErrReadControlSignature
	}
	if !sameReadSigner(previousControl.Signer, previousPolicy.Signer) {
		return ErrReadControlSigner
	}
	if previousControl.Vault != policy.Vault || policy.EpochSeq == 0 || previousControl.EpochSeq == ^uint64(0) || previousControl.EpochSeq != policy.EpochSeq-1 {
		return ErrReadControlEpoch
	}
	previousPolicyDigest, err := vault.ComputePolicyDigest(previousPolicyBytes)
	if err != nil || previousControl.PolicyDigest != previousPolicyDigest {
		return ErrReadControlPolicyDigest
	}
	if !bytes.Equal(control.PrevControlCID, previousCID) {
		return ErrReadControlLinkage
	}
	return nil
}

func authorizedReadSigner(signer vault.Signer, roles []vault.RoleBinding, certificates map[string]storedCertificate, vaultID [32]byte, epoch uint64, trustAnchor [32]byte, revoked []vault.RevokedDevice, minimumRole vault.Role) (storedCertificate, error) {
	certificate, found := certificates[certificateIdentity(signer.DeviceID, signer.KeyID)]
	if !found {
		return storedCertificate{}, errors.New("signing certificate is absent")
	}
	if certificate.object.Vault != vaultID || certificate.object.CertEpoch > epoch {
		return storedCertificate{}, errors.New("signing certificate vault or epoch is invalid")
	}
	role := roleForDevice(roles, certificate.object.DeviceID)
	if role != certificate.object.Role || !rolePermitted(role, minimumRole) {
		return storedCertificate{}, errors.New("signing certificate role is not permitted")
	}
	for _, item := range revoked {
		if item.DeviceID == certificate.object.DeviceID && item.CertEpoch >= certificate.object.CertEpoch {
			return storedCertificate{}, errors.New("signing certificate is revoked")
		}
	}
	if err := verifyCertificateChain(certificate.object, certificates, vaultID, epoch, trustAnchor, 1, make(map[string]bool)); err != nil {
		return storedCertificate{}, err
	}
	if certificate.object.Issuer != certificate.object.DeviceID {
		issuer := certificates[certificateIdentity(certificate.object.Issuer, certificate.object.Signer.KeyID)]
		if issuer.object.Role != vault.RoleRoot || roleForDevice(roles, issuer.object.DeviceID) != vault.RoleRoot || issuer.object.CertEpoch > epoch {
			return storedCertificate{}, errors.New("certificate issuer is not authorized by the current policy")
		}
		for _, item := range revoked {
			if item.DeviceID == issuer.object.DeviceID && item.CertEpoch >= issuer.object.CertEpoch {
				return storedCertificate{}, errors.New("certificate issuer is revoked")
			}
		}
	}
	return certificate, nil
}

func verifyCertificateChain(certificate vault.Certificate, certificates map[string]storedCertificate, vaultID [32]byte, epoch uint64, trustAnchor [32]byte, depth int, visited map[string]bool) error {
	if depth > 3 || certificate.Vault != vaultID || certificate.CertEpoch > epoch {
		return errors.New("certificate chain bounds or identity are invalid")
	}
	identity := certificateIdentity(certificate.DeviceID, certificate.KeyID)
	if visited[identity] {
		return errors.New("certificate chain contains a cycle")
	}
	visited[identity] = true
	defer delete(visited, identity)
	encoded, found := certificates[identity]
	if !found {
		return errors.New("certificate chain member is absent")
	}
	if certificate.Issuer == certificate.DeviceID {
		if certificate.Role != vault.RoleRoot || certificate.Signer.DeviceID != certificate.DeviceID || !bytes.Equal(certificate.Signer.KeyID, certificate.KeyID) {
			return errors.New("root certificate identity is invalid")
		}
		if readSHA256(certificate.SigningPublicKey[:]) != trustAnchor {
			return errors.New("root certificate does not match the trust anchor")
		}
		return verifySignedObject(encoded.objectBytes, "dottie/v1/sig-certificate", certificate.Signature[:], certificate.SigningPublicKey[:])
	}
	if certificate.Signer.DeviceID != certificate.Issuer {
		return errors.New("certificate issuer and signer differ")
	}
	issuer, found := certificates[certificateIdentity(certificate.Issuer, certificate.Signer.KeyID)]
	if !found || issuer.object.Role != vault.RoleRoot {
		return errors.New("certificate issuer is not a root")
	}
	if err := verifyCertificateChain(issuer.object, certificates, vaultID, epoch, trustAnchor, depth+1, visited); err != nil {
		return err
	}
	return verifySignedObject(encoded.objectBytes, "dottie/v1/sig-certificate", certificate.Signature[:], issuer.object.SigningPublicKey[:])
}

func rolePermitted(actual, minimum vault.Role) bool {
	if minimum == vault.RoleRoot {
		return actual == vault.RoleRoot
	}
	return actual == vault.RoleRoot || actual == vault.RolePublisher
}

func roleForDevice(roles []vault.RoleBinding, deviceID string) vault.Role {
	var result vault.Role
	found := false
	for _, binding := range roles {
		if binding.DeviceID != deviceID {
			continue
		}
		if found {
			return 0
		}
		result = binding.Role
		found = true
	}
	return result
}

func VerifySnapshotEnvelopeSignature(encoded []byte, certificate vault.Certificate) error {
	envelope, err := vault.DecodeEnvelope(encoded)
	if err != nil {
		return err
	}
	if envelope.Purpose != vault.PurposeSnapshot || envelope.DeviceID != certificate.DeviceID || !bytes.Equal(envelope.KeyID, certificate.KeyID) {
		return ErrReadVaultAuthentication
	}
	return verifyEnvelopeSignature(encoded, envelope, certificate.SigningPublicKey[:])
}

func verifyEnvelopeSignature(encoded []byte, envelope vault.Envelope, publicKey ed25519.PublicKey) error {
	if envelope.Purpose != vault.PurposeSnapshot || len(encoded) < ed25519.SignatureSize {
		return ErrReadEnvelopeInvalid
	}
	return verifySignedObject(encoded, "dottie/v1/sig-snapshot", envelope.Signature[:], publicKey)
}

func verifySignedObject(encoded []byte, context string, signature []byte, publicKey ed25519.PublicKey) error {
	if len(encoded) < ed25519.SignatureSize {
		return errors.New("signed object is truncated")
	}
	preimage := make([]byte, 0, len("dottie/v1/sig")+len(encoded)-ed25519.SignatureSize)
	preimage = append(preimage, "dottie/v1/sig"...)
	preimage = append(preimage, encoded[:len(encoded)-ed25519.SignatureSize]...)
	return vault.Verify(context, preimage, signature, publicKey)
}

func cidBytes(envelope []byte) []byte {
	value, _ := rawBlobCID(envelope)
	return value
}

func readSHA256(value []byte) [32]byte {
	return sha256.Sum256(value)
}

func certificateChainsForOpen(policy vault.Policy, control vault.Control, envelope vault.Envelope, certificates map[string]storedCertificate) [][]byte {
	ordered := make([]string, 0, 3)
	seen := make(map[string]bool)
	appendChain := func(signer vault.Signer) {
		identity := certificateIdentity(signer.DeviceID, signer.KeyID)
		for identity != "" && !seen[identity] {
			certificate, found := certificates[identity]
			if !found {
				return
			}
			seen[identity] = true
			ordered = append(ordered, identity)
			if certificate.object.Issuer == certificate.object.DeviceID {
				return
			}
			identity = certificateIdentity(certificate.object.Issuer, certificate.object.Signer.KeyID)
		}
	}
	appendChain(policy.Signer)
	appendChain(control.Signer)
	appendChain(vault.Signer{DeviceID: envelope.DeviceID, KeyID: envelope.KeyID})
	result := make([][]byte, 0, len(ordered))
	for _, identity := range ordered {
		result = append(result, bytes.Clone(certificates[identity].objectBytes))
	}
	return result
}
