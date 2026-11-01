package atproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
)

const (
	VaultHeadNSID          = "systems.lamb.dottie.vaultHead"
	VaultControlNSID       = "systems.lamb.dottie.vaultControl"
	VaultSnapshotNSID      = "systems.lamb.dottie.vaultSnapshot"
	VaultPolicyNSID        = "systems.lamb.dottie.vaultPolicy"
	VaultCertificateNSID   = "systems.lamb.dottie.vaultCertificate"
	VaultCheckpointNSID    = "systems.lamb.dottie.vaultCheckpoint"
	VaultAttestationNSID   = "systems.lamb.dottie.vaultAttestation"
	RecordSignatureContext = "dottie/v1/recordsig"
)

type Record interface {
	LexiconID() string
}

type SnapshotRecord struct {
	SchemaVersion           int64       `json:"schemaVersion"`
	Vault                   []byte      `json:"vault"`
	PublicationID           []byte      `json:"publicationId"`
	EpochSeq                uint64      `json:"epochSeq"`
	PolicyDigest            []byte      `json:"policyDigest"`
	Parent                  []byte      `json:"parent"`
	Blob                    atdata.Blob `json:"blob"`
	SignerDeviceID          string      `json:"signerDeviceId"`
	SignerKeyID             []byte      `json:"signerKeyId"`
	EnvelopeSignatureDigest []byte      `json:"envelopeSignatureDigest"`
	Signature               []byte      `json:"signature"`
}

func (SnapshotRecord) LexiconID() string { return VaultSnapshotNSID }

type HeadRecord struct {
	SchemaVersion    int64  `json:"schemaVersion"`
	Vault            []byte `json:"vault"`
	EpochSeq         uint64 `json:"epochSeq"`
	PolicyDigest     []byte `json:"policyDigest"`
	SnapshotCID      []byte `json:"snapshotCid"`
	BlobCID          []byte `json:"blobCid"`
	PublicationCount uint64 `json:"publicationCount"`
	PrevHeadCID      []byte `json:"prevHeadCid"`
	SignerDeviceID   string `json:"signerDeviceId"`
	SignerKeyID      []byte `json:"signerKeyId"`
	Signature        []byte `json:"signature"`
}

func (HeadRecord) LexiconID() string { return VaultHeadNSID }

type ControlRecord struct {
	SchemaVersion   int64                 `json:"schemaVersion"`
	Vault           []byte                `json:"vault"`
	EpochSeq        uint64                `json:"epochSeq"`
	PolicyDigest    []byte                `json:"policyDigest"`
	HeadSnapshotCID []byte                `json:"headSnapshotCid"`
	Revoked         []RevokedDeviceRecord `json:"revoked"`
	PrevControlCID  []byte                `json:"prevControlCid"`
	SignerDeviceID  string                `json:"signerDeviceId"`
	SignerKeyID     []byte                `json:"signerKeyId"`
	Signature       []byte                `json:"signature"`
}

func (ControlRecord) LexiconID() string { return VaultControlNSID }

type RevokedDeviceRecord struct {
	DeviceID  string `json:"deviceId"`
	CertEpoch uint64 `json:"certEpoch"`
}

type PolicyRecord struct {
	SchemaVersion          int64                   `json:"schemaVersion"`
	Vault                  []byte                  `json:"vault"`
	EpochSeq               uint64                  `json:"epochSeq"`
	Roles                  []PolicyRoleRecord      `json:"roles"`
	Recipients             []PolicyRecipientRecord `json:"recipients"`
	PolicyRetentionFloor   uint64                  `json:"policyRetentionFloor"`
	RetainedRecoveryPoints uint16                  `json:"retainedRecoveryPoints"`
	MaxPublications        uint32                  `json:"maxPublications"`
	MaxEpochAge            uint32                  `json:"maxEpochAge"`
	RecoveryAnchor         []byte                  `json:"recoveryAnchor"`
	PrevPolicyDigest       []byte                  `json:"prevPolicyDigest"`
	SignerDeviceID         string                  `json:"signerDeviceId"`
	SignerKeyID            []byte                  `json:"signerKeyId"`
	Signature              []byte                  `json:"signature"`
}

func (PolicyRecord) LexiconID() string { return VaultPolicyNSID }

type PolicyRoleRecord struct {
	DeviceID string `json:"deviceId"`
	Role     uint8  `json:"role"`
}

type PolicyRecipientRecord struct {
	DeviceID  string `json:"deviceId"`
	KeyID     []byte `json:"keyId"`
	PublicKey []byte `json:"publicKey"`
}

type CertificateRecord struct {
	SchemaVersion       int64  `json:"schemaVersion"`
	Vault               []byte `json:"vault"`
	DeviceID            string `json:"deviceId"`
	KeyID               []byte `json:"keyId"`
	SigningPublicKey    []byte `json:"signingPublicKey"`
	EncryptionPublicKey []byte `json:"encryptionPublicKey"`
	Role                uint8  `json:"role"`
	CertEpoch           uint64 `json:"certEpoch"`
	Issuer              string `json:"issuer"`
	RevocationRef       []byte `json:"revocationRef"`
	SignerDeviceID      string `json:"signerDeviceId"`
	SignerKeyID         []byte `json:"signerKeyId"`
	Signature           []byte `json:"signature"`
}

func (CertificateRecord) LexiconID() string { return VaultCertificateNSID }

type CheckpointRecord struct {
	SchemaVersion  int64  `json:"schemaVersion"`
	Vault          []byte `json:"vault"`
	SnapshotCID    []byte `json:"snapshotCid"`
	EpochSeq       uint64 `json:"epochSeq"`
	PolicyDigest   []byte `json:"policyDigest"`
	Anchor         []byte `json:"anchor"`
	ControlCID     []byte `json:"controlCid"`
	SignerDeviceID string `json:"signerDeviceId"`
	SignerKeyID    []byte `json:"signerKeyId"`
	Signature      []byte `json:"signature"`
}

func (CheckpointRecord) LexiconID() string { return VaultCheckpointNSID }

type AttestationRecord struct {
	SchemaVersion          int64  `json:"schemaVersion"`
	Vault                  []byte `json:"vault"`
	DeviceID               string `json:"deviceId"`
	PolicyDigest           []byte `json:"policyDigest"`
	RetentionFloor         uint64 `json:"retentionFloor"`
	RetainedRecoveryPoints uint16 `json:"retainedRecoveryPoints"`
	ControlCID             []byte `json:"controlCid"`
	SignerDeviceID         string `json:"signerDeviceId"`
	SignerKeyID            []byte `json:"signerKeyId"`
	Signature              []byte `json:"signature"`
}

func (AttestationRecord) LexiconID() string { return VaultAttestationNSID }

const (
	MaxRecordBytes   = vault.MaxPolicyObjectBytes
	MaxRecordInteger = uint64(1<<53 - 1)
)

var ErrRecord = errors.New("invalid vault record")

type RecordDecodeError struct {
	Field  string
	Reason string
}

func (e *RecordDecodeError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%v: %s", ErrRecord, e.Reason)
	}
	return fmt.Sprintf("%v: %s: %s", ErrRecord, e.Field, e.Reason)
}

func (e *RecordDecodeError) Unwrap() error { return ErrRecord }

type RecordBindingError struct {
	Field string
}

func (e *RecordBindingError) Error() string {
	return fmt.Sprintf("record binding mismatch: %s", e.Field)
}

type RecordSignatureError struct{}

func (RecordSignatureError) Error() string { return "invalid snapshot record signature" }

func DecodeRecord(data []byte) (Record, error) {
	if len(data) == 0 || len(data) > MaxRecordBytes {
		return nil, &RecordDecodeError{Field: "record", Reason: "size limit"}
	}
	object, err := atdata.UnmarshalCBOR(data)
	if err != nil {
		return nil, &RecordDecodeError{Field: "record", Reason: "invalid DAG-CBOR"}
	}
	typeID, ok := object["$type"].(string)
	if !ok {
		return nil, &RecordDecodeError{Field: "$type", Reason: "missing or invalid type"}
	}
	switch typeID {
	case VaultSnapshotNSID:
		return decodeSnapshotRecord(object)
	case VaultHeadNSID:
		return decodeHeadRecord(object)
	case VaultControlNSID:
		return decodeControlRecord(object)
	case VaultPolicyNSID:
		return decodePolicyRecord(object)
	case VaultCertificateNSID:
		return decodeCertificateRecord(object)
	case VaultCheckpointNSID:
		return decodeCheckpointRecord(object)
	case VaultAttestationNSID:
		return decodeAttestationRecord(object)
	default:
		return nil, &RecordDecodeError{Field: "$type", Reason: "unsupported type"}
	}
}

func EncodeRecord(record Record) ([]byte, error) {
	if err := validateRecordIntegers(record); err != nil {
		return nil, err
	}
	object, err := recordMap(record)
	if err != nil {
		return nil, err
	}
	encoded, err := atdata.MarshalCBOR(normalizeRecordMap(object))
	if err != nil {
		return nil, &RecordDecodeError{Field: "record", Reason: "DAG-CBOR encoding failed"}
	}
	if len(encoded) > MaxRecordBytes {
		return nil, &RecordDecodeError{Field: "record", Reason: "size limit"}
	}
	if _, err := DecodeRecord(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func validateRecordIntegers(record Record) error {
	check := func(field string, value uint64) error {
		if value > MaxRecordInteger {
			return &RecordDecodeError{Field: field, Reason: "integer exceeds interoperable range"}
		}
		return nil
	}
	switch value := record.(type) {
	case SnapshotRecord:
		return check("epochSeq", value.EpochSeq)
	case *SnapshotRecord:
		if value == nil {
			return &RecordDecodeError{Field: "record", Reason: "nil value"}
		}
		return check("epochSeq", value.EpochSeq)
	case HeadRecord:
		if err := check("epochSeq", value.EpochSeq); err != nil {
			return err
		}
		return check("publicationCount", value.PublicationCount)
	case *HeadRecord:
		if value == nil {
			return &RecordDecodeError{Field: "record", Reason: "nil value"}
		}
		return validateRecordIntegers(*value)
	case ControlRecord:
		if err := check("epochSeq", value.EpochSeq); err != nil {
			return err
		}
		for _, revoked := range value.Revoked {
			if err := check("revoked.certEpoch", revoked.CertEpoch); err != nil {
				return err
			}
		}
	case *ControlRecord:
		if value == nil {
			return &RecordDecodeError{Field: "record", Reason: "nil value"}
		}
		return validateRecordIntegers(*value)
	case PolicyRecord:
		if err := check("epochSeq", value.EpochSeq); err != nil {
			return err
		}
		return check("policyRetentionFloor", value.PolicyRetentionFloor)
	case *PolicyRecord:
		if value == nil {
			return &RecordDecodeError{Field: "record", Reason: "nil value"}
		}
		return validateRecordIntegers(*value)
	case CertificateRecord:
		return check("certEpoch", value.CertEpoch)
	case *CertificateRecord:
		if value == nil {
			return &RecordDecodeError{Field: "record", Reason: "nil value"}
		}
		return validateRecordIntegers(*value)
	case CheckpointRecord:
		return check("epochSeq", value.EpochSeq)
	case *CheckpointRecord:
		if value == nil {
			return &RecordDecodeError{Field: "record", Reason: "nil value"}
		}
		return validateRecordIntegers(*value)
	case AttestationRecord:
		return check("retentionFloor", value.RetentionFloor)
	case *AttestationRecord:
		if value == nil {
			return &RecordDecodeError{Field: "record", Reason: "nil value"}
		}
		return validateRecordIntegers(*value)
	default:
		return &RecordDecodeError{Field: "record", Reason: "unsupported Go type"}
	}
	return nil
}

func normalizeRecordMap(object map[string]any) map[string]any {
	for key, value := range object {
		object[key] = normalizeRecordValue(value)
	}
	return object
}

func normalizeRecordValue(value any) any {
	switch item := value.(type) {
	case []byte:
		if item == nil {
			return []byte{}
		}
	case atdata.Bytes:
		if item == nil {
			return atdata.Bytes{}
		}
	case []any:
		for index := range item {
			item[index] = normalizeRecordValue(item[index])
		}
		return item
	case map[string]any:
		return normalizeRecordMap(item)
	}
	return value
}

func recordMap(record Record) (map[string]any, error) {
	if record == nil || (reflect.ValueOf(record).Kind() == reflect.Pointer && reflect.ValueOf(record).IsNil()) {
		return nil, &RecordDecodeError{Field: "record", Reason: "nil value"}
	}
	switch value := record.(type) {
	case SnapshotRecord:
		return snapshotRecordMap(value), nil
	case *SnapshotRecord:
		return snapshotRecordMap(*value), nil
	case HeadRecord:
		return headRecordMap(value), nil
	case *HeadRecord:
		return headRecordMap(*value), nil
	case ControlRecord:
		return controlRecordMap(value), nil
	case *ControlRecord:
		return controlRecordMap(*value), nil
	case PolicyRecord:
		return policyRecordMap(value), nil
	case *PolicyRecord:
		return policyRecordMap(*value), nil
	case CertificateRecord:
		return certificateRecordMap(value), nil
	case *CertificateRecord:
		return certificateRecordMap(*value), nil
	case CheckpointRecord:
		return checkpointRecordMap(value), nil
	case *CheckpointRecord:
		return checkpointRecordMap(*value), nil
	case AttestationRecord:
		return attestationRecordMap(value), nil
	case *AttestationRecord:
		return attestationRecordMap(*value), nil
	default:
		return nil, &RecordDecodeError{Field: "record", Reason: "unsupported Go type"}
	}
}

func VerifyRecordBinding(record, envelopeOrObject []byte) error {
	decoded, err := DecodeRecord(record)
	if err != nil {
		return err
	}
	switch value := decoded.(type) {
	case SnapshotRecord:
		envelope, decodeErr := vault.DecodeEnvelope(envelopeOrObject)
		if decodeErr != nil || envelope.Purpose != vault.PurposeSnapshot {
			return &RecordDecodeError{Field: "object", Reason: "invalid snapshot envelope"}
		}
		blobCID, cidErr := rawBlobCID(envelopeOrObject)
		if cidErr != nil {
			return &RecordDecodeError{Field: "blob", Reason: "invalid envelope CID"}
		}
		if err := bindingBytes("vault", value.Vault, envelope.Vault[:]); err != nil {
			return err
		}
		if err := bindingBytes("publicationId", value.PublicationID, envelope.PublicationID[:]); err != nil {
			return err
		}
		if err := bindingUint("epochSeq", value.EpochSeq, envelope.EpochSeq); err != nil {
			return err
		}
		if err := bindingBytes("policyDigest", value.PolicyDigest, envelope.PolicyDigest[:]); err != nil {
			return err
		}
		if err := bindingBytes("parent", value.Parent, envelope.Parent); err != nil {
			return err
		}
		if err := bindingString("signerDeviceId", value.SignerDeviceID, envelope.DeviceID); err != nil {
			return err
		}
		if err := bindingBytes("signerKeyId", value.SignerKeyID, envelope.KeyID); err != nil {
			return err
		}
		if err := bindingBytes("blob.ref", cid.Cid(value.Blob.Ref).Bytes(), blobCID); err != nil {
			return err
		}
		if value.Blob.Size < 0 || uint64(value.Blob.Size) != uint64(len(envelopeOrObject)) {
			return &RecordBindingError{Field: "blob.size"}
		}
		digest := sha256.Sum256(envelope.Signature[:])
		if err := bindingBytes("envelopeSignatureDigest", value.EnvelopeSignatureDigest, digest[:]); err != nil {
			return err
		}
		return nil
	case HeadRecord:
		object, decodeErr := vault.DecodeHead(envelopeOrObject)
		if decodeErr != nil {
			return &RecordDecodeError{Field: "object", Reason: "invalid head object"}
		}
		return verifyHeadBinding(value, object)
	case ControlRecord:
		object, decodeErr := vault.DecodeControl(envelopeOrObject)
		if decodeErr != nil {
			return &RecordDecodeError{Field: "object", Reason: "invalid control object"}
		}
		return verifyControlBinding(value, object)
	case PolicyRecord:
		object, decodeErr := vault.DecodePolicy(envelopeOrObject)
		if decodeErr != nil {
			return &RecordDecodeError{Field: "object", Reason: "invalid policy object"}
		}
		return verifyPolicyBinding(value, object)
	case CertificateRecord:
		object, decodeErr := vault.DecodeCertificate(envelopeOrObject)
		if decodeErr != nil {
			return &RecordDecodeError{Field: "object", Reason: "invalid certificate object"}
		}
		return verifyCertificateBinding(value, object)
	case CheckpointRecord:
		object, decodeErr := vault.DecodeCheckpoint(envelopeOrObject)
		if decodeErr != nil {
			return &RecordDecodeError{Field: "object", Reason: "invalid checkpoint object"}
		}
		return verifyCheckpointBinding(value, object)
	case AttestationRecord:
		object, decodeErr := vault.DecodeAttestation(envelopeOrObject)
		if decodeErr != nil {
			return &RecordDecodeError{Field: "object", Reason: "invalid attestation object"}
		}
		return verifyAttestationBinding(value, object)
	default:
		return &RecordDecodeError{Field: "$type", Reason: "unsupported type"}
	}
}

func SnapshotRecordSigningPreimage(record SnapshotRecord) ([]byte, error) {
	candidate := record
	candidate.Signature = make([]byte, ed25519.SignatureSize)
	fullRecord, err := EncodeRecord(candidate)
	if err != nil {
		return nil, err
	}
	object, err := atdata.UnmarshalCBOR(fullRecord)
	if err != nil {
		return nil, &RecordDecodeError{Field: "record", Reason: "invalid DAG-CBOR"}
	}
	delete(object, "signature")
	encoded, err := atdata.MarshalCBOR(normalizeRecordMap(object))
	if err != nil {
		return nil, &RecordDecodeError{Field: "record", Reason: "DAG-CBOR encoding failed"}
	}
	preimage := make([]byte, 0, len(RecordSignatureContext)+len(encoded))
	preimage = append(preimage, RecordSignatureContext...)
	preimage = append(preimage, encoded...)
	return preimage, nil
}

func SignSnapshotRecord(record SnapshotRecord, key ed25519.PrivateKey) (SnapshotRecord, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SnapshotRecord{}, &RecordDecodeError{Field: "signature", Reason: "invalid signing key"}
	}
	preimage, err := SnapshotRecordSigningPreimage(record)
	if err != nil {
		return SnapshotRecord{}, err
	}
	signature, err := key.Sign(nil, preimage, &ed25519.Options{Context: RecordSignatureContext})
	if err != nil {
		return SnapshotRecord{}, &RecordDecodeError{Field: "signature", Reason: "signing failed"}
	}
	record.Signature = bytes.Clone(signature)
	return record, nil
}

func VerifySnapshotRecordSignature(record SnapshotRecord, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize || len(record.Signature) != ed25519.SignatureSize {
		return RecordSignatureError{}
	}
	preimage, err := SnapshotRecordSigningPreimage(record)
	if err != nil || ed25519.VerifyWithOptions(publicKey, preimage, record.Signature, &ed25519.Options{Context: RecordSignatureContext}) != nil {
		return RecordSignatureError{}
	}
	return nil
}

func rawBlobCID(data []byte) ([]byte, error) {
	hash, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return nil, err
	}
	return cid.NewCidV1(cid.Raw, hash).Bytes(), nil
}

func recordCID(data []byte) ([]byte, error) {
	hash, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return nil, err
	}
	return cid.NewCidV1(cid.DagCBOR, hash).Bytes(), nil
}

func bindingBytes(field string, got, want []byte) error {
	if !bytes.Equal(got, want) {
		return &RecordBindingError{Field: field}
	}
	return nil
}

func bindingUint(field string, got, want uint64) error {
	if got != want {
		return &RecordBindingError{Field: field}
	}
	return nil
}

func bindingString(field, got, want string) error {
	if got != want {
		return &RecordBindingError{Field: field}
	}
	return nil
}

func verifyHeadBinding(value HeadRecord, object vault.Head) error {
	if err := bindingBytes("vault", value.Vault, object.Vault[:]); err != nil {
		return err
	}
	if err := bindingUint("epochSeq", value.EpochSeq, object.EpochSeq); err != nil {
		return err
	}
	if err := bindingBytes("policyDigest", value.PolicyDigest, object.PolicyDigest[:]); err != nil {
		return err
	}
	if err := bindingBytes("snapshotCid", value.SnapshotCID, object.SnapshotCID); err != nil {
		return err
	}
	if err := bindingBytes("blobCid", value.BlobCID, object.BlobCID); err != nil {
		return err
	}
	if err := bindingUint("publicationCount", value.PublicationCount, object.PublicationCount); err != nil {
		return err
	}
	if err := bindingBytes("prevHeadCid", value.PrevHeadCID, object.PrevHeadCID); err != nil {
		return err
	}
	if err := bindingString("signerDeviceId", value.SignerDeviceID, object.Signer.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("signerKeyId", value.SignerKeyID, object.Signer.KeyID); err != nil {
		return err
	}
	return bindingBytes("signature", value.Signature, object.Signature[:])
}

func verifyControlBinding(value ControlRecord, object vault.Control) error {
	if err := bindingBytes("vault", value.Vault, object.Vault[:]); err != nil {
		return err
	}
	if err := bindingUint("epochSeq", value.EpochSeq, object.EpochSeq); err != nil {
		return err
	}
	if err := bindingBytes("policyDigest", value.PolicyDigest, object.PolicyDigest[:]); err != nil {
		return err
	}
	if err := bindingBytes("headSnapshotCid", value.HeadSnapshotCID, object.HeadSnapshotCID); err != nil {
		return err
	}
	if len(value.Revoked) != len(object.Revoked) {
		return &RecordBindingError{Field: "revoked"}
	}
	for index := range object.Revoked {
		if value.Revoked[index].DeviceID != object.Revoked[index].DeviceID || value.Revoked[index].CertEpoch != object.Revoked[index].CertEpoch {
			return &RecordBindingError{Field: "revoked"}
		}
	}
	if err := bindingBytes("prevControlCid", value.PrevControlCID, object.PrevControlCID); err != nil {
		return err
	}
	if err := bindingString("signerDeviceId", value.SignerDeviceID, object.Signer.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("signerKeyId", value.SignerKeyID, object.Signer.KeyID); err != nil {
		return err
	}
	return bindingBytes("signature", value.Signature, object.Signature[:])
}

func verifyPolicyBinding(value PolicyRecord, object vault.Policy) error {
	if err := bindingBytes("vault", value.Vault, object.Vault[:]); err != nil {
		return err
	}
	if err := bindingUint("epochSeq", value.EpochSeq, object.EpochSeq); err != nil {
		return err
	}
	if len(value.Roles) != len(object.Roles) {
		return &RecordBindingError{Field: "roles"}
	}
	for index := range object.Roles {
		if value.Roles[index].DeviceID != object.Roles[index].DeviceID || value.Roles[index].Role != uint8(object.Roles[index].Role) {
			return &RecordBindingError{Field: "roles"}
		}
	}
	if len(value.Recipients) != len(object.Recipients) {
		return &RecordBindingError{Field: "recipients"}
	}
	for index := range object.Recipients {
		if value.Recipients[index].DeviceID != object.Recipients[index].DeviceID || !bytes.Equal(value.Recipients[index].KeyID, object.Recipients[index].KeyID) || !bytes.Equal(value.Recipients[index].PublicKey, object.Recipients[index].PublicKey[:]) {
			return &RecordBindingError{Field: "recipients"}
		}
	}
	if err := bindingUint("policyRetentionFloor", value.PolicyRetentionFloor, object.PolicyRetentionFloor); err != nil {
		return err
	}
	if uint64(value.RetainedRecoveryPoints) != uint64(object.RetainedRecoveryPoints) {
		return &RecordBindingError{Field: "retainedRecoveryPoints"}
	}
	if uint64(value.MaxPublications) != uint64(object.MaxPublications) {
		return &RecordBindingError{Field: "maxPublications"}
	}
	if uint64(value.MaxEpochAge) != uint64(object.MaxEpochAge) {
		return &RecordBindingError{Field: "maxEpochAge"}
	}
	if err := bindingBytes("recoveryAnchor", value.RecoveryAnchor, object.RecoveryAnchor[:]); err != nil {
		return err
	}
	if err := bindingBytes("prevPolicyDigest", value.PrevPolicyDigest, object.PrevPolicyDigest[:]); err != nil {
		return err
	}
	if err := bindingString("signerDeviceId", value.SignerDeviceID, object.Signer.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("signerKeyId", value.SignerKeyID, object.Signer.KeyID); err != nil {
		return err
	}
	return bindingBytes("signature", value.Signature, object.Signature[:])
}

func verifyCertificateBinding(value CertificateRecord, object vault.Certificate) error {
	if err := bindingBytes("vault", value.Vault, object.Vault[:]); err != nil {
		return err
	}
	if err := bindingString("deviceId", value.DeviceID, object.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("keyId", value.KeyID, object.KeyID); err != nil {
		return err
	}
	if err := bindingBytes("signingPublicKey", value.SigningPublicKey, object.SigningPublicKey[:]); err != nil {
		return err
	}
	if err := bindingBytes("encryptionPublicKey", value.EncryptionPublicKey, object.EncryptionPublicKey[:]); err != nil {
		return err
	}
	if value.Role != uint8(object.Role) {
		return &RecordBindingError{Field: "role"}
	}
	if err := bindingUint("certEpoch", value.CertEpoch, object.CertEpoch); err != nil {
		return err
	}
	if err := bindingString("issuer", value.Issuer, object.Issuer); err != nil {
		return err
	}
	if err := bindingBytes("revocationRef", value.RevocationRef, object.RevocationRef); err != nil {
		return err
	}
	if err := bindingString("signerDeviceId", value.SignerDeviceID, object.Signer.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("signerKeyId", value.SignerKeyID, object.Signer.KeyID); err != nil {
		return err
	}
	return bindingBytes("signature", value.Signature, object.Signature[:])
}

func verifyCheckpointBinding(value CheckpointRecord, object vault.Checkpoint) error {
	if err := bindingBytes("vault", value.Vault, object.Vault[:]); err != nil {
		return err
	}
	if err := bindingBytes("snapshotCid", value.SnapshotCID, object.SnapshotCID); err != nil {
		return err
	}
	if err := bindingUint("epochSeq", value.EpochSeq, object.EpochSeq); err != nil {
		return err
	}
	if err := bindingBytes("policyDigest", value.PolicyDigest, object.PolicyDigest[:]); err != nil {
		return err
	}
	if err := bindingBytes("anchor", value.Anchor, object.Anchor[:]); err != nil {
		return err
	}
	if err := bindingBytes("controlCid", value.ControlCID, object.ControlCID); err != nil {
		return err
	}
	if err := bindingString("signerDeviceId", value.SignerDeviceID, object.Signer.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("signerKeyId", value.SignerKeyID, object.Signer.KeyID); err != nil {
		return err
	}
	return bindingBytes("signature", value.Signature, object.Signature[:])
}

func verifyAttestationBinding(value AttestationRecord, object vault.Attestation) error {
	if err := bindingBytes("vault", value.Vault, object.Vault[:]); err != nil {
		return err
	}
	if err := bindingString("deviceId", value.DeviceID, object.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("policyDigest", value.PolicyDigest, object.PolicyDigest[:]); err != nil {
		return err
	}
	if err := bindingUint("retentionFloor", value.RetentionFloor, object.RetentionFloor); err != nil {
		return err
	}
	if uint64(value.RetainedRecoveryPoints) != uint64(object.RetainedRecoveryPoints) {
		return &RecordBindingError{Field: "retainedRecoveryPoints"}
	}
	if err := bindingBytes("controlCid", value.ControlCID, object.ControlCID); err != nil {
		return err
	}
	if err := bindingString("signerDeviceId", value.SignerDeviceID, object.Signer.DeviceID); err != nil {
		return err
	}
	if err := bindingBytes("signerKeyId", value.SignerKeyID, object.Signer.KeyID); err != nil {
		return err
	}
	return bindingBytes("signature", value.Signature, object.Signature[:])
}

func policyFromRecord(record PolicyRecord) vault.Policy {
	policy := vault.Policy{
		Vault: [32]byte(record.Vault), EpochSeq: record.EpochSeq,
		PolicyRetentionFloor: record.PolicyRetentionFloor, RetainedRecoveryPoints: record.RetainedRecoveryPoints,
		MaxPublications: record.MaxPublications, MaxEpochAge: record.MaxEpochAge,
		RecoveryAnchor: [32]byte(record.RecoveryAnchor), PrevPolicyDigest: [32]byte(record.PrevPolicyDigest),
		Signer:    vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)},
		Signature: [ed25519.SignatureSize]byte(record.Signature),
	}
	policy.Roles = make([]vault.RoleBinding, len(record.Roles))
	for index, role := range record.Roles {
		policy.Roles[index] = vault.RoleBinding{DeviceID: role.DeviceID, Role: vault.Role(role.Role)}
	}
	policy.Recipients = make([]vault.PolicyRecipient, len(record.Recipients))
	for index, recipient := range record.Recipients {
		policy.Recipients[index] = vault.PolicyRecipient{DeviceID: recipient.DeviceID, KeyID: bytes.Clone(recipient.KeyID), PublicKey: [32]byte(recipient.PublicKey)}
	}
	return policy
}

func policyDigest(record PolicyRecord) ([32]byte, error) {
	encoded, err := vault.EncodePolicy(policyFromRecord(record))
	if err != nil {
		return [32]byte{}, err
	}
	return vault.ComputePolicyDigest(encoded)
}

func sortedFieldNames(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
