package atproto

import (
	"bytes"
	"crypto/ed25519"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/vault"
)

func snapshotRecordMap(value SnapshotRecord) map[string]any {
	return map[string]any{
		"$type": VaultSnapshotNSID, "schemaVersion": value.SchemaVersion,
		"vault": value.Vault, "publicationId": value.PublicationID, "epochSeq": int64(value.EpochSeq),
		"policyDigest": value.PolicyDigest, "parent": value.Parent, "blob": value.Blob,
		"signerDeviceId": value.SignerDeviceID, "signerKeyId": value.SignerKeyID,
		"envelopeSignatureDigest": value.EnvelopeSignatureDigest, "signature": value.Signature,
	}
}

func headRecordMap(value HeadRecord) map[string]any {
	return map[string]any{
		"$type": VaultHeadNSID, "schemaVersion": value.SchemaVersion, "vault": value.Vault,
		"epochSeq": int64(value.EpochSeq), "policyDigest": value.PolicyDigest, "snapshotCid": value.SnapshotCID,
		"blobCid": value.BlobCID, "publicationCount": int64(value.PublicationCount), "prevHeadCid": value.PrevHeadCID,
		"signerDeviceId": value.SignerDeviceID, "signerKeyId": value.SignerKeyID, "signature": value.Signature,
	}
}

func controlRecordMap(value ControlRecord) map[string]any {
	revoked := make([]any, len(value.Revoked))
	for index, entry := range value.Revoked {
		revoked[index] = map[string]any{"deviceId": entry.DeviceID, "certEpoch": int64(entry.CertEpoch)}
	}
	return map[string]any{
		"$type": VaultControlNSID, "schemaVersion": value.SchemaVersion, "vault": value.Vault,
		"epochSeq": int64(value.EpochSeq), "policyDigest": value.PolicyDigest, "headSnapshotCid": value.HeadSnapshotCID,
		"revoked": revoked, "prevControlCid": value.PrevControlCID, "signerDeviceId": value.SignerDeviceID,
		"signerKeyId": value.SignerKeyID, "signature": value.Signature,
	}
}

func policyRecordMap(value PolicyRecord) map[string]any {
	roles := make([]any, len(value.Roles))
	for index, entry := range value.Roles {
		roles[index] = map[string]any{"deviceId": entry.DeviceID, "role": int64(entry.Role)}
	}
	recipients := make([]any, len(value.Recipients))
	for index, entry := range value.Recipients {
		recipients[index] = map[string]any{"deviceId": entry.DeviceID, "keyId": entry.KeyID, "publicKey": entry.PublicKey}
	}
	return map[string]any{
		"$type": VaultPolicyNSID, "schemaVersion": value.SchemaVersion, "vault": value.Vault,
		"epochSeq": int64(value.EpochSeq), "roles": roles, "recipients": recipients,
		"policyRetentionFloor": int64(value.PolicyRetentionFloor), "retainedRecoveryPoints": int64(value.RetainedRecoveryPoints),
		"maxPublications": int64(value.MaxPublications), "maxEpochAge": int64(value.MaxEpochAge),
		"recoveryAnchor": value.RecoveryAnchor, "prevPolicyDigest": value.PrevPolicyDigest,
		"signerDeviceId": value.SignerDeviceID, "signerKeyId": value.SignerKeyID, "signature": value.Signature,
	}
}

func certificateRecordMap(value CertificateRecord) map[string]any {
	return map[string]any{
		"$type": VaultCertificateNSID, "schemaVersion": value.SchemaVersion, "vault": value.Vault,
		"deviceId": value.DeviceID, "keyId": value.KeyID, "signingPublicKey": value.SigningPublicKey,
		"encryptionPublicKey": value.EncryptionPublicKey, "role": int64(value.Role), "certEpoch": int64(value.CertEpoch),
		"issuer": value.Issuer, "revocationRef": value.RevocationRef, "signerDeviceId": value.SignerDeviceID,
		"signerKeyId": value.SignerKeyID, "signature": value.Signature,
	}
}

func checkpointRecordMap(value CheckpointRecord) map[string]any {
	return map[string]any{
		"$type": VaultCheckpointNSID, "schemaVersion": value.SchemaVersion, "vault": value.Vault,
		"snapshotCid": value.SnapshotCID, "epochSeq": int64(value.EpochSeq), "policyDigest": value.PolicyDigest,
		"anchor": value.Anchor, "controlCid": value.ControlCID, "signerDeviceId": value.SignerDeviceID,
		"signerKeyId": value.SignerKeyID, "signature": value.Signature,
	}
}

func attestationRecordMap(value AttestationRecord) map[string]any {
	object := map[string]any{
		"$type": VaultAttestationNSID, "schemaVersion": value.SchemaVersion, "vault": value.Vault,
		"deviceId": value.DeviceID, "policyDigest": value.PolicyDigest, "retentionFloor": int64(value.RetentionFloor),
		"retainedRecoveryPoints": int64(value.RetainedRecoveryPoints), "controlCid": value.ControlCID,
		"signerDeviceId": value.SignerDeviceID, "signerKeyId": value.SignerKeyID, "signature": value.Signature,
	}
	if value.SchemaVersion == 2 {
		points := make([]any, len(value.RecoveryPoints))
		for index, point := range value.RecoveryPoints {
			points[index] = map[string]any{"epoch": int64(point.Epoch), "snapshotCid": point.SnapshotCID}
		}
		object["recoveryPoints"] = points
	}
	return object
}

func decodeSnapshotRecord(object map[string]any) (Record, error) {
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "publicationId", "epochSeq", "policyDigest", "parent", "blob", "signerDeviceId", "signerKeyId", "envelopeSignatureDigest", "signature"); err != nil {
		return nil, err
	}
	value := SnapshotRecord{}
	var err error
	if value.SchemaVersion, err = fieldInt(object, "schemaVersion"); err != nil {
		return nil, err
	}
	if value.Vault, err = fieldBytes(object, "vault", 32, 32); err != nil {
		return nil, err
	}
	if value.PublicationID, err = fieldBytes(object, "publicationId", 16, 16); err != nil {
		return nil, err
	}
	if value.EpochSeq, err = fieldUint(object, "epochSeq", MaxRecordInteger); err != nil {
		return nil, err
	}
	if value.PolicyDigest, err = fieldBytes(object, "policyDigest", 32, 32); err != nil {
		return nil, err
	}
	if value.Parent, err = fieldBytes(object, "parent", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.Blob, err = fieldBlob(object, "blob"); err != nil {
		return nil, err
	}
	if value.SignerDeviceID, err = fieldString(object, "signerDeviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.SignerKeyID, err = fieldBytes(object, "signerKeyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.EnvelopeSignatureDigest, err = fieldBytes(object, "envelopeSignatureDigest", 32, 32); err != nil {
		return nil, err
	}
	if value.Signature, err = fieldBytes(object, "signature", ed25519SignatureSize, ed25519SignatureSize); err != nil {
		return nil, err
	}
	if err := versionOne(value.SchemaVersion); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeHeadRecord(object map[string]any) (Record, error) {
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "epochSeq", "policyDigest", "snapshotCid", "blobCid", "publicationCount", "prevHeadCid", "signerDeviceId", "signerKeyId", "signature"); err != nil {
		return nil, err
	}
	value := HeadRecord{}
	var err error
	if value.SchemaVersion, err = fieldInt(object, "schemaVersion"); err != nil {
		return nil, err
	}
	if value.Vault, err = fieldBytes(object, "vault", 32, 32); err != nil {
		return nil, err
	}
	if value.EpochSeq, err = fieldUint(object, "epochSeq", MaxRecordInteger); err != nil {
		return nil, err
	}
	if value.PolicyDigest, err = fieldBytes(object, "policyDigest", 32, 32); err != nil {
		return nil, err
	}
	if value.SnapshotCID, err = fieldBytes(object, "snapshotCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.BlobCID, err = fieldBytes(object, "blobCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.PublicationCount, err = fieldUint(object, "publicationCount", MaxRecordInteger); err != nil {
		return nil, err
	}
	if value.PrevHeadCID, err = fieldBytes(object, "prevHeadCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.SignerDeviceID, err = fieldString(object, "signerDeviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.SignerKeyID, err = fieldBytes(object, "signerKeyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.Signature, err = fieldBytes(object, "signature", ed25519SignatureSize, ed25519SignatureSize); err != nil {
		return nil, err
	}
	if err := versionOne(value.SchemaVersion); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeControlRecord(object map[string]any) (Record, error) {
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "epochSeq", "policyDigest", "headSnapshotCid", "revoked", "prevControlCid", "signerDeviceId", "signerKeyId", "signature"); err != nil {
		return nil, err
	}
	value := ControlRecord{}
	var err error
	if value.SchemaVersion, err = fieldInt(object, "schemaVersion"); err != nil {
		return nil, err
	}
	if value.Vault, err = fieldBytes(object, "vault", 32, 32); err != nil {
		return nil, err
	}
	if value.EpochSeq, err = fieldUint(object, "epochSeq", MaxRecordInteger); err != nil {
		return nil, err
	}
	if value.PolicyDigest, err = fieldBytes(object, "policyDigest", 32, 32); err != nil {
		return nil, err
	}
	if value.HeadSnapshotCID, err = fieldBytes(object, "headSnapshotCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.Revoked, err = fieldRevoked(object, "revoked"); err != nil {
		return nil, err
	}
	if value.PrevControlCID, err = fieldBytes(object, "prevControlCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.SignerDeviceID, err = fieldString(object, "signerDeviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.SignerKeyID, err = fieldBytes(object, "signerKeyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.Signature, err = fieldBytes(object, "signature", ed25519SignatureSize, ed25519SignatureSize); err != nil {
		return nil, err
	}
	if err := versionOne(value.SchemaVersion); err != nil {
		return nil, err
	}
	return value, nil
}

func decodePolicyRecord(object map[string]any) (Record, error) {
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "epochSeq", "roles", "recipients", "policyRetentionFloor", "retainedRecoveryPoints", "maxPublications", "maxEpochAge", "recoveryAnchor", "prevPolicyDigest", "signerDeviceId", "signerKeyId", "signature"); err != nil {
		return nil, err
	}
	value := PolicyRecord{}
	var err error
	if value.SchemaVersion, err = fieldInt(object, "schemaVersion"); err != nil {
		return nil, err
	}
	if value.Vault, err = fieldBytes(object, "vault", 32, 32); err != nil {
		return nil, err
	}
	if value.EpochSeq, err = fieldUint(object, "epochSeq", MaxRecordInteger); err != nil {
		return nil, err
	}
	if value.Roles, err = fieldRoles(object, "roles"); err != nil {
		return nil, err
	}
	if value.Recipients, err = fieldRecipients(object, "recipients"); err != nil {
		return nil, err
	}
	if len(value.Recipients) > vault.MaxRecipients {
		return nil, &RecordDecodeError{Field: "recipients", Reason: "limit exceeded"}
	}
	if value.PolicyRetentionFloor, err = fieldUint(object, "policyRetentionFloor", MaxRecordInteger); err != nil {
		return nil, err
	}
	retained, err := fieldUint(object, "retainedRecoveryPoints", uint64(^uint16(0)))
	if err != nil {
		return nil, err
	}
	value.RetainedRecoveryPoints = uint16(retained)
	publications, err := fieldUint(object, "maxPublications", 100000)
	if err != nil {
		return nil, err
	}
	if publications == 0 {
		return nil, &RecordDecodeError{Field: "maxPublications", Reason: "integer out of range"}
	}
	value.MaxPublications = uint32(publications)
	age, err := fieldUint(object, "maxEpochAge", 31536000)
	if err != nil || age < 3600 {
		return nil, &RecordDecodeError{Field: "maxEpochAge", Reason: "integer out of range"}
	}
	value.MaxEpochAge = uint32(age)
	if value.RecoveryAnchor, err = fieldBytes(object, "recoveryAnchor", 32, 32); err != nil {
		return nil, err
	}
	if value.PrevPolicyDigest, err = fieldBytes(object, "prevPolicyDigest", 32, 32); err != nil {
		return nil, err
	}
	if value.SignerDeviceID, err = fieldString(object, "signerDeviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.SignerKeyID, err = fieldBytes(object, "signerKeyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.Signature, err = fieldBytes(object, "signature", ed25519SignatureSize, ed25519SignatureSize); err != nil {
		return nil, err
	}
	if err := versionOne(value.SchemaVersion); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeCertificateRecord(object map[string]any) (Record, error) {
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "deviceId", "keyId", "signingPublicKey", "encryptionPublicKey", "role", "certEpoch", "issuer", "revocationRef", "signerDeviceId", "signerKeyId", "signature"); err != nil {
		return nil, err
	}
	value := CertificateRecord{}
	var err error
	if value.SchemaVersion, err = fieldInt(object, "schemaVersion"); err != nil {
		return nil, err
	}
	if value.Vault, err = fieldBytes(object, "vault", 32, 32); err != nil {
		return nil, err
	}
	if value.DeviceID, err = fieldString(object, "deviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.KeyID, err = fieldBytes(object, "keyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.SigningPublicKey, err = fieldBytes(object, "signingPublicKey", ed25519.PublicKeySize, ed25519.PublicKeySize); err != nil {
		return nil, err
	}
	if value.EncryptionPublicKey, err = fieldBytes(object, "encryptionPublicKey", 32, 32); err != nil {
		return nil, err
	}
	role, err := fieldUint(object, "role", 3)
	if err != nil || role == 0 {
		return nil, &RecordDecodeError{Field: "role", Reason: "invalid role"}
	}
	value.Role = uint8(role)
	if value.CertEpoch, err = fieldUint(object, "certEpoch", MaxRecordInteger); err != nil {
		return nil, err
	}
	if value.Issuer, err = fieldString(object, "issuer", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.RevocationRef, err = fieldBytes(object, "revocationRef", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.SignerDeviceID, err = fieldString(object, "signerDeviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.SignerKeyID, err = fieldBytes(object, "signerKeyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.Signature, err = fieldBytes(object, "signature", ed25519SignatureSize, ed25519SignatureSize); err != nil {
		return nil, err
	}
	if err := versionOne(value.SchemaVersion); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeCheckpointRecord(object map[string]any) (Record, error) {
	if err := exactKeys(object, "$type", "schemaVersion", "vault", "snapshotCid", "epochSeq", "policyDigest", "anchor", "controlCid", "signerDeviceId", "signerKeyId", "signature"); err != nil {
		return nil, err
	}
	value := CheckpointRecord{}
	var err error
	if value.SchemaVersion, err = fieldInt(object, "schemaVersion"); err != nil {
		return nil, err
	}
	if value.Vault, err = fieldBytes(object, "vault", 32, 32); err != nil {
		return nil, err
	}
	if value.SnapshotCID, err = fieldBytes(object, "snapshotCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.EpochSeq, err = fieldUint(object, "epochSeq", MaxRecordInteger); err != nil {
		return nil, err
	}
	if value.PolicyDigest, err = fieldBytes(object, "policyDigest", 32, 32); err != nil {
		return nil, err
	}
	if value.Anchor, err = fieldBytes(object, "anchor", 32, 32); err != nil {
		return nil, err
	}
	if value.ControlCID, err = fieldBytes(object, "controlCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.SignerDeviceID, err = fieldString(object, "signerDeviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.SignerKeyID, err = fieldBytes(object, "signerKeyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.Signature, err = fieldBytes(object, "signature", ed25519SignatureSize, ed25519SignatureSize); err != nil {
		return nil, err
	}
	if err := versionOne(value.SchemaVersion); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeAttestationRecord(object map[string]any) (Record, error) {
	value := AttestationRecord{}
	var err error
	if value.SchemaVersion, err = fieldInt(object, "schemaVersion"); err != nil {
		return nil, err
	}
	switch value.SchemaVersion {
	case 1:
		if err := exactKeys(object, "$type", "schemaVersion", "vault", "deviceId", "policyDigest", "retentionFloor", "retainedRecoveryPoints", "controlCid", "signerDeviceId", "signerKeyId", "signature"); err != nil {
			return nil, err
		}
	case 2:
		if err := exactKeys(object, "$type", "schemaVersion", "vault", "deviceId", "policyDigest", "retentionFloor", "retainedRecoveryPoints", "recoveryPoints", "controlCid", "signerDeviceId", "signerKeyId", "signature"); err != nil {
			return nil, err
		}
		if value.RecoveryPoints, err = fieldAttestationRecoveryPoints(object, "recoveryPoints"); err != nil {
			return nil, err
		}
	default:
		return nil, &RecordDecodeError{Field: "schemaVersion", Reason: "unsupported schema version"}
	}
	if value.Vault, err = fieldBytes(object, "vault", 32, 32); err != nil {
		return nil, err
	}
	if value.DeviceID, err = fieldString(object, "deviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.PolicyDigest, err = fieldBytes(object, "policyDigest", 32, 32); err != nil {
		return nil, err
	}
	if value.RetentionFloor, err = fieldUint(object, "retentionFloor", MaxRecordInteger); err != nil {
		return nil, err
	}
	retained, err := fieldUint(object, "retainedRecoveryPoints", uint64(^uint16(0)))
	if err != nil {
		return nil, err
	}
	value.RetainedRecoveryPoints = uint16(retained)
	if value.ControlCID, err = fieldBytes(object, "controlCid", 0, vault.MaxParentBytes); err != nil {
		return nil, err
	}
	if value.SignerDeviceID, err = fieldString(object, "signerDeviceId", vault.MaxDeviceIDBytes); err != nil {
		return nil, err
	}
	if value.SignerKeyID, err = fieldBytes(object, "signerKeyId", 0, vault.MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if value.Signature, err = fieldBytes(object, "signature", ed25519SignatureSize, ed25519SignatureSize); err != nil {
		return nil, err
	}
	if value.SchemaVersion == 2 && len(value.RecoveryPoints) != int(value.RetainedRecoveryPoints) {
		return nil, &RecordDecodeError{Field: "retainedRecoveryPoints", Reason: "count does not match recoveryPoints"}
	}
	return value, nil
}

func exactKeys(object map[string]any, required ...string) error {
	allowed := make(map[string]struct{}, len(required))
	for _, key := range required {
		allowed[key] = struct{}{}
	}
	for _, key := range sortedFieldNames(object) {
		if _, ok := allowed[key]; !ok {
			return &RecordDecodeError{Field: key, Reason: "unknown field"}
		}
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return &RecordDecodeError{Field: key, Reason: "required field missing"}
		}
	}
	return nil
}

func versionOne(value int64) error {
	if value != 1 {
		return &RecordDecodeError{Field: "schemaVersion", Reason: "unsupported schema version"}
	}
	return nil
}

func fieldInt(object map[string]any, name string) (int64, error) {
	value, ok := object[name].(int64)
	if !ok {
		return 0, &RecordDecodeError{Field: name, Reason: "expected integer"}
	}
	return value, nil
}

func fieldUint(object map[string]any, name string, maximum uint64) (uint64, error) {
	value, err := fieldInt(object, name)
	if err != nil {
		return 0, err
	}
	if value < 0 || uint64(value) > maximum {
		return 0, &RecordDecodeError{Field: name, Reason: "integer out of range"}
	}
	return uint64(value), nil
}

func fieldBytes(object map[string]any, name string, minimum, maximum int) ([]byte, error) {
	value, ok := object[name].(atdata.Bytes)
	if !ok {
		if raw, rawOK := object[name].([]byte); rawOK {
			value = atdata.Bytes(raw)
		} else {
			return nil, &RecordDecodeError{Field: name, Reason: "expected bytes"}
		}
	}
	if len(value) < minimum || len(value) > maximum {
		return nil, &RecordDecodeError{Field: name, Reason: "byte length out of range"}
	}
	return bytes.Clone(value), nil
}

func fieldString(object map[string]any, name string, maximum int) (string, error) {
	value, ok := object[name].(string)
	if !ok {
		return "", &RecordDecodeError{Field: name, Reason: "expected string"}
	}
	if len(value) > maximum || !utf8.ValidString(value) {
		return "", &RecordDecodeError{Field: name, Reason: "string length out of range"}
	}
	return value, nil
}

func fieldBlob(object map[string]any, name string) (atdata.Blob, error) {
	value, ok := object[name].(atdata.Blob)
	if !ok {
		return atdata.Blob{}, &RecordDecodeError{Field: name, Reason: "expected blob reference"}
	}
	if value.MimeType != "application/octet-stream" || value.Size < 0 || value.Size > vault.MaxEnvelopeBytes {
		return atdata.Blob{}, &RecordDecodeError{Field: name, Reason: "blob bounds or MIME type"}
	}
	if !cid.Cid(value.Ref).Defined() || len(cid.Cid(value.Ref).Bytes()) > vault.MaxParentBytes {
		return atdata.Blob{}, &RecordDecodeError{Field: name, Reason: "blob CID bounds"}
	}
	return value, nil
}

func fieldRoles(object map[string]any, name string) ([]PolicyRoleRecord, error) {
	values, ok := object[name].([]any)
	if !ok {
		return nil, &RecordDecodeError{Field: name, Reason: "expected array"}
	}
	roles := make([]PolicyRoleRecord, len(values))
	for index, item := range values {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, &RecordDecodeError{Field: name, Reason: "invalid role entry"}
		}
		if err := exactKeys(entry, "deviceId", "role"); err != nil {
			return nil, err
		}
		deviceID, err := fieldString(entry, "deviceId", vault.MaxDeviceIDBytes)
		if err != nil {
			return nil, err
		}
		roles[index].DeviceID = deviceID
		role, err := fieldUint(entry, "role", 3)
		if err != nil || role == 0 {
			return nil, &RecordDecodeError{Field: name, Reason: "invalid role"}
		}
		roles[index].Role = uint8(role)
	}
	return roles, nil
}

func fieldRecipients(object map[string]any, name string) ([]PolicyRecipientRecord, error) {
	values, ok := object[name].([]any)
	if !ok {
		return nil, &RecordDecodeError{Field: name, Reason: "expected array"}
	}
	recipients := make([]PolicyRecipientRecord, len(values))
	for index, item := range values {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, &RecordDecodeError{Field: name, Reason: "invalid recipient entry"}
		}
		if err := exactKeys(entry, "deviceId", "keyId", "publicKey"); err != nil {
			return nil, err
		}
		deviceID, err := fieldString(entry, "deviceId", vault.MaxDeviceIDBytes)
		if err != nil {
			return nil, err
		}
		recipients[index].DeviceID = deviceID
		recipients[index].KeyID, err = fieldBytes(entry, "keyId", 0, vault.MaxKeyIDBytes)
		if err != nil {
			return nil, err
		}
		recipients[index].PublicKey, err = fieldBytes(entry, "publicKey", 32, 32)
		if err != nil {
			return nil, err
		}
	}
	return recipients, nil
}

func fieldAttestationRecoveryPoints(object map[string]any, name string) ([]AttestationRecoveryPointRecord, error) {
	values, ok := object[name].([]any)
	if !ok {
		return nil, &RecordDecodeError{Field: name, Reason: "expected array"}
	}
	if len(values) > int(^uint16(0)) {
		return nil, &RecordDecodeError{Field: name, Reason: "limit exceeded"}
	}
	points := make([]AttestationRecoveryPointRecord, len(values))
	for index, item := range values {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, &RecordDecodeError{Field: name, Reason: "invalid recovery point"}
		}
		if err := exactKeys(entry, "epoch", "snapshotCid"); err != nil {
			return nil, err
		}
		epoch, err := fieldUint(entry, "epoch", MaxRecordInteger)
		if err != nil {
			return nil, err
		}
		points[index].Epoch = epoch
		points[index].SnapshotCID, err = fieldBytes(entry, "snapshotCid", 1, vault.MaxParentBytes)
		if err != nil {
			return nil, err
		}
		if index > 0 && !attestationRecoveryPointLess(points[index-1], points[index]) {
			return nil, &RecordDecodeError{Field: name, Reason: "duplicate or out-of-order recovery point"}
		}
	}
	return points, nil
}

func attestationRecoveryPointLess(left, right AttestationRecoveryPointRecord) bool {
	if left.Epoch != right.Epoch {
		return left.Epoch < right.Epoch
	}
	return bytes.Compare(left.SnapshotCID, right.SnapshotCID) < 0
}

func fieldRevoked(object map[string]any, name string) ([]RevokedDeviceRecord, error) {
	values, ok := object[name].([]any)
	if !ok {
		return nil, &RecordDecodeError{Field: name, Reason: "expected array"}
	}
	revoked := make([]RevokedDeviceRecord, len(values))
	for index, item := range values {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, &RecordDecodeError{Field: name, Reason: "invalid revoked entry"}
		}
		if err := exactKeys(entry, "deviceId", "certEpoch"); err != nil {
			return nil, err
		}
		deviceID, err := fieldString(entry, "deviceId", vault.MaxDeviceIDBytes)
		if err != nil {
			return nil, err
		}
		revoked[index].DeviceID = deviceID
		if revoked[index].CertEpoch, err = fieldUint(entry, "certEpoch", MaxRecordInteger); err != nil {
			return nil, err
		}
	}
	return revoked, nil
}

const ed25519SignatureSize = ed25519.SignatureSize
