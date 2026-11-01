package atproto

import (
	"bytes"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/vault"
)

type RecordContext struct {
	Policy         []byte
	Control        []byte
	Certificate    []byte
	Snapshot       []byte
	PreviousPolicy []byte
	TrustAnchor    [32]byte
}

type RecordContextError struct {
	Entry string
	Field string
}

func (e *RecordContextError) Error() string {
	if e.Entry != "" {
		return fmt.Sprintf("record context missing or mismatched: %s.%s", e.Entry, e.Field)
	}
	return fmt.Sprintf("record context mismatch: %s", e.Field)
}

func VerifyRecordContext(record []byte, context RecordContext) error {
	decoded, err := DecodeRecord(record)
	if err != nil {
		return err
	}
	switch value := decoded.(type) {
	case SnapshotRecord:
		policy, err := requirePolicyContext(context.Policy)
		if err != nil {
			return err
		}
		certificate, err := requireCertificateContext(context.Certificate)
		if err != nil {
			return err
		}
		if err := matchPolicyIdentity(value.Vault, value.PolicyDigest, policy); err != nil {
			return err
		}
		if err := matchSignerCertificate(value.SignerDeviceID, value.SignerKeyID, certificate, policy, true); err != nil {
			return err
		}
		return nil
	case HeadRecord:
		policy, err := requirePolicyContext(context.Policy)
		if err != nil {
			return err
		}
		if err := matchPolicyIdentity(value.Vault, value.PolicyDigest, policy); err != nil {
			return err
		}
		snapshotCID, blobCID, err := snapshotContextCIDs(context.Snapshot)
		if err != nil {
			return err
		}
		if !bytes.Equal(value.SnapshotCID, snapshotCID) {
			return &RecordContextError{Field: "snapshotCid"}
		}
		if !bytes.Equal(value.BlobCID, blobCID) {
			return &RecordContextError{Field: "blobCid"}
		}
		return nil
	case ControlRecord:
		policy, err := requirePolicyContext(context.Policy)
		if err != nil {
			return err
		}
		if err := matchPolicyIdentity(value.Vault, value.PolicyDigest, policy); err != nil {
			return err
		}
		snapshotRecord, err := snapshotContextRecord(context.Snapshot)
		if err != nil {
			return err
		}
		if value.EpochSeq != snapshotRecord.EpochSeq || !bytes.Equal(value.PolicyDigest[:], snapshotRecord.PolicyDigest) {
			return &RecordContextError{Field: "headSnapshotCid"}
		}
		return nil
	case PolicyRecord:
		certificate, err := requireCertificateContext(context.Certificate)
		if err != nil {
			return err
		}
		if err := matchSignerCertificate(value.SignerDeviceID, value.SignerKeyID, certificate, value, false); err != nil {
			return err
		}
		if !allZero(value.PrevPolicyDigest) {
			previous, err := requirePolicyContext(context.PreviousPolicy)
			if err != nil {
				return &RecordContextError{Entry: "PreviousPolicy", Field: "required"}
			}
			previousDigest, digestErr := policyDigest(previous)
			if digestErr != nil || !bytes.Equal(value.PrevPolicyDigest, previousDigest[:]) {
				return &RecordContextError{Field: "prevPolicyDigest"}
			}
			if !bytes.Equal(value.Vault, previous.Vault) {
				return &RecordContextError{Field: "vault"}
			}
		}
		return nil
	case CertificateRecord:
		policy, err := requirePolicyContext(context.Policy)
		if err != nil {
			return err
		}
		control, err := requireControlContext(context.Control)
		if err != nil {
			return err
		}
		if !bytes.Equal(value.Vault, policy.Vault) || !bytes.Equal(value.Vault, control.Vault) {
			return &RecordContextError{Field: "vault"}
		}
		if err := matchControlPolicy(control, policy); err != nil {
			return err
		}
		if err := policyCertificateFields(value, policy); err != nil {
			return err
		}
		controlCID, err := recordCID(context.Control)
		if err != nil {
			return &RecordContextError{Field: "controlCid"}
		}
		revoked := false
		for _, entry := range control.Revoked {
			if entry.DeviceID == value.DeviceID && entry.CertEpoch >= value.CertEpoch {
				revoked = true
				break
			}
		}
		if revoked {
			if !bytes.Equal(value.RevocationRef, controlCID) {
				return &RecordContextError{Field: "revocationRef"}
			}
		} else if len(value.RevocationRef) != 0 {
			return &RecordContextError{Field: "revocationRef"}
		}
		return nil
	case CheckpointRecord:
		policy, err := requirePolicyContext(context.Policy)
		if err != nil {
			return err
		}
		control, err := requireControlContext(context.Control)
		if err != nil {
			return err
		}
		if !bytes.Equal(value.Vault, policy.Vault) || !bytes.Equal(value.Vault, control.Vault) {
			return &RecordContextError{Field: "vault"}
		}
		if err := matchPolicyDigest(value.PolicyDigest, policy); err != nil {
			return err
		}
		if err := matchControlPolicy(control, policy); err != nil {
			return err
		}
		controlCID, err := recordCID(context.Control)
		if err != nil || !bytes.Equal(value.ControlCID, controlCID) {
			return &RecordContextError{Field: "controlCid"}
		}
		if value.EpochSeq != control.EpochSeq || !bytes.Equal(value.PolicyDigest, control.PolicyDigest) {
			return &RecordContextError{Field: "snapshotCid"}
		}
		if !allZero(value.Anchor) {
			if allZero(context.TrustAnchor[:]) {
				return &RecordContextError{Entry: "TrustAnchor", Field: "required"}
			}
			if !bytes.Equal(value.Anchor, context.TrustAnchor[:]) {
				return &RecordContextError{Field: "anchor"}
			}
		}
		return nil
	case AttestationRecord:
		policy, err := requirePolicyContext(context.Policy)
		if err != nil {
			return err
		}
		control, err := requireControlContext(context.Control)
		if err != nil {
			return err
		}
		if !bytes.Equal(value.Vault, policy.Vault) || !bytes.Equal(value.Vault, control.Vault) {
			return &RecordContextError{Field: "vault"}
		}
		if err := matchPolicyDigest(value.PolicyDigest, policy); err != nil {
			return err
		}
		if !bytes.Equal(value.PolicyDigest, control.PolicyDigest) {
			return &RecordContextError{Field: "policyDigest"}
		}
		if err := matchControlPolicy(control, policy); err != nil {
			return err
		}
		if value.RetentionFloor < policy.PolicyRetentionFloor {
			return &RecordContextError{Field: "retentionFloor"}
		}
		controlCID, err := recordCID(context.Control)
		if err != nil || !bytes.Equal(value.ControlCID, controlCID) {
			return &RecordContextError{Field: "controlCid"}
		}
		return nil
	default:
		return &RecordContextError{Field: "$type"}
	}
}

func requirePolicyContext(data []byte) (PolicyRecord, error) {
	if data == nil {
		return PolicyRecord{}, &RecordContextError{Entry: "Policy", Field: "required"}
	}
	record, err := DecodeRecord(data)
	if err != nil {
		return PolicyRecord{}, &RecordContextError{Entry: "Policy", Field: "invalid"}
	}
	value, ok := record.(PolicyRecord)
	if !ok {
		return PolicyRecord{}, &RecordContextError{Entry: "Policy", Field: "wrongType"}
	}
	return value, nil
}

func requireControlContext(data []byte) (ControlRecord, error) {
	if data == nil {
		return ControlRecord{}, &RecordContextError{Entry: "Control", Field: "required"}
	}
	record, err := DecodeRecord(data)
	if err != nil {
		return ControlRecord{}, &RecordContextError{Entry: "Control", Field: "invalid"}
	}
	value, ok := record.(ControlRecord)
	if !ok {
		return ControlRecord{}, &RecordContextError{Entry: "Control", Field: "wrongType"}
	}
	return value, nil
}

func requireCertificateContext(data []byte) (CertificateRecord, error) {
	if data == nil {
		return CertificateRecord{}, &RecordContextError{Entry: "Certificate", Field: "required"}
	}
	record, err := DecodeRecord(data)
	if err != nil {
		return CertificateRecord{}, &RecordContextError{Entry: "Certificate", Field: "invalid"}
	}
	value, ok := record.(CertificateRecord)
	if !ok {
		return CertificateRecord{}, &RecordContextError{Entry: "Certificate", Field: "wrongType"}
	}
	return value, nil
}

func matchPolicyIdentity(recordVault, digest []byte, policy PolicyRecord) error {
	if !bytes.Equal(recordVault, policy.Vault) {
		return &RecordContextError{Field: "vault"}
	}
	return matchPolicyDigest(digest, policy)
}

func matchPolicyDigest(digest []byte, policy PolicyRecord) error {
	computed, err := policyDigest(policy)
	if err != nil || !bytes.Equal(digest, computed[:]) {
		return &RecordContextError{Field: "policyDigest"}
	}
	return nil
}

func matchControlPolicy(control ControlRecord, policy PolicyRecord) error {
	return matchPolicyDigest(control.PolicyDigest, policy)
}

func matchSignerCertificate(deviceID string, keyID []byte, certificate CertificateRecord, policy PolicyRecord, requirePublishRole bool) error {
	if certificate.DeviceID != deviceID || !bytes.Equal(certificate.KeyID, keyID) {
		return &RecordContextError{Field: "signer"}
	}
	if !bytes.Equal(certificate.Vault, policy.Vault) {
		return &RecordContextError{Field: "vault"}
	}
	role, found := policyRoleForDevice(policy, deviceID)
	if !found || role != certificate.Role {
		return &RecordContextError{Field: "role"}
	}
	if requirePublishRole && role != uint8(vault.RoleRoot) && role != uint8(vault.RolePublisher) {
		return &RecordContextError{Field: "role"}
	}
	if !requirePublishRole && role != uint8(vault.RoleRoot) {
		return &RecordContextError{Field: "role"}
	}
	return nil
}

func policyRoleForDevice(policy PolicyRecord, deviceID string) (uint8, bool) {
	var role uint8
	found := false
	for _, entry := range policy.Roles {
		if entry.DeviceID != deviceID {
			continue
		}
		if found {
			return 0, false
		}
		role, found = entry.Role, true
	}
	return role, found
}

func policyCertificateFields(certificate CertificateRecord, policy PolicyRecord) error {
	role, found := policyRoleForDevice(policy, certificate.DeviceID)
	if !found || role != certificate.Role {
		return &RecordContextError{Field: "role"}
	}
	var recipient *PolicyRecipientRecord
	for index := range policy.Recipients {
		if policy.Recipients[index].DeviceID != certificate.DeviceID {
			continue
		}
		if recipient != nil {
			return &RecordContextError{Field: "recipient"}
		}
		recipient = &policy.Recipients[index]
	}
	if recipient == nil {
		return &RecordContextError{Field: "recipient"}
	}
	if !bytes.Equal(recipient.PublicKey, certificate.EncryptionPublicKey) {
		return &RecordContextError{Field: "encryptionPublicKey"}
	}
	return nil
}

func snapshotContextRecord(data []byte) (SnapshotRecord, error) {
	decoded, err := DecodeRecord(data)
	if err != nil {
		return SnapshotRecord{}, &RecordContextError{Entry: "Snapshot", Field: "invalid"}
	}
	record, ok := decoded.(SnapshotRecord)
	if !ok {
		return SnapshotRecord{}, &RecordContextError{Entry: "Snapshot", Field: "wrongType"}
	}
	return record, nil
}

func snapshotContextCIDs(data []byte) ([]byte, []byte, error) {
	if data == nil {
		return nil, nil, &RecordContextError{Entry: "Snapshot", Field: "required"}
	}
	if len(data) == 0 {
		return []byte{}, []byte{}, nil
	}
	decoded, err := DecodeRecord(data)
	if err != nil {
		return nil, nil, &RecordContextError{Entry: "Snapshot", Field: "invalid"}
	}
	snapshot, ok := decoded.(SnapshotRecord)
	if !ok {
		return nil, nil, &RecordContextError{Entry: "Snapshot", Field: "wrongType"}
	}
	blobCID := cid.Cid(snapshot.Blob.Ref).Bytes()
	if len(blobCID) > vault.MaxParentBytes {
		return nil, nil, &RecordContextError{Entry: "Snapshot", Field: "blobCid"}
	}
	return blobCID, blobCID, nil
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
