package vault

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"unicode/utf8"
)

type Role uint8

const (
	RoleRoot Role = 1 + iota
	RolePublisher
	RoleRestoreOnly
)

const (
	minPolicyMaxPublications uint32 = 1
	maxPolicyMaxPublications uint32 = 100000
	minPolicyMaxEpochAge     uint32 = 3600
	maxPolicyMaxEpochAge     uint32 = 31536000
)

type Signer struct {
	DeviceID string
	KeyID    []byte
}

type RoleBinding struct {
	DeviceID string
	Role     Role
}

type PolicyRecipient struct {
	DeviceID  string
	KeyID     []byte
	PublicKey [32]byte
}

type Policy struct {
	Vault                  [32]byte
	EpochSeq               uint64
	Roles                  []RoleBinding
	Recipients             []PolicyRecipient
	PolicyRetentionFloor   uint64
	RetainedRecoveryPoints uint16
	MaxPublications        uint32
	MaxEpochAge            uint32
	RecoveryAnchor         [32]byte
	PrevPolicyDigest       [32]byte
	Signer                 Signer
	Signature              [ed25519.SignatureSize]byte
}

type RevokedDevice struct {
	DeviceID  string
	CertEpoch uint64
}

type Control struct {
	Vault           [32]byte
	EpochSeq        uint64
	PolicyDigest    [32]byte
	HeadSnapshotCID []byte
	Revoked         []RevokedDevice
	PrevControlCID  []byte
	Signer          Signer
	Signature       [ed25519.SignatureSize]byte
}

type Certificate struct {
	Vault               [32]byte
	DeviceID            string
	KeyID               []byte
	SigningPublicKey    [ed25519.PublicKeySize]byte
	EncryptionPublicKey [32]byte
	Role                Role
	CertEpoch           uint64
	Issuer              string
	RevocationRef       []byte
	Signer              Signer
	Signature           [ed25519.SignatureSize]byte
}

type Checkpoint struct {
	Vault        [32]byte
	SnapshotCID  []byte
	EpochSeq     uint64
	PolicyDigest [32]byte
	Anchor       [32]byte
	ControlCID   []byte
	Signer       Signer
	Signature    [ed25519.SignatureSize]byte
}

type Head struct {
	Vault            [32]byte
	EpochSeq         uint64
	PolicyDigest     [32]byte
	SnapshotCID      []byte
	BlobCID          []byte
	PublicationCount uint64
	PrevHeadCID      []byte
	Signer           Signer
	Signature        [ed25519.SignatureSize]byte
}

type Attestation struct {
	SchemaVersion          uint8
	Vault                  [32]byte
	DeviceID               string
	PolicyDigest           [32]byte
	RetentionFloor         uint64
	RetainedRecoveryPoints uint16
	RecoveryPoints         []RetentionRecoveryPoint
	ControlCID             []byte
	Signer                 Signer
	Signature              [ed25519.SignatureSize]byte
}

const (
	AttestationVersion1   uint8  = 1
	AttestationVersion2   uint8  = 2
	MaxAttestationInteger uint64 = 1<<53 - 1
)

func EncodePolicy(value Policy) ([]byte, error) {
	prefix, err := encodePolicyPrefix(value)
	if err != nil {
		return nil, err
	}
	return append(prefix, value.Signature[:]...), nil
}

func DecodePolicy(data []byte) (Policy, error) {
	if err := validateHeader(data, objectKindPolicy, false); err != nil {
		return Policy{}, err
	}
	if len(data) > MaxPolicyObjectBytes {
		return Policy{}, fmt.Errorf("%w: policy", ErrLimit)
	}
	if err := scanPolicy(data); err != nil {
		return Policy{}, err
	}
	cursor := wireCursor{data: data, offset: 5}
	value := Policy{}
	fixed, _ := cursor.take(32)
	copy(value.Vault[:], fixed)
	value.EpochSeq = cursor.u64()
	roleCount := int(cursor.u16())
	value.Roles = make([]RoleBinding, roleCount)
	for index := range value.Roles {
		value.Roles[index].DeviceID = string(cursor.bytes16(MaxDeviceIDBytes))
		role, _ := cursor.take(1)
		value.Roles[index].Role = Role(role[0])
	}
	recipientCount := int(cursor.u16())
	value.Recipients = make([]PolicyRecipient, recipientCount)
	for index := range value.Recipients {
		value.Recipients[index].DeviceID = string(cursor.bytes16(MaxDeviceIDBytes))
		value.Recipients[index].KeyID = cursor.bytes16(MaxKeyIDBytes)
		fixed, _ = cursor.take(32)
		copy(value.Recipients[index].PublicKey[:], fixed)
	}
	value.PolicyRetentionFloor = cursor.u64()
	value.RetainedRecoveryPoints = cursor.u16()
	value.MaxPublications = cursor.u32()
	value.MaxEpochAge = cursor.u32()
	fixed, _ = cursor.take(32)
	copy(value.RecoveryAnchor[:], fixed)
	fixed, _ = cursor.take(32)
	copy(value.PrevPolicyDigest[:], fixed)
	value.Signer = decodeSigner(&cursor)
	fixed, _ = cursor.take(ed25519.SignatureSize)
	copy(value.Signature[:], fixed)
	return value, nil
}

func EncodeControl(value Control) ([]byte, error) {
	prefix, err := encodeControlPrefix(value)
	if err != nil {
		return nil, err
	}
	return append(prefix, value.Signature[:]...), nil
}

func DecodeControl(data []byte) (Control, error) {
	if err := validateHeader(data, objectKindControl, false); err != nil {
		return Control{}, err
	}
	if len(data) > MaxPolicyObjectBytes {
		return Control{}, fmt.Errorf("%w: control", ErrLimit)
	}
	if err := scanControl(data); err != nil {
		return Control{}, err
	}
	cursor := wireCursor{data: data, offset: 5}
	value := Control{}
	fixed, _ := cursor.take(32)
	copy(value.Vault[:], fixed)
	value.EpochSeq = cursor.u64()
	fixed, _ = cursor.take(32)
	copy(value.PolicyDigest[:], fixed)
	value.HeadSnapshotCID = cursor.bytes16(MaxParentBytes)
	revokedCount := int(cursor.u16())
	value.Revoked = make([]RevokedDevice, revokedCount)
	for index := range value.Revoked {
		value.Revoked[index].DeviceID = string(cursor.bytes16(MaxDeviceIDBytes))
		value.Revoked[index].CertEpoch = cursor.u64()
	}
	value.PrevControlCID = cursor.bytes16(MaxParentBytes)
	value.Signer = decodeSigner(&cursor)
	fixed, _ = cursor.take(ed25519.SignatureSize)
	copy(value.Signature[:], fixed)
	return value, nil
}

func EncodeCertificate(value Certificate) ([]byte, error) {
	prefix, err := encodeCertificatePrefix(value)
	if err != nil {
		return nil, err
	}
	return append(prefix, value.Signature[:]...), nil
}

func DecodeCertificate(data []byte) (Certificate, error) {
	if err := validateHeader(data, objectKindCertificate, false); err != nil {
		return Certificate{}, err
	}
	if len(data) > MaxPolicyObjectBytes {
		return Certificate{}, fmt.Errorf("%w: certificate", ErrLimit)
	}
	if err := scanCertificate(data); err != nil {
		return Certificate{}, err
	}
	cursor := wireCursor{data: data, offset: 5}
	value := Certificate{}
	fixed, _ := cursor.take(32)
	copy(value.Vault[:], fixed)
	value.DeviceID = string(cursor.bytes16(MaxDeviceIDBytes))
	value.KeyID = cursor.bytes16(MaxKeyIDBytes)
	fixed, _ = cursor.take(ed25519.PublicKeySize)
	copy(value.SigningPublicKey[:], fixed)
	fixed, _ = cursor.take(32)
	copy(value.EncryptionPublicKey[:], fixed)
	role, _ := cursor.take(1)
	value.Role = Role(role[0])
	value.CertEpoch = cursor.u64()
	value.Issuer = string(cursor.bytes16(MaxDeviceIDBytes))
	value.RevocationRef = cursor.bytes16(MaxParentBytes)
	value.Signer = decodeSigner(&cursor)
	fixed, _ = cursor.take(ed25519.SignatureSize)
	copy(value.Signature[:], fixed)
	return value, nil
}

func EncodeCheckpoint(value Checkpoint) ([]byte, error) {
	prefix, err := encodeCheckpointPrefix(value)
	if err != nil {
		return nil, err
	}
	return append(prefix, value.Signature[:]...), nil
}

func DecodeCheckpoint(data []byte) (Checkpoint, error) {
	if err := validateHeader(data, objectKindCheckpoint, false); err != nil {
		return Checkpoint{}, err
	}
	if len(data) > MaxPolicyObjectBytes {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint", ErrLimit)
	}
	if err := scanCheckpoint(data); err != nil {
		return Checkpoint{}, err
	}
	cursor := wireCursor{data: data, offset: 5}
	value := Checkpoint{}
	fixed, _ := cursor.take(32)
	copy(value.Vault[:], fixed)
	value.SnapshotCID = cursor.bytes16(MaxParentBytes)
	value.EpochSeq = cursor.u64()
	fixed, _ = cursor.take(32)
	copy(value.PolicyDigest[:], fixed)
	fixed, _ = cursor.take(32)
	copy(value.Anchor[:], fixed)
	value.ControlCID = cursor.bytes16(MaxParentBytes)
	value.Signer = decodeSigner(&cursor)
	fixed, _ = cursor.take(ed25519.SignatureSize)
	copy(value.Signature[:], fixed)
	return value, nil
}

func EncodeAttestation(value Attestation) ([]byte, error) {
	prefix, err := encodeAttestationPrefix(value)
	if err != nil {
		return nil, err
	}
	return append(prefix, value.Signature[:]...), nil
}

func DecodeAttestation(data []byte) (Attestation, error) {
	if err := validateHeader(data, objectKindAttestation, false); err != nil {
		return Attestation{}, err
	}
	if len(data) > MaxPolicyObjectBytes {
		return Attestation{}, fmt.Errorf("%w: attestation", ErrLimit)
	}
	version := AttestationVersion1
	if legacyErr := scanAttestationV1(data); legacyErr != nil {
		if len(data) >= 7 && data[5] == 0 {
			bodyVersion := uint16(data[5])<<8 | uint16(data[6])
			if bodyVersion == uint16(AttestationVersion2) {
				if err := scanAttestationV2(data); err != nil {
					return Attestation{}, err
				}
				version = AttestationVersion2
			} else if bodyVersion > uint16(AttestationVersion2) {
				return Attestation{}, fmt.Errorf("%w: attestation body version", ErrUnsupportedVersion)
			} else {
				return Attestation{}, legacyErr
			}
		} else {
			return Attestation{}, legacyErr
		}
	}
	cursor := wireCursor{data: data, offset: 5}
	value := Attestation{SchemaVersion: version}
	if version == AttestationVersion2 {
		_ = cursor.u16()
	}
	fixed, _ := cursor.take(32)
	copy(value.Vault[:], fixed)
	value.DeviceID = string(cursor.bytes16(MaxDeviceIDBytes))
	fixed, _ = cursor.take(32)
	copy(value.PolicyDigest[:], fixed)
	value.RetentionFloor = cursor.u64()
	value.RetainedRecoveryPoints = cursor.u16()
	if version == AttestationVersion2 {
		count := int(cursor.u16())
		value.RecoveryPoints = make([]RetentionRecoveryPoint, count)
		for index := range value.RecoveryPoints {
			value.RecoveryPoints[index] = RetentionRecoveryPoint{Epoch: cursor.u64(), SnapshotCID: cursor.bytes16(MaxParentBytes)}
		}
	}
	value.ControlCID = cursor.bytes16(MaxParentBytes)
	value.Signer = decodeSigner(&cursor)
	fixed, _ = cursor.take(ed25519.SignatureSize)
	copy(value.Signature[:], fixed)
	return value, nil
}

func ComputePolicyDigest(encoded []byte) ([32]byte, error) {
	if _, err := DecodePolicy(encoded); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte(preimagePolicy), encoded...)), nil
}

func encodePolicyPrefix(value Policy) ([]byte, error) {
	if err := validateRole(value.Signer, value.Roles); err != nil {
		return nil, err
	}
	if len(value.Roles) > 65535 || len(value.Recipients) > MaxRecipients {
		return nil, fmt.Errorf("%w: policy arrays", ErrLimit)
	}
	buffer := appendHeader(nil, objectKindPolicy)
	buffer = append(buffer, value.Vault[:]...)
	buffer = appendU64(buffer, value.EpochSeq)
	buffer = appendU16(buffer, uint16(len(value.Roles)))
	for _, binding := range value.Roles {
		if err := validateDeviceID(binding.DeviceID); err != nil {
			return nil, err
		}
		if !validRole(binding.Role) {
			return nil, fmt.Errorf("%w: role", ErrFormat)
		}
		buffer = appendBytes16(buffer, []byte(binding.DeviceID))
		buffer = append(buffer, byte(binding.Role))
	}
	buffer = appendU16(buffer, uint16(len(value.Recipients)))
	for _, recipient := range value.Recipients {
		if err := validateDeviceID(recipient.DeviceID); err != nil {
			return nil, err
		}
		if len(recipient.KeyID) > MaxKeyIDBytes {
			return nil, fmt.Errorf("%w: key_id", ErrLimit)
		}
		buffer = appendBytes16(buffer, []byte(recipient.DeviceID))
		buffer = appendBytes16(buffer, recipient.KeyID)
		buffer = append(buffer, recipient.PublicKey[:]...)
	}
	buffer = appendU64(buffer, value.PolicyRetentionFloor)
	buffer = appendU16(buffer, value.RetainedRecoveryPoints)
	buffer = appendU32(buffer, value.MaxPublications)
	buffer = appendU32(buffer, value.MaxEpochAge)
	buffer = append(buffer, value.RecoveryAnchor[:]...)
	buffer = append(buffer, value.PrevPolicyDigest[:]...)
	buffer = appendSigner(buffer, value.Signer)
	return limitObject(buffer)
}

func encodeControlPrefix(value Control) ([]byte, error) {
	if len(value.HeadSnapshotCID) > MaxParentBytes || len(value.PrevControlCID) > MaxParentBytes || len(value.Revoked) > 65535 {
		return nil, fmt.Errorf("%w: control fields", ErrLimit)
	}
	if err := validateSigner(value.Signer); err != nil {
		return nil, err
	}
	buffer := appendHeader(nil, objectKindControl)
	buffer = append(buffer, value.Vault[:]...)
	buffer = appendU64(buffer, value.EpochSeq)
	buffer = append(buffer, value.PolicyDigest[:]...)
	buffer = appendBytes16(buffer, value.HeadSnapshotCID)
	buffer = appendU16(buffer, uint16(len(value.Revoked)))
	for _, revoked := range value.Revoked {
		if err := validateDeviceID(revoked.DeviceID); err != nil {
			return nil, err
		}
		buffer = appendBytes16(buffer, []byte(revoked.DeviceID))
		buffer = appendU64(buffer, revoked.CertEpoch)
	}
	buffer = appendBytes16(buffer, value.PrevControlCID)
	buffer = appendSigner(buffer, value.Signer)
	return limitObject(buffer)
}

func encodeCertificatePrefix(value Certificate) ([]byte, error) {
	if err := validateDeviceID(value.DeviceID); err != nil {
		return nil, err
	}
	if err := validateDeviceID(value.Issuer); err != nil {
		return nil, err
	}
	if !validRole(value.Role) || len(value.KeyID) > MaxKeyIDBytes || len(value.RevocationRef) > MaxParentBytes {
		return nil, fmt.Errorf("%w: certificate fields", ErrFormat)
	}
	if err := validateSigner(value.Signer); err != nil {
		return nil, err
	}
	buffer := appendHeader(nil, objectKindCertificate)
	buffer = append(buffer, value.Vault[:]...)
	buffer = appendBytes16(buffer, []byte(value.DeviceID))
	buffer = appendBytes16(buffer, value.KeyID)
	buffer = append(buffer, value.SigningPublicKey[:]...)
	buffer = append(buffer, value.EncryptionPublicKey[:]...)
	buffer = append(buffer, byte(value.Role))
	buffer = appendU64(buffer, value.CertEpoch)
	buffer = appendBytes16(buffer, []byte(value.Issuer))
	buffer = appendBytes16(buffer, value.RevocationRef)
	buffer = appendSigner(buffer, value.Signer)
	return limitObject(buffer)
}

func encodeCheckpointPrefix(value Checkpoint) ([]byte, error) {
	if len(value.SnapshotCID) > MaxParentBytes || len(value.ControlCID) > MaxParentBytes {
		return nil, fmt.Errorf("%w: checkpoint CID", ErrLimit)
	}
	if err := validateSigner(value.Signer); err != nil {
		return nil, err
	}
	buffer := appendHeader(nil, objectKindCheckpoint)
	buffer = append(buffer, value.Vault[:]...)
	buffer = appendBytes16(buffer, value.SnapshotCID)
	buffer = appendU64(buffer, value.EpochSeq)
	buffer = append(buffer, value.PolicyDigest[:]...)
	buffer = append(buffer, value.Anchor[:]...)
	buffer = appendBytes16(buffer, value.ControlCID)
	buffer = appendSigner(buffer, value.Signer)
	return limitObject(buffer)
}

func EncodeHead(value Head) ([]byte, error) {
	prefix, err := encodeHeadPrefix(value)
	if err != nil {
		return nil, err
	}
	return append(prefix, value.Signature[:]...), nil
}

func DecodeHead(data []byte) (Head, error) {
	if err := validateHeader(data, objectKindHead, false); err != nil {
		return Head{}, err
	}
	if len(data) > MaxPolicyObjectBytes {
		return Head{}, fmt.Errorf("%w: head", ErrLimit)
	}
	if err := scanHead(data); err != nil {
		return Head{}, err
	}
	cursor := wireCursor{data: data, offset: 5}
	value := Head{}
	fixed, _ := cursor.take(32)
	copy(value.Vault[:], fixed)
	value.EpochSeq = cursor.u64()
	fixed, _ = cursor.take(32)
	copy(value.PolicyDigest[:], fixed)
	value.SnapshotCID = cursor.bytes16(MaxParentBytes)
	value.BlobCID = cursor.bytes16(MaxParentBytes)
	value.PublicationCount = cursor.u64()
	value.PrevHeadCID = cursor.bytes16(MaxParentBytes)
	value.Signer = decodeSigner(&cursor)
	fixed, _ = cursor.take(ed25519.SignatureSize)
	copy(value.Signature[:], fixed)
	return value, nil
}

func encodeHeadPrefix(value Head) ([]byte, error) {
	if len(value.SnapshotCID) > MaxParentBytes || len(value.BlobCID) > MaxParentBytes || len(value.PrevHeadCID) > MaxParentBytes {
		return nil, fmt.Errorf("%w: head CID", ErrLimit)
	}
	if err := validateSigner(value.Signer); err != nil {
		return nil, err
	}
	buffer := appendHeader(nil, objectKindHead)
	buffer = append(buffer, value.Vault[:]...)
	buffer = appendU64(buffer, value.EpochSeq)
	buffer = append(buffer, value.PolicyDigest[:]...)
	buffer = appendBytes16(buffer, value.SnapshotCID)
	buffer = appendBytes16(buffer, value.BlobCID)
	buffer = appendU64(buffer, value.PublicationCount)
	buffer = appendBytes16(buffer, value.PrevHeadCID)
	buffer = appendSigner(buffer, value.Signer)
	return limitObject(buffer)
}

func scanHead(data []byte) error {
	cursor := wireCursor{data: data, offset: 5}
	if !cursor.skip(32 + 8 + 32) {
		return cursor.err
	}
	for _, limit := range []int{MaxParentBytes, MaxParentBytes} {
		if err := scanBytes16(&cursor, limit); err != nil {
			return err
		}
	}
	if !cursor.skip(8) {
		return cursor.err
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	if err := scanSigner(&cursor); err != nil {
		return err
	}
	return finishObjectScan(&cursor, data)
}

func encodeAttestationPrefix(value Attestation) ([]byte, error) {
	if err := validateDeviceID(value.DeviceID); err != nil {
		return nil, err
	}
	if len(value.ControlCID) > MaxParentBytes {
		return nil, fmt.Errorf("%w: control_cid", ErrLimit)
	}
	if err := validateSigner(value.Signer); err != nil {
		return nil, err
	}
	version := attestationVersion(value)
	if version != AttestationVersion1 && version != AttestationVersion2 {
		return nil, fmt.Errorf("%w: attestation version", ErrUnsupportedVersion)
	}
	if version == AttestationVersion1 && len(value.RecoveryPoints) != 0 {
		return nil, fmt.Errorf("%w: version 1 attestation has recovery points", ErrFormat)
	}
	if version == AttestationVersion2 {
		if value.RetentionFloor > MaxAttestationInteger {
			return nil, fmt.Errorf("%w: retention floor", ErrLimit)
		}
		if len(value.RecoveryPoints) > int(^uint16(0)) {
			return nil, fmt.Errorf("%w: recovery points", ErrLimit)
		}
		if len(value.RecoveryPoints) != int(value.RetainedRecoveryPoints) {
			return nil, fmt.Errorf("%w: retained recovery point count mismatch", ErrFormat)
		}
		if err := validateAttestationRecoveryPoints(value.RecoveryPoints); err != nil {
			return nil, err
		}
	}
	buffer := appendHeader(nil, objectKindAttestation)
	if version == AttestationVersion2 {
		buffer = appendU16(buffer, uint16(version))
	}
	buffer = append(buffer, value.Vault[:]...)
	buffer = appendBytes16(buffer, []byte(value.DeviceID))
	buffer = append(buffer, value.PolicyDigest[:]...)
	buffer = appendU64(buffer, value.RetentionFloor)
	buffer = appendU16(buffer, value.RetainedRecoveryPoints)
	if version == AttestationVersion2 {
		buffer = appendU16(buffer, uint16(len(value.RecoveryPoints)))
		for _, point := range value.RecoveryPoints {
			buffer = appendU64(buffer, point.Epoch)
			buffer = appendBytes16(buffer, point.SnapshotCID)
		}
	}
	buffer = appendBytes16(buffer, value.ControlCID)
	buffer = appendSigner(buffer, value.Signer)
	return limitObject(buffer)
}

func scanPolicy(data []byte) error {
	cursor := wireCursor{data: data, offset: 5}
	if !cursor.skip(32 + 8) {
		return cursor.err
	}
	roleCount := int(cursor.u16())
	for index := 0; index < roleCount; index++ {
		if err := scanString16(&cursor, MaxDeviceIDBytes); err != nil {
			return err
		}
		role, ok := cursor.take(1)
		if !ok {
			return cursor.err
		}
		if !validRole(Role(role[0])) {
			return fmt.Errorf("%w: role", ErrFormat)
		}
	}
	recipientCount := int(cursor.u16())
	if cursor.err != nil {
		return cursor.err
	}
	if recipientCount > MaxRecipients {
		return fmt.Errorf("%w: recipients", ErrLimit)
	}
	for index := 0; index < recipientCount; index++ {
		if err := scanString16(&cursor, MaxDeviceIDBytes); err != nil {
			return err
		}
		if err := scanBytes16(&cursor, MaxKeyIDBytes); err != nil {
			return err
		}
		if !cursor.skip(32) {
			return cursor.err
		}
	}
	if !cursor.skip(8 + 2) {
		return cursor.err
	}
	maxPublications := cursor.u32()
	if cursor.err != nil {
		return cursor.err
	}
	if maxPublications < minPolicyMaxPublications || maxPublications > maxPolicyMaxPublications {
		return fmt.Errorf("%w: max_publications", ErrLimit)
	}
	maxEpochAge := cursor.u32()
	if cursor.err != nil {
		return cursor.err
	}
	if maxEpochAge < minPolicyMaxEpochAge || maxEpochAge > maxPolicyMaxEpochAge {
		return fmt.Errorf("%w: max_epoch_age", ErrLimit)
	}
	if !cursor.skip(32 + 32) {
		return cursor.err
	}
	if err := scanSigner(&cursor); err != nil {
		return err
	}
	return finishObjectScan(&cursor, data)
}

func scanControl(data []byte) error {
	cursor := wireCursor{data: data, offset: 5}
	if !cursor.skip(32 + 8 + 32) {
		return cursor.err
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	revokedCount := int(cursor.u16())
	if cursor.err != nil {
		return cursor.err
	}
	for index := 0; index < revokedCount; index++ {
		if err := scanString16(&cursor, MaxDeviceIDBytes); err != nil {
			return err
		}
		if !cursor.skip(8) {
			return cursor.err
		}
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	if err := scanSigner(&cursor); err != nil {
		return err
	}
	return finishObjectScan(&cursor, data)
}

func scanCertificate(data []byte) error {
	cursor := wireCursor{data: data, offset: 5}
	if !cursor.skip(32) {
		return cursor.err
	}
	if err := scanString16(&cursor, MaxDeviceIDBytes); err != nil {
		return err
	}
	if err := scanBytes16(&cursor, MaxKeyIDBytes); err != nil {
		return err
	}
	if !cursor.skip(32 + 32) {
		return cursor.err
	}
	role, ok := cursor.take(1)
	if !ok {
		return cursor.err
	}
	if !validRole(Role(role[0])) {
		return fmt.Errorf("%w: role", ErrFormat)
	}
	if !cursor.skip(8) {
		return cursor.err
	}
	if err := scanString16(&cursor, MaxDeviceIDBytes); err != nil {
		return err
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	if err := scanSigner(&cursor); err != nil {
		return err
	}
	return finishObjectScan(&cursor, data)
}

func scanCheckpoint(data []byte) error {
	cursor := wireCursor{data: data, offset: 5}
	if !cursor.skip(32) {
		return cursor.err
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	if !cursor.skip(8 + 32 + 32) {
		return cursor.err
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	if err := scanSigner(&cursor); err != nil {
		return err
	}
	return finishObjectScan(&cursor, data)
}

func scanAttestationV1(data []byte) error {
	cursor := wireCursor{data: data, offset: 5}
	if !cursor.skip(32) {
		return cursor.err
	}
	if err := scanString16(&cursor, MaxDeviceIDBytes); err != nil {
		return err
	}
	if !cursor.skip(32 + 8 + 2) {
		return cursor.err
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	if err := scanSigner(&cursor); err != nil {
		return err
	}
	return finishObjectScan(&cursor, data)
}

func scanAttestationV2(data []byte) error {
	cursor := wireCursor{data: data, offset: 5}
	if version := cursor.u16(); cursor.err != nil || version != uint16(AttestationVersion2) {
		return fmt.Errorf("%w: attestation body version", ErrUnsupportedVersion)
	}
	if !cursor.skip(32) {
		return cursor.err
	}
	if err := scanString16(&cursor, MaxDeviceIDBytes); err != nil {
		return err
	}
	if !cursor.skip(32) {
		return cursor.err
	}
	retentionFloor := cursor.u64()
	if cursor.err != nil {
		return cursor.err
	}
	if retentionFloor > MaxAttestationInteger {
		return fmt.Errorf("%w: retention floor", ErrLimit)
	}
	count := cursor.u16()
	pointCount := int(cursor.u16())
	if cursor.err != nil {
		return cursor.err
	}
	if pointCount != int(count) {
		return fmt.Errorf("%w: retained recovery point count mismatch", ErrFormat)
	}
	var previous RetentionRecoveryPoint
	for index := 0; index < pointCount; index++ {
		point := RetentionRecoveryPoint{Epoch: cursor.u64()}
		if cursor.err != nil {
			return cursor.err
		}
		cidField := cursor.length16(MaxParentBytes)
		if !cidField.ok {
			return cidField.err
		}
		point.SnapshotCID = cursor.data[cidField.start : cidField.start+cidField.length]
		if len(point.SnapshotCID) == 0 || point.Epoch > MaxAttestationInteger {
			return fmt.Errorf("%w: recovery point bounds", ErrLimit)
		}
		if index > 0 && !retentionRecoveryPointLess(previous, point) {
			return fmt.Errorf("%w: recovery points are duplicate or out of order", ErrFormat)
		}
		previous = point
	}
	if err := scanBytes16(&cursor, MaxParentBytes); err != nil {
		return err
	}
	if err := scanSigner(&cursor); err != nil {
		return err
	}
	return finishObjectScan(&cursor, data)
}

func attestationVersion(value Attestation) uint8 {
	if value.SchemaVersion != 0 {
		return value.SchemaVersion
	}
	if len(value.RecoveryPoints) != 0 {
		return AttestationVersion2
	}
	return AttestationVersion1
}

func validateAttestationRecoveryPoints(points []RetentionRecoveryPoint) error {
	if len(points) > int(^uint16(0)) {
		return fmt.Errorf("%w: recovery points", ErrLimit)
	}
	for index, point := range points {
		if point.Epoch > MaxAttestationInteger || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > MaxParentBytes {
			return fmt.Errorf("%w: recovery point bounds", ErrLimit)
		}
		if index > 0 && !retentionRecoveryPointLess(points[index-1], point) {
			return fmt.Errorf("%w: recovery points are duplicate or out of order", ErrFormat)
		}
	}
	return nil
}

func scanSigner(cursor *wireCursor) error {
	if err := scanString16(cursor, MaxDeviceIDBytes); err != nil {
		return err
	}
	if err := scanBytes16(cursor, MaxKeyIDBytes); err != nil {
		return err
	}
	if !cursor.skip(ed25519.SignatureSize) {
		return cursor.err
	}
	return nil
}

func scanBytes16(cursor *wireCursor, maximum int) error {
	value := cursor.length16(maximum)
	if !value.ok {
		return value.err
	}
	return nil
}

func scanString16(cursor *wireCursor, maximum int) error {
	value := cursor.length16(maximum)
	if !value.ok {
		return value.err
	}
	if !utf8.Valid(cursor.data[value.start : value.start+value.length]) {
		return fmt.Errorf("%w: device_id", ErrFormat)
	}
	return nil
}

func finishObjectScan(cursor *wireCursor, data []byte) error {
	if cursor.err != nil {
		return cursor.err
	}
	if cursor.offset != len(data) {
		return fmt.Errorf("%w: trailing bytes", ErrFormat)
	}
	return nil
}

func appendSigner(buffer []byte, signer Signer) []byte {
	buffer = appendBytes16(buffer, []byte(signer.DeviceID))
	return appendBytes16(buffer, signer.KeyID)
}

func decodeSigner(cursor *wireCursor) Signer {
	return Signer{DeviceID: string(cursor.bytes16(MaxDeviceIDBytes)), KeyID: cursor.bytes16(MaxKeyIDBytes)}
}

func validateSigner(signer Signer) error {
	if err := validateDeviceID(signer.DeviceID); err != nil {
		return err
	}
	if len(signer.KeyID) > MaxKeyIDBytes {
		return fmt.Errorf("%w: signer key_id", ErrLimit)
	}
	return nil
}

func validateRole(signer Signer, bindings []RoleBinding) error {
	if err := validateSigner(signer); err != nil {
		return err
	}
	for _, binding := range bindings {
		if !validRole(binding.Role) {
			return fmt.Errorf("%w: role", ErrFormat)
		}
	}
	return nil
}

func validRole(role Role) bool {
	return role == RoleRoot || role == RolePublisher || role == RoleRestoreOnly
}

func validateDeviceID(deviceID string) error {
	if len(deviceID) > MaxDeviceIDBytes {
		return fmt.Errorf("%w: device_id", ErrLimit)
	}
	if !utf8.ValidString(deviceID) {
		return fmt.Errorf("%w: device_id", ErrFormat)
	}
	return nil
}

func limitObject(encoded []byte) ([]byte, error) {
	if len(encoded)+ed25519.SignatureSize > MaxPolicyObjectBytes {
		return nil, fmt.Errorf("%w: object", ErrLimit)
	}
	return encoded, nil
}

func objectSignaturePreimage(prefix []byte) []byte {
	preimage := make([]byte, 0, len(preimageSig)+len(prefix))
	preimage = append(preimage, preimageSig...)
	return append(preimage, prefix...)
}

func objectSignatureContext(kind byte) string {
	switch kind {
	case objectKindPolicy:
		return "dottie/v1/sig-policy"
	case objectKindControl:
		return "dottie/v1/sig-control"
	case objectKindCertificate:
		return "dottie/v1/sig-certificate"
	case objectKindCheckpoint:
		return "dottie/v1/sig-checkpoint"
	case objectKindAttestation:
		return "dottie/v1/sig-attestation"
	case objectKindHead:
		return "dottie/v1/sig-head"
	default:
		return ""
	}
}

func signObject(label string, prefix []byte, key ed25519.PrivateKey) ([ed25519.SignatureSize]byte, error) {
	var signature [ed25519.SignatureSize]byte
	encoded, err := Sign(label, objectSignaturePreimage(prefix), key)
	if err != nil {
		return signature, err
	}
	copy(signature[:], encoded)
	return signature, nil
}
