package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MaxEnvelopeBytes     = 384 << 20
	MaxCiphertextBytes   = 320 << 20
	MaxRecipients        = 64
	MaxDeviceIDBytes     = 255
	MaxKeyIDBytes        = 255
	MaxParentBytes       = 128
	MaxPolicyObjectBytes = 64 << 10
)

var (
	ErrFormat             = errors.New("invalid format field")
	ErrUnsupportedVersion = errors.New("unsupported version field")
	ErrLimit              = errors.New("limit exceeded for field")
	ErrRecipient          = errors.New("invalid recipient field")
	ErrPolicyRequired     = errors.New("policy is required for field")
	ErrAuthorization      = errors.New("authorization failed for field")
	ErrSignature          = errors.New("signature verification failed for field")
	ErrCommitment         = errors.New("commitment mismatch for field")
	ErrAuthentication     = errors.New("authentication failed for field")
)

const (
	PurposeSnapshot Purpose = 1 + iota
	PurposePolicy
	PurposeControl
	PurposeCertificate
	PurposeCheckpoint
	PurposeAttestation
)

const (
	objectKindEnvelope byte = 1 + iota
	objectKindPolicy
	objectKindControl
	objectKindCertificate
	objectKindCheckpoint
	objectKindAttestation
)

var wireMagic = [3]byte{'D', 'T', 'E'}

const wireVersion byte = 1

const (
	preimageAD       = "dottie/v1/ad"
	preimageSig      = "dottie/v1/sig"
	preimageWrapAD   = "dottie/v1/wrapad"
	preimageCommit   = "dottie/v1/commit"
	preimagePolicy   = "dottie/v1/policy"
	preimageWrapInfo = "dottie/v1/wrap"
)

type Purpose uint8

type Envelope struct {
	Purpose       Purpose
	Vault         [32]byte
	PublicationID [16]byte
	EpochSeq      uint64
	PolicyDigest  [32]byte
	Parent        []byte
	DeviceID      string
	KeyID         []byte
	Commit        [32]byte
	Recipients    []EnvelopeRecipient
	Nonce         [24]byte
	Ciphertext    []byte
	Tag           [16]byte
	Signature     [ed25519.SignatureSize]byte
}

type EnvelopeRecipient struct {
	KeyID      []byte
	Ephemeral  [32]byte
	WrapNonce  [24]byte
	WrappedKey []byte
}

type RecipientPublicKey struct {
	KeyID     []byte
	PublicKey []byte
}

type PreparedRecipient struct {
	KeyID            []byte
	PublicKey        []byte
	EphemeralPrivate []byte
	WrapNonce        [24]byte
}

type SealRequest struct {
	Purpose       Purpose
	Vault         [32]byte
	PublicationID [16]byte
	EpochSeq      uint64
	PolicyDigest  [32]byte
	Parent        []byte
	DeviceID      string
	KeyID         []byte
	Plaintext     []byte
	SigningKey    ed25519.PrivateKey
	Recipients    []RecipientPublicKey
}

type PreparedSeal struct {
	Purpose       Purpose
	Vault         [32]byte
	PublicationID [16]byte
	EpochSeq      uint64
	PolicyDigest  [32]byte
	Parent        []byte
	DeviceID      string
	KeyID         []byte
	Plaintext     []byte
	SigningKey    ed25519.PrivateKey
	ContentKey    []byte
	Nonce         [24]byte
	Recipients    []PreparedRecipient
}

type OpenRequest struct {
	Vault        [32]byte
	EpochSeq     uint64
	PolicyDigest [32]byte
	Policy       []byte
	Control      []byte
	TrustAnchor  [32]byte
	Certificates [][]byte
	DeviceKeyID  []byte
	DeviceKey    *ecdh.PrivateKey
}

func validPurpose(p Purpose) bool {
	return p >= PurposeSnapshot && p <= PurposeAttestation
}

func contextForPurpose(p Purpose) string {
	switch p {
	case PurposeSnapshot:
		return "dottie/v1/sig-snapshot"
	case PurposePolicy:
		return "dottie/v1/sig-policy"
	case PurposeControl:
		return "dottie/v1/sig-control"
	case PurposeCertificate:
		return "dottie/v1/sig-certificate"
	case PurposeCheckpoint:
		return "dottie/v1/sig-checkpoint"
	case PurposeAttestation:
		return "dottie/v1/sig-attestation"
	default:
		return ""
	}
}

func Sign(label string, preimage []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || !knownSignatureContext(label) {
		return nil, fmt.Errorf("%w: signature context or key", ErrFormat)
	}
	return key.Sign(nil, preimage, &ed25519.Options{Context: label})
}

func Verify(label string, preimage, signature []byte, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !knownSignatureContext(label) {
		return fmt.Errorf("%w: signature context or key", ErrFormat)
	}
	if err := ed25519.VerifyWithOptions(key, preimage, signature, &ed25519.Options{Context: label}); err != nil {
		return fmt.Errorf("%w: signature", ErrSignature)
	}
	return nil
}

func knownSignatureContext(label string) bool {
	switch label {
	case "dottie/v1/sig-snapshot", "dottie/v1/sig-record", "dottie/v1/sig-policy", "dottie/v1/sig-control", "dottie/v1/sig-certificate", "dottie/v1/sig-checkpoint", "dottie/v1/sig-attestation":
		return true
	default:
		return false
	}
}

func Seal(request SealRequest) (Envelope, error) {
	contentKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(contentKey); err != nil {
		return Envelope{}, fmt.Errorf("%w: content key", ErrAuthentication)
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Envelope{}, fmt.Errorf("%w: nonce", ErrAuthentication)
	}
	if len(request.Recipients) == 0 || len(request.Recipients) > MaxRecipients {
		return Envelope{}, fmt.Errorf("%w: recipients", ErrLimit)
	}
	prepared := PreparedSeal{
		Purpose: request.Purpose, Vault: request.Vault, PublicationID: request.PublicationID,
		EpochSeq: request.EpochSeq, PolicyDigest: request.PolicyDigest, Parent: request.Parent,
		DeviceID: request.DeviceID, KeyID: request.KeyID, Plaintext: request.Plaintext,
		SigningKey: request.SigningKey, ContentKey: contentKey, Nonce: nonce,
		Recipients: make([]PreparedRecipient, 0, len(request.Recipients)),
	}
	for _, recipient := range request.Recipients {
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return Envelope{}, fmt.Errorf("%w: ephemeral key", ErrRecipient)
		}
		var wrapNonce [24]byte
		if _, err := rand.Read(wrapNonce[:]); err != nil {
			return Envelope{}, fmt.Errorf("%w: wrap nonce", ErrAuthentication)
		}
		prepared.Recipients = append(prepared.Recipients, PreparedRecipient{
			KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey),
			EphemeralPrivate: privateKey.Bytes(), WrapNonce: wrapNonce,
		})
	}
	return SealPrepared(prepared)
}

func SealPrepared(prepared PreparedSeal) (Envelope, error) {
	if !validPurpose(prepared.Purpose) {
		return Envelope{}, fmt.Errorf("%w: purpose", ErrFormat)
	}
	if len(prepared.SigningKey) != ed25519.PrivateKeySize || len(prepared.ContentKey) != chacha20poly1305.KeySize {
		return Envelope{}, fmt.Errorf("%w: signing key or content key", ErrFormat)
	}
	if err := validateEnvelopeMetadata(prepared.Parent, prepared.DeviceID, prepared.KeyID); err != nil {
		return Envelope{}, err
	}
	if len(prepared.Plaintext) > MaxCiphertextBytes {
		return Envelope{}, fmt.Errorf("%w: ciphertext", ErrLimit)
	}
	if len(prepared.Recipients) == 0 || len(prepared.Recipients) > MaxRecipients {
		return Envelope{}, fmt.Errorf("%w: recipients", ErrLimit)
	}
	recipients := append([]PreparedRecipient(nil), prepared.Recipients...)
	sort.Slice(recipients, func(i, j int) bool { return bytes.Compare(recipients[i].KeyID, recipients[j].KeyID) < 0 })
	for index := range recipients {
		if len(recipients[index].KeyID) > MaxKeyIDBytes || len(recipients[index].PublicKey) != 32 || len(recipients[index].EphemeralPrivate) != 32 {
			return Envelope{}, fmt.Errorf("%w: recipient", ErrRecipient)
		}
		if index > 0 && bytes.Equal(recipients[index-1].KeyID, recipients[index].KeyID) {
			return Envelope{}, fmt.Errorf("%w: recipient key_id", ErrRecipient)
		}
	}
	commit := commitment(prepared.ContentKey, prepared.Vault, prepared.EpochSeq)
	envelope := Envelope{
		Purpose: prepared.Purpose, Vault: prepared.Vault, PublicationID: prepared.PublicationID,
		EpochSeq: prepared.EpochSeq, PolicyDigest: prepared.PolicyDigest, Parent: bytes.Clone(prepared.Parent),
		DeviceID: prepared.DeviceID, KeyID: bytes.Clone(prepared.KeyID), Commit: commit,
		Nonce: prepared.Nonce,
	}
	for _, recipient := range recipients {
		privateKey, err := ecdh.X25519().NewPrivateKey(recipient.EphemeralPrivate)
		if err != nil {
			return Envelope{}, fmt.Errorf("%w: ephemeral private key", ErrRecipient)
		}
		recipientKey, err := ecdh.X25519().NewPublicKey(recipient.PublicKey)
		if err != nil {
			return Envelope{}, fmt.Errorf("%w: recipient public key", ErrRecipient)
		}
		sharedSecret, err := privateKey.ECDH(recipientKey)
		if err != nil {
			return Envelope{}, fmt.Errorf("%w: X25519", ErrRecipient)
		}
		ephemeralPublic := privateKey.PublicKey().Bytes()
		wrapKey, err := deriveWrapKey(sharedSecret, prepared.Vault, recipient.KeyID, prepared.EpochSeq, prepared.Purpose)
		if err != nil {
			return Envelope{}, fmt.Errorf("%w: wrap key", ErrRecipient)
		}
		wrapAD := wrapAssociatedData(prepared.Vault, recipient.KeyID, prepared.EpochSeq, prepared.Purpose, recipient.PublicKey, ephemeralPublic)
		wrapAEAD, err := chacha20poly1305.NewX(wrapKey)
		if err != nil {
			return Envelope{}, fmt.Errorf("%w: wrap key", ErrRecipient)
		}
		wrapped := wrapAEAD.Seal(nil, recipient.WrapNonce[:], prepared.ContentKey, wrapAD)
		var ephemeral [32]byte
		copy(ephemeral[:], ephemeralPublic)
		envelope.Recipients = append(envelope.Recipients, EnvelopeRecipient{
			KeyID: bytes.Clone(recipient.KeyID), Ephemeral: ephemeral,
			WrapNonce: recipient.WrapNonce, WrappedKey: wrapped,
		})
	}
	contentAEAD, err := chacha20poly1305.NewX(prepared.ContentKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: content key", ErrAuthentication)
	}
	sealed := contentAEAD.Seal(nil, prepared.Nonce[:], prepared.Plaintext, contentAssociatedData(envelope))
	if len(sealed) < chacha20poly1305.Overhead {
		return Envelope{}, fmt.Errorf("%w: content", ErrAuthentication)
	}
	envelope.Ciphertext = bytes.Clone(sealed[:len(sealed)-chacha20poly1305.Overhead])
	copy(envelope.Tag[:], sealed[len(sealed)-chacha20poly1305.Overhead:])
	prefix, err := encodeEnvelopePrefix(envelope)
	if err != nil {
		return Envelope{}, err
	}
	preimage := append([]byte(preimageSig), prefix...)
	signature, err := Sign(contextForPurpose(envelope.Purpose), preimage, prepared.SigningKey)
	if err != nil {
		return Envelope{}, err
	}
	copy(envelope.Signature[:], signature)
	return envelope, nil
}

func Open(envelope Envelope, request OpenRequest) ([]byte, error) {
	if !validPurpose(envelope.Purpose) {
		return nil, fmt.Errorf("%w: purpose", ErrFormat)
	}
	if err := validateEnvelopeFields(envelope); err != nil {
		return nil, err
	}
	policyBytes, err := requirePolicy(request.Policy)
	if err != nil {
		return nil, err
	}
	policy, err := DecodePolicy(policyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: policy", ErrAuthorization)
	}
	if policy.Vault != request.Vault {
		return nil, fmt.Errorf("%w: policy vault", ErrAuthorization)
	}
	policyDigest := sha256.Sum256(append([]byte(preimagePolicy), policyBytes...))
	if policyDigest != envelope.PolicyDigest {
		return nil, fmt.Errorf("%w: policy_digest", ErrAuthorization)
	}
	policySigner, err := resolveTrustedCertificate(policy.Signer.DeviceID, policy.Signer.KeyID, request)
	if err != nil || policySigner.Role != RoleRoot {
		return nil, fmt.Errorf("%w: policy signer", ErrAuthorization)
	}
	policyPrefix, err := encodePolicyPrefix(policy)
	if err != nil {
		return nil, fmt.Errorf("%w: policy", ErrAuthorization)
	}
	if err := Verify("dottie/v1/sig-policy", objectSignaturePreimage(policyPrefix), policy.Signature[:], policySigner.SigningPublicKey[:]); err != nil {
		return nil, fmt.Errorf("%w: policy signature", ErrSignature)
	}
	certificate, err := authorizedSigner(envelope, request, policy)
	if err != nil {
		return nil, err
	}
	if len(request.Control) > 0 {
		control, err := authorizeControl(request)
		if err != nil {
			return nil, err
		}
		if signerRevoked(certificate, control) {
			return nil, fmt.Errorf("%w: signer revocation", ErrAuthorization)
		}
	}
	if envelope.Vault != request.Vault || envelope.EpochSeq != request.EpochSeq || envelope.PolicyDigest != request.PolicyDigest {
		return nil, fmt.Errorf("%w: vault, epoch_seq, or policy_digest", ErrAuthorization)
	}
	prefix, err := encodeEnvelopePrefix(envelope)
	if err != nil {
		return nil, err
	}
	preimage := append([]byte(preimageSig), prefix...)
	if err := Verify(contextForPurpose(envelope.Purpose), preimage, envelope.Signature[:], certificate.SigningPublicKey[:]); err != nil {
		return nil, fmt.Errorf("%w: envelope", ErrSignature)
	}
	recipientIndex := -1
	for index, recipient := range envelope.Recipients {
		if bytes.Equal(recipient.KeyID, request.DeviceKeyID) {
			recipientIndex = index
			break
		}
	}
	if recipientIndex < 0 {
		return nil, fmt.Errorf("%w: key_id", ErrRecipient)
	}
	if request.DeviceKey == nil || len(request.DeviceKey.Bytes()) != 32 {
		return nil, fmt.Errorf("%w: device key", ErrRecipient)
	}
	devicePublic := request.DeviceKey.PublicKey().Bytes()
	policyRecipient, authorized := authorizedRecipient(policy, request.DeviceKeyID, devicePublic)
	if !authorized {
		return nil, fmt.Errorf("%w: recipient key_id", ErrRecipient)
	}
	recipient := envelope.Recipients[recipientIndex]
	if !bytes.Equal(recipient.KeyID, policyRecipient.KeyID) {
		return nil, fmt.Errorf("%w: recipient key_id", ErrRecipient)
	}
	ephemeralPublic, err := ecdh.X25519().NewPublicKey(recipient.Ephemeral[:])
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral", ErrRecipient)
	}
	sharedSecret, err := request.DeviceKey.ECDH(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral", ErrRecipient)
	}
	wrapKey, err := deriveWrapKey(sharedSecret, envelope.Vault, recipient.KeyID, envelope.EpochSeq, envelope.Purpose)
	if err != nil {
		return nil, fmt.Errorf("%w: wrapping", ErrRecipient)
	}
	wrapAD := wrapAssociatedData(envelope.Vault, recipient.KeyID, envelope.EpochSeq, envelope.Purpose, devicePublic, recipient.Ephemeral[:])
	wrapAEAD, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("%w: wrapping", ErrRecipient)
	}
	contentKey, err := wrapAEAD.Open(nil, recipient.WrapNonce[:], recipient.WrappedKey, wrapAD)
	if err != nil || len(contentKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: wrapped_key", ErrAuthentication)
	}
	if commitment(contentKey, envelope.Vault, envelope.EpochSeq) != envelope.Commit {
		return nil, fmt.Errorf("%w: commit", ErrCommitment)
	}
	contentAEAD, err := chacha20poly1305.NewX(contentKey)
	if err != nil {
		return nil, fmt.Errorf("%w: content key", ErrAuthentication)
	}
	sealed := make([]byte, 0, len(envelope.Ciphertext)+len(envelope.Tag))
	sealed = append(sealed, envelope.Ciphertext...)
	sealed = append(sealed, envelope.Tag[:]...)
	plaintext, err := contentAEAD.Open(nil, envelope.Nonce[:], sealed, contentAssociatedData(envelope))
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext", ErrAuthentication)
	}
	return plaintext, nil
}

func DecodeEnvelope(data []byte) (Envelope, error) {
	if err := validateHeader(data, objectKindEnvelope, true); err != nil {
		return Envelope{}, err
	}
	if len(data) > MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("%w: envelope", ErrLimit)
	}
	if err := scanEnvelope(data); err != nil {
		return Envelope{}, err
	}
	cursor := wireCursor{data: data, offset: 6}
	envelope := Envelope{}
	envelope.Purpose = Purpose(data[5])
	fixed, _ := cursor.take(32)
	copy(envelope.Vault[:], fixed)
	fixed, _ = cursor.take(16)
	copy(envelope.PublicationID[:], fixed)
	envelope.EpochSeq = cursor.u64()
	fixed, _ = cursor.take(32)
	copy(envelope.PolicyDigest[:], fixed)
	envelope.Parent = cursor.bytes16(MaxParentBytes)
	envelope.DeviceID = string(cursor.bytes16(MaxDeviceIDBytes))
	envelope.KeyID = cursor.bytes16(MaxKeyIDBytes)
	fixed, _ = cursor.take(32)
	copy(envelope.Commit[:], fixed)
	recipientCount := int(cursor.u16())
	envelope.Recipients = make([]EnvelopeRecipient, recipientCount)
	for index := range envelope.Recipients {
		recipient := &envelope.Recipients[index]
		recipient.KeyID = cursor.bytes16(MaxKeyIDBytes)
		fixed, _ = cursor.take(32)
		copy(recipient.Ephemeral[:], fixed)
		fixed, _ = cursor.take(24)
		copy(recipient.WrapNonce[:], fixed)
		recipient.WrappedKey = cursor.bytes16(64)
	}
	fixed, _ = cursor.take(24)
	copy(envelope.Nonce[:], fixed)
	ciphertextLen := int(cursor.u32())
	envelope.Ciphertext, _ = cursor.take(ciphertextLen)
	fixed, _ = cursor.take(16)
	copy(envelope.Tag[:], fixed)
	fixed, _ = cursor.take(ed25519.SignatureSize)
	copy(envelope.Signature[:], fixed)
	return envelope, nil
}

func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	if !validPurpose(envelope.Purpose) {
		return nil, fmt.Errorf("%w: purpose", ErrFormat)
	}
	if err := validateEnvelopeFields(envelope); err != nil {
		return nil, err
	}
	prefix, err := encodeEnvelopePrefix(envelope)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, len(prefix)+ed25519.SignatureSize)
	copy(encoded, prefix)
	copy(encoded[len(prefix):], envelope.Signature[:])
	if len(encoded) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope", ErrLimit)
	}
	return encoded, nil
}

func encodeEnvelopePrefix(envelope Envelope) ([]byte, error) {
	if err := validateEnvelopeFields(envelope); err != nil {
		return nil, err
	}
	capacity := 6 + 1 + 32 + 16 + 8 + 32 + 2 + len(envelope.Parent) + 2 + len(envelope.DeviceID) + 2 + len(envelope.KeyID) + 32 + 2 + 24 + 4 + len(envelope.Ciphertext) + 16
	for _, recipient := range envelope.Recipients {
		capacity += 2 + len(recipient.KeyID) + 32 + 24 + 2 + len(recipient.WrappedKey)
	}
	buffer := make([]byte, 0, capacity)
	buffer = appendHeader(buffer, objectKindEnvelope)
	buffer = append(buffer, byte(envelope.Purpose))
	buffer = append(buffer, envelope.Vault[:]...)
	buffer = append(buffer, envelope.PublicationID[:]...)
	buffer = appendU64(buffer, envelope.EpochSeq)
	buffer = append(buffer, envelope.PolicyDigest[:]...)
	buffer = appendBytes16(buffer, envelope.Parent)
	buffer = appendBytes16(buffer, []byte(envelope.DeviceID))
	buffer = appendBytes16(buffer, envelope.KeyID)
	buffer = append(buffer, envelope.Commit[:]...)
	buffer = appendU16(buffer, uint16(len(envelope.Recipients)))
	for _, recipient := range envelope.Recipients {
		buffer = appendBytes16(buffer, recipient.KeyID)
		buffer = append(buffer, recipient.Ephemeral[:]...)
		buffer = append(buffer, recipient.WrapNonce[:]...)
		buffer = appendBytes16(buffer, recipient.WrappedKey)
	}
	buffer = append(buffer, envelope.Nonce[:]...)
	buffer = appendU32(buffer, uint32(len(envelope.Ciphertext)))
	buffer = append(buffer, envelope.Ciphertext...)
	buffer = append(buffer, envelope.Tag[:]...)
	if len(buffer)+ed25519.SignatureSize > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope", ErrLimit)
	}
	return buffer, nil
}

func validateEnvelopeFields(envelope Envelope) error {
	if len(envelope.Ciphertext) > MaxCiphertextBytes {
		return fmt.Errorf("%w: ciphertext", ErrLimit)
	}
	if len(envelope.Recipients) > MaxRecipients {
		return fmt.Errorf("%w: recipients", ErrLimit)
	}
	if err := validateEnvelopeMetadata(envelope.Parent, envelope.DeviceID, envelope.KeyID); err != nil {
		return err
	}
	encodedLength := 6 + 1 + 32 + 16 + 8 + 32 + 2 + len(envelope.Parent) + 2 + len(envelope.DeviceID) + 2 + len(envelope.KeyID) + 32 + 2 + 24 + 4 + len(envelope.Ciphertext) + 16 + ed25519.SignatureSize
	for _, recipient := range envelope.Recipients {
		encodedLength += 2 + len(recipient.KeyID) + 32 + 24 + 2 + len(recipient.WrappedKey)
	}
	if encodedLength > MaxEnvelopeBytes {
		return fmt.Errorf("%w: envelope", ErrLimit)
	}
	for index, recipient := range envelope.Recipients {
		if len(recipient.KeyID) > MaxKeyIDBytes || len(recipient.WrappedKey) != 48 {
			return fmt.Errorf("%w: recipient", ErrRecipient)
		}
		if index > 0 && bytes.Compare(envelope.Recipients[index-1].KeyID, recipient.KeyID) >= 0 {
			return fmt.Errorf("%w: recipient order", ErrRecipient)
		}
	}
	return nil
}

func validateEnvelopeMetadata(parent []byte, deviceID string, keyID []byte) error {
	if len(parent) > MaxParentBytes || len(deviceID) > MaxDeviceIDBytes || !utf8.ValidString(deviceID) || len(keyID) > MaxKeyIDBytes {
		return fmt.Errorf("%w: parent, device_id, or key_id", ErrLimit)
	}
	return nil
}

func scanEnvelope(data []byte) error {
	if len(data) > MaxEnvelopeBytes {
		return fmt.Errorf("%w: envelope", ErrLimit)
	}
	cursor := wireCursor{data: data, offset: 6}
	if !cursor.skip(32 + 16 + 8 + 32) {
		return fmt.Errorf("%w: header", ErrFormat)
	}
	parent := cursor.length16(MaxParentBytes)
	if !parent.ok {
		return parent.err
	}
	device := cursor.length16(MaxDeviceIDBytes)
	if !device.ok {
		return device.err
	}
	if !utf8.Valid(data[device.start : device.start+device.length]) {
		return fmt.Errorf("%w: device_id", ErrFormat)
	}
	keyID := cursor.length16(MaxKeyIDBytes)
	if !keyID.ok {
		return keyID.err
	}
	if !cursor.skip(32) {
		return fmt.Errorf("%w: commit", ErrFormat)
	}
	count := int(cursor.u16())
	if cursor.err != nil {
		return cursor.err
	}
	if count > MaxRecipients {
		return fmt.Errorf("%w: recipients", ErrLimit)
	}
	var previous []byte
	for index := 0; index < count; index++ {
		id := cursor.length16(MaxKeyIDBytes)
		if !id.ok {
			return id.err
		}
		current := data[id.start : id.start+id.length]
		if index > 0 && bytes.Compare(previous, current) >= 0 {
			return fmt.Errorf("%w: recipient order", ErrRecipient)
		}
		previous = current
		if !cursor.skip(32 + 24) {
			return fmt.Errorf("%w: recipient keys", ErrFormat)
		}
		wrapped := cursor.length16(64)
		if !wrapped.ok {
			return wrapped.err
		}
		if wrapped.length != 48 {
			return fmt.Errorf("%w: wrapped_key", ErrRecipient)
		}
	}
	if !cursor.skip(24) {
		return fmt.Errorf("%w: nonce", ErrFormat)
	}
	ciphertextLength := cursor.u32()
	if cursor.err != nil {
		return cursor.err
	}
	if uint64(ciphertextLength) > MaxCiphertextBytes {
		return fmt.Errorf("%w: ciphertext", ErrLimit)
	}
	if !cursor.skip(int(ciphertextLength) + 16 + ed25519.SignatureSize) {
		return fmt.Errorf("%w: ciphertext or authentication fields", ErrFormat)
	}
	if cursor.offset != len(data) {
		return fmt.Errorf("%w: trailing bytes", ErrFormat)
	}
	return nil
}

func contentAssociatedData(envelope Envelope) []byte {
	buffer := make([]byte, 0, len(preimageAD)+4+1+32+16+8+32+2+len(envelope.Parent)+32)
	buffer = append(buffer, preimageAD...)
	buffer = append(buffer, wireMagic[:]...)
	buffer = append(buffer, wireVersion, byte(objectKindEnvelope), byte(envelope.Purpose))
	buffer = append(buffer, envelope.Vault[:]...)
	buffer = append(buffer, envelope.PublicationID[:]...)
	buffer = appendU64(buffer, envelope.EpochSeq)
	buffer = append(buffer, envelope.PolicyDigest[:]...)
	buffer = appendBytes16(buffer, envelope.Parent)
	buffer = append(buffer, envelope.Commit[:]...)
	return buffer
}

func wrapAssociatedData(vault [32]byte, keyID []byte, epoch uint64, purpose Purpose, recipientPublicKey, ephemeralPublicKey []byte) []byte {
	buffer := make([]byte, 0, len(preimageWrapAD)+32+2+len(keyID)+8+1+32+32)
	buffer = append(buffer, preimageWrapAD...)
	buffer = append(buffer, vault[:]...)
	buffer = appendBytes16(buffer, keyID)
	buffer = appendU64(buffer, epoch)
	buffer = append(buffer, byte(purpose))
	buffer = append(buffer, recipientPublicKey...)
	buffer = append(buffer, ephemeralPublicKey...)
	return buffer
}

func commitment(contentKey []byte, vault [32]byte, epoch uint64) [32]byte {
	buffer := make([]byte, 0, len(preimageCommit)+len(contentKey)+32+8)
	buffer = append(buffer, preimageCommit...)
	buffer = append(buffer, contentKey...)
	buffer = append(buffer, vault[:]...)
	buffer = appendU64(buffer, epoch)
	return sha256.Sum256(buffer)
}

func deriveWrapKey(sharedSecret []byte, vault [32]byte, keyID []byte, epoch uint64, purpose Purpose) ([]byte, error) {
	info := make([]byte, 0, len(preimageWrapInfo)+32+2+len(keyID)+8+1)
	info = append(info, preimageWrapInfo...)
	info = append(info, vault[:]...)
	info = appendBytes16(info, keyID)
	info = appendU64(info, epoch)
	info = append(info, byte(purpose))
	return hkdf.Key[hash.Hash](sha256.New, sharedSecret, nil, string(info), chacha20poly1305.KeySize)
}

func authorizedSigner(envelope Envelope, request OpenRequest, policy Policy) (Certificate, error) {
	matched, err := resolveTrustedCertificate(envelope.DeviceID, envelope.KeyID, request)
	if err != nil {
		return Certificate{}, err
	}
	role, exists := policyRole(policy, matched.DeviceID)
	if !exists || role != matched.Role || !roleAllowed(envelope.Purpose, role) {
		return Certificate{}, fmt.Errorf("%w: signer role", ErrAuthorization)
	}
	return matched, nil
}

func resolveTrustedCertificate(deviceID string, keyID []byte, request OpenRequest) (Certificate, error) {
	var matched *Certificate
	for _, encoded := range request.Certificates {
		certificate, err := DecodeCertificate(encoded)
		if err != nil || certificate.DeviceID != deviceID || !bytes.Equal(certificate.KeyID, keyID) {
			continue
		}
		if matched != nil {
			return Certificate{}, fmt.Errorf("%w: ambiguous certificate", ErrAuthorization)
		}
		copyOf := certificate
		matched = &copyOf
	}
	if matched == nil {
		return Certificate{}, fmt.Errorf("%w: signer certificate", ErrAuthorization)
	}
	if err := verifyCertificateChain(*matched, request, 1, make(map[string]bool)); err != nil {
		return Certificate{}, err
	}
	return *matched, nil
}

func verifyCertificateChain(certificate Certificate, request OpenRequest, depth int, visited map[string]bool) error {
	if depth > 3 || certificate.Vault != request.Vault {
		return fmt.Errorf("%w: certificate chain", ErrAuthorization)
	}
	if certificate.CertEpoch > request.EpochSeq {
		return fmt.Errorf("%w: cert_epoch", ErrAuthorization)
	}
	identity := certificate.DeviceID + "\x00" + string(certificate.KeyID)
	if visited[identity] {
		return fmt.Errorf("%w: certificate chain", ErrAuthorization)
	}
	visited[identity] = true
	defer delete(visited, identity)
	if certificate.Issuer == certificate.DeviceID {
		if certificate.Role != RoleRoot || certificate.Signer.DeviceID != certificate.DeviceID || !bytes.Equal(certificate.Signer.KeyID, certificate.KeyID) {
			return fmt.Errorf("%w: root certificate", ErrAuthorization)
		}
		fingerprint := sha256.Sum256(certificate.SigningPublicKey[:])
		if fingerprint != request.TrustAnchor {
			return fmt.Errorf("%w: trust_anchor", ErrAuthorization)
		}
		prefix, err := encodeCertificatePrefix(certificate)
		if err != nil || Verify("dottie/v1/sig-certificate", objectSignaturePreimage(prefix), certificate.Signature[:], certificate.SigningPublicKey[:]) != nil {
			return fmt.Errorf("%w: root certificate signature", ErrAuthorization)
		}
		return nil
	}
	if certificate.Signer.DeviceID != certificate.Issuer {
		return fmt.Errorf("%w: certificate issuer", ErrAuthorization)
	}
	var issuer *Certificate
	for _, encoded := range request.Certificates {
		candidate, err := DecodeCertificate(encoded)
		if err != nil || candidate.DeviceID != certificate.Issuer {
			continue
		}
		if issuer != nil {
			return fmt.Errorf("%w: ambiguous issuer", ErrAuthorization)
		}
		copyOf := candidate
		issuer = &copyOf
	}
	if issuer == nil || !bytes.Equal(certificate.Signer.KeyID, issuer.KeyID) {
		return fmt.Errorf("%w: certificate issuer", ErrAuthorization)
	}
	if issuer.Role != RoleRoot {
		return fmt.Errorf("%w: certificate issuer role", ErrAuthorization)
	}
	if err := verifyCertificateChain(*issuer, request, depth+1, visited); err != nil {
		return err
	}
	prefix, err := encodeCertificatePrefix(certificate)
	if err != nil || Verify("dottie/v1/sig-certificate", objectSignaturePreimage(prefix), certificate.Signature[:], issuer.SigningPublicKey[:]) != nil {
		return fmt.Errorf("%w: certificate signature", ErrAuthorization)
	}
	return nil
}

func authorizeControl(request OpenRequest) (Control, error) {
	control, err := DecodeControl(request.Control)
	if err != nil {
		return Control{}, err
	}
	if control.Vault != request.Vault || control.EpochSeq != request.EpochSeq {
		return Control{}, fmt.Errorf("%w: control vault or epoch_seq", ErrAuthorization)
	}
	signerCertificate, err := resolveTrustedCertificate(control.Signer.DeviceID, control.Signer.KeyID, request)
	if err != nil || signerCertificate.Role != RoleRoot {
		return Control{}, fmt.Errorf("%w: control signer", ErrAuthorization)
	}
	prefix, err := encodeControlPrefix(control)
	if err != nil {
		return Control{}, fmt.Errorf("%w: control", ErrAuthorization)
	}
	if err := Verify("dottie/v1/sig-control", objectSignaturePreimage(prefix), control.Signature[:], signerCertificate.SigningPublicKey[:]); err != nil {
		return Control{}, fmt.Errorf("%w: control signature", ErrSignature)
	}
	if control.PolicyDigest != request.PolicyDigest {
		return Control{}, fmt.Errorf("%w: control policy_digest", ErrAuthorization)
	}
	return control, nil
}

func signerRevoked(certificate Certificate, control Control) bool {
	for _, revoked := range control.Revoked {
		if revoked.DeviceID == certificate.DeviceID && revoked.CertEpoch >= certificate.CertEpoch {
			return true
		}
	}
	return false
}

func authorizedRecipient(policy Policy, keyID, publicKey []byte) (PolicyRecipient, bool) {
	var match *PolicyRecipient
	for index := range policy.Recipients {
		recipient := &policy.Recipients[index]
		if bytes.Equal(recipient.KeyID, keyID) {
			if match != nil || !bytes.Equal(recipient.PublicKey[:], publicKey) {
				return PolicyRecipient{}, false
			}
			match = recipient
		}
	}
	if match == nil {
		return PolicyRecipient{}, false
	}
	return *match, true
}

func policyRole(policy Policy, deviceID string) (Role, bool) {
	for _, entry := range policy.Roles {
		if entry.DeviceID == deviceID {
			return entry.Role, true
		}
	}
	return 0, false
}

func roleAllowed(purpose Purpose, role Role) bool {
	switch purpose {
	case PurposeSnapshot:
		return role == RolePublisher || role == RoleRoot
	case PurposePolicy, PurposeControl, PurposeCertificate, PurposeCheckpoint:
		return role == RoleRoot
	case PurposeAttestation:
		return role == RoleRoot || role == RolePublisher || role == RoleRestoreOnly
	default:
		return false
	}
}

func requirePolicy(policy []byte) ([]byte, error) {
	if len(policy) == 0 {
		return nil, ErrPolicyRequired
	}
	if len(policy) > MaxPolicyObjectBytes {
		return nil, fmt.Errorf("%w: policy", ErrLimit)
	}
	return policy, nil
}

type lengthValue struct {
	start  int
	length int
	ok     bool
	err    error
}

type wireCursor struct {
	data   []byte
	offset int
	err    error
}

func (cursor *wireCursor) take(length int) ([]byte, bool) {
	if cursor.err != nil || length < 0 || length > len(cursor.data)-cursor.offset {
		cursor.err = fmt.Errorf("%w: truncated field", ErrFormat)
		return nil, false
	}
	start := cursor.offset
	cursor.offset += length
	return cursor.data[start:cursor.offset], true
}

func (cursor *wireCursor) skip(length int) bool {
	_, ok := cursor.take(length)
	return ok
}

func (cursor *wireCursor) u16() uint16 {
	b, ok := cursor.take(2)
	if !ok {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (cursor *wireCursor) u32() uint32 {
	b, ok := cursor.take(4)
	if !ok {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (cursor *wireCursor) u64() uint64 {
	b, ok := cursor.take(8)
	if !ok {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (cursor *wireCursor) length16(max int) lengthValue {
	length := int(cursor.u16())
	if cursor.err != nil {
		return lengthValue{err: cursor.err}
	}
	if length > max {
		return lengthValue{err: fmt.Errorf("%w: variable field", ErrLimit)}
	}
	start := cursor.offset
	if !cursor.skip(length) {
		return lengthValue{err: cursor.err}
	}
	return lengthValue{start: start, length: length, ok: true}
}

func (cursor *wireCursor) bytes16(max int) []byte {
	value := cursor.length16(max)
	if !value.ok {
		cursor.err = value.err
		return nil
	}
	return bytes.Clone(cursor.data[value.start : value.start+value.length])
}

func appendHeader(buffer []byte, kind byte) []byte {
	buffer = append(buffer, wireMagic[:]...)
	buffer = append(buffer, wireVersion, kind)
	return buffer
}

func validateHeader(data []byte, expectedKind byte, envelope bool) error {
	if len(data) < 5 {
		return fmt.Errorf("%w: header", ErrFormat)
	}
	if !bytes.Equal(data[:3], wireMagic[:]) {
		return fmt.Errorf("%w: magic", ErrFormat)
	}
	if data[3] != wireVersion {
		return fmt.Errorf("%w: version", ErrUnsupportedVersion)
	}
	if data[4] != expectedKind {
		return fmt.Errorf("%w: object kind", ErrFormat)
	}
	if envelope {
		if len(data) < 6 || !validPurpose(Purpose(data[5])) {
			return fmt.Errorf("%w: purpose", ErrFormat)
		}
	}
	return nil
}

func appendBytes16(buffer, value []byte) []byte {
	buffer = appendU16(buffer, uint16(len(value)))
	return append(buffer, value...)
}

func appendU16(buffer []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(buffer, encoded[:]...)
}

func appendU32(buffer []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(buffer, encoded[:]...)
}

func appendU64(buffer []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(buffer, encoded[:]...)
}
