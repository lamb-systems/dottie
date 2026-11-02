package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

type envelopeFixture struct {
	signingKey           ed25519.PrivateKey
	publisherKey         ed25519.PrivateKey
	recipientKey         *ecdh.PrivateKey
	policy               Policy
	policyBytes          []byte
	rootCertificate      Certificate
	rootCertificateBytes []byte
	certificate          Certificate
	certificateBytes     []byte
	trustAnchor          [32]byte
	prepared             PreparedSeal
	envelope             Envelope
	openRequest          OpenRequest
}

func fixedSigningKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func fixedX25519Key(seed byte) *ecdh.PrivateKey {
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		panic(err)
	}
	return key
}

func fixtureBytes(start byte, length int) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = start + byte(index)
	}
	return value
}

func signPolicyValue(t *testing.T, value Policy, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodePolicyPrefix(value)
	require.NoError(t, err)
	value.Signature, err = signObject(objectSignatureContext(objectKindPolicy), prefix, key)
	require.NoError(t, err)
	encoded, err := EncodePolicy(value)
	require.NoError(t, err)
	return encoded
}

func signControlValue(t *testing.T, value Control, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodeControlPrefix(value)
	require.NoError(t, err)
	value.Signature, err = signObject(objectSignatureContext(objectKindControl), prefix, key)
	require.NoError(t, err)
	encoded, err := EncodeControl(value)
	require.NoError(t, err)
	return encoded
}

func signCertificateValue(t *testing.T, value Certificate, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodeCertificatePrefix(value)
	require.NoError(t, err)
	value.Signature, err = signObject(objectSignatureContext(objectKindCertificate), prefix, key)
	require.NoError(t, err)
	encoded, err := EncodeCertificate(value)
	require.NoError(t, err)
	return encoded
}

func signCheckpointValue(t *testing.T, value Checkpoint, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodeCheckpointPrefix(value)
	require.NoError(t, err)
	value.Signature, err = signObject(objectSignatureContext(objectKindCheckpoint), prefix, key)
	require.NoError(t, err)
	encoded, err := EncodeCheckpoint(value)
	require.NoError(t, err)
	return encoded
}

func signHeadValue(t *testing.T, value Head, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodeHeadPrefix(value)
	require.NoError(t, err)
	value.Signature, err = signObject(objectSignatureContext(objectKindHead), prefix, key)
	require.NoError(t, err)
	encoded, err := EncodeHead(value)
	require.NoError(t, err)
	return encoded
}

func signAttestationValue(t *testing.T, value Attestation, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodeAttestationPrefix(value)
	require.NoError(t, err)
	value.Signature, err = signObject(objectSignatureContext(objectKindAttestation), prefix, key)
	require.NoError(t, err)
	encoded, err := EncodeAttestation(value)
	require.NoError(t, err)
	return encoded
}

func newEnvelopeFixture(t *testing.T) envelopeFixture {
	t.Helper()
	signingKey := fixedSigningKey(11)
	publisherKey := fixedSigningKey(12)
	recipientKey := fixedX25519Key(21)
	vaultID := [32]byte(fixtureBytes(31, 32))
	rootCertificate := Certificate{
		Vault: vaultID, DeviceID: "device-root", KeyID: []byte("signer-root"),
		SigningPublicKey:    [ed25519.PublicKeySize]byte(signingKey.Public().(ed25519.PublicKey)),
		EncryptionPublicKey: [32]byte(fixedX25519Key(22).PublicKey().Bytes()), Role: RoleRoot, CertEpoch: 0,
		Issuer: "device-root", Signer: Signer{DeviceID: "device-root", KeyID: []byte("signer-root")},
	}
	rootCertificateBytes := signCertificateValue(t, rootCertificate, signingKey)
	certificate := Certificate{
		Vault: vaultID, DeviceID: "device-publisher", KeyID: []byte("signer-publisher"),
		SigningPublicKey:    [ed25519.PublicKeySize]byte(publisherKey.Public().(ed25519.PublicKey)),
		EncryptionPublicKey: [32]byte(recipientKey.PublicKey().Bytes()), Role: RolePublisher, CertEpoch: 5,
		Issuer: "device-root", Signer: Signer{DeviceID: "device-root", KeyID: []byte("signer-root")},
	}
	certificateBytes := signCertificateValue(t, certificate, signingKey)
	policy := Policy{
		Vault: vaultID, EpochSeq: 7,
		Roles:                []RoleBinding{{DeviceID: "device-root", Role: RoleRoot}, {DeviceID: "device-publisher", Role: RolePublisher}},
		Recipients:           []PolicyRecipient{{DeviceID: "device-publisher", KeyID: []byte("recipient-a"), PublicKey: [32]byte(recipientKey.PublicKey().Bytes())}},
		PolicyRetentionFloor: 2, RetainedRecoveryPoints: 3, MaxPublications: 100, MaxEpochAge: 86400,
		RecoveryAnchor: [32]byte(fixtureBytes(71, 32)), PrevPolicyDigest: [32]byte{},
		Signer: Signer{DeviceID: "device-root", KeyID: []byte("signer-root")},
	}
	policyBytes := signPolicyValue(t, policy, signingKey)
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	prepared := PreparedSeal{
		Purpose: PurposeSnapshot, Vault: vaultID, PublicationID: [16]byte(fixtureBytes(101, 16)),
		EpochSeq: 7, PolicyDigest: policyDigest, Parent: fixtureCIDBytes(t),
		DeviceID: certificate.DeviceID, KeyID: certificate.KeyID, Plaintext: []byte("fixture plaintext: path=/home/synthetic/.config/example, value=never-public"),
		SigningKey: publisherKey, ContentKey: fixtureBytes(121, 32), Nonce: [24]byte(fixtureBytes(151, 24)),
		Recipients: []PreparedRecipient{{
			KeyID: []byte("recipient-a"), PublicKey: recipientKey.PublicKey().Bytes(),
			EphemeralPrivate: fixedX25519Key(41).Bytes(), WrapNonce: [24]byte(fixtureBytes(181, 24)),
		}},
	}
	envelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	trustAnchor := sha256.Sum256(rootCertificate.SigningPublicKey[:])
	openRequest := OpenRequest{
		Vault: vaultID, EpochSeq: 7, PolicyDigest: policyDigest, Policy: policyBytes,
		TrustAnchor: trustAnchor, Certificates: [][]byte{rootCertificateBytes, certificateBytes},
		DeviceKeyID: []byte("recipient-a"), DeviceKey: recipientKey,
	}
	return envelopeFixture{
		signingKey: signingKey, publisherKey: publisherKey, recipientKey: recipientKey,
		policy: policy, policyBytes: policyBytes, rootCertificate: rootCertificate,
		rootCertificateBytes: rootCertificateBytes, certificate: certificate,
		certificateBytes: certificateBytes, trustAnchor: trustAnchor, prepared: prepared,
		envelope: envelope, openRequest: openRequest,
	}
}

func signedVectors(t *testing.T) map[string][]byte {
	t.Helper()
	fixture := newEnvelopeFixture(t)
	envelopeOne, err := EncodeEnvelope(fixture.envelope)
	require.NoError(t, err)
	secondKey := fixedX25519Key(22)
	manyPolicy := fixture.policy
	manyPolicy.Recipients = append(manyPolicy.Recipients, PolicyRecipient{
		DeviceID: "device-second", KeyID: []byte("recipient-b"), PublicKey: [32]byte(secondKey.PublicKey().Bytes()),
	})
	manyPolicyBytes := signPolicyValue(t, manyPolicy, fixture.signingKey)
	manyPolicyDigest, err := ComputePolicyDigest(manyPolicyBytes)
	require.NoError(t, err)
	many := fixture.prepared
	many.PolicyDigest = manyPolicyDigest
	many.Recipients = []PreparedRecipient{{
		KeyID: []byte("recipient-b"), PublicKey: secondKey.PublicKey().Bytes(),
		EphemeralPrivate: fixedX25519Key(42).Bytes(), WrapNonce: [24]byte(fixtureBytes(201, 24)),
	}, many.Recipients[0]}
	manyEnvelope, err := SealPrepared(many)
	require.NoError(t, err)
	envelopeMany, err := EncodeEnvelope(manyEnvelope)
	require.NoError(t, err)
	policyBytes := fixture.policyBytes
	controlBytes := signControlValue(t, Control{
		Vault: fixture.policy.Vault, EpochSeq: 7, PolicyDigest: fixture.prepared.PolicyDigest,
		HeadSnapshotCID: fixtureCIDBytes(t),
		Revoked:         []RevokedDevice{{DeviceID: "retired-device", CertEpoch: 4}},
		PrevControlCID:  fixtureCIDBytes(t),
		Signer:          Signer{DeviceID: "device-root", KeyID: []byte("signer-root")},
	}, fixture.signingKey)
	certificateBytes := fixture.certificateBytes
	checkpointBytes := signCheckpointValue(t, Checkpoint{
		Vault: fixture.policy.Vault, SnapshotCID: fixtureCIDBytes(t),
		EpochSeq: 7, PolicyDigest: fixture.prepared.PolicyDigest,
		Anchor:     [32]byte(fixtureBytes(71, 32)),
		ControlCID: fixtureCIDBytes(t),
		Signer:     Signer{DeviceID: "device-root", KeyID: []byte("signer-root")},
	}, fixture.signingKey)
	headBytes := signHeadValue(t, Head{
		Vault: fixture.policy.Vault, EpochSeq: 7, PolicyDigest: fixture.prepared.PolicyDigest,
		SnapshotCID: fixtureCIDBytes(t), BlobCID: fixtureCIDBytes(t), PublicationCount: 9,
		PrevHeadCID: fixtureCIDBytes(t),
		Signer:      Signer{DeviceID: "device-publisher", KeyID: []byte("signer-publisher")},
	}, fixture.publisherKey)
	attestationBytes := signAttestationValue(t, Attestation{
		Vault: fixture.policy.Vault, DeviceID: "device-root", PolicyDigest: fixture.prepared.PolicyDigest,
		RetentionFloor: 2, RetainedRecoveryPoints: 3,
		ControlCID: fixtureCIDBytes(t),
		Signer:     Signer{DeviceID: "device-root", KeyID: []byte("signer-root")},
	}, fixture.signingKey)
	return map[string][]byte{
		"envelope-one-recipient-chain.hex":             envelopeOne,
		"envelope-many-recipients-chain.hex":           envelopeMany,
		"policy-root-signed-chain.hex":                 policyBytes,
		"policy-many-recipients-root-signed-chain.hex": manyPolicyBytes,
		"control-root-signed-chain.hex":                controlBytes,
		"certificate-publisher-root-issued-chain.hex":  certificateBytes,
		"certificate-root-self-signed.hex":             fixture.rootCertificateBytes,
		"checkpoint-root-signed-chain.hex":             checkpointBytes,
		"attestation-root-signed-chain.hex":            attestationBytes,
		"head-publisher-signed-chain.hex":              headBytes,
	}
}

func fixtureCIDBytes(t *testing.T) []byte {
	t.Helper()
	parsed, err := cid.Decode("bafybeigdyrzt5sfp7udm7hu76uh2yqgj7zs3l4w7p52r7c3v6rdjwxz4fe")
	require.NoError(t, err)
	return cid.NewCidV1(cid.DagCBOR, parsed.Hash()).Bytes()
}

func TestRegenerateSignedObjectVectors(t *testing.T) {
	vectors := signedVectors(t)
	for name, data := range vectors {
		path := filepath.Join("testdata", name)
		encoded := hex.EncodeToString(data) + "\n"
		contents, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && os.Getenv("UPDATE_V02_VECTORS") == "1" {
			require.NoError(t, os.WriteFile(path, []byte(encoded), 0o600))
			contents, err = os.ReadFile(path)
		}
		require.NoError(t, err, "vector %s", name)
		assert.Equal(t, string(contents), encoded, "regenerated vector %s", name)
	}
}

func TestKindByteDisambiguatesEveryObjectType(t *testing.T) {
	vectors := signedVectors(t)
	decoders := map[byte]func([]byte) error{
		objectKindEnvelope: func(data []byte) error { _, err := DecodeEnvelope(data); return err },
		objectKindPolicy:   func(data []byte) error { _, err := DecodePolicy(data); return err },
		objectKindControl:  func(data []byte) error { _, err := DecodeControl(data); return err },
		objectKindCertificate: func(data []byte) error {
			_, err := DecodeCertificate(data)
			return err
		},
		objectKindCheckpoint:  func(data []byte) error { _, err := DecodeCheckpoint(data); return err },
		objectKindAttestation: func(data []byte) error { _, err := DecodeAttestation(data); return err },
		objectKindHead:        func(data []byte) error { _, err := DecodeHead(data); return err },
	}
	samples := map[byte][]byte{
		objectKindEnvelope:    vectors["envelope-one-recipient-chain.hex"],
		objectKindPolicy:      vectors["policy-root-signed-chain.hex"],
		objectKindControl:     vectors["control-root-signed-chain.hex"],
		objectKindCertificate: vectors["certificate-publisher-root-issued-chain.hex"],
		objectKindCheckpoint:  vectors["checkpoint-root-signed-chain.hex"],
		objectKindAttestation: vectors["attestation-root-signed-chain.hex"],
		objectKindHead:        vectors["head-publisher-signed-chain.hex"],
	}
	for kind, data := range samples {
		require.NoError(t, decoders[kind](data), "kind %d must decode as itself", kind)
		for other, decode := range decoders {
			if other == kind {
				continue
			}
			altered := bytes.Clone(data)
			altered[4] = other
			assert.Error(t, decode(altered), "kind byte %d must not decode as kind %d", kind, other)
		}
	}
}

func TestSealGeneratesMaterialAndOpens(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := SealRequest{
		Purpose: PurposeSnapshot, Vault: fixture.envelope.Vault, PublicationID: [16]byte(fixtureBytes(41, 16)),
		EpochSeq: fixture.envelope.EpochSeq, PolicyDigest: fixture.envelope.PolicyDigest,
		Parent: fixture.envelope.Parent, DeviceID: fixture.envelope.DeviceID, KeyID: fixture.envelope.KeyID,
		Plaintext: fixture.prepared.Plaintext, SigningKey: fixture.publisherKey,
		Recipients: []RecipientPublicKey{{KeyID: []byte("recipient-a"), PublicKey: fixture.recipientKey.PublicKey().Bytes()}},
	}
	envelope, err := Seal(request)
	require.NoError(t, err)
	plaintext, err := Open(envelope, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, request.Plaintext, plaintext)
}

func TestManyRecipientEnvelopeOpensForEveryPolicyRecipient(t *testing.T) {
	vectors := signedVectors(t)
	envelope, err := DecodeEnvelope(vectors["envelope-many-recipients-chain.hex"])
	require.NoError(t, err)
	policyBytes := vectors["policy-many-recipients-root-signed-chain.hex"]
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	fixture := newEnvelopeFixture(t)
	for _, recipient := range []struct {
		keyID []byte
		key   *ecdh.PrivateKey
	}{
		{[]byte("recipient-a"), fixture.recipientKey},
		{[]byte("recipient-b"), fixedX25519Key(22)},
	} {
		request := fixture.openRequest
		request.Policy = policyBytes
		request.PolicyDigest = policyDigest
		request.DeviceKeyID = recipient.keyID
		request.DeviceKey = recipient.key
		plaintext, openErr := Open(envelope, request)
		require.NoError(t, openErr)
		assert.Equal(t, fixture.prepared.Plaintext, plaintext)
	}
}

func TestEnvelopeSealOpenAndBinaryRoundTrip(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	encoded, err := EncodeEnvelope(fixture.envelope)
	require.NoError(t, err)
	decoded, err := DecodeEnvelope(encoded)
	require.NoError(t, err)
	assert.Equal(t, fixture.envelope, decoded)
	plaintext, err := Open(decoded, fixture.openRequest)
	require.NoError(t, err)
	assert.Equal(t, fixture.prepared.Plaintext, plaintext)
}

func TestSignedObjectEncodersAndDecodersRoundTrip(t *testing.T) {
	vectors := signedVectors(t)
	tests := []struct {
		name   string
		decode func([]byte) error
	}{
		{"policy", func(data []byte) error {
			value, err := DecodePolicy(data)
			if err == nil {
				encoded, encodeErr := EncodePolicy(value)
				if encodeErr != nil {
					return encodeErr
				}
				if !bytes.Equal(data, encoded) {
					return ErrFormat
				}
			}
			return err
		}},
		{"control", func(data []byte) error {
			value, err := DecodeControl(data)
			if err == nil {
				encoded, encodeErr := EncodeControl(value)
				if encodeErr != nil {
					return encodeErr
				}
				if !bytes.Equal(data, encoded) {
					return ErrFormat
				}
			}
			return err
		}},
		{"certificate", func(data []byte) error {
			value, err := DecodeCertificate(data)
			if err == nil {
				encoded, encodeErr := EncodeCertificate(value)
				if encodeErr != nil {
					return encodeErr
				}
				if !bytes.Equal(data, encoded) {
					return ErrFormat
				}
			}
			return err
		}},
		{"checkpoint", func(data []byte) error {
			value, err := DecodeCheckpoint(data)
			if err == nil {
				encoded, encodeErr := EncodeCheckpoint(value)
				if encodeErr != nil {
					return encodeErr
				}
				if !bytes.Equal(data, encoded) {
					return ErrFormat
				}
			}
			return err
		}},
		{"attestation", func(data []byte) error {
			value, err := DecodeAttestation(data)
			if err == nil {
				encoded, encodeErr := EncodeAttestation(value)
				if encodeErr != nil {
					return encodeErr
				}
				if !bytes.Equal(data, encoded) {
					return ErrFormat
				}
			}
			return err
		}},
	}
	vectorFiles := map[string]string{
		"policy": "policy-root-signed-chain.hex", "control": "control-root-signed-chain.hex",
		"certificate": "certificate-publisher-root-issued-chain.hex", "checkpoint": "checkpoint-root-signed-chain.hex",
		"attestation": "attestation-root-signed-chain.hex",
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vector := vectors[vectorFiles[test.name]]
			assert.NoError(t, test.decode(vector))
		})
	}
	rootCertificate, err := DecodeCertificate(vectors["certificate-root-self-signed.hex"])
	require.NoError(t, err)
	rootEncoding, err := EncodeCertificate(rootCertificate)
	require.NoError(t, err)
	assert.Equal(t, vectors["certificate-root-self-signed.hex"], rootEncoding)
	manyPolicy, err := DecodePolicy(vectors["policy-many-recipients-root-signed-chain.hex"])
	require.NoError(t, err)
	manyPolicyEncoding, err := EncodePolicy(manyPolicy)
	require.NoError(t, err)
	assert.Equal(t, vectors["policy-many-recipients-root-signed-chain.hex"], manyPolicyEncoding)
	fixture := newEnvelopeFixture(t)
	rootPublic := fixture.signingKey.Public().(ed25519.PublicKey)
	verifySignedObjectVector(t, vectors["policy-root-signed-chain.hex"], "dottie/v1/sig-policy", rootPublic)
	verifySignedObjectVector(t, vectors["policy-many-recipients-root-signed-chain.hex"], "dottie/v1/sig-policy", rootPublic)
	verifySignedObjectVector(t, vectors["control-root-signed-chain.hex"], "dottie/v1/sig-control", rootPublic)
	verifySignedObjectVector(t, vectors["certificate-publisher-root-issued-chain.hex"], "dottie/v1/sig-certificate", rootPublic)
	verifySignedObjectVector(t, vectors["certificate-root-self-signed.hex"], "dottie/v1/sig-certificate", rootPublic)
	verifySignedObjectVector(t, vectors["checkpoint-root-signed-chain.hex"], "dottie/v1/sig-checkpoint", rootPublic)
	verifySignedObjectVector(t, vectors["attestation-root-signed-chain.hex"], "dottie/v1/sig-attestation", rootPublic)
	for _, name := range []string{"envelope-one-recipient-chain.hex", "envelope-many-recipients-chain.hex"} {
		envelope, decodeErr := DecodeEnvelope(vectors[name])
		require.NoError(t, decodeErr)
		prefix, prefixErr := encodeEnvelopePrefix(envelope)
		require.NoError(t, prefixErr)
		assert.NoError(t, Verify(contextForPurpose(envelope.Purpose), append([]byte(preimageSig), prefix...), envelope.Signature[:], fixture.publisherKey.Public().(ed25519.PublicKey)))
	}
}

func verifySignedObjectVector(t *testing.T, data []byte, context string, publicKey ed25519.PublicKey) {
	t.Helper()
	require.GreaterOrEqual(t, len(data), ed25519.SignatureSize)
	prefix := data[:len(data)-ed25519.SignatureSize]
	signature := data[len(data)-ed25519.SignatureSize:]
	assert.NoError(t, Verify(context, objectSignaturePreimage(prefix), signature, publicKey))
}

func TestEnvelopeDecodeRejectsMalformedWire(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	encoded, err := EncodeEnvelope(fixture.envelope)
	require.NoError(t, err)
	boundaries := []int{0, 3, 4, 5, 6, 7, 39, 55, 63, 95, 97, 129, len(encoded) - 16, len(encoded) - 64, len(encoded)}
	for _, boundary := range boundaries {
		if boundary >= 0 && boundary < len(encoded) {
			_, err := DecodeEnvelope(encoded[:boundary])
			assert.Error(t, err, "accepted truncation at byte boundary %d", boundary)
		}
	}
	for end := 0; end < len(encoded); end++ {
		_, err := DecodeEnvelope(encoded[:end])
		assert.Error(t, err, "accepted truncation at byte %d", end)
	}
	_, err = DecodeEnvelope(append(bytes.Clone(encoded), 0))
	assert.ErrorIs(t, err, ErrFormat)
	for _, field := range envelopeLengthFields(encoded) {
		malformed := bytes.Clone(encoded)
		if field.width == 2 {
			current := binary.BigEndian.Uint16(malformed[field.offset : field.offset+2])
			binary.BigEndian.PutUint16(malformed[field.offset:field.offset+2], current+1)
		} else {
			current := binary.BigEndian.Uint32(malformed[field.offset : field.offset+4])
			binary.BigEndian.PutUint32(malformed[field.offset:field.offset+4], current+1)
		}
		_, err = DecodeEnvelope(malformed)
		assert.Error(t, err, "accepted tampered length field at byte %d", field.offset)
	}
	unknownMagic := bytes.Clone(encoded)
	unknownMagic[0] ^= 0xff
	_, err = DecodeEnvelope(unknownMagic)
	assert.ErrorIs(t, err, ErrFormat)
	unknownPurpose := bytes.Clone(encoded)
	unknownPurpose[5] = 99
	_, err = DecodeEnvelope(unknownPurpose)
	assert.ErrorIs(t, err, ErrFormat)
	unsupportedVersion := bytes.Clone(encoded)
	unsupportedVersion[3] = 2
	_, err = DecodeEnvelope(unsupportedVersion)
	assert.ErrorIs(t, err, ErrUnsupportedVersion)
}

func TestEnvelopeRecipientsRequireUniqueByteOrder(t *testing.T) {
	vectors := signedVectors(t)
	many := vectors["envelope-many-recipients-chain.hex"]
	offsets := encodedRecipientKeyOffsets(many)
	require.Len(t, offsets, 2)
	duplicate := bytes.Clone(many)
	copy(duplicate[offsets[1].start:offsets[1].start+offsets[1].length], duplicate[offsets[0].start:offsets[0].start+offsets[0].length])
	_, err := DecodeEnvelope(duplicate)
	assert.ErrorIs(t, err, ErrRecipient)
	outOfOrder := bytes.Clone(many)
	copy(outOfOrder[offsets[0].start:offsets[0].start+offsets[0].length], []byte("z"))
	copy(outOfOrder[offsets[1].start:offsets[1].start+offsets[1].length], []byte("a"))
	_, err = DecodeEnvelope(outOfOrder)
	assert.ErrorIs(t, err, ErrRecipient)
}

type byteRange struct {
	start  int
	length int
}

type wireLengthField struct {
	offset int
	width  int
}

func envelopeLengthFields(data []byte) []wireLengthField {
	offset := 6 + 32 + 16 + 8 + 32
	fields := []wireLengthField{{offset: offset, width: 2}}
	parentLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + parentLength
	fields = append(fields, wireLengthField{offset: offset, width: 2})
	deviceLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + deviceLength
	fields = append(fields, wireLengthField{offset: offset, width: 2})
	keyLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + keyLength + 32
	fields = append(fields, wireLengthField{offset: offset, width: 2})
	count := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	for index := 0; index < count; index++ {
		fields = append(fields, wireLengthField{offset: offset, width: 2})
		keyIDLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + keyIDLength + 32 + 24
		fields = append(fields, wireLengthField{offset: offset, width: 2})
		wrappedKeyLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + wrappedKeyLength
	}
	offset += 24
	fields = append(fields, wireLengthField{offset: offset, width: 4})
	return fields
}

func encodedRecipientKeyOffsets(data []byte) []byteRange {
	offset := 6 + 32 + 16 + 8 + 32
	parentLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + parentLength
	deviceLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + deviceLength
	keyLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + keyLength + 32
	count := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	result := make([]byteRange, count)
	for index := range result {
		length := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		result[index] = byteRange{start: offset + 2, length: length}
		offset += 2 + length + 32 + 24
		wrappedLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + wrappedLength
	}
	return result
}

func TestEnvelopeOpenRejectsTamperingAndContextMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	mutations := []struct {
		name  string
		apply func(*Envelope)
	}{
		{"purpose", func(e *Envelope) { e.Purpose = PurposePolicy }},
		{"vault", func(e *Envelope) { e.Vault[0] ^= 1 }},
		{"publication_id", func(e *Envelope) { e.PublicationID[0] ^= 1 }},
		{"epoch_seq", func(e *Envelope) { e.EpochSeq++ }},
		{"policy_digest", func(e *Envelope) { e.PolicyDigest[0] ^= 1 }},
		{"parent", func(e *Envelope) { e.Parent[0] ^= 1 }},
		{"device_id", func(e *Envelope) { e.DeviceID = "other-device" }},
		{"signer_key_id", func(e *Envelope) { e.KeyID = []byte("other-key") }},
		{"commit", func(e *Envelope) { e.Commit[0] ^= 1 }},
		{"recipient_key_id", func(e *Envelope) { e.Recipients[0].KeyID = []byte("other-key") }},
		{"ephemeral", func(e *Envelope) { e.Recipients[0].Ephemeral[0] ^= 1 }},
		{"wrap_nonce", func(e *Envelope) { e.Recipients[0].WrapNonce[0] ^= 1 }},
		{"wrapped_key", func(e *Envelope) { e.Recipients[0].WrappedKey[0] ^= 1 }},
		{"nonce", func(e *Envelope) { e.Nonce[0] ^= 1 }},
		{"ciphertext", func(e *Envelope) { e.Ciphertext[0] ^= 1 }},
		{"tag", func(e *Envelope) { e.Tag[0] ^= 1 }},
		{"signature", func(e *Envelope) { e.Signature[0] ^= 1 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			encoded, err := EncodeEnvelope(fixture.envelope)
			require.NoError(t, err)
			copyEnvelope, err := DecodeEnvelope(encoded)
			require.NoError(t, err)
			mutation.apply(&copyEnvelope)
			_, err = Open(copyEnvelope, fixture.openRequest)
			assert.Error(t, err)
		})
	}
	wrongContext := fixture.envelope
	prefix, err := encodeEnvelopePrefix(wrongContext)
	require.NoError(t, err)
	signature, err := Sign("dottie/v1/sig-certificate", append([]byte(preimageSig), prefix...), fixture.publisherKey)
	require.NoError(t, err)
	copy(wrongContext.Signature[:], signature)
	_, err = Open(wrongContext, fixture.openRequest)
	assert.ErrorIs(t, err, ErrSignature)
}

func TestOpenVerificationOrderAndAuthorizationErrors(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	_, err := Open(fixture.envelope, OpenRequest{})
	assert.ErrorIs(t, err, ErrPolicyRequired)
	wrongVault := fixture.openRequest
	wrongVault.Vault[0] ^= 1
	_, err = Open(fixture.envelope, wrongVault)
	assert.ErrorIs(t, err, ErrAuthorization)
	wrongEpoch := fixture.openRequest
	wrongEpoch.EpochSeq++
	_, err = Open(fixture.envelope, wrongEpoch)
	assert.ErrorIs(t, err, ErrAuthorization)
	wrongPolicyDigest := fixture.openRequest
	wrongPolicyDigest.PolicyDigest[0] ^= 1
	_, err = Open(fixture.envelope, wrongPolicyDigest)
	assert.ErrorIs(t, err, ErrAuthorization)
	wrongPolicyVault := fixture.policy
	wrongPolicyVault.Vault[0] ^= 1
	wrongPolicyBytes := signPolicyValue(t, wrongPolicyVault, fixture.signingKey)
	wrongPolicy := fixture.openRequest
	wrongPolicy.Policy = wrongPolicyBytes
	_, err = Open(fixture.envelope, wrongPolicy)
	assert.ErrorIs(t, err, ErrAuthorization)
	wrongSignerKey := fixture.envelope
	otherSigningKey := fixedSigningKey(99)
	wrongPrefix, err := encodeEnvelopePrefix(wrongSignerKey)
	require.NoError(t, err)
	wrongSignature, err := Sign(contextForPurpose(wrongSignerKey.Purpose), append([]byte(preimageSig), wrongPrefix...), otherSigningKey)
	require.NoError(t, err)
	copy(wrongSignerKey.Signature[:], wrongSignature)
	_, err = Open(wrongSignerKey, fixture.openRequest)
	assert.ErrorIs(t, err, ErrSignature)
	absentCertificate := fixture.openRequest
	absentCertificate.Certificates = nil
	_, err = Open(fixture.envelope, absentCertificate)
	assert.ErrorIs(t, err, ErrAuthorization)
	absentRecipient := fixture.openRequest
	absentRecipient.DeviceKeyID = []byte("absent")
	_, err = Open(fixture.envelope, absentRecipient)
	assert.ErrorIs(t, err, ErrRecipient)
	wrongDeviceKey := fixture.openRequest
	wrongDeviceKey.DeviceKey = fixedX25519Key(88)
	_, err = Open(fixture.envelope, wrongDeviceKey)
	assert.ErrorIs(t, err, ErrRecipient)
}

func TestOpenRejectsSwappedRecipientKey(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := fixture.openRequest
	request.DeviceKey = fixedX25519Key(88)
	_, err := Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrRecipient)
}

func TestSealPreparedRejectsLowOrderRecipientKey(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	prepared := fixture.prepared
	prepared.Recipients = []PreparedRecipient{{
		KeyID: []byte("recipient-a"), PublicKey: make([]byte, 32),
		EphemeralPrivate: fixedX25519Key(52).Bytes(), WrapNonce: [24]byte(fixtureBytes(220, 24)),
	}}
	_, err := SealPrepared(prepared)
	assert.ErrorIs(t, err, ErrRecipient)
}

func TestCommitmentRejectsCiphertextValidUnderTwoContentKeys(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	otherContentKey := fixtureBytes(231, 32)
	ad := contentAssociatedData(fixture.envelope)
	ciphertext, tag := dualKeyCiphertext(t, fixture.prepared.ContentKey, otherContentKey, fixture.envelope.Nonce[:], ad)
	sealed := append(bytes.Clone(ciphertext), tag[:]...)
	for _, key := range [][]byte{fixture.prepared.ContentKey, otherContentKey} {
		aead, err := chacha20poly1305.NewX(key)
		require.NoError(t, err)
		_, err = aead.Open(nil, fixture.envelope.Nonce[:], sealed, ad)
		assert.NoError(t, err, "crafted ciphertext did not authenticate under both content keys")
	}
	changed := fixture.envelope
	changed.Ciphertext = ciphertext
	changed.Tag = tag
	changed.Recipients = append([]EnvelopeRecipient(nil), fixture.envelope.Recipients...)
	ephemeralPrivate, err := ecdh.X25519().NewPrivateKey(fixture.prepared.Recipients[0].EphemeralPrivate)
	require.NoError(t, err)
	recipientPublic, err := ecdh.X25519().NewPublicKey(fixture.prepared.Recipients[0].PublicKey)
	require.NoError(t, err)
	sharedSecret, err := ephemeralPrivate.ECDH(recipientPublic)
	require.NoError(t, err)
	wrapKey, err := deriveWrapKey(sharedSecret, changed.Vault, changed.Recipients[0].KeyID, changed.EpochSeq, changed.Purpose)
	require.NoError(t, err)
	wrapAEAD, err := chacha20poly1305.NewX(wrapKey)
	require.NoError(t, err)
	wrapAD := wrapAssociatedData(changed.Vault, changed.Recipients[0].KeyID, changed.EpochSeq, changed.Purpose, fixture.prepared.Recipients[0].PublicKey, ephemeralPrivate.PublicKey().Bytes())
	changed.Recipients[0].WrappedKey = wrapAEAD.Seal(nil, changed.Recipients[0].WrapNonce[:], otherContentKey, wrapAD)
	prefix, err := encodeEnvelopePrefix(changed)
	require.NoError(t, err)
	signature, err := Sign(contextForPurpose(changed.Purpose), append([]byte(preimageSig), prefix...), fixture.publisherKey)
	require.NoError(t, err)
	copy(changed.Signature[:], signature)
	plaintext, err := Open(changed, fixture.openRequest)
	assert.ErrorIs(t, err, ErrCommitment)
	assert.Nil(t, plaintext)
}

func dualKeyCiphertext(t *testing.T, keyA, keyB, nonce, associatedData []byte) ([]byte, [16]byte) {
	t.Helper()
	const primeExponent = 130
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), primeExponent), big.NewInt(5))
	oneTimeA := poly1305Key(t, keyA, nonce)
	oneTimeB := poly1305Key(t, keyB, nonce)
	rA, sA := poly1305Parameters(oneTimeA)
	rB, sB := poly1305Parameters(oneTimeB)
	zeroCiphertext := make([]byte, 32)
	baseA := poly1305Accumulator(associatedData, zeroCiphertext, rA, prime)
	baseB := poly1305Accumulator(associatedData, zeroCiphertext, rB, prime)
	powerA3 := new(big.Int).Exp(rA, big.NewInt(3), prime)
	powerB3 := new(big.Int).Exp(rB, big.NewInt(3), prime)
	powerA2 := new(big.Int).Exp(rA, big.NewInt(2), prime)
	powerB2 := new(big.Int).Exp(rB, big.NewInt(2), prime)
	coefficientX := new(big.Int).Sub(powerA3, powerB3)
	coefficientX.Mod(coefficientX, prime)
	coefficientY := new(big.Int).Sub(powerA2, powerB2)
	coefficientY.Mod(coefficientY, prime)
	inverseY := new(big.Int).ModInverse(coefficientY, prime)
	require.NotNil(t, inverseY)
	constant := new(big.Int).Add(baseA, sA)
	constant.Sub(constant, baseB)
	constant.Sub(constant, sB)
	constant.Mod(constant, prime)
	maxBlock := new(big.Int).Lsh(big.NewInt(1), 128)
	var x, y *big.Int
	for candidate := int64(0); candidate < 256; candidate++ {
		x = big.NewInt(candidate)
		numerator := new(big.Int).Mul(coefficientX, x)
		numerator.Add(numerator, constant)
		numerator.Neg(numerator)
		numerator.Mod(numerator, prime)
		y = new(big.Int).Mul(numerator, inverseY)
		y.Mod(y, prime)
		if y.Cmp(maxBlock) < 0 {
			break
		}
	}
	require.NotNil(t, y)
	assert.Less(t, y.Cmp(maxBlock), 0, "could not find a bounded ciphertext block collision")
	ciphertext := make([]byte, 32)
	copy(ciphertext[:16], bigIntLittleEndian(x, 16))
	copy(ciphertext[16:], bigIntLittleEndian(y, 16))
	message := poly1305Message(associatedData, ciphertext)
	var tag [16]byte
	poly1305.Sum(&tag, message, &oneTimeA)
	return ciphertext, tag
}

func poly1305Key(t *testing.T, key, nonce []byte) [32]byte {
	t.Helper()
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	require.NoError(t, err)
	stream := make([]byte, 64)
	cipher.XORKeyStream(stream, make([]byte, len(stream)))
	var polyKey [32]byte
	copy(polyKey[:], stream[:32])
	return polyKey
}

func poly1305Parameters(key [32]byte) (*big.Int, *big.Int) {
	rawR := bytes.Clone(key[:16])
	rawR[3] &= 15
	rawR[7] &= 15
	rawR[11] &= 15
	rawR[15] &= 15
	rawR[4] &= 252
	rawR[8] &= 252
	rawR[12] &= 252
	return littleEndianBigInt(rawR), littleEndianBigInt(key[16:])
}

func poly1305Accumulator(associatedData, ciphertext []byte, r, prime *big.Int) *big.Int {
	message := poly1305Message(associatedData, ciphertext)
	accumulator := new(big.Int)
	for offset := 0; offset < len(message); offset += 16 {
		block := new(big.Int).SetBytes(reverseBytes(message[offset : offset+16]))
		block.Add(block, new(big.Int).Lsh(big.NewInt(1), 128))
		accumulator.Add(accumulator, block)
		accumulator.Mul(accumulator, r)
		accumulator.Mod(accumulator, prime)
	}
	return accumulator
}

func poly1305Message(associatedData, ciphertext []byte) []byte {
	message := bytes.Clone(associatedData)
	if remainder := len(message) % 16; remainder != 0 {
		message = append(message, make([]byte, 16-remainder)...)
	}
	message = append(message, ciphertext...)
	if remainder := len(ciphertext) % 16; remainder != 0 {
		message = append(message, make([]byte, 16-remainder)...)
	}
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[:8], uint64(len(associatedData)))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(len(ciphertext)))
	return append(message, lengths[:]...)
}

func littleEndianBigInt(value []byte) *big.Int {
	return new(big.Int).SetBytes(reverseBytes(value))
}

func reverseBytes(value []byte) []byte {
	result := bytes.Clone(value)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func bigIntLittleEndian(value *big.Int, length int) []byte {
	bigEndian := value.Bytes()
	result := make([]byte, length)
	for index := 0; index < len(bigEndian); index++ {
		result[index] = bigEndian[len(bigEndian)-index-1]
	}
	return result
}

func TestOpenRejectsValidEnvelopeUnderDifferentPurpose(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	changed := fixture.envelope
	changed.Purpose = PurposeAttestation
	_, err := Open(changed, fixture.openRequest)
	assert.ErrorIs(t, err, ErrSignature)
}

func TestSealPackOutputKeepsPlaintextPathsAndValuesPrivate(t *testing.T) {
	path := "dottie-secret/config.toml"
	value := "private-value-never-in-envelope"
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("files", "dottie-secret", model.SelectionDirectory)},
		Entries: []model.Entry{fileEntry("files", path, model.FileRegular, model.FilePresent, []byte(value))},
	}
	blob, err := Pack(snapshot)
	require.NoError(t, err)
	fixture := newEnvelopeFixture(t)
	prepared := fixture.prepared
	prepared.Plaintext = blob.Payload
	prepared.PublicationID = [16]byte(fixtureBytes(11, 16))
	envelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	encoded, err := EncodeEnvelope(envelope)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), path)
	assert.NotContains(t, string(encoded), value)
}

func TestObjectMagicKindAndUnknownRolesAreRejected(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	policyBytes := bytes.Clone(fixture.policyBytes)
	policyBytes[4] = objectKindCertificate
	_, err := DecodePolicy(policyBytes)
	assert.ErrorIs(t, err, ErrFormat)
	unsupported := bytes.Clone(fixture.policyBytes)
	unsupported[3] = 2
	_, err = DecodePolicy(unsupported)
	assert.ErrorIs(t, err, ErrUnsupportedVersion)
	badRole := fixture.policy
	badRole.Roles = []RoleBinding{{DeviceID: "device-root", Role: 99}}
	_, err = EncodePolicy(badRole)
	assert.ErrorIs(t, err, ErrFormat)
}

func TestObjectCrossVaultPolicyAuthorization(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := fixture.openRequest
	request.Vault[0] ^= 1
	_, err := Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func TestObjectDecodersRejectTrailingAndTruncatedInput(t *testing.T) {
	vectors := signedVectors(t)
	decoders := map[string]func([]byte) error{
		"policy-root-signed-chain.hex":                func(data []byte) error { _, err := DecodePolicy(data); return err },
		"control-root-signed-chain.hex":               func(data []byte) error { _, err := DecodeControl(data); return err },
		"certificate-publisher-root-issued-chain.hex": func(data []byte) error { _, err := DecodeCertificate(data); return err },
		"checkpoint-root-signed-chain.hex":            func(data []byte) error { _, err := DecodeCheckpoint(data); return err },
		"attestation-root-signed-chain.hex":           func(data []byte) error { _, err := DecodeAttestation(data); return err },
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			data := vectors[name]
			for index := 0; index < len(data); index++ {
				assert.Error(t, decode(data[:index]), "accepted truncated object at %d", index)
			}
			assert.ErrorIs(t, decode(append(bytes.Clone(data), 0)), ErrFormat)
		})
	}
}

func TestObjectDecodersBoundHostileInputAllocations(t *testing.T) {
	hostile := bytes.Repeat([]byte{0xff}, MaxPolicyObjectBytes+1)
	copy(hostile[:3], wireMagic[:])
	hostile[3] = wireVersion
	decoders := []struct {
		kind   byte
		decode func([]byte) error
	}{
		{objectKindPolicy, func(data []byte) error { _, err := DecodePolicy(data); return err }},
		{objectKindControl, func(data []byte) error { _, err := DecodeControl(data); return err }},
		{objectKindCertificate, func(data []byte) error { _, err := DecodeCertificate(data); return err }},
		{objectKindCheckpoint, func(data []byte) error { _, err := DecodeCheckpoint(data); return err }},
		{objectKindAttestation, func(data []byte) error { _, err := DecodeAttestation(data); return err }},
	}
	for _, decoder := range decoders {
		t.Run(string(rune('0'+decoder.kind)), func(t *testing.T) {
			hostile[4] = decoder.kind
			allocations := testing.AllocsPerRun(20, func() {
				if err := decoder.decode(hostile); !errors.Is(err, ErrLimit) {
					panic("hostile object length was not rejected by the limit pass")
				}
			})
			assert.LessOrEqual(t, allocations, 20.0)
		})
	}
}

func TestEnvelopeDecodeBoundsDeclaredLengthsBeforeAllocation(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	encoded, err := EncodeEnvelope(fixture.envelope)
	require.NoError(t, err)
	fieldOffset := len(encoded) - ed25519.SignatureSize - 16 - len(fixture.envelope.Ciphertext) - 4
	binary.BigEndian.PutUint32(encoded[fieldOffset:fieldOffset+4], ^uint32(0))
	allocations := testing.AllocsPerRun(20, func() {
		_, decodeErr := DecodeEnvelope(encoded)
		if !errors.Is(decodeErr, ErrLimit) {
			panic("hostile ciphertext length was not rejected by the length pass")
		}
	})
	assert.LessOrEqual(t, allocations, 20.0)
}

func FuzzDecodeEnvelope(f *testing.F) {
	f.Add(vectorSeed("envelope-one-recipient-chain.hex"))
	f.Add([]byte{0x44, 0x54, 0x45, 1, 1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeEnvelope(data)
	})
}

func FuzzDecodePolicy(f *testing.F) {
	f.Add(vectorSeed("policy-root-signed-chain.hex"))
	f.Add(vectorSeed("policy-many-recipients-root-signed-chain.hex"))
	f.Add([]byte{0x44, 0x54, 0x45, 1, objectKindPolicy})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodePolicy(data) })
}

func FuzzDecodeControl(f *testing.F) {
	f.Add(vectorSeed("control-root-signed-chain.hex"))
	f.Add([]byte{0x44, 0x54, 0x45, 1, objectKindControl})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeControl(data) })
}

func FuzzDecodeCertificate(f *testing.F) {
	f.Add(vectorSeed("certificate-publisher-root-issued-chain.hex"))
	f.Add(vectorSeed("certificate-root-self-signed.hex"))
	f.Add([]byte{0x44, 0x54, 0x45, 1, objectKindCertificate})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeCertificate(data) })
}

func FuzzDecodeCheckpoint(f *testing.F) {
	f.Add(vectorSeed("checkpoint-root-signed-chain.hex"))
	f.Add([]byte{0x44, 0x54, 0x45, 1, objectKindCheckpoint})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeCheckpoint(data) })
}

func FuzzDecodeAttestation(f *testing.F) {
	f.Add(vectorSeed("attestation-root-signed-chain.hex"))
	f.Add([]byte{0x44, 0x54, 0x45, 1, objectKindAttestation})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeAttestation(data) })
}

func vectorSeed(name string) []byte {
	encoded, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		return nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil
	}
	return decoded
}

func TestOpenRejectsPolicyEpochMismatch(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	shifted := fixture.policy
	shifted.EpochSeq = fixture.policy.EpochSeq + 1
	shiftedBytes := signPolicyValue(t, shifted, fixture.signingKey)
	shiftedDigest, err := ComputePolicyDigest(shiftedBytes)
	require.NoError(t, err)
	prepared := fixture.prepared
	prepared.PolicyDigest = shiftedDigest
	envelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	request := fixture.openRequest
	request.Policy = shiftedBytes
	request.PolicyDigest = shiftedDigest
	_, err = Open(envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization, "a policy whose epoch differs from the envelope must not authorize it")
}

func TestSealAuthorizedEnforcesRole(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := SealRequest{
		Purpose: PurposeSnapshot, Vault: fixture.policy.Vault,
		PublicationID: [16]byte(fixtureBytes(101, 16)), EpochSeq: fixture.policy.EpochSeq,
		PolicyDigest: fixture.prepared.PolicyDigest, Parent: fixtureCIDBytes(t),
		DeviceID: fixture.certificate.DeviceID, KeyID: fixture.certificate.KeyID,
		Plaintext: []byte("authorized sealing"), SigningKey: fixture.publisherKey,
		Recipients: []RecipientPublicKey{{KeyID: []byte("recipient-a"), PublicKey: fixture.recipientKey.PublicKey().Bytes()}},
	}
	_, err := SealAuthorized(request, fixture.certificate, fixture.policy)
	require.NoError(t, err, "a publisher certificate listed in the policy may seal a snapshot")

	restoreOnly := fixture.certificate
	restoreOnly.Role = RoleRestoreOnly
	_, err = SealAuthorized(request, restoreOnly, fixture.policy)
	assert.ErrorIs(t, err, ErrAuthorization, "a restore-only certificate must not seal")

	absent := fixture.certificate
	absent.DeviceID = "device-unknown"
	_, err = SealAuthorized(request, absent, fixture.policy)
	assert.ErrorIs(t, err, ErrAuthorization, "a certificate absent from the policy must not seal")

	restorePolicy := fixture.policy
	restorePolicy.Roles = append(restorePolicy.Roles, RoleBinding{DeviceID: "device-restore", Role: RoleRestoreOnly})
	restoreCert := fixture.certificate
	restoreCert.DeviceID = "device-restore"
	restoreCert.Role = RoleRestoreOnly
	_, err = SealAuthorized(request, restoreCert, restorePolicy)
	assert.ErrorIs(t, err, ErrAuthorization,
		"a restore-only device the policy does name must still be refused by the purpose rule")
}

func TestSealAuthorizedRefusesSubstitutedRecipientPair(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	secondRecipientKey := fixedX25519Key(23)
	policy := fixture.policy
	policy.Roles = append(policy.Roles, RoleBinding{DeviceID: "device-second", Role: RoleRestoreOnly})
	policy.Recipients = append(policy.Recipients, PolicyRecipient{
		DeviceID: "device-second", KeyID: []byte("recipient-b"), PublicKey: [32]byte(secondRecipientKey.PublicKey().Bytes()),
	})
	policyBytes := signPolicyValue(t, policy, fixture.signingKey)
	policyDigest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	exactPairs := []RecipientPublicKey{
		{KeyID: bytes.Clone(policy.Recipients[0].KeyID), PublicKey: bytes.Clone(policy.Recipients[0].PublicKey[:])},
		{KeyID: bytes.Clone(policy.Recipients[1].KeyID), PublicKey: bytes.Clone(policy.Recipients[1].PublicKey[:])},
	}
	request := SealRequest{
		Purpose: PurposeSnapshot, Vault: policy.Vault,
		PublicationID: [16]byte(fixtureBytes(101, 16)), EpochSeq: policy.EpochSeq,
		PolicyDigest: policyDigest, Parent: fixtureCIDBytes(t),
		DeviceID: fixture.certificate.DeviceID, KeyID: fixture.certificate.KeyID,
		Plaintext: []byte("authorized sealing"), SigningKey: fixture.publisherKey,
		Recipients: exactPairs,
	}

	wrongDevicePair := request
	wrongDevicePair.Recipients = append([]RecipientPublicKey(nil), exactPairs...)
	wrongDevicePair.Recipients[0].PublicKey = bytes.Clone(exactPairs[1].PublicKey)
	wrongDevicePair.Recipients[1].PublicKey = bytes.Clone(exactPairs[0].PublicKey)
	duplicatedPair := request
	duplicatedPair.Recipients = append([]RecipientPublicKey(nil), exactPairs...)
	duplicatedPair.Recipients[1] = RecipientPublicKey{KeyID: bytes.Clone(exactPairs[0].KeyID), PublicKey: bytes.Clone(exactPairs[0].PublicKey)}
	omittedPair := request
	omittedPair.Recipients = append([]RecipientPublicKey(nil), exactPairs[:1]...)

	t.Run("exact pair set accepted", func(t *testing.T) {
		_, err := SealAuthorized(request, fixture.certificate, policy)
		require.NoError(t, err, "SealAuthorized accepts the exact two-recipient policy pair set")
	})
	for _, test := range []struct {
		name    string
		request SealRequest
	}{
		{name: "pair assigned to the wrong device", request: wrongDevicePair},
		{name: "duplicated pair with another omitted", request: duplicatedPair},
		{name: "omitted pair", request: omittedPair},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := SealAuthorized(test.request, fixture.certificate, policy)
			require.ErrorIs(t, err, ErrRecipient, "SealAuthorized must require exact policy recipient pairs")
		})
	}
}

func TestEnvelopeCodecRefusesDuplicateRecipientKeyIDs(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	secondRecipientKey := fixedX25519Key(23)
	prepared := fixture.prepared
	prepared.Recipients = append(append([]PreparedRecipient(nil), fixture.prepared.Recipients...), PreparedRecipient{
		KeyID: []byte("recipient-b"), PublicKey: secondRecipientKey.PublicKey().Bytes(),
		EphemeralPrivate: fixedX25519Key(42).Bytes(), WrapNonce: [24]byte(fixtureBytes(201, 24)),
	})
	envelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	encoded, err := EncodeEnvelope(envelope)
	require.NoError(t, err)

	duplicateObject := envelope
	duplicateObject.Recipients = append([]EnvelopeRecipient(nil), envelope.Recipients...)
	duplicateObject.Recipients[1].KeyID = bytes.Clone(duplicateObject.Recipients[0].KeyID)
	_, err = EncodeEnvelope(duplicateObject)
	require.ErrorIs(t, err, ErrRecipient, "the encoder refuses duplicate recipient key IDs")

	duplicateWire := bytes.Clone(encoded)
	secondKeyIDOffset := bytes.Index(duplicateWire, []byte("recipient-b"))
	require.NotEqual(t, -1, secondKeyIDOffset, "the valid encoded envelope contains the second recipient key ID")
	copy(duplicateWire[secondKeyIDOffset:], []byte("recipient-a"))
	_, err = DecodeEnvelope(duplicateWire)
	require.ErrorIs(t, err, ErrRecipient,
		"the decoder refuses duplicate recipient key IDs before the reader can observe such an envelope")
}
