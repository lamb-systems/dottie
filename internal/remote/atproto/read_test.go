package atproto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/vault"
)

type readFixture struct {
	request          ReadRequest
	transport        *readTransport
	observationStore *state.Store
	records          map[RecordKey][]byte
	blocks           []proofBlock
	root             cid.Cid
}

type readTransport struct {
	*proofTransport
	blob       []byte
	blobStatus int
	blobErr    error
	blobCalls  int
}

func (f *readTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	if endpoint == "com.atproto.sync.getBlob" {
		f.blobCalls++
		if f.blobErr != nil {
			return f.blobStatus, nil, f.blobErr
		}
		status := f.blobStatus
		if status == 0 {
			status = 200
		}
		if status == 404 {
			return status, nil, nil
		}
		return status, io.NopCloser(bytes.NewReader(f.blob)), nil
	}
	return f.proofTransport.OpenStream(ctx, endpoint, query)
}

func newReadFixture(t *testing.T) readFixture {
	t.Helper()
	rootSigning := fixtureSigningKey(11)
	rootRecipient := readX25519Key(t, 21)
	publisherSigning := fixtureSigningKey(12)
	publisherRecipient := readX25519Key(t, 22)
	kit := bytes.Repeat([]byte{7}, 32)
	rootDevice := vault.DeviceMaterial{DeviceID: "root", KeyID: []byte("root-sign"), Signing: rootSigning, Recipient: rootRecipient}
	bootstrap, err := vault.Bootstrap(kit, "read fixture", rootDevice)
	require.NoError(t, err)
	ephemeralPublisher := readX25519Key(t, 31)
	ephemeralRoot := readX25519Key(t, 32)
	publisher := vault.DeviceMaterial{DeviceID: "publisher", KeyID: []byte("publisher-sign"), Signing: publisherSigning, Recipient: publisherRecipient}
	intent := vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: bootstrap.Vault, Signer: rootDevice,
		NewDevice: &publisher, RequestedRole: vault.RolePublisher, ContentKey: bytes.Repeat([]byte{41}, 32),
		Recipients: [][]byte{bootstrap.Certificate},
		Wraps: []vault.RecipientWrapInput{
			{KeyID: []byte("publisher-sign"), EphemeralPrivate: [32]byte(ephemeralPublisher.Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{51}, 24))},
			{KeyID: []byte("root-sign"), EphemeralPrivate: [32]byte(ephemeralRoot.Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{52}, 24))},
		},
		Plaintext: []byte("synthetic snapshot payload"), PublicationID: [16]byte(bytes.Repeat([]byte{61}, 16)),
		Nonce: [24]byte(bytes.Repeat([]byte{62}, 24)),
	}
	predecessor := vault.Predecessor{
		ControlCID: readRawCID(t, bootstrap.Control), PolicyDigest: readPolicyDigest(t, bootstrap.Policy),
		EpochSeq: 0, Control: bootstrap.Control, Policy: bootstrap.Policy,
		Certificates: [][]byte{bootstrap.Certificate}, TrustAnchor: bootstrap.Anchor,
	}
	transition, err := vault.PrepareTransition(predecessor, intent)
	require.NoError(t, err)
	policyObject, err := vault.DecodePolicy(transition.Policy)
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(transition.Policy)
	require.NoError(t, err)
	publisherCertificate, err := vault.DecodeCertificate(transition.Certificate)
	require.NoError(t, err)
	recipients := make([]vault.RecipientPublicKey, len(policyObject.Recipients))
	for index, recipient := range policyObject.Recipients {
		recipients[index] = vault.RecipientPublicKey{KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:])}
	}
	envelope, err := vault.SealAuthorized(vault.SealRequest{
		Purpose: vault.PurposeSnapshot, Vault: bootstrap.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{71}, 16)),
		EpochSeq: policyObject.EpochSeq, PolicyDigest: policyDigest, DeviceID: publisher.DeviceID, KeyID: publisher.KeyID,
		Plaintext: []byte("synthetic snapshot payload"), SigningKey: publisherSigning, Recipients: recipients,
	}, publisherCertificate, policyObject)
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	envelopeCID := readRawCID(t, envelopeBytes)
	parsedEnvelopeCID, err := cid.Cast(envelopeCID)
	require.NoError(t, err)
	controlObject, err := vault.DecodeControl(transition.Control)
	require.NoError(t, err)
	controlObject.HeadSnapshotCID = bytes.Clone(envelopeCID)
	controlBytes := signReadControl(t, controlObject, rootSigning)
	controlObject, err = vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	headObject := vault.Head{
		Vault: bootstrap.Vault, EpochSeq: policyObject.EpochSeq, PolicyDigest: policyDigest,
		SnapshotCID: bytes.Clone(envelopeCID), BlobCID: bytes.Clone(envelopeCID), PublicationCount: 1,
		Signer: vault.Signer{DeviceID: publisher.DeviceID, KeyID: bytes.Clone(publisher.KeyID)},
	}
	headBytes := signReadHead(t, headObject, publisherSigning)
	headObject, err = vault.DecodeHead(headBytes)
	require.NoError(t, err)
	digestValue := sha256Digest(envelope.Signature[:])
	snapshot := SnapshotRecord{
		SchemaVersion: 1, Vault: bytes.Clone(envelope.Vault[:]), PublicationID: bytes.Clone(envelope.PublicationID[:]),
		EpochSeq: envelope.EpochSeq, PolicyDigest: bytes.Clone(envelope.PolicyDigest[:]), Parent: bytes.Clone(envelope.Parent),
		Blob:           atdata.Blob{Ref: atdata.CIDLink(parsedEnvelopeCID), MimeType: "application/octet-stream", Size: int64(len(envelopeBytes))},
		SignerDeviceID: envelope.DeviceID, SignerKeyID: bytes.Clone(envelope.KeyID), EnvelopeSignatureDigest: digestValue[:],
	}
	snapshot, err = SignSnapshotRecord(snapshot, publisherSigning)
	require.NoError(t, err)
	snapshotBytes, err := EncodeRecord(snapshot)
	require.NoError(t, err)
	records := map[RecordKey][]byte{}
	putReadRecord(t, records, RecordKey{Collection: VaultPolicyNSID, RKey: "self"}, policyRecordFromObject(policyObject))
	putReadRecord(t, records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, controlRecordFromObject(controlObject))
	putReadRecord(t, records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, headRecordFromObject(headObject))
	records[RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}] = snapshotBytes
	for index, encodedCertificate := range transition.Recipients {
		certificate, decodeErr := vault.DecodeCertificate(encodedCertificate)
		require.NoError(t, decodeErr)
		putReadRecord(t, records, RecordKey{Collection: VaultCertificateNSID, RKey: fmt.Sprintf("r%d", index+1)}, certificateRecordFromObject(certificate))
	}
	car, blocks, root, method := buildReadCAR(t, records)
	transport := &readTransport{
		proofTransport: &proofTransport{
			carBytes: car, latestCIDs: repeatedCIDs(root.String(), 20), streamStatus: 200,
		},
		blob: bytes.Clone(envelopeBytes),
	}
	previousPolicy, err := vault.DecodePolicy(bootstrap.Policy)
	require.NoError(t, err)
	previousPolicyRecord, err := EncodeRecord(policyRecordFromObject(previousPolicy))
	require.NoError(t, err)
	previousControlRecord := encodeReadControlRecord(t, bootstrap.Control)
	storeRoot := t.TempDir()
	observationStore, err := state.Open(platform.Paths{
		Home: filepath.Join(storeRoot, "home"), StateHome: filepath.Join(storeRoot, "state"), CacheHome: filepath.Join(storeRoot, "cache"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, observationStore.Close()) })
	return readFixture{
		request: ReadRequest{
			DID: proofTestDID, DIDDocumentID: proofTestDID,
			VerificationMethods: []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: method}},
			Vault:               bootstrap.Vault, TrustAnchor: bootstrap.Anchor, PreviousPolicy: previousPolicyRecord,
			PreviousControl: previousControlRecord, DeviceKeyID: []byte("publisher-sign"), DeviceKey: publisherRecipient,
		},
		transport: transport, observationStore: observationStore, records: records, blocks: blocks, root: root,
	}
}

func (fixture readFixture) reader() VaultReader {
	return VaultReader{Transport: fixture.transport, ObservationStore: fixture.observationStore}
}

func repeatedCIDs(value string, count int) []string {
	result := make([]string, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func readX25519Key(t *testing.T, seed byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	return key
}

func readRawCID(t *testing.T, data []byte) []byte {
	t.Helper()
	value, err := rawBlobCID(data)
	require.NoError(t, err)
	return value
}

func signReadControl(t *testing.T, value vault.Control, key ed25519.PrivateKey) []byte {
	t.Helper()
	value.Signature = [ed25519.SignatureSize]byte{}
	unsigned, err := vault.EncodeControl(value)
	require.NoError(t, err)
	preimage := append([]byte("dottie/v1/sig"), unsigned[:len(unsigned)-ed25519.SignatureSize]...)
	signature, err := vault.Sign("dottie/v1/sig-control", preimage, key)
	require.NoError(t, err)
	copy(value.Signature[:], signature)
	encoded, err := vault.EncodeControl(value)
	require.NoError(t, err)
	return encoded
}

func signReadHead(t *testing.T, value vault.Head, key ed25519.PrivateKey) []byte {
	t.Helper()
	value.Signature = [ed25519.SignatureSize]byte{}
	unsigned, err := vault.EncodeHead(value)
	require.NoError(t, err)
	preimage := append([]byte("dottie/v1/sig"), unsigned[:len(unsigned)-ed25519.SignatureSize]...)
	signature, err := vault.Sign("dottie/v1/sig-head", preimage, key)
	require.NoError(t, err)
	copy(value.Signature[:], signature)
	encoded, err := vault.EncodeHead(value)
	require.NoError(t, err)
	return encoded
}

func readPolicyDigest(t *testing.T, data []byte) [32]byte {
	t.Helper()
	value, err := vault.ComputePolicyDigest(data)
	require.NoError(t, err)
	return value
}

func encodeReadControlRecord(t *testing.T, data []byte) []byte {
	t.Helper()
	control, err := vault.DecodeControl(data)
	require.NoError(t, err)
	record, err := EncodeRecord(controlRecordFromObject(control))
	require.NoError(t, err)
	return record
}

func sha256Digest(value []byte) [32]byte {
	return sha256.Sum256(value)
}

func putReadRecord(t *testing.T, records map[RecordKey][]byte, key RecordKey, record Record) {
	t.Helper()
	encoded, err := EncodeRecord(record)
	require.NoError(t, err)
	records[key] = encoded
}

func buildReadCAR(t *testing.T, records map[RecordKey][]byte) ([]byte, []proofBlock, cid.Cid, string) {
	t.Helper()
	privateKey, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	return buildReadCARWithPrivateKey(t, records, privateKey)
}

func buildReadCARWithPrivateKey(t *testing.T, records map[RecordKey][]byte, privateKey *atcrypto.PrivateKeyP256) ([]byte, []proofBlock, cid.Cid, string) {
	t.Helper()
	publicKey, err := privateKey.PublicKey()
	require.NoError(t, err)
	tree := mst.NewEmptyTree()
	blocks := make([]proofBlock, 0, len(records)+16)
	keys := make([]RecordKey, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Collection == keys[j].Collection {
			return keys[i].RKey < keys[j].RKey
		}
		return keys[i].Collection < keys[j].Collection
	})
	for _, key := range keys {
		data := records[key]
		blockCID := proofCID(t, data)
		path := []byte(key.Collection + "/" + key.RKey)
		_, err := tree.Insert(path, blockCID)
		require.NoError(t, err)
		blocks = append(blocks, proofBlock{cid: blockCID, data: bytes.Clone(data)})
	}
	rootCID := storeProofMST(t, tree.Root, &blocks)
	commit := &repo.Commit{DID: proofTestDID, Version: repo.ATPROTO_REPO_VERSION, Data: rootCID, Rev: "2222222222222"}
	require.NoError(t, commit.Sign(privateKey))
	commitBytes := new(bytes.Buffer)
	require.NoError(t, commit.MarshalCBOR(commitBytes))
	commitCID := proofCID(t, commitBytes.Bytes())
	blocks = append(blocks, proofBlock{cid: commitCID, data: commitBytes.Bytes()})
	car := encodeProofCAR(t, commitCID, blocks)
	return car, blocks, commitCID, publicKey.Multibase()
}

func replaceReadCAR(t *testing.T, fixture *readFixture, records map[RecordKey][]byte) {
	t.Helper()
	car, blocks, root, method := buildReadCAR(t, records)
	fixture.transport.carBytes = car
	fixture.transport.latestCIDs = repeatedCIDs(root.String(), 20)
	fixture.transport.streamCalls = 0
	fixture.transport.latestCalls = 0
	fixture.blocks = blocks
	fixture.root = root
	fixture.request.VerificationMethods = []VerificationMethod{{
		ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: method,
	}}
}

func TestVaultReaderAuthenticatesAndDecryptsPinnedSnapshot(t *testing.T) {
	fixture := newReadFixture(t)
	result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err)
	require.Equal(t, FreshnessUnverified, result.Freshness)
	require.Equal(t, []byte("synthetic snapshot payload"), result.Plaintext)
	require.Equal(t, uint64(1), result.PublicationCount)
	require.Equal(t, uint64(0), result.PublicationCountBaseline)
	require.Equal(t, result.Head.SnapshotCID, result.HeadCID)
	require.Equal(t, result.Head.EpochSeq, result.EpochSeq)
	require.Equal(t, fixture.root.String(), result.Revision.CommitCID())
	require.Equal(t, 1, fixture.transport.blobCalls)
}

func TestVaultReaderPersistsFirstSeenOncePerAuthenticatedEpoch(t *testing.T) {
	fixture := newReadFixture(t)
	reader := fixture.reader()
	reader.Clock = func() time.Time { return time.Unix(1_700_000_123, 0) }
	result, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	firstSeenAt, found, err := fixture.observationStore.VaultEpochFirstSeen(context.Background(), fixture.request.Vault, result.EpochSeq)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(1_700_000_123), firstSeenAt)

	reader.Clock = func() time.Time { return time.Unix(1_701_000_123, 0) }
	_, err = reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	firstSeenAt, found, err = fixture.observationStore.VaultEpochFirstSeen(context.Background(), fixture.request.Vault, result.EpochSeq)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(1_700_000_123), firstSeenAt)
}

func TestVaultReaderRequiresDurablePublicationObservationStore(t *testing.T) {
	fixture := newReadFixture(t)
	_, err := (VaultReader{Transport: fixture.transport}).Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrPublicationObservationRequired)
}

func TestVaultReaderRejectsLowerCountOnAuthenticatedReread(t *testing.T) {
	fixture := newReadFixture(t)
	reader := fixture.reader()
	first, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.PublicationCount)

	headKey := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
	decoded, err := DecodeRecord(fixture.records[headKey])
	require.NoError(t, err)
	head := headFromRecord(decoded.(HeadRecord))
	head.PublicationCount = 0
	lowerCount := signReadHead(t, head, fixtureSigningKey(12))
	headObject, err := vault.DecodeHead(lowerCount)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, headKey, headRecordFromObject(headObject))
	replaceReadCAR(t, &fixture, fixture.records)

	_, err = reader.Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrPublicationCountBackwards)
	var readErr *ReadError
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, ReadStageVaultAuth, readErr.Stage)
}

func TestVaultReaderRejectsZeroCountHeadOutsideEpochBaseline(t *testing.T) {
	fixture := newReadFixture(t)
	headKey := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
	headDecoded, err := DecodeRecord(fixture.records[headKey])
	require.NoError(t, err)
	require.IsType(t, HeadRecord{}, headDecoded)
	headRecord := headDecoded.(HeadRecord)
	headObject := headFromRecord(headRecord)
	headObject.PublicationCount = 0
	headBytes := signReadHead(t, headObject, fixtureSigningKey(12))
	headObject, err = vault.DecodeHead(headBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, headKey, headRecordFromObject(headObject))

	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	controlDecoded, err := DecodeRecord(fixture.records[controlKey])
	require.NoError(t, err)
	require.IsType(t, ControlRecord{}, controlDecoded)
	controlRecord := controlDecoded.(ControlRecord)
	controlObject := controlFromRecord(controlRecord)
	controlObject.HeadSnapshotCID = readRawCID(t, []byte("wrong epoch baseline"))
	controlBytes := signReadControl(t, controlObject, fixtureSigningKey(11))
	controlObject, err = vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, controlKey, controlRecordFromObject(controlObject))
	replaceReadCAR(t, &fixture, fixture.records)
	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadVaultAuthentication)
}

func TestVaultReaderRequiresDigestBoundPredecessorPolicy(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.request.PreviousPolicy = nil
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadPreviousPolicyRequired)
}

func TestVaultReaderRequiresControlForNonGenesisPolicy(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, _ := fixturePolicyParts(t, fixture)
	require.Equal(t, uint64(1), policy.EpochSeq)
	fixture.request.PreviousControl = nil
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadControlRequired)
}

func TestVaultReaderDoesNotDecryptWithoutDeviceKey(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.request.DeviceKey = nil
	fixture.request.DeviceKeyID = nil
	result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err)
	require.Nil(t, result.Plaintext)
	require.Equal(t, FreshnessUnverified, result.Freshness)
}

func TestVaultReaderRejectsCertificateContextMismatch(t *testing.T) {
	fixture := newReadFixture(t)
	mutated := false
	for key, data := range fixture.records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		decoded, err := DecodeRecord(data)
		require.NoError(t, err)
		certificateRecord, ok := decoded.(CertificateRecord)
		require.True(t, ok)
		if certificateRecord.DeviceID != "publisher" {
			continue
		}
		certificate := certificateFromRecord(certificateRecord)
		certificate.RevocationRef = []byte("not a revocation control")
		encoded := signReadCertificate(t, certificate, fixtureSigningKey(11))
		certificate, err = vault.DecodeCertificate(encoded)
		require.NoError(t, err)
		fixture.records[key], err = EncodeRecord(certificateRecordFromObject(certificate))
		require.NoError(t, err)
		mutated = true
	}
	require.True(t, mutated)
	replaceReadCAR(t, &fixture, fixture.records)
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecordContext)
}

func signReadCertificate(t *testing.T, value vault.Certificate, key ed25519.PrivateKey) []byte {
	t.Helper()
	value.Signature = [ed25519.SignatureSize]byte{}
	unsigned, err := vault.EncodeCertificate(value)
	require.NoError(t, err)
	preimage := append([]byte("dottie/v1/sig"), unsigned[:len(unsigned)-ed25519.SignatureSize]...)
	signature, err := vault.Sign("dottie/v1/sig-certificate", preimage, key)
	require.NoError(t, err)
	copy(value.Signature[:], signature)
	encoded, err := vault.EncodeCertificate(value)
	require.NoError(t, err)
	return encoded
}

func TestVaultReaderRejectsTamperedSnapshotRecord(t *testing.T) {
	fixture := newReadFixture(t)
	key := RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}
	record, err := DecodeRecord(fixture.records[key])
	require.NoError(t, err)
	snapshot := record.(SnapshotRecord)
	snapshot.Signature[0] ^= 0xff
	fixture.records[key], err = EncodeRecord(snapshot)
	require.NoError(t, err)
	replaceReadCAR(t, &fixture, fixture.records)
	_, err = fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadRecordSignature)
}

func TestVaultReaderRejectsTamperedCARBlock(t *testing.T) {
	fixture := newReadFixture(t)
	for index := range fixture.blocks {
		if bytes.Equal(fixture.blocks[index].data, fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}]) {
			fixture.blocks[index].data = bytes.Clone(fixture.blocks[index].data)
			fixture.blocks[index].data[len(fixture.blocks[index].data)-1] ^= 1
			break
		}
	}
	fixture.transport.carBytes = encodeProofCAR(t, fixture.root, fixture.blocks)
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrUntrustedCar)
	assert.Zero(t, fixture.transport.blobCalls)
}

func TestVaultReaderDistinguishesBlobFailures(t *testing.T) {
	checks := []struct {
		name   string
		mutate func(*readFixture)
		want   error
	}{
		{name: "CID mismatch", mutate: func(fixture *readFixture) { fixture.transport.blob[len(fixture.transport.blob)-1] ^= 1 }, want: ErrReadBlobCIDMismatch},
		{name: "truncated", mutate: func(fixture *readFixture) {
			fixture.transport.blob = fixture.transport.blob[:len(fixture.transport.blob)-1]
		}, want: ErrReadBlobTruncated},
		{name: "missing", mutate: func(fixture *readFixture) { fixture.transport.blobStatus = 404 }, want: ErrReadBlobMissing},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			fixture := newReadFixture(t)
			check.mutate(&fixture)
			_, err := fixture.reader().Read(context.Background(), fixture.request)
			require.ErrorIs(t, err, check.want)
		})
	}
}

func TestVaultReaderRejectsWrongEpochPolicyDigestAndCrossVaultAtBinding(t *testing.T) {
	checks := []struct {
		name   string
		mutate func(*testing.T, *readFixture, SnapshotRecord) SnapshotRecord
	}{
		{name: "wrong epoch", mutate: func(t *testing.T, _ *readFixture, record SnapshotRecord) SnapshotRecord {
			record.EpochSeq++
			return mustSignReadSnapshot(t, record)
		}},
		{name: "wrong policy digest", mutate: func(t *testing.T, _ *readFixture, record SnapshotRecord) SnapshotRecord {
			record.PolicyDigest = bytes.Clone(record.PolicyDigest)
			record.PolicyDigest[0] ^= 1
			return mustSignReadSnapshot(t, record)
		}},
		{name: "cross vault", mutate: func(t *testing.T, fixture *readFixture, record SnapshotRecord) SnapshotRecord {
			record.Vault = bytes.Clone(record.Vault)
			record.Vault[0] ^= 1
			return mustSignReadSnapshot(t, record)
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			fixture := newReadFixture(t)
			key := RecordKey{Collection: VaultSnapshotNSID, RKey: "r0"}
			decoded, err := DecodeRecord(fixture.records[key])
			require.NoError(t, err)
			mutated := check.mutate(t, &fixture, decoded.(SnapshotRecord))
			fixture.records[key], err = EncodeRecord(mutated)
			require.NoError(t, err)
			replaceReadCAR(t, &fixture, fixture.records)
			_, err = fixture.reader().Read(context.Background(), fixture.request)
			require.ErrorIs(t, err, ErrReadRecordBinding)
			var readErr *ReadError
			require.ErrorAs(t, err, &readErr)
			require.Equal(t, ReadStageRecordBinding, readErr.Stage)
			assert.Equal(t, 1, fixture.transport.blobCalls)
		})
	}
}

func mustSignReadSnapshot(t *testing.T, record SnapshotRecord) SnapshotRecord {
	t.Helper()
	updated, err := SignSnapshotRecord(record, fixtureSigningKey(12))
	require.NoError(t, err)
	return updated
}

func TestVaultReaderRetriesMovingRevisionAndDoesNotReturnOldSnapshot(t *testing.T) {
	fixture := newReadFixture(t)
	otherCID := proofCID(t, []byte("later revision"))
	fixture.transport.latestCIDs = []string{fixture.root.String(), fixture.root.String(), otherCID.String()}
	_, err := fixture.reader().Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrRevisionMoving)
}

func TestVaultReaderRespectsCARBudget(t *testing.T) {
	fixture := newReadFixture(t)
	budgets := DefaultBudgets()
	budgets.MaxCarBytes = int64(len(fixture.transport.carBytes) - 1)
	_, err := (VaultReader{Transport: fixture.transport, ObservationStore: fixture.observationStore, Budgets: budgets}).Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrUntrustedCar)
	assert.Zero(t, fixture.transport.blobCalls)
}

func TestVaultReaderRejectsOversizedDeclaredBlobBeforeFetching(t *testing.T) {
	fixture := newReadFixture(t)
	reader := VaultReader{Transport: fixture.transport, ObservationStore: fixture.observationStore, MaxBlobBytes: 1}
	_, err := reader.Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrReadBlobTooLarge)
	assert.Zero(t, fixture.transport.blobCalls)
}

func TestCheckPublicationCountRefusesBackwardRead(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(platform.Paths{
		Home: filepath.Join(root, "home"), StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"),
	})
	require.NoError(t, err)
	defer store.Close()
	vaultID := [32]byte{9}
	headCID := readRawCID(t, []byte("head-4"))
	result := ReadResult{
		PublicationCount: 4, PublicationCountBaseline: 0, EpochSeq: 2, HeadCID: headCID, ControlCID: readRawCID(t, []byte("control-2")),
		Head:    HeadRecord{PublicationCount: 4, EpochSeq: 2, SnapshotCID: bytes.Clone(headCID)},
		Control: ControlRecord{HeadSnapshotCID: bytes.Clone(headCID)},
	}
	require.NoError(t, CheckPublicationCount(context.Background(), store, vaultID, result, PublicationCountOptions{}))
	backwardsCID := readRawCID(t, []byte("head-3"))
	result.PublicationCount = 3
	result.Head.PublicationCount = 3
	result.HeadCID = backwardsCID
	result.Head.SnapshotCID = bytes.Clone(backwardsCID)
	assert.ErrorIs(t, CheckPublicationCount(context.Background(), store, vaultID, result, PublicationCountOptions{}), ErrPublicationCountBackwards)
	result.PublicationCount = 4
	result.Head.PublicationCount = 4
	result.PublicationCountBaseline = 5
	assert.ErrorIs(t, CheckPublicationCount(context.Background(), store, vaultID, result, PublicationCountOptions{}), ErrPublicationCountBackwards)
}
