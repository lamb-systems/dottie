package atproto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const legacyGenesisFixturePath = "testdata/legacy-genesis/records.json"

type legacyGenesisRecord struct {
	Collection string `json:"collection"`
	RKey       string `json:"rkey"`
	Data       string `json:"data"`
}

type legacyGenesisFixture struct {
	Records []legacyGenesisRecord `json:"records"`
	Blob    string                `json:"blob"`
	Vault   string                `json:"vault"`
	Anchor  string                `json:"anchor"`
}

func readLegacyGenesisFixture(t *testing.T) legacyGenesisFixture {
	t.Helper()
	encoded, err := os.ReadFile(legacyGenesisFixturePath)
	require.NoError(t, err)
	var fixture legacyGenesisFixture
	require.NoError(t, json.Unmarshal(encoded, &fixture))
	require.Len(t, fixture.Records, 6)
	return fixture
}

func decodeLegacyFixtureField(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

func decodeLegacyRecord(t *testing.T, data []byte) Record {
	t.Helper()
	require.NotEmpty(t, data)
	record, err := DecodeRecord(data)
	require.NoError(t, err)
	return record
}

func TestRetiredKitBootstrappedGenesisRecordsRemainReadable(t *testing.T) {
	fixture := readLegacyGenesisFixture(t)
	var expectedVault, anchor [32]byte
	copy(expectedVault[:], decodeLegacyFixtureField(t, fixture.Vault))
	copy(anchor[:], decodeLegacyFixtureField(t, fixture.Anchor))
	blob := decodeLegacyFixtureField(t, fixture.Blob)

	records := make([]atprototest.Record, 0, len(fixture.Records))
	byKey := make(map[RecordKey][]byte, len(fixture.Records))
	for _, record := range fixture.Records {
		data := decodeLegacyFixtureField(t, record.Data)
		records = append(records, atprototest.Record{Collection: record.Collection, RKey: record.RKey, Data: data})
		byKey[RecordKey{Collection: record.Collection, RKey: record.RKey}] = data
	}

	publishedCheckpoint, ok := decodeLegacyRecord(t, byKey[RecordKey{Collection: VaultCheckpointNSID, RKey: "self"}]).(CheckpointRecord)
	require.True(t, ok)
	assert.Equal(t, "recovery-kit", publishedCheckpoint.SignerDeviceID,
		"the retired path signed the genesis checkpoint with a kit-derived key")
	publishedPolicy, ok := decodeLegacyRecord(t, byKey[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}]).(PolicyRecord)
	require.True(t, ok)
	assert.NotEqual(t, make([]byte, 32), publishedPolicy.RecoveryAnchor,
		"the retired path published a kit fingerprint as the policy recovery anchor")

	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	revision, err := atprototest.BuildSignedRevision(genesisTestDID, repositoryKey, records)
	require.NoError(t, err)
	blobCID, err := rawBlobCID(blob)
	require.NoError(t, err)
	parsedBlobCID, err := cid.Cast(blobCID)
	require.NoError(t, err)
	transport := &genesisMemoryTransport{
		current: revision, repositoryKey: repositoryKey,
		blobs: map[string][]byte{parsedBlobCID.String(): blob},
	}
	rootDir := t.TempDir()
	store, err := state.Open(platform.Paths{Home: filepath.Join(rootDir, "home"), StateHome: filepath.Join(rootDir, "state")})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	recipient, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{21}, 32))
	require.NoError(t, err)
	reader := VaultReader{Transport: transport, ObservationStore: store, Clock: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	read, err := reader.Read(context.Background(), ReadRequest{
		DID: genesisTestDID, DIDDocumentID: genesisTestDID,
		VerificationMethods: []VerificationMethod{{
			ID: revision.VerificationMethod.ID, Type: revision.VerificationMethod.Type,
			Controller: revision.VerificationMethod.Controller, PublicKeyMultibase: revision.VerificationMethod.PublicKeyMultibase,
		}},
		Vault: expectedVault, TrustAnchor: anchor,
		DeviceKeyID: []byte("genesis-root-key"), DeviceKey: recipient,
	})
	require.NoError(t, err, "the vault read must authenticate a repository published by the retired kit path")
	packed, err := vault.Pack(model.Snapshot{Version: model.SnapshotVersion})
	require.NoError(t, err)
	assert.Equal(t, packed.Payload, read.Plaintext)

	checkpoint, evidence, err := TrustMaterialFromVerifiedRead(read, anchor)
	require.NoError(t, err)
	assert.Equal(t, expectedVault, checkpoint.Vault)
	assert.Equal(t, anchor, checkpoint.Anchor)
	assert.Zero(t, checkpoint.Epoch)
	positioned, err := vault.DecodeCheckpoint(evidence.CheckpointPosition)
	require.NoError(t, err)
	assert.Equal(t, publishedCheckpoint.SignerDeviceID, positioned.Signer.DeviceID,
		"the authenticated position still carries the retired kit signer")
	assert.Equal(t, bytes.Clone(publishedCheckpoint.Signature), positioned.Signature[:])
}
