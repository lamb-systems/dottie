package atproto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const genesisTestDID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"

type genesisMemoryTransport struct {
	mu                   sync.Mutex
	current              atprototest.SignedRevision
	repositoryKey        *atcrypto.PrivateKeyP256
	blobs                map[string][]byte
	events               []string
	applyCalls           int
	loseBeforeApply      bool
	loseAfterApply       bool
	failLatestAfterApply int
	failGenesisBlobs     bool
	blobReadCalls        int
	omitCheckpoint       bool
	mismatchCheckpoint   bool
	writeActions         []string
}

func TestCommitGenesisPublishesAllCreatesAndVerifiesRealVaultRead(t *testing.T) {
	fixture := newGenesisFixture(t)
	result, err := CommitGenesis(context.Background(), fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.NoError(t, err)
	require.NotNil(t, result.Revision)
	assert.Equal(t, result.Revision.CommitCID(), result.CommitCID)
	assert.Equal(t, FreshnessUnverified, result.ReadResult.Freshness)
	assert.Zero(t, result.ReadResult.PublicationCount)
	assert.Equal(t, fixture.genesis.SnapshotCID, result.ReadResult.HeadCID)
	assert.Equal(t, fixture.genesis.ControlCID, result.ReadResult.ControlCID)
	assert.Equal(t, 6, len(result.Revision.Records()))
	assert.Equal(t, 1, fixture.transport.applyCalls)
	assert.Equal(t, 6, len(fixture.transport.writeActions))
	for _, action := range fixture.transport.writeActions {
		assert.Equal(t, "com.atproto.repo.applyWrites#create", action)
	}
	assert.NotEmpty(t, result.CheckpointCID)
	assert.Equal(t, GenesisVerified, result.Phase)
	assert.Len(t, result.RecordTargets, 6)
	assert.True(t, result.Revision.HasRecord(RecordKey{Collection: VaultCheckpointNSID, RKey: "self"}))
}

func TestCommitGenesisResolvesLostApplyResponseByVerifiedRead(t *testing.T) {
	fixture := newGenesisFixture(t)
	fixture.transport.loseAfterApply = true
	result, err := CommitGenesis(context.Background(), fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.NoError(t, err)
	assert.Equal(t, 1, fixture.transport.applyCalls)
	assert.Equal(t, GenesisVerified, result.Phase)
	assert.True(t, result.Revision.HasRecord(RecordKey{Collection: VaultCheckpointNSID, RKey: "self"}))
	assert.GreaterOrEqual(t, countGenesisEvent(fixture.transport.events, "latest"), 4)
}

func TestCommitGenesisRequiresVerifiedAbsenceBeforeAnotherAttempt(t *testing.T) {
	fixture := newGenesisFixture(t)
	fixture.transport.loseBeforeApply = true
	result, err := CommitGenesis(context.Background(), fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.ErrorIs(t, err, ErrGenesisNotLanded)
	assert.Equal(t, GenesisSubmitted, result.Phase)
	assert.Len(t, result.RecordTargets, 6)
	assert.Equal(t, 1, fixture.transport.applyCalls)
	beforeSecond := len(fixture.transport.events)

	result, err = CommitGenesis(context.Background(), fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.NoError(t, err)
	assert.Equal(t, 2, fixture.transport.applyCalls)
	assert.True(t, result.Revision.HasRecord(RecordKey{Collection: VaultCheckpointNSID, RKey: "self"}))
	secondApply := eventIndex(fixture.transport.events, "applyWrites", 2)
	require.GreaterOrEqual(t, secondApply, beforeSecond+4)
	assert.Equal(t, []string{"latest", "repo", "latest", "uploadBlob"}, fixture.transport.events[secondApply-4:secondApply])
}

func TestCommitGenesisRetriesBoundedReadbackFailures(t *testing.T) {
	fixture := newGenesisFixture(t)
	fixture.transport.failLatestAfterApply = 2
	result, err := CommitGenesis(context.Background(), fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.NoError(t, err)
	assert.Equal(t, GenesisVerified, result.Phase)
	assert.Equal(t, 0, fixture.transport.failLatestAfterApply)
	assert.GreaterOrEqual(t, countGenesisEvent(fixture.transport.events, "latest"), 6)
}

func TestCommitGenesisPreservesVerifiedMembershipWhenFinalReadbackFails(t *testing.T) {
	fixture := newGenesisFixture(t)
	fixture.transport.failGenesisBlobs = true
	result, err := CommitGenesis(context.Background(), fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.ErrorIs(t, err, ErrGenesisReadbackRejected)
	assert.Equal(t, GenesisMembershipVerified, result.Phase)
	assert.Len(t, result.RecordTargets, 6)
	assert.Equal(t, 3, fixture.transport.blobReadCalls)
	assert.ErrorIs(t, err, ErrGenesisReadbackRejected)
}

func TestCommitGenesisRejectsOmittedOrMismatchedCheckpoint(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*genesisMemoryTransport)
	}{
		{name: "omitted", set: func(transport *genesisMemoryTransport) { transport.omitCheckpoint = true }},
		{name: "mismatched", set: func(transport *genesisMemoryTransport) { transport.mismatchCheckpoint = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGenesisFixture(t)
			test.set(fixture.transport)
			result, err := CommitGenesis(context.Background(), fixture.io, fixture.kit, fixture.root, fixture.genesis)
			require.ErrorIs(t, err, ErrGenesisCheckpointMismatch)
			assert.Equal(t, GenesisSubmitted, result.Phase)
			assert.Equal(t, 1, fixture.transport.applyCalls)
		})
	}
}

type genesisFixture struct {
	kit       []byte
	root      vault.DeviceMaterial
	genesis   vault.Genesis
	transport *genesisMemoryTransport
	io        GenesisIO
	store     *state.Store
}

func newGenesisFixture(t *testing.T) genesisFixture {
	t.Helper()
	kit := bytes.Repeat([]byte{7}, 32)
	root := vault.DeviceMaterial{DeviceID: "genesis-root", KeyID: []byte("genesis-root-key"), Signing: fixtureSigningKey(11), Recipient: readX25519Key(t, 21)}
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: "genesis commit fixture", RootDevice: root, ContentKey: bytes.Repeat([]byte{31}, 32),
		Wraps: []vault.RecipientWrapInput{{
			KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(readX25519Key(t, 22).Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{51}, 24)),
		}},
		PublicationID: [16]byte(bytes.Repeat([]byte{61}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{71}, 24)),
	})
	require.NoError(t, err)
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	initial, err := atprototest.BuildSignedRevision(genesisTestDID, repositoryKey, nil)
	require.NoError(t, err)
	transport := &genesisMemoryTransport{current: initial, repositoryKey: repositoryKey, blobs: make(map[string][]byte)}
	rootDir := t.TempDir()
	store, err := state.Open(platform.Paths{Home: filepath.Join(rootDir, "home"), StateHome: filepath.Join(rootDir, "state")})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	io := GenesisIO{
		Reader: RevisionReader{
			DIDDocumentID: genesisTestDID,
			VerificationMethods: []VerificationMethod{{
				ID: initial.VerificationMethod.ID, Type: initial.VerificationMethod.Type,
				Controller: initial.VerificationMethod.Controller, PublicKeyMultibase: initial.VerificationMethod.PublicKeyMultibase,
			}},
		},
		Transport: transport, BlobUploadLimit: 1 << 20, DID: genesisTestDID, ObservationStore: store,
	}
	return genesisFixture{kit: kit, root: root, genesis: genesis, transport: transport, io: io, store: store}
}

func (transport *genesisMemoryTransport) Do(_ context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.events = append(transport.events, eventForEndpoint(endpoint))
	switch endpoint {
	case "com.atproto.sync.getLatestCommit":
		if transport.applyCalls > 0 && transport.failLatestAfterApply > 0 {
			transport.failLatestAfterApply--
			return 503, nil, nil
		}
		return 200, jsonBytes(map[string]any{"cid": transport.current.CommitCID.String(), "rev": atprototest.RepositoryRevision}), nil
	case "com.atproto.repo.uploadBlob":
		if contentType != "application/octet-stream" {
			return 400, []byte(`{"error":"InvalidMimeType"}`), nil
		}
		blob, err := atprototest.BuildBlob(body)
		if err != nil {
			return 400, nil, err
		}
		transport.blobs[blob.CID.String()] = bytes.Clone(body)
		response, err := json.Marshal(struct {
			Blob atdata.Blob `json:"blob"`
		}{Blob: blob.Reference})
		if err != nil {
			return 500, nil, err
		}
		return 200, response, nil
	case "com.atproto.repo.applyWrites":
		transport.applyCalls++
		var input applyWritesInput
		if err := json.Unmarshal(body, &input); err != nil || input.Repo != genesisTestDID || input.SwapCommit != transport.current.CommitCID.String() {
			return 400, []byte(`{"error":"InvalidSwap"}`), nil
		}
		records := make([]atprototest.Record, 0, len(input.Writes))
		for _, encoded := range input.Writes {
			var write struct {
				Type       string          `json:"$type"`
				Collection string          `json:"collection"`
				RKey       string          `json:"rkey"`
				Value      json.RawMessage `json:"value"`
			}
			if err := json.Unmarshal(encoded, &write); err != nil {
				return 400, []byte(`{"error":"InvalidRecord"}`), nil
			}
			transport.writeActions = append(transport.writeActions, write.Type)
			if transport.omitCheckpoint && write.Collection == VaultCheckpointNSID {
				continue
			}
			value := write.Value
			if transport.mismatchCheckpoint && write.Collection == VaultCheckpointNSID {
				record, err := decodeRecordJSON(value)
				if err != nil {
					return 400, nil, err
				}
				checkpoint, ok := record.(CheckpointRecord)
				if !ok {
					return 400, nil, ErrRecord
				}
				checkpoint.Anchor = bytes.Clone(checkpoint.Anchor)
				checkpoint.Anchor[0] ^= 0xff
				value, err = marshalRecord(checkpoint)
				if err != nil {
					return 400, nil, err
				}
			}
			if transport.loseBeforeApply {
				transport.loseBeforeApply = false
				return 0, nil, errors.New("synthetic response lost before apply")
			}
			record, err := decodeRecordJSON(value)
			if err != nil {
				return 400, nil, err
			}
			recordBytes, err := EncodeRecord(record)
			if err != nil {
				return 400, nil, err
			}
			records = append(records, atprototest.Record{Collection: write.Collection, RKey: write.RKey, Data: recordBytes})
		}
		next, err := atprototest.BuildSignedRevision(genesisTestDID, transport.repositoryKey, records)
		if err != nil {
			return 500, nil, err
		}
		transport.current = next
		if transport.loseAfterApply {
			transport.loseAfterApply = false
			return 0, nil, errors.New("synthetic response lost after apply")
		}
		return 200, jsonBytes(map[string]any{"commit": map[string]any{"cid": next.CommitCID.String()}}), nil
	default:
		return 404, []byte(`{"error":"NotFound"}`), nil
	}
}

func (transport *genesisMemoryTransport) OpenStream(_ context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.events = append(transport.events, eventForEndpoint(endpoint))
	switch endpoint {
	case "com.atproto.sync.getRepo":
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(transport.current.CAR))), nil
	case "com.atproto.sync.getBlob":
		transport.blobReadCalls++
		if transport.failGenesisBlobs {
			return 503, nil, nil
		}
		data, exists := transport.blobs[query.Get("cid")]
		if !exists {
			return 404, nil, nil
		}
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(data))), nil
	default:
		return 404, nil, nil
	}
}

func eventForEndpoint(endpoint string) string {
	switch endpoint {
	case "com.atproto.sync.getLatestCommit":
		return "latest"
	case "com.atproto.sync.getRepo":
		return "repo"
	case "com.atproto.repo.uploadBlob":
		return "uploadBlob"
	case "com.atproto.repo.applyWrites":
		return "applyWrites"
	default:
		return endpoint
	}
}

func jsonBytes(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func countGenesisEvent(events []string, name string) int {
	count := 0
	for _, event := range events {
		if event == name {
			count++
		}
	}
	return count
}

func eventIndex(events []string, name string, occurrence int) int {
	found := 0
	for index, event := range events {
		if event == name {
			found++
			if found == occurrence {
				return index
			}
		}
	}
	return -1
}
