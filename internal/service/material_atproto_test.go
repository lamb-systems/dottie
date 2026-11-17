package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/vault"
)

const (
	atprotoMaterialDID       = "did:plc:abcdefghijklmnopqrstuvwx"
	atprotoMaterialOtherDID  = "did:plc:zyxwvutsrqponmlkjihgfedc"
	atprotoMaterialUploadCap = int64(1 << 20)
)

var errAtprotoMaterialLostResponse = errors.New("synthetic repository lost the applyWrites response after commit")

type atprotoMaterialRepository struct {
	mu                 sync.Mutex
	did                string
	key                *atcrypto.PrivateKeyP256
	revision           atprototest.SignedRevision
	records            map[atproto.RecordKey][]byte
	blobs              map[string][]byte
	calls              []string
	doCalls            int
	uploads            int
	applies            int
	swaps              []string
	applied            []atprotoMaterialApplyWrites
	servedCAR          []byte
	uploadMIMEType     string
	uploadCID          string
	uploadSize         *int64
	rejectApplyStatus  int
	rejectApplyCode    string
	rejectUploadStatus int
	rejectUploadCode   string
	loseApplyResponse  bool
	failTransport      error
}

func newATProtoMaterialRepository(t *testing.T, did string) *atprotoMaterialRepository {
	t.Helper()
	key, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	repository := &atprotoMaterialRepository{
		did: did, key: key,
		records: make(map[atproto.RecordKey][]byte), blobs: make(map[string][]byte),
	}
	repository.rebuild(t)
	return repository
}

func buildATProtoMaterialRevision(
	did string,
	key *atcrypto.PrivateKeyP256,
	records map[atproto.RecordKey][]byte,
) (atprototest.SignedRevision, error) {
	keys := make([]atproto.RecordKey, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].Collection != keys[right].Collection {
			return keys[left].Collection < keys[right].Collection
		}
		return keys[left].RKey < keys[right].RKey
	})
	ordered := make([]atprototest.Record, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, atprototest.Record{Collection: key.Collection, RKey: key.RKey, Data: records[key]})
	}
	return atprototest.BuildSignedRevision(did, key, ordered)
}

func (repository *atprotoMaterialRepository) rebuild(t *testing.T) {
	t.Helper()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.rebuildLocked(t)
}

func (repository *atprotoMaterialRepository) rebuildLocked(t *testing.T) {
	t.Helper()
	revision, err := buildATProtoMaterialRevision(repository.did, repository.key, repository.records)
	require.NoError(t, err)
	repository.revision = revision
	repository.servedCAR = nil
}

func (repository *atprotoMaterialRepository) verificationMethods() []atproto.VerificationMethod {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	method := repository.revision.VerificationMethod
	return []atproto.VerificationMethod{{
		ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
	}}
}

func (repository *atprotoMaterialRepository) readerFor(documentID string) atproto.RevisionReader {
	return atproto.RevisionReader{
		Transport: repository, DIDDocumentID: documentID, VerificationMethods: repository.verificationMethods(),
	}
}

func (repository *atprotoMaterialRepository) reader() atproto.RevisionReader {
	return repository.readerFor(repository.did)
}

func (repository *atprotoMaterialRepository) setRecords(t *testing.T, records map[atproto.RecordKey][]byte) {
	t.Helper()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.records = make(map[atproto.RecordKey][]byte, len(records))
	for key, data := range records {
		repository.records[key] = bytes.Clone(data)
	}
	repository.rebuildLocked(t)
}

func (repository *atprotoMaterialRepository) commitRecord(t *testing.T, key atproto.RecordKey, data []byte) {
	t.Helper()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.records[key] = bytes.Clone(data)
	repository.rebuildLocked(t)
}

func (repository *atprotoMaterialRepository) commitUnrelatedRecord(t *testing.T) {
	t.Helper()
	record, err := atprototest.BuildRecord(
		"app.bsky.feed.post",
		"self",
		map[string]any{"text": "synthetic unrelated record"},
	)
	require.NoError(t, err)
	repository.commitRecord(t, atproto.RecordKey{Collection: "app.bsky.feed.post", RKey: "self"}, record.Data)
}

func (repository *atprotoMaterialRepository) serveCar(t *testing.T, carBytes []byte) {
	t.Helper()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.servedCAR = bytes.Clone(carBytes)
}

func (repository *atprotoMaterialRepository) car() []byte {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.carLocked()
}

func (repository *atprotoMaterialRepository) carLocked() []byte {
	if repository.servedCAR != nil {
		return bytes.Clone(repository.servedCAR)
	}
	return bytes.Clone(repository.revision.CAR)
}

func (repository *atprotoMaterialRepository) commitCID() string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.revision.CommitCID.String()
}

func (repository *atprotoMaterialRepository) record(key atproto.RecordKey) []byte {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return bytes.Clone(repository.records[key])
}

func (repository *atprotoMaterialRepository) blob(payloadCID []byte) []byte {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	identifier, err := cid.Cast(payloadCID)
	if err != nil {
		return nil
	}
	return bytes.Clone(repository.blobs[identifier.String()])
}

func (repository *atprotoMaterialRepository) blobRetrievable(payloadCID []byte) bool {
	return repository.blob(payloadCID) != nil
}

func (repository *atprotoMaterialRepository) doCount() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.doCalls
}

func (repository *atprotoMaterialRepository) uploadCount() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.uploads
}

func (repository *atprotoMaterialRepository) applyCount() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.applies
}

func (repository *atprotoMaterialRepository) swapsSeen() []string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]string(nil), repository.swaps...)
}

func (repository *atprotoMaterialRepository) appliedBodies() []atprotoMaterialApplyWrites {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]atprotoMaterialApplyWrites(nil), repository.applied...)
}

func (repository *atprotoMaterialRepository) rejectNextApply(status int, code string) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.rejectApplyStatus, repository.rejectApplyCode = status, code
}

func (repository *atprotoMaterialRepository) rejectNextUpload(status int, code string) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.rejectUploadStatus, repository.rejectUploadCode = status, code
}

func (repository *atprotoMaterialRepository) failNextTransportCall(err error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.failTransport = err
}

func (repository *atprotoMaterialRepository) loseNextApplyResponse() {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.loseApplyResponse = true
}

func (repository *atprotoMaterialRepository) overrideUpload(mimeType, identifier string, size *int64) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.uploadMIMEType, repository.uploadCID, repository.uploadSize = mimeType, identifier, size
}

func (repository *atprotoMaterialRepository) Do(
	ctx context.Context,
	method, endpoint string,
	_ url.Values,
	body []byte,
	contentType string,
) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.doCalls++
	switch endpoint {
	case "com.atproto.sync.getLatestCommit":
		if method != "GET" {
			return atprotoMaterialErrorResponse(400, "InvalidRequest")
		}
		return atprotoMaterialJSONResponse(map[string]string{
			"cid": repository.revision.CommitCID.String(), "rev": atprototest.RepositoryRevision,
		})
	case atprotoMaterialUploadEndpoint:
		if method != "POST" || contentType != publication.BlobMIMEType {
			return atprotoMaterialErrorResponse(400, "InvalidRequest")
		}
		repository.uploads++
		if repository.rejectUploadStatus != 0 {
			status, code := repository.rejectUploadStatus, repository.rejectUploadCode
			repository.rejectUploadStatus, repository.rejectUploadCode = 0, ""
			if code == "" {
				code = "UploadRejected"
			}
			return atprotoMaterialErrorResponse(status, code)
		}
		blob, err := atprototest.BuildBlob(body)
		if err != nil {
			return atprotoMaterialErrorResponse(400, "InvalidBlob")
		}
		repository.blobs[blob.CID.String()] = bytes.Clone(body)
		reference := map[string]any{
			"$type": atprotoMaterialBlobType, "ref": map[string]string{"$link": blob.CID.String()},
			"mimeType": publication.SnapshotBlobMIMEType, "size": int64(len(body)),
		}
		if repository.uploadMIMEType == "!empty!" {
			delete(reference, "mimeType")
		} else if repository.uploadMIMEType != "" {
			reference["mimeType"] = repository.uploadMIMEType
		}
		if repository.uploadCID != "" {
			reference["ref"] = map[string]string{"$link": repository.uploadCID}
		}
		if repository.uploadSize != nil {
			reference["size"] = *repository.uploadSize
		}
		return atprotoMaterialJSONResponse(map[string]any{"blob": reference})
	case atprotoMaterialApplyEndpoint:
		if method != "POST" || contentType != "application/json" {
			return atprotoMaterialErrorResponse(400, "InvalidRequest")
		}
		repository.applies++
		if repository.failTransport != nil {
			failure := repository.failTransport
			repository.failTransport = nil
			return 0, nil, failure
		}
		return repository.applyWrites(body)
	default:
		return atprotoMaterialErrorResponse(404, "NotFound")
	}
}

func (repository *atprotoMaterialRepository) applyWrites(body []byte) (int, []byte, error) {
	if repository.rejectApplyStatus != 0 {
		status, code := repository.rejectApplyStatus, repository.rejectApplyCode
		repository.rejectApplyStatus, repository.rejectApplyCode = 0, ""
		if code == "" {
			code = "ApplyWritesRejected"
		}
		return atprotoMaterialErrorResponse(status, code)
	}
	var input atprotoMaterialApplyWrites
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.Repo != repository.did || len(input.Writes) != 2 {
		return atprotoMaterialErrorResponse(400, "InvalidRequest")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return atprotoMaterialErrorResponse(400, "InvalidRequest")
	}
	repository.swaps = append(repository.swaps, input.SwapCommit)
	repository.applied = append(repository.applied, input)
	if input.SwapCommit != repository.revision.CommitCID.String() {
		return atprotoMaterialErrorResponse(400, "InvalidSwap")
	}
	snapshotWrites, headWrites := 0, 0
	next := make(map[atproto.RecordKey][]byte, len(repository.records)+2)
	maps.Copy(next, repository.records)
	seen := make(map[atproto.RecordKey]bool, len(input.Writes))
	for _, write := range input.Writes {
		key := atproto.RecordKey{Collection: write.Collection, RKey: write.RKey}
		if seen[key] {
			return atprotoMaterialErrorResponse(400, "InvalidRecord")
		}
		seen[key] = true
		_, exists := next[key]
		switch write.Type {
		case atprotoMaterialCreateAction:
			if exists {
				return atprotoMaterialErrorResponse(400, "RecordAlreadyExists")
			}
		case atprotoMaterialUpdateAction:
			if !exists {
				return atprotoMaterialErrorResponse(400, "RecordNotFound")
			}
		default:
			return atprotoMaterialErrorResponse(400, "InvalidRecord")
		}
		switch write.Collection {
		case publication.SnapshotNSID:
			snapshotWrites++
			if _, err := publication.ParseSequenceKey(write.RKey); err != nil {
				return atprotoMaterialErrorResponse(400, "InvalidRecord")
			}
		case publication.HeadNSID:
			headWrites++
			if write.RKey != materialHeadKey {
				return atprotoMaterialErrorResponse(400, "InvalidRecord")
			}
		default:
			return atprotoMaterialErrorResponse(400, "InvalidRecord")
		}
		value, err := atdata.UnmarshalJSON(write.Value)
		if err != nil || value["$type"] != write.Collection {
			return atprotoMaterialErrorResponse(400, "InvalidRecord")
		}
		for _, blob := range atdata.ExtractBlobs(value) {
			if _, stored := repository.blobs[cid.Cid(blob.Ref).String()]; !stored {
				return atprotoMaterialErrorResponse(400, "InvalidBlobReference")
			}
		}
		encoded, err := atdata.MarshalCBOR(value)
		if err != nil {
			return atprotoMaterialErrorResponse(400, "InvalidRecord")
		}
		next[key] = encoded
	}
	if snapshotWrites != 1 || headWrites != 1 {
		return atprotoMaterialErrorResponse(400, "InvalidRecord")
	}
	revision, err := buildATProtoMaterialRevision(repository.did, repository.key, next)
	if err != nil {
		return atprotoMaterialErrorResponse(400, "InvalidRecord")
	}
	repository.records = next
	repository.revision = revision
	repository.servedCAR = nil
	if repository.loseApplyResponse {
		repository.loseApplyResponse = false
		return 0, nil, errAtprotoMaterialLostResponse
	}
	return atprotoMaterialJSONResponse(map[string]any{"commit": map[string]string{"cid": revision.CommitCID.String()}})
}

func (repository *atprotoMaterialRepository) OpenStream(
	ctx context.Context,
	endpoint string,
	_ url.Values,
) (int, io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if endpoint != "com.atproto.sync.getRepo" {
		return 404, io.NopCloser(strings.NewReader(`{"error":"NotFound"}`)), nil
	}
	return 200, io.NopCloser(bytes.NewReader(repository.carLocked())), nil
}

func atprotoMaterialJSONResponse(value any) (int, []byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return atprotoMaterialErrorResponse(500, "InternalServerError")
	}
	return 200, encoded, nil
}

func atprotoMaterialErrorResponse(status int, code string) (int, []byte, error) {
	return status, []byte(fmt.Sprintf(`{"error":%q}`, strings.TrimSpace(code))), nil
}

func atprotoMaterialTamperSnapshot(t *testing.T, carBytes []byte, target cid.Cid, replacement []byte) []byte {
	t.Helper()
	reader, err := car.NewCarReader(bytes.NewReader(carBytes))
	require.NoError(t, err)
	require.Len(t, reader.Header.Roots, 1)
	var output bytes.Buffer
	require.NoError(t, car.WriteHeader(&car.CarHeader{Roots: []cid.Cid{reader.Header.Roots[0]}, Version: 1}, &output))
	replaced := false
	for {
		block, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		require.NoError(t, nextErr)
		data := block.RawData()
		if block.Cid().Equals(target) {
			data, replaced = replacement, true
		}
		section := append(bytes.Clone(block.Cid().Bytes()), data...)
		var length [binary.MaxVarintLen64]byte
		written := binary.PutUvarint(length[:], uint64(len(section)))
		output.Write(length[:written])
		output.Write(section)
	}
	require.True(t, replaced, "served CAR did not contain the targeted record block")
	return output.Bytes()
}

func newATProtoMaterialTransport(
	t *testing.T,
	binding publicationstate.Binding,
	did string,
	repository *atprotoMaterialRepository,
) *ATProtoMaterialTransport {
	t.Helper()
	transport, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
		Binding: binding, DID: did, Reader: repository.readerFor(did),
		Transport: repository, BlobUploadLimit: atprotoMaterialUploadCap,
	})
	require.NoError(t, err)
	return transport
}

func atprotoMaterialBinding(did string) publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: did, Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x61, 0x72, 0x83},
	}
	binding.Repository = "at://" + did
	return binding
}

func atprotoMaterialRecords(
	t *testing.T,
	binding publicationstate.Binding,
	publicationID [16]byte,
	sequence uint64,
	parent []byte,
) ([]byte, []byte) {
	t.Helper()
	payload := []byte(fmt.Sprintf("synthetic atproto repository payload %d", sequence))
	candidate := materialTestCandidate(t, binding, publicationID, sequence, parent, payload)
	return candidate.SnapshotRecord, candidate.HeadRecord
}

func atprotoMaterialGenesisRecords(t *testing.T, binding publicationstate.Binding) map[atproto.RecordKey][]byte {
	t.Helper()
	snapshotRecord, headRecord := atprotoMaterialRecords(t, binding, [16]byte{0x51, 0x61}, 0, nil)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	return map[atproto.RecordKey][]byte{
		{Collection: publication.SnapshotNSID, RKey: key}:         snapshotRecord,
		{Collection: publication.HeadNSID, RKey: materialHeadKey}: headRecord,
	}
}

type atprotoMaterialFixture struct {
	binding       publicationstate.Binding
	store         *publicationstate.Store
	repository    *atprotoMaterialRepository
	transport     *ATProtoMaterialTransport
	coordinator   *Coordinator
	snapshot      model.Snapshot
	publicationID [16]byte
	review        publicationstate.LocalReviewContext
	reviews       *materialReviewSource
}

func newATProtoMaterialFixture(t *testing.T) *atprotoMaterialFixture {
	t.Helper()
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	coordinator, err := NewCoordinator(Dependencies{State: openCoordinatorState(t)})
	require.NoError(t, err)
	review := publicationstate.LocalReviewContext{
		SelectionDigest: [32]byte{3}, SelectionRevision: 1, ApprovalDigest: [32]byte{4}, ApprovalRevision: 1,
	}
	return &atprotoMaterialFixture{
		binding: binding, store: store, repository: repository, transport: transport, coordinator: coordinator,
		snapshot: materialTestSnapshot("synthetic atproto genesis payload"), publicationID: [16]byte{0x35, 0x81},
		review: review, reviews: newMaterialReviewSource(review),
	}
}

func (fixture *atprotoMaterialFixture) request() MaterialPublishRequest {
	return MaterialPublishRequest{
		Store: fixture.store, Transport: fixture.transport, Binding: fixture.binding,
		Snapshot: fixture.snapshot, PublicationID: fixture.publicationID, Reviews: fixture.reviews,
	}
}

func (fixture *atprotoMaterialFixture) prepare(t *testing.T) MaterialPublishProposal {
	t.Helper()
	proposal, err := fixture.coordinator.PreparePublishMaterial(context.Background(), fixture.request())
	require.NoError(t, err)
	return proposal
}

func (fixture *atprotoMaterialFixture) publish(t *testing.T) (MaterialPublishProposal, MaterialPublishResult) {
	t.Helper()
	proposal := fixture.prepare(t)
	result, err := fixture.coordinator.PublishMaterial(context.Background(), proposal, proposal.Confirmation)
	require.NoError(t, err)
	return proposal, result
}

func requireATProtoMaterialRefusal(t *testing.T, err error, class error, reason string) {
	t.Helper()
	require.ErrorIs(t, err, class)
	var refusal *atprotoMaterialError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, reason, refusal.Reason())
}

func TestMaterialATProtoGenesisPublishesThroughCoordinator(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)

	empty, err := fixture.transport.ReadView(ctx)
	require.NoError(t, err)
	assert.Equal(t, fixture.binding, empty.Origin)
	assert.Equal(t, publicationstate.ViewScopeWholeRepository, empty.Scope)
	assert.Empty(t, empty.Head)
	assert.Empty(t, empty.Snapshots)
	assert.Equal(t, atprototest.RepositoryRevision, empty.SuppliedContext.RepositoryRevision)
	assert.Equal(t, []byte(fixture.repository.commitCID()), empty.SuppliedContext.RepositoryDigest)
	assert.Nil(t, empty.SuppliedContext.Policy)

	proposal := fixture.prepare(t)
	assert.Equal(t, publication.SnapshotNSID, proposal.Batch.SnapshotCollection)
	assert.Equal(t, publication.HeadNSID, proposal.Batch.HeadCollection)
	assert.True(t, proposal.Batch.SnapshotCreateOnly)
	assert.True(t, proposal.Batch.HeadCreate)
	assert.Nil(t, proposal.Batch.ExpectedPredecessor)
	assert.Nil(t, proposal.Batch.ExpectedContext.Policy)

	result, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.OutcomeCurrent, result.Outcome)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, result.Attempt.Lifecycle)
	assert.Equal(t, uint64(1), result.Floor.Revision)
	assert.Equal(t, uint64(0), result.Floor.Sequence)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, result.Floor.RecordCID)
	assert.Equal(t, proposal.Blob.CID, result.Floor.BlobCID)
	assert.Equal(t, proposal.Batch.HeadRecord, result.Floor.Head)

	assert.Equal(t, 1, fixture.repository.uploadCount())
	assert.Equal(t, 1, fixture.repository.applyCount())
	assert.Equal(t, []string{string(proposal.Batch.ExpectedContext.RepositoryDigest)}, fixture.repository.swapsSeen())
	bodies := fixture.repository.appliedBodies()
	require.Len(t, bodies, 1)
	assert.Equal(t, fixture.binding.AccountDID, bodies[0].Repo)
	require.Len(t, bodies[0].Writes, 2)
	assert.Equal(t, atprotoMaterialCreateAction, bodies[0].Writes[0].Type)
	assert.Equal(t, proposal.Batch.SnapshotKey, bodies[0].Writes[0].RKey)
	assert.Equal(t, atprotoMaterialCreateAction, bodies[0].Writes[1].Type)
	assert.Equal(t, materialHeadKey, bodies[0].Writes[1].RKey)

	assert.Equal(
		t,
		proposal.Batch.SnapshotRecord,
		fixture.repository.record(
			atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: proposal.Batch.SnapshotKey},
		),
	)
	assert.Equal(
		t,
		proposal.Batch.HeadRecord,
		fixture.repository.record(atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey}),
	)
	require.True(t, fixture.repository.blobRetrievable(proposal.Blob.CID))
	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	assert.Equal(t, packed.Payload, fixture.repository.blob(proposal.Blob.CID))

	committed, err := fixture.transport.ReadView(ctx)
	require.NoError(t, err)
	require.Len(t, committed.Snapshots, 1)
	assert.Equal(t, proposal.Batch.SnapshotRecord, committed.Snapshots[0].Raw)
	assert.Equal(t, proposal.Batch.HeadRecord, committed.Head)

	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, result.Floor, floor)
}

func TestMaterialATProtoSuccessorFencesPreviousCommit(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	genesisProposal, genesis := fixture.publish(t)
	afterGenesis := fixture.repository.commitCID()

	fixture.publicationID = [16]byte{0x35, 0x82}
	fixture.snapshot = materialTestSnapshot("synthetic atproto successor payload")
	proposal := fixture.prepare(t)
	assert.False(t, proposal.Batch.HeadCreate)
	require.NotNil(t, proposal.Batch.ExpectedPredecessor)
	assert.Equal(t, publicationstate.RecordReference{
		Key: genesisProposal.Batch.SnapshotKey, CID: genesis.Floor.RecordCID, Sequence: 0,
	}, *proposal.Batch.ExpectedPredecessor)

	result, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), result.Floor.Revision)
	assert.Equal(t, uint64(1), result.Floor.Sequence)
	record, err := publication.DecodeSnapshot(proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, genesis.Floor.RecordCID, record.Parent)

	assert.Equal(
		t,
		[]string{string(genesisProposal.Batch.ExpectedContext.RepositoryDigest), afterGenesis},
		fixture.repository.swapsSeen(),
	)
	bodies := fixture.repository.appliedBodies()
	require.Len(t, bodies, 2)
	assert.Equal(t, atprotoMaterialCreateAction, bodies[1].Writes[0].Type)
	assert.Equal(t, atprotoMaterialUpdateAction, bodies[1].Writes[1].Type)
	assert.Equal(
		t,
		genesisProposal.Batch.SnapshotRecord,
		fixture.repository.record(
			atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: genesisProposal.Batch.SnapshotKey},
		),
	)
	assert.Equal(
		t,
		proposal.Batch.HeadRecord,
		fixture.repository.record(atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey}),
	)
}

func TestMaterialATProtoRefusesFenceChangedAtRepository(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	genesisProposal, genesis := fixture.publish(t)

	packed, err := vault.Pack(materialTestSnapshot("synthetic atproto fenced payload"))
	require.NoError(t, err)
	candidate := materialTestCandidate(
		t,
		fixture.binding,
		[16]byte{0x35, 0x83},
		1,
		genesis.Floor.RecordCID,
		packed.Payload,
	)
	view, err := fixture.transport.ReadView(ctx)
	require.NoError(t, err)
	captured := genesis.Floor
	batch, err := newMaterialWriteBatch(fixture.binding, &captured, view, candidate)
	require.NoError(t, err)
	blob, err := fixture.transport.UploadPayload(ctx, candidate.Payload)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, fixture.repository.blob(blob.CID))
	prepared, err := fixture.transport.PrepareWrites(ctx, batch)
	require.NoError(t, err)
	assert.Equal(t, string(batch.ExpectedContext.RepositoryDigest), fixture.repository.commitCID())
	_ = genesisProposal

	fixture.repository.commitUnrelatedRecord(t)
	movedTo := fixture.repository.commitCID()
	require.NotEqual(t, string(batch.ExpectedContext.RepositoryDigest), movedTo)
	appliesBefore := fixture.repository.applyCount()
	doBefore := fixture.repository.doCount()

	outcome, sendErr := fixture.transport.SendWrites(ctx, prepared)
	require.ErrorIs(t, sendErr, ErrATProtoMaterialProvider)
	require.ErrorIs(t, sendErr, atproto.ErrFenceLost)
	require.ErrorIs(t, sendErr, atproto.ErrCandidateMayBeDisclosed)
	var refusal *atprotoMaterialError
	require.ErrorAs(t, sendErr, &refusal)
	assert.Contains(t, refusal.Reason(), "dispatch_rejected:")
	assert.False(t, outcome.Committed)
	assert.Equal(t, appliesBefore+1, fixture.repository.applyCount())
	assert.Equal(t, doBefore+1, fixture.repository.doCount())
	assert.Equal(t, movedTo, fixture.repository.commitCID())
	assert.Empty(
		t,
		fixture.repository.record(atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: batch.SnapshotKey}),
	)
	swaps := fixture.repository.swapsSeen()
	require.Len(t, swaps, 2)
	assert.Equal(t, string(batch.ExpectedContext.RepositoryDigest), swaps[1])
}

func TestMaterialATProtoRecordsProviderExposureOnRejectedBatch(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	marker := "synthetic-atproto-plaintext-marker"
	fixture.snapshot = materialTestSnapshot(marker)
	fixture.repository.rejectNextApply(400, "StorageQuotaExceeded")
	proposal := fixture.prepare(t)

	result, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_rejected")
	require.ErrorIs(t, err, ErrMaterialSubmissionRejected)
	require.ErrorIs(t, err, atproto.ErrPublicationQuota)
	require.ErrorIs(t, err, atproto.ErrCandidateMayBeDisclosed)
	assert.NotContains(t, err.Error(), marker)
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.OutcomeRejected, attempt.Outcome)
	assert.Equal(t, publicationstate.AttemptRetiredAbandoned, attempt.Lifecycle)
	assert.Equal(t, result.Attempt.ID, attempt.ID)

	assert.Equal(t, 1, fixture.repository.applyCount())
	packed, packErr := vault.Pack(fixture.snapshot)
	require.NoError(t, packErr)
	assert.Equal(t, packed.Payload, fixture.repository.blob(proposal.Blob.CID))
	assert.Empty(
		t,
		fixture.repository.record(
			atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: proposal.Batch.SnapshotKey},
		),
	)
	assert.Empty(
		t,
		fixture.repository.record(atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey}),
	)

	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	_, active, activeErr := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, activeErr)
	assert.False(t, active, "a definite provider refusal left the attempt blocking")
	_, readErr := fixture.store.ReadCandidate(ctx, proposal.Proposal.AttemptID)
	var custody *publicationstate.Error
	require.ErrorAs(t, readErr, &custody)
	assert.Equal(t, publicationstate.ReasonCandidateMissing, custody.Reason())
}

func TestMaterialATProtoResolvesAmbiguousDispatchWithoutRetry(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	fixture.repository.loseNextApplyResponse()
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	require.ErrorIs(t, err, atproto.ErrAmbiguousTransport)
	require.ErrorIs(t, err, atproto.ErrCandidateMayBeDisclosed)
	assert.Equal(t, 1, fixture.repository.applyCount())
	assert.Equal(
		t,
		proposal.Batch.SnapshotRecord,
		fixture.repository.record(
			atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: proposal.Batch.SnapshotKey},
		),
	)

	view, err := fixture.transport.ReadView(ctx)
	require.NoError(t, err)
	loaded, err := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, err)
	resolution, err := fixture.store.ResolveAttempt(ctx, proposal.Proposal.AttemptID, loaded.StateDigest, view)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.OutcomeCurrent, resolution.Outcome)
	finalization, err := fixture.store.FinalizeAttempt(
		ctx,
		proposal.Proposal.AttemptID,
		resolution.Attempt.StateDigest,
		view,
	)
	require.NoError(t, err)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, finalization.Floor.RecordCID)
	assert.Equal(t, 1, fixture.repository.applyCount())
}

func TestMaterialATProtoRefusesPayloadAdmission(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	doBefore := fixture.repository.doCount()

	_, err := fixture.transport.UploadPayload(ctx, nil)
	requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialPayload, "payload_size")
	_, err = fixture.transport.UploadPayload(ctx, []byte{})
	requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialPayload, "payload_size")
	_, err = fixture.transport.UploadPayload(ctx, bytes.Repeat([]byte{0x41}, int(atprotoMaterialUploadCap)+1))
	requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialPayload, "payload_size")

	assert.Equal(t, doBefore, fixture.repository.doCount())
	assert.Equal(t, 0, fixture.repository.uploadCount())
	assert.Equal(t, 0, fixture.repository.applyCount())

	assert.Equal(t, uint64(0), atprotoMaterialPayloadLimit(0))
	assert.Equal(t, uint64(0), atprotoMaterialPayloadLimit(-1))
	assert.Equal(t, uint64(1024), atprotoMaterialPayloadLimit(1024))
	assert.Equal(t, uint64(atprotoMaterialUploadCap), atprotoMaterialPayloadLimit(atprotoMaterialUploadCap))
	assert.Equal(t, publication.MaxBlobBytes, atprotoMaterialPayloadLimit(int64(publication.MaxBlobBytes)))
	assert.Equal(t, publication.MaxBlobBytes, atprotoMaterialPayloadLimit(math.MaxInt64))
}

func TestMaterialATProtoRefusesUploadReferenceMismatch(t *testing.T) {
	ctx := context.Background()
	payload := []byte("synthetic atproto upload payload")
	otherCID, err := publication.RawPayloadCID([]byte("synthetic unrelated payload"))
	require.NoError(t, err)
	other, err := cid.Cast(otherCID)
	require.NoError(t, err)
	cases := []struct {
		name      string
		reason    string
		configure func(*atprotoMaterialRepository)
	}{
		{name: "cid", reason: "upload_reference_cid", configure: func(repository *atprotoMaterialRepository) {
			repository.overrideUpload("", other.String(), nil)
		}},
		{name: "size", reason: "upload_reference_size", configure: func(repository *atprotoMaterialRepository) {
			size := int64(len(payload) + 1)
			repository.overrideUpload("", "", &size)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			binding := atprotoMaterialBinding(atprotoMaterialDID)
			repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
			transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)
			testCase.configure(repository)
			_, uploadErr := transport.UploadPayload(ctx, payload)
			requireATProtoMaterialRefusal(t, uploadErr, ErrATProtoMaterialProvider, testCase.reason)
			require.ErrorIs(t, uploadErr, atproto.ErrCandidateMayBeDisclosed)
			assert.Equal(t, 1, repository.uploadCount())
			assert.Equal(t, 0, repository.applyCount())
		})
	}

	t.Run("accepts-a-canonicalised-media-type", func(t *testing.T) {
		binding := atprotoMaterialBinding(atprotoMaterialDID)
		repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
		repository.overrideUpload("application/x-tar", "", nil)
		transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)

		reference, uploadErr := transport.UploadPayload(ctx, payload)
		require.NoError(t, uploadErr)
		assert.Equal(t, uint64(len(payload)), reference.Size)
		assert.Equal(
			t,
			"application/x-tar",
			reference.MIMEType,
			"the provider's canonicalised media type must travel with the reference",
		)

		expected, cidErr := publication.RawPayloadCID(payload)
		require.NoError(t, cidErr)
		assert.Equal(t, expected, reference.CID)
	})

	t.Run("refuses-an-empty-media-type", func(t *testing.T) {
		binding := atprotoMaterialBinding(atprotoMaterialDID)
		repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
		repository.overrideUpload("!empty!", "", nil)
		transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)

		_, uploadErr := transport.UploadPayload(ctx, payload)
		requireATProtoMaterialRefusal(t, uploadErr, ErrATProtoMaterialProvider, "upload_reference_mime:empty")
	})

	t.Run("provider-rejection", func(t *testing.T) {
		binding := atprotoMaterialBinding(atprotoMaterialDID)
		repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
		transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)
		repository.rejectNextUpload(429, "")
		_, uploadErr := transport.UploadPayload(ctx, payload)
		requireATProtoMaterialRefusal(t, uploadErr, ErrATProtoMaterialProvider, "upload_rejected")
		require.ErrorIs(t, uploadErr, atproto.ErrPublicationRateLimited)
		require.ErrorIs(t, uploadErr, atproto.ErrCandidateMayBeDisclosed)
		var status *atproto.ProviderStatusError
		require.ErrorAs(t, uploadErr, &status)
		assert.Equal(t, 429, status.StatusCode)

		repository.rejectNextUpload(413, "BlobTooLarge")
		_, uploadErr = transport.UploadPayload(ctx, payload)
		require.ErrorIs(t, uploadErr, atproto.ErrCandidateExceedsBlobUploadLimit)
		require.ErrorIs(t, uploadErr, atproto.ErrCandidateMayBeDisclosed)
		assert.Equal(t, 2, repository.uploadCount())
	})
}

func TestMaterialATProtoRefusesIdentityMismatch(t *testing.T) {
	ctx := context.Background()
	binding := atprotoMaterialBinding(atprotoMaterialDID)

	t.Run("adapter-did-differs-from-binding", func(t *testing.T) {
		repository := newATProtoMaterialRepository(t, atprotoMaterialOtherDID)
		_, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
			Binding: binding, DID: atprotoMaterialOtherDID, Reader: repository.reader(),
			Transport: repository, BlobUploadLimit: atprotoMaterialUploadCap,
		})
		require.ErrorIs(t, err, ErrATProtoMaterialIdentity)
		assert.Equal(t, 0, repository.doCount())
		assert.Equal(t, 0, repository.applyCount())
	})

	t.Run("account-did-differs-from-adapter-did", func(t *testing.T) {
		repository := newATProtoMaterialRepository(t, atprotoMaterialOtherDID)
		substituted := atprotoMaterialBinding(atprotoMaterialOtherDID)
		substituted.AccountDID = atprotoMaterialDID
		_, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
			Binding: substituted, DID: atprotoMaterialOtherDID, Reader: repository.reader(),
			Transport: repository, BlobUploadLimit: atprotoMaterialUploadCap,
		})
		requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialIdentity, "identity")
		assert.Equal(t, 0, repository.doCount())
	})

	t.Run("binding-repository-differs", func(t *testing.T) {
		repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
		mismatched := binding
		mismatched.Repository = "at://" + atprotoMaterialOtherDID
		_, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
			Binding: mismatched, DID: atprotoMaterialDID, Reader: repository.reader(),
			Transport: repository, BlobUploadLimit: atprotoMaterialUploadCap,
		})
		require.ErrorIs(t, err, ErrATProtoMaterialIdentity)
		assert.Equal(t, 0, repository.doCount())
	})

	t.Run("binding-vault-is-zero", func(t *testing.T) {
		repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
		zeroVault := binding
		zeroVault.Vault = [32]byte{}
		_, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
			Binding: zeroVault, DID: atprotoMaterialDID, Reader: repository.reader(),
			Transport: repository, BlobUploadLimit: atprotoMaterialUploadCap,
		})
		require.ErrorIs(t, err, ErrATProtoMaterialIdentity)
		assert.Equal(t, 0, repository.doCount())
	})

	t.Run("authenticated-revision-did-differs", func(t *testing.T) {
		repository := newATProtoMaterialRepository(t, atprotoMaterialOtherDID)
		repository.setRecords(t, atprotoMaterialGenesisRecords(t, atprotoMaterialBinding(atprotoMaterialOtherDID)))
		transport, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
			Binding: binding, DID: atprotoMaterialDID, Reader: repository.readerFor(atprotoMaterialDID),
			Transport: repository, BlobUploadLimit: atprotoMaterialUploadCap,
		})
		require.NoError(t, err)
		view, viewErr := transport.ReadView(ctx)
		requireATProtoMaterialRefusal(t, viewErr, ErrATProtoMaterialView, "revision")
		require.ErrorIs(t, viewErr, atproto.ErrKeyBinding)
		assert.Equal(t, publicationstate.SuppliedRepositoryView{}, view)
		assert.Equal(t, 0, repository.uploadCount())
		assert.Equal(t, 0, repository.applyCount())
	})
}

func TestMaterialATProtoRefusesWriteBatchShapes(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	genesis := fixture.prepare(t).Batch

	genesisCases := []struct {
		name   string
		reason string
		tamper func(*MaterialWriteBatch)
	}{
		{name: "missing-head", reason: "record", tamper: func(batch *MaterialWriteBatch) { batch.HeadRecord = nil }},
		{
			name:   "missing-snapshot",
			reason: "record",
			tamper: func(batch *MaterialWriteBatch) { batch.SnapshotRecord = nil },
		},
		{
			name:   "wrong-snapshot-collection",
			reason: "collection",
			tamper: func(batch *MaterialWriteBatch) { batch.SnapshotCollection = publication.HeadNSID },
		},
		{
			name:   "wrong-head-collection",
			reason: "collection",
			tamper: func(batch *MaterialWriteBatch) { batch.HeadCollection = publication.SnapshotNSID },
		},
		{
			name:   "wrong-head-key",
			reason: "collection",
			tamper: func(batch *MaterialWriteBatch) { batch.HeadKey = "current" },
		},
		{
			name:   "wrong-snapshot-key",
			reason: "snapshot_key",
			tamper: func(batch *MaterialWriteBatch) { batch.SnapshotKey = "0000000000000009" },
		},
		{
			name:   "type-mismatch",
			reason: "head_record",
			tamper: func(batch *MaterialWriteBatch) { batch.HeadRecord = batch.SnapshotRecord },
		},
		{
			name:   "create-only-false",
			reason: "create_only",
			tamper: func(batch *MaterialWriteBatch) { batch.SnapshotCreateOnly = false },
		},
		{
			name:   "atomic-batch-false",
			reason: "conditions",
			tamper: func(batch *MaterialWriteBatch) { batch.RequiresAtomicBatch = false },
		},
		{
			name:   "create-exclude-false",
			reason: "conditions",
			tamper: func(batch *MaterialWriteBatch) { batch.RequiresCreateExclude = false },
		},
		{
			name:   "policy-check-true",
			reason: "conditions",
			tamper: func(batch *MaterialWriteBatch) { batch.RequiresPolicyCheck = true },
		},
		{name: "policy-not-nil", reason: "policy", tamper: func(batch *MaterialWriteBatch) {
			batch.ExpectedContext.Policy = &publicationstate.Policy{
				Revision:  "synthetic",
				Identity:  []byte{0x01},
				OwnerOnly: true,
			}
		}},
		{
			name:   "digest-not-a-cid",
			reason: "context",
			tamper: func(batch *MaterialWriteBatch) { batch.ExpectedContext.RepositoryDigest = []byte("synthetic-digest") },
		},
		{
			name:   "revision-missing",
			reason: "context",
			tamper: func(batch *MaterialWriteBatch) { batch.ExpectedContext.RepositoryRevision = "" },
		},
		{name: "unexpected-predecessor", reason: "predecessor", tamper: func(batch *MaterialWriteBatch) {
			batch.ExpectedPredecessor = &publicationstate.RecordReference{
				Key:      "0000000000000000",
				CID:      bytes.Clone(batch.ExpectedSnapshotCID),
				Sequence: 0,
			}
		}},
	}
	for _, testCase := range genesisCases {
		t.Run("genesis-"+testCase.name, func(t *testing.T) {
			batch := genesis
			batch.SnapshotRecord = bytes.Clone(genesis.SnapshotRecord)
			batch.ExpectedSnapshotCID = bytes.Clone(genesis.ExpectedSnapshotCID)
			batch.HeadRecord = bytes.Clone(genesis.HeadRecord)
			testCase.tamper(&batch)
			_, err := fixture.transport.PrepareWrites(ctx, batch)
			requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialBatch, testCase.reason)
			assert.Equal(t, 0, fixture.repository.uploadCount())
			assert.Equal(t, 0, fixture.repository.applyCount())
		})
	}

	t.Run("genesis-foreign-vault", func(t *testing.T) {
		foreign := fixture.binding
		foreign.Vault = [32]byte{0x11, 0x22, 0x33}
		snapshotRecord, headRecord := atprotoMaterialRecords(t, foreign, [16]byte{0x35, 0x84}, 0, nil)
		snapshotCID, err := publication.RecordCID(snapshotRecord)
		require.NoError(t, err)
		batch := genesis
		batch.SnapshotRecord = snapshotRecord
		batch.HeadRecord = headRecord
		batch.ExpectedSnapshotCID = snapshotCID
		_, err = fixture.transport.PrepareWrites(ctx, batch)
		requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialBatch, "vault")
	})

	_, published := fixture.publish(t)
	fixture.publicationID = [16]byte{0x35, 0x85}
	fixture.snapshot = materialTestSnapshot("synthetic atproto successor shape payload")
	successor := fixture.prepare(t).Batch
	appliesBefore := fixture.repository.applyCount()
	require.NotNil(t, successor.ExpectedPredecessor)
	assert.Equal(t, published.Floor.Sequence+1, mustATProtoMaterialSequence(t, successor))

	successorCases := []struct {
		name   string
		reason string
		tamper func(*MaterialWriteBatch)
	}{
		{
			name:   "missing-predecessor",
			reason: "predecessor",
			tamper: func(batch *MaterialWriteBatch) { batch.ExpectedPredecessor = nil },
		},
		{name: "predecessor-key-sequence", reason: "predecessor", tamper: func(batch *MaterialWriteBatch) {
			batch.ExpectedPredecessor.Key = "0000000000000009"
		}},
		{name: "predecessor-sequence", reason: "predecessor", tamper: func(batch *MaterialWriteBatch) {
			batch.ExpectedPredecessor.Sequence = 7
		}},
		{name: "predecessor-cid-role", reason: "predecessor", tamper: func(batch *MaterialWriteBatch) {
			batch.ExpectedPredecessor.CID = []byte("synthetic-predecessor-cid")
		}},
		{name: "predecessor-cid-differs", reason: "predecessor", tamper: func(batch *MaterialWriteBatch) {
			batch.ExpectedPredecessor.CID = bytes.Clone(successor.ExpectedSnapshotCID)
		}},
		{
			name:   "head-create-true",
			reason: "predecessor",
			tamper: func(batch *MaterialWriteBatch) { batch.HeadCreate = true },
		},
	}
	for _, testCase := range successorCases {
		t.Run("successor-"+testCase.name, func(t *testing.T) {
			batch := successor
			batch.SnapshotRecord = bytes.Clone(successor.SnapshotRecord)
			batch.ExpectedSnapshotCID = bytes.Clone(successor.ExpectedSnapshotCID)
			batch.HeadRecord = bytes.Clone(successor.HeadRecord)
			batch.ExpectedPredecessor = &publicationstate.RecordReference{
				Key:      successor.ExpectedPredecessor.Key,
				CID:      bytes.Clone(successor.ExpectedPredecessor.CID),
				Sequence: successor.ExpectedPredecessor.Sequence,
			}
			testCase.tamper(&batch)
			_, err := fixture.transport.PrepareWrites(ctx, batch)
			requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialBatch, testCase.reason)
			assert.Equal(t, appliesBefore, fixture.repository.applyCount())
		})
	}
}

func mustATProtoMaterialSequence(t *testing.T, batch MaterialWriteBatch) uint64 {
	t.Helper()
	record, err := publication.DecodeSnapshot(batch.SnapshotRecord)
	require.NoError(t, err)
	return record.PublicationSeq
}

func TestMaterialATProtoClassifiesDispatchOutcomes(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name       string
		status     int
		code       string
		failure    error
		expected   []error
		statusCode int
		reason     string
	}{
		{
			name:     "transport-error",
			failure:  errAtprotoMaterialLostResponse,
			reason:   "dispatch_ambiguous",
			expected: []error{atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed},
		},
		{
			name:       "rate-limited",
			status:     429,
			expected:   []error{atproto.ErrPublicationRateLimited, atproto.ErrCandidateMayBeDisclosed},
			statusCode: 429,
		},
		{
			name:       "quota",
			status:     400,
			code:       "StorageQuotaExceeded",
			expected:   []error{atproto.ErrPublicationQuota, atproto.ErrCandidateMayBeDisclosed},
			statusCode: 400,
		},
		{
			name:       "rate-limit-code",
			status:     400,
			code:       "RateLimitExceeded",
			expected:   []error{atproto.ErrPublicationRateLimited, atproto.ErrCandidateMayBeDisclosed},
			statusCode: 400,
		},
		{
			name:       "batch-too-large",
			status:     413,
			expected:   []error{atproto.ErrPublicationBatchTooLarge, atproto.ErrCandidateMayBeDisclosed},
			statusCode: 413,
		},
		{
			name:       "payload-too-large",
			status:     400,
			code:       "PayloadTooLarge",
			expected:   []error{atproto.ErrPublicationBatchTooLarge, atproto.ErrCandidateMayBeDisclosed},
			statusCode: 400,
		},
		{
			name:   "authorization",
			status: 403,
			expected: []error{
				atproto.ErrPublicationQueued,
				atproto.ErrBatchRejected,
				atproto.ErrCandidateMayBeDisclosed,
			},
			statusCode: 403,
		},
		{
			name:       "batch-rejected",
			status:     400,
			expected:   []error{atproto.ErrBatchRejected, atproto.ErrCandidateMayBeDisclosed},
			statusCode: 400,
		},
		{
			name:       "server-error",
			status:     503,
			expected:   []error{atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed},
			statusCode: 503,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newATProtoMaterialFixture(t)
			proposal := fixture.prepare(t)
			_, err := fixture.transport.UploadPayload(ctx, proposal.Candidate.Payload)
			require.NoError(t, err)
			prepared, err := fixture.transport.PrepareWrites(ctx, proposal.Batch)
			require.NoError(t, err)
			if testCase.failure != nil {
				fixture.repository.failNextTransportCall(testCase.failure)
			} else {
				fixture.repository.rejectNextApply(testCase.status, testCase.code)
			}
			outcome, sendErr := fixture.transport.SendWrites(ctx, prepared)
			if testCase.reason != "" {
				requireATProtoMaterialRefusal(t, sendErr, ErrATProtoMaterialProvider, testCase.reason)
			} else {
				var refusal *atprotoMaterialError
				require.ErrorAs(t, sendErr, &refusal)
				assert.Contains(t, refusal.Reason(), "dispatch_rejected:")
			}
			for _, expected := range testCase.expected {
				require.ErrorIs(t, sendErr, expected)
			}
			assert.False(t, outcome.Committed)
			assert.Equal(t, 1, fixture.repository.applyCount())
			if testCase.failure != nil {
				return
			}
			var status *atproto.ProviderStatusError
			require.ErrorAs(t, sendErr, &status)
			assert.Equal(t, testCase.statusCode, status.StatusCode)
		})
	}
}

func TestMaterialATProtoRefusesConsumedAndUnknownPreparedWrites(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	proposal := fixture.prepare(t)
	_, err := fixture.transport.UploadPayload(ctx, proposal.Candidate.Payload)
	require.NoError(t, err)
	prepared, err := fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)
	assert.Equal(t, 1, prepared.Dispatch)
	assert.NotEmpty(t, prepared.Secret)

	appliesBefore := fixture.repository.applyCount()
	_, err = fixture.transport.SendWrites(ctx, MaterialPreparedWrites{Secret: "synthetic-unknown-secret", Dispatch: 1})
	requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialPrepared, "consumed")
	_, err = fixture.transport.SendWrites(ctx, MaterialPreparedWrites{Secret: prepared.Secret, Dispatch: 2})
	requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialPrepared, "prepared")
	assert.Equal(t, appliesBefore, fixture.repository.applyCount())

	doBefore := fixture.repository.doCount()
	outcome, err := fixture.transport.SendWrites(ctx, prepared)
	require.NoError(t, err)
	assert.True(t, outcome.Committed)
	assert.Equal(t, appliesBefore+1, fixture.repository.applyCount())
	assert.Equal(t, doBefore+1, fixture.repository.doCount())

	_, err = fixture.transport.SendWrites(ctx, prepared)
	requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialPrepared, "consumed")
	assert.Equal(t, appliesBefore+1, fixture.repository.applyCount())
	assert.Equal(t, doBefore+1, fixture.repository.doCount())
}

func TestMaterialATProtoConsumesPreparedWritesOnError(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	fixture.repository.rejectNextApply(500, "InternalServerError")
	proposal := fixture.prepare(t)
	_, err := fixture.transport.UploadPayload(ctx, proposal.Candidate.Payload)
	require.NoError(t, err)
	prepared, err := fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)

	_, sendErr := fixture.transport.SendWrites(ctx, prepared)
	require.ErrorIs(t, sendErr, ErrATProtoMaterialProvider)
	require.ErrorIs(t, sendErr, atproto.ErrAmbiguousTransport)
	require.ErrorIs(t, sendErr, atproto.ErrCandidateMayBeDisclosed)
	appliesAfterFailure := fixture.repository.applyCount()
	assert.Equal(t, 1, appliesAfterFailure)

	_, replayErr := fixture.transport.SendWrites(ctx, prepared)
	requireATProtoMaterialRefusal(t, replayErr, ErrATProtoMaterialPrepared, "consumed")
	assert.Equal(t, appliesAfterFailure, fixture.repository.applyCount())
}

func TestMaterialATProtoDispatchesConcurrentSendsOnce(t *testing.T) {
	ctx := context.Background()
	fixture := newATProtoMaterialFixture(t)
	proposal := fixture.prepare(t)
	_, err := fixture.transport.UploadPayload(ctx, proposal.Candidate.Payload)
	require.NoError(t, err)
	prepared, err := fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)

	var wait sync.WaitGroup
	results := make([]error, 2)
	outcomes := make([]MaterialWriteOutcome, 2)
	wait.Add(2)
	for index := range results {
		go func(index int) {
			defer wait.Done()
			outcomes[index], results[index] = fixture.transport.SendWrites(ctx, prepared)
		}(index)
	}
	wait.Wait()

	assert.Equal(t, 1, fixture.repository.applyCount())
	committed := 0
	refused := 0
	for index, result := range results {
		if result == nil {
			committed++
			assert.True(t, outcomes[index].Committed)
			continue
		}
		requireATProtoMaterialRefusal(t, result, ErrATProtoMaterialPrepared, "consumed")
		refused++
	}
	assert.Equal(t, 1, committed)
	assert.Equal(t, 1, refused)
}

func TestMaterialATProtoRefusesRepositoryViews(t *testing.T) {
	ctx := context.Background()
	binding := atprotoMaterialBinding(atprotoMaterialDID)

	type viewCase struct {
		name      string
		reason    string
		records   func(t *testing.T) map[atproto.RecordKey][]byte
		servedCAR func(t *testing.T, repository *atprotoMaterialRepository) []byte
	}
	snapshotKey := func(t *testing.T, sequence uint64) atproto.RecordKey {
		t.Helper()
		key, err := publication.SequenceKey(sequence)
		require.NoError(t, err)
		return atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: key}
	}
	headKey := atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey}
	cases := []viewCase{
		{name: "missing-head", reason: "head", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			genesis := atprotoMaterialGenesisRecords(t, binding)
			delete(genesis, headKey)
			return genesis
		}},
		{name: "head-without-snapshot", reason: "snapshot", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			genesis := atprotoMaterialGenesisRecords(t, binding)
			delete(genesis, snapshotKey(t, 0))
			return genesis
		}},
		{name: "broken-chain", reason: "chain", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			first, _ := atprotoMaterialRecords(t, binding, [16]byte{0x51, 0x71}, 0, nil)
			firstCID, err := publication.RecordCID(first)
			require.NoError(t, err)
			third, head := atprotoMaterialRecords(t, binding, [16]byte{0x51, 0x73}, 2, firstCID)
			return map[atproto.RecordKey][]byte{snapshotKey(t, 0): first, snapshotKey(t, 2): third, headKey: head}
		}},
		{name: "parent-mismatch", reason: "chain", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			first, firstHead := atprotoMaterialRecords(t, binding, [16]byte{0x51, 0x74}, 0, nil)
			detached, err := publication.RecordCID(firstHead)
			require.NoError(t, err)
			second, head := atprotoMaterialRecords(t, binding, [16]byte{0x51, 0x75}, 1, detached)
			return map[atproto.RecordKey][]byte{snapshotKey(t, 0): first, snapshotKey(t, 1): second, headKey: head}
		}},
		{name: "foreign-vault", reason: "vault", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			foreign := binding
			foreign.Vault = [32]byte{0x91, 0x92, 0x93}
			return atprotoMaterialGenesisRecords(t, foreign)
		}},
		{name: "wrong-snapshot-key", reason: "record_key", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			snapshotRecord, headRecord := atprotoMaterialRecords(t, binding, [16]byte{0x51, 0x76}, 0, nil)
			return map[atproto.RecordKey][]byte{
				{Collection: publication.SnapshotNSID, RKey: "self"}: snapshotRecord,
				headKey: headRecord,
			}
		}},
		{name: "unexpected-head-key", reason: "head_key", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			genesis := atprotoMaterialGenesisRecords(t, binding)
			records := make(map[atproto.RecordKey][]byte, len(genesis)+1)
			maps.Copy(records, genesis)
			records[atproto.RecordKey{Collection: publication.HeadNSID, RKey: "current"}] = records[headKey]
			return records
		}},
		{name: "hostile-car", reason: "revision", records: func(t *testing.T) map[atproto.RecordKey][]byte {
			return atprotoMaterialGenesisRecords(t, binding)
		}, servedCAR: func(t *testing.T, repository *atprotoMaterialRepository) []byte {
			genesis := atprotoMaterialGenesisRecords(t, binding)
			targetCID, err := publication.RecordCID(genesis[snapshotKey(t, 0)])
			require.NoError(t, err)
			identifier, err := cid.Cast(targetCID)
			require.NoError(t, err)
			replacementCandidate := materialTestCandidate(
				t,
				binding,
				[16]byte{0x51, 0x79},
				0,
				nil,
				[]byte("synthetic shadow payload"),
			)
			return atprotoMaterialTamperSnapshot(t, repository.car(), identifier, replacementCandidate.SnapshotRecord)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
			repository.setRecords(t, testCase.records(t))
			transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)
			if testCase.servedCAR != nil {
				repository.serveCar(t, testCase.servedCAR(t, repository))
			}
			view, err := transport.ReadView(ctx)
			requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialView, testCase.reason)
			assert.Equal(t, publicationstate.SuppliedRepositoryView{}, view)
			assert.Equal(t, 0, repository.uploadCount())
			assert.Equal(t, 0, repository.applyCount())
		})
	}

	for _, collection := range []string{
		atproto.VaultHeadNSID, atproto.VaultControlNSID, atproto.VaultSnapshotNSID,
		atproto.VaultPolicyNSID, atproto.VaultCertificateNSID, atproto.VaultCheckpointNSID, atproto.VaultAttestationNSID,
	} {
		t.Run("legacy-"+collection, func(t *testing.T) {
			repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
			records := atprotoMaterialGenesisRecords(t, binding)
			legacy, err := atprototest.BuildRecord(collection, "self", map[string]any{"schemaVersion": int64(1)})
			require.NoError(t, err)
			records[atproto.RecordKey{Collection: collection, RKey: "self"}] = legacy.Data
			repository.setRecords(t, records)
			transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)
			view, viewErr := transport.ReadView(ctx)
			requireATProtoMaterialRefusal(t, viewErr, ErrATProtoMaterialView, "legacy_profile")
			assert.Equal(t, publicationstate.SuppliedRepositoryView{}, view)

			empty := newATProtoMaterialRepository(t, atprotoMaterialDID)
			empty.setRecords(t, map[atproto.RecordKey][]byte{
				{Collection: collection, RKey: "self"}: legacy.Data,
			})
			emptyTransport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, empty)
			emptyView, emptyErr := emptyTransport.ReadView(ctx)
			requireATProtoMaterialRefusal(t, emptyErr, ErrATProtoMaterialView, "legacy_profile")
			assert.Equal(t, publicationstate.SuppliedRepositoryView{}, emptyView)
		})
	}
}

func TestMaterialATProtoRefusesTamperedCarWithoutShadowRead(t *testing.T) {
	ctx := context.Background()
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	genesis := atprotoMaterialGenesisRecords(t, binding)
	repository.setRecords(t, genesis)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	committed, err := publication.RecordCID(genesis[atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: key}])
	require.NoError(t, err)
	identifier, err := cid.Cast(committed)
	require.NoError(t, err)
	substitute := materialTestCandidate(
		t,
		binding,
		[16]byte{0x51, 0x7a},
		0,
		nil,
		[]byte("synthetic substitute payload"),
	)
	repository.serveCar(t, atprotoMaterialTamperSnapshot(t, repository.car(), identifier, substitute.SnapshotRecord))
	transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)

	view, readErr := transport.ReadView(ctx)
	requireATProtoMaterialRefusal(t, readErr, ErrATProtoMaterialView, "revision")
	require.ErrorIs(t, readErr, atproto.ErrUntrustedCar)
	assert.Equal(t, publicationstate.SuppliedRepositoryView{}, view)
	assert.Equal(t, 0, repository.uploadCount())
	assert.Equal(t, 0, repository.applyCount())
}

func TestMaterialATProtoRefusesRecordByteSubstitution(t *testing.T) {
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	snapshotRecord, headRecord := atprotoMaterialRecords(t, binding, [16]byte{0x51, 0x7b}, 0, nil)
	committed, err := publication.RecordCID(snapshotRecord)
	require.NoError(t, err)
	identifier, err := cid.Cast(committed)
	require.NoError(t, err)
	require.NoError(
		t,
		atprotoMaterialRoundTrip(
			atproto.ProvenRecord{CID: identifier.String(), Data: snapshotRecord},
			identifier.String(),
		),
	)

	substitute := materialTestCandidate(
		t,
		binding,
		[16]byte{0x51, 0x7c},
		0,
		nil,
		[]byte("synthetic substitute payload"),
	)
	require.Error(
		t,
		atprotoMaterialRoundTrip(
			atproto.ProvenRecord{CID: identifier.String(), Data: substitute.SnapshotRecord},
			identifier.String(),
		),
	)
	require.Error(
		t,
		atprotoMaterialRoundTrip(atproto.ProvenRecord{CID: identifier.String(), Data: headRecord}, identifier.String()),
	)
}

func TestMaterialATProtoKeepsUnrelatedCollectionsSeparate(t *testing.T) {
	ctx := context.Background()
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	genesis := atprotoMaterialGenesisRecords(t, binding)
	repository.setRecords(t, genesis)
	unrelated, err := atprototest.BuildRecord(
		"app.bsky.feed.post",
		"self",
		map[string]any{"text": "synthetic unrelated record"},
	)
	require.NoError(t, err)
	repository.commitRecord(t, atproto.RecordKey{Collection: "app.bsky.feed.post", RKey: "self"}, unrelated.Data)
	transport := newATProtoMaterialTransport(t, binding, atprotoMaterialDID, repository)

	view, err := transport.ReadView(ctx)
	require.NoError(t, err)
	assert.Equal(t, binding, view.Origin)
	assert.Equal(t, publicationstate.ViewScopeWholeRepository, view.Scope)
	assert.Nil(t, view.SuppliedContext.Policy)
	assert.Equal(t, genesis[atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey}], view.Head)
	require.Len(t, view.Snapshots, 1)
	assert.Equal(
		t,
		genesis[atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: view.Snapshots[0].Key}],
		view.Snapshots[0].Raw,
	)
}
