package atprototest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/ipld/go-car"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const memoryPDSTestDID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"

func TestMemoryPDSServesSignedRepositoryAndRecordEndpoints(t *testing.T) {
	pds := newMemoryPDS(t)
	ctx := context.Background()
	status, body, err := pds.Do(ctx, "GET", "com.atproto.sync.getLatestCommit", url.Values{"did": {memoryPDSTestDID}}, nil, "")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	var latest struct {
		CID string `json:"cid"`
	}
	require.NoError(t, json.Unmarshal(body, &latest))
	assert.Equal(t, pds.CurrentRevision().CommitCID.String(), latest.CID)

	status, stream, err := pds.OpenStream(ctx, "com.atproto.sync.getRepo", url.Values{"did": {memoryPDSTestDID}})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	carBytes, err := io.ReadAll(stream)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	commit, loaded, err := repo.LoadRepoFromCAR(ctx, bytes.NewReader(carBytes))
	require.NoError(t, err)
	assert.Equal(t, memoryPDSTestDID, loaded.DID.String())
	publicKey, err := pds.key.PublicKey()
	require.NoError(t, err)
	assert.NoError(t, commit.VerifySignature(publicKey))
	carReader, err := car.NewCarReader(bytes.NewReader(carBytes))
	require.NoError(t, err)
	require.Len(t, carReader.Header.Roots, 1)
	assert.Equal(t, pds.CurrentRevision().CommitCID, carReader.Header.Roots[0])

	record := createPDSRecord(t, pds, pds.CurrentRevision().CommitCID.String(), "systems.example.preferences", "self", []byte(`{"$type":"systems.example.preferences","value":"synthetic"}`))
	status, body, err = pds.Do(ctx, "GET", "com.atproto.repo.getRecord", url.Values{"repo": {memoryPDSTestDID}, "collection": {record.Collection}, "rkey": {record.RKey}}, nil, "")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	var result struct {
		URI   string         `json:"uri"`
		CID   string         `json:"cid"`
		Value map[string]any `json:"value"`
	}
	require.NoError(t, json.Unmarshal(body, &result))
	assert.Equal(t, "at://"+memoryPDSTestDID+"/systems.example.preferences/self", result.URI)
	recordCID, exists := pds.RecordCID(record.Collection, record.RKey)
	require.True(t, exists)
	assert.Equal(t, recordCID.String(), result.CID)
	assert.Equal(t, "synthetic", result.Value["value"])
}

func TestMemoryPDSRejectsStaleSwapAtomically(t *testing.T) {
	pds := newMemoryPDS(t)
	ctx := context.Background()
	staleCommit := pds.CurrentRevision().CommitCID.String()
	winner := createPDSRecord(t, pds, staleCommit, "systems.example.preferences", "winner", []byte(`{"$type":"systems.example.preferences","value":"winner"}`))
	winnerCID, exists := pds.RecordCID(winner.Collection, winner.RKey)
	require.True(t, exists)
	winnerCommit := pds.CurrentRevision().CommitCID

	blobData := []byte("orphaned candidate bytes")
	blob := uploadPDSBlob(t, pds, blobData)
	loser, err := json.Marshal(map[string]any{
		"repo": memoryPDSTestDID, "swapCommit": staleCommit,
		"writes": []any{map[string]any{
			"$type": "com.atproto.repo.applyWrites#create", "collection": "systems.example.blobRecord", "rkey": "loser",
			"value": map[string]any{"$type": "systems.example.blobRecord", "blob": blob},
		}},
	})
	require.NoError(t, err)
	status, response, err := pds.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, loser, "application/json")
	require.NoError(t, err)
	assert.Equal(t, 400, status)
	assert.JSONEq(t, `{"error":"InvalidSwap"}`, string(response))
	assert.Equal(t, winnerCommit, pds.CurrentRevision().CommitCID)
	actualWinnerCID, exists := pds.RecordCID(winner.Collection, winner.RKey)
	require.True(t, exists)
	assert.Equal(t, winnerCID, actualWinnerCID)
	_, exists = pds.Record("systems.example.blobRecord", "loser")
	assert.False(t, exists)
	assert.False(t, pds.BlobIsLive(blob.Ref.CID().String()))
	status, _, err = pds.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {memoryPDSTestDID}, "cid": {blob.Ref.CID().String()}})
	require.NoError(t, err)
	assert.Equal(t, 404, status)
}

func TestMemoryPDSBlobLifecycleAndServingRefusal(t *testing.T) {
	pds := newMemoryPDS(t)
	ctx := context.Background()
	blobData := []byte("synthetic ciphertext")
	blob := uploadPDSBlob(t, pds, blobData)
	blobCID := blob.Ref.CID().String()
	assert.False(t, pds.BlobIsLive(blobCID))
	status, _, err := pds.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {memoryPDSTestDID}, "cid": {blobCID}})
	require.NoError(t, err)
	assert.Equal(t, 404, status)

	value, err := json.Marshal(map[string]any{"$type": "systems.example.blobRecord", "blob": blob})
	require.NoError(t, err)
	createPDSRecord(t, pds, pds.CurrentRevision().CommitCID.String(), "systems.example.blobRecord", "live", value)
	assert.True(t, pds.BlobIsLive(blobCID))
	status, stream, err := pds.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {memoryPDSTestDID}, "cid": {blobCID}})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	served, err := io.ReadAll(stream)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	assert.Equal(t, blobData, served)

	pds.SetHooks(MemoryPDSHooks{GetBlobStatus: 503})
	status, _, err = pds.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {memoryPDSTestDID}, "cid": {blobCID}})
	require.NoError(t, err)
	assert.Equal(t, 503, status)
}

func TestMemoryPDSListRecordsAndListBlobsExposeLiveProjection(t *testing.T) {
	pds := newMemoryPDS(t)
	ctx := context.Background()
	orphan := uploadPDSBlob(t, pds, []byte("orphan bytes"))
	orphanCID := orphan.Ref.CID().String()
	live := uploadPDSBlob(t, pds, []byte("live bytes"))
	liveCID := live.Ref.CID().String()
	liveRecord, err := json.Marshal(map[string]any{"$type": "systems.example.blobRecord", "blob": live})
	require.NoError(t, err)
	createPDSRecord(t, pds, pds.CurrentRevision().CommitCID.String(), "systems.example.blobRecord", "live", liveRecord)
	createPDSRecord(t, pds, pds.CurrentRevision().CommitCID.String(), "systems.example.blobRecord", "second", []byte(`{"$type":"systems.example.blobRecord","value":"second"}`))

	status, body, err := pds.Do(ctx, "GET", "com.atproto.repo.listRecords", url.Values{"repo": {memoryPDSTestDID}, "collection": {"systems.example.blobRecord"}}, nil, "")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	var records struct {
		Records []struct {
			URI   string         `json:"uri"`
			CID   string         `json:"cid"`
			Value map[string]any `json:"value"`
		} `json:"records"`
	}
	require.NoError(t, json.Unmarshal(body, &records))
	require.Len(t, records.Records, 2)
	assert.Equal(t, "at://"+memoryPDSTestDID+"/systems.example.blobRecord/live", records.Records[0].URI)
	assert.Equal(t, "at://"+memoryPDSTestDID+"/systems.example.blobRecord/second", records.Records[1].URI)
	assert.Equal(t, liveCID, records.Records[0].Value["blob"].(map[string]any)["ref"].(map[string]any)["$link"])

	status, body, err = pds.Do(ctx, "GET", "com.atproto.sync.listBlobs", url.Values{"did": {memoryPDSTestDID}}, nil, "")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	var listed struct {
		CIDs []string `json:"cids"`
	}
	require.NoError(t, json.Unmarshal(body, &listed))
	assert.Equal(t, []string{liveCID}, listed.CIDs)
	assert.ElementsMatch(t, []string{liveCID, orphanCID}, pds.StoredBlobCIDs())
	assert.True(t, pds.PubliclyRetrievable(liveCID))
	assert.False(t, pds.PubliclyRetrievable(orphanCID))
}

func TestMemoryPDSFailureHooksAndPostProcessingExposure(t *testing.T) {
	pds := newMemoryPDS(t)
	ctx := context.Background()
	pds.SetHooks(MemoryPDSHooks{RejectNextUploadBlobStatus: 413, RejectNextUploadBlobCode: "StorageQuotaExceeded"})
	status, body, err := pds.Do(ctx, "POST", "com.atproto.repo.uploadBlob", nil, []byte("rejected"), "application/octet-stream")
	require.NoError(t, err)
	assert.Equal(t, 413, status)
	assert.JSONEq(t, `{"error":"StorageQuotaExceeded"}`, string(body))
	assert.Empty(t, pds.StoredBlobCIDs())

	pds.SetHooks(MemoryPDSHooks{RejectNextApplyWritesStatus: 429, RejectNextApplyWritesCode: "QuotaExceeded"})
	status, body, err = applyPDSRecord(ctx, pds, pds.CurrentRevision().CommitCID.String(), "create", "systems.example.preferences", "rejected", []byte(`{"$type":"systems.example.preferences","value":"no"}`))
	require.NoError(t, err)
	assert.Equal(t, 429, status)
	assert.JSONEq(t, `{"error":"QuotaExceeded"}`, string(body))
	_, exists := pds.Record("systems.example.preferences", "rejected")
	assert.False(t, exists)

	blob := uploadPDSBlob(t, pds, []byte("post-processing candidate"))
	blobCID := blob.Ref.CID().String()
	value, err := json.Marshal(map[string]any{"$type": "systems.example.blobRecord", "blob": blob})
	require.NoError(t, err)
	pds.SetHooks(MemoryPDSHooks{
		RejectNextApplyWritesAfterBlobProcessing:       true,
		RejectNextApplyWritesAfterBlobProcessingStatus: 400,
		RejectNextApplyWritesAfterBlobProcessingCode:   "StorageQuotaExceeded",
	})
	before := pds.CurrentRevision().CommitCID
	status, body, err = applyPDSRecord(ctx, pds, before.String(), "create", "systems.example.blobRecord", "candidate", value)
	require.NoError(t, err)
	assert.Equal(t, 400, status)
	assert.JSONEq(t, `{"error":"StorageQuotaExceeded"}`, string(body))
	assert.Equal(t, before, pds.CurrentRevision().CommitCID)
	_, exists = pds.Record("systems.example.blobRecord", "candidate")
	assert.False(t, exists)
	assert.Contains(t, pds.StoredBlobCIDs(), blobCID)
	assert.False(t, pds.BlobIsLive(blobCID))
	assert.True(t, pds.PubliclyRetrievable(blobCID))
	streamStatus, stream, err := pds.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {memoryPDSTestDID}, "cid": {blobCID}})
	require.NoError(t, err)
	assert.Equal(t, 200, streamStatus)
	served, err := io.ReadAll(stream)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	assert.Equal(t, []byte("post-processing candidate"), served)
}

func TestMemoryPDSApplyWritesResponseHooksAndDelete(t *testing.T) {
	pds := newMemoryPDS(t)
	ctx := context.Background()
	first := []byte(`{"$type":"systems.example.preferences","value":"one"}`)
	pds.SetHooks(MemoryPDSHooks{LoseNextApplyWritesResponse: true})
	_, _, err := applyPDSRecord(ctx, pds, pds.CurrentRevision().CommitCID.String(), "create", "systems.example.preferences", "self", first)
	require.ErrorIs(t, err, ErrLostResponse)
	_, exists := pds.Record("systems.example.preferences", "self")
	assert.True(t, exists)

	pds.SetHooks(MemoryPDSHooks{DuplicateNextApplyWritesResponse: true})
	status, response, err := applyPDSRecord(ctx, pds, pds.CurrentRevision().CommitCID.String(), "update", "systems.example.preferences", "self", []byte(`{"$type":"systems.example.preferences","value":"two"}`))
	require.NoError(t, err)
	assert.Equal(t, 200, status)
	assert.False(t, json.Valid(response))

	before := pds.CurrentRevision().CommitCID
	pds.SetHooks(MemoryPDSHooks{RejectNextApplyWrites: true})
	status, _, err = applyPDSRecord(ctx, pds, before.String(), "create", "systems.example.preferences", "rejected", first)
	require.NoError(t, err)
	assert.Equal(t, 400, status)
	assert.Equal(t, before, pds.CurrentRevision().CommitCID)
	_, exists = pds.Record("systems.example.preferences", "rejected")
	assert.False(t, exists)

	status, _, err = applyPDSRecord(ctx, pds, pds.CurrentRevision().CommitCID.String(), "delete", "systems.example.preferences", "self", nil)
	require.NoError(t, err)
	assert.Equal(t, 200, status)
	_, exists = pds.Record("systems.example.preferences", "self")
	assert.False(t, exists)
	createPDSRecord(t, pds, pds.CurrentRevision().CommitCID.String(), "systems.example.preferences", "self", first)

	deleteBody, err := json.Marshal(map[string]string{"repo": memoryPDSTestDID, "collection": "systems.example.preferences", "rkey": "self"})
	require.NoError(t, err)
	status, _, err = pds.Do(ctx, "POST", "com.atproto.repo.deleteRecord", nil, deleteBody, "application/json")
	require.NoError(t, err)
	assert.Equal(t, 200, status)
	_, exists = pds.Record("systems.example.preferences", "self")
	assert.False(t, exists)
}

func newMemoryPDS(t *testing.T) *MemoryPDS {
	t.Helper()
	key, err := NewSigningKey()
	require.NoError(t, err)
	pds, err := NewMemoryPDS(memoryPDSTestDID, key)
	require.NoError(t, err)
	return pds
}

func createPDSRecord(t *testing.T, pds *MemoryPDS, swapCommit, collection, rkey string, value []byte) Record {
	t.Helper()
	status, _, err := applyPDSRecord(context.Background(), pds, swapCommit, "create", collection, rkey, value)
	require.NoError(t, err)
	require.Equal(t, 200, status)
	record, exists := pds.Record(collection, rkey)
	require.True(t, exists)
	return record
}

func applyPDSRecord(ctx context.Context, pds *MemoryPDS, swapCommit, action, collection, rkey string, value []byte) (int, []byte, error) {
	typeName := "com.atproto.repo.applyWrites#" + action
	var jsonValue json.RawMessage = value
	if action == "delete" {
		jsonValue = nil
	}
	body, err := json.Marshal(map[string]any{
		"repo": memoryPDSTestDID, "swapCommit": swapCommit,
		"writes": []any{map[string]any{"$type": typeName, "collection": collection, "rkey": rkey, "value": jsonValue}},
	})
	if err != nil {
		return 0, nil, err
	}
	return pds.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, body, "application/json")
}

func uploadPDSBlob(t *testing.T, pds *MemoryPDS, data []byte) atdata.Blob {
	t.Helper()
	status, response, err := pds.Do(context.Background(), "POST", "com.atproto.repo.uploadBlob", nil, data, "application/octet-stream")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	var result struct {
		Blob atdata.Blob `json:"blob"`
	}
	require.NoError(t, json.Unmarshal(response, &result))
	require.True(t, result.Blob.Ref.IsDefined())
	return result.Blob
}
