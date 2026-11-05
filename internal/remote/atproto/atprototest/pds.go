package atprototest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
)

const (
	maxJSONResponseBytes = 2 << 20
	maxCARResponseBytes  = 8 << 20
	maxRecordBytes       = 1 << 20
	maxUploadBytes       = 16 << 20
	maxWriteCount        = 128
)

var ErrLostResponse = errors.New("synthetic PDS response lost after commit")

type MemoryPDSHooks struct {
	LoseNextApplyWritesResponse      bool
	DuplicateNextApplyWritesResponse bool
	RejectNextApplyWrites            bool
	GetBlobStatus                    int
}

type MemoryPDS struct {
	mu      sync.Mutex
	did     string
	key     *atcrypto.PrivateKeyP256
	current SignedRevision
	records map[string]Record
	blobs   map[string][]byte
	hooks   MemoryPDSHooks
	calls   []string
}

type applyWrite struct {
	Type       string          `json:"$type"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	Value      json.RawMessage `json:"value"`
}

type applyWritesRequest struct {
	Repo       string       `json:"repo"`
	SwapCommit string       `json:"swapCommit"`
	Writes     []applyWrite `json:"writes"`
}

type deleteRecordRequest struct {
	Repo       string `json:"repo"`
	Collection string `json:"collection"`
	RKey       string `json:"rkey"`
}

func NewMemoryPDS(did string, signingKey *atcrypto.PrivateKeyP256) (*MemoryPDS, error) {
	parsedDID, err := syntax.ParseDID(did)
	if err != nil || parsedDID.String() != did || signingKey == nil {
		return nil, errors.New("valid DID and repository signing key are required")
	}
	initial, err := BuildSignedRevision(did, signingKey, nil)
	if err != nil {
		return nil, err
	}
	return &MemoryPDS{
		did: did, key: signingKey, current: initial,
		records: make(map[string]Record), blobs: make(map[string][]byte),
	}, nil
}

func (p *MemoryPDS) VerificationMethod() VerificationMethod {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current.VerificationMethod
}

func (p *MemoryPDS) CurrentRevision() SignedRevision {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneSignedRevision(p.current)
}

func (p *MemoryPDS) Record(collection, rkey string) (Record, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	record, exists := p.records[recordKey(collection, rkey)]
	return cloneRecord(record), exists
}

func (p *MemoryPDS) RecordCID(collection, rkey string) (cid.Cid, bool) {
	record, exists := p.Record(collection, rkey)
	if !exists {
		return cid.Undef, false
	}
	identifier, err := dagCBORCID(record.Data)
	return identifier, err == nil
}

func (p *MemoryPDS) BlobIsLive(blobCID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isLiveBlob(blobCID)
}

func (p *MemoryPDS) RemoveBlob(blobCID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.blobs, blobCID)
}

func (p *MemoryPDS) RemoveRecord(collection, rkey string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := recordKey(collection, rkey)
	if _, exists := p.records[key]; !exists {
		return errors.New("synthetic PDS record does not exist")
	}
	nextRecords := cloneRecords(p.records)
	delete(nextRecords, key)
	revision, err := p.buildRevision(nextRecords)
	if err != nil {
		return err
	}
	p.records = nextRecords
	p.current = revision
	return nil
}

func (p *MemoryPDS) SetHooks(hooks MemoryPDSHooks) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hooks = hooks
}

func (p *MemoryPDS) Calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func (p *MemoryPDS) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, endpoint)
	if endpoint == "com.atproto.repo.uploadBlob" {
		if len(body) > maxUploadBytes {
			return errorResponse(413, "BlobTooLarge")
		}
	} else if len(body) > maxJSONResponseBytes {
		return errorResponse(413, "RequestTooLarge")
	}
	switch endpoint {
	case "com.atproto.server.describeServer":
		if method != "GET" {
			return errorResponse(400, "InvalidRequest")
		}
		return jsonResponse(200, map[string]int64{"blobUploadLimit": maxUploadBytes})
	case "com.atproto.sync.getLatestCommit":
		if method != "GET" || query.Get("did") != p.did {
			return errorResponse(400, "InvalidRequest")
		}
		return jsonResponse(200, map[string]string{"cid": p.current.CommitCID.String(), "rev": RepositoryRevision})
	case "com.atproto.sync.getRecord", "com.atproto.repo.getRecord":
		if method != "GET" || query.Get("repo") != p.did || !validRecordKey(query.Get("collection"), query.Get("rkey")) {
			return errorResponse(400, "InvalidRequest")
		}
		record, exists := p.records[recordKey(query.Get("collection"), query.Get("rkey"))]
		if !exists {
			return errorResponse(404, "RecordNotFound")
		}
		value, err := atdata.UnmarshalCBOR(record.Data)
		if err != nil {
			return errorResponse(500, "InternalServerError")
		}
		recordCID, err := dagCBORCID(record.Data)
		if err != nil {
			return errorResponse(500, "InternalServerError")
		}
		uri := "at://" + p.did + "/" + record.Collection + "/" + record.RKey
		return jsonResponse(200, map[string]any{"uri": uri, "cid": recordCID.String(), "value": value})
	case "com.atproto.repo.uploadBlob":
		if method != "POST" || contentType != "application/octet-stream" || len(body) == 0 {
			return errorResponse(400, "InvalidRequest")
		}
		if len(body) > maxUploadBytes {
			return errorResponse(413, "BlobTooLarge")
		}
		blob, err := BuildBlob(body)
		if err != nil {
			return errorResponse(400, "InvalidBlob")
		}
		p.blobs[blob.CID.String()] = bytes.Clone(body)
		return jsonResponse(200, map[string]any{"blob": blob.Reference})
	case "com.atproto.repo.applyWrites":
		if method != "POST" || contentType != "application/json" {
			return errorResponse(400, "InvalidRequest")
		}
		if p.hooks.RejectNextApplyWrites {
			p.hooks.RejectNextApplyWrites = false
			return errorResponse(400, "InvalidRecord")
		}
		return p.applyWrites(body)
	case "com.atproto.repo.deleteRecord":
		if method != "POST" || contentType != "application/json" {
			return errorResponse(400, "InvalidRequest")
		}
		return p.deleteRecord(body)
	default:
		return errorResponse(404, "NotFound")
	}
}

func (p *MemoryPDS) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, endpoint)
	switch endpoint {
	case "com.atproto.sync.getRepo":
		if query.Get("did") != p.did {
			return 400, io.NopCloser(bytes.NewReader([]byte(`{"error":"InvalidRequest"}`))), nil
		}
		if len(p.current.CAR) > maxCARResponseBytes {
			return 413, io.NopCloser(bytes.NewReader([]byte(`{"error":"RepoTooLarge"}`))), nil
		}
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(p.current.CAR))), nil
	case "com.atproto.sync.getBlob":
		if query.Get("did") != p.did {
			return 400, io.NopCloser(bytes.NewReader([]byte(`{"error":"InvalidRequest"}`))), nil
		}
		if p.hooks.GetBlobStatus != 0 {
			return p.hooks.GetBlobStatus, io.NopCloser(bytes.NewReader([]byte(`{"error":"BlobUnavailable"}`))), nil
		}
		blobCID := query.Get("cid")
		data, exists := p.blobs[blobCID]
		if !exists || !p.isLiveBlob(blobCID) {
			return 404, io.NopCloser(bytes.NewReader([]byte(`{"error":"BlobNotFound"}`))), nil
		}
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(data))), nil
	default:
		return 404, io.NopCloser(bytes.NewReader([]byte(`{"error":"NotFound"}`))), nil
	}
}

func (p *MemoryPDS) applyWrites(body []byte) (int, []byte, error) {
	if len(body) > maxJSONResponseBytes {
		return errorResponse(413, "RequestTooLarge")
	}
	var input applyWritesRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.Repo != p.did || len(input.Writes) == 0 || len(input.Writes) > maxWriteCount {
		return errorResponse(400, "InvalidRequest")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errorResponse(400, "InvalidRequest")
	}
	if input.SwapCommit != p.current.CommitCID.String() {
		return errorResponse(400, "InvalidSwap")
	}
	nextRecords := cloneRecords(p.records)
	seen := make(map[string]struct{}, len(input.Writes))
	for _, write := range input.Writes {
		if !validRecordKey(write.Collection, write.RKey) {
			return errorResponse(400, "InvalidRecord")
		}
		key := recordKey(write.Collection, write.RKey)
		if _, duplicate := seen[key]; duplicate {
			return errorResponse(400, "InvalidRecord")
		}
		seen[key] = struct{}{}
		exists := false
		if _, exists = nextRecords[key]; exists {
			if write.Type == "com.atproto.repo.applyWrites#create" {
				return errorResponse(400, "RecordAlreadyExists")
			}
		} else if write.Type == "com.atproto.repo.applyWrites#update" || write.Type == "com.atproto.repo.applyWrites#delete" {
			return errorResponse(400, "RecordNotFound")
		}
		switch write.Type {
		case "com.atproto.repo.applyWrites#create", "com.atproto.repo.applyWrites#update":
			if len(write.Value) == 0 || len(write.Value) > maxRecordBytes {
				return errorResponse(400, "InvalidRecord")
			}
			value, err := atdata.UnmarshalJSON(write.Value)
			if err != nil || value["$type"] != write.Collection {
				return errorResponse(400, "InvalidRecord")
			}
			encoded, err := atdata.MarshalCBOR(value)
			if err != nil || len(encoded) > maxRecordBytes {
				return errorResponse(400, "InvalidRecord")
			}
			nextRecords[key] = Record{Collection: write.Collection, RKey: write.RKey, Data: encoded}
		case "com.atproto.repo.applyWrites#delete":
			if len(write.Value) != 0 && !bytes.Equal(bytes.TrimSpace(write.Value), []byte("null")) {
				return errorResponse(400, "InvalidRecord")
			}
			delete(nextRecords, key)
		default:
			return errorResponse(400, "InvalidRecord")
		}
	}
	revision, err := p.buildRevision(nextRecords)
	if err != nil {
		return errorResponse(400, "InvalidRecord")
	}
	response := jsonBytes(map[string]any{"commit": map[string]string{"cid": revision.CommitCID.String()}})
	if len(response) > maxJSONResponseBytes {
		return errorResponse(500, "ResponseTooLarge")
	}
	p.records = nextRecords
	p.current = revision
	if p.hooks.LoseNextApplyWritesResponse {
		p.hooks.LoseNextApplyWritesResponse = false
		return 0, nil, ErrLostResponse
	}
	if p.hooks.DuplicateNextApplyWritesResponse {
		p.hooks.DuplicateNextApplyWritesResponse = false
		return 200, append(bytes.Clone(response), response...), nil
	}
	return 200, response, nil
}

func (p *MemoryPDS) deleteRecord(body []byte) (int, []byte, error) {
	var request deleteRecordRequest
	if err := json.Unmarshal(body, &request); err != nil || request.Repo != p.did || !validRecordKey(request.Collection, request.RKey) {
		return errorResponse(400, "InvalidRequest")
	}
	key := recordKey(request.Collection, request.RKey)
	if _, exists := p.records[key]; !exists {
		return errorResponse(400, "RecordNotFound")
	}
	nextRecords := cloneRecords(p.records)
	delete(nextRecords, key)
	revision, err := p.buildRevision(nextRecords)
	if err != nil {
		return errorResponse(400, "InvalidRecord")
	}
	p.records = nextRecords
	p.current = revision
	return jsonResponse(200, map[string]any{})
}

func (p *MemoryPDS) buildRevision(records map[string]Record) (SignedRevision, error) {
	if len(records) > 4096 {
		return SignedRevision{}, errors.New("repository record count exceeds the PDS test bound")
	}
	ordered := make([]Record, 0, len(records))
	for _, record := range records {
		ordered = append(ordered, cloneRecord(record))
	}
	sort.Slice(ordered, func(i, j int) bool {
		return recordKey(ordered[i].Collection, ordered[i].RKey) < recordKey(ordered[j].Collection, ordered[j].RKey)
	})
	revision, err := BuildSignedRevision(p.did, p.key, ordered)
	if err != nil {
		return SignedRevision{}, err
	}
	if len(revision.CAR) > maxCARResponseBytes {
		return SignedRevision{}, errors.New("repository CAR exceeds the PDS test bound")
	}
	return revision, nil
}

func (p *MemoryPDS) isLiveBlob(blobCID string) bool {
	parsedCID, err := cid.Parse(blobCID)
	if err != nil || parsedCID.String() != blobCID {
		return false
	}
	for _, record := range p.records {
		object, err := atdata.UnmarshalCBOR(record.Data)
		if err != nil || object["$type"] != record.Collection {
			continue
		}
		for _, blob := range atdata.ExtractBlobs(object) {
			if cid.Cid(blob.Ref).Equals(parsedCID) {
				return true
			}
		}
	}
	return false
}

func validRecordKey(collection, rkey string) bool {
	parsedCollection, err := syntax.ParseNSID(collection)
	if err != nil || parsedCollection.String() != collection {
		return false
	}
	parsedRKey, err := syntax.ParseRecordKey(rkey)
	return err == nil && parsedRKey.String() == rkey
}

func recordKey(collection, rkey string) string {
	return collection + "/" + rkey
}

func cloneRecords(records map[string]Record) map[string]Record {
	cloned := make(map[string]Record, len(records))
	for key, record := range records {
		cloned[key] = cloneRecord(record)
	}
	return cloned
}

func cloneRecord(record Record) Record {
	return Record{Collection: record.Collection, RKey: record.RKey, Data: bytes.Clone(record.Data)}
}

func cloneSignedRevision(revision SignedRevision) SignedRevision {
	cloned := revision
	cloned.CAR = bytes.Clone(revision.CAR)
	cloned.Records = make([]Record, len(revision.Records))
	for index, record := range revision.Records {
		cloned.Records[index] = cloneRecord(record)
	}
	return cloned
}

func jsonResponse(status int, value any) (int, []byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxJSONResponseBytes {
		return errorResponse(500, "InternalServerError")
	}
	return status, encoded, nil
}

func errorResponse(status int, code string) (int, []byte, error) {
	return status, []byte(fmt.Sprintf(`{"error":%q}`, strings.TrimSpace(code))), nil
}

func jsonBytes(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
