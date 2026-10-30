package atproto

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
)

const (
	RecordCreate = "create"
	RecordUpdate = "update"
)

type RecordWrite struct {
	Action     string
	Collection string
	RKey       string
	Record     json.RawMessage
}

type FencedPublication struct {
	FirstBlobReference RecordWrite
	VaultHead          RecordWrite
	VaultControl       RecordWrite
	Additional         []RecordWrite
}

type PublishResult struct {
	CommitCID string
}

type applyWritesInput struct {
	Repo       string            `json:"repo"`
	SwapCommit string            `json:"swapCommit"`
	Writes     []json.RawMessage `json:"writes"`
}

type applyWritesOutput struct {
	Commit struct {
		CID string `json:"cid"`
	} `json:"commit"`
}

type applyWritesError struct {
	Error string `json:"error"`
}

func PublishFenced(ctx context.Context, transport Transport, revision *Revision, publication FencedPublication) (PublishResult, error) {
	if transport == nil || revision == nil || !validDID(revision.did) || revision.commitCID == "" {
		return PublishResult{}, fmt.Errorf("%w: verified revision and transport are required", ErrBatchRejected)
	}
	if _, err := syntax.ParseCID(revision.commitCID); err != nil {
		return PublishResult{}, fmt.Errorf("%w: verified revision commit CID is invalid", ErrBatchRejected)
	}
	if publication.FirstBlobReference.Action != RecordCreate || !containsBlobReference(publication.FirstBlobReference.Record) {
		return PublishResult{}, fmt.Errorf("%w: first reference must create a record containing a blob reference", ErrBatchRejected)
	}
	writes := []RecordWrite{publication.FirstBlobReference, publication.VaultHead, publication.VaultControl}
	writes = append(writes, publication.Additional...)
	if len(writes) < 3 {
		return PublishResult{}, fmt.Errorf("%w: first reference, head and control writes are required", ErrBatchRejected)
	}
	input := applyWritesInput{Repo: revision.did, SwapCommit: revision.commitCID, Writes: make([]json.RawMessage, 0, len(writes))}
	seen := make(map[RecordKey]struct{}, len(writes))
	for _, write := range writes {
		encoded, err := encodeRecordWrite(write)
		if err != nil {
			return PublishResult{}, err
		}
		key := RecordKey{Collection: write.Collection, RKey: write.RKey}
		if _, exists := seen[key]; exists {
			return PublishResult{}, fmt.Errorf("%w: duplicate record target %s/%s", ErrBatchRejected, key.Collection, key.RKey)
		}
		seen[key] = struct{}{}
		input.Writes = append(input.Writes, encoded)
	}
	body, err := json.Marshal(input)
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: could not encode applyWrites batch", ErrBatchRejected)
	}
	status, response, err := transport.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, body, "application/json")
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites request outcome is unknown", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)
	}
	if status >= 500 {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, status)
	}
	if status >= 400 && status < 500 {
		var remoteError applyWritesError
		if json.Unmarshal(response, &remoteError) == nil && remoteError.Error == "InvalidSwap" {
			return PublishResult{}, ErrFenceLost
		}
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrBatchRejected, ErrCandidateMayBeDisclosed, status)
	}
	if status < 200 || status >= 300 {
		return PublishResult{}, fmt.Errorf("%w: %w: applyWrites returned HTTP %d", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed, status)
	}
	var output applyWritesOutput
	if len(response) != 0 {
		if err := json.Unmarshal(response, &output); err != nil {
			return PublishResult{}, fmt.Errorf("%w: %w: applyWrites response is malformed after submission", ErrAmbiguousTransport, ErrCandidateMayBeDisclosed)
		}
	}
	return PublishResult{CommitCID: output.Commit.CID}, nil
}

func encodeRecordWrite(write RecordWrite) (json.RawMessage, error) {
	if write.Action != RecordCreate && write.Action != RecordUpdate {
		return nil, fmt.Errorf("%w: record action must be create or update", ErrBatchRejected)
	}
	collection, err := syntax.ParseNSID(write.Collection)
	if err != nil || collection.String() != write.Collection {
		return nil, fmt.Errorf("%w: invalid record collection", ErrBatchRejected)
	}
	rkey, err := syntax.ParseRecordKey(write.RKey)
	if err != nil || rkey.String() != write.RKey {
		return nil, fmt.Errorf("%w: invalid record key", ErrBatchRejected)
	}
	if len(write.Record) == 0 || !json.Valid(write.Record) {
		return nil, fmt.Errorf("%w: record value must be valid JSON", ErrBatchRejected)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(write.Record, &value); err != nil || value == nil {
		return nil, fmt.Errorf("%w: record value must be an object", ErrBatchRejected)
	}
	var recordType string
	if raw, ok := value["$type"]; !ok || json.Unmarshal(raw, &recordType) != nil || strings.TrimSpace(recordType) == "" {
		return nil, fmt.Errorf("%w: record value requires a non-empty $type", ErrBatchRejected)
	}
	var typeName string
	if write.Action == RecordCreate {
		typeName = "com.atproto.repo.applyWrites#create"
	} else {
		typeName = "com.atproto.repo.applyWrites#update"
	}
	return json.Marshal(struct {
		Type       string          `json:"$type"`
		Collection string          `json:"collection"`
		RKey       string          `json:"rkey"`
		Value      json.RawMessage `json:"value"`
	}{Type: typeName, Collection: write.Collection, RKey: write.RKey, Value: write.Record})
}

func containsBlobReference(record json.RawMessage) bool {
	var value map[string]json.RawMessage
	if json.Unmarshal(record, &value) != nil {
		return false
	}
	var blob map[string]json.RawMessage
	if json.Unmarshal(value["blob"], &blob) != nil {
		return false
	}
	var blobType string
	if json.Unmarshal(blob["$type"], &blobType) != nil || blobType != "blob" {
		return false
	}
	var reference map[string]json.RawMessage
	if json.Unmarshal(blob["ref"], &reference) != nil {
		return false
	}
	var link string
	if json.Unmarshal(reference["$link"], &link) != nil || link == "" {
		return false
	}
	parsed, err := cid.Parse(link)
	return err == nil && parsed.String() == link
}

func ParseInvalidSwapError(body []byte) bool {
	var response applyWritesError
	return json.Unmarshal(body, &response) == nil && response.Error == "InvalidSwap"
}
