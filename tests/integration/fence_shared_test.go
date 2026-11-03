package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fenceSnapshotCollection = "systems.lamb.dottie.vaultSnapshot"
	fenceHeadCollection     = "systems.lamb.dottie.vaultHead"
	fenceControlCollection  = "systems.lamb.dottie.vaultControl"
)

type fenceCreatedRecord struct {
	collection string
	rkey       string
}

type fenceSnapshotFixture struct {
	Type      string          `json:"$type"`
	Probe     string          `json:"probe"`
	Blob      json.RawMessage `json:"blob"`
	CreatedAt string          `json:"createdAt"`
}

type fenceHeadFixture struct {
	Type         string `json:"$type"`
	SnapshotRKey string `json:"snapshotRkey"`
	SnapshotCID  string `json:"snapshotCid"`
	UpdatedAt    string `json:"updatedAt"`
}

type fenceControlDevice struct {
	DID  string `json:"did"`
	Role string `json:"role"`
}

type fenceControlFixture struct {
	Type        string               `json:"$type"`
	Devices     []fenceControlDevice `json:"devices"`
	PolicyEpoch int                  `json:"policyEpoch"`
	UpdatedAt   string               `json:"updatedAt"`
}

type fenceDeleteInput struct {
	Repo       string `json:"repo"`
	SwapCommit string `json:"swapCommit"`
	Writes     []struct {
		Type       string `json:"$type"`
		Collection string `json:"collection"`
		RKey       string `json:"rkey"`
	} `json:"writes"`
}

func revisionReferencesBlob(revision *atproto.Revision, target string) (bool, error) {
	if revision == nil {
		return false, errors.New("verified revision is nil")
	}
	for key, record := range revision.Records() {
		decoded, err := atdata.UnmarshalCBOR(record.Data)
		if err != nil {
			return false, fmt.Errorf("decode verified record %s/%s: %w", key.Collection, key.RKey, err)
		}
		for _, blob := range atdata.ExtractBlobs(decoded) {
			if blob.Ref.CID().String() == target {
				return true, nil
			}
		}
	}
	return false, nil
}

func fenceRecordCID(record []byte) (string, error) {
	decoded, err := atdata.UnmarshalJSON(record)
	if err != nil {
		return "", err
	}
	encoded, err := atdata.MarshalCBOR(decoded)
	if err != nil {
		return "", err
	}
	computed, err := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256).Sum(encoded)
	if err != nil {
		return "", err
	}
	return computed.String(), nil
}

func createNeverUploadedCID(t *testing.T) string {
	t.Helper()
	computed, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum([]byte("never-uploaded DOT-F04 fixture"))
	if err != nil {
		require.NoError(t, err)
	}
	return computed.String()
}

func newFenceProbeKey(t *testing.T) string {
	t.Helper()
	key, err := newPDSProbeKey()
	if err != nil {
		require.NoError(t, err)
	}
	return "probe-" + key
}

func cleanupFenceRecords(t *testing.T, provider string, identity atproto.Identity, transport atproto.Transport, reader atproto.RevisionReader, records []fenceCreatedRecord) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		verified := false
		for attempt := 0; attempt < 3; attempt++ {
			revision, err := reader.Read(ctx, identity.DID)
			if err != nil {
				assert.NoError(t, err, "F04 cleanup read %s/%s: %v", record.collection, record.rkey, err)
				break
			}
			key := atproto.RecordKey{Collection: record.collection, RKey: record.rkey}
			if !revision.HasRecord(key) {
				if err := verifyFenceRecordDeleted(ctx, transport, reader, identity.DID, record.collection, record.rkey); err != nil {
					assert.NoError(t, err, "F04 cleanup verification %s/%s: %v", record.collection, record.rkey, err)
				} else {
					verified = true
				}
				break
			}
			input := fenceDeleteInput{Repo: identity.DID, SwapCommit: revision.CommitCID(), Writes: []struct {
				Type       string `json:"$type"`
				Collection string `json:"collection"`
				RKey       string `json:"rkey"`
			}{{Type: "com.repo.applyWrites#delete", Collection: record.collection, RKey: record.rkey}}}
			body, err := json.Marshal(input)
			if err != nil {
				assert.NoError(t, err, "F04 cleanup encode %s/%s: %v", record.collection, record.rkey, err)
				break
			}
			status, response, requestErr := transport.Do(ctx, http.MethodPost, "com.repo.applyWrites", nil, body, "application/json")
			verifyErr := verifyFenceRecordDeleted(ctx, transport, reader, identity.DID, record.collection, record.rkey)
			if verifyErr == nil {
				verified = true
				break
			}
			if status == http.StatusBadRequest && atproto.ParseInvalidSwapError(response) {
				continue
			}
			if requestErr != nil || status >= 500 {
				assert.NoError(t, requestErr, "F04 cleanup delete %s/%s status=%d error=%v verification=%v", record.collection, record.rkey, status, requestErr, verifyErr)
				assert.Less(t, status, 500, "F04 cleanup delete %s/%s status=%d error=%v verification=%v", record.collection, record.rkey, status, requestErr, verifyErr)
				break
			}
			if status < 200 || status >= 300 {
				assert.GreaterOrEqual(t, status, 200, "F04 cleanup delete %s/%s rejected status=%d body=%s verification=%v", record.collection, record.rkey, status, redactBodyPrefix(response), verifyErr)
				assert.Less(t, status, 300, "F04 cleanup delete %s/%s rejected status=%d body=%s verification=%v", record.collection, record.rkey, status, redactBodyPrefix(response), verifyErr)
				break
			}
			assert.True(t, false, "F04 cleanup verification %s/%s: %v", record.collection, record.rkey, verifyErr)
			break
		}
		if !verified {
			if err := verifyFenceRecordDeleted(ctx, transport, reader, identity.DID, record.collection, record.rkey); err != nil {
				assert.NoError(t, err, "F04 final cleanup verification %s/%s: %v", record.collection, record.rkey, err)
			}
		}
	}
}

func verifyFenceRecordDeleted(ctx context.Context, transport atproto.Transport, reader atproto.RevisionReader, did, collection, rkey string) error {
	revision, err := reader.Read(ctx, did)
	if err != nil {
		return err
	}
	if revision.HasRecord(atproto.RecordKey{Collection: collection, RKey: rkey}) {
		return errors.New("record remains in the current verified revision")
	}
	status, body, err := transport.Do(ctx, http.MethodGet, "com.repo.getRecord", url.Values{"repo": {did}, "collection": {collection}, "rkey": {rkey}}, nil, "")
	if err != nil {
		return err
	}
	if status == http.StatusNotFound || status == http.StatusBadRequest && isPDSRecordAbsent(status, body) {
		return nil
	}
	return fmt.Errorf("record still present or absence unproven: status=%d body=%s", status, redactBodyPrefix(body))
}
