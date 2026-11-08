package publication

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	recordJSONBlobCID     = "bafkreieqc5p7wksheg3xlum7o2zxo3wwsurxud747kalpuokgaeefluyvm"
	recordJSONParentCID   = "bafyreihy6ke4ij3sgd6pl7jzf2osqzst22i4773bcnvq7wnkkueafy76ha"
	recordJSONSnapshotCID = "bafyreieevsp4xc7nore7zzo5roo3gj67ypurlzfjuoq65lexnm6d3ieh2m"
	recordJSONHeadCID     = "bafyreighqowweveosjsytnjw5437sm66vxhe4xnhbyjk7stbov7ll43u3u"
	recordJSONGoldenPubID = "oKGio6SlpqeoqaqrrK2urw"
)

func TestRecordToJSONFixedWireVectors(t *testing.T) {
	blobCID, err := cid.Decode(recordJSONBlobCID)
	require.NoError(t, err)
	parentCID, err := cid.Decode(recordJSONParentCID)
	require.NoError(t, err)
	snapshot := SnapshotRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          fixtureVault(),
		PublicationID:  fixturePublicationID(),
		PublicationSeq: 7,
		Parent:         parentCID.Bytes(),
		Blob:           BlobReference{CID: blobCID.Bytes(), Size: uint64(len("golden publication payload"))},
	}
	snapshotCBOR, err := EncodeSnapshot(snapshot)
	require.NoError(t, err)
	encoded, err := RecordToJSON(snapshotCBOR)
	require.NoError(t, err)
	assert.Equal(t, `{"$type":"systems.lamb.dottie.vaultSnapshotV2","blob":{"$type":"blob","ref":{"$link":"bafkreieqc5p7wksheg3xlum7o2zxo3wwsurxud747kalpuokgaeefluyvm"},"mimeType":"application/octet-stream","size":26},"parent":{"$bytes":"AXESIPjyicQncjD89f05Lp0oZlPWkc//YRNrD9mqVQgC4/44"},"publicationId":{"$bytes":"oKGio6SlpqeoqaqrrK2urw"},"publicationSeq":7,"schemaVersion":2,"vault":{"$bytes":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}}`, string(encoded))
	assertRecordJSONSDKRoundTrip(t, snapshotCBOR, encoded, recordJSONSnapshotCID)

	genesis := snapshot
	genesis.PublicationSeq = 0
	genesis.Parent = nil
	genesisCBOR, err := EncodeSnapshot(genesis)
	require.NoError(t, err)
	genesisJSON, err := RecordToJSON(genesisCBOR)
	require.NoError(t, err)
	assert.Equal(t, `{"$type":"systems.lamb.dottie.vaultSnapshotV2","blob":{"$type":"blob","ref":{"$link":"bafkreieqc5p7wksheg3xlum7o2zxo3wwsurxud747kalpuokgaeefluyvm"},"mimeType":"application/octet-stream","size":26},"parent":{"$bytes":""},"publicationId":{"$bytes":"oKGio6SlpqeoqaqrrK2urw"},"publicationSeq":0,"schemaVersion":2,"vault":{"$bytes":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}}`, string(genesisJSON))
	assertRecordJSONSDKRoundTrip(t, genesisCBOR, genesisJSON, "")

	snapshotCID, err := cid.Decode(recordJSONSnapshotCID)
	require.NoError(t, err)
	head := HeadRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          snapshot.Vault,
		PublicationSeq: snapshot.PublicationSeq,
		SnapshotCID:    snapshotCID.Bytes(),
		BlobCID:        blobCID.Bytes(),
	}
	headCBOR, err := EncodeHead(head)
	require.NoError(t, err)
	headJSON, err := RecordToJSON(headCBOR)
	require.NoError(t, err)
	assert.Equal(t, `{"$type":"systems.lamb.dottie.vaultHeadV2","blobCid":{"$bytes":"AVUSIJAXX/sqRyG3ddGfdrN3btaVI3oP/PqAt9HKMAhCrpir"},"publicationSeq":7,"schemaVersion":2,"snapshotCid":{"$bytes":"AXESIISsn8uL7XRJ/OXdi52zJ9/D6RXkqaOh7qyXazw9oIfT"},"vault":{"$bytes":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}}`, string(headJSON))
	assertRecordJSONSDKRoundTrip(t, headCBOR, headJSON, recordJSONHeadCID)
}

func TestRecordToJSONMaximumAcceptedValuesFitBounds(t *testing.T) {
	blobCID, err := cid.Decode(recordJSONBlobCID)
	require.NoError(t, err)
	parentCID, err := cid.Decode(recordJSONParentCID)
	require.NoError(t, err)
	snapshot := SnapshotRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          fixtureVault(),
		PublicationID:  fixturePublicationID(),
		PublicationSeq: MaxSequence,
		Parent:         parentCID.Bytes(),
		Blob:           BlobReference{CID: blobCID.Bytes(), Size: MaxBlobBytes},
	}
	snapshotCBOR, err := EncodeSnapshot(snapshot)
	require.NoError(t, err)
	snapshotJSON, err := RecordToJSON(snapshotCBOR)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(snapshotJSON), maxRecordJSONBytes)
	assertRecordJSONSDKRoundTrip(t, snapshotCBOR, snapshotJSON, "")
	object, err := atdata.UnmarshalJSON(snapshotJSON)
	require.NoError(t, err)
	assert.Equal(t, int64(MaxSequence), object["publicationSeq"])
	blob, ok := object["blob"].(atdata.Blob)
	require.True(t, ok)
	assert.Equal(t, int64(MaxBlobBytes), blob.Size)

	snapshotCID, err := RecordCID(snapshotCBOR)
	require.NoError(t, err)
	headCBOR, err := EncodeHead(HeadRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          fixtureVault(),
		PublicationSeq: MaxSequence,
		SnapshotCID:    snapshotCID,
		BlobCID:        blobCID.Bytes(),
	})
	require.NoError(t, err)
	headJSON, err := RecordToJSON(headCBOR)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(headJSON), maxRecordJSONBytes)
	assertRecordJSONSDKRoundTrip(t, headCBOR, headJSON, "")
	object, err = atdata.UnmarshalJSON(headJSON)
	require.NoError(t, err)
	assert.Equal(t, int64(MaxSequence), object["publicationSeq"])
}

func TestRecordToJSONRejectsInvalidInputAndPreservesValidationErrors(t *testing.T) {
	valid, err := EncodeSnapshot(fixtureSnapshotValue(t))
	require.NoError(t, err)
	unsupported, err := atdata.MarshalCBOR(map[string]any{"$type": "systems.lamb.dottie.vaultSnapshot"})
	require.NoError(t, err)
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty", data: nil, want: ErrInvalidRecord},
		{name: "invalid cbor", data: []byte{0xff}, want: ErrInvalidRecord},
		{name: "noncanonical", data: append(bytes.Clone(valid), 0x00), want: ErrNonCanonical},
		{name: "unsupported collection", data: unsupported, want: ErrInvalidRecord},
		{name: "oversized cbor", data: make([]byte, MaxRecordBytes+1), want: ErrInvalidRecord},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := RecordToJSON(test.data)
			require.Nil(t, encoded)
			require.ErrorIs(t, err, test.want)
			assert.NotErrorIs(t, err, ErrRecordJSON)
		})
	}
}

func TestRecordToJSONSelfCheckRejectsEmittedCorruption(t *testing.T) {
	blobCID, err := cid.Decode(recordJSONBlobCID)
	require.NoError(t, err)
	parentCID, err := cid.Decode(recordJSONParentCID)
	require.NoError(t, err)
	snapshot := SnapshotRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          fixtureVault(),
		PublicationID:  fixturePublicationID(),
		PublicationSeq: 7,
		Parent:         parentCID.Bytes(),
		Blob:           BlobReference{CID: blobCID.Bytes(), Size: uint64(len("golden publication payload"))},
	}
	snapshotCBOR, err := EncodeSnapshot(snapshot)
	require.NoError(t, err)

	wrongParent := func(value any) ([]byte, error) {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return bytes.Replace(encoded, []byte(`"parent":{"$bytes":"`), []byte(`"parent":{"$link":"`), 1), nil
	}
	encoded, err := recordToJSONWithEncoder(snapshotCBOR, wrongParent)
	require.Nil(t, encoded)
	requireRecordJSONViolation(t, err, "reconstruction")

	genesis := snapshot
	genesis.PublicationSeq = 0
	genesis.Parent = nil
	genesisCBOR, err := EncodeSnapshot(genesis)
	require.NoError(t, err)
	nullParent := func(value any) ([]byte, error) {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return bytes.Replace(encoded, []byte(`"parent":{"$bytes":""}`), []byte(`"parent":null`), 1), nil
	}
	encoded, err = recordToJSONWithEncoder(genesisCBOR, nullParent)
	require.Nil(t, encoded)
	requireRecordJSONViolation(t, err, "reconstruction")

	changedID := snapshot.PublicationID
	changedID[0] ^= 0x80
	changedIDText := base64.RawStdEncoding.EncodeToString(changedID[:])
	changedPublication := func(value any) ([]byte, error) {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return bytes.Replace(encoded, []byte(recordJSONGoldenPubID), []byte(changedIDText), 1), nil
	}
	encoded, err = recordToJSONWithEncoder(snapshotCBOR, changedPublication)
	require.Nil(t, encoded)
	requireRecordJSONViolation(t, err, "cid_mismatch")

	alternate := snapshot
	alternate.PublicationID[0] ^= 0x80
	alternateCBOR, err := EncodeSnapshot(alternate)
	require.NoError(t, err)
	alternateJSON, err := RecordToJSON(alternateCBOR)
	require.NoError(t, err)
	assert.NotEmpty(t, alternateJSON)
	originalCID, err := RecordCID(snapshotCBOR)
	require.NoError(t, err)
	alternateCID, err := RecordCID(alternateCBOR)
	require.NoError(t, err)
	assert.NotEqual(t, originalCID, alternateCID)
	assert.NotEqual(t, snapshotCBOR, alternateCBOR)
}

func TestRecordToJSONClosedErrorsDoNotExposeEncoderOrParserText(t *testing.T) {
	valid, err := EncodeSnapshot(fixtureSnapshotValue(t))
	require.NoError(t, err)

	encoded, err := recordToJSONWithEncoder(valid, func(any) ([]byte, error) {
		return nil, errors.New("CANARY encoder secret CID")
	})
	require.Nil(t, encoded)
	requireRecordJSONViolation(t, err, "encoding")
	assert.NotContains(t, err.Error(), "CANARY")

	encoded, err = recordToJSONWithEncoder(valid, func(any) ([]byte, error) {
		return []byte(`{"$type":"CANARY malformed CID"`), nil
	})
	require.Nil(t, encoded)
	requireRecordJSONViolation(t, err, "reconstruction")
	assert.NotContains(t, err.Error(), "CANARY")

	encoded, err = recordToJSONWithEncoder(valid, func(any) ([]byte, error) {
		return bytes.Repeat([]byte(" "), maxRecordJSONBytes+1), nil
	})
	require.Nil(t, encoded)
	requireRecordJSONViolation(t, err, "size_limit")
}

func TestRecordToJSONIsDeterministicAndDoesNotShareBuffers(t *testing.T) {
	input, err := EncodeSnapshot(fixtureSnapshotValue(t))
	require.NoError(t, err)
	originalInput := bytes.Clone(input)
	first, err := RecordToJSON(input)
	require.NoError(t, err)
	second, err := RecordToJSON(input)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	first[0] ^= 0xff
	assert.Equal(t, originalInput, input)
	assert.NotEqual(t, first, second)
	assertRecordJSONSDKRoundTrip(t, input, second, "")
}

func assertRecordJSONSDKRoundTrip(t *testing.T, original, encoded []byte, expectedCID string) {
	t.Helper()
	parsed, err := atdata.UnmarshalJSON(encoded)
	require.NoError(t, err)
	reconstructed, err := atdata.MarshalCBOR(parsed)
	require.NoError(t, err)
	assert.Equal(t, original, reconstructed)
	originalCID, err := RecordCID(original)
	require.NoError(t, err)
	reconstructedCID, err := RecordCID(reconstructed)
	require.NoError(t, err)
	assert.Equal(t, originalCID, reconstructedCID)
	if expectedCID != "" {
		identifier, err := cid.Cast(originalCID)
		require.NoError(t, err)
		assert.Equal(t, expectedCID, identifier.String())
	}
}

func requireRecordJSONViolation(t *testing.T, err error, reason string) {
	t.Helper()
	require.ErrorIs(t, err, ErrRecordJSON)
	var problem *Violation
	require.ErrorAs(t, err, &problem)
	assert.Equal(t, "record", problem.Field())
	assert.Equal(t, reason, problem.Reason())
}
