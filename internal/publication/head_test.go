package publication

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

func TestIndependentMalformedHeadCBORIsRejectedWithoutPartialRecords(t *testing.T) {
	base := fixtureHeadValue(t)
	cases := []struct {
		name    string
		encoded []byte
		want    error
		field   string
		reason  string
	}{
		{name: "v1 type", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["$type"] = "systems.lamb.dottie.vaultHead" }), want: ErrInvalidRecord, field: "$type", reason: "unsupported"},
		{name: "unsupported version", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["schemaVersion"] = int64(1) }), want: ErrInvalidRecord, field: "schemaVersion", reason: "unsupported"},
		{name: "old field", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["updatedAt"] = "2030-01-01T00:00:00Z" }), want: ErrInvalidRecord, field: "record", reason: "fields"},
		{name: "missing field", encoded: independentRecordMutation(t, base, func(value map[string]any) { delete(value, "blobCid") }), want: ErrInvalidRecord, field: "record", reason: "fields"},
		{name: "null sequence", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["publicationSeq"] = nil }), want: ErrInvalidRecord, field: "publicationSeq", reason: "integer"},
		{name: "oversized snapshot CID", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["snapshotCid"] = bytes.Repeat([]byte{1}, MaxCIDBytes+1) }), want: ErrCID, field: "snapshotCid", reason: "length"},
		{name: "snapshot CID integer type", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["snapshotCid"] = int64(1) }), want: ErrInvalidRecord, field: "snapshotCid", reason: "type"},
		{name: "blob CID text type", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["blobCid"] = "not-byte-cid" }), want: ErrInvalidRecord, field: "blobCid", reason: "type"},
		{name: "integral float sequence", encoded: independentRecordMutation(t, base, func(value map[string]any) { value["publicationSeq"] = float64(0) }), want: ErrNonCanonical, field: "record", reason: "byte_mismatch"},
		{name: "bytes map in vault", encoded: independentRecordMutation(t, base, func(value map[string]any) {
			value["vault"] = map[string]any{"$bytes": base64.RawStdEncoding.EncodeToString(value["vault"].([]byte))}
		}), want: ErrNonCanonical, field: "record", reason: "byte_mismatch"},
		{name: "trailing item", encoded: append(testCBOR(base), 0x00), want: ErrNonCanonical, field: "record", reason: "byte_mismatch"},
		{name: "oversized head", encoded: bytes.Repeat([]byte{0}, MaxRecordBytes+1), want: ErrInvalidRecord, field: "record", reason: "size_limit"},
	}
	pairs := make(testCBORPairs, 0, len(base)+1)
	for key, value := range base {
		pairs = append(pairs, testPair{key: key, value: value})
	}
	pairs = append(pairs, testPair{key: "$type", value: HeadNSID})
	cases = append(cases, struct {
		name    string
		encoded []byte
		want    error
		field   string
		reason  string
	}{name: "duplicate head field", encoded: testCBOR(pairs), want: ErrInvalidRecord, field: "record", reason: "invalid_cbor"})
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			record, err := DecodeHead(test.encoded)
			require.Equal(t, HeadRecord{}, record)
			requireViolation(t, err, test.want, test.field, test.reason)
		})
	}
}

func TestHeadCIDLengthErrorsMatchEncodeAndDecode(t *testing.T) {
	base := fixtureHeadValue(t)
	for _, field := range []string{"snapshotCid", "blobCid"} {
		for _, test := range []struct {
			name   string
			length int
		}{{name: "empty", length: 0}, {name: "overlong", length: MaxCIDBytes + 1}} {
			t.Run(field+"/"+test.name, func(t *testing.T) {
				invalidBytes := bytes.Repeat([]byte{1}, test.length)
				encodedValue := cloneTestMap(base)
				encodedValue[field] = bytes.Clone(invalidBytes)
				encoded := testCBOR(encodedValue)
				record, err := DecodeHead(encoded)
				require.Equal(t, HeadRecord{}, record)
				requireViolation(t, err, ErrCID, field, "length")

				head := HeadRecord{SchemaVersion: SchemaVersion, Vault: fixtureVault()}
				if field == "snapshotCid" {
					head.SnapshotCID = bytes.Clone(invalidBytes)
					head.BlobCID = independentCID(t, []byte("head payload"), cid.Raw)
				} else {
					head.SnapshotCID = independentCID(t, []byte("snapshot record"), cid.DagCBOR)
					head.BlobCID = bytes.Clone(invalidBytes)
				}
				encoded, err = EncodeHead(head)
				require.Nil(t, encoded)
				requireViolation(t, err, ErrCID, field, "length")
			})
		}
	}
}

func fixtureHeadValue(t testing.TB) map[string]any {
	t.Helper()
	vaultID := fixtureVault()
	return map[string]any{
		"$type":          HeadNSID,
		"schemaVersion":  SchemaVersion,
		"vault":          bytes.Clone(vaultID[:]),
		"publicationSeq": int64(0),
		"snapshotCid":    independentCID(t, []byte("head snapshot fixture"), cid.DagCBOR),
		"blobCid":        independentCID(t, []byte("head payload fixture"), cid.Raw),
	}
}
