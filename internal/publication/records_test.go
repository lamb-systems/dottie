package publication

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
)

func TestSequenceKeyBoundsAndCanonicalForm(t *testing.T) {
	key, err := SequenceKey(0)
	require.NoError(t, err)
	assert.Equal(t, "0000000000000000", key)
	sequence, err := ParseSequenceKey("0000000000000000")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), sequence)
	key, err = SequenceKey(MaxSequence)
	require.NoError(t, err)
	assert.Equal(t, "9007199254740991", key)
	sequence, err = ParseSequenceKey(key)
	require.NoError(t, err)
	assert.Equal(t, MaxSequence, sequence)

	for _, invalid := range []struct {
		key    string
		reason string
	}{
		{key: "0", reason: "format"},
		{key: "000000000000000", reason: "format"},
		{key: "00000000000000000", reason: "format"},
		{key: "000000000000000a", reason: "format"},
		{key: "00000000000000 0", reason: "format"},
		{key: "００００００００００００００００", reason: "format"},
		{key: "9007199254740992", reason: "out_of_range"},
		{key: "-000000000000001", reason: "format"},
		{key: "+000000000000001", reason: "format"},
		{key: " 000000000000001", reason: "format"},
	} {
		_, err := ParseSequenceKey(invalid.key)
		requireViolation(t, err, ErrSequenceKey, "snapshotKey", invalid.reason)
	}
	key, err = SequenceKey(MaxSequence + 1)
	require.Empty(t, key)
	requireViolation(t, err, ErrSequenceKey, "sequence", "out_of_range")
}

func TestIndependentAtdataMapsMatchFixedCanonicalGoldens(t *testing.T) {
	payload := []byte("golden publication payload")
	blobCID := independentCID(t, payload, cid.Raw)
	parentCID := independentCID(t, []byte("previous record fixture"), cid.DagCBOR)
	snapshot := SnapshotRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          fixtureVault(),
		PublicationID:  fixturePublicationID(),
		PublicationSeq: 7,
		Parent:         parentCID,
		Segments: []SnapshotSegment{{
			Target: fixturePackedTarget(), Form: SegmentFormPacked,
			Blob: BlobReference{CID: blobCID, Size: uint64(len(payload)), MIMEType: SnapshotBlobMIMEType},
		}},
	}
	independentSnapshot := independentSnapshotBytes(t, snapshot)
	encodedSnapshot, err := EncodeSnapshot(snapshot)
	require.NoError(t, err)
	assert.Equal(t, independentSnapshot, encodedSnapshot)
	assert.Equal(
		t,
		"a7652474797065782373797374656d732e6c616d622e646f747469652e7661756c74536e617073686f745632657661756c7458200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066706172656e74582401711220f8f289c4277230fcf5fd392e9d286653d691cfff61136b0fd9aa550802e3fe38687365676d656e747381a364626c6f62a463726566d82a5825000155122090175ffb2a4721b775d19f76b3776ed695237a0ffcfa80b7d1ca300842ae98ab6473697a65181a65247479706564626c6f62686d696d6554797065716170706c69636174696f6e2f782d74617264666f726d667061636b656466746172676574a46269646566696c657364726f6f74a3646261736564686f6d65646b696e64696469726563746f7279647061746868646f7466696c657366736f757263656566696c65736e736f757263655f76657273696f6e016d7075626c69636174696f6e496450a0a1a2a3a4a5a6a7a8a9aaabacadaeaf6d736368656d6156657273696f6e026e7075626c69636174696f6e53657107",
		hex.EncodeToString(encodedSnapshot),
	)
	decodedSnapshot, err := DecodeSnapshot(independentSnapshot)
	require.NoError(t, err)
	assert.Equal(t, snapshot, decodedSnapshot)
	recordCID, err := RecordCID(independentSnapshot)
	require.NoError(t, err)
	assert.Equal(
		t,
		"bafyreiahc4lmoti3pp35aihxohxsvtlvaibiu7m6sayyvupueagraefn44",
		cid.NewCidV1(cid.DagCBOR, mustHash(t, independentSnapshot)).String(),
	)
	blobIdentifier, err := cid.Cast(blobCID)
	require.NoError(t, err)
	assert.Equal(t, "bafkreieqc5p7wksheg3xlum7o2zxo3wwsurxud747kalpuokgaeefluyvm", blobIdentifier.String())

	head := HeadRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          snapshot.Vault,
		PublicationSeq: snapshot.PublicationSeq,
		SnapshotCID:    independentCID(t, independentSnapshot, cid.DagCBOR),
	}
	independentHead := independentHeadBytes(t, head)
	encodedHead, err := EncodeHead(head)
	require.NoError(t, err)
	assert.Equal(t, independentHead, encodedHead)
	assert.Equal(
		t,
		"a5652474797065781f73797374656d732e6c616d622e646f747469652e7661756c74486561645632657661756c7458200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206b736e617073686f74436964582401711220071716c74d1b7bf7d020f771ef2acd7502028a7d9e90318ad1f4200d1010ade76d736368656d6156657273696f6e026e7075626c69636174696f6e53657107",
		hex.EncodeToString(encodedHead),
	)
	decodedHead, err := DecodeHead(independentHead)
	require.NoError(t, err)
	assert.Equal(t, head, decodedHead)
	headCID, err := RecordCID(encodedHead)
	require.NoError(t, err)
	headCIDValue, err := cid.Cast(headCID)
	require.NoError(t, err)
	assert.Equal(t, "bafyreicp44qnlfnblupivdycknb72wpkmi47y2fi3ai2bznsttdgfkudum", headCIDValue.String())
	assert.Equal(t, head.SnapshotCID, recordCID)
}

func TestHeadBindingChecksEveryRecordAndPayloadJoin(t *testing.T) {
	payload := []byte("binding canary payload")
	snapshot, snapshotBytes := fixtureSnapshot(t, payload, 0, nil, 1)
	sequenceKey, err := SequenceKey(snapshot.PublicationSeq)
	require.NoError(t, err)
	snapshotCID, err := RecordCID(snapshotBytes)
	require.NoError(t, err)
	head := HeadRecord{
		SchemaVersion: SchemaVersion, Vault: snapshot.Vault, PublicationSeq: snapshot.PublicationSeq,
		SnapshotCID: snapshotCID,
	}
	headBytes, err := EncodeHead(head)
	require.NoError(t, err)
	require.NoError(t, VerifyHeadBinding(headBytes, snapshotBytes, sequenceKey))
	require.NoError(t, VerifyPayload(payload, blobOf(snapshot)))

	wrongVault := head
	wrongVault.Vault[0] ^= 0x80
	wrongVaultBytes, err := EncodeHead(wrongVault)
	require.NoError(t, err)
	requireViolation(t, VerifyHeadBinding(wrongVaultBytes, snapshotBytes, sequenceKey), ErrBinding, "vault", "mismatch")

	wrongSequence := head
	wrongSequence.PublicationSeq++
	wrongSequenceBytes, err := EncodeHead(wrongSequence)
	require.NoError(t, err)
	requireViolation(
		t,
		VerifyHeadBinding(wrongSequenceBytes, snapshotBytes, sequenceKey),
		ErrBinding,
		"publicationSeq",
		"mismatch",
	)
	wrongKey, err := SequenceKey(snapshot.PublicationSeq + 1)
	require.NoError(t, err)
	requireViolation(
		t,
		VerifyHeadBinding(headBytes, snapshotBytes, wrongKey),
		ErrBinding,
		"snapshotKey",
		"sequence_mismatch",
	)

	otherSnapshot := snapshot
	otherSnapshot.PublicationID[0]++
	otherSnapshotBytes, err := EncodeSnapshot(otherSnapshot)
	require.NoError(t, err)
	requireViolation(
		t,
		VerifyHeadBinding(headBytes, otherSnapshotBytes, sequenceKey),
		ErrBinding,
		"snapshotCid",
		"mismatch",
	)

	short := bytes.Clone(payload[:len(payload)-1])
	requireViolation(t, VerifyPayload(short, blobOf(snapshot)), ErrPayload, "blob.size", "mismatch")
	altered := bytes.Clone(payload)
	altered[0] ^= 1
	requireViolation(t, VerifyPayload(altered, blobOf(snapshot)), ErrPayload, "blob.ref", "mismatch")
	wrongLength := blobOf(snapshot)
	wrongLength.Size++
	requireViolation(t, VerifyPayload(payload, wrongLength), ErrPayload, "blob.size", "mismatch")
}

func TestIdenticalPayloadHasDistinctChainedPublicationRecords(t *testing.T) {
	payload := []byte("identical plaintext for two publications")
	first, firstBytes := fixtureSnapshot(t, payload, 0, nil, 3)
	firstCID, err := RecordCID(firstBytes)
	require.NoError(t, err)
	second, secondBytes := fixtureSnapshot(t, payload, 1, firstCID, 4)
	assert.Equal(t, blobOf(first).CID, blobOf(second).CID)
	assert.NotEqual(t, firstBytes, secondBytes)
	secondCID, err := RecordCID(secondBytes)
	require.NoError(t, err)
	assert.NotEqual(t, firstCID, secondCID)
	key, err := SequenceKey(second.PublicationSeq)
	require.NoError(t, err)
	require.NoError(t, VerifySuccessor(firstBytes, secondBytes, key))
	firstKey, err := SequenceKey(first.PublicationSeq)
	require.NoError(t, err)
	assert.NotEqual(t, firstKey, key)

	crossVault := second
	crossVault.Vault[1]++
	crossVaultBytes, err := EncodeSnapshot(crossVault)
	require.NoError(t, err)
	requireViolation(t, VerifySuccessor(firstBytes, crossVaultBytes, key), ErrBinding, "vault", "mismatch")

	skipped, skippedBytes := fixtureSnapshot(t, payload, 2, firstCID, 5)
	skippedKey, err := SequenceKey(skipped.PublicationSeq)
	require.NoError(t, err)
	requireViolation(
		t,
		VerifySuccessor(firstBytes, skippedBytes, skippedKey),
		ErrBinding,
		"publicationSeq",
		"not_successor",
	)

	substitutedParent := second
	substitutedParent.Parent = independentCID(t, []byte("another record"), cid.DagCBOR)
	substitutedParentBytes, err := EncodeSnapshot(substitutedParent)
	require.NoError(t, err)
	requireViolation(t, VerifySuccessor(firstBytes, substitutedParentBytes, key), ErrBinding, "parent", "mismatch")
	wrongKey, err := SequenceKey(9)
	require.NoError(t, err)
	requireViolation(
		t,
		VerifySuccessor(firstBytes, secondBytes, wrongKey),
		ErrBinding,
		"snapshotKey",
		"sequence_mismatch",
	)

	maximum, maximumBytes := fixtureSnapshot(
		t,
		payload,
		MaxSequence,
		independentCID(t, []byte("valid predecessor link"), cid.DagCBOR),
		6,
	)
	_, zeroBytes := fixtureSnapshot(t, payload, 0, nil, 7)
	assert.Equal(t, MaxSequence, maximum.PublicationSeq)
	requireViolation(
		t,
		VerifySuccessor(maximumBytes, zeroBytes, "0000000000000000"),
		ErrBinding,
		"publicationSeq",
		"not_successor",
	)
}

func TestEncodeRejectsInvalidIdentifiersSequencesAndCIDRoles(t *testing.T) {
	payload := []byte("valid payload")
	snapshot, _ := fixtureSnapshot(t, payload, 0, nil, 1)
	invalid := snapshot
	invalid.SchemaVersion = 1
	encoded, err := EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "schemaVersion", "unsupported")
	invalid = snapshot
	invalid.Vault = [32]byte{}
	encoded, err = EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "vault", "zero")
	invalid = snapshot
	invalid.PublicationID = [16]byte{}
	encoded, err = EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "publicationId", "zero")
	invalid = snapshot
	invalid.PublicationSeq = MaxSequence + 1
	encoded, err = EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "publicationSeq", "range")
	invalid = snapshot
	invalid.Parent = independentCID(t, []byte("nonempty genesis parent"), cid.DagCBOR)
	encoded, err = EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "parent", "genesis_nonempty")
	invalid = snapshot
	invalid.PublicationSeq = 1
	encoded, err = EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "parent", "missing")
	invalid = snapshot
	invalid.Segments[0].Blob.Size = MaxBlobBytes + 1
	encoded, err = EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "segments.blob", "unsupported")
	invalid = snapshot
	invalid.Segments[0].Blob.CID = independentCID(t, []byte("wrong role"), cid.DagCBOR)
	encoded, err = EncodeSnapshot(invalid)
	require.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "segments.blob", "unsupported")

	head := HeadRecord{
		SchemaVersion: 1,
		Vault:         snapshot.Vault,
		SnapshotCID:   independentCID(t, []byte("record"), cid.DagCBOR),
	}
	headBytes, err := EncodeHead(head)
	require.Nil(t, headBytes)
	requireViolation(t, err, ErrInvalidRecord, "schemaVersion", "unsupported")
	head.SchemaVersion = SchemaVersion
	head.SnapshotCID = independentCID(t, []byte("record"), cid.Raw)
	headBytes, err = EncodeHead(head)
	require.Nil(t, headBytes)
	requireViolation(t, err, ErrCID, "snapshotCid", "role")
}

func TestIndependentMalformedCBORIsRejectedWithoutPartialRecords(t *testing.T) {
	base := independentSnapshotValue(t, fixtureSnapshotValue(t))
	blobCID := segmentValue(base, 0)["blob"].(map[string]any)["ref"].(testTag).value.([]byte)[1:]
	blobCIDText, err := cid.Cast(blobCID)
	require.NoError(t, err)
	parentCID := independentCID(t, []byte("preceding fixture"), cid.DagCBOR)

	cases := []struct {
		name    string
		encoded []byte
		want    error
		field   string
		reason  string
	}{
		{
			name: "v1 type",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { value["$type"] = "systems.lamb.dottie.vaultSnapshot" },
			),
			want:   ErrInvalidRecord,
			field:  "$type",
			reason: "unsupported",
		},
		{
			name: "unknown type",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { value["$type"] = "systems.lamb.dottie.vaultSnapshotUnknown" },
			),
			want:   ErrInvalidRecord,
			field:  "$type",
			reason: "unsupported",
		},
		{
			name: "unknown version",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { value["schemaVersion"] = int64(3) },
			),
			want:   ErrInvalidRecord,
			field:  "schemaVersion",
			reason: "unsupported",
		},
		{
			name:    "legacy fields",
			encoded: independentRecordMutation(t, base, func(value map[string]any) { value["epochSeq"] = int64(0) }),
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "fields",
		},
		{
			name:    "unknown field",
			encoded: independentRecordMutation(t, base, func(value map[string]any) { value["extra"] = "unrecognized" }),
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "fields",
		},
		{
			name:    "missing field",
			encoded: independentRecordMutation(t, base, func(value map[string]any) { delete(value, "publicationId") }),
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "fields",
		},
		{name: "renamed field", encoded: independentRecordMutation(t, base, func(value map[string]any) {
			value["publicationID"] = value["publicationId"]
			delete(value, "publicationId")
		}), want: ErrInvalidRecord, field: "publicationId", reason: "missing"},
		{
			name:    "null sequence",
			encoded: independentRecordMutation(t, base, func(value map[string]any) { value["publicationSeq"] = nil }),
			want:    ErrInvalidRecord,
			field:   "publicationSeq",
			reason:  "integer",
		},
		{
			name: "integral float sequence",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { value["publicationSeq"] = float64(0) },
			),
			want:   ErrNonCanonical,
			field:  "record",
			reason: "byte_mismatch",
		},
		{
			name:    "boolean sequence",
			encoded: independentRecordMutation(t, base, func(value map[string]any) { value["publicationSeq"] = true }),
			want:    ErrInvalidRecord,
			field:   "publicationSeq",
			reason:  "integer",
		},
		{
			name: "negative sequence",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { value["publicationSeq"] = int64(-1) },
			),
			want:   ErrInvalidRecord,
			field:  "publicationSeq",
			reason: "integer",
		},
		{
			name: "overflow sequence",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { value["publicationSeq"] = int64(MaxSequence + 1) },
			),
			want:   ErrInvalidRecord,
			field:  "publicationSeq",
			reason: "integer",
		},
		{
			name: "uint64 overflow sequence",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { value["publicationSeq"] = ^uint64(0) },
			),
			want:   ErrInvalidRecord,
			field:  "publicationSeq",
			reason: "integer",
		},
		{
			name: "integral float blob size",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) {
					segmentValue(value, 0)["blob"].(map[string]any)["size"] = float64(len("fixture payload"))
				},
			),
			want:   ErrNonCanonical,
			field:  "record",
			reason: "byte_mismatch",
		},
		{
			name: "unknown nested blob field",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { segmentValue(value, 0)["blob"].(map[string]any)["extra"] = true },
			),
			want:   ErrInvalidRecord,
			field:  "record",
			reason: "invalid_cbor",
		},
		{
			name: "missing nested blob size",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { delete(segmentValue(value, 0)["blob"].(map[string]any), "size") },
			),
			want:   ErrInvalidRecord,
			field:  "record",
			reason: "invalid_cbor",
		},
		{
			name: "null nested blob field",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) { segmentValue(value, 0)["blob"].(map[string]any)["size"] = nil },
			),
			want:   ErrInvalidRecord,
			field:  "record",
			reason: "invalid_cbor",
		},
		{name: "bytes map in vault", encoded: independentRecordMutation(t, base, func(value map[string]any) {
			value["vault"] = map[string]any{"$bytes": base64.RawStdEncoding.EncodeToString(value["vault"].([]byte))}
		}), want: ErrNonCanonical, field: "record", reason: "byte_mismatch"},
		{name: "bytes map in parent", encoded: independentRecordMutation(t, base, func(value map[string]any) {
			value["publicationSeq"] = int64(1)
			value["parent"] = map[string]any{"$bytes": base64.RawStdEncoding.EncodeToString(parentCID)}
		}), want: ErrNonCanonical, field: "record", reason: "byte_mismatch"},
		{name: "link map in blob ref", encoded: independentRecordMutation(t, base, func(value map[string]any) {
			segmentValue(value, 0)["blob"].(map[string]any)["ref"] = map[string]any{"$link": blobCIDText.String()}
		}), want: ErrNonCanonical, field: "record", reason: "byte_mismatch"},
		{name: "legacy blob map", encoded: independentRecordMutation(t, base, func(value map[string]any) {
			value["blob"] = map[string]any{"mimeType": SnapshotBlobMIMEType, "cid": blobCIDText.String()}
		}), want: ErrInvalidRecord, field: "record", reason: "fields"},
		{
			name:    "trailing item",
			encoded: append(independentSnapshotBytes(t, fixtureSnapshotValue(t)), 0x00),
			want:    ErrNonCanonical,
			field:   "record",
			reason:  "byte_mismatch",
		},
		{
			name:    "indefinite map",
			encoded: independentIndefiniteSnapshot(t, base),
			want:    ErrNonCanonical,
			field:   "record",
			reason:  "byte_mismatch",
		},
		{
			name:    "nonminimal map header",
			encoded: independentNonminimalSnapshot(t, base),
			want:    ErrNonCanonical,
			field:   "record",
			reason:  "byte_mismatch",
		},
		{
			name: "invalid utf8",
			encoded: independentRecordMutation(
				t,
				base,
				func(value map[string]any) {
					segmentValue(value, 0)["blob"].(map[string]any)["mimeType"] = string([]byte{0xff})
				},
			),
			want:   ErrNonCanonical,
			field:  "record",
			reason: "invalid_utf8",
		},
		{
			name:    "undefined sequence",
			encoded: independentUndefinedSequence(t, base),
			want:    ErrInvalidRecord,
			field:   "publicationSeq",
			reason:  "integer",
		},
		{
			name:    "huge map declaration",
			encoded: []byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "invalid_cbor",
		},
		{
			name:    "huge byte string declaration",
			encoded: []byte{0xa1, 0x65, 'v', 'a', 'u', 'l', 't', 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "invalid_cbor",
		},
		{
			name:    "large representable byte string declaration",
			encoded: []byte{0xa1, 0x65, 'v', 'a', 'u', 'l', 't', 0x5a, 0x01, 0xff, 0xff, 0xff},
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "invalid_cbor",
		},
		{
			name:    "large representable map declaration",
			encoded: []byte{0xa1, 0x65, 'e', 'x', 't', 'r', 'a', 0xba, 0x7f, 0xff, 0xff, 0xff},
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "invalid_cbor",
		},
		{
			name:    "large representable array declaration under map",
			encoded: []byte{0xa1, 0x65, 'e', 'x', 't', 'r', 'a', 0x9a, 0x7f, 0xff, 0xff, 0xff},
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "invalid_cbor",
		},
		{name: "oversized parent bytes", encoded: independentRecordMutation(t, base, func(value map[string]any) {
			value["publicationSeq"] = int64(1)
			value["parent"] = bytes.Repeat([]byte{1}, MaxCIDBytes+1)
		}), want: ErrInvalidRecord, field: "parent", reason: "length"},
		{
			name:    "oversized record",
			encoded: bytes.Repeat([]byte{0}, MaxRecordBytes+1),
			want:    ErrInvalidRecord,
			field:   "record",
			reason:  "size_limit",
		},
	}

	duplicateTop := independentDuplicateSnapshotField(t, base, "$type", SnapshotNSID)
	cases = append(cases, struct {
		name    string
		encoded []byte
		want    error
		field   string
		reason  string
	}{name: "duplicate top-level field", encoded: duplicateTop, want: ErrInvalidRecord, field: "record", reason: "invalid_cbor"})
	duplicateNested := independentDuplicateNestedBlobField(t, base)
	cases = append(cases, struct {
		name    string
		encoded []byte
		want    error
		field   string
		reason  string
	}{name: "duplicate nested blob field", encoded: duplicateNested, want: ErrInvalidRecord, field: "record", reason: "invalid_cbor"})

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := DecodeSnapshot(test.encoded)
			require.Equal(t, SnapshotRecord{}, decoded)
			requireViolation(t, err, test.want, test.field, test.reason)
		})
	}
}

func TestIndependentCIDRoleAndHashVariantsAreRejected(t *testing.T) {
	payload := []byte("CID variant payload")
	valid := independentSnapshotValue(t, fixtureSnapshotValue(t))
	variants := []struct {
		name  string
		cid   []byte
		field string
	}{
		{name: "wrong codec", cid: independentCID(t, payload, cid.DagCBOR), field: "segments.blob.ref"},
		{name: "cid v0", cid: independentCIDV0(t, payload), field: "segments.blob.ref"},
		{
			name:  "wrong hash",
			cid:   independentCIDWithPrefix(t, payload, cid.Raw, multihash.SHA3_256, 32),
			field: "segments.blob.ref",
		},
		{
			name:  "wrong hash length",
			cid:   independentCIDWithPrefix(t, payload, cid.Raw, multihash.SHA2_256, 16),
			field: "segments.blob.ref",
		},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			value := cloneTestMap(valid)
			segmentValue(value, 0)["blob"].(map[string]any)["ref"] = testTag{number: 42, value: append([]byte{0}, variant.cid...)}
			encoded := testCBOR(value)
			decoded, err := DecodeSnapshot(encoded)
			require.Equal(t, SnapshotRecord{}, decoded)
			requireViolation(t, err, ErrCID, variant.field, "role")
		})
	}

	parentCID := independentCID(t, []byte("raw parent role"), cid.Raw)
	value := independentSnapshotValue(t, fixtureSnapshotValue(t))
	value["publicationSeq"] = int64(1)
	value["parent"] = parentCID
	encoded := testCBOR(value)
	_, err := DecodeSnapshot(encoded)
	requireViolation(t, err, ErrCID, "parent", "role")

	badHead := HeadRecord{
		SchemaVersion: SchemaVersion, Vault: fixtureVault(), PublicationSeq: 0,
		SnapshotCID: independentCID(t, []byte("raw snapshot CID"), cid.Raw),
	}
	_, err = EncodeHead(badHead)
	requireViolation(t, err, ErrCID, "snapshotCid", "role")
}

func TestRecordCIDDispatchReturnsStrictDecoderErrors(t *testing.T) {
	head := fixtureHeadValue(t)
	snapshot := independentSnapshotValue(t, fixtureSnapshotValue(t))
	cases := []struct {
		name    string
		encoded []byte
		want    error
		field   string
		reason  string
	}{
		{name: "head wrong codec", encoded: independentRecordMutation(t, head, func(value map[string]any) {
			value["snapshotCid"] = independentCID(t, []byte("raw record cid"), cid.Raw)
		}), want: ErrCID, field: "snapshotCid", reason: "role"},
		{
			name: "head unsupported version",
			encoded: independentRecordMutation(
				t,
				head,
				func(value map[string]any) { value["schemaVersion"] = int64(1) },
			),
			want:   ErrInvalidRecord,
			field:  "schemaVersion",
			reason: "unsupported",
		},
		{
			name: "invalid snapshot",
			encoded: independentRecordMutation(
				t,
				snapshot,
				func(value map[string]any) { value["schemaVersion"] = int64(1) },
			),
			want:   ErrInvalidRecord,
			field:  "schemaVersion",
			reason: "unsupported",
		},
		{
			name: "unknown type",
			encoded: independentRecordMutation(
				t,
				snapshot,
				func(value map[string]any) { value["$type"] = "systems.lamb.dottie.vaultPolicy" },
			),
			want:   ErrInvalidRecord,
			field:  "$type",
			reason: "unsupported",
		},
		{
			name:    "missing type",
			encoded: independentRecordMutation(t, snapshot, func(value map[string]any) { delete(value, "$type") }),
			want:    ErrInvalidRecord,
			field:   "$type",
			reason:  "invalid",
		},
		{name: "empty input", encoded: nil, want: ErrInvalidRecord, field: "record", reason: "size_limit"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cidBytes, err := RecordCID(test.encoded)
			require.Nil(t, cidBytes)
			requireViolation(t, err, test.want, test.field, test.reason)
		})
	}
}

func TestRawPayloadCIDRejectsInvalidSize(t *testing.T) {
	cidBytes, err := RawPayloadCID(nil)
	require.Nil(t, cidBytes)
	requireViolation(t, err, ErrPayload, "payload.size", "range")
}

func TestPublicationErrorsAreFixedAndDoNotEchoInput(t *testing.T) {
	untrusted := []byte("private record bytes with identifier and digest material")
	decoded, err := DecodeSnapshot(untrusted)
	require.Equal(t, SnapshotRecord{}, decoded)
	require.ErrorIs(t, err, ErrInvalidRecord)
	assert.NotContains(t, err.Error(), string(untrusted))
	assert.NotContains(t, err.Error(), "private")
	assert.NotContains(t, fmt.Sprintf("%v", err), "digest material")
}

func TestV2SchemasMatchTheCodecContract(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "lexicons", "v2", "*.json"))
	require.NoError(t, err)
	require.Len(t, paths, 2)
	type lexiconFile struct {
		Lexicon int    `json:"lexicon"`
		ID      string `json:"id"`
		Defs    map[string]struct {
			Type   string `json:"type"`
			Key    string `json:"key"`
			Record struct {
				Required   []string                  `json:"required"`
				Properties map[string]map[string]any `json:"properties"`
			} `json:"record"`
		} `json:"defs"`
	}
	got := make(map[string]lexiconFile)
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		var document lexiconFile
		require.NoError(t, json.Unmarshal(data, &document))
		got[document.ID] = document
	}
	snapshot := got[SnapshotNSID]
	head := got[HeadNSID]
	assert.Equal(t, 1, snapshot.Lexicon)
	assert.Equal(t, 1, head.Lexicon)
	assert.Equal(t, "record", snapshot.Defs["main"].Type)
	assert.Equal(t, "any", snapshot.Defs["main"].Key)
	assert.Equal(t, "record", head.Defs["main"].Type)
	assert.Equal(t, "literal:self", head.Defs["main"].Key)
	assert.Equal(
		t,
		[]string{"parent", "publicationId", "publicationSeq", "schemaVersion", "segments", "vault"},
		sortedStrings(snapshot.Defs["main"].Record.Required),
	)
	assert.Equal(
		t,
		[]string{"publicationSeq", "schemaVersion", "snapshotCid", "vault"},
		sortedStrings(head.Defs["main"].Record.Required),
	)
	assert.Equal(
		t,
		[]string{"parent", "publicationId", "publicationSeq", "schemaVersion", "segments", "vault"},
		sortedPropertyKeys(snapshot.Defs["main"].Record.Properties),
	)
	assert.Equal(
		t,
		[]string{"publicationSeq", "schemaVersion", "snapshotCid", "vault"},
		sortedPropertyKeys(head.Defs["main"].Record.Properties),
	)
	for _, document := range []lexiconFile{snapshot, head} {
		props := document.Defs["main"].Record.Properties
		assert.Equal(t, map[string]any{"type": "integer", "const": float64(2)}, props["schemaVersion"])
		assert.Equal(
			t,
			map[string]any{"type": "bytes", "minLength": float64(32), "maxLength": float64(32)},
			props["vault"],
		)
		assert.Equal(
			t,
			map[string]any{"type": "integer", "minimum": float64(0), "maximum": float64(MaxSequence)},
			props["publicationSeq"],
		)
	}
	assert.Equal(
		t,
		map[string]any{"type": "bytes", "minLength": float64(16), "maxLength": float64(16)},
		snapshot.Defs["main"].Record.Properties["publicationId"],
	)
	assert.Equal(
		t,
		map[string]any{"type": "bytes", "maxLength": float64(MaxCIDBytes)},
		snapshot.Defs["main"].Record.Properties["parent"],
	)
	segmentsProperty := snapshot.Defs["main"].Record.Properties["segments"]
	assert.Equal(t, "array", segmentsProperty["type"])
	assert.InDelta(t, float64(1), segmentsProperty["minLength"], 0)
	assert.InDelta(t, float64(MaxSnapshotSettings), segmentsProperty["maxLength"], 0)
	segmentItems, ok := segmentsProperty["items"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "object", segmentItems["type"])
	assert.Equal(t, []any{"target", "form"}, segmentItems["required"])
	segmentProperties, ok := segmentItems["properties"].(map[string]any)
	require.True(t, ok)
	assert.Equal(
		t,
		map[string]any{"type": "string", "enum": []any{"entries", "settings", "packed"}},
		segmentProperties["form"],
	)
	formTarget, ok := segmentProperties["target"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{"id", "source", "source_version"}, formTarget["required"])
	targetProperties, ok := formTarget["properties"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"type": "string", "maxLength": float64(128)}, targetProperties["id"])
	assert.Equal(t, map[string]any{"type": "string", "enum": []any{"files", "gnome"}}, targetProperties["source"])
	assert.Equal(t, map[string]any{"type": "integer", "const": float64(1)}, targetProperties["source_version"])
	rootProperty, ok := targetProperties["root"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{"base", "path", "kind"}, rootProperty["required"])
	rootProperties, ok := rootProperty["properties"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"type": "string", "enum": []any{"home", "xdg-config"}}, rootProperties["base"])
	assert.Equal(t, map[string]any{"type": "string", "maxLength": float64(4096)}, rootProperties["path"])
	assert.Equal(t, map[string]any{"type": "string", "enum": []any{"file", "directory"}}, rootProperties["kind"])
	entriesProperty := segmentProperties["entries"]
	entriesItems, ok := entriesProperty.(map[string]any)["items"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{"path", "mode", "size", "kind", "blob"}, entriesItems["required"])
	entryProperties, ok := entriesItems["properties"].(map[string]any)
	require.True(t, ok)
	assert.Equal(
		t,
		map[string]any{
			"type":    "blob",
			"accept":  []any{BlobMIMEType, SnapshotBlobMIMEType},
			"maxSize": float64(MaxBlobBytes),
		},
		entryProperties["blob"],
	)
	packedBlob, ok := segmentProperties["blob"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{SnapshotBlobMIMEType}, packedBlob["accept"])
	assert.Equal(t, float64(MaxBlobBytes), packedBlob["maxSize"])
	assert.Equal(
		t,
		map[string]any{"type": "bytes", "minLength": float64(1), "maxLength": float64(MaxCIDBytes)},
		head.Defs["main"].Record.Properties["snapshotCid"],
	)
	assert.NotContains(t, strings.ToLower(string(mustReadFile(t, paths))), "example.")
}

func FuzzDecodeSnapshotZeroOnError(f *testing.F) {
	valid, err := EncodeSnapshot(fixtureSnapshotValue(f))
	require.NoError(f, err)
	f.Add(valid)
	f.Add([]byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeSnapshot(data)
		if err != nil {
			require.Equal(t, SnapshotRecord{}, decoded)
			return
		}
		reencoded, err := EncodeSnapshot(decoded)
		require.NoError(t, err)
		require.Equal(t, data, reencoded)
	})
}

func FuzzDecodeHeadZeroOnError(f *testing.F) {
	valid, err := EncodeHead(HeadRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          fixtureVault(),
		PublicationSeq: 0,
		SnapshotCID:    independentCID(f, []byte("head fuzz snapshot"), cid.DagCBOR),
	})
	require.NoError(f, err)
	f.Add(valid)
	f.Add([]byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeHead(data)
		if err != nil {
			require.Equal(t, HeadRecord{}, decoded)
			return
		}
		reencoded, err := EncodeHead(decoded)
		require.NoError(t, err)
		require.Equal(t, data, reencoded)
	})
}

func fixtureSnapshotValue(t testing.TB) SnapshotRecord {
	t.Helper()
	payload := []byte("fixture payload")
	blobCID := independentCID(t, payload, cid.Raw)
	return SnapshotRecord{
		SchemaVersion: SchemaVersion,
		Vault:         fixtureVault(),
		PublicationID: fixturePublicationID(),
		Segments: []SnapshotSegment{{
			Target: fixturePackedTarget(),
			Form:   SegmentFormPacked,
			Blob:   BlobReference{CID: blobCID, Size: uint64(len(payload)), MIMEType: SnapshotBlobMIMEType},
		}},
	}
}

func fixturePackedTarget() model.Target {
	return model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "dotfiles", Kind: model.SelectionDirectory},
	}
}

func fixtureSnapshot(
	t testing.TB,
	payload []byte,
	sequence uint64,
	parent []byte,
	publicationByte byte,
) (SnapshotRecord, []byte) {
	t.Helper()
	blobCID := independentCID(t, payload, cid.Raw)
	record := SnapshotRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          fixtureVault(),
		PublicationID:  fixturePublicationID(),
		PublicationSeq: sequence,
		Parent:         bytes.Clone(parent),
		Segments: []SnapshotSegment{{
			Target: fixturePackedTarget(),
			Form:   SegmentFormPacked,
			Blob:   BlobReference{CID: blobCID, Size: uint64(len(payload)), MIMEType: SnapshotBlobMIMEType},
		}},
	}
	record.PublicationID[15] = publicationByte
	encoded, err := EncodeSnapshot(record)
	require.NoError(t, err)
	return record, encoded
}

func fixtureVault() [32]byte {
	var value [32]byte
	for index := range value {
		value[index] = byte(index + 1)
	}
	return value
}

func fixturePublicationID() [16]byte {
	var value [16]byte
	for index := range value {
		value[index] = byte(0xa0 + index)
	}
	return value
}

func independentSnapshotBytes(t testing.TB, record SnapshotRecord) []byte {
	t.Helper()
	return testCBOR(independentSnapshotValue(t, record))
}

func independentHeadBytes(t testing.TB, record HeadRecord) []byte {
	t.Helper()
	snapshotCID, err := cid.Cast(record.SnapshotCID)
	require.NoError(t, err)
	data, err := atdata.MarshalCBOR(map[string]any{
		"$type": HeadNSID, "schemaVersion": SchemaVersion, "vault": bytes.Clone(record.Vault[:]),
		"publicationSeq": int64(record.PublicationSeq), "snapshotCid": snapshotCID.Bytes(),
	})
	require.NoError(t, err)
	return data
}

func independentCID(t testing.TB, data []byte, codec uint64) []byte {
	t.Helper()
	prefix := cid.NewPrefixV1(codec, multihash.SHA2_256)
	identifier, err := prefix.Sum(data)
	require.NoError(t, err)
	return identifier.Bytes()
}

func independentCIDWithPrefix(t testing.TB, data []byte, codec, hashType uint64, hashLength int) []byte {
	t.Helper()
	prefix := cid.Prefix{Version: 1, Codec: codec, MhType: hashType, MhLength: hashLength}
	identifier, err := prefix.Sum(data)
	require.NoError(t, err)
	return identifier.Bytes()
}

func independentCIDV0(t testing.TB, data []byte) []byte {
	t.Helper()
	hash, err := multihash.Sum(data, multihash.SHA2_256, -1)
	require.NoError(t, err)
	return cid.NewCidV0(hash).Bytes()
}

func mustHash(t testing.TB, data []byte) multihash.Multihash {
	t.Helper()
	hash, err := multihash.Sum(data, multihash.SHA2_256, 32)
	require.NoError(t, err)
	return hash
}

func requireViolation(t testing.TB, err, sentinel error, field, reason string) {
	t.Helper()
	require.ErrorIs(t, err, sentinel)
	var actual *ViolationError
	require.ErrorAs(t, err, &actual)
	assert.Equal(t, field, actual.Field())
	assert.Equal(t, reason, actual.Reason())
}

func independentRecordMutation(t testing.TB, source map[string]any, mutate func(map[string]any)) []byte {
	t.Helper()
	value := cloneTestMap(source)
	mutate(value)
	return testCBOR(value)
}

func independentSnapshotValue(t testing.TB, record SnapshotRecord) map[string]any {
	t.Helper()
	parent := bytes.Clone(record.Parent)
	if parent == nil {
		parent = []byte{}
	}
	segments := make([]any, 0, len(record.Segments))
	for _, segment := range record.Segments {
		segments = append(segments, independentSegmentValue(t, segment))
	}
	return map[string]any{
		"$type": SnapshotNSID, "schemaVersion": SchemaVersion, "vault": bytes.Clone(record.Vault[:]),
		"publicationId": bytes.Clone(record.PublicationID[:]), "publicationSeq": int64(record.PublicationSeq),
		"parent": parent, "segments": segments,
	}
}

func independentSegmentValue(t testing.TB, segment SnapshotSegment) map[string]any {
	t.Helper()
	value := map[string]any{
		"target": independentTargetsValue([]model.Target{segment.Target})[0],
		"form":   string(segment.Form),
	}
	switch segment.Form {
	case SegmentFormEntries:
		value["entries"] = independentEntriesValue(t, segment.Entries)
	case SegmentFormPacked:
		ref, err := cid.Cast(segment.Blob.CID)
		require.NoError(t, err)
		value["blob"] = map[string]any{
			"$type": "blob", "ref": testTag{number: 42, value: append([]byte{0}, ref.Bytes()...)},
			"mimeType": segment.Blob.MIMEType, "size": int64(segment.Blob.Size),
		}
	case SegmentFormSettings:
		value["settings"] = independentSettingsValues(segment.Settings)
	}
	return value
}

func independentIndefiniteSnapshot(t testing.TB, value map[string]any) []byte {
	t.Helper()
	keys := sortedMapKeys(value)
	pairs := make(testCBORPairs, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, testPair{key: key, value: value[key]})
	}
	encoded := testCBOR(testIndefiniteMap{pairs: pairs})
	return encoded
}

func independentNonminimalSnapshot(t testing.TB, value map[string]any) []byte {
	t.Helper()
	canonical := testCBOR(value)
	require.NotEmpty(t, canonical)
	require.Equal(t, byte(0xa7), canonical[0])
	return append([]byte{0xb8, 0x07}, canonical[1:]...)
}

func independentUndefinedSequence(t testing.TB, source map[string]any) []byte {
	t.Helper()
	value := cloneTestMap(source)
	value["publicationSeq"] = testUndefined{}
	return testCBOR(value)
}

func independentDuplicateSnapshotField(t testing.TB, value map[string]any, key string, duplicate any) []byte {
	t.Helper()
	pairs := make(testCBORPairs, 0, len(value)+1)
	for name, item := range value {
		pairs = append(pairs, testPair{key: name, value: item})
	}
	pairs = append(pairs, testPair{key: key, value: duplicate})
	return testCBOR(pairs)
}

func independentDuplicateNestedBlobField(t testing.TB, value map[string]any) []byte {
	t.Helper()
	pairs := make(testCBORPairs, 0, len(value))
	for key, item := range value {
		if key != "segments" {
			pairs = append(pairs, testPair{key: key, value: item})
			continue
		}
		list := item.([]any)
		segments := make([]any, 0, len(list))
		for index, raw := range list {
			segment := raw.(map[string]any)
			if index != 0 {
				segments = append(segments, segment)
				continue
			}
			segmentPairs := make(testCBORPairs, 0, len(segment))
			for segmentKey, segmentValue := range segment {
				if segmentKey != "blob" {
					segmentPairs = append(segmentPairs, testPair{key: segmentKey, value: segmentValue})
					continue
				}
				blob := segmentValue.(map[string]any)
				nested := make(testCBORPairs, 0, len(blob)+1)
				for nestedKey, nestedValue := range blob {
					nested = append(nested, testPair{key: nestedKey, value: nestedValue})
				}
				nested = append(nested, testPair{key: "size", value: int64(len("fixture payload"))})
				segmentPairs = append(segmentPairs, testPair{key: "blob", value: nested})
			}
			segments = append(segments, segmentPairs)
		}
		pairs = append(pairs, testPair{key: "segments", value: segments})
	}
	return testCBOR(pairs)
}

func cloneTestMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		if nested, ok := value.(map[string]any); ok {
			result[key] = cloneTestMap(nested)
		} else if list, ok := value.([]any); ok {
			cloned := make([]any, len(list))
			for index, item := range list {
				if nested, ok := item.(map[string]any); ok {
					cloned[index] = cloneTestMap(nested)
				} else {
					cloned[index] = item
				}
			}
			result[key] = cloned
		} else if data, ok := value.([]byte); ok {
			result[key] = bytes.Clone(data)
		} else if tag, ok := value.(testTag); ok {
			tagBytes, _ := tag.value.([]byte)
			tag.value = bytes.Clone(tagBytes)
			result[key] = tag
		} else {
			result[key] = value
		}
	}
	return result
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func sortedMapKeys(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedPropertyKeys(values map[string]map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func mustReadFile(t testing.TB, paths []string) []byte {
	t.Helper()
	var combined []byte
	for _, path := range paths {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		combined = append(combined, data...)
	}
	return combined
}

type testTag struct {
	number uint64
	value  any
}

type testUndefined struct{}

type testPair struct {
	key   string
	value any
}

type testCBORPairs []testPair

type testIndefiniteMap struct {
	pairs testCBORPairs
}

func testCBOR(value any) []byte {
	switch item := value.(type) {
	case string:
		return testCBORText(item)
	case []byte:
		return append(testCBORHead(2, uint64(len(item))), item...)
	case int64:
		if item >= 0 {
			return testCBORHead(0, uint64(item))
		}
		return testCBORHead(1, uint64(-1-item))
	case int:
		return testCBOR(int64(item))
	case uint64:
		return testCBORHead(0, item)
	case float64:
		encoded := []byte{0xfb}
		return append(
			encoded,
			byte(math.Float64bits(item)>>56),
			byte(math.Float64bits(item)>>48),
			byte(math.Float64bits(item)>>40),
			byte(math.Float64bits(item)>>32),
			byte(math.Float64bits(item)>>24),
			byte(math.Float64bits(item)>>16),
			byte(math.Float64bits(item)>>8),
			byte(math.Float64bits(item)),
		)
	case bool:
		if item {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case nil:
		return []byte{0xf6}
	case testUndefined:
		return []byte{0xf7}
	case testTag:
		return append(testCBORHead(6, item.number), testCBOR(item.value)...)
	case []any:
		encoded := testCBORHead(4, uint64(len(item)))
		for _, nested := range item {
			encoded = append(encoded, testCBOR(nested)...)
		}
		return encoded
	case map[string]any:
		pairs := make(testCBORPairs, 0, len(item))
		for key, nested := range item {
			pairs = append(pairs, testPair{key: key, value: nested})
		}
		return testCBOR(pairs)
	case testCBORPairs:
		return encodeTestCBORMap(item, false)
	case testIndefiniteMap:
		return encodeTestCBORMap(item.pairs, true)
	default:
		panic(fmt.Sprintf("unsupported test CBOR type %T", value))
	}
}

func encodeTestCBORMap(pairs testCBORPairs, indefinite bool) []byte {
	sort.SliceStable(pairs, func(left, right int) bool {
		leftKey := testCBORText(pairs[left].key)
		rightKey := testCBORText(pairs[right].key)
		if len(leftKey) != len(rightKey) {
			return len(leftKey) < len(rightKey)
		}
		return bytes.Compare(leftKey, rightKey) < 0
	})
	result := []byte{}
	if indefinite {
		result = append(result, 0xbf)
	} else {
		result = testCBORHead(5, uint64(len(pairs)))
	}
	for _, pair := range pairs {
		result = append(result, testCBORText(pair.key)...)
		result = append(result, testCBOR(pair.value)...)
	}
	if indefinite {
		result = append(result, 0xff)
	}
	return result
}

func testCBORText(value string) []byte {
	data := []byte(value)
	return append(testCBORHead(3, uint64(len(data))), data...)
}

func testCBORHead(major uint8, value uint64) []byte {
	prefix := major << 5
	switch {
	case value < 24:
		return []byte{prefix | byte(value)}
	case value <= math.MaxUint8:
		return []byte{prefix | 24, byte(value)}
	case value <= math.MaxUint16:
		return []byte{prefix | 25, byte(value >> 8), byte(value)}
	case value <= math.MaxUint32:
		return []byte{prefix | 26, byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	default:
		return []byte{
			prefix | 27,
			byte(value >> 56),
			byte(value >> 48),
			byte(value >> 40),
			byte(value >> 32),
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	}
}

func TestSnapshotRecordCarriesThePackedPayloadMediaType(t *testing.T) {
	payload := []byte("carried media type payload")
	snapshot, encoded := fixtureSnapshot(t, payload, 0, nil, 1)
	require.Equal(t, SnapshotBlobMIMEType, blobOf(snapshot).MIMEType)

	decoded, err := DecodeSnapshot(encoded)
	require.NoError(t, err)
	assert.Equal(t, snapshot, decoded)
	assert.Equal(t, SnapshotBlobMIMEType, blobOf(decoded).MIMEType)

	value, err := RecordToJSON(encoded)
	require.NoError(t, err)
	assert.Contains(t, string(value), `"mimeType":"`+SnapshotBlobMIMEType+`"`)
}

func TestSnapshotRecordRefusesAnUnsupportedPackedMediaType(t *testing.T) {
	payload := []byte("legacy media type payload")
	snapshot, _ := fixtureSnapshot(t, payload, 0, nil, 1)
	snapshot.Segments[0].Blob.MIMEType = BlobMIMEType
	encoded, err := EncodeSnapshot(snapshot)
	assert.Nil(t, encoded)
	requireViolation(t, err, ErrInvalidRecord, "segments.blob", "unsupported")
}
