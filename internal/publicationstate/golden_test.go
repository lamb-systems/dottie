package publicationstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStrictPrivateJSONRejectsDuplicateUnknownTrailingAndArrayBinary(t *testing.T) {
	wire := bindingToWire(
		Binding{
			AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
			Backend:    BackendPublicRepo,
			Repository: "at://did:plc:abcdefghijklmnopqrstuvwx",
			Vault:      [32]byte{1},
		},
	)
	encoded, err := canonicalJSON(wire)
	require.NoError(t, err)
	var decoded bindingWire
	require.NoError(t, strictJSON(encoded, &decoded))
	for _, invalid := range [][]byte{
		[]byte(strings.Replace(string(encoded), `"backend":"public-repo"`, `"backend":"public-repo","backend":"spaces"`, 1)),
		[]byte(strings.TrimSuffix(string(encoded), `}`) + `,"extension":true}`),
		append(bytes.Clone(encoded), []byte(` {}`)...),
		[]byte(strings.Replace(string(encoded), `"vault":"`, `"vault":[`, 1)),
	} {
		assert.Error(t, strictJSON(invalid, &decoded))
	}
}

func TestSuppliedSetFramingBindsCountAndLengths(t *testing.T) {
	blocks := []SnapshotBlock{{Key: "0000000000000000", Raw: []byte{1}}, {Key: "0000000000000001", Raw: []byte{2, 3}}}
	framed := makeSetDigest(blocks)
	independentlyFramed := independentSetDigest(blocks)
	assert.Equal(t, independentlyFramed, framed)
	ambiguousPartition := []SnapshotBlock{
		{Key: "0000000000000000", Raw: []byte{1, 2}},
		{Key: "0000000000000001", Raw: []byte{3}},
	}
	assert.NotEqual(t, framed, makeSetDigest(ambiguousPartition))
	assert.NotEqual(t, framed, makeSetDigest(blocks[:1]))
}

func independentSetDigest(blocks []SnapshotBlock) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("systems.lamb.dottie.local-record-set.v1"))
	hash.Write([]byte{0})
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(blocks)))
	hash.Write(count[:])
	for _, block := range blocks {
		hash.Write([]byte(block.Key))
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(block.Raw)))
		hash.Write(length[:])
		hash.Write(block.Raw)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}
