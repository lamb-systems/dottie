package matrix

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeySetDigestSortsAndLengthDelimitsReferences(t *testing.T) {
	keys := []KeyRef{
		{SchemaID: "org.example.schema", Path: "/nested/", Key: "second"},
		{SchemaID: "org.example.schema", Path: "/", Key: "first"},
	}
	digest, err := KeySetDigest(keys)
	require.NoError(t, err)
	reordered, err := KeySetDigest([]KeyRef{keys[1], keys[0]})
	require.NoError(t, err)
	assert.Equal(t, digest, reordered)
	assert.Equal(t, "23cdcf6a0085ec39fe402838ce365f8e9c69159735ed8641426960b54c2a5e4a", hex.EncodeToString(digest[:]))

	combined, err := KeySetDigest([]KeyRef{{SchemaID: "org.example", Path: "/a/", Key: "bc"}})
	require.NoError(t, err)
	separate, err := KeySetDigest([]KeyRef{{SchemaID: "org.example", Path: "/ab/", Key: "c"}})
	require.NoError(t, err)
	assert.NotEqual(t, combined, separate)
}

func TestKeySetDigestRejectsEmptyInvalidAndDuplicateReferences(t *testing.T) {
	for _, keys := range [][]KeyRef{
		nil,
		{{SchemaID: "org.example", Path: "relative", Key: "key"}},
		{{SchemaID: "org.example", Path: "/", Key: "key"}, {SchemaID: "org.example", Path: "/", Key: "key"}},
	} {
		_, err := KeySetDigest(keys)
		assert.Error(t, err)
	}
}
