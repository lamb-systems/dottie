package atprototest

import (
	"bytes"
	"context"
	"testing"

	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/ipld/go-car"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSignedRevisionUsesRepositoryCommitAndCARPrimitives(t *testing.T) {
	key, err := NewSigningKey()
	require.NoError(t, err)
	record, err := BuildRecord("systems.example.preferences", "self", map[string]any{"value": "synthetic"})
	require.NoError(t, err)
	revision, err := BuildSignedRevision("did:plc:abcdefghijklmnopqrstuvwx", key, []Record{record})
	require.NoError(t, err)

	commit, loaded, err := repo.LoadRepoFromCAR(context.Background(), bytes.NewReader(revision.CAR))
	require.NoError(t, err)
	assert.Equal(t, revision.DID, loaded.DID.String())
	carReader, err := car.NewCarReader(bytes.NewReader(revision.CAR))
	require.NoError(t, err)
	require.Len(t, carReader.Header.Roots, 1)
	assert.Equal(t, revision.CommitCID, carReader.Header.Roots[0])
	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	assert.NoError(t, commit.VerifySignature(publicKey))
	assert.Equal(t, revision.DID+"#atproto", revision.VerificationMethod.ID)
	assert.Equal(t, publicKey.Multibase(), revision.VerificationMethod.PublicKeyMultibase)
	assert.Equal(t, []Record{record}, revision.Records)
	repeated, err := BuildSignedRevision(revision.DID, key, []Record{record})
	require.NoError(t, err)
	assert.Equal(t, revision.CommitCID, repeated.CommitCID)
	assert.Equal(t, revision.CAR, repeated.CAR)
}

func TestBuildBlobUsesRawCIDAndCopiesBytes(t *testing.T) {
	content := []byte("synthetic ciphertext")
	blob, err := BuildBlob(content)
	require.NoError(t, err)
	content[0] ^= 0xff
	assert.Equal(t, "application/octet-stream", blob.Reference.MimeType)
	assert.Equal(t, int64(len("synthetic ciphertext")), blob.Reference.Size)
	assert.Equal(t, "synthetic ciphertext", string(blob.Data))
	assert.Equal(t, blob.CID, blob.Reference.Ref.CID())
}
