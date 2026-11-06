package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodePayloadVerifiesReferenceBeforeInspectingBody(t *testing.T) {
	payload := []byte("malformed-body-reference-order-canary")
	cid, err := RawPayloadCID(payload)
	require.NoError(t, err)
	reference := BlobReference{CID: cid, Size: uint64(len(payload))}
	wrongCID := reference
	wrongCID.CID = bytes.Clone(reference.CID)
	wrongCID.CID[len(wrongCID.CID)-1] ^= 1
	wrongSize := reference
	wrongSize.Size++
	for _, test := range []struct {
		name   string
		ref    BlobReference
		field  string
		reason string
	}{
		{"wrong size", wrongSize, "blob.size", "mismatch"},
		{"wrong CID", wrongCID, "blob.ref", "mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodePayload(payload, test.ref)
			assert.Equal(t, model.Snapshot{}, got)
			requireViolation(t, err, ErrPayload, test.field, test.reason)
			var payloadErr *vault.PayloadError
			assert.False(t, errors.As(err, &payloadErr))
		})
	}

	var payloadErr *vault.PayloadError
	got, err := DecodePayload(payload, reference)
	assert.Equal(t, model.Snapshot{}, got)
	require.Error(t, err)
	require.ErrorAs(t, err, &payloadErr)
	assert.Equal(t, "inspect", payloadErr.Stage)
	assert.Equal(t, "malformed", payloadErr.Reason)
	assert.Empty(t, payloadErr.Kind)
	assert.NotContains(t, fmt.Sprint(err), "malformed-body-reference-order-canary")
}

func TestDecodePayloadValidWholeCIDStillChecksMemberDigestAndRedactsPath(t *testing.T) {
	path := "private/member-path-canary"
	content := []byte("private member body")
	blob, err := vault.Pack(model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: ".", Kind: model.SelectionDirectory}}},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: path, State: model.FilePresent, Kind: model.FileRegular, Content: content}}},
	})
	require.NoError(t, err)
	memberHash := sha256.Sum256(content)
	digest := []byte(hex.EncodeToString(memberHash[:]))
	mutated := bytes.Replace(bytes.Clone(blob.Payload), digest, bytes.Repeat([]byte("0"), len(digest)), 1)
	require.NotEqual(t, blob.Payload, mutated)
	cid, err := RawPayloadCID(mutated)
	require.NoError(t, err)

	got, err := DecodePayload(mutated, BlobReference{CID: cid, Size: uint64(len(mutated))})
	assert.Equal(t, model.Snapshot{}, got)
	var payloadErr *vault.PayloadError
	require.ErrorAs(t, err, &payloadErr)
	assert.Equal(t, "validate", payloadErr.Stage)
	assert.Equal(t, "malformed", payloadErr.Reason)
	assert.Empty(t, payloadErr.Kind)
	assert.ErrorIs(t, err, vault.ErrInvalidPayload)
	assert.NotContains(t, fmt.Sprint(err), path)
	assert.NotContains(t, fmt.Sprint(err), string(digest))
	assert.Nil(t, errors.Unwrap(errors.Unwrap(err)))
}

func TestPublicationAndVaultPackedPayloadCapsMatch(t *testing.T) {
	assert.Equal(t, uint64(vault.DefaultPayloadLimits().MaxPackedBytes), MaxBlobBytes)
}

func TestDecodePayloadUsesVerifiedRawSnapshotBytes(t *testing.T) {
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory}}},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("payload"), Mode: 0o600}}},
	}
	blob, err := vault.Pack(snapshot)
	require.NoError(t, err)
	cid, err := RawPayloadCID(blob.Payload)
	require.NoError(t, err)
	got, err := DecodePayload(blob.Payload, BlobReference{CID: cid, Size: uint64(len(blob.Payload))})
	require.NoError(t, err)
	assert.Equal(t, []byte("payload"), got.Entries[0].File.Content)
	assert.Equal(t, model.SnapshotVersion, got.Version)
}
