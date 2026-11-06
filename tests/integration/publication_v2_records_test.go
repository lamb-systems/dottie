package integration

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV2PublicationRecordsComposeWithPackAndFetchedPayloadUnpack(t *testing.T) {
	fileContent := []byte("synthetic editor configuration\n")
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{
			{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory}},
			{ID: "settings", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
		},
		Entries: []model.Entry{
			{TargetID: "files", File: &model.FileEntry{Path: "editor/init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: bytes.Clone(fileContent), Mode: 0o600}},
			{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "color-scheme", State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'prefer-dark'"}}},
		},
	}
	payload, err := packSnapshotPayloadOnly(snapshot)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	payloadCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	var vaultID [32]byte
	vaultID[0] = 0x41
	var publicationID [16]byte
	publicationID[0] = 0x72
	snapshotRecord := publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          vaultID,
		PublicationID:  publicationID,
		PublicationSeq: 0,
		Parent:         []byte{},
		Blob:           publication.BlobReference{CID: payloadCID, Size: uint64(len(payload))},
	}
	snapshotBytes, err := publication.EncodeSnapshot(snapshotRecord)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(snapshotBytes)
	require.NoError(t, err)
	headBytes, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          vaultID,
		PublicationSeq: 0,
		SnapshotCID:    recordCID,
		BlobCID:        payloadCID,
	})
	require.NoError(t, err)
	require.NoError(t, publication.VerifyHeadBinding(headBytes, snapshotBytes, "0000000000000000"))
	require.NoError(t, publication.VerifyPayload(payload, snapshotRecord.Blob))

	inspections := 0
	unpacked, err := unpackFetchedPublicationPayload(payload, snapshotRecord.Blob, func(data []byte) (vault.Blob, error) {
		inspections++
		return inspectPackedPayloadMetadata(data)
	})
	require.NoError(t, err)
	assert.Equal(t, 1, inspections)
	foundFile := false
	foundSetting := false
	for _, entry := range unpacked.Entries {
		if entry.File != nil && entry.File.Path == "editor/init.lua" {
			foundFile = true
			assert.Equal(t, fileContent, entry.File.Content)
			assert.Equal(t, model.FilePresent, entry.File.State)
		}
		if entry.Setting != nil && entry.Setting.SchemaID == "org.gnome.desktop.interface" && entry.Setting.Key == "color-scheme" {
			foundSetting = true
			assert.Equal(t, model.SettingPresent, entry.Setting.State)
			assert.Equal(t, &model.VariantValue{Type: "s", Text: "'prefer-dark'"}, entry.Setting.Value)
		}
	}
	assert.True(t, foundFile)
	assert.True(t, foundSetting)

	inspections = 0
	wrongCID := snapshotRecord.Blob
	wrongCID.CID = bytes.Clone(wrongCID.CID)
	wrongCID.CID[len(wrongCID.CID)-1] ^= 1
	_, err = unpackFetchedPublicationPayload(payload, wrongCID, func(data []byte) (vault.Blob, error) {
		inspections++
		return inspectPackedPayloadMetadata(data)
	})
	require.ErrorIs(t, err, publication.ErrPayload)
	assert.Equal(t, 0, inspections)

	wrongSize := snapshotRecord.Blob
	wrongSize.Size++
	_, err = unpackFetchedPublicationPayload(payload, wrongSize, func(data []byte) (vault.Blob, error) {
		inspections++
		return inspectPackedPayloadMetadata(data)
	})
	require.ErrorIs(t, err, publication.ErrPayload)
	assert.Equal(t, 0, inspections)
}

func packSnapshotPayloadOnly(snapshot model.Snapshot) ([]byte, error) {
	packed, err := vault.Pack(snapshot)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(packed.Payload), nil
}

func unpackFetchedPublicationPayload(payload []byte, reference publication.BlobReference, inspect func([]byte) (vault.Blob, error)) (model.Snapshot, error) {
	if err := publication.VerifyPayload(payload, reference); err != nil {
		return model.Snapshot{}, err
	}
	blob, err := inspect(payload)
	if err != nil {
		return model.Snapshot{}, err
	}
	return vault.UnpackWithLimits(blob, vault.DefaultLimits())
}

func inspectPackedPayloadMetadata(payload []byte) (vault.Blob, error) {
	limits := vault.DefaultLimits()
	if len(payload) == 0 || uint64(len(payload)) > publication.MaxBlobBytes {
		return vault.Blob{}, errors.New("test payload size out of range")
	}
	reader := bytes.NewReader(payload)
	archive := tar.NewReader(reader)
	header, err := archive.Next()
	if err != nil {
		return vault.Blob{}, errors.New("test payload manifest header unavailable")
	}
	if header.Name != "000000" || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > limits.MaxManifestBytes {
		return vault.Blob{}, errors.New("test payload manifest header invalid")
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(archive, limits.MaxManifestBytes+1))
	if err != nil || int64(len(manifestBytes)) != header.Size || int64(len(manifestBytes)) > limits.MaxManifestBytes {
		return vault.Blob{}, errors.New("test payload manifest size invalid")
	}
	var manifest struct {
		Version uint32 `json:"version"`
		Codec   string `json:"codec"`
		Entries []struct {
			Source model.SourceKind `json:"source"`
			State  string           `json:"state"`
			Kind   model.FileKind   `json:"kind"`
			Size   int64            `json:"size"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return vault.Blob{}, errors.New("test payload manifest invalid")
	}
	if manifest.Version != vault.Version || manifest.Codec != vault.CodecNone || len(manifest.Entries) > limits.MaxEntries {
		return vault.Blob{}, errors.New("test payload manifest profile invalid")
	}
	var plaintextBytes int64
	for _, entry := range manifest.Entries {
		if entry.Size < 0 {
			return vault.Blob{}, errors.New("test payload manifest entry size invalid")
		}
		if entry.Source == model.SourceFiles && entry.State == string(model.FilePresent) && entry.Kind == model.FileRegular {
			if entry.Size > int64(^uint64(0)>>1)-plaintextBytes {
				return vault.Blob{}, errors.New("test payload plaintext size overflow")
			}
			plaintextBytes += entry.Size
		}
	}
	return vault.Blob{
		Version:        vault.Version,
		Codec:          vault.CodecNone,
		Payload:        bytes.Clone(payload),
		Digest:         sha256.Sum256(payload),
		EntryCount:     len(manifest.Entries),
		PlaintextBytes: plaintextBytes,
	}, nil
}
