package integration

import (
	"bytes"
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
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	payload := packed.Payload
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

	unpacked, err := publication.DecodePayload(payload, snapshotRecord.Blob)
	require.NoError(t, err)
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

	wrongCID := snapshotRecord.Blob
	wrongCID.CID = bytes.Clone(wrongCID.CID)
	wrongCID.CID[len(wrongCID.CID)-1] ^= 1
	_, err = publication.DecodePayload(payload, wrongCID)
	require.ErrorIs(t, err, publication.ErrPayload)

	wrongSize := snapshotRecord.Blob
	wrongSize.Size++
	_, err = publication.DecodePayload(payload, wrongSize)
	require.ErrorIs(t, err, publication.ErrPayload)
}
