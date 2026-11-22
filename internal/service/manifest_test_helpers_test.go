package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

type manifestServiceFile struct {
	path    string
	mode    uint32
	content []byte
}

type manifestServicePublication struct {
	document publication.SnapshotRecord
	raw      []byte
	block    publicationstate.SnapshotBlock
	head     []byte
}

func newManifestServicePublication(
	t *testing.T,
	vault [32]byte,
	publicationID [16]byte,
	files ...manifestServiceFile,
) manifestServicePublication {
	t.Helper()
	return newSequencedManifestServicePublication(t, vault, publicationID, 0, nil, files...)
}

func newSequencedManifestServicePublication(
	t *testing.T,
	vault [32]byte,
	publicationID [16]byte,
	sequence uint64,
	parent []byte,
	files ...manifestServiceFile,
) manifestServicePublication {
	t.Helper()
	entries := make([]publication.SnapshotEntry, 0, len(files))
	for _, file := range files {
		blobCID, err := publication.RawPayloadCID(file.content)
		require.NoError(t, err)
		entries = append(entries, publication.SnapshotEntry{
			Path: file.path, Mode: file.mode, Size: uint64(len(file.content)),
			Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{
				CID: blobCID, Size: uint64(len(file.content)), MIMEType: publication.BlobMIMEType,
			},
		})
	}
	document := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: vault, PublicationID: publicationID,
		PublicationSeq: sequence, Parent: parent,
		Entries: entries,
	}
	raw, err := publication.EncodeSnapshot(document)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: vault,
		PublicationSeq: sequence, SnapshotCID: mustManifestRecordCID(t, raw),
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return manifestServicePublication{
		document: document, raw: raw,
		block: publicationstate.SnapshotBlock{Key: key, Raw: raw}, head: head,
	}
}

func manifestServiceFiles() []manifestServiceFile {
	return []manifestServiceFile{
		{path: "init.lua", mode: 0o600, content: []byte("synthetic manifest init")},
		{path: "lua/config/options.lua", mode: 0o644, content: []byte("synthetic manifest options")},
	}
}

func mustManifestRecordCID(t *testing.T, raw []byte) []byte {
	t.Helper()
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	return cid
}
