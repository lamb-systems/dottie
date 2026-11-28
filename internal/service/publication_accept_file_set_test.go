package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func fileSetServiceEntries(files []fileSetServiceFile) []publication.PayloadEntry {
	entries := make([]publication.PayloadEntry, 0, len(files))
	for _, file := range files {
		entries = append(entries, publication.PayloadEntry{
			Path:    file.path,
			Mode:    file.mode,
			Size:    uint64(len(file.content)),
			Content: file.content,
		})
	}
	return entries
}

func fileSetServiceFilesWithContent(t *testing.T, contents ...string) []fileSetServiceFile {
	t.Helper()
	files := make([]fileSetServiceFile, 0, len(contents))
	for index, content := range contents {
		files = append(files, fileSetServiceFile{
			path:    "synthetic/entry-" + string(rune('a'+index)) + ".lua",
			mode:    0o600,
			content: []byte(content),
		})
	}
	return files
}

func payloadServiceBasename(t *testing.T, content []byte) string {
	t.Helper()
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]) + ".payload"
}

func packedServiceBlock(
	t *testing.T,
	binding publicationstate.Binding,
	sequence uint64,
	parent []byte,
	payload []byte,
) publicationstate.SnapshotBlock {
	t.Helper()
	blobCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: sequence,
		Parent:         parent,
		Segments: []publication.SnapshotSegment{{
			Target: fileSetServiceTargets()[0], Form: publication.SegmentFormPacked,
			Blob: publication.BlobReference{
				CID: blobCID, Size: uint64(len(payload)), MIMEType: publication.SnapshotBlobMIMEType,
			},
		}},
	}
	binary.BigEndian.PutUint64(record.PublicationID[8:], sequence+9)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return publicationstate.SnapshotBlock{Key: key, Raw: raw}
}

func publicationHead(
	t *testing.T,
	binding publicationstate.Binding,
	block publicationstate.SnapshotBlock,
) []byte {
	t.Helper()
	record, err := publication.DecodeSnapshot(block.Raw)
	require.NoError(t, err)
	headRecord := publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: record.PublicationSeq,
		SnapshotCID:    mustFileSetRecordCID(t, block.Raw),
	}
	head, err := publication.EncodeHead(headRecord)
	require.NoError(t, err)
	return head
}

func publicationAcceptMaterial(
	t *testing.T,
	directory string,
	binding publicationstate.Binding,
	floor publicationstate.Floor,
) publicationstate.AcceptedMaterial {
	t.Helper()
	ctx := context.Background()
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	material, err := store.ReadAcceptedMaterial(ctx, binding, floor)
	require.NoError(t, err)
	return material
}

func TestPublicationAcceptRoutesFileSetEntriesThroughMaterialIntake(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	files := fileSetServiceFiles()
	genesis := newSequencedFileSetServicePublication(t, fixture.binding.Vault, [16]byte{0x25, 0x74}, 0, nil, files...)
	observation := publicationstate.Observation{
		Origin: fixture.binding, SuppliedContext: fixture.context,
		Head: genesis.head, Snapshots: []publicationstate.SnapshotBlock{genesis.block},
	}

	proposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding,
		Observation: observation, Entries: fileSetServiceEntries(files),
	})
	require.NoError(t, err)
	assert.Equal(t, publicationstate.ModeFirstUse, proposal.Mode)
	assert.NotEqual(t, [32]byte{}, proposal.Confirmation)

	refused, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: proposal.Mode,
		StateToken: proposal.StateToken, Confirmation: [32]byte{0x01},
		Observation: observation, Entries: fileSetServiceEntries(files),
	})
	assert.Equal(t, publicationstate.Floor{}, refused)
	require.ErrorIs(t, err, ErrPublicationAccept)
	require.ErrorIs(t, err, publicationstate.ErrConsent)
	assertPublicationAcceptFailure(t, err, "accept-material", "material_refused")

	accepted, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: proposal.Mode,
		StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
		Observation: observation, Entries: fileSetServiceEntries(files),
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), accepted.Revision)
	require.NotEmpty(t, floorFileSet(accepted))
	require.Len(t, floorFileSet(accepted), len(files))

	material := publicationAcceptMaterial(t, fixture.directory, fixture.binding, accepted)
	require.Len(t, acceptedEntriesOf(material), len(files))
	for index, file := range files {
		assert.Equal(t, file.path, acceptedEntriesOf(material)[index].Path)
		assert.Equal(t, file.mode, acceptedEntriesOf(material)[index].Mode)
		assert.Equal(t, file.content, acceptedEntriesOf(material)[index].Content)
	}

	missing := fileSetServiceEntries(files)[:1]
	missingProposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: accepted.Revision,
		Observation: observation, Entries: missing,
	})
	assert.Equal(t, PublicationAcceptProposal{}, missingProposal)
	require.ErrorIs(t, err, ErrPublicationAccept)
	require.ErrorIs(t, err, publicationstate.ErrInvalid)
	assertPublicationAcceptFailure(t, err, "accept-prepare", "proposal_refused")

	successorFiles := fileSetServiceFilesWithContent(t, "synthetic successor alpha", "synthetic successor beta")
	successor := newSequencedFileSetServicePublication(
		t,
		fixture.binding.Vault,
		[16]byte{0x25, 0x74},
		1,
		mustFileSetRecordCID(t, genesis.raw),
		successorFiles...,
	)
	successorObservation := publicationstate.Observation{
		Origin: fixture.binding, SuppliedContext: fixture.context,
		Head: successor.head,
		Snapshots: []publicationstate.SnapshotBlock{
			genesis.block,
			successor.block,
		},
	}
	advance, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: accepted.Revision,
		Observation: successorObservation, Entries: fileSetServiceEntries(successorFiles),
	})
	require.NoError(t, err)
	assert.Equal(t, publicationstate.ModeAdvance, advance.Mode)
	assert.Equal(t, [32]byte{}, advance.Confirmation)

	advanced, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: advance.Mode,
		FloorRevision: accepted.Revision, StateToken: advance.StateToken,
		Confirmation: advance.Confirmation,
		Observation:  successorObservation, Entries: fileSetServiceEntries(successorFiles),
	})
	require.NoError(t, err)
	assert.Equal(t, accepted.Revision+1, advanced.Revision)
	assert.Equal(t, accepted.Generation, advanced.Generation)
	successorMaterial := publicationAcceptMaterial(t, fixture.directory, fixture.binding, advanced)
	require.Len(t, acceptedEntriesOf(successorMaterial), len(successorFiles))
	for index, file := range successorFiles {
		assert.Equal(t, file.path, acceptedEntriesOf(successorMaterial)[index].Path)
		assert.Equal(t, file.content, acceptedEntriesOf(successorMaterial)[index].Content)
	}
}

func TestPublicationAcceptFileSetRefusesDamagedCustody(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	files := fileSetServiceFilesWithContent(t, "synthetic custody file-set alpha", "synthetic custody file-set beta")
	genesis := newSequencedFileSetServicePublication(t, fixture.binding.Vault, [16]byte{0x25, 0x75}, 0, nil, files...)
	observation := publicationstate.Observation{
		Origin: fixture.binding, SuppliedContext: fixture.context,
		Head: genesis.head, Snapshots: []publicationstate.SnapshotBlock{genesis.block},
	}
	proposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding,
		Observation: observation, Entries: fileSetServiceEntries(files),
	})
	require.NoError(t, err)
	accepted, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: proposal.Mode,
		StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
		Observation: observation, Entries: fileSetServiceEntries(files),
	})
	require.NoError(t, err)
	require.NotEmpty(t, floorFileSet(accepted))

	require.NoError(t, os.Remove(filepath.Join(
		fixture.directory,
		"payloads",
		payloadServiceBasename(t, files[1].content),
	)))
	replay, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: accepted.Revision,
		Observation: observation, Entries: fileSetServiceEntries(files),
	})
	require.NoError(t, err)
	assert.Equal(t, publicationstate.ModeAdvance, replay.Mode)
	floor, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: replay.Mode,
		FloorRevision: accepted.Revision, StateToken: replay.StateToken,
		Confirmation: replay.Confirmation,
		Observation:  observation, Entries: fileSetServiceEntries(files),
	})
	assert.Equal(t, publicationstate.Floor{}, floor)
	require.ErrorIs(t, err, ErrPublicationAccept)
	require.ErrorIs(t, err, publicationstate.ErrStorage)
	assertPublicationAcceptFailure(t, err, "accept-material", "material_refused")
}

func TestPublicationAcceptSelectsTheFormFromTheVerifiedHead(t *testing.T) {
	t.Run("head file-set with a later packed snapshot", func(t *testing.T) {
		fixture := newPublicationAcceptFixture(t)
		files := fileSetServiceFilesWithContent(t, "synthetic head file-set entry")
		genesis := newSequencedFileSetServicePublication(
			t,
			fixture.binding.Vault,
			[16]byte{0x25, 0x76},
			0,
			nil,
			files...)
		sibling := packedServiceBlock(
			t,
			fixture.binding,
			1,
			mustFileSetRecordCID(t, genesis.raw),
			[]byte("synthetic trailing packed sibling"),
		)
		observation := publicationstate.Observation{
			Origin: fixture.binding, SuppliedContext: fixture.context,
			Head:      genesis.head,
			Snapshots: []publicationstate.SnapshotBlock{genesis.block, sibling},
		}
		proposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
			Directory: fixture.directory, Binding: fixture.binding,
			Observation: observation, Entries: fileSetServiceEntries(files),
		})
		require.NoError(t, err)
		assert.Equal(t, publicationstate.ModeFirstUse, proposal.Mode)
		accepted, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
			Directory: fixture.directory, Binding: fixture.binding, Mode: proposal.Mode,
			StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
			Observation: observation, Entries: fileSetServiceEntries(files),
		})
		require.NoError(t, err)
		require.NotEmpty(t, floorFileSet(accepted))
		require.Len(t, floorFileSet(accepted), 1)
	})

	t.Run("head packed with a later file-set snapshot", func(t *testing.T) {
		fixture := newPublicationAcceptFixture(t)
		packed := fixture.append(t, "synthetic head packed payload")
		followerFiles := fileSetServiceFilesWithContent(t, "synthetic trailing file-set sibling")
		follower := newSequencedFileSetServicePublication(
			t,
			fixture.binding.Vault,
			[16]byte{0x25, 0x77},
			1,
			mustFileSetRecordCID(t, packed.block.Raw),
			followerFiles...,
		)
		head := publicationHead(t, fixture.binding, packed.block)
		observation := publicationstate.Observation{
			Origin: fixture.binding, SuppliedContext: fixture.context,
			Head:      head,
			Snapshots: []publicationstate.SnapshotBlock{packed.block, follower.block},
		}
		proposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
			Directory: fixture.directory, Binding: fixture.binding,
			Observation: observation, Payload: packed.payload,
		})
		require.NoError(t, err)
		assert.Equal(t, publicationstate.ModeFirstUse, proposal.Mode)
		accepted, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
			Directory: fixture.directory, Binding: fixture.binding, Mode: proposal.Mode,
			StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
			Observation: observation, Payload: packed.payload,
		})
		require.NoError(t, err)
		assert.Nil(t, floorFileSet(accepted))
		assert.Equal(
			t,
			packed.block.Raw,
			publicationAcceptMaterial(t, fixture.directory, fixture.binding, accepted).SnapshotRecord,
		)
	})
}
