package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

type showcaseServiceFile struct {
	path    string
	mode    uint32
	content []byte
}

type showcaseServicePublication struct {
	document publication.SnapshotRecord
	raw      []byte
	block    publicationstate.SnapshotBlock
	head     []byte
}

func newShowcaseServicePublication(
	t *testing.T,
	vault [32]byte,
	publicationID [16]byte,
	files ...showcaseServiceFile,
) showcaseServicePublication {
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
		Entries: entries,
	}
	raw, err := publication.EncodeSnapshot(document)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: vault,
		SnapshotCID: mustShowcaseRecordCID(t, raw),
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	return showcaseServicePublication{
		document: document, raw: raw,
		block: publicationstate.SnapshotBlock{Key: key, Raw: raw}, head: head,
	}
}

func showcaseServiceFiles() []showcaseServiceFile {
	return []showcaseServiceFile{
		{path: "init.lua", mode: 0o600, content: []byte("synthetic showcase init")},
		{path: "lua/config/options.lua", mode: 0o644, content: []byte("synthetic showcase options")},
	}
}

func showcaseServiceObservation(
	t *testing.T,
	binding publicationstate.Binding,
	context publicationstate.SuppliedContext,
) publicationstate.Observation {
	t.Helper()
	showcase := newShowcaseServicePublication(t, binding.Vault, [16]byte{0x25, 0x72}, showcaseServiceFiles()...)
	return publicationstate.Observation{
		Origin: binding, SuppliedContext: context, Head: showcase.head,
		Snapshots: []publicationstate.SnapshotBlock{showcase.block},
	}
}

func mustShowcaseRecordCID(t *testing.T, raw []byte) []byte {
	t.Helper()
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	return cid
}

func requireShowcaseRefusal(t *testing.T, err error, want error) {
	t.Helper()
	require.ErrorIs(t, err, want)
	require.ErrorIs(t, err, publication.ErrShowcasePayload)
	var refusal *publication.ShowcasePayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, publication.ShowcaseReasonPackedRequired, refusal.Reason)
}

func TestStagePublicationAcceptRefusesAShowcaseObservation(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	observation := showcaseServiceObservation(t, fixture.binding, fixture.context)

	proposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding,
		Observation: observation, Payload: []byte("packed payload for a showcase observation"),
	})
	assert.Equal(t, PublicationAcceptProposal{}, proposal)
	requireShowcaseRefusal(t, err, ErrPublicationAccept)
	assertPublicationAcceptFailure(t, err, "accept-input", "payload_form")
}

func TestAcceptPublicationRefusesAShowcaseObservation(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	observation := showcaseServiceObservation(t, fixture.binding, fixture.context)

	floor, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: publicationstate.ModeFirstUse,
		Observation: observation, Payload: []byte("packed payload for a showcase observation"),
	})
	assert.Equal(t, publicationstate.Floor{}, floor)
	requireShowcaseRefusal(t, err, ErrPublicationAccept)
	assertPublicationAcceptFailure(t, err, "accept-input", "payload_form")
}

func TestPreparePublicationPushRefusesAShowcaseAcceptedPublication(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationPushFixture(t)
	fixture.reader.setPayload(publication.Payload{
		Form: publication.PayloadFormShowcase,
		Entries: []publication.PayloadEntry{{
			Path: "init.lua", Mode: 0o600, Size: 20, Content: []byte("synthetic showcase init"),
		}},
	})

	preparation, err := fixture.coordinator.PreparePublicationPush(
		ctx,
		fixture.request(fixture.publicationID, nil),
	)
	assert.Equal(t, PublicationPushPreparation{}, preparation)
	requireShowcaseRefusal(t, err, publication.ErrShowcasePayload)
	assert.Empty(t, fixture.records.records, "a refused push issued a retained record")
	assert.Zero(t, fixture.transport.sendCount(), "a refused push dispatched writes")
}

func TestMaterialWriteBatchRefusesAShowcaseCandidate(t *testing.T) {
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo,
		Vault: [32]byte{0x61},
	}
	binding.Repository = "at://" + binding.AccountDID
	showcase := newShowcaseServicePublication(t, binding.Vault, [16]byte{0x25, 0x73}, showcaseServiceFiles()...)

	batch, err := newMaterialWriteBatch(
		binding,
		nil,
		publicationstate.SuppliedRepositoryView{},
		publicationstate.CandidateInput{
			SnapshotKey: showcase.block.Key, SnapshotRecord: showcase.raw, HeadRecord: showcase.head,
			Payload: []byte("packed payload for a showcase candidate"),
		},
	)
	assert.Equal(t, MaterialWriteBatch{}, batch)
	requireShowcaseRefusal(t, err, publication.ErrShowcasePayload)
}
