package publicationstate

import (
	"bytes"
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTraceBoundaryUsesFinalHeldFloorEdge(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	for sequence := uint64(0); sequence < 4; sequence++ {
		f.appendRecord(t, sequence)
	}
	limits := DefaultLimits()
	limits.MaxLineageLinks = 2
	exact, _ := newStore(t, f, limits)
	firstObs := f.observation(1)
	proposal := prepareFirstUse(t, exact, firstObs, f.payload)
	_, err := exact.Accept(ctx, ModeFirstUse, proposal.StateToken, firstObs, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	exactObservation := f.observation(3)
	exactProposal, err := exact.Prepare(ctx, ModeAdvance, exactObservation, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "joined", exactProposal.Stop)
	assert.Len(t, exactProposal.Trace, 2)
	require.NoError(t, exact.Close())

	oneOver, dir := newStore(t, f, limits)
	first := prepareFirstUse(t, oneOver, firstObs, f.payload)
	_, err = oneOver.Accept(ctx, ModeFirstUse, first.StateToken, firstObs, f.payload, first.Confirmation)
	require.NoError(t, err)
	oneOverObservation := f.observation(4)
	proposal, err = oneOver.Prepare(ctx, ModeReplaceFloor, oneOverObservation, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "walk_limit", proposal.Stop)
	assert.Equal(t, ReasonMissingLineage, proposal.Reason)
	assert.Len(t, proposal.Trace, 3)
	_, err = oneOver.Accept(ctx, ModeReplaceFloor, proposal.StateToken, oneOverObservation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	require.NoError(t, oneOver.Close())
	reopened, err := OpenWithLimits(dir, f.binding, limits)
	require.NoError(t, err)
	defer reopened.Close()
	floor, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, uint64(2), floor.Generation)
}

func TestForkAndWrongStructuralParentAreNotConsentEquivalent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	store, _ := newStore(t, f)
	defer store.Close()
	firstObs := f.observation(1)
	first := prepareFirstUse(t, store, firstObs, f.payload)
	_, err := store.Accept(ctx, ModeFirstUse, first.StateToken, firstObs, f.payload, first.Confirmation)
	require.NoError(t, err)

	alternateParent := fixtureRecord(t, f, 0, nil, 0x70)
	alternateParentCID, err := publication.RecordCID(alternateParent.Raw)
	require.NoError(t, err)
	wrongFinalEdge := fixtureRecord(t, f, 1, alternateParentCID, 0x6f)
	wrongFinalObservation := singleRecordObservation(t, f, wrongFinalEdge)
	_, err = store.Prepare(ctx, ModeAdvance, wrongFinalObservation, f.payload)
	requireErrorMetadata(t, err, ErrContinuity, StagePrepare, ReasonFork)

	alternate := fixtureRecord(t, f, 0, nil, 0x71)
	forkObservation := singleRecordObservation(t, f, alternate)
	_, err = store.Prepare(ctx, ModeAdvance, forkObservation, f.payload)
	requireErrorMetadata(t, err, ErrContinuity, StagePrepare, ReasonFork)
	forkProposal, err := store.Prepare(ctx, ModeReplaceFloor, forkObservation, f.payload)
	require.NoError(t, err)
	assert.Equal(t, ReasonFork, forkProposal.Reason)
	accepted, err := store.Accept(ctx, ModeReplaceFloor, forkProposal.StateToken, forkObservation, f.payload, forkProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), accepted.Generation)

	floorRaw := f.blocks[0].Raw
	floorCID, err := publication.RecordCID(floorRaw)
	require.NoError(t, err)
	structural := fixtureRecord(t, f, 2, floorCID, 0x72)
	structuralObservation := singleRecordObservation(t, f, structural)
	_, err = store.Prepare(ctx, ModeReplaceFloor, structuralObservation, f.payload)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)
}

func TestEverySuppliedBlockIsValidatedEvenWhenUnused(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	observation := f.observation(1)
	invalidRecord, err := publication.DecodeSnapshot(f.blocks[1].Raw)
	require.NoError(t, err)
	invalidRecord.Vault[1]++
	invalidRaw, err := publication.EncodeSnapshot(invalidRecord)
	require.NoError(t, err)
	observation.Snapshots = append(observation.Snapshots, SnapshotBlock{Key: f.blocks[1].Key, Raw: invalidRaw})
	store, _ := newStore(t, f)
	defer store.Close()
	_, err = store.Prepare(context.Background(), ModeFirstUse, observation, f.payload)
	require.ErrorIs(t, err, ErrInvalid)
}

func fixtureRecord(t *testing.T, f fixture, sequence uint64, parent []byte, pubID byte) SnapshotBlock {
	t.Helper()
	blobCID, err := publication.RawPayloadCID(f.payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: sequence, Parent: bytes.Clone(parent), Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(f.payload))}}
	record.PublicationID[15] = pubID
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return SnapshotBlock{Key: key, Raw: raw}
}

func singleRecordObservation(t *testing.T, f fixture, block SnapshotBlock) Observation {
	t.Helper()
	cid, err := publication.RecordCID(block.Raw)
	require.NoError(t, err)
	record, err := publication.DecodeSnapshot(block.Raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: record.PublicationSeq, SnapshotCID: cid, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	context := SuppliedContext{RepositoryRevision: "revision-alternate", RepositoryDigest: []byte{7, 8, 9}}
	if f.binding.Backend == BackendSpaces {
		context.Policy = &Policy{Revision: "policy-alternate", Identity: []byte{8, 9}, OwnerOnly: true}
	}
	return Observation{Origin: f.binding, SuppliedContext: context, Head: head, Snapshots: []SnapshotBlock{{Key: block.Key, Raw: bytes.Clone(block.Raw)}}}
}
