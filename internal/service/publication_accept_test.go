package service

import (
	"context"
	"os"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publicationAcceptRecord struct {
	block   publicationstate.SnapshotBlock
	payload []byte
}

type publicationAcceptFixture struct {
	directory string
	binding   publicationstate.Binding
	context   publicationstate.SuppliedContext
	records   []publicationAcceptRecord
}

func newPublicationAcceptFixture(t *testing.T) *publicationAcceptFixture {
	t.Helper()
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x41, 0x52, 0x63},
	}
	binding.Repository = "at://" + binding.AccountDID
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	return &publicationAcceptFixture{
		directory: directory, binding: binding,
		context: publicationstate.SuppliedContext{RepositoryRevision: "synthetic-accept-revision", RepositoryDigest: []byte{0x11, 0x12}},
	}
}

func (fixture *publicationAcceptFixture) append(t *testing.T, content string) publicationAcceptRecord {
	t.Helper()
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID: "synthetic-files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory},
		}},
		Entries: []model.Entry{{
			TargetID: "synthetic-files",
			File:     &model.FileEntry{Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular, Content: []byte(content), Mode: 0o600},
		}},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	sequence := uint64(len(fixture.records))
	var parent []byte
	if sequence > 0 {
		parent, err = publication.RecordCID(fixture.records[sequence-1].block.Raw)
		require.NoError(t, err)
	}
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault,
		PublicationSeq: sequence, Parent: parent,
		Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload)), MIMEType: publication.SnapshotBlobMIMEType},
	}
	record.PublicationID[15] = byte(sequence + 1)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	appended := publicationAcceptRecord{block: publicationstate.SnapshotBlock{Key: key, Raw: raw}, payload: packed.Payload}
	fixture.records = append(fixture.records, appended)
	return appended
}

func (fixture *publicationAcceptFixture) observation(t *testing.T) publicationstate.Observation {
	t.Helper()
	require.NotEmpty(t, fixture.records)
	blocks := make([]publicationstate.SnapshotBlock, 0, len(fixture.records))
	for _, record := range fixture.records {
		blocks = append(blocks, record.block)
	}
	terminal := fixture.records[len(fixture.records)-1]
	terminalRecord, err := publication.DecodeSnapshot(terminal.block.Raw)
	require.NoError(t, err)
	terminalCID, err := publication.RecordCID(terminal.block.Raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault,
		PublicationSeq: terminalRecord.PublicationSeq, SnapshotCID: terminalCID, BlobCID: terminalRecord.Blob.CID,
	})
	require.NoError(t, err)
	return publicationstate.Observation{
		Origin: fixture.binding, SuppliedContext: fixture.context, Head: head, Snapshots: blocks,
	}
}

func (fixture *publicationAcceptFixture) stage(t *testing.T, floorRevision uint64) PublicationAcceptProposal {
	t.Helper()
	terminal := fixture.records[len(fixture.records)-1]
	proposal, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: floorRevision,
		Observation: fixture.observation(t), Payload: terminal.payload,
	})
	require.NoError(t, err)
	return proposal
}

func (fixture *publicationAcceptFixture) accept(t *testing.T, proposal PublicationAcceptProposal, floorRevision uint64) publicationstate.Floor {
	t.Helper()
	floor, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: proposal.Mode, FloorRevision: floorRevision,
		StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
		Observation: fixture.observation(t), Payload: fixture.records[len(fixture.records)-1].payload,
	})
	require.NoError(t, err)
	return floor
}

func (fixture *publicationAcceptFixture) loadedFloor(t *testing.T) publicationstate.Floor {
	t.Helper()
	store, err := publicationstate.Open(fixture.directory, fixture.binding)
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	floor, present, err := store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	return floor
}

func assertPublicationAcceptFailure(t *testing.T, err error, stage, reason string) {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPublicationAccept)
	var refusal *publicationAcceptError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, stage, refusal.Stage())
	assert.Equal(t, reason, refusal.Reason())
}

func TestStagePublicationAcceptUsesFirstUseWithoutAFloorThenAdvances(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	first := fixture.stage(t, 0)
	assert.Equal(t, publicationstate.ModeFirstUse, first.Mode)
	assert.NotEqual(t, [32]byte{}, first.StateToken)
	assert.NotEqual(t, [32]byte{}, first.Confirmation)
	assert.NotEqual(t, [32]byte{}, first.ObservationDigest)

	accepted := fixture.accept(t, first, 0)
	assert.Equal(t, uint64(1), accepted.Revision)
	assert.Equal(t, uint64(1), accepted.Generation)
	assert.Equal(t, first.ObservationDigest, accepted.ObservationDigest)

	fixture.append(t, "synthetic accept payload two")
	second := fixture.stage(t, accepted.Revision)
	assert.Equal(t, publicationstate.ModeAdvance, second.Mode)
	assert.Equal(t, [32]byte{}, second.Confirmation, "an advance accept carries no confirmation")
	assert.NotEqual(t, first.ObservationDigest, second.ObservationDigest)
	assert.NotEqual(t, first.StateToken, second.StateToken)

	advanced := fixture.accept(t, second, accepted.Revision)
	assert.Equal(t, accepted.Revision+1, advanced.Revision)
	assert.Equal(t, accepted.Generation, advanced.Generation)
	terminal, err := publication.DecodeSnapshot(fixture.records[1].block.Raw)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), terminal.PublicationSeq)
	assert.Equal(t, terminal.PublicationSeq, advanced.Sequence)
}

func TestStagePublicationAcceptRefusesAFloorRevisionThatMoved(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	first := fixture.stage(t, 0)
	accepted := fixture.accept(t, first, 0)

	fixture.append(t, "synthetic accept payload two")
	_, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: accepted.Revision + 1,
		Observation: fixture.observation(t), Payload: fixture.records[1].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-position", "revision_moved")
	assert.ErrorIs(t, err, errPublicationAcceptRevision)

	_, err = AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: publicationstate.ModeAdvance,
		FloorRevision: accepted.Revision + 1, StateToken: first.StateToken, Confirmation: [32]byte{},
		Observation: fixture.observation(t), Payload: fixture.records[1].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-position", "revision_moved")

	floor := fixture.loadedFloor(t)
	assert.Equal(t, accepted.Revision, floor.Revision)
	assert.Equal(t, first.ObservationDigest, floor.ObservationDigest)
}

func TestAcceptPublicationRefusesAStaleStateToken(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	first := fixture.stage(t, 0)
	accepted := fixture.accept(t, first, 0)

	fixture.append(t, "synthetic accept payload two")
	stale := fixture.stage(t, accepted.Revision)
	fixture.accept(t, stale, accepted.Revision)
	current := fixture.loadedFloor(t)
	assert.Equal(t, accepted.Revision+1, current.Revision)

	_, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: stale.Mode, FloorRevision: current.Revision,
		StateToken: stale.StateToken, Confirmation: stale.Confirmation,
		Observation: fixture.observation(t), Payload: fixture.records[1].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-material", "material_refused")
	var stateError *publicationstate.Error
	require.ErrorAs(t, err, &stateError)
	assert.Equal(t, publicationstate.ErrConsent, stateError.Class())
	assert.Equal(t, publicationstate.ReasonStale, stateError.Reason())
	assert.Equal(t, current.Revision, fixture.loadedFloor(t).Revision)
}

func TestAcceptPublicationRefusesAReplacementFloor(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	first := fixture.stage(t, 0)
	accepted := fixture.accept(t, first, 0)

	fixture.append(t, "synthetic accept payload two")
	proposal := fixture.stage(t, accepted.Revision)
	_, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: publicationstate.ModeReplaceFloor,
		FloorRevision: accepted.Revision, StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
		Observation: fixture.observation(t), Payload: fixture.records[1].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-input", "mode_refused")
	assert.Equal(t, accepted.Revision, fixture.loadedFloor(t).Revision)
}

func TestAcceptPublicationRefusesMaterialTheProposalWasNotStagedFrom(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	first := fixture.stage(t, 0)
	accepted := fixture.accept(t, first, 0)

	fixture.append(t, "synthetic accept payload two")
	proposal := fixture.stage(t, accepted.Revision)
	_, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: proposal.Mode, FloorRevision: accepted.Revision,
		StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
		Observation: fixture.observation(t), Payload: fixture.records[0].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-material", "material_refused")
	assert.Equal(t, accepted.Revision, fixture.loadedFloor(t).Revision)
}

func TestAcceptPublicationRefusesFirstUseWhenAFloorExists(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	first := fixture.stage(t, 0)
	accepted := fixture.accept(t, first, 0)

	_, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: publicationstate.ModeFirstUse,
		FloorRevision: 0, StateToken: first.StateToken, Confirmation: first.Confirmation,
		Observation: fixture.observation(t), Payload: fixture.records[0].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-position", "revision_moved")
	assert.Equal(t, accepted.Revision, fixture.loadedFloor(t).Revision)
}

func TestStagePublicationAcceptRefusesAProviderRecordThatIsNotAForwardExtension(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	first := fixture.stage(t, 0)
	accepted := fixture.accept(t, first, 0)

	diverged := newPublicationAcceptFixture(t)
	diverged.directory, diverged.binding, diverged.context = fixture.directory, fixture.binding, fixture.context
	record := diverged.append(t, "synthetic accept payload diverged")
	_, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: accepted.Revision,
		Observation: diverged.observation(t), Payload: record.payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-prepare", "proposal_refused")
	var stateError *publicationstate.Error
	require.ErrorAs(t, err, &stateError)
	assert.Equal(t, publicationstate.ErrContinuity, stateError.Class())
	assert.Equal(t, publicationstate.ReasonFork, stateError.Reason())
	assert.Equal(t, accepted.Revision, fixture.loadedFloor(t).Revision)
}

func TestStagePublicationAcceptRefusesAnUnusablePositionStoreOrPayload(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	missing := t.TempDir()
	require.NoError(t, os.Chmod(missing, 0o700))
	_, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: missing, Binding: fixture.binding, FloorRevision: 0,
		Observation: fixture.observation(t), Payload: fixture.records[0].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-position", "position_absent")
	_, statErr := os.Lstat(missing + "/publication.db")
	assert.ErrorIs(t, statErr, os.ErrNotExist, "staging created the position store")

	_, err = StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: 0,
		Observation: fixture.observation(t), Payload: nil,
	})
	assertPublicationAcceptFailure(t, err, "accept-input", "request_invalid")
}

func TestStagePublicationAcceptRefusesPayloadThatIsNotTheObservedRecord(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	first := fixture.append(t, "synthetic accept payload")
	second := fixture.append(t, "synthetic accept payload two")
	_, err := StagePublicationAccept(context.Background(), PublicationAcceptStageRequest{
		Directory: fixture.directory, Binding: fixture.binding, FloorRevision: 0,
		Observation: fixture.observation(t), Payload: first.payload,
	})
	require.Error(t, err)
	assertPublicationAcceptFailure(t, err, "accept-prepare", "proposal_refused")
	assert.NotEqual(t, second.payload, first.payload)
}

func TestAcceptPublicationRefusesAModeThatDoesNotMatchTheStore(t *testing.T) {
	fixture := newPublicationAcceptFixture(t)
	fixture.append(t, "synthetic accept payload")
	proposal := fixture.stage(t, 0)
	require.Equal(t, publicationstate.ModeFirstUse, proposal.Mode)

	_, err := AcceptPublication(context.Background(), PublicationAcceptRequest{
		Directory: fixture.directory, Binding: fixture.binding, Mode: publicationstate.ModeAdvance,
		FloorRevision: 0, StateToken: proposal.StateToken, Confirmation: [32]byte{},
		Observation: fixture.observation(t), Payload: fixture.records[0].payload,
	})
	assertPublicationAcceptFailure(t, err, "accept-position", "mode_refused")

	store, err := publicationstate.Open(fixture.directory, fixture.binding)
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	_, present, err := store.Load(context.Background())
	require.NoError(t, err)
	assert.False(t, present, "a refused mode created a floor")
}
