package publicationstate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDID = "did:plc:abcdefghijklmnopqrstuvwx"

type fixture struct {
	t       testing.TB
	binding Binding
	payload []byte
	blocks  []SnapshotBlock
}

func newFixture(t *testing.T, backend Backend) fixture {
	t.Helper()
	payloadSnapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory}}},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "init.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic publication state payload"), Mode: 0o600}}},
	}
	blob, err := vault.Pack(payloadSnapshot)
	require.NoError(t, err)
	repository := "at://" + testDID
	if backend == BackendSpaces {
		repository += "/systems.lamb.dottie.vaultSnapshotV2/record"
	}
	binding := Binding{AccountDID: testDID, Backend: backend, Repository: repository}
	binding.Vault[0] = 9
	return fixture{t: t, binding: binding, payload: bytes.Clone(blob.Payload)}
}

func (f *fixture) appendRecord(t *testing.T, sequence uint64) SnapshotBlock {
	t.Helper()
	require.Equal(t, uint64(len(f.blocks)), sequence)
	var parent []byte
	if sequence > 0 {
		var err error
		parent, err = publication.RecordCID(f.blocks[sequence-1].Raw)
		require.NoError(t, err)
	}
	blobCID, err := publication.RawPayloadCID(f.payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: sequence, Parent: parent, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(f.payload))}}
	binary.BigEndian.PutUint64(record.PublicationID[8:], sequence+1)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	block := SnapshotBlock{Key: key, Raw: raw}
	f.blocks = append(f.blocks, block)
	return block
}

func (f fixture) observation(count int) Observation {
	f.t.Helper()
	require.Positive(f.t, count)
	require.GreaterOrEqual(f.t, len(f.blocks), count)
	blocks := make([]SnapshotBlock, count)
	for i := range blocks {
		blocks[i] = SnapshotBlock{Key: f.blocks[i].Key, Raw: bytes.Clone(f.blocks[i].Raw)}
	}
	candidate := blocks[len(blocks)-1]
	cid, err := publication.RecordCID(candidate.Raw)
	require.NoError(f.t, err)
	record, err := publication.DecodeSnapshot(candidate.Raw)
	require.NoError(f.t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: record.PublicationSeq, SnapshotCID: cid, BlobCID: record.Blob.CID})
	require.NoError(f.t, err)
	context := SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}}
	if f.binding.Backend == BackendSpaces {
		context.Policy = &Policy{Revision: "policy-1", Identity: []byte{4, 5, 6}, OwnerOnly: true}
	}
	return Observation{Origin: f.binding, SuppliedContext: context, Head: head, Snapshots: blocks}
}

func newStore(t *testing.T, f fixture, limits ...Limits) (*Store, string) {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	require.NoError(t, validateBinding(f.binding))
	require.NoError(t, validateLimits(DefaultLimits()))
	require.NoError(t, checkPrivateDirectory(directory))
	var store *Store
	var err error
	if len(limits) == 0 {
		store, err = Open(directory, f.binding)
	} else {
		store, err = OpenWithLimits(directory, f.binding, limits[0])
	}
	require.NoError(t, err)
	return store, directory
}

func assertFloorMatchesFixture(t *testing.T, floor Floor, observation Observation, block SnapshotBlock) {
	t.Helper()
	record, err := publication.DecodeSnapshot(block.Raw)
	require.NoError(t, err)
	cid, err := publication.RecordCID(block.Raw)
	require.NoError(t, err)
	assert.Equal(t, observation.Origin, floor.Binding)
	assert.Equal(t, observation.SuppliedContext, floor.SuppliedContext)
	assert.Equal(t, observation.Head, floor.Head)
	assert.Equal(t, block.Key, floor.SnapshotKey)
	assert.Equal(t, record.PublicationSeq, floor.Sequence)
	assert.Equal(t, record.PublicationID, floor.PublicationID)
	assert.Equal(t, cid, floor.RecordCID)
	assert.Equal(t, record.Blob.CID, floor.BlobCID)
	assert.Equal(t, record.Blob.Size, floor.BlobSize)
}

func prepareFirstUse(t *testing.T, store *Store, observation Observation, payload []byte) Proposal {
	t.Helper()
	proposal, err := store.Prepare(context.Background(), ModeFirstUse, observation, payload)
	require.NoError(t, err)
	return proposal
}

func TestStoreFirstUseAdvanceHistoryAndPayloadAvailability(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	before, exists, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Equal(t, Floor{}, before)
	accepted, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), accepted.Revision)
	assert.Equal(t, uint64(1), accepted.Generation)
	floor, exists, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, accepted, floor)
	changedContext := observation
	changedContext.SuppliedContext.RepositoryRevision = "same-position-new-context"
	noOpProposal, err := store.Prepare(ctx, ModeAdvance, changedContext, f.payload)
	require.NoError(t, err)
	noOpFloor, err := store.Accept(ctx, ModeAdvance, noOpProposal.StateToken, changedContext, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, accepted, noOpFloor)
	assert.Equal(t, observation.SuppliedContext, noOpFloor.SuppliedContext)
	page, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.Equal(t, "first_use", page.Events[0].Stop)
	require.Len(t, page.Records, 1)
	cid, err := publication.RecordCID(page.Records[0].Raw)
	require.NoError(t, err)
	assert.Equal(t, cid, page.Events[0].Trace[0].CID)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	loaded, exists, err := reopened.Load(ctx)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, accepted, loaded)
	_, err = reopened.Prepare(ctx, ModeAdvance, observation, nil)
	assert.Error(t, err, "decoded marker must not substitute for the payload bytes")
	noOp, err := reopened.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	missingPayload, err := reopened.Accept(ctx, ModeAdvance, noOp.StateToken, observation, nil, [32]byte{})
	require.Error(t, err)
	assert.Equal(t, Floor{}, missingPayload)
	result, err := reopened.Accept(ctx, ModeAdvance, noOp.StateToken, observation, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, accepted, result)
	assert.Equal(t, uint64(1), result.Revision)
}

func TestStoreMultiLinkAdvanceAndReplacementHistory(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	for sequence := uint64(0); sequence < 4; sequence++ {
		f.appendRecord(t, sequence)
	}
	store, directory := newStore(t, f)
	firstObs := f.observation(1)
	first := prepareFirstUse(t, store, firstObs, f.payload)
	floor, err := store.Accept(ctx, ModeFirstUse, first.StateToken, firstObs, f.payload, first.Confirmation)
	require.NoError(t, err)
	initialFloor := cloneFloor(floor)
	advanceObs := f.observation(4)
	advance, err := store.Prepare(ctx, ModeAdvance, advanceObs, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "joined", advance.Stop)
	assert.Len(t, advance.Trace, 3)
	floor, err = store.Accept(ctx, ModeAdvance, advance.StateToken, advanceObs, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), floor.Revision)
	assert.Equal(t, uint64(1), floor.Generation)
	advancedFloor := cloneFloor(floor)

	f.appendRecord(t, 4)
	f.appendRecord(t, 5)
	replacementObs := f.observation(6)
	replacementObs.Snapshots = []SnapshotBlock{{Key: f.blocks[5].Key, Raw: bytes.Clone(f.blocks[5].Raw)}}
	replacement, err := store.Prepare(ctx, ModeReplaceFloor, replacementObs, f.payload)
	require.NoError(t, err)
	assert.Equal(t, ReasonMissingLineage, replacement.Reason)
	assert.Equal(t, "replace floor: loses continuity with the prior recorded publication; no apply", replacement.Warning)
	oldDBID := floor.DatabaseID
	floor, err = store.Accept(ctx, ModeReplaceFloor, replacement.StateToken, replacementObs, f.payload, replacement.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), floor.Generation)
	assert.Equal(t, ProvenanceReplace, floor.Provenance)
	assert.Equal(t, oldDBID, floor.DatabaseID)
	replacedFloor := cloneFloor(floor)
	rollbackObs := f.observation(1)
	rollbackObs.SuppliedContext.RepositoryRevision = "rollback-revision"
	rollbackProposal, err := store.Prepare(ctx, ModeReplaceFloor, rollbackObs, f.payload)
	require.NoError(t, err)
	assert.Equal(t, ReasonRollback, rollbackProposal.Reason)
	floor, err = store.Accept(ctx, ModeReplaceFloor, rollbackProposal.StateToken, rollbackObs, f.payload, rollbackProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), floor.Generation)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	page, err := reopened.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 4)
	assert.Equal(t, []uint64{1, 2, 3, 4}, []uint64{page.Events[0].Revision, page.Events[1].Revision, page.Events[2].Revision, page.Events[3].Revision})
	assert.Equal(t, []string{"first_use", "joined", "missing_parent", "rollback"}, []string{page.Events[0].Stop, page.Events[1].Stop, page.Events[2].Stop, page.Events[3].Stop})
	assert.Equal(t, firstObs.SuppliedContext, page.Events[0].NewFloor.SuppliedContext)
	assert.Equal(t, advanceObs.SuppliedContext, page.Events[1].NewFloor.SuppliedContext)
	assert.Equal(t, replacementObs.SuppliedContext, page.Events[2].NewFloor.SuppliedContext)
	assert.Equal(t, rollbackObs.SuppliedContext, page.Events[3].NewFloor.SuppliedContext)
	assertFloorMatchesFixture(t, page.Events[0].NewFloor, firstObs, f.blocks[0])
	assertFloorMatchesFixture(t, page.Events[1].NewFloor, advanceObs, f.blocks[3])
	assertFloorMatchesFixture(t, page.Events[2].NewFloor, replacementObs, f.blocks[5])
	assertFloorMatchesFixture(t, page.Events[3].NewFloor, rollbackObs, f.blocks[0])
	require.NotNil(t, page.Events[1].OldFloor)
	require.NotNil(t, page.Events[2].OldFloor)
	require.NotNil(t, page.Events[3].OldFloor)
	assert.Equal(t, initialFloor, *page.Events[1].OldFloor)
	assert.Equal(t, advancedFloor, *page.Events[2].OldFloor)
	assert.Equal(t, replacedFloor, *page.Events[3].OldFloor)
	assertFloorMatchesFixture(t, *page.Events[1].OldFloor, firstObs, f.blocks[0])
	assertFloorMatchesFixture(t, *page.Events[2].OldFloor, advanceObs, f.blocks[3])
	assertFloorMatchesFixture(t, *page.Events[3].OldFloor, replacementObs, f.blocks[5])
	seenZero := 0
	for _, record := range page.Records {
		if bytes.Equal(record.Reference.CID, initialFloor.RecordCID) {
			seenZero++
			assert.Equal(t, f.blocks[0].Raw, record.Raw)
		}
	}
	assert.Equal(t, 1, seenZero)
	for _, event := range page.Events {
		for index, ref := range event.Trace {
			var matched bool
			for _, record := range page.Records {
				if bytes.Equal(ref.CID, record.Reference.CID) {
					matched = true
					computed, err := publication.RecordCID(record.Raw)
					require.NoError(t, err)
					assert.Equal(t, computed, ref.CID)
					break
				}
			}
			require.True(t, matched)
			if index+1 < len(event.Trace) {
				var current, previous []byte
				for _, record := range page.Records {
					if bytes.Equal(record.Reference.CID, ref.CID) {
						current = record.Raw
					}
					if bytes.Equal(record.Reference.CID, event.Trace[index+1].CID) {
						previous = record.Raw
					}
				}
				assert.NoError(t, publication.VerifySuccessor(previous, current, ref.Key))
			}
		}
		if event.Stop == "joined" {
			var held, oldest []byte
			for _, record := range page.Records {
				if bytes.Equal(record.Reference.CID, event.OldFloor.RecordCID) {
					held = record.Raw
				}
			}
			last := event.Trace[len(event.Trace)-1]
			for _, record := range page.Records {
				if bytes.Equal(record.Reference.CID, last.CID) {
					oldest = record.Raw
				}
			}
			assert.NoError(t, publication.VerifySuccessor(held, oldest, last.Key))
		}
	}
	firstPage, err := reopened.History(ctx, 0, 2)
	require.NoError(t, err)
	assert.True(t, firstPage.HasMore)
	assert.Equal(t, uint64(2), firstPage.NextRevision)
	secondPage, err := reopened.History(ctx, firstPage.NextRevision, 2)
	require.NoError(t, err)
	assert.False(t, secondPage.HasMore)
	require.Len(t, secondPage.Events, 2)
}

func TestStoreOriginUTF8AndStaleTokensRefuseWithoutWrites(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendSpaces)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	observation := f.observation(1)
	wrong := observation
	wrong.Origin.AccountDID = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
	wrong.Origin.Repository = "at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb/systems.lamb.dottie.vaultSnapshotV2/record"
	wrongID, err := store.RecordObservation(ctx, wrong)
	require.ErrorIs(t, err, ErrInvalid)
	assert.Equal(t, [32]byte{}, wrongID)
	assert.Equal(t, "binding", bindingReason(err))
	wrongBackend := observation
	wrongBackend.Origin.Backend = BackendPublicRepo
	wrongBackend.Origin.Repository = "at://" + testDID
	_, err = store.RecordObservation(ctx, wrongBackend)
	require.ErrorIs(t, err, ErrInvalid)
	var cached int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM cache_observations").Scan(&cached))
	assert.Equal(t, 0, cached)
	invalid := observation
	invalid.SuppliedContext.Policy = &Policy{Revision: string([]byte{0x80}), Identity: []byte{1}, OwnerOnly: true}
	_, err = store.Prepare(ctx, ModeFirstUse, invalid, f.payload)
	require.ErrorIs(t, err, ErrInvalid)
	invalid.SuppliedContext.Policy.Revision = string([]byte{0x81})
	_, err = store.Prepare(ctx, ModeFirstUse, invalid, f.payload)
	require.ErrorIs(t, err, ErrInvalid)
	invalid = observation
	invalid.SuppliedContext.RepositoryRevision = string([]byte{0x80})
	_, err = store.Prepare(ctx, ModeFirstUse, invalid, f.payload)
	require.ErrorIs(t, err, ErrInvalid)
	invalid.SuppliedContext.RepositoryRevision = string([]byte{0x81})
	_, err = store.RecordObservation(ctx, invalid)
	require.ErrorIs(t, err, ErrInvalid)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	competing := prepareFirstUse(t, store, observation, f.payload)
	changedContext := observation
	changedContext.SuppliedContext.RepositoryRevision = "changed-revision"
	_, err = store.Accept(ctx, ModeFirstUse, proposal.StateToken, changedContext, f.payload, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonConfirmation)
	_, err = store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, competing.StateToken, observation, f.payload, competing.Confirmation)
	requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonStale)
	_, exists, err := store.Load(ctx)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestStoreSeparateCacheAndAcceptedBudgetsAndDatabaseIdentity(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	for sequence := uint64(0); sequence < 3; sequence++ {
		f.appendRecord(t, sequence)
	}
	limits := DefaultLimits()
	limits.CacheObservationCount = 1
	limits.CacheRecordCount = 1
	limits.CacheLogicalBytes = 1 << 20
	store, directory := newStore(t, f, limits)
	first := f.observation(1)
	firstID, err := store.RecordObservation(ctx, first)
	require.NoError(t, err)
	repeatedID, err := store.RecordObservation(ctx, first)
	require.NoError(t, err)
	assert.Equal(t, firstID, repeatedID)
	second := f.observation(2)
	_, err = store.RecordObservation(ctx, second)
	require.ErrorIs(t, err, ErrLimit)
	proposal := prepareFirstUse(t, store, first, f.payload)
	firstFloor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, first, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	advance, err := store.Prepare(ctx, ModeAdvance, second, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeAdvance, advance.StateToken, second, f.payload, [32]byte{})
	require.NoError(t, err)
	replacement, err := store.Prepare(ctx, ModeReplaceFloor, first, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeReplaceFloor, replacement.StateToken, first, f.payload, replacement.Confirmation)
	require.NoError(t, err)
	oldFloor, exists, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, exists)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonLimits)
	assert.Nil(t, reopened)
	wrongBinding := f.binding
	wrongBinding.Backend = BackendSpaces
	wrongBinding.Repository = "at://" + testDID + "/systems.lamb.dottie.vaultSnapshotV2/record"
	_, err = OpenWithLimits(directory, wrongBinding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
	otherDir := t.TempDir()
	require.NoError(t, os.Chmod(otherDir, 0o700))
	other, err := Open(otherDir, f.binding)
	require.NoError(t, err)
	defer other.Close()
	otherProposal, err := other.Prepare(ctx, ModeFirstUse, first, f.payload)
	require.NoError(t, err)
	fresh, err := other.Accept(ctx, ModeFirstUse, otherProposal.StateToken, first, f.payload, otherProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, firstFloor.Sequence, fresh.Sequence)
	assert.Equal(t, firstFloor.Generation, fresh.Generation)
	assert.NotEqual(t, firstFloor.DatabaseID, fresh.DatabaseID)
	assert.NotEqual(t, oldFloor.DatabaseID, other.databaseID)
}

func TestStoreOpenRejectsUnsafeExistingModesWithoutRepair(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	path := filepath.Join(directory, "publication.db.lock")
	require.NoError(t, os.WriteFile(path, []byte("lock"), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))
	_, err := Open(directory, f.binding)
	require.ErrorIs(t, err, ErrInvalid)
	info, statErr := os.Stat(path)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestCanonicalJSONEncodingUsesBase64AndDoesNotEscapeHTML(t *testing.T) {
	var dbid [32]byte
	for index := range dbid {
		dbid[index] = byte(index)
	}
	wire := stateTokenWire{Version: 1, DatabaseID: bytes.Clone(dbid[:]), Revision: 7, Generation: 2, Binding: bindingToWire(Binding{AccountDID: "<>&", Backend: BackendPublicRepo, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx"}), Limits: limitsToWire(DefaultLimits()), Floor: nil}
	encoded, err := canonicalJSON(wire)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "\\u003c")
	assert.Contains(t, string(encoded), "\"databaseId\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"")
	var decoded stateTokenWire
	require.NoError(t, strictJSON(encoded, &decoded))
	assert.Equal(t, encoded, mustCanonicalJSON(t, decoded))
	var unknown map[string]any
	require.NoError(t, json.Unmarshal(encoded, &unknown))
	unknown["extension"] = true
	bad, err := json.Marshal(unknown)
	require.NoError(t, err)
	assert.Error(t, strictJSON(bad, &decoded))
}

func mustCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := canonicalJSON(value)
	require.NoError(t, err)
	return encoded
}
func bindingReason(err error) string {
	var closed *closedError
	if errors.As(err, &closed) {
		return string(closed.reason)
	}
	return ""
}
