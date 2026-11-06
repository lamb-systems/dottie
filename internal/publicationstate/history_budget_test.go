package publicationstate

import (
	"context"
	"os"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryReturnsLargestCompleteByteBoundedPrefix(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	firstObs := f.observation(1)
	firstValidated, err := validateObservation(firstObs, f.binding, DefaultLimits())
	require.NoError(t, err)
	secondObs := f.observation(2)
	secondValidated, err := validateObservation(secondObs, f.binding, DefaultLimits())
	require.NoError(t, err)
	var dbid [32]byte
	dbid[0] = 0x71
	firstTrace := resolvedTrace{refs: []RecordReference{firstValidated.candidate.ref}, records: []validatedRecord{firstValidated.candidate}, stop: "first_use"}
	firstFloor := buildFloor(dbid, f.binding, firstValidated, stateSnapshot{}, firstTrace, ModeFirstUse)
	firstBody, err := makeEventBody(ModeFirstUse, "", nil, firstFloor, firstTrace.refs, "first_use", firstValidated.observationDigest, firstValidated.setDigest)
	require.NoError(t, err)
	firstDigest := domainHash("systems.lamb.dottie.local-publication-event.v1", firstBody)
	firstFloor.AcceptedEventDigest = firstDigest
	firstBytes := uint64(len(firstBody)+32+8) + recordLogicalBytes(firstValidated.candidate)
	secondTrace := resolvedTrace{refs: []RecordReference{secondValidated.candidate.ref}, records: []validatedRecord{secondValidated.candidate}, stop: "joined"}
	secondState := stateSnapshot{floor: &firstFloor, revision: 1, generation: 1}
	secondFloor := buildFloor(dbid, f.binding, secondValidated, secondState, secondTrace, ModeAdvance)
	secondBody, err := makeEventBody(ModeAdvance, "", &firstFloor, secondFloor, secondTrace.refs, "joined", secondValidated.observationDigest, secondValidated.setDigest)
	require.NoError(t, err)
	secondDigest := domainHash("systems.lamb.dottie.local-publication-event.v1", secondBody)
	secondFloor.AcceptedEventDigest = secondDigest
	secondBytes := uint64(len(secondBody)+32+8) + recordLogicalBytes(secondValidated.candidate) + recordLogicalBytes(firstValidated.candidate)
	budget := firstBytes
	if secondBytes > budget {
		budget = secondBytes
	}
	require.Greater(t, firstBytes+secondBytes, budget)
	limits := DefaultLimits()
	limits.HistoryEvidenceBytes = budget
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	defer store.Close()
	proposal, err := store.Prepare(ctx, ModeFirstUse, firstObs, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, proposal.StateToken, firstObs, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	advance, err := store.Prepare(ctx, ModeAdvance, secondObs, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeAdvance, advance.StateToken, secondObs, f.payload, [32]byte{})
	require.NoError(t, err)
	page, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.True(t, page.HasMore)
	assert.Equal(t, uint64(1), page.NextRevision)
	next, err := store.History(ctx, page.NextRevision, 10)
	require.NoError(t, err)
	require.Len(t, next.Events, 1)
	assert.False(t, next.HasMore)
	assert.Equal(t, uint64(2), next.NextRevision)
}

func TestHistoryAnchorAdmissionRejectsOneByteUnderStandaloneEvent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	firstObs := f.observation(1)
	v0, err := validateObservation(firstObs, f.binding, DefaultLimits())
	require.NoError(t, err)
	secondObs := f.observation(2)
	v1, err := validateObservation(secondObs, f.binding, DefaultLimits())
	require.NoError(t, err)
	var dbid [32]byte
	dbid[0] = 0x71
	t0 := resolvedTrace{refs: []RecordReference{v0.candidate.ref}, records: []validatedRecord{v0.candidate}, stop: "first_use"}
	floor0 := buildFloor(dbid, f.binding, v0, stateSnapshot{}, t0, ModeFirstUse)
	body0, err := makeEventBody(ModeFirstUse, "", nil, floor0, t0.refs, "first_use", v0.observationDigest, v0.setDigest)
	require.NoError(t, err)
	firstBytes := uint64(len(body0)+40) + independentRecordBytes(t, f.blocks[0])
	t1 := resolvedTrace{refs: []RecordReference{v1.candidate.ref}, records: []validatedRecord{v1.candidate}, stop: "joined"}
	state1 := stateSnapshot{floor: &floor0, revision: 1, generation: 1}
	floor1 := buildFloor(dbid, f.binding, v1, state1, t1, ModeAdvance)
	body1, err := makeEventBody(ModeAdvance, "", &floor0, floor1, t1.refs, "joined", v1.observationDigest, v1.setDigest)
	require.NoError(t, err)
	secondBytes := uint64(len(body1)+40) + independentRecordBytes(t, f.blocks[1]) + independentRecordBytes(t, f.blocks[0])
	require.Greater(t, secondBytes, firstBytes)
	budget := secondBytes - 1
	require.GreaterOrEqual(t, budget, firstBytes)
	limits := DefaultLimits()
	limits.HistoryEvidenceBytes = budget
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	store, err := OpenWithLimits(dir, f.binding, limits)
	require.NoError(t, err)
	defer store.Close()
	first, err := store.Prepare(ctx, ModeFirstUse, firstObs, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, firstObs, f.payload, first.Confirmation)
	require.NoError(t, err)
	advance, err := store.Prepare(ctx, ModeAdvance, secondObs, f.payload)
	require.NoError(t, err)
	before := readLogicalRows(t, store.conn)
	result, err := store.Accept(ctx, ModeAdvance, advance.StateToken, secondObs, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrLimit, StageAccept, ReasonCapacity)
	assert.Equal(t, Floor{}, result)
	assert.Equal(t, before, readLogicalRows(t, store.conn))
	page, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.False(t, page.HasMore)
}

func TestHistoryAnchorPagingChargesOldFloorAtNonzeroCursor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	for seq := uint64(0); seq < 3; seq++ {
		f.appendRecord(t, seq)
	}
	obs0 := f.observation(1)
	v0, err := validateObservation(obs0, f.binding, DefaultLimits())
	require.NoError(t, err)
	obs1 := f.observation(2)
	v1, err := validateObservation(obs1, f.binding, DefaultLimits())
	require.NoError(t, err)
	obs2 := f.observation(3)
	v2, err := validateObservation(obs2, f.binding, DefaultLimits())
	require.NoError(t, err)
	var dbid [32]byte
	dbid[0] = 0x72
	t0 := resolvedTrace{refs: []RecordReference{v0.candidate.ref}, records: []validatedRecord{v0.candidate}, stop: "first_use"}
	floor0 := buildFloor(dbid, f.binding, v0, stateSnapshot{}, t0, ModeFirstUse)
	body0, err := makeEventBody(ModeFirstUse, "", nil, floor0, t0.refs, "first_use", v0.observationDigest, v0.setDigest)
	require.NoError(t, err)
	floor0.AcceptedEventDigest = domainHash("systems.lamb.dottie.local-publication-event.v1", body0)
	t1 := resolvedTrace{refs: []RecordReference{v1.candidate.ref}, records: []validatedRecord{v1.candidate}, stop: "joined"}
	floor1 := buildFloor(dbid, f.binding, v1, stateSnapshot{floor: &floor0, revision: 1, generation: 1}, t1, ModeAdvance)
	body1, err := makeEventBody(ModeAdvance, "", &floor0, floor1, t1.refs, "joined", v1.observationDigest, v1.setDigest)
	require.NoError(t, err)
	floor1.AcceptedEventDigest = domainHash("systems.lamb.dottie.local-publication-event.v1", body1)
	t2 := resolvedTrace{refs: []RecordReference{v2.candidate.ref}, records: []validatedRecord{v2.candidate}, stop: "joined"}
	floor2 := buildFloor(dbid, f.binding, v2, stateSnapshot{floor: &floor1, revision: 2, generation: 1}, t2, ModeAdvance)
	body2, err := makeEventBody(ModeAdvance, "", &floor1, floor2, t2.refs, "joined", v2.observationDigest, v2.setDigest)
	require.NoError(t, err)
	event2 := uint64(len(body1)+40) + independentRecordBytes(t, f.blocks[0]) + independentRecordBytes(t, f.blocks[1])
	event3 := uint64(len(body2)+40) + independentRecordBytes(t, f.blocks[1]) + independentRecordBytes(t, f.blocks[2])
	combined := uint64(len(body1)+40+len(body2)+40) + independentRecordBytes(t, f.blocks[0]) + independentRecordBytes(t, f.blocks[1]) + independentRecordBytes(t, f.blocks[2])
	budget := combined - 1
	require.GreaterOrEqual(t, budget, event2)
	require.GreaterOrEqual(t, budget, event3)
	require.GreaterOrEqual(t, budget, uint64(len(body0)+40)+independentRecordBytes(t, f.blocks[0]))
	limits := DefaultLimits()
	limits.HistoryEvidenceBytes = budget
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	store, err := OpenWithLimits(dir, f.binding, limits)
	require.NoError(t, err)
	defer store.Close()
	p0, err := store.Prepare(ctx, ModeFirstUse, obs0, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, p0.StateToken, obs0, f.payload, p0.Confirmation)
	require.NoError(t, err)
	p1, err := store.Prepare(ctx, ModeAdvance, obs1, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeAdvance, p1.StateToken, obs1, f.payload, [32]byte{})
	require.NoError(t, err)
	p2, err := store.Prepare(ctx, ModeAdvance, obs2, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeAdvance, p2.StateToken, obs2, f.payload, [32]byte{})
	require.NoError(t, err)
	page, err := store.History(ctx, 1, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.Equal(t, uint64(2), page.Events[0].Revision)
	assert.True(t, page.HasMore)
	assert.Equal(t, uint64(2), page.NextRevision)
	require.NotNil(t, page.Events[0].OldFloor)
	assert.Equal(t, f.blocks[0].Raw, findHistoryRaw(t, page, page.Events[0].OldFloor.RecordCID))
	next, err := store.History(ctx, page.NextRevision, 10)
	require.NoError(t, err)
	require.Len(t, next.Events, 1)
	assert.Equal(t, uint64(3), next.Events[0].Revision)
	assert.False(t, next.HasMore)
}

func independentRecordBytes(t *testing.T, block SnapshotBlock) uint64 {
	t.Helper()
	cid, err := publication.RecordCID(block.Raw)
	require.NoError(t, err)
	return uint64(len(block.Raw) + len(cid) + len(block.Key) + 8)
}
