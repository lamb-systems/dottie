package publicationstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogicalBudgetAccountingExactBoundaries(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	observation := f.observation(1)
	validated, err := validateObservation(observation, f.binding, DefaultLimits())
	require.NoError(t, err)
	cacheMetadata, err := canonicalJSON(cacheObservationWire{Version: 1, ObservationDigest: bytes.Clone(validated.observationDigest[:]), SuppliedSetDigest: bytes.Clone(validated.setDigest[:]), Context: contextToWire(validated.context), Head: bytes.Clone(validated.head), Candidate: referenceToWire(validated.candidate.ref)})
	require.NoError(t, err)
	cacheBytes := recordLogicalBytes(validated.candidate) + uint64(len(cacheMetadata)+32+8)
	limits := DefaultLimits()
	limits.CacheRecordCount = 1
	limits.CacheObservationCount = 1
	limits.CacheLogicalBytes = cacheBytes
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	_, err = store.RecordObservation(ctx, observation)
	require.NoError(t, err)
	var actualCacheBytes int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT (SELECT COALESCE(SUM(logical_bytes),0) FROM cache_records)+(SELECT COALESCE(SUM(logical_bytes),0) FROM cache_observations)").Scan(&actualCacheBytes))
	assert.Equal(t, int64(cacheBytes), actualCacheBytes)
	require.NoError(t, store.Close())

	limits.CacheLogicalBytes = cacheBytes - 1
	directory = t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err = OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	_, err = store.RecordObservation(ctx, observation)
	require.ErrorIs(t, err, ErrLimit)
	require.NoError(t, store.Close())

	setDigest := validated.setDigest
	var dbid [32]byte
	dbid[0] = 1
	state := stateSnapshot{}
	trace := resolvedTrace{refs: []RecordReference{validated.candidate.ref}, records: []validatedRecord{validated.candidate}, stop: "first_use"}
	next := buildFloor(dbid, f.binding, validated, state, trace, ModeFirstUse)
	body, err := makeEventBody(ModeFirstUse, "", nil, next, trace.refs, trace.stop, validated.observationDigest, setDigest)
	require.NoError(t, err)
	eventDigest := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
	next.AcceptedEventDigest = eventDigest
	encodedFloor, err := encodeFloor(next)
	require.NoError(t, err)
	eventBytes := eventLogicalBytes(body, eventDigest[:], nil, encodedFloor, string(ModeFirstUse), "", trace.stop)
	acceptedBytes := recordLogicalBytes(validated.candidate) + eventBytes
	limits = DefaultLimits()
	limits.AcceptedRecordCount = 1
	limits.AcceptedEventCount = 1
	limits.AcceptedLogicalBytes = acceptedBytes
	directory = t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err = OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	proposal, err := store.Prepare(ctx, ModeFirstUse, observation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	var actualAcceptedBytes int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT (SELECT COALESCE(SUM(logical_bytes),0) FROM accepted_records)+(SELECT COALESCE(SUM(logical_bytes),0) FROM accepted_events)").Scan(&actualAcceptedBytes))
	assert.Equal(t, int64(acceptedBytes), actualAcceptedBytes)
	require.NoError(t, store.Close())

	limits.AcceptedLogicalBytes = acceptedBytes - 1
	directory = t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err = OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	proposal, err = store.Prepare(ctx, ModeFirstUse, observation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.ErrorIs(t, err, ErrLimit)
	_, present, loadErr := store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	require.NoError(t, store.Close())
}

func TestOpenRejectsUnsafeDatabaseAndDirectoryModesWithoutRepair(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := Open(directory, f.binding)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	dbPath := filepath.Join(directory, "publication.db")
	require.NoError(t, os.Chmod(dbPath, 0o644))
	_, err = Open(directory, f.binding)
	require.ErrorIs(t, err, ErrInvalid)
	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	require.NoError(t, os.Chmod(dbPath, 0o600))
	require.NoError(t, os.Chmod(directory, 0o755))
	_, err = Open(directory, f.binding)
	require.ErrorIs(t, err, ErrInvalid)
	info, err = os.Stat(directory)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}
