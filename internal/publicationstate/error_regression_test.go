package publicationstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilesystemCanaryIsRedactedOnUnsafeSymlinkRefusal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "filesystem-path-canary-7f3a")
	require.NoError(t, os.Mkdir(root, 0o700))
	target := filepath.Join(root, "target-name-canary-9a21")
	targetBytes := []byte("filesystem-target-content-canary")
	require.NoError(t, os.WriteFile(target, targetBytes, 0o600))
	info, err := os.Stat(target)
	require.NoError(t, err)
	targetMode := info.Mode().Perm()
	publicationPath := filepath.Join(root, "publication.db")
	require.NoError(t, os.Symlink(target, publicationPath))
	f := newFixture(t, BackendPublicRepo)
	require.True(t, strings.Contains(root, "filesystem-path-canary-7f3a"))
	require.True(t, strings.Contains(target, "target-name-canary-9a21"))
	store, err := Open(root, f.binding)
	require.Nil(t, store)
	requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
	assertErrorRedacted(t, err, "filesystem-path-canary-7f3a", "target-name-canary-9a21", "filesystem-target-content-canary")
	after, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, targetBytes, after)
	afterInfo, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, targetMode, afterInfo.Mode().Perm())
	_, err = os.Lstat(filepath.Join(root, "publication.db.lock"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func assertErrorRedacted(t *testing.T, err error, canaries ...string) {
	t.Helper()
	require.Error(t, err)
	seen := map[error]bool{}
	var visit func(error, int)
	visit = func(node error, depth int) {
		require.Less(t, depth, 32)
		if node == nil {
			return
		}
		if comparableError(node) {
			if seen[node] {
				return
			}
			seen[node] = true
		}
		for _, rendered := range []string{node.Error(), fmt.Sprintf("%+v", node), fmt.Sprintf("%#v", node)} {
			for _, canary := range canaries {
				assert.NotContains(t, rendered, canary)
			}
		}
		if many, ok := node.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				visit(child, depth+1)
			}
			return
		}
		if one, ok := node.(interface{ Unwrap() error }); ok {
			visit(one.Unwrap(), depth+1)
		}
	}
	visit(err, 0)
}

func comparableError(err error) bool {
	defer func() { _ = recover() }()
	_ = map[error]bool{err: true}
	return true
}

func TestMalformedCachedRecordReturnsClosedCorruptError(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	store, _ := newStore(t, f)
	defer store.Close()
	initial := f.observation(1)
	proposal := prepareFirstUse(t, store, initial, f.payload)
	_, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, initial, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	bridge := f.observation(2)
	bridge.Snapshots = bridge.Snapshots[1:]
	_, err = store.RecordObservation(ctx, bridge)
	require.NoError(t, err)
	cid, err := publication.RecordCID(f.blocks[1].Raw)
	require.NoError(t, err)
	const canary = "private-cache-sequence-canary"
	_, err = store.conn.ExecContext(ctx, "UPDATE cache_records SET sequence=? WHERE cid=?", canary, cid)
	require.NoError(t, err)
	candidate := f.observation(3)
	candidate.Snapshots = candidate.Snapshots[2:]
	_, err = store.Prepare(ctx, ModeAdvance, candidate, f.payload)
	requireErrorMetadata(t, err, ErrSchema, StagePrepare, ReasonCorrupt)
	assert.NotContains(t, err.Error(), canary)
	assert.NotContains(t, fmt.Sprintf("%+v", err), canary)
	for current := error(err); current != nil; current = errors.Unwrap(current) {
		assert.NotContains(t, current.Error(), canary)
	}
	assert.Nil(t, errors.Unwrap(errors.Unwrap(err)))
}

func TestCanceledPublicCallsExposeClosedStageAndSafeIdentity(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	observation := f.observation(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := store.Load(ctx)
	requireErrorMetadata(t, err, ErrStorage, StageLoad, ReasonCanceled)
	require.ErrorIs(t, err, context.Canceled)
	_, err = store.RecordObservation(ctx, observation)
	requireErrorMetadata(t, err, ErrStorage, StageObserve, ReasonCanceled)
	require.ErrorIs(t, err, context.Canceled)
	_, err = store.Prepare(ctx, ModeFirstUse, observation, f.payload)
	requireErrorMetadata(t, err, ErrStorage, StagePrepare, ReasonCanceled)
	require.ErrorIs(t, err, context.Canceled)
	_, err = store.Accept(ctx, ModeFirstUse, [32]byte{}, observation, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonCanceled)
	require.ErrorIs(t, err, context.Canceled)
	_, err = store.History(ctx, 0, 1)
	requireErrorMetadata(t, err, ErrStorage, StageHistory, ReasonCanceled)
	require.ErrorIs(t, err, context.Canceled)
	commitCtx, commitCancel := context.WithCancel(context.Background())
	err = store.withTx(commitCtx, StageAccept, func(*sql.Tx) error { commitCancel(); return nil })
	requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonCanceled)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, errors.Unwrap(errors.Unwrap(err)))
}

func TestDeferredCommitFailureRequiresReadbackAndKeepsCommittedFloor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	defer store.Close()
	initial := f.observation(1)
	first := prepareFirstUse(t, store, initial, f.payload)
	old, err := store.Accept(ctx, ModeFirstUse, first.StateToken, initial, f.payload, first.Confirmation)
	require.NoError(t, err)
	for _, statement := range []string{"CREATE TEMP TABLE commit_probe_parent(id INTEGER PRIMARY KEY)", "CREATE TEMP TABLE commit_probe_child(id INTEGER REFERENCES commit_probe_parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TEMP TRIGGER commit_probe_failure AFTER INSERT ON main.accepted_events BEGIN INSERT INTO commit_probe_child(id) VALUES(new.revision); END"} {
		_, err = store.conn.ExecContext(ctx, statement)
		require.NoError(t, err)
	}
	candidate := f.observation(2)
	proposal, err := store.Prepare(ctx, ModeAdvance, candidate, f.payload)
	require.NoError(t, err)
	result, err := store.Accept(ctx, ModeAdvance, proposal.StateToken, candidate, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonCommitUnknown)
	assert.Equal(t, Floor{}, result)
	assert.True(t, store.needsReadback)
	_, err = store.Prepare(ctx, ModeAdvance, candidate, f.payload)
	requireErrorMetadata(t, err, ErrStorage, StagePrepare, ReasonCommitUnknown)
	result, err = store.Accept(ctx, ModeAdvance, proposal.StateToken, candidate, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonCommitUnknown)
	assert.Equal(t, Floor{}, result)
	readback, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, old, readback)
	assert.False(t, store.needsReadback)
	continued, err := store.Prepare(ctx, ModeAdvance, candidate, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "joined", continued.Stop)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	persisted, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, old, persisted)
}
