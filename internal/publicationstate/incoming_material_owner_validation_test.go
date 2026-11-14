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

type incomingNoOpState struct {
	rows       map[string]string
	references [][]any
	mutation   uint64
	durable    uint64
}

func incomingNoOpCapture(t *testing.T, ctx context.Context, store *Store) incomingNoOpState {
	t.Helper()
	return incomingNoOpState{
		rows:       readAttemptLogicalRows(t, store),
		references: b8IncomingRows(t, ctx, store.conn),
		mutation:   store.attemptMutationRevision,
		durable:    intakeDurableMutation(t, ctx, store),
	}
}

func requireIncomingNoOpUnchanged(t *testing.T, ctx context.Context, store *Store, accepted Floor, state incomingNoOpState) {
	t.Helper()
	require.Equal(t, state.rows, readAttemptLogicalRows(t, store))
	require.Equal(t, state.references, b8IncomingRows(t, ctx, store.conn))
	assert.Equal(t, state.mutation, store.attemptMutationRevision)
	assert.Equal(t, state.durable, intakeDurableMutation(t, ctx, store))
	assert.False(t, store.needsReadback)
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, accepted, loaded)
}

func incomingNoOpAcceptedMaterial(t *testing.T) (*Store, fixture, string, Floor, Proposal) {
	t.Helper()
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	observation := f.observation(1)
	first := prepareFirstUse(t, store, observation, f.payload)
	accepted, err := store.acceptMaterial(ctx, ModeFirstUse, first.StateToken, observation, f.payload, first.Confirmation)
	require.NoError(t, err)
	proposal, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	require.Equal(t, "same", proposal.Stop)
	return store, f, directory, accepted, proposal
}

func incomingFinalizedNoOpMaterial(t *testing.T) (*Store, fixture, string, Finalization, Proposal) {
	t.Helper()
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	_, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
	observation := f.observation(1)
	proposal, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	require.Equal(t, "same", proposal.Stop)
	return store, f, directory, finalized, proposal
}

func incomingNoOpIntake(ctx context.Context, store *Store, f fixture, proposal Proposal) (Floor, error) {
	return store.acceptMaterial(ctx, ModeAdvance, proposal.StateToken, f.observation(1), f.payload, [32]byte{})
}

func TestAcceptMaterialNoOpValidatesSelectedBytes(t *testing.T) {
	t.Run("healthy no-op", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, accepted, proposal := incomingNoOpAcceptedMaterial(t)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		require.NoError(t, err)
		assert.Equal(t, accepted, floor)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		assert.False(t, store.needsReadback)
		loaded, present, err := store.Load(ctx)
		require.NoError(t, err)
		require.True(t, present)
		assert.Equal(t, accepted, loaded)
		file, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload)), len(f.payload))
		require.NoError(t, err)
		require.True(t, file.Exists)
		assert.Equal(t, f.payload, file.Bytes)
	})

	t.Run("missing selected file", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, accepted, proposal := incomingNoOpAcceptedMaterial(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
		t.Cleanup(func() { assert.NoError(t, os.WriteFile(path, f.payload, 0o600)) })
		require.NoError(t, os.Remove(path))
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialMissing)
		requireIncomingNoOpUnchanged(t, ctx, store, accepted, state)
		_, statErr := os.Lstat(path)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
		entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("same-size corrupt file", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, accepted, proposal := incomingNoOpAcceptedMaterial(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
		corrupt := bytes.Clone(f.payload)
		corrupt[0] ^= 0xff
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		require.NoError(t, err)
		written, writeErr := file.WriteAt(corrupt[:1], 0)
		syncErr := file.Sync()
		closeErr := file.Close()
		require.NoError(t, writeErr)
		require.Equal(t, 1, written)
		require.NoError(t, syncErr)
		require.NoError(t, closeErr)
		damaged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, damaged.Exists)
		assert.Equal(t, corrupt, damaged.Bytes)
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialCorrupt)
		requireIncomingNoOpUnchanged(t, ctx, store, accepted, state)
		unchanged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, unchanged.Exists)
		assert.Equal(t, damaged, unchanged)
	})

	t.Run("unsafe selected mode", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, accepted, proposal := incomingNoOpAcceptedMaterial(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
		t.Cleanup(func() { assert.NoError(t, os.Chmod(path, 0o600)) })
		require.NoError(t, os.Chmod(path, 0o644))
		damaged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, damaged.Exists)
		assert.Equal(t, uint32(0o644), damaged.Mode&0o777)
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialUnsafe)
		requireIncomingNoOpUnchanged(t, ctx, store, accepted, state)
		unchanged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, unchanged.Exists)
		assert.Equal(t, damaged, unchanged)
		assert.Equal(t, uint32(0o644), unchanged.Mode&0o777)
	})

	t.Run("linked selected object", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, accepted, proposal := incomingNoOpAcceptedMaterial(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
		secondLink := filepath.Join(t.TempDir(), "second-link")
		require.NoError(t, os.Link(path, secondLink))
		t.Cleanup(func() { assert.NoError(t, os.Remove(secondLink)) })
		damaged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, damaged.Exists)
		require.Equal(t, uint64(2), damaged.Nlink)
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialUnsafe)
		requireIncomingNoOpUnchanged(t, ctx, store, accepted, state)
		unchanged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, unchanged.Exists)
		assert.Equal(t, damaged, unchanged)
		require.Equal(t, uint64(2), unchanged.Nlink)
	})

	t.Run("truncated selected file", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, accepted, proposal := incomingNoOpAcceptedMaterial(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
		t.Cleanup(func() { assert.NoError(t, os.WriteFile(path, f.payload, 0o600)) })
		truncated := f.payload[:len(f.payload)-1]
		require.NoError(t, os.WriteFile(path, truncated, 0o600))
		damaged, err := observeAcceptedMaterialPayloadFile(path, len(truncated))
		require.NoError(t, err)
		require.True(t, damaged.Exists)
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialUnsafe)
		requireIncomingNoOpUnchanged(t, ctx, store, accepted, state)
		unchanged, err := observeAcceptedMaterialPayloadFile(path, len(truncated))
		require.NoError(t, err)
		require.True(t, unchanged.Exists)
		assert.Equal(t, damaged, unchanged)
		assert.Equal(t, truncated, unchanged.Bytes)
	})
}

func TestAcceptMaterialNoOpValidatesFinalizedOwnerBytes(t *testing.T) {
	t.Run("healthy no-op", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, finalized, proposal := incomingFinalizedNoOpMaterial(t)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		require.NoError(t, err)
		assert.Equal(t, finalized.Floor, floor)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		file, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload)), len(f.payload))
		require.NoError(t, err)
		require.True(t, file.Exists)
		assert.Equal(t, f.payload, file.Bytes)
	})

	t.Run("missing selected file", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, finalized, proposal := incomingFinalizedNoOpMaterial(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
		t.Cleanup(func() { assert.NoError(t, os.WriteFile(path, f.payload, 0o600)) })
		require.NoError(t, os.Remove(path))
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialMissing)
		requireIncomingNoOpUnchanged(t, ctx, store, finalized.Floor, state)
		_, statErr := os.Lstat(path)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
		entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("same-size corrupt file", func(t *testing.T) {
		ctx := context.Background()
		store, f, directory, finalized, proposal := incomingFinalizedNoOpMaterial(t)
		path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
		corrupt := bytes.Clone(f.payload)
		corrupt[0] ^= 0xff
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		require.NoError(t, err)
		written, writeErr := file.WriteAt(corrupt[:1], 0)
		syncErr := file.Sync()
		closeErr := file.Close()
		require.NoError(t, writeErr)
		require.Equal(t, 1, written)
		require.NoError(t, syncErr)
		require.NoError(t, closeErr)
		damaged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, damaged.Exists)
		assert.Equal(t, corrupt, damaged.Bytes)
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialCorrupt)
		requireIncomingNoOpUnchanged(t, ctx, store, finalized.Floor, state)
		unchanged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, unchanged.Exists)
		assert.Equal(t, damaged, unchanged)
	})
}

func TestAcceptMaterialNoOpDirectoryValidation(t *testing.T) {
	t.Run("healthy after reopen", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		observation := f.observation(1)
		first := prepareFirstUse(t, store, observation, f.payload)
		accepted, err := store.acceptMaterial(ctx, ModeFirstUse, first.StateToken, observation, f.payload, first.Confirmation)
		require.NoError(t, err)
		require.GreaterOrEqual(t, store.payloadFD, 0)
		require.NoError(t, store.Close())

		reopened, err := Open(directory, f.binding)
		require.NoError(t, err)
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NotNil(t, reopened)
		require.Equal(t, -1, reopened.payloadFD)
		proposal, err := reopened.Prepare(ctx, ModeAdvance, observation, f.payload)
		require.NoError(t, err)
		require.Equal(t, "same", proposal.Stop)
		require.Equal(t, -1, reopened.payloadFD)

		floor, err := reopened.acceptMaterial(ctx, ModeAdvance, proposal.StateToken, observation, f.payload, [32]byte{})
		require.NoError(t, err)
		assert.Equal(t, accepted, floor)
		require.GreaterOrEqual(t, reopened.payloadFD, 0)
		require.Equal(t, int64(1), b8Count(t, ctx, reopened.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		require.Equal(t, int64(1), b8Count(t, ctx, reopened.conn, "SELECT COUNT(*) FROM payload_objects"))
		material, err := reopened.ReadAcceptedMaterial(ctx, f.binding, floor)
		require.NoError(t, err)
		assert.Equal(t, floor, material.Floor)
		assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
		assert.Equal(t, f.payload, material.Payload)
	})

	t.Run("pinned directory replaced", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		observation := f.observation(1)
		first := prepareFirstUse(t, store, observation, f.payload)
		accepted, err := store.acceptMaterial(ctx, ModeFirstUse, first.StateToken, observation, f.payload, first.Confirmation)
		require.NoError(t, err)
		require.GreaterOrEqual(t, store.payloadFD, 0)
		proposal, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
		require.NoError(t, err)
		require.Equal(t, "same", proposal.Stop)

		payloadDirectory := filepath.Join(directory, payloadDirectoryName)
		heldDirectory := filepath.Join(directory, "payloads-held")
		require.NoError(t, os.Rename(payloadDirectory, heldDirectory))
		t.Cleanup(func() {
			assert.NoError(t, os.RemoveAll(payloadDirectory))
			assert.NoError(t, os.Rename(heldDirectory, payloadDirectory))
		})
		require.NoError(t, os.Mkdir(payloadDirectory, 0o700))
		name := payloadBasename(f.payload)
		held, err := observeAcceptedMaterialPayloadFile(filepath.Join(heldDirectory, name), len(f.payload))
		require.NoError(t, err)
		require.True(t, held.Exists)
		state := incomingNoOpCapture(t, ctx, store)

		floor, err := incomingNoOpIntake(ctx, store, f, proposal)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonIO)
		requireIncomingNoOpUnchanged(t, ctx, store, accepted, state)

		replaced, err := os.ReadDir(payloadDirectory)
		require.NoError(t, err)
		assert.Empty(t, replaced)
		kept, err := os.ReadDir(heldDirectory)
		require.NoError(t, err)
		require.Len(t, kept, 1)
		assert.Equal(t, name, kept[0].Name())
		unchanged, err := observeAcceptedMaterialPayloadFile(filepath.Join(heldDirectory, name), len(f.payload))
		require.NoError(t, err)
		require.True(t, unchanged.Exists)
		assert.Equal(t, held, unchanged)
		require.GreaterOrEqual(t, store.payloadFD, 0)
	})

	t.Run("absent payload directory", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		observation := f.observation(1)
		first := prepareFirstUse(t, store, observation, f.payload)
		accepted, err := store.acceptMaterial(ctx, ModeFirstUse, first.StateToken, observation, f.payload, first.Confirmation)
		require.NoError(t, err)
		require.GreaterOrEqual(t, store.payloadFD, 0)
		require.NoError(t, store.Close())

		payloadDirectory := filepath.Join(directory, payloadDirectoryName)
		require.NoError(t, os.RemoveAll(payloadDirectory))

		reopened, err := Open(directory, f.binding)
		require.NoError(t, err)
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NotNil(t, reopened)
		require.Equal(t, -1, reopened.payloadFD)
		proposal, err := reopened.Prepare(ctx, ModeAdvance, observation, f.payload)
		require.NoError(t, err)
		require.Equal(t, "same", proposal.Stop)
		state := incomingNoOpCapture(t, ctx, reopened)

		floor, err := reopened.acceptMaterial(ctx, ModeAdvance, proposal.StateToken, observation, f.payload, [32]byte{})
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialMissing)
		requireIncomingNoOpUnchanged(t, ctx, reopened, accepted, state)
		_, statErr := os.Lstat(payloadDirectory)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})
}

func TestAcceptMaterialAttachmentPathUnchanged(t *testing.T) {
	t.Run("attaches new payload", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		accepted := incomingMaterialFirstUse(t, store, f)
		unowned, err := store.ReadAcceptedMaterial(ctx, f.binding, accepted)
		assert.Equal(t, AcceptedMaterial{}, unowned)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)

		observation := f.observation(1)
		proposal, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
		require.NoError(t, err)
		require.Equal(t, "same", proposal.Stop)
		floor, err := store.acceptMaterial(ctx, ModeAdvance, proposal.StateToken, observation, f.payload, [32]byte{})
		require.NoError(t, err)
		assert.Equal(t, accepted, floor)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		file, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload)), len(f.payload))
		require.NoError(t, err)
		require.True(t, file.Exists)
		assert.Equal(t, f.payload, file.Bytes)
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
		require.NoError(t, err)
		assert.Equal(t, floor, material.Floor)
		assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
		assert.Equal(t, f.payload, material.Payload)
	})

	t.Run("refuses corrupt orphan", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		name := incomingCustodyPlaceOrphan(t, directory, f.payload)
		path := filepath.Join(directory, payloadDirectoryName, name)
		corrupt := bytes.Clone(f.payload)
		corrupt[0] ^= 0xff
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		require.NoError(t, err)
		written, writeErr := file.WriteAt(corrupt[:1], 0)
		syncErr := file.Sync()
		closeErr := file.Close()
		require.NoError(t, writeErr)
		require.Equal(t, 1, written)
		require.NoError(t, syncErr)
		require.NoError(t, closeErr)
		observation := f.observation(1)
		proposal := prepareFirstUse(t, store, observation, f.payload)

		floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonMaterialCorrupt)
		require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
		require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		damaged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
		require.NoError(t, err)
		require.True(t, damaged.Exists)
		assert.Equal(t, corrupt, damaged.Bytes)
	})
}
