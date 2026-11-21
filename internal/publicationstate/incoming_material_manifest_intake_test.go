package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/lamb-systems/dottie/internal/publication"
)

func manifestMaterialPrepare(
	t *testing.T,
	store *Store,
	mode Mode,
	observation Observation,
	input MaterialInput,
) Proposal {
	t.Helper()
	proposal, err := store.PrepareMaterial(context.Background(), mode, observation, input)
	require.NoError(t, err)
	return proposal
}

func requireManifestMaterialRowsAbsent(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
}

func TestManifestMaterialAcceptanceLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	genesisFiles := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/init.lua", content: "synthetic genesis manifest entry"},
	)
	successorFiles := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/init.lua", content: "synthetic genesis manifest entry"},
		manifestMaterialFile{path: "config/plugins.lua", content: "synthetic successor manifest entry"},
	)
	forkFiles := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/other.lua", content: "synthetic fork manifest entry"},
	)
	genesisBlock := manifestMaterialBlock(t, f.binding, 0, nil, genesisFiles)
	successorBlock := manifestMaterialBlock(t, f.binding, 1, mustRecordCID(t, genesisBlock.Raw), successorFiles)
	genesisObservation := manifestMaterialObservation(t, f.binding, genesisBlock)
	successorObservation := manifestMaterialObservation(t, f.binding, genesisObservation.Snapshots[0], successorBlock)

	proposal := manifestMaterialPrepare(t, store, ModeFirstUse, genesisObservation, manifestMaterialInput(genesisFiles))
	assert.Equal(t, ModeFirstUse, proposal.Mode)
	assert.Equal(t, WarningFirstUse, proposal.Warning)
	assert.Equal(t, "first_use", proposal.Stop)
	assert.NotEqual(t, [32]byte{}, proposal.Confirmation)

	floor, err := store.AcceptMaterialInput(
		ctx,
		ModeFirstUse,
		proposal.StateToken,
		genesisObservation,
		manifestMaterialInput(genesisFiles),
		[32]byte{1},
	)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrConsent, StageAcceptMaterial, ReasonConfirmation)
	requireManifestMaterialRowsAbsent(t, store)

	competing := manifestMaterialPrepare(t, store, ModeFirstUse, genesisObservation, manifestMaterialInput(genesisFiles))
	accepted, err := store.AcceptMaterialInput(
		ctx,
		ModeFirstUse,
		proposal.StateToken,
		genesisObservation,
		manifestMaterialInput(genesisFiles),
		proposal.Confirmation,
	)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), accepted.Revision)
	assert.Equal(t, uint64(1), accepted.Generation)

	_, err = store.AcceptMaterialInput(
		ctx,
		ModeFirstUse,
		competing.StateToken,
		genesisObservation,
		manifestMaterialInput(genesisFiles),
		competing.Confirmation,
	)
	requireErrorMetadata(t, err, ErrConsent, StageAcceptMaterial, ReasonStale)

	_, err = store.PrepareMaterial(ctx, ModeFirstUse, genesisObservation, manifestMaterialInput(genesisFiles))
	requireErrorMetadata(t, err, ErrConsent, StagePrepare, ReasonMode)

	advance := manifestMaterialPrepare(t, store, ModeAdvance, successorObservation, manifestMaterialInput(successorFiles))
	assert.Equal(t, ModeAdvance, advance.Mode)
	assert.Equal(t, "joined", advance.Stop)
	assert.Equal(t, [32]byte{}, advance.Confirmation)

	advanced, err := store.AcceptMaterialInput(
		ctx,
		ModeAdvance,
		advance.StateToken,
		successorObservation,
		manifestMaterialInput(successorFiles),
		[32]byte{},
	)
	require.NoError(t, err)
	assert.Equal(t, accepted.Revision+1, advanced.Revision)
	assert.Equal(t, accepted.Generation, advanced.Generation)
	require.NotNil(t, advanced.Manifest)
	require.Len(t, advanced.Manifest.Entries, 2)
	require.Equal(t, int64(2), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	assert.Equal(t, int64(2), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))

	current, err := store.ReadAcceptedMaterial(ctx, f.binding, advanced)
	require.NoError(t, err)
	require.Len(t, current.Entries, 2)
	assert.Equal(t, []byte("synthetic successor manifest entry"), current.Entries[1].Content)

	replay := manifestMaterialPrepare(t, store, ModeAdvance, successorObservation, manifestMaterialInput(successorFiles))
	assert.Equal(t, "same", replay.Stop)
	assert.Equal(t, [32]byte{}, replay.Confirmation)
	repeated, err := store.AcceptMaterialInput(
		ctx,
		ModeAdvance,
		replay.StateToken,
		successorObservation,
		manifestMaterialInput(successorFiles),
		[32]byte{},
	)
	require.NoError(t, err)
	assert.Equal(t, advanced, repeated)
	require.Equal(t, int64(2), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Equal(t, int64(2), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))

	forkBlock := manifestMaterialBlock(t, f.binding, 0, nil, forkFiles)
	forkObservation := manifestMaterialObservation(t, f.binding, forkBlock)
	replacement := manifestMaterialPrepare(t, store, ModeReplaceFloor, forkObservation, manifestMaterialInput(forkFiles))
	assert.Equal(t, ModeReplaceFloor, replacement.Mode)
	assert.Equal(t, WarningReplacement, replacement.Warning)
	assert.Equal(t, ReasonRollback, replacement.Reason)
	replaced, err := store.AcceptMaterialInput(
		ctx,
		ModeReplaceFloor,
		replacement.StateToken,
		forkObservation,
		manifestMaterialInput(forkFiles),
		replacement.Confirmation,
	)
	require.NoError(t, err)
	assert.Equal(t, advanced.Revision+1, replaced.Revision)
	assert.Equal(t, advanced.Generation+1, replaced.Generation)
	assert.Equal(t, forkBlock.Raw, func() []byte {
		material, readErr := store.ReadAcceptedMaterial(ctx, f.binding, replaced)
		require.NoError(t, readErr)
		return material.SnapshotRecord
	}())
}

func TestManifestMaterialAcceptsReplacementBytesOnlyWhenTheyMatchTheObservation(t *testing.T) {
	files := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/init.lua", mode: 0o600, content: "synthetic first manifest entry"},
		manifestMaterialFile{path: "config/plugins.lua", mode: 0o644, content: "synthetic second manifest entry"},
	)
	cases := []struct {
		name   string
		input  MaterialInput
		class  error
		reason Reason
	}{
		{name: "mode mismatch", class: ErrInvalid, reason: ReasonRecordSet, input: func() MaterialInput {
			input := manifestMaterialInput(files)
			input.Entries[0].Mode = 0o644
			return input
		}()},
		{name: "path mismatch", class: ErrInvalid, reason: ReasonRecordSet, input: func() MaterialInput {
			input := manifestMaterialInput(files)
			input.Entries[0].Path = "config/other.lua"
			return input
		}()},
		{name: "declared size mismatch", class: ErrInvalid, reason: ReasonRecordSet, input: func() MaterialInput {
			input := manifestMaterialInput(files)
			input.Entries[0].Size--
			return input
		}()},
		{name: "content mismatch", class: ErrInvalid, reason: ReasonRecordSet, input: func() MaterialInput {
			input := manifestMaterialInput(files)
			input.Entries[1].Content = bytes.Clone(input.Entries[1].Content)
			input.Entries[1].Content[0] ^= 0xff
			return input
		}()},
		{name: "missing entry", class: ErrInvalid, reason: ReasonRecordSet, input: func() MaterialInput {
			input := manifestMaterialInput(files)
			input.Entries = input.Entries[:1]
			return input
		}()},
		{name: "reordered entries", class: ErrInvalid, reason: ReasonRecordSet, input: func() MaterialInput {
			input := manifestMaterialInput(files)
			input.Entries[0], input.Entries[1] = input.Entries[1], input.Entries[0]
			return input
		}()},
		{
			name:   "packed payload for a manifest observation",
			class:  ErrUnsupported,
			reason: ReasonPayloadForm,
			input:  MaterialInput{Payload: []byte("synthetic packed replacement")},
		},
		{name: "mixed payload and entries", class: ErrInvalid, reason: ReasonRecordSet, input: func() MaterialInput {
			input := manifestMaterialInput(files)
			input.Payload = []byte("synthetic packed replacement")
			return input
		}()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			observation := manifestMaterialObservation(
				t,
				f.binding,
				manifestMaterialBlock(t, f.binding, 0, nil, files),
			)
			proposal := manifestMaterialPrepare(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
			floor, err := store.AcceptMaterialInput(
				ctx,
				ModeFirstUse,
				proposal.StateToken,
				observation,
				test.input,
				proposal.Confirmation,
			)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, test.class, StageInput, test.reason)
			requireManifestMaterialRowsAbsent(t, store)
			_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName))
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}

func TestPackedMaterialInputRefusesManifestEntries(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	entries := []publication.PayloadEntry{{Path: "init.lua", Mode: 0o600, Size: uint64(len(f.payload)), Content: f.payload}}
	floor, err := store.AcceptMaterialInput(
		ctx,
		ModeFirstUse,
		proposal.StateToken,
		observation,
		MaterialInput{Payload: f.payload, Entries: entries},
		proposal.Confirmation,
	)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)
	_, err = store.PrepareMaterial(ctx, ModeFirstUse, observation, MaterialInput{Entries: entries})
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)
	requireManifestMaterialRowsAbsent(t, store)
}

func TestPackedMaterialObservationStillRefusesOrdinaryManifestPreparation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := manifestMaterialFiles(t, manifestMaterialFile{path: "config/init.lua", content: "synthetic boundary manifest entry"})
	observation := manifestMaterialObservation(
		t,
		f.binding,
		manifestMaterialBlock(t, f.binding, 0, nil, files),
	)
	_, err := store.Prepare(ctx, ModeFirstUse, observation, f.payload)
	requireErrorMetadata(t, err, ErrUnsupported, StageInput, ReasonPayloadForm)
	_, err = store.Accept(ctx, ModeFirstUse, [32]byte{}, observation, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrUnsupported, StageInput, ReasonPayloadForm)
	_, err = store.AcceptMaterial(ctx, ModeFirstUse, [32]byte{}, observation, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrUnsupported, StageInput, ReasonPayloadForm)

	proposal := manifestMaterialPrepare(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
	floor, err := store.AcceptMaterialInput(
		ctx,
		ModeFirstUse,
		proposal.StateToken,
		observation,
		manifestMaterialInput(files),
		proposal.Confirmation,
	)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), floor.Revision)
}

func TestManifestMaterialEntryFaultsLeaveBoundedResidue(t *testing.T) {
	files := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/init.lua", content: "synthetic first faulted manifest entry"},
		manifestMaterialFile{path: "config/plugins.lua", content: "synthetic second faulted manifest entry"},
	)
	cases := []struct {
		name  string
		apply func(t *testing.T, store *Store, original custodyOperations, second []byte) *custodySyncObserver
	}{
		{
			name: "entry two write",
			apply: func(t *testing.T, store *Store, original custodyOperations, second []byte) *custodySyncObserver {
				t.Helper()
				writes := 0
				store.custodyOps.write = func(fd int, data []byte) (int, error) {
					if bytes.HasPrefix(data, second) {
						writes++
						return 0, unix.EIO
					}
					return original.write(fd, data)
				}
				t.Cleanup(func() { assert.Equal(t, 1, writes) })
				return nil
			},
		},
		{
			name: "entry two link",
			apply: func(t *testing.T, store *Store, original custodyOperations, _ []byte) *custodySyncObserver {
				t.Helper()
				links := 0
				store.custodyOps.link = func(fd, directoryFD int, name string) error {
					links++
					if links == 2 {
						return unix.EIO
					}
					return original.link(fd, directoryFD, name)
				}
				t.Cleanup(func() { assert.Equal(t, 2, links) })
				return nil
			},
		},
		{
			name: "entry two sync",
			apply: func(t *testing.T, store *Store, _ custodyOperations, _ []byte) *custodySyncObserver {
				t.Helper()
				return installCustodySyncObserver(t, store, custodySyncFault{
					kind: custodySyncFileKind, ordinal: 2, requireLink: true,
				})
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			observation := manifestMaterialObservation(
				t,
				f.binding,
				manifestMaterialBlock(t, f.binding, 0, nil, files),
			)
			proposal := manifestMaterialPrepare(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
			original := store.custodyOps
			t.Cleanup(func() { store.custodyOps = original })
			observer := test.apply(t, store, original, []byte(files[1].content))

			floor, err := store.AcceptMaterialInput(
				ctx,
				ModeFirstUse,
				proposal.StateToken,
				observation,
				manifestMaterialInput(files),
				proposal.Confirmation,
			)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonIO)
			assert.False(t, store.needsReadback)
			if observer != nil {
				assert.Equal(t, 1, observer.fired)
			}
			requireManifestMaterialRowsAbsent(t, store)
			requireIncomingMaterialLoadAbsent(t, ctx, store)
			firstResidue := requireIncomingMaterialOrphan(t, directory, []byte(files[0].content))

			store.custodyOps = original
			floor, err = store.AcceptMaterialInput(
				ctx,
				ModeFirstUse,
				proposal.StateToken,
				observation,
				manifestMaterialInput(files),
				proposal.Confirmation,
			)
			require.NoError(t, err)
			assert.Equal(t, uint64(1), floor.Revision)
			assert.Equal(t, int64(2), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
			adopted, err := observeAcceptedMaterialPayloadFile(
				filepath.Join(directory, payloadDirectoryName, payloadBasename([]byte(files[0].content))),
				len(files[0].content),
			)
			require.NoError(t, err)
			require.True(t, adopted.Exists)
			assert.Equal(t, firstResidue.Device, adopted.Device)
			assert.Equal(t, firstResidue.Inode, adopted.Inode)
			material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
			require.NoError(t, err)
			require.Len(t, material.Entries, 2)
		})
	}
}

func TestManifestMaterialCommitUnknownOutcomes(t *testing.T) {
	genesis := func(t *testing.T) (*Store, fixture, Observation, MaterialInput, Proposal) {
		t.Helper()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/init.lua", content: "synthetic commit manifest entry"},
		)
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, files),
		)
		input := manifestMaterialInput(files)
		proposal := manifestMaterialPrepare(t, store, ModeFirstUse, observation, input)
		return store, f, observation, input, proposal
	}

	t.Run("committed then reported unknown", func(t *testing.T) {
		ctx := context.Background()
		store, f, observation, input, proposal := genesis(t)
		originalCommit := store.commitTransaction
		t.Cleanup(func() { store.commitTransaction = originalCommit })
		commits := 0
		store.commitTransaction = func(tx *sql.Tx) error {
			commits++
			return commitThenReturnError(tx)
		}
		floor, err := store.AcceptMaterialInput(
			ctx,
			ModeFirstUse,
			proposal.StateToken,
			observation,
			input,
			proposal.Confirmation,
		)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonCommitUnknown)
		assert.Equal(t, 1, commits)
		assert.True(t, store.needsReadback)

		fenced, err := store.AcceptMaterialInput(
			ctx,
			ModeFirstUse,
			proposal.StateToken,
			observation,
			input,
			proposal.Confirmation,
		)
		assert.Equal(t, Floor{}, fenced)
		requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonCommitUnknown)
		assert.Equal(t, 1, commits)

		loaded, present, err := store.Load(ctx)
		require.NoError(t, err)
		require.True(t, present)
		assert.Equal(t, uint64(1), loaded.Revision)
		assert.False(t, store.needsReadback)
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, loaded)
		require.NoError(t, err)
		require.Len(t, material.Entries, 1)
		assert.Equal(t, []byte("synthetic commit manifest entry"), material.Entries[0].Content)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	})

	t.Run("commit failed before publication", func(t *testing.T) {
		ctx := context.Background()
		store, _, observation, input, proposal := genesis(t)
		commits := countIncomingCommits(t, store)
		installIncomingCommitFailure(t, store)

		floor, err := store.AcceptMaterialInput(
			ctx,
			ModeFirstUse,
			proposal.StateToken,
			observation,
			input,
			proposal.Confirmation,
		)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonCommitUnknown)
		assert.Equal(t, 1, *commits)
		assert.True(t, store.needsReadback)
		requireManifestMaterialRowsAbsent(t, store)

		removeIncomingCommitFailure(t, store)
		probe, err := store.AcceptMaterialInput(
			ctx,
			ModeFirstUse,
			proposal.StateToken,
			observation,
			input,
			proposal.Confirmation,
		)
		assert.Equal(t, Floor{}, probe)
		requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonCommitUnknown)
		assert.Equal(t, 1, *commits)
		requireManifestMaterialRowsAbsent(t, store)

		requireIncomingMaterialLoadAbsent(t, ctx, store)
		assert.False(t, store.needsReadback)
		floor, err = store.AcceptMaterialInput(
			ctx,
			ModeFirstUse,
			proposal.StateToken,
			observation,
			input,
			proposal.Confirmation,
		)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), floor.Revision)
		assert.Equal(t, 2, *commits)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	})
}

type manifestReplaySetup struct {
	store       *Store
	directory   string
	observation Observation
	input       MaterialInput
	floor       Floor
	target      []byte
}

func manifestReplayIncomingOwner(t *testing.T) manifestReplaySetup {
	t.Helper()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	files := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/init.lua", content: "synthetic replay first entry"},
		manifestMaterialFile{path: "config/plugins.lua", content: "synthetic replay second entry"},
	)
	observation := manifestMaterialObservation(
		t,
		f.binding,
		manifestMaterialBlock(t, f.binding, 0, nil, files),
	)
	floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
	return manifestReplaySetup{
		store:       store,
		directory:   directory,
		observation: observation,
		input:       manifestMaterialInput(files),
		floor:       floor,
		target:      []byte(files[1].content),
	}
}

func manifestReplayFinalizedOwner(t *testing.T) manifestReplaySetup {
	t.Helper()
	manifestFixtureValue := manifestFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: manifestFixtureValue.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	review := attemptReview()
	submitted := submitManifestAttempt(t, store, manifestFixtureValue, manifestFixtureValue.view(), review)
	finalized, err := store.FinalizeAttempt(
		context.Background(),
		submitted.ID,
		submitted.StateDigest,
		manifestFixtureValue.currentView(),
	)
	require.NoError(t, err)
	return manifestReplaySetup{
		store:     store,
		directory: directory,
		observation: manifestMaterialObservation(
			t,
			manifestFixtureValue.binding,
			SnapshotBlock{Key: manifestFixtureValue.key, Raw: manifestFixtureValue.raw},
		),
		input:  MaterialInput{Entries: manifestFixtureValue.entries},
		floor:  finalized.Floor,
		target: manifestFixtureValue.entries[1].Content,
	}
}

func TestManifestMaterialReplayVerifiesOwnershipThroughBothOwners(t *testing.T) {
	damageCases := []struct {
		name   string
		damage func(t *testing.T, path string, target []byte)
		reason Reason
	}{
		{
			name: "missing",
			damage: func(t *testing.T, path string, _ []byte) {
				t.Helper()
				require.NoError(t, os.Remove(path))
			},
			reason: ReasonMaterialMissing,
		},
		{
			name: "corrupt",
			damage: func(t *testing.T, path string, target []byte) {
				t.Helper()
				require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(target)), 0o600))
			},
			reason: ReasonMaterialCorrupt,
		},
		{
			name: "unsafe",
			damage: func(t *testing.T, path string, target []byte) {
				t.Helper()
				require.NoError(t, os.Truncate(path, int64(len(target))-1))
			},
			reason: ReasonMaterialUnsafe,
		},
	}
	owners := []struct {
		name  string
		setup func(t *testing.T) manifestReplaySetup
		stop  string
	}{
		{name: "incoming owner", setup: manifestReplayIncomingOwner, stop: "same"},
		{name: "finalized owner", setup: manifestReplayFinalizedOwner, stop: "same"},
	}
	for _, owner := range owners {
		for _, damage := range damageCases {
			t.Run(owner.name+" "+damage.name, func(t *testing.T) {
				ctx := context.Background()
				setup := owner.setup(t)
				replay := manifestMaterialPrepare(t, setup.store, ModeAdvance, setup.observation, setup.input)
				assert.Equal(t, owner.stop, replay.Stop)
				repeated, err := setup.store.AcceptMaterialInput(
					ctx,
					ModeAdvance,
					replay.StateToken,
					setup.observation,
					setup.input,
					[32]byte{},
				)
				require.NoError(t, err)
				assert.Equal(t, setup.floor, repeated)
				require.Equal(t, int64(1), b8Count(t, ctx, setup.store.conn, "SELECT COUNT(*) FROM accepted_events"))

				path := filepath.Join(setup.directory, payloadDirectoryName, payloadBasename(setup.target))
				damage.damage(t, path, setup.target)
				repeated, err = setup.store.AcceptMaterialInput(
					ctx,
					ModeAdvance,
					replay.StateToken,
					setup.observation,
					setup.input,
					[32]byte{},
				)
				assert.Equal(t, Floor{}, repeated)
				requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, damage.reason)
				loaded, present, err := setup.store.Load(ctx)
				require.NoError(t, err)
				require.True(t, present)
				assert.Equal(t, setup.floor, loaded)
				require.Equal(t, int64(1), b8Count(t, ctx, setup.store.conn, "SELECT COUNT(*) FROM accepted_events"))
			})
		}
	}

	t.Run("finalized owner refuses caller bytes that contradict custody", func(t *testing.T) {
		ctx := context.Background()
		setup := manifestReplayFinalizedOwner(t)
		replay := manifestMaterialPrepare(t, setup.store, ModeAdvance, setup.observation, setup.input)
		target := filepath.Join(setup.directory, payloadDirectoryName, payloadBasename(setup.target))
		require.NoError(t, os.WriteFile(target, bytes.Repeat([]byte{'x'}, len(setup.target)), 0o600))
		repaired := MaterialInput{Entries: append([]publication.PayloadEntry(nil), setup.input.Entries...)}
		repaired.Entries[1].Content = []byte("synthetic repaired manifest entry")
		repaired.Entries[1].Size = uint64(len(repaired.Entries[1].Content))
		repeated, err := setup.store.AcceptMaterialInput(
			ctx,
			ModeAdvance,
			replay.StateToken,
			setup.observation,
			repaired,
			[32]byte{},
		)
		assert.Equal(t, Floor{}, repeated)
		requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)
		damaged, readErr := os.ReadFile(target)
		require.NoError(t, readErr)
		assert.Equal(t, bytes.Repeat([]byte{'x'}, len(setup.target)), damaged)
	})
}

func TestManifestMaterialBatchCapacity(t *testing.T) {
	t.Run("shared CID counts one object", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		attemptLimits := DefaultAttemptLimits()
		attemptLimits.ManagedObjects = 1
		store, _ := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/private.lua", mode: 0o600, content: "synthetic shared capacity content"},
			manifestMaterialFile{path: "config/shared.lua", mode: 0o644, content: "synthetic shared capacity content"},
		)
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, files),
		)
		floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
		require.NotNil(t, floor.Manifest)
		require.Len(t, floor.Manifest.Entries, 2)
		assert.Equal(t, floor.Manifest.Entries[0].CID, floor.Manifest.Entries[1].CID)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
		require.NoError(t, err)
		require.Len(t, material.Entries, 2)
	})

	t.Run("distinct CID over the object cap", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		attemptLimits := DefaultAttemptLimits()
		attemptLimits.ManagedObjects = 1
		store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/init.lua", content: "synthetic distinct capacity alpha"},
			manifestMaterialFile{path: "config/plugins.lua", content: "synthetic distinct capacity beta"},
		)
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, files),
		)
		_, err := store.PrepareMaterial(ctx, ModeFirstUse, observation, manifestMaterialInput(files))
		requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
		floor, err := store.AcceptMaterialInput(
			ctx,
			ModeFirstUse,
			[32]byte{},
			observation,
			manifestMaterialInput(files),
			[32]byte{},
		)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
		requireManifestMaterialRowsAbsent(t, store)
		_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName))
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("aggregate bytes exact boundary", func(t *testing.T) {
		files := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/init.lua", content: "synthetic aggregate boundary alpha"},
			manifestMaterialFile{path: "config/plugins.lua", content: "synthetic aggregate boundary beta"},
		)
		total := uint64(len(files[0].content) + len(files[1].content))
		for _, test := range []struct {
			name       string
			custody    uint64
			acceptance bool
		}{
			{name: "exact", custody: total, acceptance: true},
			{name: "one byte short", custody: total - 1, acceptance: false},
		} {
			t.Run(test.name, func(t *testing.T) {
				ctx := context.Background()
				f := newFixture(t, BackendPublicRepo)
				f.appendRecord(t, 0)
				attemptLimits := DefaultAttemptLimits()
				attemptLimits.CustodyBytes = test.custody
				store, _ := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
				observation := manifestMaterialObservation(
					t,
					f.binding,
					manifestMaterialBlock(t, f.binding, 0, nil, files),
				)
				input := manifestMaterialInput(files)
				if !test.acceptance {
					_, err := store.PrepareMaterial(ctx, ModeFirstUse, observation, input)
					requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
					floor, err := store.AcceptMaterialInput(
						ctx,
						ModeFirstUse,
						[32]byte{},
						observation,
						input,
						[32]byte{},
					)
					assert.Equal(t, Floor{}, floor)
					requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
					requireManifestMaterialRowsAbsent(t, store)
					return
				}
				proposal := manifestMaterialPrepare(t, store, ModeFirstUse, observation, input)
				floor, err := store.AcceptMaterialInput(
					ctx,
					ModeFirstUse,
					proposal.StateToken,
					observation,
					input,
					proposal.Confirmation,
				)
				require.NoError(t, err)
				assert.Equal(t, uint64(1), floor.Revision)
			})
		}
	})

	t.Run("successor distinct CID over the object cap", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		attemptLimits := DefaultAttemptLimits()
		attemptLimits.ManagedObjects = 1
		store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		genesisFiles := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/init.lua", content: "synthetic catalogued capacity alpha"},
		)
		successorFiles := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/plugins.lua", content: "synthetic catalogued capacity beta"},
		)
		genesisBlock := manifestMaterialBlock(t, f.binding, 0, nil, genesisFiles)
		genesisObservation := manifestMaterialObservation(t, f.binding, genesisBlock)
		accepted := manifestMaterialAccept(t, store, ModeFirstUse, genesisObservation, manifestMaterialInput(genesisFiles))
		successorBlock := manifestMaterialBlock(t, f.binding, 1, mustRecordCID(t, genesisBlock.Raw), successorFiles)
		successorObservation := manifestMaterialObservation(t, f.binding, genesisBlock, successorBlock)
		proposal := manifestMaterialPrepare(t, store, ModeAdvance, successorObservation, manifestMaterialInput(successorFiles))
		assert.Equal(t, "joined", proposal.Stop)
		floor, err := store.AcceptMaterialInput(
			ctx,
			ModeAdvance,
			proposal.StateToken,
			successorObservation,
			manifestMaterialInput(successorFiles),
			[32]byte{},
		)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrLimit, StageAcceptMaterial, ReasonCapacity)
		loaded, present, err := store.Load(ctx)
		require.NoError(t, err)
		require.True(t, present)
		assert.Equal(t, accepted, loaded)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, payloadBasename([]byte(genesisFiles[0].content)), entries[0].Name())
	})

	t.Run("entry count exact boundary", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := make([]manifestMaterialFile, 0, publication.MaxSnapshotEntries)
		for index := range publication.MaxSnapshotEntries {
			files = append(files, manifestMaterialFile{
				path:    "config/entry-" + string(rune('a'+index%26)) + "-" + string(rune('0'+index/26)) + ".lua",
				content: "synthetic bounded manifest entry " + string(rune('a'+index%26)) + string(rune('0'+index/26)),
			})
		}
		sorted := manifestMaterialFiles(t, files...)
		require.Len(t, sorted, publication.MaxSnapshotEntries)
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, sorted),
		)
		floor := manifestMaterialAccept(t, store, ModeFirstUse, observation, manifestMaterialInput(sorted))
		require.NotNil(t, floor.Manifest)
		require.Len(t, floor.Manifest.Entries, publication.MaxSnapshotEntries)
		require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
		require.NoError(t, err)
		require.Len(t, material.Entries, publication.MaxSnapshotEntries)
	})

	t.Run("filesystem residue joins the batch", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		attemptLimits := DefaultAttemptLimits()
		attemptLimits.ManagedObjects = 2
		store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		files := manifestMaterialFiles(t,
			manifestMaterialFile{path: "config/init.lua", content: "synthetic residue capacity alpha"},
			manifestMaterialFile{path: "config/plugins.lua", content: "synthetic residue capacity beta"},
		)
		residue := []byte("synthetic unrelated residue object")
		incomingCustodyPlaceOrphan(t, directory, residue)
		observation := manifestMaterialObservation(
			t,
			f.binding,
			manifestMaterialBlock(t, f.binding, 0, nil, files),
		)
		proposal := manifestMaterialPrepare(t, store, ModeFirstUse, observation, manifestMaterialInput(files))
		floor, err := store.AcceptMaterialInput(
			ctx,
			ModeFirstUse,
			proposal.StateToken,
			observation,
			manifestMaterialInput(files),
			proposal.Confirmation,
		)
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrLimit, StageAcceptMaterial, ReasonCapacity)
		requireManifestMaterialRowsAbsent(t, store)
		entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, payloadBasename(residue), entries[0].Name())
	})
}

func TestManifestSnapshotEncodingRefusesASixtyFifthEntry(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	entries := make([]publication.SnapshotEntry, 0, publication.MaxSnapshotEntries+1)
	for index := range publication.MaxSnapshotEntries + 1 {
		content := []byte(fmt.Sprintf("synthetic entry %03d", index))
		cid, err := publication.RawPayloadCID(content)
		require.NoError(t, err)
		entries = append(entries, publication.SnapshotEntry{
			Path: fmt.Sprintf("config/entry-%03d.lua", index),
			Mode: 0o600, Size: uint64(len(content)), Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{CID: cid, Size: uint64(len(content)), MIMEType: publication.BlobMIMEType},
		})
	}
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault,
		PublicationSeq: 0, Parent: nil, Entries: entries,
	}
	binary.BigEndian.PutUint64(record.PublicationID[8:], 1)
	raw, err := publication.EncodeSnapshot(record)
	require.Error(t, err)
	assert.Nil(t, raw)
	require.ErrorIs(t, err, publication.ErrInvalidRecord)
	var violation *publication.ViolationError
	require.ErrorAs(t, err, &violation)
	assert.Equal(t, "entries", violation.Field())
	assert.Equal(t, "count", violation.Reason())
	requireManifestMaterialRowsAbsent(t, store)
}

func TestManifestMaterialRefusesOverLimitEntriesBeforeHashing(t *testing.T) {
	content := "synthetic shared over-limit entry"
	files := manifestMaterialFiles(t,
		manifestMaterialFile{path: "config/private.lua", mode: 0o600, content: content},
		manifestMaterialFile{path: "config/shared.lua", mode: 0o644, content: content},
	)
	attemptLimits := DefaultAttemptLimits()
	attemptLimits.ManagedObjects = 1
	attemptLimits.CustodyBytes = uint64(len(content))
	cases := []struct {
		name  string
		input MaterialInput
	}{
		{name: "matching entries", input: manifestMaterialInput(files)},
		{name: "entries whose bytes contradict the observation", input: func() MaterialInput {
			input := manifestMaterialInput(files)
			for index := range input.Entries {
				input.Entries[index].Content = bytes.Repeat([]byte{'x'}, len(content))
			}
			return input
		}()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			block := manifestMaterialBlock(t, f.binding, 0, nil, files)
			record, err := publication.DecodeSnapshot(block.Raw)
			require.NoError(t, err)
			require.Len(t, record.Entries, 2)
			require.Equal(t, record.Entries[0].Blob.CID, record.Entries[1].Blob.CID)
			observation := manifestMaterialObservation(t, f.binding, block)

			_, err = store.PrepareMaterial(ctx, ModeFirstUse, observation, test.input)
			requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
			floor, err := store.AcceptMaterialInput(
				ctx,
				ModeFirstUse,
				[32]byte{},
				observation,
				test.input,
				[32]byte{},
			)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
			requireManifestMaterialRowsAbsent(t, store)
			_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName))
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}
