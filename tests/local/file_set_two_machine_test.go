//go:build linux

package local_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
)

func newFileSetTwoMachineFixture(t *testing.T) *publicationTwoMachineFixture {
	t.Helper()
	fixture := newPublicationTwoMachineFixture(t)
	for _, machine := range []*publicationTwoMachine{fixture.a, fixture.b} {
		machine.configuration.Targets = machine.configuration.Targets[:1]
	}
	return fixture
}

func fileSetTwoMachineSnapshot(
	t *testing.T,
	fixture *publicationTwoMachineFixture,
	machine *publicationTwoMachine,
	record publication.SnapshotRecord,
) (model.Snapshot, []publication.PayloadEntry, []byte) {
	t.Helper()
	blobs := atproto.VaultReader{Transport: fixture.pds, Budgets: atproto.DefaultBudgets()}
	if record.PayloadForm() == publication.PayloadFormPacked {
		payload, err := blobs.FetchBlob(
			context.Background(),
			publicationTwoMachineDID,
			recordPackedBlob(record).CID,
			int64(recordPackedBlob(record).Size),
		)
		require.NoError(t, err)
		snapshot, err := publication.DecodePayload(payload, recordPackedBlob(record))
		require.NoError(t, err)
		return snapshot, nil, payload
	}
	portable, err := machine.target.Model()
	require.NoError(t, err)
	entries := make([]publication.PayloadEntry, 0, len(recordFileSetEntries(record)))
	for _, entry := range recordFileSetEntries(record) {
		content, err := blobs.FetchBlob(
			context.Background(), publicationTwoMachineDID, entry.Blob.CID, int64(entry.Blob.Size))
		require.NoError(t, err)
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: content,
		})
	}
	snapshot, err := service.ProjectFileSetSnapshot(portable, entries)
	require.NoError(t, err)
	return snapshot, entries, nil
}

func fileSetTwoMachineFinding(floor publicationstate.Floor, view publicationstate.SuppliedRepositoryView) string {
	if len(view.Snapshots) == 0 {
		return "absent"
	}
	terminal := view.Snapshots[len(view.Snapshots)-1]
	recordCID, err := publication.RecordCID(terminal.Raw)
	if err != nil || !bytes.Equal(recordCID, floor.RecordCID) {
		return "diverges"
	}
	record, err := publication.DecodeSnapshot(terminal.Raw)
	if err != nil {
		return "unreadable"
	}
	if !service.PublicationFloorMatchesRecord(floor, record) {
		return "diverges"
	}
	return "matches"
}

func fileSetTwoMachineJoin(
	t *testing.T,
	fixture *publicationTwoMachineFixture,
	machine *publicationTwoMachine,
) publicationstate.Floor {
	t.Helper()
	ctx := context.Background()
	view, err := fixture.adapter.ReadView(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, view.Snapshots)
	record, err := publication.DecodeSnapshot(view.Snapshots[len(view.Snapshots)-1].Raw)
	require.NoError(t, err)
	_, entries, _ := fileSetTwoMachineSnapshot(t, fixture, machine, record)
	store, err := publicationstate.Open(machine.storeDir, fixture.binding)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	observation := publicationTwoMachineObservation(view)
	proposal, err := service.StagePublicationAccept(ctx, service.PublicationAcceptStageRequest{
		Directory: machine.storeDir, Binding: fixture.binding, Observation: observation, Entries: entries,
	})
	require.NoError(t, err)
	accepted, err := service.AcceptPublication(ctx, service.PublicationAcceptRequest{
		Directory: machine.storeDir, Binding: fixture.binding, Mode: proposal.Mode,
		StateToken: proposal.StateToken, Confirmation: proposal.Confirmation,
		Observation: observation, Entries: entries,
	})
	require.NoError(t, err)
	return accepted
}

func fileSetTwoMachinePull(t *testing.T, fixture *publicationTwoMachineFixture, machine *publicationTwoMachine) error {
	t.Helper()
	ctx := context.Background()
	inspection, err := publicationstate.Inspect(ctx, machine.storeDir, fixture.binding)
	require.NoError(t, err)
	require.True(t, inspection.Present)
	view, err := fixture.adapter.ReadView(ctx)
	require.NoError(t, err)
	require.Equal(t, "diverges", fileSetTwoMachineFinding(inspection.Floor, view))

	baseBlock := view.Snapshots[inspection.Floor.Sequence]
	baseRecord, err := publication.DecodeSnapshot(baseBlock.Raw)
	require.NoError(t, err)
	base, _, _ := fileSetTwoMachineSnapshot(t, fixture, machine, baseRecord)
	terminalRecord, err := publication.DecodeSnapshot(view.Snapshots[len(view.Snapshots)-1].Raw)
	require.NoError(t, err)
	remote, remoteEntries, remotePayload := fileSetTwoMachineSnapshot(t, fixture, machine, terminalRecord)
	require.Equal(t, publication.PayloadFormFileSet, terminalRecord.PayloadForm())

	request := service.PublicationApplyRequest{
		Vault: fixture.binding.Vault, FloorRevision: inspection.Floor.Revision,
		Configuration: machine.configuration, BaseSnapshot: base, RemoteSnapshot: remote,
		Roots: map[string]string{machine.target.ID: machine.selected}, Local: machine.local,
		FileSetTargets: []string{machine.target.ID},
	}
	plan, err := service.PlanPublicationApply(ctx, request)
	if err != nil {
		return err
	}
	require.NotZero(t, plan.Changes)
	observation := publicationTwoMachineObservation(view)
	staged, err := service.StagePublicationAccept(ctx, service.PublicationAcceptStageRequest{
		Directory: machine.storeDir, Binding: fixture.binding, FloorRevision: inspection.Floor.Revision,
		Observation: observation, Payload: remotePayload, Entries: remoteEntries,
	})
	require.NoError(t, err)
	journal, err := publicationstate.OpenJournal(machine.storeDir)
	require.NoError(t, err)
	request.Journal = journal
	request.ExpectedPlan = plan.Digest
	report, err := service.ApplyPublication(ctx, request)
	require.NoError(t, err)
	assert.Positive(t, report.Applied)
	_, err = service.AcceptPublication(ctx, service.PublicationAcceptRequest{
		Directory: machine.storeDir, Binding: fixture.binding, Mode: staged.Mode,
		FloorRevision: inspection.Floor.Revision, StateToken: staged.StateToken,
		Confirmation: staged.Confirmation, Observation: observation,
		Payload: remotePayload, Entries: remoteEntries,
	})
	require.NoError(t, err)
	require.NoError(t, journal.Close())
	return nil
}

func TestFileSetPublicationTwoMachinePullApplyGate(t *testing.T) {
	fileSetTwoMachineUmask(t)
	fixture := newFileSetTwoMachineFixture(t)
	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineAlpha)
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineAlpha)

	first := fixture.push(t, fixture.a)
	require.NotEmpty(t, floorFileSet(first.Floor))
	require.Len(t, floorFileSet(first.Floor), 1)

	joined := fileSetTwoMachineJoin(t, fixture, fixture.b)
	assert.Equal(t, first.Floor.Revision, joined.Revision)
	require.NoDirExists(t, filepath.Join(fixture.b.selected, "nested"))

	require.NoError(t, os.Mkdir(filepath.Join(fixture.a.selected, "nested"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(fixture.a.selected, "nested", "app.conf"), []byte("nested alpha"), 0o600))
	second := fixture.push(t, fixture.a)
	require.NotEmpty(t, floorFileSet(second.Floor))
	require.Len(t, floorFileSet(second.Floor), 2)

	require.NoError(t, fileSetTwoMachinePull(t, fixture, fixture.b))
	content, err := os.ReadFile(filepath.Join(fixture.b.selected, "nested", "app.conf"))
	require.NoError(t, err)
	assert.Equal(t, []byte("nested alpha"), content)
	fileInfo, err := os.Stat(filepath.Join(fixture.b.selected, "nested", "app.conf"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
	info, err := os.Stat(filepath.Join(fixture.b.selected, "nested"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	assert.Equal(t, publicationTwoMachineAlpha, readPublicationTwoMachineFile(t, fixture.b))

	require.NoError(t, os.WriteFile(
		filepath.Join(fixture.a.selected, "nested", "app.conf"), []byte("nested beta"), 0o644))
	require.NoError(t, os.Chmod(filepath.Join(fixture.a.selected, "nested", "app.conf"), 0o644))
	fixture.push(t, fixture.a)

	require.NoError(t, fileSetTwoMachinePull(t, fixture, fixture.b))
	content, err = os.ReadFile(filepath.Join(fixture.b.selected, "nested", "app.conf"))
	require.NoError(t, err)
	assert.Equal(t, []byte("nested beta"), content)
	fileInfo, err = os.Stat(filepath.Join(fixture.b.selected, "nested", "app.conf"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fileInfo.Mode().Perm())
	info, err = os.Stat(filepath.Join(fixture.b.selected, "nested"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	view, err := fixture.adapter.ReadView(context.Background())
	require.NoError(t, err)
	inspection, err := publicationstate.Inspect(context.Background(), fixture.b.storeDir, fixture.binding)
	require.NoError(t, err)
	assert.Equal(t, "matches", fileSetTwoMachineFinding(inspection.Floor, view))
}

func fileSetTwoMachineUmask(t *testing.T) {
	t.Helper()
	previous := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(previous) })
}

func TestFileSetPublicationTwoMachineConflictRefusesWithoutMutation(t *testing.T) {
	fixture := newFileSetTwoMachineFixture(t)
	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineAlpha)
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineAlpha)
	fixture.push(t, fixture.a)
	fileSetTwoMachineJoin(t, fixture, fixture.b)
	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineBeta)
	fixture.push(t, fixture.a)
	require.NoError(t, fileSetTwoMachinePull(t, fixture, fixture.b))

	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineConflictA)
	fixture.push(t, fixture.a)
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineConflictB)
	before := readPublicationTwoMachineFile(t, fixture.b)

	err := fileSetTwoMachinePull(t, fixture, fixture.b)
	require.Error(t, err)
	assert.Equal(t, before, readPublicationTwoMachineFile(t, fixture.b))
}

func TestAutomaticPackedFallbackPublishesAndAppliesSupportedContent(t *testing.T) {
	fixture := newFileSetTwoMachineFixture(t)
	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineAlpha)
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineAlpha)
	require.NoError(t, os.WriteFile(filepath.Join(fixture.a.selected, "empty"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.b.selected, "empty"), nil, 0o600))

	first := fixture.push(t, fixture.a)
	assert.Empty(t, floorFileSet(first.Floor), "an empty file did not force the packed fallback")
	fixture.joinFirstUse(t, fixture.b)

	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineBeta)
	second := fixture.push(t, fixture.a)
	assert.Empty(t, floorFileSet(second.Floor))
	pulled := fixture.pull(t, fixture.b)
	assert.Equal(t, 1, pulled.Plan.Changes)
	assert.Equal(t, publicationTwoMachineBeta, readPublicationTwoMachineFile(t, fixture.b))
	content, err := os.ReadFile(filepath.Join(fixture.b.selected, "empty"))
	require.NoError(t, err)
	assert.Empty(t, content)
}
