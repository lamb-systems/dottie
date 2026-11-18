package cli

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

type cliManifestFile struct {
	path    string
	mode    uint32
	content []byte
}

type cliManifestPublication struct {
	block publicationstate.SnapshotBlock
	head  []byte
	view  publicationstate.SuppliedRepositoryView
	floor publicationstate.Floor
}

func newCLIManifestPublication(t *testing.T, binding publicationstate.Binding) cliManifestPublication {
	t.Helper()
	files := []cliManifestFile{
		{path: "init.lua", mode: 0o600, content: []byte("synthetic manifest init")},
		{path: "lua/config/options.lua", mode: 0o644, content: []byte("synthetic manifest options")},
	}
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
	raw, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault,
		PublicationID: [16]byte{0x62, 0x31}, Entries: entries,
	})
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, SnapshotCID: recordCID,
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	view := publicationstate.SuppliedRepositoryView{
		Origin: binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{
			RepositoryRevision: "synthetic-manifest-revision", RepositoryDigest: []byte{0x71},
		},
		Head:      head,
		Snapshots: []publicationstate.SnapshotBlock{{Key: key, Raw: raw}},
	}
	floor := publicationstate.Floor{
		Revision: 1, Generation: 1, Binding: binding, RecordCID: recordCID, SnapshotKey: key,
	}
	return cliManifestPublication{block: view.Snapshots[0], head: head, view: view, floor: floor}
}

func pullTestManifestBinding() publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: pullTestDID, Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x62},
	}
	binding.Repository = "at://" + binding.AccountDID
	return binding
}

func TestPullApplyPlanningRefusesAManifestProviderPayload(t *testing.T) {
	binding := pullTestManifestBinding()
	manifest := newCLIManifestPublication(t, binding)
	fetched := 0
	remote := pullRemote{
		Blob: func(context.Context, publication.SnapshotRecord) ([]byte, error) {
			fetched++
			return nil, nil
		},
	}

	material, err := pullApplySnapshots(context.Background(), remote, manifest.view, manifest.floor, false)
	assert.Equal(t, pullApplyMaterial{}, material)
	require.ErrorIs(t, err, publication.ErrManifestPayload)
	var refusal *publication.ManifestPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, publication.ManifestReasonPackedRequired, refusal.Reason)
	assert.Zero(t, fetched, "apply planning fetched a payload it refuses")

	var exitError urfave.ExitCoder
	require.ErrorAs(t, pullApplyRemoteFailure("pull", err), &exitError)
	assert.Equal(t, 3, exitError.ExitCode())
	assert.Contains(t, exitError.Error(), "manifest")
}

func TestPullPositionComparisonReportsAManifestPayloadForm(t *testing.T) {
	binding := pullTestManifestBinding()
	manifest := newCLIManifestPublication(t, binding)

	finding := comparePullPosition(manifest.floor, manifest.view)
	assert.Equal(t, pullFinding{Kind: pullFindingDiverges, Reason: pullDivergencePayloadForm}, finding)
}

func TestSyncViewComparisonRefusesAManifestProviderPayload(t *testing.T) {
	binding := pullTestManifestBinding()
	manifest := newCLIManifestPublication(t, binding)

	err := syncViewMatchesFloor(manifest.floor, manifest.view)
	require.ErrorIs(t, err, errSyncFloorMismatch)
}

func TestSyncAcceptedMaterialRefusesAManifestRecord(t *testing.T) {
	binding := pullTestManifestBinding()
	manifest := newCLIManifestPublication(t, binding)

	snapshot, err := syncAcceptedSnapshot(publicationstate.AcceptedMaterial{
		Floor: manifest.floor, SnapshotRecord: manifest.block.Raw,
		Payload: []byte("packed payload for a manifest accepted record"),
	})
	assert.Equal(t, model.Snapshot{}, snapshot)
	require.ErrorIs(t, err, publication.ErrManifestPayload)
	var refusal *publication.ManifestPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, publication.ManifestReasonPackedRequired, refusal.Reason)
}

func TestPullRefusesAManifestProviderPositionWithoutChangingAnything(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	manifest := newCLIManifestPublication(t, fixture.binding)
	reader := &pullTestReader{view: manifest.view}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)

	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code, stderr.String())
	assert.Contains(t, stderr.String(), "manifest")
	assert.Contains(t, stderr.String(), "nothing was changed")
	assert.NotContains(t, stdout.String(), "confirmation:")
	assert.Contains(t, stdout.String(), "pull: first-use")

	_, err := os.Stat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, err, os.ErrNotExist)
	inspection, err := publicationstate.Inspect(
		context.Background(),
		fixture.paths.PublicationStateDir(),
		fixture.binding,
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present)
}
