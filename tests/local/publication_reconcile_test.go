package local_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/vault"
)

const publicationReconcileTargetID = "synthetic-files"

var publicationReconcileInitial = []byte("source A initial settings\n")
var publicationReconcileSentinelA = []byte("source A local-only sentinel\n")
var publicationReconcileSentinelB = []byte("destination B local-only sentinel\n")

type publicationReconcileHome struct {
	paths    platform.Paths
	root     string
	selected string
	sentinel string
	local    *service.PublicationLocalContext
	pubStore *publicationstate.Store
	floor    publicationstate.Floor
}

type publicationReconcileMaterial struct {
	payload   []byte
	key       string
	record    []byte
	recordCID []byte
	head      []byte
}

func newPublicationReconcileHome(t *testing.T, sentinel []byte) *publicationReconcileHome {
	t.Helper()
	root := canonicalPublicationReconcileTempDir(t)
	home := filepath.Join(root, "home")
	paths := platform.Paths{
		Home: home, ConfigHome: filepath.Join(home, ".config"),
		StateHome: filepath.Join(home, ".local", "state"), CacheHome: filepath.Join(home, ".cache"),
		DataHome: filepath.Join(home, ".local", "share"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	selected := filepath.Join(paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(selected, 0o700))
	selected, err := filepath.EvalSymlinks(selected)
	require.NoError(t, err)
	sentinelPath := filepath.Join(selected, "machine-only")
	writePublicationReconcileFile(t, sentinelPath, sentinel, 0o640)

	publicationDirectory := filepath.Join(root, "publication-state")
	require.NoError(t, os.Mkdir(publicationDirectory, 0o700))
	store, err := publicationstate.Open(publicationDirectory, publicationReconcileBinding())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return &publicationReconcileHome{
		paths:    paths,
		root:     selected,
		selected: selected,
		sentinel: sentinelPath,
		pubStore: store,
	}
}

func canonicalPublicationReconcileTempDir(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs(t.TempDir())
	require.NoError(t, err)
	resolved, err := filepath.EvalSymlinks(absolute)
	require.NoError(t, err)
	return filepath.Clean(resolved)
}

func newPublicationReconcileContext(t *testing.T, paths platform.Paths) *service.PublicationLocalContext {
	t.Helper()
	local, err := service.NewPublicationLocalContext(paths, nil, nil)
	require.NoError(t, err)
	return local
}

func publicationReconcileBinding() publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo,
		Repository: "at://did:plc:abcdefghijklmnopqrstuvwx", Vault: [32]byte{0x41, 0x52, 0x63},
	}
	return binding
}

func capturePublicationReconcileSource(
	t *testing.T,
	home *publicationReconcileHome,
	target config.Target,
	expected []byte,
) []model.Entry {
	t.Helper()
	captured, err := (service.LocalFilesCapture{}).Capture(context.Background(), target, home.selected)
	require.NoError(t, err)
	require.Len(t, captured.Observations, 1)
	observation := captured.Observations[0]
	require.Equal(t, model.ObservationPresent, observation.State)
	require.NotNil(t, observation.Entry)
	require.NotNil(t, observation.Entry.File)
	assert.Equal(t, "settings.ini", observation.Entry.File.Path)
	assert.Equal(t, model.FileRegular, observation.Entry.File.Kind)
	assert.Equal(t, expected, observation.Entry.File.Content)
	assert.Equal(t, uint32(0o600), observation.Entry.File.Mode)
	require.Len(t, captured.Skipped, 1)
	assert.Equal(t, "machine-only", captured.Skipped[0].Path)
	assert.Equal(t, files.SkipExcluded, captured.Skipped[0].Reason)
	entry := *observation.Entry
	entry.File.Content = bytes.Clone(observation.Entry.File.Content)
	return []model.Entry{entry}
}

func encodePublicationReconcileMaterial(
	t *testing.T,
	binding publicationstate.Binding,
	snapshot model.Snapshot,
	sequence uint64,
	parent []byte,
	publicationID [16]byte,
) publicationReconcileMaterial {
	t.Helper()
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	recordRaw, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationID:  publicationID,
		PublicationSeq: sequence,
		Parent:         bytes.Clone(parent),
		Blob: publication.BlobReference{
			CID:      blobCID,
			Size:     uint64(len(packed.Payload)),
			MIMEType: publication.SnapshotBlobMIMEType,
		},
	})
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(recordRaw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: sequence,
		SnapshotCID: recordCID, BlobCID: blobCID,
	})
	require.NoError(t, err)
	return publicationReconcileMaterial{
		payload:   bytes.Clone(packed.Payload),
		key:       key,
		record:    recordRaw,
		recordCID: recordCID,
		head:      head,
	}
}

func publicationReconcileObservation(
	binding publicationstate.Binding,
	supplied publicationstate.SuppliedContext,
	current publicationReconcileMaterial,
	previous ...publicationReconcileMaterial,
) publicationstate.Observation {
	blocks := make([]publicationstate.SnapshotBlock, 0, len(previous)+1)
	for _, item := range previous {
		blocks = append(blocks, publicationstate.SnapshotBlock{Key: item.key, Raw: bytes.Clone(item.record)})
	}
	blocks = append(blocks, publicationstate.SnapshotBlock{Key: current.key, Raw: bytes.Clone(current.record)})
	return publicationstate.Observation{
		Origin:          binding,
		SuppliedContext: supplied,
		Head:            bytes.Clone(current.head),
		Snapshots:       blocks,
	}
}

func clonePublicationReconcileFloor(floor publicationstate.Floor) publicationstate.Floor {
	floor.AnchorCID = bytes.Clone(floor.AnchorCID)
	floor.SuppliedContext = clonePublicationReconcileContext(floor.SuppliedContext)
	floor.Head = bytes.Clone(floor.Head)
	floor.RecordCID = bytes.Clone(floor.RecordCID)
	floor.BlobCID = bytes.Clone(floor.BlobCID)
	return floor
}

func clonePublicationReconcileContext(supplied publicationstate.SuppliedContext) publicationstate.SuppliedContext {
	supplied.RepositoryDigest = bytes.Clone(supplied.RepositoryDigest)
	if supplied.Policy != nil {
		policy := *supplied.Policy
		policy.Identity = bytes.Clone(policy.Identity)
		supplied.Policy = &policy
	}
	return supplied
}

func acceptPublicationReconcilePosition(
	t *testing.T,
	store *publicationstate.Store,
	mode publicationstate.Mode,
	observation publicationstate.Observation,
	payload []byte,
) publicationstate.Floor {
	t.Helper()
	proposal, err := store.Prepare(context.Background(), mode, observation, payload)
	require.NoError(t, err)
	floor, err := store.Accept(
		context.Background(),
		mode,
		proposal.StateToken,
		observation,
		payload,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	return floor
}

func publicationReconcileRequest(
	home *publicationReconcileHome,
	binding publicationstate.Binding,
	material publicationReconcileMaterial,
	configuration config.Config,
	local *service.PublicationLocalContext,
) service.PublicationReconciliationRequest {
	return service.PublicationReconciliationRequest{
		Store: home.pubStore, Binding: binding, ExpectedFloor: home.floor,
		SnapshotRecord: bytes.Clone(material.record), Payload: bytes.Clone(material.payload),
		Configuration: configuration, TargetID: publicationReconcileTargetID, Local: local,
	}
}

func assertPublicationReconcileFile(t *testing.T, path string, expected []byte, mode os.FileMode) {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, expected, content)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, mode.Perm(), info.Mode().Perm())
}

func writePublicationReconcileFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, mode))
	require.NoError(t, os.Chmod(path, mode))
}
