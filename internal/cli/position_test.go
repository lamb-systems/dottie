package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const positionTestDID = "did:plc:abcdefghijklmnopqrstuvwx"

func positionTestBinding() publicationstate.Binding {
	binding := publicationstate.Binding{AccountDID: positionTestDID, Backend: publicationstate.BackendPublicRepo, Repository: "at://" + positionTestDID}
	binding.Vault = [32]byte{0x09, 0x11, 0x23}
	return binding
}

func positionTestDirectory(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	directory := paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(directory, 0o700))
	return directory
}

func newPositionFloorStore(t *testing.T, directory string, binding publicationstate.Binding) (*publicationstate.Store, publicationstate.Floor) {
	t.Helper()
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("synthetic position status"), Mode: 0o600}}},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion,
		Vault:         binding.Vault,
		PublicationID: [16]byte{0x25, 0x71},
		Parent:        []byte{},
		Blob:          publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload)), MIMEType: publication.SnapshotBlobMIMEType},
	}
	recordRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(recordRaw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: 0, SnapshotCID: recordCID, BlobCID: blobCID})
	require.NoError(t, err)
	observation := publicationstate.Observation{
		Origin:          binding,
		SuppliedContext: publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}},
		Head:            head,
		Snapshots:       []publicationstate.SnapshotBlock{{Key: "0000000000000000", Raw: recordRaw}},
	}
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	proposal, err := store.Prepare(context.Background(), publicationstate.ModeFirstUse, observation, packed.Payload)
	require.NoError(t, err)
	floor, err := store.Accept(context.Background(), publicationstate.ModeFirstUse, proposal.StateToken, observation, packed.Payload, proposal.Confirmation)
	require.NoError(t, err)
	return store, floor
}

func requireNoPositionIdentifiers(t *testing.T, output string, binding publicationstate.Binding) {
	t.Helper()
	assert.NotContains(t, output, binding.AccountDID, "output contains the account DID")
	assert.NotContains(t, output, hex.EncodeToString(binding.Vault[:]), "output contains the vault fingerprint")
	assert.NotContains(t, output, "publication.db", "output contains the store file name")
}

func TestPositionStatusRefusesWithTypedTripleOnly(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		build  func(t *testing.T, directory string)
	}{
		{name: "absent store", reason: "schema/inspect/position_absent", build: func(*testing.T, string) {}},
		{name: "unsafe directory", reason: "storage/inspect/io", build: func(t *testing.T, directory string) {
			require.NoError(t, os.Chmod(directory, 0o755))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := positionTestDirectory(t)
			test.build(t, directory)
			binding := positionTestBinding()
			var stdout, stderr bytes.Buffer
			code := Run([]string{"position", "status", "--did", binding.AccountDID, "--vault", hex.EncodeToString(binding.Vault[:])}, &stdout, &stderr)
			require.Equal(t, 3, code, "exit code")
			assert.Empty(t, stdout.String(), "unexpected stdout")
			assert.Equal(t, "dottie: publication state: "+test.reason+"\n", stderr.String(), "stderr")
			requireNoPositionIdentifiers(t, stderr.String(), binding)
			assert.NotContains(t, stderr.String(), directory, "stderr contains the store path")
			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			assert.Empty(t, entries, "refusal created store files")
		})
	}
}

func TestPositionStatusReportsEmptyFloor(t *testing.T) {
	directory := positionTestDirectory(t)
	binding := positionTestBinding()
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	before, err := os.ReadDir(directory)
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"position", "status", "--did", binding.AccountDID, "--vault", hex.EncodeToString(binding.Vault[:])}, &stdout, &stderr)
	require.Equal(t, 0, code, "exit code")
	assert.Equal(t, "position: empty\n", stdout.String(), "stdout")
	assert.Empty(t, stderr.String(), "stderr")
	requireNoPositionIdentifiers(t, stdout.String(), binding)
	after, err := os.ReadDir(directory)
	require.NoError(t, err)
	assert.Equal(t, before, after, "inspection changed the store directory")
}

func TestPositionStatusReportsAcceptedFloorWithoutLeakingIdentifiers(t *testing.T) {
	directory := positionTestDirectory(t)
	binding := positionTestBinding()
	store, floor := newPositionFloorStore(t, directory, binding)
	require.NoError(t, store.Close())
	require.Equal(t, uint64(1), floor.Revision)
	require.Equal(t, uint64(1), floor.Generation)
	require.Equal(t, uint64(0), floor.Sequence)
	require.Equal(t, publicationstate.ProvenanceFirst, floor.Provenance)
	before, err := os.ReadDir(directory)
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"position", "status", "--did", binding.AccountDID, "--vault", hex.EncodeToString(binding.Vault[:])}, &stdout, &stderr)
	require.Equal(t, 0, code, "exit code")
	assert.Equal(t, "position: revision=1 generation=1 provenance=first sequence=0\n", stdout.String(), "stdout")
	assert.Empty(t, stderr.String(), "stderr")
	requireNoPositionIdentifiers(t, stdout.String(), binding)
	assert.NotContains(t, stdout.String(), "at://", "stdout contains the repository")
	assert.NotContains(t, stdout.String(), filepath.Dir(directory), "stdout contains a path")
	after, err := os.ReadDir(directory)
	require.NoError(t, err)
	assert.Equal(t, before, after, "inspection changed the store directory")
}

func TestPositionStatusRefusesFreshInstallAsAbsent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	directory := paths.PublicationStateDir()
	var stdout, stderr strings.Builder
	code := runPosition([]string{"status", "--did", positionTestDID, "--vault", "091123" + strings.Repeat("00", 29)}, &stdout, &stderr, os.Getenv)
	assert.Equal(t, 3, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "schema/inspect/position_absent")
	assert.NotContains(t, stderr.String(), positionTestDID)
	_, statErr := os.Lstat(directory)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "inspection created the store directory")
}

func TestPositionStatusHelpNamesTheNestedCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var stdout, stderr strings.Builder
	code := runPosition([]string{"status", "--help"}, &stdout, &stderr, os.Getenv)
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "dottie position status")
}

func TestPositionStatusRefusesUsageFaults(t *testing.T) {
	directory := positionTestDirectory(t)
	binding := positionTestBinding()
	vaultHex := hex.EncodeToString(binding.Vault[:])
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing did", args: []string{"position", "status", "--vault", vaultHex}},
		{name: "malformed did", args: []string{"position", "status", "--did", "not-a-did", "--vault", vaultHex}},
		{name: "malformed vault", args: []string{"position", "status", "--did", binding.AccountDID, "--vault", "abc"}},
		{name: "short vault", args: []string{"position", "status", "--did", binding.AccountDID, "--vault", vaultHex[:62]}},
		{name: "zero vault", args: []string{"position", "status", "--did", binding.AccountDID, "--vault", hex.EncodeToString(make([]byte, 32))}},
		{name: "positional argument", args: []string{"position", "status", "--did", binding.AccountDID, "--vault", vaultHex, "extra"}},
		{name: "missing subcommand", args: []string{"position"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(test.args, &stdout, &stderr)
			require.Equal(t, 2, code, "exit code")
			assert.Empty(t, stdout.String(), "unexpected stdout")
			assert.Contains(t, stderr.String(), "usage:", "stderr")
			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			assert.Empty(t, entries, "usage fault created store files")
		})
	}
}

func TestPositionStatusRefusesHeldWriterAndKeepsItUsable(t *testing.T) {
	directory := positionTestDirectory(t)
	binding := positionTestBinding()
	store, _ := newPositionFloorStore(t, directory, binding)
	vaultHex := hex.EncodeToString(binding.Vault[:])
	var stdout, stderr bytes.Buffer
	code := Run([]string{"position", "status", "--did", binding.AccountDID, "--vault", vaultHex}, &stdout, &stderr)
	require.Equal(t, 3, code, "exit code while the writer holds the store")
	assert.Empty(t, stdout.String(), "unexpected stdout")
	assert.Equal(t, "dottie: publication state: locked/inspect/locked\n", stderr.String(), "stderr")
	requireNoPositionIdentifiers(t, stderr.String(), binding)
	require.NoError(t, store.Close())
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"position", "status", "--did", binding.AccountDID, "--vault", vaultHex}, &stdout, &stderr)
	require.Equal(t, 0, code, "exit code after the writer released the store")
	assert.Equal(t, "position: revision=1 generation=1 provenance=first sequence=0\n", stdout.String(), "stdout")
	assert.Empty(t, stderr.String(), "stderr")
}

func TestPositionStatusResolvesVaultFromRecordedBinding(t *testing.T) {
	directory := positionTestDirectory(t)
	binding := positionTestBinding()
	store, _ := newPositionFloorStore(t, directory, binding)
	require.NoError(t, store.Close())
	var resolved, resolvedErr bytes.Buffer
	code := Run([]string{"position", "status", "--did", binding.AccountDID}, &resolved, &resolvedErr)
	require.Equal(t, 0, code, "exit code without --vault")
	assert.Empty(t, resolvedErr.String(), "stderr without --vault")
	assert.Equal(t, "position: revision=1 generation=1 provenance=first sequence=0\n", resolved.String(), "stdout without --vault")
	var explicit, explicitErr bytes.Buffer
	code = Run([]string{"position", "status", "--did", binding.AccountDID, "--vault", hex.EncodeToString(binding.Vault[:])}, &explicit, &explicitErr)
	require.Equal(t, 0, code, "exit code with --vault")
	assert.Empty(t, explicitErr.String(), "stderr with --vault")
	assert.Equal(t, explicit.String(), resolved.String(), "resolved output differs from the explicit vault output")
	requireNoPositionIdentifiers(t, resolved.String(), binding)
}

func TestPositionStatusUsesExplicitVaultOverride(t *testing.T) {
	directory := positionTestDirectory(t)
	binding := positionTestBinding()
	store, _ := newPositionFloorStore(t, directory, binding)
	require.NoError(t, store.Close())
	other := binding
	other.Vault = [32]byte{0x0a, 0x22, 0x34}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"position", "status", "--did", binding.AccountDID, "--vault", hex.EncodeToString(other.Vault[:])}, &stdout, &stderr)
	require.Equal(t, 3, code, "exit code for an override that differs from the binding")
	assert.Empty(t, stdout.String(), "unexpected stdout")
	assert.Equal(t, "dottie: publication state: invalid/inspect/binding\n", stderr.String(), "stderr")
	requireNoPositionIdentifiers(t, stderr.String(), binding)
}

func TestPositionStatusRefusesAbsentBindingWithoutVault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	var stdout, stderr strings.Builder
	code := runPosition([]string{"status", "--did", positionTestDID}, &stdout, &stderr, os.Getenv)
	require.Equal(t, 3, code, "exit code")
	assert.Empty(t, stdout.String(), "unexpected stdout")
	assert.Equal(t, "dottie: publication state: schema/inspect/position_absent\n", stderr.String(), "stderr")
	assert.NotContains(t, stderr.String(), positionTestDID, "stderr contains the account DID")
	_, statErr := os.Lstat(paths.PublicationStateDir())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "inspection created the store directory")
}

func TestPositionStatusRefusesRecordedBindingOfAnotherAccount(t *testing.T) {
	directory := positionTestDirectory(t)
	binding := positionTestBinding()
	store, _ := newPositionFloorStore(t, directory, binding)
	require.NoError(t, store.Close())
	const otherDID = "did:plc:zyxwvutsrqponmlkjihgfedc"
	var stdout, stderr bytes.Buffer
	code := Run([]string{"position", "status", "--did", otherDID}, &stdout, &stderr)
	require.Equal(t, 3, code, "exit code")
	assert.Empty(t, stdout.String(), "unexpected stdout")
	assert.Equal(t, "dottie: publication state: invalid/inspect/binding\n", stderr.String(), "stderr")
	assert.NotContains(t, stderr.String(), otherDID, "stderr contains the requested account DID")
	requireNoPositionIdentifiers(t, stderr.String(), binding)
}
