package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	urfave "github.com/urfave/cli/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
)

func TestPlanEscapesPathsAndNeverPrintsContents(t *testing.T) {
	target := model.Target{
		ID:            "files",
		Source:        model.SourceFiles,
		SourceVersion: model.SourceVersion,
		Root:          &model.FileRoot{Base: model.RootHome, Path: "prefs", Kind: model.SelectionDirectory},
	}
	baseEntry := model.Entry{TargetID: target.ID, File: &model.FileEntry{
		Path:    "name\n\x1b\u0085",
		State:   model.FilePresent,
		Kind:    model.FileRegular,
		Content: []byte("old-private-content"),
		Mode:    0o600,
	}}
	observedEntry := model.Entry{TargetID: target.ID, File: &model.FileEntry{
		Path:    "name\n\x1b\u0085",
		State:   model.FilePresent,
		Kind:    model.FileRegular,
		Content: []byte("ULTRA_PRIVATE_PLAN_CONTENT_7d2ca91e"),
		Mode:    0o640,
	}}
	bundle := map[string]any{
		"version":     1,
		"base_status": "known",
		"targets":     []model.Target{target},
		"base":        []model.Entry{baseEntry},
		"observations": []model.Observation{
			{State: model.ObservationPresent, Identity: observedEntry.Identity(), Entry: &observedEntry},
		},
		"remote":   []model.Entry{baseEntry},
		"coverage": []string{"files"},
	}
	input, err := json.Marshal(bundle)
	require.NoError(t, err)
	inputPath := filepath.Join(t.TempDir(), "views.json")
	require.NoError(t, os.WriteFile(inputPath, input, 0o600))
	before, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"plan", "--from", inputPath}, &stdout, &stderr)
	require.Equal(t, 0, code, "plan exit code")
	assert.Empty(t, stderr.String(), "plan error output")
	assert.Contains(t, stdout.String(), "change", "plan action")
	assert.Contains(t, stdout.String(), "name\\x0A\\x1B\\x85", "text output escapes controls in the path")
	assert.NotContains(t, stdout.String(), "\x1b", "text output contains a raw terminal escape")
	assert.NotContains(t, stdout.String(), "\u0085", "text output contains a raw Unicode line control")
	assert.NotContains(t, stdout.String(), "ULTRA_PRIVATE_PLAN_CONTENT_7d2ca91e", "text output contains file content")
	assert.NotContains(t, stdout.String(), "old-private-content", "text output contains base content")
	after, err := os.ReadFile(inputPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "plan command modified its input file")

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"plan", "--from", inputPath, "--json"}, &stdout, &stderr)
	require.Equal(t, 0, code, "JSON plan exit code")
	assert.Empty(t, stderr.String(), "JSON plan error output")
	assert.Contains(t, stdout.String(), `"name\n\u001b\u0085"`, "JSON output escapes controls in the path")
	assert.NotContains(t, stdout.String(), "\x1b", "JSON output contains a raw terminal escape")
	assert.NotContains(t, stdout.String(), "\u0085", "JSON output contains a raw Unicode line control")
	assert.NotContains(t, stdout.String(), "ULTRA_PRIVATE_PLAN_CONTENT_7d2ca91e", "JSON output contains file content")
	assert.NotContains(t, stdout.String(), "old-private-content", "JSON output contains base content")
	var preview syncengine.Preview
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &preview), "JSON output remains valid after escaping controls")
	require.Len(t, preview.Targets, 1)
	assert.Equal(t, "name\n\x1b\u0085", preview.Targets[0].Entries[0].Key.FilePath, "JSON path round-trips exactly")
}

func TestPlanTextLabelsIncompleteResultingSnapshotAsLowerBound(t *testing.T) {
	output := renderPreview(syncengine.Preview{
		TransferBytes:          5,
		ResultingSnapshotBytes: 12,
		Complete:               false,
		UnresolvedEntries:      2,
	})
	assert.Contains(t, output, "transfer bytes=5\n", "transfer amount is explicit")
	assert.Contains(
		t,
		output,
		"resulting snapshot at least 12 bytes, incomplete: 2 unresolved\n",
		"incomplete result is labeled as a lower bound",
	)
}

func TestPlanRequiresFromFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"plan"}, &stdout, &stderr)
	require.Equal(t, 2, code, "missing --from exit code")
	assert.Empty(t, stdout.String(), "missing --from output")
	assert.Contains(t, stderr.String(), "--from", "usage error names the required flag")
}

func TestPlanInputRequiresFieldsWithTypedError(t *testing.T) {
	_, err := decodePlanInput(
		[]byte(`{"base_status":"missing","targets":[],"base":[],"observations":[],"remote":[],"coverage":[]}`),
	)
	require.Error(t, err, "version is required")
	var inputError *PlanInputError
	require.ErrorAs(t, err, &inputError, "missing required fields have a typed error")
	assert.Equal(t, "version", inputError.Field, "missing field")
	assert.Equal(t, "is missing required", inputError.Kind, "missing field error kind")
}

func TestPlanInputRejectsUnknownFields(t *testing.T) {
	_, err := decodePlanInput(
		[]byte(
			`{"version":1,"base_status":"missing","targets":[],"base":[],"observations":[],"remote":[],"coverage":[],"hook":"run me"}`,
		),
	)
	require.Error(t, err, "unknown input fields must be rejected")
	var inputError *PlanInputError
	require.ErrorAs(t, err, &inputError, "invalid JSON has a typed error")
	assert.Equal(t, "is invalid JSON", inputError.Kind, "unknown field error kind")
}

const (
	syncTestBaseA   = "synthetic sync base a"
	syncTestRemoteA = "synthetic sync remote a"
	syncTestBaseB   = "synthetic sync base b"
	syncTestLocalB  = "synthetic sync local b"
)

type syncTestFixture struct {
	paths         platform.Paths
	binding       publicationstate.Binding
	transport     *pushTestTransport
	coordinator   *service.Coordinator
	reviews       pushTestReviews
	configuration config.Config
}

func newSyncTestFixture(t *testing.T, mode config.Mode) *syncTestFixture {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home:       filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(
			root,
			"state",
		),
		CacheHome: filepath.Join(root, "cache"),
		DataHome:  filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(paths.Home, "config"), 0o700))
	require.NoError(t, os.MkdirAll(paths.PublicationStateDir(), 0o700))
	require.NoError(t, os.Chmod(paths.PublicationStateDir(), 0o700))
	stateStore, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, stateStore.Close()) })
	coordinator, err := service.NewCoordinator(service.Dependencies{State: stateStore, Paths: paths})
	require.NoError(t, err)
	binding := publicationstate.Binding{
		AccountDID: pullTestDID,
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x62},
	}
	binding.Repository = "at://" + binding.AccountDID
	directory := paths.AppConfigDir()
	require.NoError(t, os.MkdirAll(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o700))
	content := "config_version = 2\n\n[[targets]]\nid = \"files\"\nsource = \"files\"\n"
	if mode != "" {
		content += "mode = \"" + string(mode) + "\"\n"
	}
	content += "\n[targets.root]\nbase = \"home\"\npath = \"config\"\nkind = \"directory\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(directory, config.FileName), []byte(content), 0o600))
	loaded, err := service.FileConfigPort{Paths: paths}.Load(context.Background())
	require.NoError(t, err)
	require.NoError(t, loaded.Validate())
	review := publicationstate.LocalReviewContext{
		SelectionDigest:   [32]byte{0x63},
		SelectionRevision: 1,
		ApprovalDigest:    [32]byte{0x64},
		ApprovalRevision:  1,
	}
	return &syncTestFixture{
		paths: paths, binding: binding, transport: newPushTestTransport(binding),
		coordinator: coordinator, reviews: pushTestReviews{review: review, calls: new(int)}, configuration: loaded,
	}
}

func (fixture *syncTestFixture) session() pushSession {
	return pushSession{Session: &atproto.Session{DID: fixture.binding.AccountDID, Scopes: atproto.VaultScopes()}}
}

func (fixture *syncTestFixture) pullVaults(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
	return fixture.binding.Vault, nil
}

func (fixture *syncTestFixture) blob(_ context.Context, record publication.SnapshotRecord) ([]byte, error) {
	return fixture.transport.blob(context.Background(), record.Blob)
}

func (fixture *syncTestFixture) snapshotA(a string) model.Snapshot {
	return model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{
			{
				ID:            "files",
				Source:        model.SourceFiles,
				SourceVersion: model.SourceVersion,
				Root:          &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
			},
		},
		Entries: []model.Entry{
			{
				TargetID: "files",
				File: &model.FileEntry{
					Path:    "a.txt",
					State:   model.FilePresent,
					Kind:    model.FileRegular,
					Content: []byte(a),
					Mode:    0o600,
				},
			},
			{
				TargetID: "files",
				File: &model.FileEntry{
					Path:    "b.txt",
					State:   model.FilePresent,
					Kind:    model.FileRegular,
					Content: []byte(syncTestBaseB),
					Mode:    0o600,
				},
			},
		},
	}
}

func (fixture *syncTestFixture) writeLocal(t *testing.T, a, b string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "config", "a.txt"), []byte(a), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "config", "b.txt"), []byte(b), 0o600))
}

func (fixture *syncTestFixture) seed(
	t *testing.T,
	snapshot model.Snapshot,
) (publicationstate.SnapshotBlock, publication.SnapshotRecord) {
	t.Helper()
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	block, record := syncTestRecord(t, fixture.binding, packed.Payload, 0, nil)
	head := syncTestHead(t, fixture.binding, block, record)
	fixture.transport.mu.Lock()
	fixture.transport.blocks[block.Key] = bytes.Clone(block.Raw)
	fixture.transport.blobs[string(record.Blob.CID)] = bytes.Clone(packed.Payload)
	fixture.transport.head = head
	fixture.transport.context = pushTestContext(0)
	fixture.transport.mu.Unlock()
	fixture.accept(t, payloadObservation(fixture.binding, head, block), packed.Payload)
	return block, record
}

func (fixture *syncTestFixture) advance(
	t *testing.T,
	snapshot model.Snapshot,
) (publicationstate.SnapshotBlock, publication.SnapshotRecord) {
	t.Helper()
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	parentCID, err := publication.RecordCID(fixture.terminal(t))
	require.NoError(t, err)
	block, record := syncTestRecord(t, fixture.binding, packed.Payload, 1, parentCID)
	head := syncTestHead(t, fixture.binding, block, record)
	fixture.transport.mu.Lock()
	fixture.transport.blocks[block.Key] = bytes.Clone(block.Raw)
	fixture.transport.blobs[string(record.Blob.CID)] = bytes.Clone(packed.Payload)
	fixture.transport.head = head
	fixture.transport.context = pushTestContext(1)
	fixture.transport.mu.Unlock()
	return block, record
}

func (fixture *syncTestFixture) rewriteProvider(t *testing.T, snapshot model.Snapshot) publicationstate.SnapshotBlock {
	t.Helper()
	floor := fixture.readFloor(t)
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	block, record := syncTestRecord(t, fixture.binding, packed.Payload, 1, floor.RecordCID)
	head := syncTestHead(t, fixture.binding, block, record)
	fixture.transport.mu.Lock()
	fixture.transport.blocks[block.Key] = bytes.Clone(block.Raw)
	fixture.transport.blobs[string(record.Blob.CID)] = bytes.Clone(packed.Payload)
	fixture.transport.head = head
	fixture.transport.mu.Unlock()
	return block
}

func (fixture *syncTestFixture) terminal(t *testing.T) []byte {
	t.Helper()
	fixture.transport.mu.Lock()
	defer fixture.transport.mu.Unlock()
	var latest []byte
	var latestSeq uint64
	for _, raw := range fixture.transport.blocks {
		record, err := publication.DecodeSnapshot(raw)
		require.NoError(t, err)
		if len(latest) == 0 || record.PublicationSeq >= latestSeq {
			latest = bytes.Clone(raw)
			latestSeq = record.PublicationSeq
		}
	}
	require.NotEmpty(t, latest)
	return latest
}

func payloadObservation(
	binding publicationstate.Binding,
	head []byte,
	blocks ...publicationstate.SnapshotBlock,
) publicationstate.Observation {
	snapshots := make([]publicationstate.SnapshotBlock, 0, len(blocks))
	for _, block := range blocks {
		snapshots = append(snapshots, publicationstate.SnapshotBlock{Key: block.Key, Raw: bytes.Clone(block.Raw)})
	}
	return publicationstate.Observation{
		Origin: binding, SuppliedContext: pushTestContext(0), Head: bytes.Clone(head), Snapshots: snapshots,
	}
}

func (fixture *syncTestFixture) accept(t *testing.T, observation publicationstate.Observation, payload []byte) {
	t.Helper()
	store, err := publicationstate.Open(fixture.paths.PublicationStateDir(), fixture.binding)
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	mode := publicationstate.ModeFirstUse
	if _, present, err := store.Load(context.Background()); err != nil {
		require.NoError(t, err)
	} else if present {
		mode = publicationstate.ModeAdvance
	}
	proposal, err := store.Prepare(context.Background(), mode, observation, payload)
	require.NoError(t, err)
	_, err = store.AcceptMaterial(
		context.Background(),
		mode,
		proposal.StateToken,
		observation,
		payload,
		proposal.Confirmation,
	)
	require.NoError(t, err)
}

func syncTestRecord(
	t *testing.T,
	binding publicationstate.Binding,
	payload []byte,
	sequence uint64,
	parent []byte,
) (publicationstate.SnapshotBlock, publication.SnapshotRecord) {
	t.Helper()
	blobCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: sequence,
		Parent:         parent,
		Blob: publication.BlobReference{
			CID:      blobCID,
			Size:     uint64(len(payload)),
			MIMEType: publication.SnapshotBlobMIMEType,
		},
	}
	binary.BigEndian.PutUint64(record.PublicationID[8:], sequence+7)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return publicationstate.SnapshotBlock{Key: key, Raw: raw}, record
}

func syncTestHead(
	t *testing.T,
	binding publicationstate.Binding,
	block publicationstate.SnapshotBlock,
	record publication.SnapshotRecord,
) []byte {
	t.Helper()
	cid, err := publication.RecordCID(block.Raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault,
		PublicationSeq: record.PublicationSeq, SnapshotCID: cid, BlobCID: record.Blob.CID,
	})
	require.NoError(t, err)
	return head
}

func (fixture *syncTestFixture) readFloor(t *testing.T) publicationstate.Floor {
	t.Helper()
	store, err := publicationstate.Open(fixture.paths.PublicationStateDir(), fixture.binding)
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	floor, present, err := store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	return floor
}

func (fixture *syncTestFixture) proposalCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), publicationProposalFilePrefix) {
			count++
		}
	}
	return count
}

func (fixture *syncTestFixture) setEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", fixture.paths.Home)
	t.Setenv("XDG_CONFIG_HOME", fixture.paths.ConfigHome)
	t.Setenv("XDG_STATE_HOME", fixture.paths.StateHome)
	t.Setenv("XDG_CACHE_HOME", fixture.paths.CacheHome)
	t.Setenv("XDG_DATA_HOME", fixture.paths.DataHome)
}

type syncTestHooks struct {
	preview  func(*syncTestFixture)
	provider func(*syncTestFixture)
	push     func(*syncTestFixture)
}

func runSyncForTest(t *testing.T, fixture *syncTestFixture, hooks syncTestHooks, args ...string) (int, string, string) {
	t.Helper()
	return runSyncForTestWithDIDs(t, fixture, hooks, pushTestDIDs(fixture.binding.AccountDID), args...)
}

func runSyncForTestWithDIDs(
	t *testing.T,
	fixture *syncTestFixture,
	hooks syncTestHooks,
	dids sessionDIDSource,
	args ...string,
) (int, string, string) {
	t.Helper()
	fixture.setEnvironment(t)
	var stdout, stderr bytes.Buffer
	exitCode := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return fixture.session(), nil }
	remotes := func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error) {
		return pullRemote{Reader: fixture.transport, Blob: fixture.blob, Close: func() {}}, nil
	}
	previews := func(context.Context, *urfave.Command, publicationstate.Binding) (syncPushPreviewSources, error) {
		if hooks.preview != nil {
			hooks.preview(fixture)
		}
		return syncPushPreviewSources{
			Binding: fixture.binding, Coordinator: fixture.coordinator, Reviews: fixture.reviews,
			Configuration: fixture.configuration, Close: func() {},
		}, nil
	}
	pushes := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		if hooks.provider != nil {
			hooks.provider(fixture)
		}
		if hooks.push != nil {
			hooks.push(fixture)
		}
		return publicationPushSources{
			Paths: fixture.paths, Binding: fixture.binding, Coordinator: fixture.coordinator,
			Reader: pushTestAcceptedSource{transport: fixture.transport}, Transport: fixture.transport,
			Reviews: fixture.reviews, Records: newPublicationProposalStore(fixture.paths.PublicationStateDir()),
			Configuration: fixture.configuration, Close: func() {},
		}, nil
	}
	command := newSyncCommand(
		&stdout,
		&stderr,
		&exitCode,
		sessions,
		remotes,
		fixture.pullVaults,
		productionPullApplySourcesFactory(os.Getenv),
		previews,
		pushes,
		dids,
	)
	ctx := context.Background()
	if err := command.Run(ctx, append([]string{"dottie", "sync"}, args...)); err != nil && exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return exitCode, stdout.String(), stderr.String()
}

func syncTestToken(t *testing.T, output string) string {
	t.Helper()
	match := regexp.MustCompile(`(?m)^confirmation: ([0-9a-f]{64})$`).FindStringSubmatch(output)
	require.Len(t, match, 2)
	return match[1]
}

func (fixture *syncTestFixture) confirmedScenario(t *testing.T) {
	t.Helper()
	fixture.seed(t, fixture.snapshotA(syncTestBaseA))
	fixture.advance(t, fixture.snapshotA(syncTestRemoteA))
	fixture.writeLocal(t, syncTestBaseA, syncTestLocalB)
}

func TestSyncUnconfirmedPrintsBothHalvesAndChangesNothing(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: diverges (record_cid)")
	assert.Contains(t, stdout, "apply: changes=1 unchanged=1")
	assert.Contains(t, stdout, "apply: write a.txt")
	assert.Contains(t, stdout, "push: targets=1 entries=2")
	assert.Contains(t, stdout, "push: candidate payload:")
	assert.Contains(t, stdout, "confirmation: ")
	assert.Contains(t, stdout, "sync: plan only; nothing was applied or published; repeat with --confirm ")
	assert.Equal(t, syncTestBaseA, readSyncFile(t, fixture, "a.txt"), "the unconfirmed run applied the pull half")
	assert.Equal(t, syncTestLocalB, readSyncFile(t, fixture, "b.txt"))
	assert.Equal(t, before.Revision, fixture.readFloor(t).Revision, "the unconfirmed run advanced the floor")
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "the unconfirmed run uploaded the push half")
	assert.Zero(t, sends, "the unconfirmed run submitted the push half")
	assert.Zero(t, fixture.proposalCount(t), "the unconfirmed run left a retained push record")
}

func TestSyncConfirmedAppliesThePullHalfAndPublishesTheReconciledCandidate(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	token := syncTestToken(t, stdout)

	code, confirmed, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
		"--confirm",
		token,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, confirmed, "pull: applied changes=1 unchanged=1")
	assert.Contains(t, confirmed, "floor: revision=")
	assert.Contains(t, confirmed, "push: committed")
	assert.Equal(t, syncTestRemoteA, readSyncFile(t, fixture, "a.txt"), "the pull half did not apply the remote entry")
	assert.Equal(t, syncTestLocalB, readSyncFile(t, fixture, "b.txt"), "the pull half overwrote the local-only entry")
	floor := fixture.readFloor(t)
	assert.Equal(t, before.Revision+2, floor.Revision, "the pull accept and push commit did not both advance the floor")
	assert.Equal(t, before.Sequence+2, floor.Sequence)
	uploads, sends := fixture.transport.counts()
	assert.Equal(t, 1, uploads)
	assert.Equal(t, 1, sends)
	assert.Zero(t, fixture.proposalCount(t), "a retained push record survived the confirmed sync")
	last := syncTestTerminalSnapshot(t, fixture)
	assert.Equal(t, syncTestRemoteA, string(last.Entries[0].File.Content))
	assert.Equal(t, syncTestLocalB, string(last.Entries[1].File.Content))
}

func TestSyncPlainPushWhenTheAcceptedFloorMatchesTheProvider(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.seed(t, fixture.snapshotA(syncTestBaseA))
	fixture.writeLocal(t, syncTestBaseA, syncTestLocalB)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "pull: matches")
	assert.Contains(t, stdout, "apply: changes=0")
	token := syncTestToken(t, stdout)

	code, confirmed, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
		"--confirm",
		token,
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, confirmed, "pull: no changes")
	assert.Contains(t, confirmed, "push: committed")
	uploads, sends := fixture.transport.counts()
	assert.Equal(t, 1, uploads)
	assert.Equal(t, 1, sends)
	last := syncTestTerminalSnapshot(t, fixture)
	assert.Equal(t, syncTestLocalB, string(last.Entries[1].File.Content))
}

func TestSyncRefusesAChangedPullPlan(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	token := syncTestToken(t, stdout)

	fixture.rewriteProvider(t, fixture.snapshotA("synthetic sync remote a moved"))
	code, _, stderr = runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
		"--confirm",
		token,
	)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr, "stale or bound to a different vault")
	assert.Equal(t, syncTestBaseA, readSyncFile(t, fixture, "a.txt"), "a stale sync token applied the pull half")
	assert.Equal(t, before.Revision, fixture.readFloor(t).Revision)
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads)
	assert.Zero(t, sends)
	assert.Zero(t, fixture.proposalCount(t))
}

func TestSyncRefusesAChangedPushCandidate(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	token := syncTestToken(t, stdout)

	require.NoError(
		t,
		os.WriteFile(
			filepath.Join(fixture.paths.Home, "config", "b.txt"),
			[]byte("local changed before confirmation"),
			0o600,
		),
	)
	code, _, stderr = runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
		"--confirm",
		token,
	)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr, "stale or bound to a different vault")
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "a stale sync token uploaded the changed push candidate")
	assert.Zero(t, sends, "a stale sync token submitted the changed push candidate")
}

func TestSyncRefusesAConflictAtPlanningBeforeAnyChange(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.seed(t, fixture.snapshotA(syncTestBaseA))
	fixture.advance(t, fixture.snapshotA(syncTestRemoteA))
	fixture.writeLocal(t, "local conflicting a", syncTestBaseB)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr, "apply-plan/plan_conflict")
	assert.NotContains(t, stdout, "confirmation:")
	assert.Equal(
		t,
		"local conflicting a",
		readSyncFile(t, fixture, "a.txt"),
		"a conflicting sync applied the pull half",
	)
	assert.Equal(t, before.Revision, fixture.readFloor(t).Revision)
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads)
	assert.Zero(t, sends)
	assert.Zero(t, fixture.proposalCount(t))
}

func TestSyncPullRefusalsStopEverythingBeforeAnyPublication(t *testing.T) {
	t.Run("backup-only", func(t *testing.T) {
		fixture := newSyncTestFixture(t, config.BackupOnly)
		fixture.confirmedScenario(t)
		code, stdout, stderr := runSyncForTest(
			t,
			fixture,
			syncTestHooks{},
			"--did",
			fixture.binding.AccountDID,
			"--vault",
			pullTestVaultHex(),
		)
		require.Equal(t, 3, code)
		assert.Contains(t, stderr, "backup-only")
		assert.NotContains(t, stdout, "confirmation:")
		assertSyncNothingPublished(t, fixture)
	})
	t.Run("lease held", func(t *testing.T) {
		fixture := newSyncTestFixture(t, "")
		fixture.confirmedScenario(t)
		code, stdout, stderr := runSyncForTest(
			t,
			fixture,
			syncTestHooks{},
			"--did",
			fixture.binding.AccountDID,
			"--vault",
			pullTestVaultHex(),
		)
		require.Equal(t, 0, code, stderr)
		token := syncTestToken(t, stdout)
		journal, err := publicationstate.OpenJournal(fixture.paths.PublicationStateDir())
		require.NoError(t, err)
		lease, err := journal.AcquireApplyLease(context.Background())
		require.NoError(t, err)
		require.NoError(t, journal.Close())
		defer func() { assert.NoError(t, lease.Close()) }()
		code, _, stderr = runSyncForTest(
			t,
			fixture,
			syncTestHooks{},
			"--did",
			fixture.binding.AccountDID,
			"--vault",
			pullTestVaultHex(),
			"--confirm",
			token,
		)
		require.Equal(t, 3, code)
		assert.Contains(t, stderr, "apply_lease_held")
		assertSyncNothingPublished(t, fixture)
	})
	t.Run("indeterminate provider read", func(t *testing.T) {
		fixture := newSyncTestFixture(t, "")
		fixture.confirmedScenario(t)
		fixture.transport.viewErr = pullTestViewFailure{reason: "revision", cause: atproto.ErrAmbiguousTransport}
		code, stdout, stderr := runSyncForTest(
			t,
			fixture,
			syncTestHooks{},
			"--did",
			fixture.binding.AccountDID,
			"--vault",
			pullTestVaultHex(),
		)
		require.Equal(t, 4, code)
		assert.Contains(t, stdout, "pull: unreadable (revision)")
		assert.Contains(t, stderr, "sync is indeterminate")
		assertSyncNothingPublished(t, fixture)
	})
}

func TestSyncPushRefusalAfterThePullHalfLeavesThePullApplied(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	token := syncTestToken(t, stdout)

	code, confirmed, stderr := runSyncForTest(t, fixture, syncTestHooks{push: func(fixture *syncTestFixture) {
		fixture.reviews.failOn = 4
	}}, "--did", fixture.binding.AccountDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 4, code)
	assert.Contains(t, confirmed, "pull: applied changes=1")
	assert.Contains(t, stderr, "post_pull_prepare")
	assert.Contains(t, stderr, "nothing was published")
	assert.Equal(t, syncTestRemoteA, readSyncFile(t, fixture, "a.txt"), "the pull half did not stay applied")
	assert.Equal(t, before.Revision+1, fixture.readFloor(t).Revision, "the pull half did not advance the floor")
	_, sends := fixture.transport.counts()
	assert.Zero(t, sends, "a refused push half dispatched writes")
	assert.Zero(t, fixture.proposalCount(t), "a refused push half left a retained record")
}

func TestSyncPushHalfReportsADefiniteProviderRefusalWithoutPublishing(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	token := syncTestToken(t, stdout)

	code, confirmed, stderr := runSyncForTest(t, fixture, syncTestHooks{push: func(fixture *syncTestFixture) {
		fixture.transport.sendErr = pushTestDefiniteRejection()
	}}, "--did", fixture.binding.AccountDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 4, code, stderr)
	assert.Contains(t, confirmed, "push: rejected")
	assert.Contains(t, stderr, "the push half did not commit")
	assert.Contains(t, stderr, "nothing was published")
	assert.Equal(t, syncTestRemoteA, readSyncFile(t, fixture, "a.txt"), "the pull half did not stay applied")
	assert.Equal(
		t,
		before.Revision+1,
		fixture.readFloor(t).Revision,
		"the refused push half advanced the accepted floor",
	)
	_, sends := fixture.transport.counts()
	assert.Equal(t, 1, sends, "the refused push half dispatched writes twice")
}

func TestSyncRefusesWhenThePostPullCandidateChangesDuringApply(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	token := syncTestToken(t, stdout)

	code, confirmed, stderr := runSyncForTest(t, fixture, syncTestHooks{push: func(fixture *syncTestFixture) {
		require.NoError(
			t,
			os.WriteFile(filepath.Join(fixture.paths.Home, "config", "b.txt"), []byte("drifted during apply"), 0o600),
		)
	}}, "--did", fixture.binding.AccountDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 4, code)
	assert.Contains(t, confirmed, "pull: applied changes=1")
	assert.Contains(t, stderr, "post_pull_candidate_mismatch")
	assert.Contains(t, stderr, "nothing was published")
	assert.Equal(t, before.Revision+1, fixture.readFloor(t).Revision, "the pull half did not stay accepted")
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "a mismatched post-pull candidate uploaded")
	assert.Zero(t, sends, "a mismatched post-pull candidate dispatched writes")
	assert.Zero(t, fixture.proposalCount(t), "a mismatched post-pull candidate left a retained record")
}

func TestSyncRequiresTheDIDSelectorAndRejectsUnknownFlags(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.setEnvironment(t)
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "handle instead of did", args: []string{"--handle", "example.test"}, want: "flag provided but not defined"},
		{name: "malformed vault", args: []string{"--did", fixture.binding.AccountDID, "--vault", "abcd"}, want: "--vault must be a 32-byte hexadecimal identifier"},
		{name: "malformed confirmation", args: []string{"--did", fixture.binding.AccountDID, "--vault", pullTestVaultHex(), "--confirm", "abcd"}, want: "32-byte hexadecimal confirmation"},
		{name: "positional argument", args: []string{"--did", fixture.binding.AccountDID, "--vault", pullTestVaultHex(), "extra"}, want: "sync takes no positional arguments"},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runSyncForTest(t, fixture, syncTestHooks{}, test.args...)
			require.Equal(t, 2, code)
			assert.Empty(t, stdout)
			assert.Contains(t, stderr, test.want)
		})
	}
}

func TestSyncConfirmationTokenBindsThePullAndPushHalves(t *testing.T) {
	binding := publicationstate.Binding{
		AccountDID: pullTestDID,
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x62},
	}
	binding.Repository = "at://" + pullTestDID
	plan := sha256.Sum256([]byte("pull plan"))
	stateToken := sha256.Sum256([]byte("staged state"))
	observation := sha256.Sum256([]byte("observation"))
	view := sha256.Sum256([]byte("provider view"))
	identity := syncPushIdentity{
		PayloadCID:    []byte{0x01},
		PayloadDigest: sha256.Sum256([]byte("candidate")),
		PayloadSize:   9,
		Review: publicationstate.LocalReviewContext{
			SelectionDigest:   [32]byte{0x71},
			SelectionRevision: 2,
			ApprovalDigest:    [32]byte{0x72},
			ApprovalRevision:  3,
		},
	}
	token := syncConfirmationToken(binding, plan, stateToken, observation, view, identity)
	assert.NotEqual(
		t,
		token,
		syncConfirmationToken(binding, sha256.Sum256([]byte("changed plan")), stateToken, observation, view, identity),
	)
	assert.NotEqual(
		t,
		token,
		syncConfirmationToken(binding, plan, sha256.Sum256([]byte("moved state")), observation, view, identity),
	)
	assert.NotEqual(
		t,
		token,
		syncConfirmationToken(binding, plan, stateToken, sha256.Sum256([]byte("moved observation")), view, identity),
	)
	assert.NotEqual(
		t,
		token,
		syncConfirmationToken(binding, plan, stateToken, observation, sha256.Sum256([]byte("moved view")), identity),
	)
	moved := identity
	moved.PayloadDigest = sha256.Sum256([]byte("changed candidate"))
	assert.NotEqual(t, token, syncConfirmationToken(binding, plan, stateToken, observation, view, moved))
	reviewed := identity
	reviewed.Review.ApprovalRevision++
	assert.NotEqual(t, token, syncConfirmationToken(binding, plan, stateToken, observation, view, reviewed))
	otherVault := binding
	otherVault.Vault = [32]byte{0x63}
	assert.NotEqual(t, token, syncConfirmationToken(otherVault, plan, stateToken, observation, view, identity))
	assert.Equal(t, token, syncConfirmationToken(binding, plan, stateToken, observation, view, identity))
}

func TestSyncRefusesAFloorThatDoesNotMatchTheReviewedPosition(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	_, record := fixture.seed(t, fixture.snapshotA(syncTestBaseA))
	block, _ := syncTestRecord(t, fixture.binding, []byte("other payload"), 0, nil)
	view := publicationstate.SuppliedRepositoryView{Snapshots: []publicationstate.SnapshotBlock{block}}
	floor := publicationstate.Floor{
		RecordCID:   record.Blob.CID,
		BlobCID:     record.Blob.CID,
		BlobSize:    record.Blob.Size,
		Sequence:    0,
		SnapshotKey: block.Key,
	}
	require.ErrorIs(t, syncViewMatchesFloor(floor, view), errSyncFloorMismatch)
	assert.NoError(t, syncViewMatchesFloor(publicationstate.Floor{
		RecordCID: mustPullRecordCID(
			t,
			block.Raw,
		),
		BlobCID:     mustPullBlobCID(t, block.Raw),
		BlobSize:    mustPullBlobSize(t, block.Raw),
		Sequence:    0,
		SnapshotKey: block.Key,
	}, view))
}

func readSyncFile(t *testing.T, fixture *syncTestFixture, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture.paths.Home, "config", name))
	require.NoError(t, err)
	return string(data)
}

func assertSyncNothingPublished(t *testing.T, fixture *syncTestFixture) {
	t.Helper()
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "a refused sync uploaded a payload")
	assert.Zero(t, sends, "a refused sync dispatched writes")
	assert.Zero(t, fixture.proposalCount(t), "a refused sync left a retained push record")
}

func syncTestTerminalSnapshot(t *testing.T, fixture *syncTestFixture) model.Snapshot {
	t.Helper()
	raw := fixture.terminal(t)
	record, err := publication.DecodeSnapshot(raw)
	require.NoError(t, err)
	fixture.transport.mu.Lock()
	payload := bytes.Clone(fixture.transport.blobs[string(record.Blob.CID)])
	fixture.transport.mu.Unlock()
	snapshot, err := publication.DecodePayload(payload, record.Blob)
	require.NoError(t, err)
	return snapshot
}

func mustPullRecordCID(t *testing.T, raw []byte) []byte {
	t.Helper()
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	return cid
}

func mustPullBlobCID(t *testing.T, raw []byte) []byte {
	t.Helper()
	record, err := publication.DecodeSnapshot(raw)
	require.NoError(t, err)
	return record.Blob.CID
}

func mustPullBlobSize(t *testing.T, raw []byte) uint64 {
	t.Helper()
	record, err := publication.DecodeSnapshot(raw)
	require.NoError(t, err)
	return record.Blob.Size
}

func TestSyncRefusesAProviderViewThatDivergesWhileTheFloorStillMatches(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTest(
		t,
		fixture,
		syncTestHooks{},
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	token := syncTestToken(t, stdout)

	code, confirmed, stderr := runSyncForTest(t, fixture, syncTestHooks{provider: func(fixture *syncTestFixture) {
		fixture.transport.mu.Lock()
		defer fixture.transport.mu.Unlock()
		terminalKey := ""
		for key := range fixture.transport.blocks {
			if key > terminalKey {
				terminalKey = key
			}
		}
		require.NotEmpty(t, terminalKey)
		earlier := bytes.Clone(fixture.transport.blocks[terminalKey])
		fixture.transport.blocks["0000000000000"] = earlier
	}}, "--did", fixture.binding.AccountDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 4, code)
	assert.Contains(t, confirmed, "pull: applied changes=1")
	assert.Contains(t, stderr, "post_pull_provider_moved")
	assert.Equal(t, before.Revision+1, fixture.readFloor(t).Revision, "the pull half did not stay accepted")
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "a diverged provider view uploaded")
	assert.Zero(t, sends, "a diverged provider view dispatched writes")
	assert.Zero(t, fixture.proposalCount(t), "a diverged provider view left a retained record")
}

func TestSyncResolvesTheOnlyAuthorisedSessionWhenDIDIsOmitted(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	code, stdout, stderr := runSyncForTestWithDIDs(
		t,
		fixture,
		syncTestHooks{},
		pushTestDIDs(fixture.binding.AccountDID),
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	assert.Contains(
		t,
		stdout,
		"account: "+fixture.binding.AccountDID+" (resolved from the only authorised session; --did was omitted)",
	)
	assert.Contains(t, stdout, "pull: diverges (record_cid)")
	assert.Contains(t, stdout, "sync: plan only; nothing was applied or published")
	assert.Equal(t, before.Revision, fixture.readFloor(t).Revision, "the unconfirmed run advanced the floor")
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads)
	assert.Zero(t, sends)
}

func TestSyncRefusesWithoutAnyAuthorisedSession(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	before := publicationStateEntries(t, fixture.paths.PublicationStateDir())
	code, stdout, stderr := runSyncForTestWithDIDs(t, fixture, syncTestHooks{}, pushTestDIDs())
	require.Equal(t, 3, code)
	assert.Empty(t, stdout)
	assert.Equal(
		t,
		"dottie: sync refused: no account is authorised locally; run dottie account login --handle HANDLE or pass --did DID\n",
		stderr,
	)
	assert.Equal(
		t,
		before,
		publicationStateEntries(t, fixture.paths.PublicationStateDir()),
		"the refusal wrote local state",
	)
}

func TestSyncRefusesTwoAuthorisedSessionsWithoutDID(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	before := fixture.readFloor(t)
	other := "did:plc:zyxwvutsrqponmlkjihgfedc"
	code, stdout, stderr := runSyncForTestWithDIDs(
		t,
		fixture,
		syncTestHooks{},
		pushTestDIDs(fixture.binding.AccountDID, other),
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 3, code)
	assert.Empty(t, stdout)
	assert.Equal(
		t,
		"dottie: sync refused: 2 accounts are authorised locally; --did is required to choose the account this command acts on\n",
		stderr,
	)
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "the ambiguous refusal uploaded a payload")
	assert.Zero(t, sends, "the ambiguous refusal dispatched writes")
	assert.Zero(t, fixture.proposalCount(t), "the ambiguous refusal left a retained record")
	assert.Equal(t, before.Revision, fixture.readFloor(t).Revision, "the ambiguous refusal advanced the floor")
	assert.Equal(t, syncTestBaseA, readSyncFile(t, fixture, "a.txt"), "the ambiguous refusal applied the pull half")
}

func TestSyncProceedsWithTheExplicitDIDWhenTwoSessionsAreAuthorised(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	other := "did:plc:zyxwvutsrqponmlkjihgfedc"
	code, stdout, stderr := runSyncForTestWithDIDs(
		t,
		fixture,
		syncTestHooks{},
		pushTestDIDs(other, fixture.binding.AccountDID),
		"--did",
		fixture.binding.AccountDID,
		"--vault",
		pullTestVaultHex(),
	)
	require.Equal(t, 0, code, stderr)
	assert.NotContains(
		t,
		stdout,
		"resolved from the only authorised session",
		"an explicit --did reported a session resolution",
	)
	assert.Contains(t, stdout, "pull: diverges (record_cid)")
}

func TestSyncRefusesAnExplicitDIDWithNoStoredSession(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.confirmedScenario(t)
	fixture.setEnvironment(t)
	var stdout, stderr bytes.Buffer
	exitCode := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		return pushSession{}, atproto.ErrSessionNotFound
	}
	remotes := func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error) {
		return pullRemote{}, errors.New("the provider reader must not be constructed")
	}
	previews := func(context.Context, *urfave.Command, publicationstate.Binding) (syncPushPreviewSources, error) {
		return syncPushPreviewSources{}, errors.New("the preview must not be constructed")
	}
	pushes := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return publicationPushSources{}, errors.New("the push sources must not be constructed")
	}
	command := newSyncCommand(
		&stdout,
		&stderr,
		&exitCode,
		sessions,
		remotes,
		fixture.pullVaults,
		productionPullApplySourcesFactory(os.Getenv),
		previews,
		pushes,
		pushTestDIDs(fixture.binding.AccountDID),
	)
	args := []string{"dottie", "sync", "--did", fixture.binding.AccountDID, "--vault", pullTestVaultHex()}
	if err := command.Run(context.Background(), args); err != nil && exitCode == 0 {
		command.ExitErrHandler(context.Background(), command, err)
	}
	require.Equal(t, 3, exitCode)
	assert.Empty(t, stdout.String())
	assert.Equal(t, "dottie: sync refused: account session is unavailable\n", stderr.String())
}

func TestSyncResolvesThePublishedVaultWhenNoBindingIsStored(t *testing.T) {
	fixture := newSyncTestFixture(t, "")
	fixture.setEnvironment(t)
	var stdout, stderr bytes.Buffer
	exitCode := 0
	vaultCalls := 0
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		vaultCalls++
		return fixture.binding.Vault, nil
	}
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return fixture.session(), nil }
	remotes := func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error) {
		return pullRemote{}, errors.New("the provider reader must not be constructed")
	}
	previews := func(context.Context, *urfave.Command, publicationstate.Binding) (syncPushPreviewSources, error) {
		return syncPushPreviewSources{}, errors.New("the preview must not be constructed")
	}
	pushes := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return publicationPushSources{}, errors.New("the push sources must not be constructed")
	}
	command := newSyncCommand(
		&stdout,
		&stderr,
		&exitCode,
		sessions,
		remotes,
		vaults,
		productionPullApplySourcesFactory(os.Getenv),
		previews,
		pushes,
		pushTestDIDs(fixture.binding.AccountDID),
	)
	ctx := context.Background()
	if err := command.Run(
		ctx,
		[]string{"dottie", "sync", "--did", fixture.binding.AccountDID},
	); err != nil &&
		exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	require.Equal(t, 3, exitCode)
	assert.Equal(t, 1, vaultCalls, "the sync did not resolve the published vault exactly once")
	assert.Equal(
		t,
		"vault: "+pullTestVaultHex()+" (adopted from the published position at self)\npull: unreadable (position_absent)\n",
		stdout.String(),
	)
	assert.Equal(
		t,
		"dottie: sync refused: the local position store cannot be inspected read-only; nothing was changed\n",
		stderr.String(),
	)
}
