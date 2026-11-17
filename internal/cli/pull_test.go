package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
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
	"github.com/lamb-systems/dottie/internal/vault"
)

const pullTestDID = "did:plc:abcdefghijklmnopqrstuvwx"

const (
	pullTestBaseContent   = "synthetic pull payload"
	pullTestRemoteContent = "synthetic pull payload two"
)

type pullTestReader struct {
	mu       sync.Mutex
	view     publicationstate.SuppliedRepositoryView
	payloads map[uint64]model.Snapshot
	err      error
	reads    int
}

func (reader *pullTestReader) ReadPayload(
	ctx context.Context,
	record publication.SnapshotRecord,
) (model.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, err
	}
	snapshot, ok := reader.payloads[record.PublicationSeq]
	if !ok {
		return model.Snapshot{}, errors.New("synthetic payload is unavailable")
	}
	return snapshot, nil
}

func (reader *pullTestReader) ReadBlob(ctx context.Context, record publication.SnapshotRecord) ([]byte, error) {
	snapshot, err := reader.ReadPayload(ctx, record)
	if err != nil {
		return nil, err
	}
	packed, err := vault.Pack(snapshot)
	if err != nil {
		return nil, err
	}
	return packed.Payload, nil
}

func (reader *pullTestReader) ReadView(ctx context.Context) (publicationstate.SuppliedRepositoryView, error) {
	if err := ctx.Err(); err != nil {
		return publicationstate.SuppliedRepositoryView{}, err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.reads++
	if reader.err != nil {
		return publicationstate.SuppliedRepositoryView{}, reader.err
	}
	return reader.view, nil
}

func (reader *pullTestReader) count() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.reads
}

type pullTestViewFailure struct {
	reason string
	cause  error
}

func (failure pullTestViewFailure) Error() string { return "synthetic provider view failure" }

func (failure pullTestViewFailure) Unwrap() error { return failure.cause }

func (failure pullTestViewFailure) Reason() string { return failure.reason }

type pullTestFixture struct {
	paths    platform.Paths
	binding  publicationstate.Binding
	payload  []byte
	snapshot model.Snapshot
	context  publicationstate.SuppliedContext
	block    publicationstate.SnapshotBlock
	record   publication.SnapshotRecord
	head     []byte
}

func newPullTestFixture(t *testing.T) *pullTestFixture {
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
	binding := publicationstate.Binding{
		AccountDID: pullTestDID,
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x62},
	}
	binding.Repository = "at://" + binding.AccountDID
	snapshot := model.Snapshot{
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
					Path:    "init.lua",
					State:   model.FilePresent,
					Kind:    model.FileRegular,
					Content: []byte(pullTestBaseContent),
					Mode:    0o600,
				},
			},
		},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	block, record := pullTestSnapshot(t, binding, packed.Payload, 0, nil)
	return &pullTestFixture{
		paths:    paths,
		binding:  binding,
		payload:  packed.Payload,
		snapshot: snapshot,
		context: publicationstate.SuppliedContext{
			RepositoryRevision: "synthetic-pull-revision",
			RepositoryDigest:   []byte{0x51, 0x52, 0x53},
		},
		block:  block,
		record: record,
		head:   pullTestHead(t, binding, block, record),
	}
}

func pullTestSnapshot(
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
	binary.BigEndian.PutUint64(record.PublicationID[8:], sequence+1)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	return publicationstate.SnapshotBlock{Key: key, Raw: raw}, record
}

func pullTestHead(
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

func (fixture *pullTestFixture) observation() publicationstate.Observation {
	return publicationstate.Observation{
		Origin: fixture.binding, SuppliedContext: fixture.context, Head: bytes.Clone(fixture.head),
		Snapshots: []publicationstate.SnapshotBlock{{Key: fixture.block.Key, Raw: bytes.Clone(fixture.block.Raw)}},
	}
}

func (fixture *pullTestFixture) view() publicationstate.SuppliedRepositoryView {
	return publicationstate.SuppliedRepositoryView{
		Origin: fixture.binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: fixture.context, Head: bytes.Clone(fixture.head),
		Snapshots: []publicationstate.SnapshotBlock{{Key: fixture.block.Key, Raw: bytes.Clone(fixture.block.Raw)}},
	}
}

func (fixture *pullTestFixture) divergedView(t *testing.T) publicationstate.SuppliedRepositoryView {
	t.Helper()
	payload := append(bytes.Clone(fixture.payload), 0x00)
	block, record := pullTestSnapshot(t, fixture.binding, payload, 0, nil)
	return publicationstate.SuppliedRepositoryView{
		Origin: fixture.binding,
		Scope:  publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{
			RepositoryRevision: "synthetic-pull-revision",
			RepositoryDigest:   []byte{0x51, 0x52, 0x53},
		},
		Head:      pullTestHead(t, fixture.binding, block, record),
		Snapshots: []publicationstate.SnapshotBlock{{Key: block.Key, Raw: block.Raw}},
	}
}

func (fixture *pullTestFixture) openStore(t *testing.T) *publicationstate.Store {
	t.Helper()
	require.NoError(t, os.MkdirAll(fixture.paths.PublicationStateDir(), 0o700))
	require.NoError(t, os.Chmod(fixture.paths.PublicationStateDir(), 0o700))
	store, err := publicationstate.Open(fixture.paths.PublicationStateDir(), fixture.binding)
	require.NoError(t, err)
	return store
}

func (fixture *pullTestFixture) accept(t *testing.T) {
	t.Helper()
	store := fixture.openStore(t)
	observation := fixture.observation()
	proposal, err := store.Prepare(context.Background(), publicationstate.ModeFirstUse, observation, fixture.payload)
	require.NoError(t, err)
	_, err = store.Accept(
		context.Background(),
		publicationstate.ModeFirstUse,
		proposal.StateToken,
		observation,
		fixture.payload,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	require.NoError(t, store.Close())
}

func (fixture *pullTestFixture) emptyStore(t *testing.T) {
	t.Helper()
	require.NoError(t, fixture.openStore(t).Close())
}

func (fixture *pullTestFixture) payloads() map[uint64]model.Snapshot {
	return map[uint64]model.Snapshot{fixture.record.PublicationSeq: fixture.snapshot}
}

func (fixture *pullTestFixture) advancedView(
	t *testing.T,
	content string,
) (publicationstate.SuppliedRepositoryView, map[uint64]model.Snapshot) {
	t.Helper()
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: fixture.snapshot.Targets,
		Entries: []model.Entry{
			{
				TargetID: "files",
				File: &model.FileEntry{
					Path:    "init.lua",
					State:   model.FilePresent,
					Kind:    model.FileRegular,
					Content: []byte(content),
					Mode:    0o600,
				},
			},
		},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	parent, err := publication.RecordCID(fixture.block.Raw)
	require.NoError(t, err)
	block, record := pullTestSnapshot(t, fixture.binding, packed.Payload, fixture.record.PublicationSeq+1, parent)
	view := publicationstate.SuppliedRepositoryView{
		Origin:          fixture.binding,
		Scope:           publicationstate.ViewScopeWholeRepository,
		SuppliedContext: fixture.context,
		Head:            pullTestHead(t, fixture.binding, block, record),
		Snapshots: []publicationstate.SnapshotBlock{
			{Key: fixture.block.Key, Raw: bytes.Clone(fixture.block.Raw)},
			block,
		},
	}
	payloads := map[uint64]model.Snapshot{
		fixture.record.PublicationSeq: fixture.snapshot,
		record.PublicationSeq:         snapshot,
	}
	return view, payloads
}

func (fixture *pullTestFixture) writeBaseFile(t *testing.T) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(fixture.targetPath("init.lua")), 0o700))
	require.NoError(t, os.WriteFile(fixture.targetPath("init.lua"), []byte(pullTestBaseContent), 0o600))
}

func (fixture *pullTestFixture) configure(t *testing.T, mode config.Mode) {
	t.Helper()
	directory := fixture.paths.AppConfigDir()
	require.NoError(t, os.MkdirAll(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o700))
	content := "config_version = 2\n\n[[targets]]\nid = \"files\"\nsource = \"files\"\n"
	if mode != "" {
		content += "mode = \"" + string(mode) + "\"\n"
	}
	content += "\n[targets.root]\nbase = \"home\"\npath = \"config\"\nkind = \"directory\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(directory, config.FileName), []byte(content), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(fixture.paths.Home, "config"), 0o700))
}

func (fixture *pullTestFixture) targetPath(name string) string {
	return filepath.Join(fixture.paths.Home, "config", name)
}

func pullTestConfirmation(t *testing.T, output string) string {
	t.Helper()
	match := regexp.MustCompile(`(?m)^confirmation: ([0-9a-f]{64})$`).FindStringSubmatch(output)
	require.Len(t, match, 2)
	return match[1]
}

func newPullTestCommand(
	t *testing.T,
	fixture *pullTestFixture,
	stdout, stderr *bytes.Buffer,
	exitCode *int,
	session *atproto.Session,
	sessionErr error,
	reader *pullTestReader,
	factoryCalls *int,
) *urfave.Command {
	t.Helper()
	return newPullTestCommandWithDIDs(
		t,
		fixture,
		stdout,
		stderr,
		exitCode,
		session,
		sessionErr,
		reader,
		factoryCalls,
		pushTestDIDs(pullTestDID),
	)
}

func newPullTestCommandWithDIDs(
	t *testing.T,
	fixture *pullTestFixture,
	stdout, stderr *bytes.Buffer,
	exitCode *int,
	session *atproto.Session,
	sessionErr error,
	reader *pullTestReader,
	factoryCalls *int,
	dids sessionDIDSource,
) *urfave.Command {
	t.Helper()
	return newPullTestCommandWithVaults(
		t,
		fixture,
		stdout,
		stderr,
		exitCode,
		session,
		sessionErr,
		reader,
		factoryCalls,
		dids,
		func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
			return fixture.binding.Vault, nil
		},
	)
}

func newPullTestCommandWithVaults(
	t *testing.T,
	fixture *pullTestFixture,
	stdout, stderr *bytes.Buffer,
	exitCode *int,
	session *atproto.Session,
	sessionErr error,
	reader *pullTestReader,
	factoryCalls *int,
	dids sessionDIDSource,
	vaults pullVaultFactory,
) *urfave.Command {
	t.Helper()
	t.Setenv("HOME", fixture.paths.Home)
	t.Setenv("XDG_CONFIG_HOME", fixture.paths.ConfigHome)
	t.Setenv("XDG_STATE_HOME", fixture.paths.StateHome)
	t.Setenv("XDG_CACHE_HOME", fixture.paths.CacheHome)
	t.Setenv("XDG_DATA_HOME", fixture.paths.DataHome)
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		if sessionErr != nil {
			return pushSession{}, sessionErr
		}
		return pushSession{Session: session}, nil
	}
	remotes := func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error) {
		if factoryCalls != nil {
			*factoryCalls++
		}
		return pullRemote{Reader: reader, Blob: reader.ReadBlob, Close: func() {}}, nil
	}
	return newPullCommand(
		stdout,
		stderr,
		exitCode,
		sessions,
		remotes,
		vaults,
		productionPullApplySourcesFactory(os.Getenv),
		dids,
		os.Getenv,
	)
}

func runPullForTest(command *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	arguments := append([]string{"dottie", "pull"}, args...)
	if err := command.Run(ctx, arguments); err != nil && *exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return *exitCode
}

func pullTestSession() *atproto.Session {
	return &atproto.Session{DID: pullTestDID, Scopes: atproto.VaultScopes()}
}

func pullTestVaultHex() string {
	vault := [32]byte{0x62}
	return hex.EncodeToString(vault[:])
}

func pullTestForeignVaultHex() string {
	vault := [32]byte{0x63}
	return hex.EncodeToString(vault[:])
}

func pullTestDirectoryState(t *testing.T, directory string) []string {
	t.Helper()
	var entries []string
	walkErr := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			entries = append(entries, relative+"/"+info.Mode().String())
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		entries = append(entries, fmt.Sprintf("%s=%d:%x:%s", relative, info.Size(), digest, info.Mode().String()))
		return nil
	})
	require.NoError(t, walkErr)
	sort.Strings(entries)
	return entries
}

func TestPullComparisonClassifiesTheFloorAgainstTheValidatedView(t *testing.T) {
	fixture := newPullTestFixture(t)
	recordCID, err := publication.RecordCID(fixture.block.Raw)
	require.NoError(t, err)
	accepted := publicationstate.Floor{
		RecordCID: recordCID,
		BlobCID:   fixture.record.Blob.CID,
		BlobSize:  fixture.record.Blob.Size,
	}
	for _, test := range []struct {
		name  string
		floor publicationstate.Floor
		view  publicationstate.SuppliedRepositoryView
		want  pullFinding
	}{
		{name: "matching record and payload size", floor: accepted, view: fixture.view(), want: pullFinding{Kind: pullFindingMatches}},
		{name: "empty provider records", floor: accepted, view: publicationstate.SuppliedRepositoryView{}, want: pullFinding{Kind: pullFindingAbsent}},
		{name: "different record", floor: publicationstate.Floor{RecordCID: []byte{0x01, 0x02}, BlobSize: fixture.record.Blob.Size}, view: fixture.view(),
			want: pullFinding{Kind: pullFindingDiverges, Reason: pullDivergenceRecordCID}},
		{name: "different payload size", floor: publicationstate.Floor{RecordCID: recordCID, BlobSize: fixture.record.Blob.Size + 1}, view: fixture.view(),
			want: pullFinding{Kind: pullFindingDiverges, Reason: pullDivergencePayloadSize}},
		{name: "undecodable provider record", floor: accepted,
			view: publicationstate.SuppliedRepositoryView{Snapshots: []publicationstate.SnapshotBlock{{Key: fixture.block.Key, Raw: []byte("not a snapshot record")}}},
			want: pullFinding{Kind: pullFindingUnreadable, Reason: pullReasonRecord}},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, comparePullPosition(test.floor, test.view))
		})
	}
}

func TestPullRendersOneLinePerFinding(t *testing.T) {
	assert.Equal(t, "pull: matches\n", renderPullFinding(pullFinding{Kind: pullFindingMatches}))
	assert.Equal(t, "pull: absent\n", renderPullFinding(pullFinding{Kind: pullFindingAbsent}))
	assert.Equal(
		t,
		"pull: diverges (record_cid)\n",
		renderPullFinding(pullFinding{Kind: pullFindingDiverges, Reason: pullDivergenceRecordCID}),
	)
	assert.Equal(
		t,
		"pull: unreadable (locked)\n",
		renderPullFinding(pullFinding{Kind: pullFindingUnreadable, Reason: "locked"}),
	)
	assert.Equal(
		t,
		"pull: unreadable (a\\x1B[2Jb)\n",
		renderPullFinding(pullFinding{Kind: pullFindingUnreadable, Reason: "a\x1b[2Jb"}),
	)
}

func TestPullReportsAMatchingPositionAndWritesNothing(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	before := pullTestDirectoryState(t, fixture.paths.PublicationStateDir())
	reader := &pullTestReader{view: fixture.view()}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code)
	assert.Equal(t, "pull: matches\n", stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, 1, reader.count())
	assert.Equal(
		t,
		before,
		pullTestDirectoryState(t, fixture.paths.PublicationStateDir()),
		"the inspection changed the position store",
	)
	assert.NotContains(t, stdout.String(), fixture.paths.Home)
	assert.NotContains(t, stdout.String(), pullTestVaultHex())
	assert.NotContains(t, stdout.String(), pullTestDID)
}

func TestPullReportsAbsentWhenTheProviderHoldsNoRecords(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{view: publicationstate.SuppliedRepositoryView{}}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code)
	assert.Equal(t, "pull: absent\n", stdout.String())
	assert.Empty(t, stderr.String())
}

func TestPullReportsDivergenceAsAFindingNotAFailure(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{view: fixture.divergedView(t)}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code)
	assert.Equal(t, "pull: diverges (record_cid)\n", stdout.String())
	assert.Empty(t, stderr.String())
}

func TestPullRefusesAScopeGrantBeforeDiscovery(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	before := pullTestDirectoryState(t, fixture.paths.PublicationStateDir())
	reader := &pullTestReader{view: fixture.view()}
	factoryCalls := 0
	session := &atproto.Session{DID: pullTestDID, Scopes: []string{"atproto"}}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, session, nil, reader, &factoryCalls)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls, "the scope refusal reached account discovery")
	assert.Zero(t, reader.count())
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "v2 publication profile")
	assert.Contains(t, stderr.String(), "unchanged")
	assert.Equal(t, before, pullTestDirectoryState(t, fixture.paths.PublicationStateDir()))
}

func TestPullRefusesAnUnavailableSessionBeforeTheScopeCheck(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{}
	factoryCalls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		nil,
		errors.New("synthetic keyring failure"),
		reader,
		&factoryCalls,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls)
	assert.Zero(t, reader.count())
	assert.Equal(t, "dottie: pull refused: account session is unavailable\n", stderr.String())
}

func TestPullRefusesAnAccountThatDiffersFromTheDIDBinding(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{}
	factoryCalls := 0
	session := &atproto.Session{DID: "did:plc:zyxwvutsrqponmlkjihgfedc", Scopes: atproto.VaultScopes()}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, session, nil, reader, &factoryCalls)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls)
	assert.Zero(t, reader.count())
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "differs from the --did publication binding")
}

func TestPullAdoptsThePublishedVaultWhenNoBindingIsStored(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}
	vaultCalls := 0
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		vaultCalls++
		return fixture.binding.Vault, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithVaults(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		nil,
		pushTestDIDs(pullTestDID),
		vaults,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID)
	require.Equal(t, 0, code, stderr.String())
	assert.Equal(t, 1, vaultCalls, "the pull did not resolve the published vault exactly once")
	assert.Contains(t, stdout.String(), "vault: "+pullTestVaultHex()+" (adopted from the published position at self)\n")
	assert.Contains(t, stdout.String(), "pull: first-use\n")
	assert.Contains(t, stdout.String(), "pull: plan only; nothing was applied; repeat with --confirm ")
	info, err := os.Stat(fixture.paths.PublicationStateDir())
	require.NoError(t, err, "the unconfirmed newcomer pull did not provision the position store")
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	stored, err := publicationstate.ReadBinding(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	assert.Equal(t, fixture.binding, stored, "the adopted binding was not recorded")
}

func TestPullUsesTheExplicitVaultWithoutReadingThePublishedVault(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{view: fixture.view()}
	vaultCalls := 0
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		vaultCalls++
		return [32]byte{0x77}, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithVaults(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		nil,
		pushTestDIDs(pullTestDID),
		vaults,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Zero(t, vaultCalls, "an explicit --vault still read the published vault")
	assert.Equal(t, "pull: matches\n", stdout.String())
	assert.NotContains(t, stdout.String(), pullTestVaultHex())
}

func TestPullPrefersTheStoredBindingOverThePublishedVault(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{view: fixture.view()}
	vaultCalls := 0
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		vaultCalls++
		return [32]byte{0x77}, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithVaults(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		nil,
		pushTestDIDs(pullTestDID),
		vaults,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID)
	require.Equal(t, 0, code, stderr.String())
	assert.Zero(t, vaultCalls, "a recorded binding still read the published vault")
	assert.Equal(
		t,
		"vault: "+pullTestVaultHex()+" (resolved from the recorded binding)\npull: matches\n",
		stdout.String(),
	)
}

func TestPullRefusesAnAccountWithNoPublishedVault(t *testing.T) {
	fixture := newPullTestFixture(t)
	factoryCalls := 0
	reader := &pullTestReader{view: fixture.view()}
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		return [32]byte{}, service.ErrPublicationHeadAbsent
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithVaults(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		&factoryCalls,
		pushTestDIDs(pullTestDID),
		vaults,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID)
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: no-publication\n", stdout.String())
	assert.Contains(t, stderr.String(), "the account publishes no v2 position record at self")
	assert.Contains(t, stderr.String(), "pass --vault")
	assert.Zero(t, reader.count(), "the refusal read the provider view")
	assert.Zero(t, factoryCalls, "the refusal constructed the provider reader")
	_, statErr := os.Lstat(fixture.paths.PublicationStateDir())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the refusal created the position store directory")
}

func TestPullTreatsAnUnresolvedPublishedVaultReadAsIndeterminate(t *testing.T) {
	fixture := newPullTestFixture(t)
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		return [32]byte{}, atproto.ErrRevisionMoving
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithVaults(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		&pullTestReader{},
		nil,
		pushTestDIDs(pullTestDID),
		vaults,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID)
	require.Equal(t, 4, code)
	assert.Equal(t, "pull: unreadable (head)\n", stdout.String())
	assert.Contains(t, stderr.String(), "the published vault read did not resolve")
	_, statErr := os.Lstat(fixture.paths.PublicationStateDir())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the indeterminate read created the position store directory")
}

func TestPullWithoutAVaultStillRefusesAnUnusablePositionStore(t *testing.T) {
	fixture := newPullTestFixture(t)
	directory := fixture.paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o755))
	vaultCalls := 0
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		vaultCalls++
		return fixture.binding.Vault, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithVaults(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		&pullTestReader{},
		nil,
		pushTestDIDs(pullTestDID),
		vaults,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID)
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: unreadable (io)\n", stdout.String())
	assert.Contains(t, stderr.String(), "the local position store cannot be inspected read-only")
	assert.Zero(t, vaultCalls, "an unusable local store still read the published vault")
	info, err := os.Stat(directory)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "the refused store directory was repaired")
}

func TestPullRefusesAnUnsafePositionStoreWithoutRecreatingIt(t *testing.T) {
	fixture := newPullTestFixture(t)
	directory := fixture.paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o755))
	reader := &pullTestReader{}
	factoryCalls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, &factoryCalls)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: unreadable (unsafe)\n", stdout.String())
	assert.Contains(t, stderr.String(), "neither created nor repaired")
	assert.Zero(t, reader.count(), "an unusable local store still contacted the provider")
	assert.Zero(t, factoryCalls, "an unusable local store still reached discovery")
	info, err := os.Stat(directory)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "the refused store directory was repaired")
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	assert.Empty(t, entries, "the refused store directory was populated")
}

func TestPullProvisionsAnAbsentPositionStoreAndAdoptsOnlyOnConfirm(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(t, stdout.String(), "pull: first-use\n")
	assert.Contains(t, stdout.String(), "apply: changes=1 unchanged=0\n")
	assert.Contains(t, stdout.String(), fmt.Sprintf("apply: write init.lua size=%d\n", len(pullTestBaseContent)))
	assert.Contains(t, stdout.String(), "pull: plan only; nothing was applied; repeat with --confirm ")
	assert.NotContains(t, stdout.String(), "pull: applied")
	info, err := os.Stat(fixture.paths.PublicationStateDir())
	require.NoError(t, err, "the unconfirmed newcomer pull did not provision the position store")
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	inspection, err := publicationstate.Inspect(
		context.Background(),
		fixture.paths.PublicationStateDir(),
		fixture.binding,
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present, "the unconfirmed newcomer pull accepted a floor")
	_, statErr := os.Lstat(fixture.targetPath("init.lua"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "the unconfirmed newcomer pull wrote a target file")
	token := pullTestConfirmation(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(t, stdout.String(), "pull: first-use\n")
	assert.Contains(
		t,
		stdout.String(),
		fmt.Sprintf("pull: applied changes=1 unchanged=0 bytes=%d\n", len(pullTestBaseContent)),
	)
	assert.Contains(t, stdout.String(), "floor: revision=1 generation=1 sequence=0\n")
	assert.NotContains(t, stdout.String(), "pull: applied but not accepted")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err, "the confirmed newcomer pull did not apply the remote snapshot")
	assert.Equal(t, pullTestBaseContent, string(content))
	target, err := os.Stat(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), target.Mode().Perm())
	accepted := fixture.acceptedFloor(t)
	assert.Equal(t, uint64(1), accepted.Revision)
	assert.Equal(t, uint64(1), accepted.Generation)
	assert.Equal(t, uint64(0), accepted.Sequence)
	assert.Equal(t, publicationstate.ProvenanceFirst, accepted.Provenance)

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Equal(t, "pull: matches\n", stdout.String())
	assert.Equal(t, accepted.Revision, fixture.acceptedFloor(t).Revision)
}

func TestPullReportsAnEmptyProviderPositionWithoutAdoptingAnything(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, "")
	reader := &pullTestReader{view: publicationstate.SuppliedRepositoryView{}}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Equal(t, "pull: absent\n", stdout.String())
	inspection, err := publicationstate.Inspect(
		context.Background(),
		fixture.paths.PublicationStateDir(),
		fixture.binding,
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present)
}

func TestPullReportsAHeldStoreAsUnreadableAndTouchesNothing(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	held := fixture.openStore(t)
	defer func() { assert.NoError(t, held.Close()) }()
	before := pullTestDirectoryState(t, fixture.paths.PublicationStateDir())
	reader := &pullTestReader{}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: unreadable (locked)\n", stdout.String())
	assert.Zero(t, reader.count())
	assert.Equal(t, before, pullTestDirectoryState(t, fixture.paths.PublicationStateDir()))
}

func TestPullRefusesAPositionStoreBoundToAnotherVault(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestForeignVaultHex())
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: unreadable (binding)\n", stdout.String())
	assert.Zero(t, reader.count())
}

func TestPullReportsAnAmbiguousProviderReadAsIndeterminate(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{err: pullTestViewFailure{reason: "revision", cause: atproto.ErrAmbiguousTransport}}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 4, code)
	assert.Equal(t, "pull: unreadable (revision)\n", stdout.String())
	assert.Contains(t, stderr.String(), "indeterminate")
}

func TestPullRefusesAProviderViewItCannotValidate(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{err: pullTestViewFailure{reason: "chain"}}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: unreadable (chain)\n", stdout.String())
	assert.Contains(t, stderr.String(), "pull refused")
}

func TestPullUsesAClosedReasonVocabularyForUnclassifiedFailures(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{err: errors.New("synthetic provider failure with /absolute/path/and token-secret")}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: unreadable (view)\n", stdout.String())
	assert.NotContains(t, stdout.String(), "token-secret")
	assert.NotContains(t, stderr.String(), "token-secret")
	assert.NotContains(t, stderr.String(), "/absolute/path")
}

func TestPullResolvesAnOmittedVaultFromTheStoredBinding(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{view: fixture.view()}
	vaultCalls := 0
	vaults := func(context.Context, *urfave.Command, pushSession) ([32]byte, error) {
		vaultCalls++
		return fixture.binding.Vault, nil
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithVaults(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		nil,
		pushTestDIDs(pullTestDID),
		vaults,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID)
	require.Equal(t, 0, code, stderr.String())
	assert.Zero(t, vaultCalls, "a recorded binding still read the published vault")
	assert.Equal(
		t,
		"vault: "+pullTestVaultHex()+" (resolved from the recorded binding)\npull: matches\n",
		stdout.String(),
	)
}

func TestPullRequiresTheAccountAndVaultSelectors(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{}
	factoryCalls := 0
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "handle instead of did", args: []string{"--did", pullTestDID, "--handle", "example.test", "--vault", pullTestVaultHex()}, want: "a handle cannot be resolved before the publication scope check"},
		{name: "invalid did", args: []string{"--did", "not-a-did", "--vault", pullTestVaultHex()}, want: "--did must be a valid account DID"},
		{name: "malformed vault", args: []string{"--did", pullTestDID, "--vault", "abcd"}, want: "--vault must be a 32-byte hexadecimal identifier"},
		{name: "malformed confirmation", args: []string{"--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", "abcd"}, want: "--confirm must be the 32-byte hexadecimal confirmation printed by dottie pull"},
		{name: "positional argument", args: []string{"--did", pullTestDID, "--vault", pullTestVaultHex(), "extra"}, want: "pull takes no positional arguments"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := 0
			command := newPullTestCommand(
				t,
				fixture,
				&stdout,
				&stderr,
				&code,
				pullTestSession(),
				nil,
				reader,
				&factoryCalls,
			)
			code = runPullForTest(command, &code, test.args...)
			require.Equal(t, 2, code)
			assert.Contains(t, stderr.String(), test.want)
			assert.Empty(t, stdout.String())
		})
	}
	assert.Zero(t, factoryCalls)
}

func TestPullConfirmationTokenBindsTheVaultThePlanTheStateAndTheObservation(t *testing.T) {
	binding := publicationstate.Binding{
		AccountDID: pullTestDID,
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x62},
	}
	binding.Repository = "at://" + pullTestDID
	plan := sha256.Sum256([]byte("prepared plan"))
	state := sha256.Sum256([]byte("staged state"))
	observation := sha256.Sum256([]byte("observed position"))
	token := pullApplyConfirmationToken(binding, plan, state, observation)
	assert.NotEqual(
		t,
		token,
		pullApplyConfirmationToken(binding, sha256.Sum256([]byte("changed plan")), state, observation),
	)
	assert.NotEqual(
		t,
		token,
		pullApplyConfirmationToken(binding, plan, sha256.Sum256([]byte("moved state")), observation),
	)
	assert.NotEqual(
		t,
		token,
		pullApplyConfirmationToken(binding, plan, state, sha256.Sum256([]byte("moved observation"))),
	)
	otherVault := binding
	otherVault.Vault = [32]byte{0x63}
	assert.NotEqual(t, token, pullApplyConfirmationToken(otherVault, plan, state, observation))
	otherAccount := binding
	otherAccount.AccountDID = "did:plc:zyxwvutsrqponmlkjihgfedc"
	otherAccount.Repository = "at://" + otherAccount.AccountDID
	assert.NotEqual(t, token, pullApplyConfirmationToken(otherAccount, plan, state, observation))
	assert.Equal(t, token, pullApplyConfirmationToken(binding, plan, state, observation))
}

func TestPullPrintsTheApplyPlanAndAppliesOnlyThePreparedToken(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, "")
	fixture.writeBaseFile(t)
	view, payloads := fixture.advancedView(t, pullTestRemoteContent)
	reader := &pullTestReader{view: view, payloads: payloads}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(t, stdout.String(), "pull: diverges (record_cid)\n")
	assert.Contains(t, stdout.String(), "apply: changes=1 unchanged=0\n")
	assert.Contains(t, stdout.String(), fmt.Sprintf("apply: write init.lua size=%d\n", len(pullTestRemoteContent)))
	assert.Contains(t, stdout.String(), "pull: plan only; nothing was applied; repeat with --confirm ")
	assert.NotContains(t, stdout.String(), "pull: applied")
	target := fixture.targetPath("init.lua")
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, pullTestBaseContent, string(content), "the unconfirmed plan changed a target file")
	token := pullTestConfirmation(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(
		t,
		stdout.String(),
		fmt.Sprintf("pull: applied changes=1 unchanged=0 bytes=%d\n", len(pullTestRemoteContent)),
	)
	content, err = os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, pullTestRemoteContent, string(content))
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestPullAppliesNothingWhenTheProviderMatchesTheFloor(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, "")
	fixture.writeBaseFile(t)
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Equal(t, "pull: matches\n", stdout.String())
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, pullTestBaseContent, string(content))
}

func TestPullRefusesAConfirmationWhosePlanChanged(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, "")
	fixture.writeBaseFile(t)
	firstView, firstPayloads := fixture.advancedView(t, pullTestRemoteContent)
	reader := &pullTestReader{view: firstView, payloads: firstPayloads}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	token := pullTestConfirmation(t, stdout.String())

	secondView, secondPayloads := fixture.advancedView(t, "synthetic pull payload three")
	reader = &pullTestReader{view: secondView, payloads: secondPayloads}
	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "stale or bound to a different vault")
	assert.Contains(t, stdout.String(), "apply: changes=1 unchanged=0\n")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, pullTestBaseContent, string(content), "a stale confirmation applied the plan")
}

func TestPullRefusesABackupOnlySelectionWithoutApplying(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, config.BackupOnly)
	fixture.writeBaseFile(t)
	view, payloads := fixture.advancedView(t, pullTestRemoteContent)
	reader := &pullTestReader{view: view, payloads: payloads}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "backup-only")
	assert.NotContains(t, stdout.String(), "confirmation:")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, pullTestBaseContent, string(content))
}

func TestPullSurfacesAnApplyLeaseRefusal(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, "")
	fixture.writeBaseFile(t)
	before := fixture.acceptedFloor(t)
	view, payloads := fixture.advancedView(t, pullTestRemoteContent)
	reader := &pullTestReader{view: view, payloads: payloads}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	token := pullTestConfirmation(t, stdout.String())

	journal, err := publicationstate.OpenJournal(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	lease, err := journal.AcquireApplyLease(context.Background())
	require.NoError(t, err)
	require.NoError(t, journal.Close())
	defer func() { assert.NoError(t, lease.Close()) }()

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "apply_lease_held")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, pullTestBaseContent, string(content))
	accepted := fixture.acceptedFloor(t)
	assert.Equal(t, before.Revision, accepted.Revision)
	assert.Equal(t, before.RecordCID, accepted.RecordCID)
}

func (fixture *pullTestFixture) acceptedFloor(t *testing.T) publicationstate.Floor {
	t.Helper()
	store := fixture.openStore(t)
	defer func() { assert.NoError(t, store.Close()) }()
	floor, present, err := store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	return floor
}

type pullTestStageRefusal struct {
	stage  string
	reason string
}

func (refusal pullTestStageRefusal) Error() string  { return "synthetic accept refusal" }
func (refusal pullTestStageRefusal) Stage() string  { return refusal.stage }
func (refusal pullTestStageRefusal) Reason() string { return refusal.reason }

func TestPullAdvancesTheAcceptedFloorAfterAConfirmedApply(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, "")
	fixture.writeBaseFile(t)
	before := fixture.acceptedFloor(t)
	view, payloads := fixture.advancedView(t, pullTestRemoteContent)
	reader := &pullTestReader{view: view, payloads: payloads}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	token := pullTestConfirmation(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(
		t,
		stdout.String(),
		fmt.Sprintf(
			"floor: revision=%d generation=%d sequence=%d\n",
			before.Revision+1,
			before.Generation,
			before.Sequence+1,
		),
	)
	assert.NotContains(t, stdout.String(), "applied but not accepted")
	accepted := fixture.acceptedFloor(t)
	assert.Equal(t, before.Revision+1, accepted.Revision)
	assert.Equal(t, before.Generation, accepted.Generation)
	assert.Equal(t, before.Sequence+1, accepted.Sequence)
	packed, err := vault.Pack(payloads[before.Sequence+1])
	require.NoError(t, err)
	store := fixture.openStore(t)
	material, err := store.ReadAcceptedMaterial(context.Background(), fixture.binding, accepted)
	require.NoError(t, err)
	assert.Equal(t, packed.Payload, material.Payload)
	require.NoError(t, store.Close())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Equal(t, "pull: matches\n", stdout.String())
	assert.Equal(t, accepted.Revision, fixture.acceptedFloor(t).Revision)
}

func TestPullRefusesAConfirmationWhoseObservationDigestChanged(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, "")
	fixture.writeBaseFile(t)
	before := fixture.acceptedFloor(t)
	view, payloads := fixture.advancedView(t, pullTestRemoteContent)
	reader := &pullTestReader{view: view, payloads: payloads}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	token := pullTestConfirmation(t, stdout.String())

	movedView := view
	movedView.SuppliedContext = publicationstate.SuppliedContext{
		RepositoryRevision: "synthetic-pull-revision-moved", RepositoryDigest: fixture.context.RepositoryDigest,
	}
	reader = &pullTestReader{view: movedView, payloads: payloads}
	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "stale or bound to a different vault")
	assert.Contains(t, stdout.String(), "apply: changes=1 unchanged=0\n")
	assert.NotContains(t, stdout.String(), "pull: applied")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(
		t,
		pullTestBaseContent,
		string(content),
		"a confirmation bound to another observation applied the plan",
	)
	assert.Equal(t, before.Revision, fixture.acceptedFloor(t).Revision)
}

func TestPullReportsAFailedAcceptAsAppliedButNotAccepted(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	fixture.configure(t, "")
	fixture.writeBaseFile(t)
	before := fixture.acceptedFloor(t)
	view, payloads := fixture.advancedView(t, pullTestRemoteContent)
	reader := &pullTestReader{view: view, payloads: payloads}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	token := pullTestConfirmation(t, stdout.String())

	require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(fixture.paths.PublicationStateDir(), "payloads")))

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 3, code)
	assert.Contains(
		t,
		stdout.String(),
		fmt.Sprintf("pull: applied changes=1 unchanged=0 bytes=%d\n", len(pullTestRemoteContent)),
	)
	assert.Contains(t, stdout.String(), "pull: applied but not accepted (accept-material/")
	assert.Contains(t, stderr.String(), "the accepted floor is unchanged")
	assert.NotContains(t, stderr.String(), fixture.paths.Home)
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(
		t,
		pullTestRemoteContent,
		string(content),
		"the apply did not run before the accepted material was refused",
	)
	accepted := fixture.acceptedFloor(t)
	assert.Equal(t, before.Revision, accepted.Revision)
	assert.Equal(t, before.RecordCID, accepted.RecordCID)
}

func TestPullRendersAnAcceptRefusalAsAppliedButNotAccepted(t *testing.T) {
	fixture := newPullTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, &pullTestReader{}, nil)
	report := "pull: applied changes=1 unchanged=0 bytes=19\n"
	refused := pullAcceptFailure(
		command,
		"pull",
		report,
		pullTestStageRefusal{stage: "accept-material", reason: "stale"},
	)
	var exitError urfave.ExitCoder
	require.ErrorAs(t, refused, &exitError)
	assert.Equal(t, 3, exitError.ExitCode())
	assert.Equal(t, report+"pull: applied but not accepted (accept-material/stale)\n", stdout.String())
	assert.Contains(t, exitError.Error(), "the accepted floor is unchanged")

	stdout.Reset()
	unconfirmed := pullAcceptFailure(command, "pull", report, context.Canceled)
	require.ErrorAs(t, unconfirmed, &exitError)
	assert.Equal(t, 4, exitError.ExitCode())
	assert.Equal(t, report+"pull: applied but not accepted (accept)\n", stdout.String())
	assert.Contains(t, exitError.Error(), "not confirmed")
}

func TestPullRefusesAStagingRefusalBeforeApplyingAnything(t *testing.T) {
	moved := pullAcceptStagingFailure("pull", pullTestStageRefusal{stage: "accept-position", reason: "revision_moved"})
	var exitError urfave.ExitCoder
	require.ErrorAs(t, moved, &exitError)
	assert.Equal(t, 3, exitError.ExitCode())
	assert.Contains(t, moved.Error(), "the accepted floor changed after the apply plan was prepared")

	refused := pullAcceptStagingFailure(
		"pull",
		pullTestStageRefusal{stage: "accept-prepare", reason: "proposal_refused"},
	)
	require.ErrorAs(t, refused, &exitError)
	assert.Equal(t, 3, exitError.ExitCode())
	assert.Contains(t, refused.Error(), "accept-prepare/proposal_refused")
	assert.Contains(t, refused.Error(), "nothing was changed")
}

func TestPullResolvesTheOnlyAuthorisedSessionWhenDIDIsOmitted(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{view: fixture.view()}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithDIDs(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		nil,
		pushTestDIDs(pullTestDID),
	)
	code = runPullForTest(command, &code)
	require.Equal(t, 0, code, stderr.String())
	assert.Empty(t, stderr.String())
	assert.Equal(
		t,
		"account: "+pullTestDID+" (resolved from the only authorised session; --did was omitted)\nvault: "+pullTestVaultHex()+" (resolved from the recorded binding)\npull: matches\n",
		stdout.String(),
	)
}

func TestPullRefusesWithoutAnyAuthorisedSession(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{}
	factoryCalls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommandWithDIDs(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		&factoryCalls,
		pushTestDIDs(),
	)
	code = runPullForTest(command, &code)
	require.Equal(t, 3, code)
	assert.Empty(t, stdout.String())
	assert.Equal(
		t,
		"dottie: pull refused: no account is authorised locally; run dottie account login --handle HANDLE or pass --did DID\n",
		stderr.String(),
	)
	assert.Zero(t, factoryCalls, "the refusal constructed the provider reader")
}

func TestPullRefusesTwoAuthorisedSessionsWithoutDID(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{view: fixture.view()}
	factoryCalls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	other := "did:plc:zyxwvutsrqponmlkjihgfedc"
	command := newPullTestCommandWithDIDs(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		&factoryCalls,
		pushTestDIDs(pullTestDID, other),
	)
	code = runPullForTest(command, &code)
	require.Equal(t, 3, code)
	assert.Empty(t, stdout.String())
	assert.Equal(
		t,
		"dottie: pull refused: 2 accounts are authorised locally; --did is required to choose the account this command acts on\n",
		stderr.String(),
	)
	assert.Zero(t, factoryCalls, "the ambiguous refusal constructed the provider reader")
	_, statErr := os.Lstat(fixture.paths.PublicationStateDir())
	require.ErrorIs(t, statErr, os.ErrNotExist, "the ambiguous refusal created the position store")
	assert.NoFileExists(t, fixture.targetPath("init.lua"), "the ambiguous refusal applied a file")
}

func TestPullProceedsWithTheExplicitDIDWhenTwoSessionsAreAuthorised(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.accept(t)
	reader := &pullTestReader{view: fixture.view()}
	var stdout, stderr bytes.Buffer
	code := 0
	other := "did:plc:zyxwvutsrqponmlkjihgfedc"
	command := newPullTestCommandWithDIDs(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		pullTestSession(),
		nil,
		reader,
		nil,
		pushTestDIDs(other, pullTestDID),
	)
	code = runPullForTest(command, &code, "--did", pullTestDID)
	require.Equal(t, 0, code, stderr.String())
	assert.Equal(
		t,
		"vault: "+pullTestVaultHex()+" (resolved from the recorded binding)\npull: matches\n",
		stdout.String(),
	)
}

func TestPullRefusesAnExplicitDIDWithNoStoredSession(t *testing.T) {
	fixture := newPullTestFixture(t)
	reader := &pullTestReader{}
	factoryCalls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(
		t,
		fixture,
		&stdout,
		&stderr,
		&code,
		nil,
		atproto.ErrSessionNotFound,
		reader,
		&factoryCalls,
	)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code)
	assert.Empty(t, stdout.String())
	assert.Equal(t, "dottie: pull refused: account session is unavailable\n", stderr.String())
	assert.Zero(t, factoryCalls, "a missing session constructed the provider reader")
}
