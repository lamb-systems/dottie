package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pushTestTransport struct {
	mu         sync.Mutex
	binding    publicationstate.Binding
	context    publicationstate.SuppliedContext
	contextSeq int
	blocks     map[string][]byte
	head       []byte
	blobs      map[string][]byte
	prepared   map[string]service.MaterialWriteBatch
	dispatched map[string]bool
	uploads    int
	sends      int
	prepareErr error
	staleWrite bool
	viewErr    error
	uploadErr  error
}

func newPushTestTransport(binding publicationstate.Binding) *pushTestTransport {
	return &pushTestTransport{
		binding: binding, context: pushTestContext(0), blocks: map[string][]byte{},
		blobs: map[string][]byte{}, prepared: map[string]service.MaterialWriteBatch{}, dispatched: map[string]bool{},
	}
}

func pushTestContext(sequence int) publicationstate.SuppliedContext {
	return publicationstate.SuppliedContext{RepositoryRevision: fmt.Sprintf("synthetic-revision-%d", sequence), RepositoryDigest: []byte{byte(sequence + 1), 0x5b}}
}

func (transport *pushTestTransport) UploadPayload(ctx context.Context, payload []byte) (publication.BlobReference, error) {
	if err := ctx.Err(); err != nil {
		return publication.BlobReference{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploads++
	if transport.uploadErr != nil {
		return publication.BlobReference{}, transport.uploadErr
	}
	cid, err := publication.RawPayloadCID(payload)
	if err != nil {
		return publication.BlobReference{}, err
	}
	transport.blobs[string(cid)] = bytes.Clone(payload)
	return publication.BlobReference{CID: cid, Size: uint64(len(payload))}, nil
}

func (transport *pushTestTransport) PrepareWrites(ctx context.Context, batch service.MaterialWriteBatch) (service.MaterialPreparedWrites, error) {
	if err := ctx.Err(); err != nil {
		return service.MaterialPreparedWrites{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.prepareErr != nil {
		return service.MaterialPreparedWrites{}, transport.prepareErr
	}
	secret := fmt.Sprintf("synthetic-prepared-%d", len(transport.prepared)+1)
	transport.prepared[secret] = batch
	return service.MaterialPreparedWrites{Secret: secret, Dispatch: 1}, nil
}

func (transport *pushTestTransport) SendWrites(ctx context.Context, prepared service.MaterialPreparedWrites) (service.MaterialWriteOutcome, error) {
	if err := ctx.Err(); err != nil {
		return service.MaterialWriteOutcome{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	batch, known := transport.prepared[prepared.Secret]
	if !known || prepared.Dispatch != 1 || transport.dispatched[prepared.Secret] {
		return service.MaterialWriteOutcome{}, errors.New("synthetic transport refused an unprepared or replayed dispatch")
	}
	transport.dispatched[prepared.Secret] = true
	transport.sends++
	if transport.staleWrite || !samePushTestContext(batch.ExpectedContext, transport.context) {
		return service.MaterialWriteOutcome{}, errors.New("synthetic transport refused a write with a stale expected context")
	}
	transport.blocks[batch.SnapshotKey] = bytes.Clone(batch.SnapshotRecord)
	transport.head = bytes.Clone(batch.HeadRecord)
	transport.contextSeq++
	transport.context = pushTestContext(transport.contextSeq)
	return service.MaterialWriteOutcome{Committed: true}, nil
}

func samePushTestContext(left, right publicationstate.SuppliedContext) bool {
	return left.RepositoryRevision == right.RepositoryRevision && bytes.Equal(left.RepositoryDigest, right.RepositoryDigest)
}

func (transport *pushTestTransport) ReadView(ctx context.Context) (publicationstate.SuppliedRepositoryView, error) {
	if err := ctx.Err(); err != nil {
		return publicationstate.SuppliedRepositoryView{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.viewErr != nil {
		return publicationstate.SuppliedRepositoryView{}, transport.viewErr
	}
	keys := make([]string, 0, len(transport.blocks))
	for key := range transport.blocks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	view := publicationstate.SuppliedRepositoryView{
		Origin: transport.binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: transport.context, Head: bytes.Clone(transport.head),
		Snapshots: make([]publicationstate.SnapshotBlock, 0, len(keys)),
	}
	for _, key := range keys {
		view.Snapshots = append(view.Snapshots, publicationstate.SnapshotBlock{Key: key, Raw: bytes.Clone(transport.blocks[key])})
	}
	return view, nil
}

func (transport *pushTestTransport) blob(ctx context.Context, reference publication.BlobReference) ([]byte, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	payload, found := transport.blobs[string(reference.CID)]
	if !found {
		return nil, errors.New("synthetic transport was asked for an uploaded payload it does not hold")
	}
	return bytes.Clone(payload), nil
}

func (transport *pushTestTransport) counts() (int, int) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.uploads, transport.sends
}

type pushTestAcceptedSource struct {
	transport *pushTestTransport
}

func (source pushTestAcceptedSource) ReadAcceptedPayload(ctx context.Context) (service.AcceptedPublication, error) {
	view, err := source.transport.ReadView(ctx)
	if err != nil {
		return service.AcceptedPublication{}, err
	}
	if len(view.Head) == 0 || len(view.Snapshots) == 0 {
		return service.AcceptedPublication{}, errors.Join(service.ErrPublicationReaderAccepted, atproto.ErrReadRecordMissing)
	}
	terminal := view.Snapshots[len(view.Snapshots)-1]
	record, err := publication.DecodeSnapshot(terminal.Raw)
	if err != nil {
		return service.AcceptedPublication{}, err
	}
	payload, err := source.transport.blob(ctx, record.Blob)
	if err != nil {
		return service.AcceptedPublication{}, err
	}
	snapshot, err := publication.DecodePayload(payload, record.Blob)
	if err != nil {
		return service.AcceptedPublication{}, err
	}
	return service.AcceptedPublication{View: view, Snapshot: snapshot}, nil
}

type pushTestGuard struct{}

func (pushTestGuard) Release() {}

type pushTestReviews struct {
	review publicationstate.LocalReviewContext
	err    error
	calls  *int
	failOn int
}

func (reviews pushTestReviews) Acquire(context.Context) (publicationstate.LocalReviewContext, config.Token, service.ConfigGuard, error) {
	if reviews.calls != nil {
		*reviews.calls++
		if reviews.failOn != 0 && *reviews.calls == reviews.failOn {
			return publicationstate.LocalReviewContext{}, config.Token{}, nil, errors.New("synthetic review acquisition refused")
		}
	}
	if reviews.err != nil {
		return publicationstate.LocalReviewContext{}, config.Token{}, nil, reviews.err
	}
	return reviews.review, config.Token{0x61, 0x62}, pushTestGuard{}, nil
}

type publicationPushTestFixture struct {
	paths         platform.Paths
	binding       publicationstate.Binding
	position      *publicationstate.Store
	records       publicationProposalStore
	transport     *pushTestTransport
	coordinator   *service.Coordinator
	configuration config.Config
	reviews       pushTestReviews
}

func newPublicationPushTestFixture(t *testing.T) *publicationPushTestFixture {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"), DataHome: filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(paths.Home, "config"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(paths.Home, "config", "init.lua"), []byte("synthetic cli push payload"), 0o600))
	require.NoError(t, os.MkdirAll(paths.PublicationStateDir(), 0o700))
	require.NoError(t, os.Chmod(paths.PublicationStateDir(), 0o700))
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	coordinator, err := service.NewCoordinator(service.Dependencies{State: store, Paths: paths})
	require.NoError(t, err)
	binding := publicationstate.Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo, Vault: [32]byte{0x62}}
	binding.Repository = "at://" + binding.AccountDID
	position, err := publicationstate.Open(paths.PublicationStateDir(), binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, position.Close()) })
	review := publicationstate.LocalReviewContext{SelectionDigest: [32]byte{0x63}, SelectionRevision: 1, ApprovalDigest: [32]byte{0x64}, ApprovalRevision: 1}
	return &publicationPushTestFixture{
		paths: paths, binding: binding, position: position,
		records: newPublicationProposalStore(paths.PublicationStateDir()), transport: newPushTestTransport(binding),
		coordinator: coordinator, reviews: pushTestReviews{review: review},
		configuration: config.Config{Version: config.Version, Targets: []config.Target{{
			ID: "files", Source: model.SourceFiles, Mode: config.BackupOnly,
			Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}}},
	}
}

func (fixture *publicationPushTestFixture) sources() publicationPushSources {
	return publicationPushSources{
		Paths: fixture.paths, Binding: fixture.binding, Coordinator: fixture.coordinator, Store: fixture.position,
		Reader: pushTestAcceptedSource{transport: fixture.transport}, Transport: fixture.transport,
		Reviews: fixture.reviews, Records: fixture.records, Configuration: fixture.configuration,
		Close: func() {},
	}
}

func pushTestSession(t *testing.T) pushSession {
	t.Helper()
	return pushSession{Session: &atproto.Session{DID: "did:plc:abcdefghijklmnopqrstuvwx", Scopes: atproto.VaultScopes()}}
}

func newPushTestCommand(t *testing.T, stdout, stderr *bytes.Buffer, exitCode *int, session pushSession, factoryCalls *int, sessionErr error) *urfave.Command {
	t.Helper()
	diag := assert.New(t)
	fixture := newPublicationPushTestFixture(t)
	sessions := func(context.Context, *urfave.Command) (pushSession, error) {
		if sessionErr != nil {
			return pushSession{}, sessionErr
		}
		return session, nil
	}
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		if factoryCalls != nil {
			*factoryCalls++
		}
		diag.NotNil(fixture)
		return fixture.sources(), nil
	}
	return newPushCommand(stdout, stderr, exitCode, sessions, sources)
}

func runPushForTest(command *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	if err := command.Run(ctx, append([]string{"dottie"}, args...)); err != nil && *exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return *exitCode
}

func confirmationFromOutput(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if value, found := strings.CutPrefix(line, "confirmation: "); found {
			return value
		}
	}
	require.FailNow(t, "the review output carried no confirmation", output)
	return ""
}

func TestPushPrintsTheReviewConfirmationAndWritesOnePrivateRecord(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	command := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(command, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	output := stdout.String()
	assert.Contains(t, output, "push: review required")
	confirmation := confirmationFromOutput(t, output)
	decoded, err := hex.DecodeString(confirmation)
	require.NoError(t, err)
	assert.Len(t, decoded, 32)
	assert.Contains(t, output, "confirmation: "+confirmation)
	assert.Contains(t, output, "targets: 1")
	assert.NotContains(t, output, fixture.paths.Home)
	assert.NotContains(t, output, "synthetic cli push payload")
	assert.NotContains(t, output, hex.EncodeToString(fixture.binding.Vault[:]))
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads, "a review-only push uploaded a payload")
	assert.Zero(t, sends, "a review-only push dispatched writes")
	assert.Contains(t, stderr.String(), "--confirm "+confirmation)

	entries, err := os.ReadDir(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	proposals := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), publicationProposalFilePrefix) {
			proposals = append(proposals, entry.Name())
		}
	}
	require.Len(t, proposals, 1)
	info, err := os.Stat(filepath.Join(fixture.paths.PublicationStateDir(), proposals[0]))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	raw, err := os.ReadFile(filepath.Join(fixture.paths.PublicationStateDir(), proposals[0]))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "synthetic cli push payload")
	assert.Contains(t, string(raw), confirmation)
}

func TestPushConfirmPublishesOnceAndPrintsTheAcceptedFloor(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	confirmed := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(confirmed, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "push: committed")
	assert.Contains(t, stdout.String(), "floor: revision=1 generation=1 sequence=0")
	uploads, sends := fixture.transport.counts()
	assert.Equal(t, 1, uploads)
	assert.Equal(t, 1, sends)

	records, err := fixture.records.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, records, "the terminal publication left a retained proposal behind")

	stdout.Reset()
	stderr.Reset()
	code = 0
	replayed := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(replayed, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 3, code)
	_, sends = fixture.transport.counts()
	assert.Equal(t, 1, sends, "a second confirmation dispatched writes")
}

func TestPushConfirmsARePreparedProposalAfterStateChanged(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	require.NotEmpty(t, confirmationFromOutput(t, stdout.String()))

	fixture.transport.mu.Lock()
	fixture.transport.context = pushTestContext(1)
	fixture.transport.mu.Unlock()

	stdout.Reset()
	stderr.Reset()
	code = 0
	review := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(review, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	refreshed := confirmationFromOutput(t, stdout.String())
	require.NotEmpty(t, refreshed)

	stdout.Reset()
	stderr.Reset()
	code = 0
	confirm := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(confirm, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", refreshed)
	assert.Equal(t, 0, code, stderr.String())
	assert.Contains(t, stdout.String(), "push: committed")
	assert.Contains(t, stdout.String(), "floor: revision=1")
}

func TestPushReportsASubmissionFailureAsIndeterminate(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	fixture.transport.staleWrite = true
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	confirm := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(confirm, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	assert.Equal(t, 4, code, stderr.String())
}

func TestPushRefusesAMismatchedConfirmationWithoutDispatch(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, stdout.String())
	other := bytes.Repeat([]byte{0x7f}, 32)

	stdout.Reset()
	stderr.Reset()
	code = 0
	stale := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(stale, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", hex.EncodeToString(other))
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "stale")
	_, sends := fixture.transport.counts()
	assert.Zero(t, sends, "a mismatched confirmation dispatched writes")
	records, err := fixture.records.List(context.Background())
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.False(t, records[0].Consumed, "a stale confirmation consumed the record")
	assert.Equal(t, confirmation, hex.EncodeToString(records[0].Confirmation[:]))

	stdout.Reset()
	stderr.Reset()
	code = 0
	accepted := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(accepted, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 0, code, "an unchanged re-run after a stale refusal did not publish")
}

func TestPushRefusesAConfirmationWhoseCandidateChangedSinceReview(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, stdout.String())
	path := filepath.Join(fixture.paths.Home, "config", "init.lua")
	require.NoError(t, os.WriteFile(path, []byte("changed since review payload"), 0o600))

	stdout.Reset()
	stderr.Reset()
	code = 0
	changed := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(changed, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "stale")
	_, sends := fixture.transport.counts()
	assert.Zero(t, sends, "a changed candidate dispatched writes against the reviewed confirmation")
	records, err := fixture.records.List(context.Background())
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.False(t, records[0].Consumed, "a stale re-run consumed the retained record")
	assert.Equal(t, confirmation, hex.EncodeToString(records[0].Confirmation[:]))
	updated := confirmationFromOutput(t, stdout.String())
	assert.NotEqual(t, confirmation, updated, "a changed candidate reproduced the reviewed confirmation")

	require.NoError(t, os.WriteFile(path, []byte("synthetic cli push payload"), 0o600))
	stdout.Reset()
	stderr.Reset()
	code = 0
	restored := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(restored, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 0, code, "an unchanged re-run after a stale refusal did not publish")
}

func TestPushRefusesAConfirmationWhenNoProposalWasRetained(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	command := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(command, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)))
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "no retained publication proposal")
	uploads, sends := fixture.transport.counts()
	assert.Zero(t, uploads)
	assert.Zero(t, sends)
	records, err := fixture.records.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, records, "a confirmation-only invocation issued a proposal")
}

func TestPushClearsAStrandedPreSubmissionAttemptWithoutAFlag(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, stdout.String())
	fixture.transport.prepareErr = errors.New("synthetic transport refused write preparation")
	stdout.Reset()
	stderr.Reset()
	code = 0
	failed := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(failed, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 4, code)

	fixture.transport.prepareErr = nil
	stdout.Reset()
	stderr.Reset()
	code = 0
	again := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(again, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	assert.Contains(t, stdout.String(), "review required")
	assert.NotContains(t, stderr.String(), "already active")
	assert.NotContains(t, stderr.String(), "--discard")
}

func TestPushRefusesAConsumedRecordBeforeConfirmation(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, stdout.String())
	records, err := fixture.records.List(context.Background())
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.NoError(t, fixture.records.Consume(context.Background(), records[0].PublicationID))

	stdout.Reset()
	stderr.Reset()
	code = 0
	consumed := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(consumed, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "already consumed")
	_, sends := fixture.transport.counts()
	assert.Zero(t, sends)
}

func TestPushRefusesAScopeGrantBeforeDiscovery(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := 0
	factoryCalls := 0
	session := pushSession{Session: &atproto.Session{DID: "did:plc:abcdefghijklmnopqrstuvwx", Scopes: []string{"atproto"}}}
	command := newPushTestCommand(t, &stdout, &stderr, &code, session, &factoryCalls, nil)
	code = runPushForTest(command, &code, "push", "--did", "did:plc:abcdefghijklmnopqrstuvwx")
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls, "a scope refusal constructed the transport and reader")
	assert.Contains(t, stderr.String(), "sign in again")
	assert.Contains(t, stderr.String(), "dottie account login")
	assert.Empty(t, stdout.String())
}

func TestPushRefusesAnUnavailableSessionBeforeTheScopeCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := 0
	factoryCalls := 0
	command := newPushTestCommand(t, &stdout, &stderr, &code, pushSession{}, &factoryCalls, errors.New("session unavailable"))
	code = runPushForTest(command, &code, "push", "--did", "did:plc:abcdefghijklmnopqrstuvwx")
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls)
	assert.Contains(t, stderr.String(), "account session is unavailable")
}

func TestPushRequiresTheDIDSelector(t *testing.T) {
	for _, args := range [][]string{
		{"push"},
		{"push", "--handle", "example.test"},
		{"push", "--did", "did:plc:abcdefghijklmnopqrstuvwx", "--confirm", "not-hex"},
		{"push", "--did", "did:plc:abcdefghijklmnopqrstuvwx", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		code := 0
		command := newPushCommand(&stdout, &stderr, &code,
			func(context.Context, *urfave.Command) (pushSession, error) {
				return pushSession{}, errors.New("the session factory must not be reached")
			},
			func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
				return publicationPushSources{}, errors.New("the sources factory must not be reached")
			})
		code = runPushForTest(command, &code, args...)
		require.Equal(t, 2, code, "args %v", args)
		assert.Contains(t, stderr.String(), "usage:")
	}
}

func TestPushNoOpAfterTheSameSnapshotIsAccepted(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, stdout.String())
	stdout.Reset()
	stderr.Reset()
	code = 0
	confirmed := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(confirmed, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 0, code)

	stdout.Reset()
	stderr.Reset()
	code = 0
	unchanged := newPushCommand(&stdout, &stderr, &code, sessions, sources)
	code = runPushForTest(unchanged, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "push: no-op")
	uploads, sends := fixture.transport.counts()
	assert.Equal(t, 1, uploads, "a no-op push uploaded a payload")
	assert.Equal(t, 1, sends, "a no-op push dispatched writes")
	records, err := fixture.records.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestPushRefusesAnUnprovisionedPositionStoreBeforeAnyAccountWork(t *testing.T) {
	root := t.TempDir()
	env := func(key string) string {
		switch key {
		case "HOME":
			return root
		case "XDG_STATE_HOME":
			return filepath.Join(root, "state")
		case "XDG_CONFIG_HOME":
			return filepath.Join(root, "config")
		case "XDG_CACHE_HOME":
			return filepath.Join(root, "cache")
		case "XDG_DATA_HOME":
			return filepath.Join(root, "data")
		default:
			return ""
		}
	}
	_, err := productionPushSourcesFactory(func() (accountKeyring, error) {
		return nil, errors.New("the keyring must not be opened")
	}, env)(context.Background(), &urfave.Command{}, pushTestSession(t))
	require.ErrorIs(t, err, errPublicationStoreAbsent)
}

func TestPublicationProposalStoreRejectsForeignFilePermissions(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var stdout, stderr bytes.Buffer
	code := 0
	command := newPushCommand(&stdout, &stderr, &code,
		func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil },
		func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
			return fixture.sources(), nil
		})
	code = runPushForTest(command, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	entries, err := os.ReadDir(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	path := filepath.Join(fixture.paths.PublicationStateDir(), entries[0].Name())
	require.NoError(t, os.Chmod(path, 0o644))

	stdout.Reset()
	stderr.Reset()
	code = 0
	other := newPushCommand(&stdout, &stderr, &code,
		func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil },
		func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
			return fixture.sources(), nil
		})
	code = runPushForTest(other, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "private regular file")
}

func TestPublicationProposalStoreRoundTripsTheRetainedRecord(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var publicationID [16]byte
	_, err := rand.Read(publicationID[:])
	require.NoError(t, err)
	record := service.PublicationProposalRecord{
		Version: 1, Binding: fixture.binding, DatabaseID: [32]byte{0x65}, Generation: 1, FloorRevision: 0,
		CandidateRecordCID: []byte{0x66}, CandidatePayloadCID: []byte{0x67}, CandidatePayloadSize: 8,
		Review:        publicationstate.LocalReviewContext{SelectionDigest: [32]byte{0x68}, SelectionRevision: 1, ApprovalDigest: [32]byte{0x69}, ApprovalRevision: 1},
		PublicationID: publicationID, Lifecycle: publicationstate.AttemptPrepared, Confirmation: [32]byte{0x6a},
	}
	ctx := context.Background()
	require.NoError(t, fixture.records.Issue(ctx, record))
	require.ErrorIs(t, fixture.records.Issue(ctx, record), errProposalRecordDuplicate, "issuance overwrote a retained record")
	records, err := fixture.records.List(ctx)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, record, records[0])
	require.NoError(t, fixture.records.Consume(ctx, publicationID))
	consumed, err := fixture.records.List(ctx)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	assert.True(t, consumed[0].Consumed)
	assert.Equal(t, record.Confirmation, consumed[0].Confirmation)
	require.NoError(t, fixture.records.Delete(ctx, publicationID))
	remaining, err := fixture.records.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, remaining)
}

type syntheticStoreFailure struct {
	reason publicationstate.Reason
}

func (failure syntheticStoreFailure) Error() string { return "synthetic store failure" }

func (failure syntheticStoreFailure) Reason() publicationstate.Reason { return failure.reason }

func TestPushMaterialStatusSeparatesRefusalsFromIndeterminateOutcomes(t *testing.T) {
	assert.Equal(t, service.StatusCommitted, pushMaterialStatus(nil))
	assert.Equal(t, service.StatusRejected, pushMaterialStatus(service.ErrPublicationProposalStale))
	assert.Equal(t, service.StatusRejected, pushMaterialStatus(service.ErrPublicationProposalConsumed))
	assert.Equal(t, service.StatusRejected, pushMaterialStatus(fmt.Errorf("wrapped: %w", service.ErrPublicationProposalActive)))
	assert.Equal(t, service.StatusFenceLost, pushMaterialStatus(fmt.Errorf("wrapped: %w", atproto.ErrFenceLost)))
	assert.Equal(t, service.StatusRejected, pushMaterialStatus(syntheticStoreFailure{reason: publicationstate.ReasonConfirmation}))
	assert.Equal(t, service.StatusUnavailable, pushMaterialStatus(syntheticStoreFailure{reason: publicationstate.ReasonCommitUnknown}))
	assert.Equal(t, service.StatusUnavailable, pushMaterialStatus(errors.New("transport is unavailable")))
}

func TestPushReportsACommittedPublicationWhoseOutputFailed(t *testing.T) {
	fixture := newPublicationPushTestFixture(t)
	var prepareOut, prepareErr bytes.Buffer
	code := 0
	sessions := func(context.Context, *urfave.Command) (pushSession, error) { return pushTestSession(t), nil }
	sources := func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error) {
		return fixture.sources(), nil
	}
	prepared := newPushCommand(&prepareOut, &prepareErr, &code, sessions, sources)
	code = runPushForTest(prepared, &code, "push", "--did", fixture.binding.AccountDID)
	require.Equal(t, 3, code)
	confirmation := confirmationFromOutput(t, prepareOut.String())

	var stderr bytes.Buffer
	code = 0
	broken := newPushCommand(failingWriter{}, &stderr, &code, sessions, sources)
	code = runPushForTest(broken, &code, "push", "--did", fixture.binding.AccountDID, "--confirm", confirmation)
	require.Equal(t, 4, code)
	assert.Contains(t, stderr.String(), "committed")
	_, sends := fixture.transport.counts()
	assert.Equal(t, 1, sends, "the committed publication was not dispatched")
}
