package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
)

var (
	errMaterialTestBatchShape     = errors.New("material transport: unsupported batch shape")
	errMaterialTestStaleContext   = errors.New("material transport: stale expected context")
	errMaterialTestCreateConflict = errors.New("material transport: snapshot create conflict")
	errMaterialTestHeadExists     = errors.New("material transport: head already exists")
	errMaterialTestPredecessor    = errors.New(
		"material transport: expected predecessor does not match the committed head",
	)
	errMaterialTestPayloadMissing = errors.New("material transport: referenced payload was never uploaded")
	errMaterialTestRecordMismatch = errors.New(
		"material transport: record bytes do not hash to the expected snapshot cid",
	)
	errMaterialTestBeforeCommit   = errors.New("material transport: failed before commit")
	errMaterialTestCommitUnknown  = errors.New("material transport: committed but the response was lost")
	errMaterialTestUploadRejected = errors.New("material transport: upload rejected")
	errMaterialTestBackend        = errors.New("material transport: backend is not a public repository")
	errMaterialTestPolicyCheck    = errors.New("material transport: policy check is not supported for this backend")
	errMaterialTestUnprepared     = errors.New("material transport: send refused a write value that was never prepared")
	errMaterialTestReplayed       = errors.New("material transport: prepared write value was already dispatched")
)

type materialTestTransport struct {
	mu               sync.Mutex
	binding          publicationstate.Binding
	scope            publicationstate.ViewScope
	context          publicationstate.SuppliedContext
	contextSeq       int
	blocks           map[string][]byte
	head             []byte
	blobs            map[string][]byte
	uploads          int
	prepares         int
	sends            int
	applies          int
	prepared         map[string]MaterialWriteBatch
	dispatched       map[string]bool
	calls            []string
	preparedSecret   *string
	preparedDispatch *int
	prepareErr       error
	sendErr          error
	prepareHook      func()
	sendHook         func()
	applied          []MaterialWriteBatch
	uploadErr        error
	uploadFailAt     int
	uploadMIME       string
	uploadCID        []byte
	writeOnUpload    bool
	failBeforeCommit bool
	commitThenFail   bool
}

func newMaterialTestTransport(binding publicationstate.Binding) *materialTestTransport {
	return &materialTestTransport{
		binding: binding, scope: publicationstate.ViewScopeWholeRepository,
		context: materialTestContext(0), blocks: map[string][]byte{}, blobs: map[string][]byte{},
		prepared: map[string]MaterialWriteBatch{}, dispatched: map[string]bool{},
	}
}

func materialTestContext(sequence int) publicationstate.SuppliedContext {
	return publicationstate.SuppliedContext{
		RepositoryRevision: fmt.Sprintf("synthetic-revision-%d", sequence),
		RepositoryDigest:   []byte{byte(sequence + 1), 0x5a},
	}
}

func (transport *materialTestTransport) uploadMIMEType() string {
	if transport.uploadMIME != "" {
		return transport.uploadMIME
	}
	return publication.SnapshotBlobMIMEType
}

func (transport *materialTestTransport) UploadPayload(
	ctx context.Context,
	payload []byte,
) (publication.BlobReference, error) {
	if err := ctx.Err(); err != nil {
		return publication.BlobReference{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploads++
	transport.calls = append(transport.calls, "upload-payload")
	if transport.uploadErr != nil || transport.uploadFailAt > 0 && transport.uploads == transport.uploadFailAt {
		if transport.uploadErr != nil {
			return publication.BlobReference{}, transport.uploadErr
		}
		return publication.BlobReference{}, errors.New("synthetic file-set upload failure")
	}
	cid, err := publication.RawPayloadCID(payload)
	if err != nil {
		return publication.BlobReference{}, err
	}
	transport.blobs[string(cid)] = bytes.Clone(payload)
	if transport.writeOnUpload {
		transport.advanceContextLocked()
	}
	if len(transport.uploadCID) != 0 {
		return publication.BlobReference{
			CID:      bytes.Clone(transport.uploadCID),
			Size:     uint64(len(payload)),
			MIMEType: transport.uploadMIMEType(),
		}, nil
	}
	return publication.BlobReference{CID: cid, Size: uint64(len(payload)), MIMEType: transport.uploadMIMEType()}, nil
}

func (transport *materialTestTransport) PrepareWrites(
	ctx context.Context,
	batch MaterialWriteBatch,
) (MaterialPreparedWrites, error) {
	if err := ctx.Err(); err != nil {
		return MaterialPreparedWrites{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.prepares++
	transport.calls = append(transport.calls, "prepare-writes")
	if transport.prepareHook != nil {
		transport.prepareHook()
	}
	if err := transport.validateMaterialBatch(batch); err != nil {
		return MaterialPreparedWrites{}, err
	}
	if transport.prepareErr != nil {
		return MaterialPreparedWrites{}, transport.prepareErr
	}
	secret := fmt.Sprintf("synthetic-prepared-%d", transport.prepares)
	if transport.preparedSecret != nil {
		secret = *transport.preparedSecret
	}
	dispatch := 1
	if transport.preparedDispatch != nil {
		dispatch = *transport.preparedDispatch
	}
	if secret != "" {
		transport.prepared[secret] = cloneMaterialWriteBatch(batch)
	}
	return MaterialPreparedWrites{Secret: secret, Dispatch: dispatch}, nil
}

func (transport *materialTestTransport) SendWrites(
	ctx context.Context,
	prepared MaterialPreparedWrites,
) (MaterialWriteOutcome, error) {
	if err := ctx.Err(); err != nil {
		return MaterialWriteOutcome{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	batch, known := transport.prepared[prepared.Secret]
	if !known {
		return MaterialWriteOutcome{}, errMaterialTestUnprepared
	}
	if transport.dispatched[prepared.Secret] {
		return MaterialWriteOutcome{}, errMaterialTestReplayed
	}
	transport.dispatched[prepared.Secret] = true
	transport.sends++
	transport.calls = append(transport.calls, "send-writes")
	if transport.sendHook != nil {
		transport.sendHook()
	}
	transport.applies++
	transport.applied = append(transport.applied, cloneMaterialWriteBatch(batch))
	if transport.sendErr != nil {
		return MaterialWriteOutcome{}, transport.sendErr
	}
	if transport.failBeforeCommit {
		return MaterialWriteOutcome{}, errMaterialTestBeforeCommit
	}
	if err := transport.checkMaterialBatch(batch); err != nil {
		return MaterialWriteOutcome{}, err
	}
	transport.blocks[batch.SnapshotKey] = bytes.Clone(batch.SnapshotRecord)
	transport.head = bytes.Clone(batch.HeadRecord)
	transport.advanceContextLocked()
	if transport.commitThenFail {
		return MaterialWriteOutcome{}, errMaterialTestCommitUnknown
	}
	return MaterialWriteOutcome{Committed: true}, nil
}

func (transport *materialTestTransport) ReadView(ctx context.Context) (publicationstate.SuppliedRepositoryView, error) {
	if err := ctx.Err(); err != nil {
		return publicationstate.SuppliedRepositoryView{}, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.calls = append(transport.calls, "read-view")
	keys := make([]string, 0, len(transport.blocks))
	for key := range transport.blocks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	view := publicationstate.SuppliedRepositoryView{
		Origin: transport.binding, Scope: transport.scope,
		SuppliedContext: cloneMaterialContext(transport.context), Head: bytes.Clone(transport.head),
		Snapshots: make([]publicationstate.SnapshotBlock, 0, len(keys)),
	}
	for _, key := range keys {
		view.Snapshots = append(
			view.Snapshots,
			publicationstate.SnapshotBlock{Key: key, Raw: bytes.Clone(transport.blocks[key])},
		)
	}
	return view, nil
}

func (transport *materialTestTransport) validateMaterialBatch(batch MaterialWriteBatch) error {
	if transport.binding.Backend != publicationstate.BackendPublicRepo {
		return errMaterialTestBackend
	}
	if batch.RequiresPolicyCheck {
		return errMaterialTestPolicyCheck
	}
	if batch.SnapshotCollection != publication.SnapshotNSID || batch.HeadCollection != publication.HeadNSID ||
		batch.HeadKey != materialHeadKey ||
		!batch.SnapshotCreateOnly ||
		!batch.RequiresAtomicBatch ||
		!batch.RequiresCreateExclude {
		return errMaterialTestBatchShape
	}
	if batch.SnapshotKey == "" || len(batch.SnapshotRecord) == 0 || len(batch.ExpectedSnapshotCID) == 0 ||
		len(batch.HeadRecord) == 0 {
		return errMaterialTestBatchShape
	}
	if batch.ExpectedContext.RepositoryRevision == "" {
		return errMaterialTestBatchShape
	}
	snapshot, err := publication.DecodeSnapshot(batch.SnapshotRecord)
	if err != nil || snapshot.Vault != transport.binding.Vault {
		return errMaterialTestBatchShape
	}
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	if err != nil || key != batch.SnapshotKey {
		return errMaterialTestBatchShape
	}
	cid, err := publication.RecordCID(batch.SnapshotRecord)
	if err != nil || !bytes.Equal(cid, batch.ExpectedSnapshotCID) {
		return errMaterialTestRecordMismatch
	}
	if err := publication.VerifyHeadBinding(batch.HeadRecord, batch.SnapshotRecord, batch.SnapshotKey); err != nil {
		return errMaterialTestBatchShape
	}
	head, err := publication.DecodeHead(batch.HeadRecord)
	if err != nil || head.Vault != transport.binding.Vault || head.PublicationSeq != snapshot.PublicationSeq ||
		!bytes.Equal(head.SnapshotCID, cid) {
		return errMaterialTestBatchShape
	}
	if batch.HeadCreate {
		if batch.ExpectedPredecessor != nil {
			return errMaterialTestPredecessor
		}
		if snapshot.PublicationSeq != 0 || len(snapshot.Parent) != 0 {
			return errMaterialTestBatchShape
		}
		return nil
	}
	if batch.ExpectedPredecessor == nil {
		return errMaterialTestPredecessor
	}
	if snapshot.PublicationSeq != batch.ExpectedPredecessor.Sequence+1 ||
		!bytes.Equal(snapshot.Parent, batch.ExpectedPredecessor.CID) {
		return errMaterialTestPredecessor
	}
	return nil
}

func (transport *materialTestTransport) checkMaterialBatch(batch MaterialWriteBatch) error {
	if err := transport.validateMaterialBatch(batch); err != nil {
		return err
	}
	if !sameMaterialContext(batch.ExpectedContext, transport.context) {
		return errMaterialTestStaleContext
	}
	snapshot, err := publication.DecodeSnapshot(batch.SnapshotRecord)
	if err != nil {
		return errMaterialTestBatchShape
	}
	if snapshot.PayloadForm() == publication.PayloadFormFileSet {
		for _, entry := range snapshot.Entries {
			payload, uploaded := transport.blobs[string(entry.Blob.CID)]
			if !uploaded {
				return errMaterialTestPayloadMissing
			}
			if uint64(len(payload)) != entry.Size {
				return errMaterialTestBatchShape
			}
		}
	} else {
		payload, uploaded := transport.blobs[string(snapshot.Blob.CID)]
		if !uploaded {
			return errMaterialTestPayloadMissing
		}
		if uint64(len(payload)) != snapshot.Blob.Size {
			return errMaterialTestBatchShape
		}
	}
	if batch.HeadCreate {
		if len(transport.head) != 0 {
			return errMaterialTestHeadExists
		}
	} else {
		if len(transport.head) == 0 {
			return errMaterialTestPredecessor
		}
		committed, err := publication.DecodeHead(transport.head)
		if err != nil || committed.PublicationSeq != batch.ExpectedPredecessor.Sequence ||
			!bytes.Equal(committed.SnapshotCID, batch.ExpectedPredecessor.CID) {
			return errMaterialTestPredecessor
		}
		if _, ok := transport.blocks[batch.ExpectedPredecessor.Key]; !ok {
			return errMaterialTestPredecessor
		}
	}
	if _, exists := transport.blocks[batch.SnapshotKey]; exists {
		return errMaterialTestCreateConflict
	}
	return nil
}

func (transport *materialTestTransport) advanceContextLocked() {
	transport.contextSeq++
	transport.context = materialTestContext(transport.contextSeq)
}

func (transport *materialTestTransport) advanceContext() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.advanceContextLocked()
}

func (transport *materialTestTransport) installSnapshot(t *testing.T, raw []byte) {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.installSnapshotLocked(t, raw, true)
	transport.advanceContextLocked()
}

func (transport *materialTestTransport) installSnapshotQuietly(t *testing.T, raw []byte, head bool) {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.installSnapshotLocked(t, raw, head)
}

func (transport *materialTestTransport) installSnapshotLocked(t *testing.T, raw []byte, head bool) {
	t.Helper()
	snapshot, err := publication.DecodeSnapshot(raw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	require.NoError(t, err)
	transport.blocks[key] = bytes.Clone(raw)
	if !head {
		return
	}
	snapshotCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	encoded, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: snapshot.Vault, PublicationSeq: snapshot.PublicationSeq,
		SnapshotCID: snapshotCID, BlobCID: snapshot.Blob.CID,
	})
	require.NoError(t, err)
	transport.head = encoded
}

func (transport *materialTestTransport) committed(key string) []byte {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return bytes.Clone(transport.blocks[key])
}

func (transport *materialTestTransport) committedHead() []byte {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return bytes.Clone(transport.head)
}

func (transport *materialTestTransport) applyCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.applies
}

func (transport *materialTestTransport) prepareCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.prepares
}

func (transport *materialTestTransport) sendCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.sends
}

func (transport *materialTestTransport) callOrder() []string {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]string(nil), transport.calls...)
}

func (transport *materialTestTransport) setPrepareHook(hook func()) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.prepareHook = hook
}

func (transport *materialTestTransport) setSendHook(hook func()) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.sendHook = hook
}

func (transport *materialTestTransport) setPreparedSecret(secret string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.preparedSecret = &secret
}

func (transport *materialTestTransport) setPreparedDispatch(dispatch int) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.preparedDispatch = &dispatch
}

func (transport *materialTestTransport) setPrepareError(err error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.prepareErr = err
}

func (transport *materialTestTransport) uploadCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.uploads
}

func (transport *materialTestTransport) setUploadError(err error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploadErr = err
}

func (transport *materialTestTransport) setUploadCID(cid []byte) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploadCID = bytes.Clone(cid)
}

func (transport *materialTestTransport) setUploadMIME(mimeType string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.uploadMIME = mimeType
}

func (transport *materialTestTransport) setWriteOnUpload() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.writeOnUpload = true
}

func (transport *materialTestTransport) setFailBeforeCommit() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.failBeforeCommit = true
}

func (transport *materialTestTransport) setSendError(err error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.sendErr = err
}

func (transport *materialTestTransport) setCommitThenFail() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.commitThenFail = true
}

type materialReviewGuard struct {
	source *materialReviewSource
}

func (guard *materialReviewGuard) Release() {
	guard.source.mu.Lock()
	defer guard.source.mu.Unlock()
	guard.source.releases++
}

type materialReviewSource struct {
	mu       sync.Mutex
	review   publicationstate.LocalReviewContext
	token    config.Token
	err      error
	hook     func()
	acquires int
	releases int
}

func newMaterialReviewSource(review publicationstate.LocalReviewContext) *materialReviewSource {
	return &materialReviewSource{review: review, token: config.Token{0x52, 0x4d}}
}

func (source *materialReviewSource) Acquire(
	context.Context,
) (publicationstate.LocalReviewContext, config.Token, ConfigGuard, error) {
	source.mu.Lock()
	review, token, err, hook := source.review, source.token, source.err, source.hook
	source.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return publicationstate.LocalReviewContext{}, config.Token{}, nil, err
	}
	source.mu.Lock()
	source.acquires++
	source.mu.Unlock()
	return review, token, &materialReviewGuard{source: source}, nil
}

func (source *materialReviewSource) set(review publicationstate.LocalReviewContext, token config.Token) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.review, source.token = review, token
}

func (source *materialReviewSource) setReview(review publicationstate.LocalReviewContext) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.review = review
}

func (source *materialReviewSource) setError(err error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.err = err
}

func (source *materialReviewSource) counts() (int, int) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.acquires, source.releases
}

type materialPublishFixture struct {
	binding       publicationstate.Binding
	store         *publicationstate.Store
	transport     *materialTestTransport
	coordinator   *Coordinator
	snapshot      model.Snapshot
	publicationID [16]byte
	review        publicationstate.LocalReviewContext
	reviews       *materialReviewSource
	paths         platform.Paths
}

func newMaterialPublishFixture(t *testing.T) *materialPublishFixture {
	t.Helper()
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x41, 0x52, 0x63},
	}
	binding.Repository = "at://" + binding.AccountDID
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	coordinator, err := NewCoordinator(Dependencies{State: openCoordinatorState(t)})
	require.NoError(t, err)
	review := publicationstate.LocalReviewContext{
		SelectionDigest:   [32]byte{1},
		SelectionRevision: 1,
		ApprovalDigest:    [32]byte{2},
		ApprovalRevision:  1,
	}
	return &materialPublishFixture{
		binding: binding, store: store, transport: newMaterialTestTransport(binding), coordinator: coordinator,
		snapshot: materialTestSnapshot("synthetic genesis payload"), publicationID: [16]byte{0x25, 0x71},
		review: review, reviews: newMaterialReviewSource(review), paths: materialTestPaths(t),
	}
}

func materialTestPaths(t *testing.T) platform.Paths {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home:       filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "config"),
		StateHome:  filepath.Join(root, "state"),
		CacheHome:  filepath.Join(root, "cache"),
		DataHome:   filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	return paths
}

func materialTestSnapshot(content string) model.Snapshot {
	return model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
			Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
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
}

func materialTestCandidate(
	t *testing.T,
	binding publicationstate.Binding,
	publicationID [16]byte,
	sequence uint64,
	parent, payload []byte,
) publicationstate.CandidateInput {
	t.Helper()
	blobCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	snapshotRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationID:  publicationID,
		PublicationSeq: sequence,
		Parent:         parent,
		Blob: publication.BlobReference{
			CID:      blobCID,
			Size:     uint64(len(payload)),
			MIMEType: publication.SnapshotBlobMIMEType,
		},
	})
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotRecord)
	require.NoError(t, err)
	headRecord, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: sequence,
		SnapshotCID: snapshotCID, BlobCID: blobCID,
	})
	require.NoError(t, err)
	return publicationstate.CandidateInput{
		SnapshotKey:    key,
		SnapshotRecord: snapshotRecord,
		HeadRecord:     headRecord,
		Payload:        payload,
	}
}

func (fixture *materialPublishFixture) request() MaterialPublishRequest {
	return MaterialPublishRequest{
		Store: fixture.store, Transport: fixture.transport, Binding: fixture.binding,
		Snapshot: fixture.snapshot, PublicationID: fixture.publicationID, Reviews: fixture.reviews,
	}
}

func (fixture *materialPublishFixture) prepare(t *testing.T) MaterialPublishProposal {
	t.Helper()
	proposal, err := fixture.coordinator.PreparePublishMaterial(context.Background(), fixture.request())
	require.NoError(t, err)
	return proposal
}

func (fixture *materialPublishFixture) publish(t *testing.T) (MaterialPublishProposal, MaterialPublishResult) {
	t.Helper()
	proposal := fixture.prepare(t)
	result, err := fixture.coordinator.PublishMaterial(context.Background(), proposal, proposal.Confirmation)
	require.NoError(t, err)
	return proposal, result
}

type materialWriteWitness struct {
	prepareActive    bool
	prepareLifecycle publicationstate.AttemptLifecycle
	sendActive       bool
	sendLifecycle    publicationstate.AttemptLifecycle
}

func (fixture *materialPublishFixture) witnessMaterialWrites(t *testing.T) *materialWriteWitness {
	t.Helper()
	witness := &materialWriteWitness{}
	fixture.transport.setPrepareHook(func() {
		attempt, active, err := fixture.store.ActiveAttempt(context.Background())
		require.NoError(t, err)
		witness.prepareActive, witness.prepareLifecycle = active, attempt.Lifecycle
	})
	fixture.transport.setSendHook(func() {
		attempt, active, err := fixture.store.ActiveAttempt(context.Background())
		require.NoError(t, err)
		witness.sendActive, witness.sendLifecycle = active, attempt.Lifecycle
	})
	return witness
}

func (witness *materialWriteWitness) assertPreparedPreSubmission(t *testing.T) {
	t.Helper()
	assert.True(t, witness.prepareActive, "PrepareWrites ran without a live attempt")
	assert.Equal(
		t,
		publicationstate.AttemptUploadStarted,
		witness.prepareLifecycle,
		"PrepareWrites did not run on a pre-submission attempt",
	)
	assert.True(t, witness.sendActive, "SendWrites ran without a live attempt")
	assert.Equal(
		t,
		publicationstate.AttemptMayHaveSubmitted,
		witness.sendLifecycle,
		"SendWrites did not run after BeginSubmission reserved the attempt",
	)
}

func requireMaterialRefusal(t *testing.T, err error, stage, reason string) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublishMaterial)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, stage, classified.Stage())
	assert.Equal(t, reason, classified.Reason())
}

func requireMaterialStoreRefusal(t *testing.T, err error, class error, reason publicationstate.Reason) {
	t.Helper()
	require.ErrorIs(t, err, class)
	var refused *publicationstate.Error
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, reason, refused.Reason())
}

func materialBatchTamperCases() []struct {
	name   string
	tamper func(*MaterialWriteBatch)
} {
	flip := func(data []byte) []byte {
		cloned := bytes.Clone(data)
		cloned[0] ^= 0xff
		return cloned
	}
	return []struct {
		name   string
		tamper func(*MaterialWriteBatch)
	}{
		{"snapshot-collection", func(batch *MaterialWriteBatch) { batch.SnapshotCollection = publication.HeadNSID }},
		{"snapshot-key", func(batch *MaterialWriteBatch) { batch.SnapshotKey = "0000000000000001" }},
		{"snapshot-record", func(batch *MaterialWriteBatch) {
			batch.SnapshotRecord = append(bytes.Clone(batch.SnapshotRecord), 0x00)
		}},
		{
			"expected-snapshot-cid",
			func(batch *MaterialWriteBatch) { batch.ExpectedSnapshotCID = flip(batch.ExpectedSnapshotCID) },
		},
		{"snapshot-create-only", func(batch *MaterialWriteBatch) { batch.SnapshotCreateOnly = false }},
		{"head-collection", func(batch *MaterialWriteBatch) { batch.HeadCollection = publication.SnapshotNSID }},
		{"head-key", func(batch *MaterialWriteBatch) { batch.HeadKey = "other" }},
		{
			"head-record",
			func(batch *MaterialWriteBatch) { batch.HeadRecord = append(bytes.Clone(batch.HeadRecord), 0x00) },
		},
		{"head-create", func(batch *MaterialWriteBatch) { batch.HeadCreate = !batch.HeadCreate }},
		{"expected-predecessor", func(batch *MaterialWriteBatch) {
			batch.ExpectedPredecessor = &publicationstate.RecordReference{
				Key:      batch.SnapshotKey,
				CID:      bytes.Clone(batch.ExpectedSnapshotCID),
				Sequence: 0,
			}
		}},
		{"expected-context", func(batch *MaterialWriteBatch) {
			batch.ExpectedContext.RepositoryRevision = "synthetic-revision-forged"
		}},
		{"requires-atomic-batch", func(batch *MaterialWriteBatch) { batch.RequiresAtomicBatch = false }},
		{"requires-create-exclude", func(batch *MaterialWriteBatch) { batch.RequiresCreateExclude = false }},
		{
			"requires-policy-check",
			func(batch *MaterialWriteBatch) { batch.RequiresPolicyCheck = !batch.RequiresPolicyCheck },
		},
	}
}

func TestPublishMaterialGenesisCommitsFloorAndRetiresAttempt(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	witness := fixture.witnessMaterialWrites(t)
	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	proposal, result := fixture.publish(t)

	witness.assertPreparedPreSubmission(t)
	assert.Equal(
		t,
		[]string{"read-view", "read-view", "upload-payload", "prepare-writes", "send-writes", "read-view"},
		fixture.transport.callOrder(),
	)
	assert.Equal(t, 1, fixture.transport.prepareCount())
	assert.Equal(t, 1, fixture.transport.sendCount())
	assert.Equal(t, publicationstate.OutcomeCurrent, result.Outcome)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, result.Attempt.Lifecycle)
	assert.Equal(t, uint64(1), result.Floor.Revision)
	assert.Equal(t, uint64(0), result.Floor.Sequence)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, result.Floor.RecordCID)
	assert.Equal(t, proposalPackedBlob(proposal).CID, testBlobCID(result.Floor))
	assert.Equal(t, proposal.Batch.HeadRecord, result.Floor.Head)
	assert.Equal(t, proposal.Batch.SnapshotRecord, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Equal(t, proposal.Batch.HeadRecord, fixture.transport.committedHead())
	assert.Equal(t, 1, fixture.transport.uploadCount())
	assert.Equal(t, 1, fixture.transport.applyCount())

	floor, present, err := fixture.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, result.Floor, floor)
	_, hasActive, err := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, hasActive)
	retained, err := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, retained.Lifecycle)

	decoded, err := publication.DecodePayload(packed.Payload, proposalPackedBlob(proposal))
	require.NoError(t, err)
	require.Len(t, decoded.Entries, 1)
	assert.Equal(t, []byte("synthetic genesis payload"), decoded.Entries[0].File.Content)
}

func TestPublishMaterialSuccessorExtendsCapturedFloor(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	genesisProposal, genesis := fixture.publish(t)

	fixture.publicationID = [16]byte{0x25, 0x72}
	fixture.snapshot = materialTestSnapshot("synthetic successor payload")
	witness := fixture.witnessMaterialWrites(t)
	sendsBefore := fixture.transport.sendCount()
	proposal := fixture.prepare(t)
	assert.False(t, proposal.Batch.HeadCreate)
	require.NotNil(t, proposal.Batch.ExpectedPredecessor)
	assert.Equal(
		t,
		publicationstate.RecordReference{
			Key:      genesisProposal.Batch.SnapshotKey,
			CID:      genesis.Floor.RecordCID,
			Sequence: 0,
		},
		*proposal.Batch.ExpectedPredecessor,
	)

	result, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	require.NoError(t, err)
	witness.assertPreparedPreSubmission(t)
	assert.Equal(t, sendsBefore+1, fixture.transport.sendCount())
	assert.Equal(t, uint64(2), result.Floor.Revision)
	assert.Equal(t, uint64(1), result.Floor.Sequence)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, result.Floor.RecordCID)
	record, err := publication.DecodeSnapshot(proposal.Batch.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, genesis.Floor.RecordCID, record.Parent)
	assert.Equal(
		t,
		genesisProposal.Batch.SnapshotRecord,
		fixture.transport.committed(genesisProposal.Batch.SnapshotKey),
	)
	assert.Equal(t, proposal.Batch.HeadRecord, fixture.transport.committedHead())
}

func TestPublishMaterialRefusesRejectedUpload(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setUploadError(errMaterialTestUploadRejected)
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "upload", "upload_failed")
	assert.Equal(t, 0, fixture.transport.applyCount())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptUploadStarted, attempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeNotSubmitted, attempt.Outcome)
	retained, readErr := fixture.store.ReadCandidate(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, readErr)
	assert.Equal(t, proposal.Candidate.Payload, retained.Payload)
}

func TestPublishMaterialRefusesApplyFailureBeforeCommit(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setFailBeforeCommit()
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Equal(t, 1, fixture.transport.applyCount())
	assert.Nil(t, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Nil(t, fixture.transport.committedHead())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, attempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeUnresolved, attempt.Outcome)
}

func TestPublishMaterialSurvivesCommittedResponseLoss(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setCommitThenFail()
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Equal(t, 1, fixture.transport.applyCount())
	assert.Equal(t, proposal.Batch.SnapshotRecord, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Equal(t, proposal.Batch.HeadRecord, fixture.transport.committedHead())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	pending, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, pending.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeUnresolved, pending.Outcome)

	view, viewErr := fixture.transport.ReadView(ctx)
	require.NoError(t, viewErr)
	loaded, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	resolution, resolveErr := fixture.store.ResolveAttempt(ctx, proposal.Proposal.AttemptID, loaded.StateDigest, view)
	require.NoError(t, resolveErr)
	assert.Equal(t, publicationstate.OutcomeCurrent, resolution.Outcome)
	finalization, finalizeErr := fixture.store.FinalizeAttempt(
		ctx,
		proposal.Proposal.AttemptID,
		resolution.Attempt.StateDigest,
		view,
	)
	require.NoError(t, finalizeErr)
	assert.Equal(t, proposal.Batch.ExpectedSnapshotCID, finalization.Floor.RecordCID)
	assert.Equal(t, 1, fixture.transport.applyCount())
}

func TestPublishMaterialRefusesBlobReferenceMismatch(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	other, err := publication.RawPayloadCID([]byte("synthetic unrelated payload"))
	require.NoError(t, err)
	fixture.transport.setUploadCID(other)
	proposal := fixture.prepare(t)

	_, publishErr := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, publishErr, "upload", "blob_mismatch")
	assert.Equal(t, 0, fixture.transport.applyCount())
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptUploadStarted, attempt.Lifecycle)
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
}

func TestPublishMaterialRefusesConfirmationMismatch(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	wrong := proposal.Confirmation
	wrong[0] ^= 0xff

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, wrong)
	requireMaterialRefusal(t, err, "consent", "confirmation_mismatch")
	_, zeroErr := fixture.coordinator.PublishMaterial(ctx, proposal, [32]byte{})
	requireMaterialRefusal(t, zeroErr, "consent", "confirmation_mismatch")
	_, hasActive, activeErr := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, activeErr)
	assert.False(t, hasActive)
	_, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.Error(t, loadErr)
	assert.Equal(t, 0, fixture.transport.uploadCount())
	assert.Equal(t, 0, fixture.transport.applyCount())
}

func TestPublishMaterialRefusesStaleProposal(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	view, err := fixture.transport.ReadView(ctx)
	require.NoError(t, err)
	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	otherCandidate := materialTestCandidate(t, fixture.binding, [16]byte{0x30}, 0, nil, packed.Payload)
	otherProposal, err := fixture.store.PrepareAttempt(ctx, otherCandidate, view, fixture.review)
	require.NoError(t, err)
	otherAttempt, err := fixture.store.CreateAttempt(
		ctx,
		otherProposal.StateToken,
		otherCandidate,
		view,
		fixture.review,
		otherProposal.Confirmation,
	)
	require.NoError(t, err)
	abandonProposal, err := fixture.store.PrepareAbandon(ctx, otherAttempt.ID, nil)
	require.NoError(t, err)
	_, err = fixture.store.AbandonAttempt(
		ctx,
		otherAttempt.ID,
		abandonProposal.StateToken,
		nil,
		abandonProposal.Confirmation,
	)
	require.NoError(t, err)

	_, publishErr := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialStoreRefusal(t, publishErr, publicationstate.ErrConsent, publicationstate.ReasonStale)
	assert.Equal(t, 0, fixture.transport.uploadCount())
	assert.Equal(t, 0, fixture.transport.applyCount())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
}

func TestPublishMaterialRefusesSelectionChangeAfterPrepare(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	review, _ := fixture.reviews.counts()
	changed := fixture.review
	changed.SelectionDigest = [32]byte{0x77}
	changed.SelectionRevision = 2
	fixture.reviews.set(changed, config.Token{0x31})

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "consent", "review_changed")
	require.ErrorIs(t, err, ErrConfigChangedSincePrepare, "selection drift did not refuse the publication")
	assert.Positive(t, review, "prepare did not acquire the configuration review")
	assert.Equal(t, 1, fixture.transport.uploadCount(), "the fence refused before upload")
	assert.Equal(t, 0, fixture.transport.prepareCount(), "the fence prepared writes after a configuration change")
	assert.Equal(t, 0, fixture.transport.sendCount(), "the fence dispatched writes after a configuration change")
	assert.Equal(t, 0, fixture.transport.applyCount(), "the fence applied writes after a configuration change")
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(
		t,
		publicationstate.AttemptUploadStarted,
		attempt.Lifecycle,
		"the refused publication consumed the reservation",
	)
	assert.Equal(
		t,
		publicationstate.OutcomeNotSubmitted,
		attempt.Outcome,
		"the refused publication claimed a submission",
	)
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present, "the refused publication advanced the floor")
}

func TestPublishMaterialRefusesApprovalChangeAfterPrepare(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	changed := fixture.review
	changed.ApprovalDigest = [32]byte{0x78}
	changed.ApprovalRevision = 2
	fixture.reviews.set(changed, config.Token{0x32})

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "consent", "review_changed")
	require.ErrorIs(t, err, ErrConfigChangedSincePrepare, "approval drift did not refuse the publication")
	assert.Equal(t, 0, fixture.transport.prepareCount(), "the fence prepared writes after an approval change")
	assert.Equal(t, 0, fixture.transport.sendCount(), "the fence dispatched writes after an approval change")
	assert.Equal(t, 0, fixture.transport.applyCount(), "the fence applied writes after an approval change")
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(
		t,
		publicationstate.AttemptUploadStarted,
		attempt.Lifecycle,
		"the refused publication consumed the reservation",
	)
}

func TestPublishMaterialRefusesTamperedReviewIdentity(t *testing.T) {
	ctx := context.Background()
	tamperCases := []struct {
		name   string
		tamper func(*MaterialPublishProposal)
	}{
		{"selection digest", func(p *MaterialPublishProposal) { p.Review.SelectionDigest = [32]byte{0x79} }},
		{"selection revision", func(p *MaterialPublishProposal) { p.Review.SelectionRevision++ }},
		{"approval digest", func(p *MaterialPublishProposal) { p.Review.ApprovalDigest = [32]byte{0x7a} }},
		{"approval revision", func(p *MaterialPublishProposal) { p.Review.ApprovalRevision++ }},
		{"publication id", func(p *MaterialPublishProposal) { p.PublicationID = [16]byte{0x7b} }},
		{"proposal token", func(p *MaterialPublishProposal) { p.ProposalToken[0] ^= 0xff }},
	}
	for _, testCase := range tamperCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newMaterialPublishFixture(t)
			proposal := fixture.prepare(t)
			testCase.tamper(&proposal)

			_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
			requireMaterialRefusal(t, err, "consent", "review_mismatch")
			require.ErrorIs(t, err, ErrReviewMismatch, "a tampered proposal was not refused as a review mismatch")
			_, hasActive, activeErr := fixture.store.ActiveAttempt(ctx)
			require.NoError(t, activeErr)
			assert.False(t, hasActive, "the refused proposal created an attempt")
			assert.Equal(t, 0, fixture.transport.uploadCount(), "the refused proposal uploaded a payload")
			assert.Equal(t, 0, fixture.transport.applyCount(), "the refused proposal applied a batch")
		})
	}
}

func TestPublishMaterialRefusesIdentityNoConfigurationSupports(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	forged := fixture.review
	forged.SelectionDigest = [32]byte{0x7c}
	fixture.reviews.setReview(forged)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "consent", "review_mismatch")
	require.ErrorIs(
		t,
		err,
		ErrReviewMismatch,
		"an identity the unchanged configuration cannot support was not refused as a mismatch",
	)
	assert.Equal(t, 0, fixture.transport.prepareCount(), "the forged identity reached write preparation")
	assert.Equal(t, 0, fixture.transport.sendCount(), "the forged identity reached dispatch")
}

func TestPublishMaterialFencesConfigurationWritesThroughSubmission(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	port := FileConfigPort{Paths: fixture.paths}
	_, err := port.Update(ctx, config.Token{}, func(c config.Config) (config.Config, error) {
		c.Targets = append(
			c.Targets,
			config.Target{
				ID:     "files",
				Source: model.SourceFiles,
				Root:   &config.Root{Base: model.RootHome, Path: "dotfiles", Kind: model.SelectionDirectory},
			},
		)
		return c, nil
	})
	require.NoError(t, err)
	snapshot, err := port.Snapshot(ctx)
	require.NoError(t, err)

	proposal, err := fixture.coordinator.PreparePublishMaterial(ctx, MaterialPublishRequest{
		Store: fixture.store, Transport: fixture.transport, Binding: fixture.binding,
		Snapshot: fixture.snapshot, PublicationID: fixture.publicationID, Reviews: port,
	})
	require.NoError(t, err)
	assert.Equal(t, publicationstate.LocalReviewContext{
		SelectionDigest: snapshot.Selection.Digest, SelectionRevision: snapshot.Selection.Revision,
		ApprovalDigest: snapshot.Approval.Digest, ApprovalRevision: snapshot.Approval.Revision,
	}, proposal.Review, "the proposal did not carry the prepared configuration identity")

	var fenced error
	fixture.transport.setSendHook(func() { fenced = probeConfigWriter(fixture.paths) })
	result, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.OutcomeCurrent, result.Outcome)
	assert.Equal(t, 1, fixture.transport.sendCount())
	require.ErrorIs(t, fenced, syscall.EWOULDBLOCK, "a configuration writer was not fenced during SendWrites")
	require.NoError(t, probeConfigWriter(fixture.paths), "the published fence kept the configuration lock")

	updated, err := port.Update(ctx, snapshot.Token, func(c config.Config) (config.Config, error) {
		c.Targets[0].Mode = config.AutoApply
		return c, nil
	})
	require.NoError(t, err, "a configuration write after publication was refused")
	assert.Equal(
		t,
		snapshot.Selection.Revision+1,
		updated.Selection.Revision,
		"the fenced write did not advance the selection revision",
	)
}

func probeConfigWriter(paths platform.Paths) error {
	file, err := os.OpenFile(
		filepath.Join(paths.AppConfigDir(), config.LockFileName),
		os.O_RDWR|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return err
	}
	locked := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
	return locked
}

func TestPublishMaterialRefusesUnavailableReviewSource(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	refused := errors.New("synthetic configuration read failure")
	fixture.reviews.setError(refused)

	_, err := fixture.coordinator.PreparePublishMaterial(ctx, fixture.request())
	requireMaterialRefusal(t, err, "consent", "review_changed")
	require.ErrorIs(t, err, refused)

	fixture.reviews.setError(nil)
	proposal := fixture.prepare(t)
	fixture.reviews.setError(refused)
	_, err = fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "consent", "review_changed")
	require.ErrorIs(t, err, refused)
	assert.Equal(t, 0, fixture.transport.sendCount(), "an unreadable configuration dispatched writes")
	acquires, releases := fixture.reviews.counts()
	assert.Equal(t, acquires, releases, "a review guard leaked")
}

func TestPublishMaterialRefusesMissingReviewSource(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	request := fixture.request()
	request.Reviews = nil

	_, err := fixture.coordinator.PreparePublishMaterial(ctx, request)
	requireMaterialRefusal(t, err, "input", "request_invalid")

	proposal := fixture.prepare(t)
	proposal.Reviews = nil
	_, err = fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "input", "request_invalid")
}

func TestPublishMaterialRefusesTamperedBatch(t *testing.T) {
	ctx := context.Background()
	for _, testCase := range materialBatchTamperCases() {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newMaterialPublishFixture(t)
			proposal := fixture.prepare(t)
			testCase.tamper(&proposal.Batch)

			_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
			requireMaterialRefusal(t, err, "batch", "batch_invalid")
			_, hasActive, activeErr := fixture.store.ActiveAttempt(ctx)
			require.NoError(t, activeErr)
			assert.False(t, hasActive)
			assert.Equal(t, 0, fixture.transport.uploadCount())
			assert.Equal(t, 0, fixture.transport.applyCount())
		})
	}
}

func TestPublishMaterialRefusesStaleObservation(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	stale := fixture.prepare(t)
	fixture.transport.advanceContext()
	observed, observedErr := fixture.transport.ReadView(ctx)
	require.NoError(t, observedErr)
	assert.False(t, sameMaterialContext(stale.Batch.ExpectedContext, observed.SuppliedContext))

	_, err := fixture.coordinator.PublishMaterial(ctx, stale, stale.Confirmation)
	requireMaterialRefusal(t, err, "view", "observation_stale")
	_, hasActive, activeErr := fixture.store.ActiveAttempt(ctx)
	require.NoError(t, activeErr)
	assert.False(t, hasActive)
	assert.Equal(t, 0, fixture.transport.uploadCount())
	assert.Equal(t, 0, fixture.transport.applyCount())

	fresh, freshResult := fixture.publish(t)
	assert.NotEqual(t, stale.Batch.ExpectedContext.RepositoryRevision, fresh.Batch.ExpectedContext.RepositoryRevision)
	assert.True(t, sameMaterialContext(fresh.Batch.ExpectedContext, observed.SuppliedContext))
	assert.Equal(t, fresh.Batch.ExpectedSnapshotCID, freshResult.Floor.RecordCID)
	assert.Equal(t, 1, fixture.transport.applyCount())
}

func TestPublishMaterialRefusesStaleContextRejection(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setWriteOnUpload()
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Equal(t, 1, fixture.transport.applyCount())
	assert.Nil(t, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Nil(t, fixture.transport.committedHead())
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)
	pending, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, pending.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeUnresolved, pending.Outcome)

	_, replayErr := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, replayErr, "view", "observation_stale")
	assert.Equal(t, 1, fixture.transport.applyCount())
	_, freshErr := fixture.coordinator.PreparePublishMaterial(ctx, fixture.request())
	requireMaterialStoreRefusal(t, freshErr, publicationstate.ErrConsent, publicationstate.ReasonActiveAttempt)
}

func TestPublishMaterialRefusesLostFenceResolution(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setFailBeforeCommit()
	proposal := fixture.prepare(t)
	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")

	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	competitor := materialTestCandidate(t, fixture.binding, [16]byte{0x40}, 0, nil, packed.Payload)
	fixture.transport.installSnapshot(t, competitor.SnapshotRecord)

	view, viewErr := fixture.transport.ReadView(ctx)
	require.NoError(t, viewErr)
	loaded, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	resolution, resolveErr := fixture.store.ResolveAttempt(ctx, proposal.Proposal.AttemptID, loaded.StateDigest, view)
	require.NoError(t, resolveErr)
	assert.Equal(t, publicationstate.OutcomeLostFence, resolution.Outcome)
	_, finalizeErr := fixture.store.FinalizeAttempt(
		ctx,
		proposal.Proposal.AttemptID,
		resolution.Attempt.StateDigest,
		view,
	)
	requireMaterialStoreRefusal(t, finalizeErr, publicationstate.ErrContinuity, publicationstate.ReasonSubmittedUnknown)
	_, present, loadErr := fixture.store.Load(ctx)
	require.NoError(t, loadErr)
	assert.False(t, present)

	evidence, recorded, evidenceErr := fixture.store.ReadFirstConflict(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, evidenceErr)
	require.True(t, recorded)
	assert.Equal(t, competitor.SnapshotRecord, evidence.HeadRecord)
	assert.Equal(t, uint64(0), evidence.HeadSequence)
}

func TestPublishMaterialRefusesObsoleteTokens(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	attempt, err := fixture.store.CreateAttempt(
		ctx,
		proposal.Proposal.StateToken,
		proposal.Candidate,
		proposal.View,
		proposal.Review,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	preDispatch, err := fixture.store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)

	uploadProposal, err := fixture.store.PrepareDispatch(
		ctx,
		attempt.ID,
		publicationstate.DispatchUpload,
		proposal.View,
		proposal.Review,
	)
	require.NoError(t, err)
	_, wrongDomainUpload := fixture.store.BeginUpload(
		ctx,
		attempt.ID,
		attempt.StateDigest,
		proposal.View,
		proposal.Review,
		uploadProposal.Confirmation,
	)
	requireMaterialStoreRefusal(t, wrongDomainUpload, publicationstate.ErrConsent, publicationstate.ReasonStale)
	_, err = fixture.store.BeginUpload(
		ctx,
		attempt.ID,
		uploadProposal.StateToken,
		proposal.View,
		proposal.Review,
		uploadProposal.Confirmation,
	)
	require.NoError(t, err)
	_, reusedErr := fixture.store.BeginUpload(
		ctx,
		attempt.ID,
		uploadProposal.StateToken,
		proposal.View,
		proposal.Review,
		uploadProposal.Confirmation,
	)
	requireMaterialStoreRefusal(t, reusedErr, publicationstate.ErrConsent, publicationstate.ReasonStale)

	submissionProposal, err := fixture.store.PrepareDispatch(
		ctx,
		attempt.ID,
		publicationstate.DispatchSubmission,
		proposal.View,
		proposal.Review,
	)
	require.NoError(t, err)
	_, err = fixture.store.BeginSubmission(
		ctx,
		attempt.ID,
		submissionProposal.StateToken,
		proposal.View,
		proposal.Review,
		submissionProposal.Confirmation,
	)
	require.NoError(t, err)
	postSubmission, err := fixture.store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.NotEqual(t, preDispatch.StateDigest, postSubmission.StateDigest)

	view, viewErr := fixture.transport.ReadView(ctx)
	require.NoError(t, viewErr)
	_, wrongDomainResolve := fixture.store.ResolveAttempt(ctx, attempt.ID, uploadProposal.StateToken, view)
	requireMaterialStoreRefusal(t, wrongDomainResolve, publicationstate.ErrConsent, publicationstate.ReasonStale)
	_, obsoleteErr := fixture.store.ResolveAttempt(ctx, attempt.ID, preDispatch.StateDigest, view)
	requireMaterialStoreRefusal(t, obsoleteErr, publicationstate.ErrConsent, publicationstate.ReasonStale)
	_, currentErr := fixture.store.ResolveAttempt(ctx, attempt.ID, postSubmission.StateDigest, view)
	require.NoError(t, currentErr)
}

type materialCancelingTransport struct {
	MaterialTransport

	cancel context.CancelFunc
}

func (transport materialCancelingTransport) SendWrites(
	context.Context,
	MaterialPreparedWrites,
) (MaterialWriteOutcome, error) {
	transport.cancel()
	return MaterialWriteOutcome{}, errMaterialTestBeforeCommit
}

func TestPublishMaterialKeepsSubmissionAmbiguityAfterCancellation(t *testing.T) {
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proposal.Transport = materialCancelingTransport{MaterialTransport: fixture.transport, cancel: cancel}

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "submission", "submission_unresolved")
	assert.Nil(t, fixture.transport.committed(proposal.Batch.SnapshotKey))
	assert.Nil(t, fixture.transport.committedHead())
}

func TestPublishMaterialBatchMatchesSubmissionMaterial(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	attempt, err := fixture.store.CreateAttempt(
		ctx,
		proposal.Proposal.StateToken,
		proposal.Candidate,
		proposal.View,
		proposal.Review,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	uploadProposal, err := fixture.store.PrepareDispatch(
		ctx,
		attempt.ID,
		publicationstate.DispatchUpload,
		proposal.View,
		proposal.Review,
	)
	require.NoError(t, err)
	_, err = fixture.store.BeginUpload(
		ctx,
		attempt.ID,
		uploadProposal.StateToken,
		proposal.View,
		proposal.Review,
		uploadProposal.Confirmation,
	)
	require.NoError(t, err)
	submissionProposal, err := fixture.store.PrepareDispatch(
		ctx,
		attempt.ID,
		publicationstate.DispatchSubmission,
		proposal.View,
		proposal.Review,
	)
	require.NoError(t, err)
	submission, err := fixture.store.BeginSubmission(
		ctx,
		attempt.ID,
		submissionProposal.StateToken,
		proposal.View,
		proposal.Review,
		submissionProposal.Confirmation,
	)
	require.NoError(t, err)

	material := materialWriteBatchFromSubmission(submission)
	assert.True(t, sameMaterialWriteBatch(proposal.Batch, material))
	assert.Nil(t, material.ExpectedPredecessor)
	for _, testCase := range materialBatchTamperCases() {
		t.Run(testCase.name, func(t *testing.T) {
			tampered := cloneMaterialWriteBatch(material)
			testCase.tamper(&tampered)
			assert.False(t, sameMaterialWriteBatch(proposal.Batch, tampered))
		})
	}
}

func TestPublishMaterialTransportEnforcesConditionalBatch(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	prepared, err := fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)

	_, err = fixture.transport.SendWrites(ctx, prepared)
	require.ErrorIs(t, err, errMaterialTestPayloadMissing)
	assert.Nil(t, fixture.transport.committedHead())

	fixture = newMaterialPublishFixture(t)
	proposal = fixture.prepare(t)
	prepared, err = fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)
	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)

	competing := materialTestCandidate(t, fixture.binding, [16]byte{0x41}, 0, nil, packed.Payload)
	fixture.transport.installSnapshotQuietly(t, competing.SnapshotRecord, false)
	_, err = fixture.transport.SendWrites(ctx, prepared)
	require.ErrorIs(
		t,
		err,
		errMaterialTestCreateConflict,
		"the transport accepted a create-only snapshot that already exists",
	)
	assert.Nil(t, fixture.transport.committedHead())

	fixture = newMaterialPublishFixture(t)
	proposal = fixture.prepare(t)
	prepared, err = fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)
	packed, err = vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)
	head := materialTestCandidate(t, fixture.binding, [16]byte{0x42}, 0, nil, packed.Payload)
	fixture.transport.installSnapshotQuietly(t, head.SnapshotRecord, true)
	_, err = fixture.transport.SendWrites(ctx, prepared)
	require.ErrorIs(t, err, errMaterialTestHeadExists, "the transport accepted a head create against an existing head")
	assert.Equal(t, head.SnapshotRecord, fixture.transport.committed(head.SnapshotKey))

	fixture = newMaterialPublishFixture(t)
	proposal = fixture.prepare(t)
	prepared, err = fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)
	packed, err = vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)
	fixture.transport.advanceContext()
	_, err = fixture.transport.SendWrites(ctx, prepared)
	require.ErrorIs(t, err, errMaterialTestStaleContext, "the transport accepted a batch with a stale expected context")
	assert.Nil(t, fixture.transport.committedHead())

	fixture = newMaterialPublishFixture(t)
	proposal = fixture.prepare(t)
	different := materialTestSnapshot("synthetic competing payload")
	differentPacked, err := vault.Pack(different)
	require.NoError(t, err)
	other := materialTestCandidate(t, fixture.binding, [16]byte{0x43}, 0, nil, differentPacked.Payload)
	forged := cloneMaterialWriteBatch(proposal.Batch)
	forged.SnapshotRecord = other.SnapshotRecord
	_, err = fixture.transport.PrepareWrites(ctx, forged)
	require.ErrorIs(
		t,
		err,
		errMaterialTestRecordMismatch,
		"the transport prepared record bytes that do not hash to the expected snapshot cid",
	)
	assert.Equal(t, 0, fixture.transport.sendCount())
	assert.Nil(t, fixture.transport.committedHead())
}

func materialPrepareShapeCases() []struct {
	name   string
	tamper func(*MaterialWriteBatch)
} {
	return []struct {
		name   string
		tamper func(*MaterialWriteBatch)
	}{
		{"missing-snapshot", func(batch *MaterialWriteBatch) { batch.SnapshotRecord = nil }},
		{"missing-head", func(batch *MaterialWriteBatch) { batch.HeadRecord = nil }},
		{"extra-write", func(batch *MaterialWriteBatch) { batch.HeadRecord = bytes.Clone(batch.SnapshotRecord) }},
		{"wrong-collection", func(batch *MaterialWriteBatch) { batch.SnapshotCollection = publication.HeadNSID }},
		{"wrong-head-key", func(batch *MaterialWriteBatch) { batch.HeadKey = "other" }},
	}
}

func TestPublishMaterialPrepareRefusesNonPairBatch(t *testing.T) {
	ctx := context.Background()
	for _, testCase := range materialPrepareShapeCases() {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newMaterialPublishFixture(t)
			proposal := fixture.prepare(t)
			batch := cloneMaterialWriteBatch(proposal.Batch)
			testCase.tamper(&batch)

			_, err := fixture.transport.PrepareWrites(ctx, batch)
			require.ErrorIs(t, err, errMaterialTestBatchShape)
			assert.Equal(t, 0, fixture.transport.sendCount())
			assert.Equal(t, 0, fixture.transport.applyCount())
			assert.Nil(t, fixture.transport.committedHead())
		})
	}
}

func TestPublishMaterialPrepareRefusesPolicyCheckAndPrivateBackend(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	policyBatch := cloneMaterialWriteBatch(proposal.Batch)
	policyBatch.RequiresPolicyCheck = true

	_, err := fixture.transport.PrepareWrites(ctx, policyBatch)
	require.ErrorIs(t, err, errMaterialTestPolicyCheck)
	assert.Equal(t, 0, fixture.transport.sendCount())
	assert.Equal(t, 0, fixture.transport.applyCount())

	spacesBinding := fixture.binding
	spacesBinding.Backend = publicationstate.BackendSpaces
	spacesTransport := newMaterialTestTransport(spacesBinding)
	_, err = spacesTransport.PrepareWrites(ctx, proposal.Batch)
	require.ErrorIs(t, err, errMaterialTestBackend)
	assert.Equal(t, 0, spacesTransport.sendCount())
	assert.Equal(t, 0, spacesTransport.applyCount())
}

func TestPublishMaterialRefusesUnusablePreparedWrites(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*materialTestTransport)
	}{
		{"empty-secret", func(transport *materialTestTransport) { transport.setPreparedSecret("") }},
		{"dispatch-count", func(transport *materialTestTransport) { transport.setPreparedDispatch(2) }},
		{"dispatch-zero", func(transport *materialTestTransport) { transport.setPreparedDispatch(0) }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newMaterialPublishFixture(t)
			testCase.configure(fixture.transport)
			proposal := fixture.prepare(t)

			_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
			requireMaterialRefusal(t, err, "submission", "submission_mismatch")
			assert.Equal(t, 1, fixture.transport.prepareCount())
			assert.Equal(t, 0, fixture.transport.sendCount())
			assert.Equal(t, 0, fixture.transport.applyCount())
			assert.Nil(t, fixture.transport.committedHead())
			attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
			require.NoError(t, loadErr)
			assert.Equal(t, publicationstate.AttemptUploadStarted, attempt.Lifecycle)
			assert.Equal(t, publicationstate.OutcomeNotSubmitted, attempt.Outcome)
		})
	}
}

func TestPublishMaterialRefusesPrepareFailureThroughOrchestration(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	fixture.transport.setPrepareError(errMaterialTestBatchShape)
	proposal := fixture.prepare(t)

	_, err := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
	requireMaterialRefusal(t, err, "batch", "batch_invalid")
	assert.Equal(t, 1, fixture.transport.prepareCount())
	assert.Equal(t, 0, fixture.transport.sendCount())
	assert.Equal(t, 0, fixture.transport.applyCount())
	assert.Nil(t, fixture.transport.committedHead())
	attempt, loadErr := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
	require.NoError(t, loadErr)
	assert.Equal(t, publicationstate.AttemptUploadStarted, attempt.Lifecycle)
	assert.Equal(t, publicationstate.OutcomeNotSubmitted, attempt.Outcome)
}

func TestPublishMaterialDispatchConsumesPreparedWrites(t *testing.T) {
	ctx := context.Background()
	fixture := newMaterialPublishFixture(t)
	proposal := fixture.prepare(t)
	packed, err := vault.Pack(fixture.snapshot)
	require.NoError(t, err)
	_, err = fixture.transport.UploadPayload(ctx, packed.Payload)
	require.NoError(t, err)
	prepared, err := fixture.transport.PrepareWrites(ctx, proposal.Batch)
	require.NoError(t, err)
	dispatch := materialWriteDispatch{prepared: prepared}

	err = dispatch.send(ctx, fixture.transport)
	require.NoError(t, err)
	assert.Equal(t, 1, fixture.transport.sendCount())
	assert.Equal(t, 1, fixture.transport.applyCount())

	replayErr := dispatch.send(ctx, fixture.transport)
	requireMaterialRefusal(t, replayErr, "submission", "submission_mismatch")
	assert.Equal(t, 1, fixture.transport.sendCount())
	assert.Equal(t, 1, fixture.transport.applyCount())

	_, transportReplay := fixture.transport.SendWrites(ctx, prepared)
	require.ErrorIs(t, transportReplay, errMaterialTestReplayed)
	assert.Equal(t, 1, fixture.transport.sendCount())
	assert.Equal(t, 1, fixture.transport.applyCount())
}

func TestPublishMaterialDeclaresAndVerifiesTheProviderBlobMediaType(t *testing.T) {
	ctx := context.Background()

	t.Run("declares-the-packed-payload-media-type", func(t *testing.T) {
		fixture := newMaterialPublishFixture(t)
		proposal, result := fixture.publish(t)

		sealed, err := publication.DecodeSnapshot(proposal.Batch.SnapshotRecord)
		require.NoError(t, err)
		assert.Equal(t, publication.SnapshotBlobMIMEType, sealed.Blob.MIMEType)
		assert.Equal(t, publication.SnapshotBlobMIMEType, proposalPackedBlob(proposal).MIMEType)
		assert.Equal(t, publicationstate.OutcomeCurrent, result.Outcome)
		assert.Equal(t, 1, fixture.transport.applyCount())

		committed, err := publication.DecodeSnapshot(fixture.transport.committed(proposal.Batch.SnapshotKey))
		require.NoError(t, err)
		assert.Equal(t, publication.SnapshotBlobMIMEType, committed.Blob.MIMEType)
	})

	t.Run("refuses-a-provider-media-type-that-differs", func(t *testing.T) {
		fixture := newMaterialPublishFixture(t)
		fixture.transport.setUploadMIME(publication.BlobMIMEType)
		proposal := fixture.prepare(t)

		_, publishErr := fixture.coordinator.PublishMaterial(ctx, proposal, proposal.Confirmation)
		requireMaterialRefusal(t, publishErr, "upload", "blob_mismatch")
		assert.Equal(t, 0, fixture.transport.applyCount())
		assert.Nil(t, fixture.transport.committed(proposal.Batch.SnapshotKey))

		attempt, err := fixture.store.LoadAttempt(ctx, proposal.Proposal.AttemptID)
		require.NoError(t, err)
		assert.Equal(t, publicationstate.AttemptUploadStarted, attempt.Lifecycle)
		_, present, err := fixture.store.Load(ctx)
		require.NoError(t, err)
		assert.False(t, present)
	})
}
