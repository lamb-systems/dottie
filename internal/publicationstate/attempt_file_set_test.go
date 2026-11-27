package publicationstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

type fileSetAttemptFixture struct {
	binding Binding
	raw     []byte
	head    []byte
	key     string
	entries []publication.PayloadEntry
}

func newFileSetAttemptFixture(t *testing.T, paths []string) fileSetAttemptFixture {
	t.Helper()
	entries := make([]publication.SnapshotEntry, 0, len(paths))
	supplied := make([]publication.PayloadEntry, 0, len(paths))
	for _, path := range paths {
		content := []byte("synthetic file-set entry for " + path)
		cid, err := publication.RawPayloadCID(content)
		require.NoError(t, err)
		entries = append(entries, publication.SnapshotEntry{
			Path: path, Mode: 0o600, Size: uint64(len(content)), Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{
				CID: cid, Size: uint64(len(content)), MIMEType: publication.BlobMIMEType,
			},
		})
		supplied = append(supplied, publication.PayloadEntry{
			Path: path, Mode: 0o600, Size: uint64(len(content)), Content: content,
		})
	}
	binding := Binding{AccountDID: testDID, Backend: BackendPublicRepo, Repository: "at://" + testDID}
	binding.Vault[0] = 9
	var publicationID [16]byte
	publicationID[0] = 0x42
	record := publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationID:  publicationID,
		PublicationSeq: 0,
		Parent:         []byte{},
		Segments:       []publication.SnapshotSegment{{Target: fileSetTestTargets()[0], Form: publication.SegmentFormEntries, Entries: entries}},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: 0,
		SnapshotCID:    recordCID,
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	return fileSetAttemptFixture{
		binding: binding,
		raw:     raw,
		head:    head,
		key:     key,
		entries: supplied,
	}
}

func (f fileSetAttemptFixture) view() SuppliedRepositoryView {
	return SuppliedRepositoryView{
		Origin:          f.binding,
		Scope:           ViewScopeWholeRepository,
		SuppliedContext: SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}},
	}
}

func (f fileSetAttemptFixture) currentView() SuppliedRepositoryView {
	view := f.view()
	view.Head = bytes.Clone(f.head)
	view.Snapshots = []SnapshotBlock{{Key: f.key, Raw: bytes.Clone(f.raw)}}
	return view
}

func (f fileSetAttemptFixture) candidate() CandidateInput {
	entries := make([]publication.PayloadEntry, 0, len(f.entries))
	for _, entry := range f.entries {
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: bytes.Clone(entry.Content),
		})
	}
	segments, payloads := fixtureCandidateSegments(f.raw, nil)
	return CandidateInput{
		SnapshotKey:    f.key,
		SnapshotRecord: bytes.Clone(f.raw),
		HeadRecord:     bytes.Clone(f.head),
		Entries:        entries,
		Segments:       segments,
		Payloads:       payloads,
	}
}

func (f fileSetAttemptFixture) references() []PayloadEntryReference {
	references := make([]PayloadEntryReference, 0, len(f.entries))
	for _, entry := range f.entries {
		cid, err := publication.RawPayloadCID(entry.Content)
		if err != nil {
			return nil
		}
		references = append(references, PayloadEntryReference{
			Path: entry.Path, CID: cid, Size: uint64(len(entry.Content)),
		})
	}
	return references
}

func fileSetFixture(t *testing.T) fileSetAttemptFixture {
	return newFileSetAttemptFixture(t, []string{"init.lua", "lua/config/options.lua", "lua/plugin/init.lua"})
}

func stageFileSetAttempt(
	t *testing.T,
	store *Store,
	f fileSetAttemptFixture,
	view SuppliedRepositoryView,
	review LocalReviewContext,
) Attempt {
	t.Helper()
	candidate := f.candidate()
	proposal, err := store.PrepareAttempt(context.Background(), candidate, view, review)
	require.NoError(t, err)
	assert.Equal(t, AttemptGenesis, proposal.Kind)
	assert.Len(t, proposal.CandidateSegments, 1)
	assert.Equal(t, PayloadFormFileSet, proposal.CandidateSegments[0].Form)
	attempt, err := store.CreateAttempt(
		context.Background(),
		proposal.StateToken,
		candidate,
		view,
		review,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	require.NotNil(t, testFileSet(attempt))
	assert.Nil(t, testBlobCID(attempt))
	assert.Equal(t, uint64(0), testBlobSize(attempt))
	return attempt
}

func beginFileSetUpload(
	t *testing.T,
	store *Store,
	attempt Attempt,
	view SuppliedRepositoryView,
	review LocalReviewContext,
) UploadMaterial {
	t.Helper()
	proposal, err := store.PrepareDispatch(context.Background(), attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	material, err := store.BeginUpload(
		context.Background(),
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	return material
}

func TestFileSetAttemptStagesUploadsSubmitsAndReadsBack(t *testing.T) {
	ctx := context.Background()
	f := fileSetFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageFileSetAttempt(t, store, f, view, review)
	require.Len(t, fileSetEntries(attempt), 3)

	for _, entry := range f.entries {
		info, err := os.Stat(filepath.Join(directory, payloadDirectoryName, payloadBasename(entry.Content)))
		require.NoError(t, err)
		assert.Equal(t, int64(len(entry.Content)), info.Size())
	}
	var objects, refs int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&refs))
	assert.Equal(t, 3, objects)
	assert.Equal(t, 0, refs)

	staged, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	require.Len(t, staged.Entries, 3)
	assert.Empty(t, acceptedPayload(staged))
	for index, entry := range f.entries {
		assert.Equal(t, entry.Path, staged.Entries[index].Path)
		assert.Equal(t, entry.Mode, staged.Entries[index].Mode)
		assert.Equal(t, entry.Content, staged.Entries[index].Content)
	}

	upload := beginFileSetUpload(t, store, attempt, view, review)
	assert.Empty(t, uploadPayload(upload))
	assert.Empty(t, testUploadBlob(upload).CID)
	require.Len(t, upload.Entries, 3)
	for index, entry := range f.entries {
		cid, err := publication.RawPayloadCID(entry.Content)
		require.NoError(t, err)
		assert.Equal(t, entry.Path, upload.Entries[index].Path)
		assert.Equal(t, cid, upload.Entries[index].Blob.CID)
		assert.Equal(t, uint64(len(entry.Content)), upload.Entries[index].Blob.Size)
		assert.Equal(t, entry.Content, upload.Entries[index].Payload)
	}
	uploaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, uploaded.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, uploaded.Outcome)

	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	submission, err := store.BeginFileSetSubmission(
		ctx,
		attempt.ID,
		submissionProposal.StateToken,
		view,
		review,
		submissionProposal.Confirmation,
		f.references(),
	)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormFileSet, submission.PayloadForm)
	assert.Equal(t, f.references(), submission.Entries)
	assert.Equal(t, f.raw, submission.SnapshotRecord)
	assert.Equal(t, f.head, submission.HeadRecord)
	assert.True(t, submission.RequiresAtomicBatch)
	assert.True(t, submission.SnapshotCreateOnly)
	submitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, submitted.Lifecycle)
	assert.Equal(t, OutcomeUnresolved, submitted.Outcome)

	resolution, err := store.ResolveAttempt(ctx, attempt.ID, submitted.StateDigest, view)
	require.NoError(t, err)
	assert.Equal(t, OutcomeAbsentUnresolved, resolution.Outcome)
	readBack, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	require.Len(t, readBack.Entries, 3)
	for index, entry := range f.entries {
		assert.Equal(t, entry.Path, readBack.Entries[index].Path)
		assert.Equal(t, entry.Content, readBack.Entries[index].Content)
	}

	extended := f.view()
	extended.Head = bytes.Clone(f.head)
	extended.Snapshots = []SnapshotBlock{{Key: f.key, Raw: bytes.Clone(f.raw)}}
	current, err := store.ResolveAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, extended)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, current.Outcome)
	assert.Equal(t, f.key, current.Attempt.SnapshotKey)
	require.NotEmpty(t, current.Evidence)
}

func TestPackedAttemptMaterialsKeepTheSinglePackedPayload(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	candidateCID, err := publication.RawPayloadCID(acceptedPayload(candidate))
	require.NoError(t, err)
	assert.Equal(t, candidateCID, proposal.CandidateSegments[0].BlobCID)
	assert.Equal(t, uint64(len(acceptedPayload(candidate))), proposal.CandidateSegments[0].BlobSize)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Nil(t, testFileSet(attempt))

	upload := beginFileSetPackedUpload(t, store, attempt, empty, review)
	assert.Empty(t, upload.Entries)
	assert.Equal(t, acceptedPayload(candidate), uploadPayload(upload))
	assert.NotEmpty(t, testUploadBlob(upload).CID)

	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	submission, err := store.BeginSubmission(
		ctx,
		attempt.ID,
		submissionProposal.StateToken,
		empty,
		review,
		submissionProposal.Confirmation,
	)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormPacked, submission.PayloadForm)
	assert.Empty(t, acceptedEntries(submission))
}

func beginFileSetPackedUpload(
	t *testing.T,
	store *Store,
	attempt Attempt,
	view SuppliedRepositoryView,
	review LocalReviewContext,
) UploadMaterial {
	t.Helper()
	proposal, err := store.PrepareDispatch(context.Background(), attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	material, err := store.BeginUpload(
		context.Background(),
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	return material
}

func TestFileSetSubmissionRefusesAnIncompleteUploadedEntryList(t *testing.T) {
	ctx := context.Background()
	f := fileSetFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageFileSetAttempt(t, store, f, view, review)
	beginFileSetUpload(t, store, attempt, view, review)

	references := f.references()
	partial := [][]PayloadEntryReference{
		references[:2],
		references[1:],
		{references[0], references[2], references[1]},
		{{}, references[1], references[2]},
		append(append([]PayloadEntryReference{}, references...), PayloadEntryReference{
			Path: "extra.lua", CID: references[0].CID, Size: references[0].Size,
		}),
		{},
	}
	for index, uploaded := range partial {
		proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
		require.NoError(t, err)
		_, err = store.BeginFileSetSubmission(
			ctx,
			attempt.ID,
			proposal.StateToken,
			view,
			review,
			proposal.Confirmation,
			uploaded,
		)
		requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonUploadIncomplete)
		blocked, err := store.LoadAttempt(ctx, attempt.ID)
		require.NoError(t, err, index)
		assert.Equal(t, AttemptUploadStarted, blocked.Lifecycle, index)
		assert.Equal(t, OutcomeNotSubmitted, blocked.Outcome, index)
		assert.Empty(t, blocked.Blocked, index)
	}
	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, attempt.ID, active.ID)

	proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(
		ctx,
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
	)
	requireErrorMetadata(t, err, ErrUnsupported, StageDispatch, ReasonPayloadForm)

	submitted, err := store.BeginFileSetSubmission(
		ctx,
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
		references,
	)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormFileSet, submitted.PayloadForm)
	after, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, after.Lifecycle)
}

func TestFileSetAttemptRejectionRetiresAfterSuccessfulUploads(t *testing.T) {
	ctx := context.Background()
	f := fileSetFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageFileSetAttempt(t, store, f, view, review)
	beginFileSetUpload(t, store, attempt, view, review)
	proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginFileSetSubmission(
		ctx,
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
		f.references(),
	)
	require.NoError(t, err)
	submitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	rejected, err := store.RejectAttempt(ctx, attempt.ID, submitted.StateDigest)
	require.NoError(t, err)
	assert.Equal(t, OutcomeRejected, rejected.Outcome)
	assert.Equal(t, AttemptRetiredAbandoned, rejected.Lifecycle)
	_, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	var retained int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retained))
	assert.Equal(t, 0, retained)
}

func TestFileSetAttemptMidUploadFailureStaysBlockingAndAbandonable(t *testing.T) {
	ctx := context.Background()
	f := fileSetFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageFileSetAttempt(t, store, f, view, review)
	upload := beginFileSetUpload(t, store, attempt, view, review)
	require.Len(t, upload.Entries, 3)

	failed, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, failed.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, failed.Outcome)
	_, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)

	proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginFileSetSubmission(
		ctx,
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
		f.references()[:1],
	)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonUploadIncomplete)

	abandonProposal, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	abandoned, err := store.AbandonAttempt(
		ctx,
		attempt.ID,
		abandonProposal.StateToken,
		nil,
		abandonProposal.Confirmation,
	)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, abandoned.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, abandoned.Outcome)
	_, present, err = store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, present)
}

func TestFileSetCustodyRefusesAStoredObjectThatContradictsItsEntry(t *testing.T) {
	ctx := context.Background()
	f := fileSetFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageFileSetAttempt(t, store, f, view, review)

	target := f.entries[1]
	path := filepath.Join(directory, payloadDirectoryName, payloadBasename(target.Content))
	original := bytes.Clone(target.Content)
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(original)), 0o600))
	_, err := store.ReadCandidate(ctx, attempt.ID)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateCorrupt)
	require.NoError(t, os.WriteFile(path, original, 0o600))

	require.NoError(t, os.Truncate(path, int64(len(original))-1))
	_, err = store.ReadCandidate(ctx, attempt.ID)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateUnsafe)
	require.NoError(t, os.WriteFile(path, original, 0o600))

	cid, err := publication.RawPayloadCID(original)
	require.NoError(t, err)
	name := payloadBasename(original)
	require.NoError(t, validateFileSetEntryForCustody(original, publication.BlobReference{
		CID: cid, Size: uint64(len(original)), MIMEType: publication.BlobMIMEType,
	}, name))
	require.ErrorIs(t, validateFileSetEntryForCustody(original, publication.BlobReference{
		CID: f.entries[0].Content, Size: uint64(len(original)),
	}, name), errInvalidPayloadInput)
	require.ErrorIs(t, validateFileSetEntryForCustody(original, publication.BlobReference{
		CID: cid, Size: uint64(len(original)) + 1,
	}, name), errInvalidPayloadInput)

	readBack, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	require.Len(t, readBack.Entries, 3)
	for index, entry := range f.entries {
		assert.Equal(t, entry.Content, readBack.Entries[index].Content)
	}
}

func TestFileSetEntryCustodyProofKeepsThePackedDecode(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	cid, err := publication.RawPayloadCID(f.payload)
	require.NoError(t, err)
	blob := publication.BlobReference{
		CID: cid, Size: uint64(len(f.payload)), MIMEType: publication.SnapshotBlobMIMEType,
	}
	require.NoError(t, validatePayloadForCustody(f.payload, blob, payloadBasename(f.payload)))
	require.NoError(t, validateFileSetEntryForCustody(f.payload, blob, payloadBasename(f.payload)))

	plain := []byte("synthetic plain entry")
	plainCID, err := publication.RawPayloadCID(plain)
	require.NoError(t, err)
	plainBlob := publication.BlobReference{
		CID: plainCID, Size: uint64(len(plain)), MIMEType: publication.BlobMIMEType,
	}
	require.NoError(t, validateFileSetEntryForCustody(plain, plainBlob, payloadBasename(plain)))
	require.ErrorIs(
		t,
		validatePayloadForCustody(plain, plainBlob, payloadBasename(plain)),
		errInvalidPayloadInput,
	)
}

func TestFileSetAttemptFinalizesAndReopensRetainedPosition(t *testing.T) {
	ctx := context.Background()
	f := fileSetFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	review := attemptReview()
	submitted := submitFileSetAttempt(t, store, f, f.view(), review)
	finalized, err := store.FinalizeAttempt(ctx, submitted.ID, submitted.StateDigest, f.currentView())
	require.NoError(t, err)
	assertFileSetRetainedPosition(t, store, f, directory, submitted.ID, finalized.Floor)

	reopened := reopenFileSetStore(t, store, directory, f.binding)
	loaded, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, finalized.Floor, loaded)
	state, err := reopened.readState(ctx, reopened.conn, StageLoad)
	require.NoError(t, err)
	require.NotNil(t, state.floor)
	assert.Equal(t, finalized.Floor, *state.floor)
}

func TestLargeFileSetAttemptFinalizesWithEncodedFloorUnderTheCap(t *testing.T) {
	ctx := context.Background()
	f := newLargeFileSetFixture(t)
	require.Greater(t, len(f.raw), publication.MaxRecordBytes)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	review := attemptReview()
	submitted := submitFileSetAttempt(t, store, f, f.view(), review)
	finalized, err := store.FinalizeAttempt(ctx, submitted.ID, submitted.StateDigest, f.currentView())
	require.NoError(t, err)
	encodedFloor, err := encodeFloor(finalized.Floor)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(encodedFloor), 65536)
	assertFileSetRetainedPosition(t, store, f, directory, submitted.ID, finalized.Floor)

	reopened := reopenFileSetStore(t, store, directory, f.binding)
	loaded, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, finalized.Floor, loaded)
}

func submitFileSetAttempt(
	t *testing.T,
	store *Store,
	f fileSetAttemptFixture,
	view SuppliedRepositoryView,
	review LocalReviewContext,
) Attempt {
	t.Helper()
	ctx := context.Background()
	attempt := stageFileSetAttempt(t, store, f, view, review)
	beginFileSetUpload(t, store, attempt, view, review)
	proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginFileSetSubmission(
		ctx,
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
		f.references(),
	)
	require.NoError(t, err)
	submitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	require.Equal(t, AttemptMayHaveSubmitted, submitted.Lifecycle)
	return submitted
}

func assertFileSetRetainedPosition(
	t *testing.T,
	store *Store,
	f fileSetAttemptFixture,
	directory string,
	id [16]byte,
	floor Floor,
) {
	t.Helper()
	ctx := context.Background()
	attempt, err := store.LoadAttempt(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, attempt.Lifecycle)
	assert.Equal(t, OutcomeCurrent, attempt.Outcome)
	require.NotNil(t, testFileSet(attempt))
	assert.Equal(t, f.references(), fileSetEntries(attempt))
	assert.Empty(t, testBlobCID(attempt))
	assert.Equal(t, uint64(0), testBlobSize(attempt))

	assert.Equal(t, f.key, floor.SnapshotKey)
	require.NotNil(t, testFileSet(floor))
	assert.Equal(t, f.references(), fileSetEntries(floor))
	assert.Empty(t, testBlobCID(floor))
	assert.Equal(t, uint64(0), testBlobSize(floor))

	var segmentsValue any
	require.NoError(t, store.conn.QueryRowContext(
		ctx,
		"SELECT segments FROM retained_publications WHERE attempt_id=?",
		id[:],
	).Scan(&segmentsValue))
	encodedSegments, segmentsOK := segmentsValue.([]byte)
	require.True(t, segmentsOK)
	retainedSegments, err := decodeSegmentSummaries(encodedSegments)
	require.NoError(t, err)
	assert.Equal(t, summariesOfRecord(f.recordSegments()), retainedSegments)
	assert.Equal(t, f.references(), fileSetEntries(retainedSegments))

	for _, query := range []string{
		"SELECT COUNT(*) FROM accepted_material_refs",
		"SELECT COUNT(*) FROM active_publication_attempt",
		"SELECT COUNT(*) FROM pending_genesis",
	} {
		var count int
		require.NoError(t, store.conn.QueryRowContext(ctx, query).Scan(&count))
		assert.Equal(t, 0, count, query)
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?",
		"SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?",
	} {
		var count int
		require.NoError(t, store.conn.QueryRowContext(ctx, query, id[:]).Scan(&count))
		assert.Equal(t, 0, count, query)
	}
	var objects int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	assert.Equal(t, len(f.entries), objects)
	for _, entry := range f.entries {
		_, err := os.Stat(filepath.Join(directory, payloadDirectoryName, payloadBasename(entry.Content)))
		assert.NoError(t, err)
	}
	_, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, present)
}

func reopenFileSetStore(t *testing.T, store *Store, directory string, binding Binding) *Store {
	t.Helper()
	require.NoError(t, store.Close())
	reopened, err := Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	return reopened
}

func TestFileSetAttemptFinalizationAdmissionBudgetsTheFileSetFloor(t *testing.T) {
	ctx := context.Background()
	f := newLargeFileSetFixture(t)
	candidate := f.candidate()
	view := f.view()
	review := attemptReview()

	baseline, _ := newStore(t, fixture{t: t, binding: f.binding})
	unmodeled := finalizationHistoryBound(t, baseline, candidate, view, review, false)
	submitted := submitFileSetAttempt(t, baseline, f, view, review)
	_, err := baseline.FinalizeAttempt(ctx, submitted.ID, submitted.StateDigest, f.currentView())
	require.NoError(t, err)
	modeled := fileSetCompletionHistoryBytes(t, baseline, f)
	require.Greater(t, modeled, unmodeled)
	require.NoError(t, baseline.Close())

	underLimits := DefaultLimits()
	underLimits.HistoryEvidenceBytes = modeled - 1
	under, underDirectory := openAttemptStoreWithLimits(t, fixture{t: t, binding: f.binding}, underLimits)
	_, err = under.PrepareAttempt(ctx, candidate, view, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assertNoAttemptCustodyMutation(t, under, underDirectory)
	require.NoError(t, under.Close())

	exactLimits := DefaultLimits()
	exactLimits.HistoryEvidenceBytes = modeled
	exact, exactDirectory := openAttemptStoreWithLimits(t, fixture{t: t, binding: f.binding}, exactLimits)
	exactSubmitted := submitFileSetAttempt(t, exact, f, view, review)
	finalized, err := exact.FinalizeAttempt(
		ctx,
		exactSubmitted.ID,
		exactSubmitted.StateDigest,
		f.currentView(),
	)
	require.NoError(t, err)
	assertFileSetRetainedPosition(t, exact, f, exactDirectory, exactSubmitted.ID, finalized.Floor)
	require.NoError(t, exact.Close())

	reopened, err := OpenWithLimits(exactDirectory, f.binding, exactLimits)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	loaded, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, finalized.Floor, loaded)
}

func fileSetCompletionHistoryBytes(t *testing.T, store *Store, f fileSetAttemptFixture) uint64 {
	t.Helper()
	var bodyValue any
	require.NoError(t,
		store.conn.QueryRowContext(context.Background(), "SELECT body FROM accepted_events WHERE revision=1").
			Scan(&bodyValue))
	body, bodyOK := rawBytes(bodyValue)
	require.True(t, bodyOK)
	recordCID, err := publication.RecordCID(f.raw)
	require.NoError(t, err)
	limits := DefaultLimits()
	encodedContext, err := canonicalJSON(contextToWire(f.view().SuppliedContext))
	require.NoError(t, err)
	require.LessOrEqual(t, len(encodedContext), int(limits.SuppliedContextBytes))
	record := validatedRecord{
		ref: RecordReference{Key: f.key, CID: recordCID, Sequence: 0},
		raw: f.raw,
	}
	return uint64(len(body)+32+8) + recordLogicalBytes(record) +
		uint64(limits.SuppliedContextBytes) - uint64(len(encodedContext))
}

func TestOversizedFileSetAttemptRefusesFinalizationAdmission(t *testing.T) {
	ctx := context.Background()
	f := newFileSetAttemptFixture(t, oversizedFloorFileSetPaths())
	require.Greater(t, len(f.raw), publication.MaxRecordBytes)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	_, err := store.PrepareAttempt(ctx, f.candidate(), f.view(), attemptReview())
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assertNoAttemptCustodyMutation(t, store, directory)
	require.NoError(t, store.Close())
}

func TestAcceptedFloorRefusesOversizedEncodedFileSetFloor(t *testing.T) {
	ctx := context.Background()
	f := newFileSetAttemptFixture(t, oversizedFloorFileSetPaths())
	require.Greater(t, len(f.raw), publication.MaxRecordBytes)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	state, err := store.readState(ctx, store.conn, StageFinalize)
	require.NoError(t, err)
	require.Nil(t, state.floor)
	view, err := validateSuppliedRepositoryView(f.currentView(), store.binding, store.limits, false)
	require.NoError(t, err)
	validated, err := validateFinalizationObservation(repositoryViewToObservation(view), store.binding, store.limits)
	require.NoError(t, err)
	trace, err := store.resolveTrace(ctx, store.conn, validated, state.floor, StageFinalize)
	require.NoError(t, err)
	prospective := buildFloor(store.databaseID, store.binding, validated, state, trace, ModeFirstUse)
	encodedFloor, err := encodeFloor(prospective)
	require.NoError(t, err)
	require.Greater(t, len(encodedFloor), 65536)

	tx, err := store.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = store.acceptFloorTx(ctx, tx, ModeFirstUse, state, validated, trace, StageFinalize, nil)
	requireErrorMetadata(t, err, ErrLimit, StageFinalize, ReasonCapacity)
	require.NoError(t, tx.Rollback())
	assertEmptyPublicationFloorState(t, store)

	reopened := reopenFileSetStore(t, store, directory, f.binding)
	loaded, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, zeroFloor(), loaded)
	assertEmptyPublicationFloorState(t, reopened)
}

func assertEmptyPublicationFloorState(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	for _, table := range []string{"accepted_records", "accepted_events", "active_floor", "retained_publications"} {
		var count int
		require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count))
		assert.Equal(t, 0, count, table)
	}
	state, err := store.readState(ctx, store.conn, StageLoad)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), state.revision)
	assert.Equal(t, uint64(0), state.generation)
	assert.Nil(t, state.floor)
}

func TestFileSetCandidateRefusesEntriesThatContradictTheRecord(t *testing.T) {
	f := fileSetFixture(t)
	binding := f.binding
	limits := DefaultAttemptLimits()

	candidate := f.candidate()
	_, err := validateCandidateInput(candidate, binding, limits)
	require.NoError(t, err)

	wrongContent := f.candidate()
	wrongContent.Entries[1].Content = []byte("contradicts the record")
	_, err = validateCandidateInput(wrongContent, binding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	missingContent := f.candidate()
	missingContent.Entries = missingContent.Entries[:2]
	_, err = validateCandidateInput(missingContent, binding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	extraContent := f.candidate()
	extraContent.Entries = append(extraContent.Entries, extraContent.Entries[0])
	_, err = validateCandidateInput(extraContent, binding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	packedMaterial := f.candidate()
	packedMaterial.Payloads[0] = []byte("packed payload supplied for a file-set record")
	_, err = validateCandidateInput(packedMaterial, binding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	missingSegments := f.candidate()
	missingSegments.Segments = nil
	missingSegments.Payloads = nil
	_, err = validateCandidateInput(missingSegments, binding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	missingSegmentOnly := f.candidate()
	missingSegmentOnly.Segments = nil
	_, err = validateCandidateInput(missingSegmentOnly, binding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	tightened := limits
	tightened.ManagedObjects = 2
	_, err = validateCandidateInput(f.candidate(), binding, tightened)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
	assert.Contains(t, err.Error(), "file-set managed objects: 3 exceeds 2")
}

func TestFileSetEntryCapacityRefusesTheSixtyFifthEntryNamingTheLimit(t *testing.T) {
	limits := DefaultAttemptLimits()
	entries := make([]PayloadEntryReference, 0, publication.MaxSnapshotEntries+1)
	for index := range publication.MaxSnapshotEntries + 1 {
		entries = append(entries, PayloadEntryReference{
			Path: "entry.lua" + string(rune('a'+index%26)) + string(rune('a'+index/26)),
			CID:  []byte{byte(index + 1)},
			Size: 1,
		})
	}
	err := validateFileSetPayloadCustody(&FileSetPayload{Entries: entries}, limits)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
	assert.Contains(t, err.Error(), "file-set entry count: 65 exceeds 64")
	assert.Equal(t, uint32(64), limits.ManagedObjects)
}
