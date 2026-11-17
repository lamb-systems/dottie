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

type showcaseAttemptFixture struct {
	binding Binding
	raw     []byte
	head    []byte
	key     string
	entries []publication.PayloadEntry
}

func newShowcaseAttemptFixture(t *testing.T, paths []string) showcaseAttemptFixture {
	t.Helper()
	entries := make([]publication.SnapshotEntry, 0, len(paths))
	supplied := make([]publication.PayloadEntry, 0, len(paths))
	for _, path := range paths {
		content := []byte("synthetic showcase entry for " + path)
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
		Entries:        entries,
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
	return showcaseAttemptFixture{
		binding: binding,
		raw:     raw,
		head:    head,
		key:     key,
		entries: supplied,
	}
}

func (f showcaseAttemptFixture) view() SuppliedRepositoryView {
	return SuppliedRepositoryView{
		Origin:          f.binding,
		Scope:           ViewScopeWholeRepository,
		SuppliedContext: SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}},
	}
}

func (f showcaseAttemptFixture) candidate() CandidateInput {
	entries := make([]publication.PayloadEntry, 0, len(f.entries))
	for _, entry := range f.entries {
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: bytes.Clone(entry.Content),
		})
	}
	return CandidateInput{
		SnapshotKey:    f.key,
		SnapshotRecord: bytes.Clone(f.raw),
		HeadRecord:     bytes.Clone(f.head),
		Entries:        entries,
	}
}

func (f showcaseAttemptFixture) references() []PayloadEntryReference {
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

func showcaseFixture(t *testing.T) showcaseAttemptFixture {
	return newShowcaseAttemptFixture(t, []string{"init.lua", "lua/config/options.lua", "lua/plugin/init.lua"})
}

func stageShowcaseAttempt(
	t *testing.T,
	store *Store,
	f showcaseAttemptFixture,
	view SuppliedRepositoryView,
	review LocalReviewContext,
) Attempt {
	t.Helper()
	candidate := f.candidate()
	proposal, err := store.PrepareAttempt(context.Background(), candidate, view, review)
	require.NoError(t, err)
	assert.Equal(t, AttemptGenesis, proposal.Kind)
	assert.Nil(t, proposal.CandidateBlobCID)
	assert.Equal(t, uint64(0), proposal.CandidateBlobSize)
	attempt, err := store.CreateAttempt(
		context.Background(),
		proposal.StateToken,
		candidate,
		view,
		review,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	require.NotNil(t, attempt.Showcase)
	assert.Nil(t, attempt.BlobCID)
	assert.Equal(t, uint64(0), attempt.BlobSize)
	return attempt
}

func beginShowcaseUpload(
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

func TestShowcaseAttemptStagesUploadsSubmitsAndReadsBack(t *testing.T) {
	ctx := context.Background()
	f := showcaseFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageShowcaseAttempt(t, store, f, view, review)
	require.Len(t, attempt.Showcase.Entries, 3)

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
	assert.Empty(t, staged.Payload)
	for index, entry := range f.entries {
		assert.Equal(t, entry.Path, staged.Entries[index].Path)
		assert.Equal(t, entry.Mode, staged.Entries[index].Mode)
		assert.Equal(t, entry.Content, staged.Entries[index].Content)
	}

	upload := beginShowcaseUpload(t, store, attempt, view, review)
	assert.Empty(t, upload.Payload)
	assert.Empty(t, upload.Blob.CID)
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
	submission, err := store.BeginShowcaseSubmission(
		ctx,
		attempt.ID,
		submissionProposal.StateToken,
		view,
		review,
		submissionProposal.Confirmation,
		f.references(),
	)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormShowcase, submission.PayloadForm)
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
	candidateCID, err := publication.RawPayloadCID(candidate.Payload)
	require.NoError(t, err)
	assert.Equal(t, candidateCID, proposal.CandidateBlobCID)
	assert.Equal(t, uint64(len(candidate.Payload)), proposal.CandidateBlobSize)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Nil(t, attempt.Showcase)

	upload := beginShowcasePackedUpload(t, store, attempt, empty, review)
	assert.Empty(t, upload.Entries)
	assert.Equal(t, candidate.Payload, upload.Payload)
	assert.NotEmpty(t, upload.Blob.CID)

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
	assert.Empty(t, submission.Entries)
}

func beginShowcasePackedUpload(
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

func TestShowcaseSubmissionRefusesAnIncompleteUploadedEntryList(t *testing.T) {
	ctx := context.Background()
	f := showcaseFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageShowcaseAttempt(t, store, f, view, review)
	beginShowcaseUpload(t, store, attempt, view, review)

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
		_, err = store.BeginShowcaseSubmission(
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

	submitted, err := store.BeginShowcaseSubmission(
		ctx,
		attempt.ID,
		proposal.StateToken,
		view,
		review,
		proposal.Confirmation,
		references,
	)
	require.NoError(t, err)
	assert.Equal(t, PayloadFormShowcase, submitted.PayloadForm)
	after, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, after.Lifecycle)
}

func TestShowcaseAttemptRejectionRetiresAfterSuccessfulUploads(t *testing.T) {
	ctx := context.Background()
	f := showcaseFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageShowcaseAttempt(t, store, f, view, review)
	beginShowcaseUpload(t, store, attempt, view, review)
	proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginShowcaseSubmission(
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

func TestShowcaseAttemptMidUploadFailureStaysBlockingAndAbandonable(t *testing.T) {
	ctx := context.Background()
	f := showcaseFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageShowcaseAttempt(t, store, f, view, review)
	upload := beginShowcaseUpload(t, store, attempt, view, review)
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
	_, err = store.BeginShowcaseSubmission(
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

func TestShowcaseCustodyRefusesAStoredObjectThatContradictsItsEntry(t *testing.T) {
	ctx := context.Background()
	f := showcaseFixture(t)
	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageShowcaseAttempt(t, store, f, view, review)

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
	require.NoError(t, validateShowcaseEntryForCustody(original, publication.BlobReference{
		CID: cid, Size: uint64(len(original)), MIMEType: publication.BlobMIMEType,
	}, name))
	require.ErrorIs(t, validateShowcaseEntryForCustody(original, publication.BlobReference{
		CID: f.entries[0].Content, Size: uint64(len(original)),
	}, name), errInvalidPayloadInput)
	require.ErrorIs(t, validateShowcaseEntryForCustody(original, publication.BlobReference{
		CID: cid, Size: uint64(len(original)) + 1,
	}, name), errInvalidPayloadInput)

	readBack, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	require.Len(t, readBack.Entries, 3)
	for index, entry := range f.entries {
		assert.Equal(t, entry.Content, readBack.Entries[index].Content)
	}
}

func TestShowcaseEntryCustodyProofKeepsThePackedDecode(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	cid, err := publication.RawPayloadCID(f.payload)
	require.NoError(t, err)
	blob := publication.BlobReference{
		CID: cid, Size: uint64(len(f.payload)), MIMEType: publication.SnapshotBlobMIMEType,
	}
	require.NoError(t, validatePayloadForCustody(f.payload, blob, payloadBasename(f.payload)))
	require.NoError(t, validateShowcaseEntryForCustody(f.payload, blob, payloadBasename(f.payload)))

	plain := []byte("synthetic plain entry")
	plainCID, err := publication.RawPayloadCID(plain)
	require.NoError(t, err)
	plainBlob := publication.BlobReference{
		CID: plainCID, Size: uint64(len(plain)), MIMEType: publication.BlobMIMEType,
	}
	require.NoError(t, validateShowcaseEntryForCustody(plain, plainBlob, payloadBasename(plain)))
	require.ErrorIs(
		t,
		validatePayloadForCustody(plain, plainBlob, payloadBasename(plain)),
		errInvalidPayloadInput,
	)
}

func TestShowcaseAttemptRefusesFinalizationOfTheSingleBlobFloor(t *testing.T) {
	ctx := context.Background()
	f := showcaseFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	defer store.Close()
	view := f.view()
	review := attemptReview()
	attempt := stageShowcaseAttempt(t, store, f, view, review)
	beginShowcaseUpload(t, store, attempt, view, review)
	proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = store.BeginShowcaseSubmission(
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
	_, err = store.FinalizeAttempt(ctx, attempt.ID, submitted.StateDigest, view)
	requireErrorMetadata(t, err, ErrUnsupported, StageFinalize, ReasonPayloadForm)
	var retained int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retained))
	assert.Equal(t, 0, retained)
	_, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.True(t, present)
}

func TestShowcaseCandidateRefusesEntriesThatContradictTheRecord(t *testing.T) {
	f := showcaseFixture(t)
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
	packedMaterial.Payload = []byte("packed payload supplied for a showcase record")
	_, err = validateCandidateInput(packedMaterial, binding, limits)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	tightened := limits
	tightened.ManagedObjects = 2
	_, err = validateCandidateInput(f.candidate(), binding, tightened)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
	assert.Contains(t, err.Error(), "showcase managed objects: 3 exceeds 2")
}

func TestShowcaseEntryCapacityRefusesTheSixtyFifthEntryNamingTheLimit(t *testing.T) {
	limits := DefaultAttemptLimits()
	entries := make([]PayloadEntryReference, 0, publication.MaxSnapshotEntries+1)
	for index := range publication.MaxSnapshotEntries + 1 {
		entries = append(entries, PayloadEntryReference{
			Path: "entry.lua" + string(rune('a'+index%26)) + string(rune('a'+index/26)),
			CID:  []byte{byte(index + 1)},
			Size: 1,
		})
	}
	err := validateShowcasePayloadCustody(&ShowcasePayload{Entries: entries}, limits)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
	assert.Contains(t, err.Error(), "showcase entry count: 65 exceeds 64")
	assert.Equal(t, uint32(64), limits.ManagedObjects)
}
