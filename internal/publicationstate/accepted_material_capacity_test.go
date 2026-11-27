package publicationstate

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/lamb-systems/dottie/internal/publication"
)

func TestPublicationReadAcceptedMaterialRemainsReadableAtManagedObjectCapacity(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	baseCandidate := attemptCandidate(f, 0)
	successorPayload := packFixtureContent(
		t,
		acceptedPayload(baseCandidate),
		[]byte("synthetic successor with independent packed content"),
	)
	successorCandidate := candidateWithPayload(t, attemptCandidate(f, 1), f.binding, successorPayload)
	assertAcceptedMaterialCapacitySuccessor(t, f, baseCandidate, successorCandidate)
	successorWitness := cloneAcceptedMaterialCapacityCandidate(successorCandidate)
	lowSuccessorCandidate := cloneAcceptedMaterialCapacityCandidate(successorWitness)
	positiveSuccessorCandidate := cloneAcceptedMaterialCapacityCandidate(successorWitness)
	require.Equal(t, lowSuccessorCandidate, positiveSuccessorCandidate)
	defaultCustodyBytes := DefaultAttemptLimits().CustodyBytes
	require.LessOrEqual(t, uint64(len(acceptedPayload(baseCandidate))), defaultCustodyBytes)
	require.LessOrEqual(t, uint64(len(acceptedPayload(successorCandidate))), defaultCustodyBytes)
	require.LessOrEqual(t, uint64(len(acceptedPayload(baseCandidate))+len(acceptedPayload(successorCandidate))), defaultCustodyBytes)

	lowOptions := DefaultOpenOptions()
	lowAttemptLimits := DefaultAttemptLimits()
	lowAttemptLimits.ManagedObjects = 1
	lowOptions.AttemptLimits = lowAttemptLimits
	require.Equal(t, DefaultLimits(), lowOptions.PositionLimits)
	require.Equal(t, lowAttemptLimits, lowOptions.AttemptLimits)
	require.Equal(t, uint32(1), lowOptions.AttemptLimits.ManagedObjects)
	require.Equal(t, DefaultAttemptLimits().CustodyBytes, lowOptions.AttemptLimits.CustodyBytes)
	lowDirectory := t.TempDir()
	require.NoError(t, os.Chmod(lowDirectory, 0o700))
	lowStore, err := OpenWithOptions(lowDirectory, f.binding, lowOptions)
	require.NoError(t, err)
	defer lowStore.Close()

	lowAttempt, lowFinalized := acceptedMaterialRevisionFinalizeGenesis(t, lowStore, f, baseCandidate)
	lowFloor := cloneFloor(lowFinalized.Floor)
	require.Equal(t, uint64(0), lowFloor.Sequence)
	require.Equal(t, mustRecordCID(t, baseCandidate.SnapshotRecord), lowFloor.RecordCID)
	require.Equal(t, lowFloor.RecordCID, mustSuccessorParent(t, successorCandidate))
	lowPredecessorView := attemptView(f, f.observation(1), false)
	lowReview := attemptReview()
	lowMaterial, err := lowStore.ReadAcceptedMaterial(ctx, f.binding, lowFloor)
	require.NoError(t, err)
	require.Equal(t, lowFloor, lowMaterial.Floor)
	require.Equal(t, baseCandidate.SnapshotRecord, lowMaterial.SnapshotRecord)
	require.Equal(t, acceptedPayload(baseCandidate), acceptedPayload(lowMaterial))
	lowBefore := readAcceptedMaterialCapacityEvidence(
		t,
		lowStore,
		lowDirectory,
		lowAttempt.ID,
		lowFloor,
		baseCandidate,
		lowAttemptLimits,
	)
	require.Equal(t, int64(1), lowBefore.CatalogCount)
	require.Equal(t, int64(len(acceptedPayload(baseCandidate))), lowBefore.CatalogBytes)
	require.Equal(t, int64(1), lowBefore.RetainedReferences)
	require.Zero(t, lowBefore.AttemptReferences)
	require.Zero(t, lowBefore.ActiveAttempts)
	require.Equal(t, []string{payloadBasename(acceptedPayload(baseCandidate))}, lowBefore.FileNames)

	proposal, err := lowStore.PrepareAttempt(ctx, lowSuccessorCandidate, lowPredecessorView, lowReview)
	assert.Equal(t, AttemptProposal{}, proposal)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	require.Equal(t, successorWitness, lowSuccessorCandidate)
	lowAfterRefusal := readAcceptedMaterialCapacityEvidence(
		t,
		lowStore,
		lowDirectory,
		lowAttempt.ID,
		lowFloor,
		baseCandidate,
		lowAttemptLimits,
	)
	assert.Equal(t, lowBefore, lowAfterRefusal)
	assert.Equal(t, lowBefore.LogicalRows, readAttemptLogicalRows(t, lowStore))

	lowMaterialAfterRefusal, err := lowStore.ReadAcceptedMaterial(ctx, f.binding, lowFloor)
	require.NoError(t, err)
	require.Equal(t, lowFloor, lowMaterialAfterRefusal.Floor)
	require.Equal(t, baseCandidate.SnapshotRecord, lowMaterialAfterRefusal.SnapshotRecord)
	require.Equal(t, acceptedPayload(baseCandidate), acceptedPayload(lowMaterialAfterRefusal))
	lowAfterRead := readAcceptedMaterialCapacityEvidence(
		t,
		lowStore,
		lowDirectory,
		lowAttempt.ID,
		lowFloor,
		baseCandidate,
		lowAttemptLimits,
	)
	assert.Equal(t, lowBefore, lowAfterRead)
	assert.Equal(t, lowBefore.LogicalRows, readAttemptLogicalRows(t, lowStore))

	require.NoError(t, lowStore.Close())
	reopened, err := OpenWithOptions(lowDirectory, f.binding, lowOptions)
	require.NoError(t, err)
	defer reopened.Close()
	reopenedMaterial, err := reopened.ReadAcceptedMaterial(ctx, f.binding, lowFloor)
	require.NoError(t, err)
	require.Equal(t, lowFloor, reopenedMaterial.Floor)
	require.Equal(t, baseCandidate.SnapshotRecord, reopenedMaterial.SnapshotRecord)
	require.Equal(t, acceptedPayload(baseCandidate), acceptedPayload(reopenedMaterial))
	lowAfterReopen := readAcceptedMaterialCapacityEvidence(
		t,
		reopened,
		lowDirectory,
		lowAttempt.ID,
		lowFloor,
		baseCandidate,
		lowAttemptLimits,
	)
	assert.Equal(t, lowBefore, lowAfterReopen)
	assert.Equal(t, lowBefore.LogicalRows, readAttemptLogicalRows(t, reopened))
	require.Equal(t, successorWitness, lowSuccessorCandidate)
	require.Equal(t, lowSuccessorCandidate, positiveSuccessorCandidate)

	positiveOptions := DefaultOpenOptions()
	positiveAttemptLimits := DefaultAttemptLimits()
	positiveAttemptLimits.ManagedObjects = 2
	positiveOptions.AttemptLimits = positiveAttemptLimits
	require.Equal(t, DefaultLimits(), positiveOptions.PositionLimits)
	require.Equal(t, positiveAttemptLimits, positiveOptions.AttemptLimits)
	require.Equal(t, uint32(2), positiveOptions.AttemptLimits.ManagedObjects)
	require.Equal(t, DefaultAttemptLimits().CustodyBytes, positiveOptions.AttemptLimits.CustodyBytes)
	positiveDirectory := t.TempDir()
	require.NoError(t, os.Chmod(positiveDirectory, 0o700))
	positiveStore, err := OpenWithOptions(positiveDirectory, f.binding, positiveOptions)
	require.NoError(t, err)
	defer positiveStore.Close()

	positiveBaseAttempt, positiveFinalized := acceptedMaterialRevisionFinalizeGenesis(
		t,
		positiveStore,
		f,
		baseCandidate,
	)
	positiveFloor := cloneFloor(positiveFinalized.Floor)
	require.Equal(t, uint64(0), positiveFloor.Sequence)
	require.Equal(t, mustRecordCID(t, baseCandidate.SnapshotRecord), positiveFloor.RecordCID)
	require.Equal(t, positiveFloor.RecordCID, mustSuccessorParent(t, successorCandidate))
	require.NotEqual(t, lowFloor.DatabaseID, positiveFloor.DatabaseID)
	require.Equal(t, successorWitness, positiveSuccessorCandidate)
	require.Equal(t, lowSuccessorCandidate, positiveSuccessorCandidate)
	positivePredecessorView := attemptView(f, f.observation(1), false)
	positiveReview := attemptReview()
	positiveHistoryBefore, err := positiveStore.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, positiveHistoryBefore.HasMore)
	require.Len(t, positiveHistoryBefore.Events, 1)
	positivePositionLimitsBefore, positiveAttemptLimitsBefore := readAcceptedMaterialCapacityLimitBytes(
		t,
		positiveStore,
		positiveAttemptLimits,
	)

	positiveProposal, err := positiveStore.PrepareAttempt(
		ctx,
		positiveSuccessorCandidate,
		positivePredecessorView,
		positiveReview,
	)
	require.NoError(t, err)
	require.Equal(t, successorWitness.SnapshotRecord, positiveSuccessorCandidate.SnapshotRecord)
	require.NotNil(t, positiveProposal.CapturedFloor)
	require.Equal(t, positiveFloor, *positiveProposal.CapturedFloor)
	positiveAttempt, err := positiveStore.CreateAttempt(
		ctx,
		positiveProposal.StateToken,
		positiveSuccessorCandidate,
		positivePredecessorView,
		positiveReview,
		positiveProposal.Confirmation,
	)
	require.NoError(t, err)
	require.Equal(t, positiveProposal.AttemptID, positiveAttempt.ID)
	assert.Equal(t, AttemptPrepared, positiveAttempt.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, positiveAttempt.Outcome)
	require.Equal(t, successorWitness, positiveSuccessorCandidate)

	loadedFloor, present, err := positiveStore.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, positiveFloor, loadedFloor)
	positiveHistoryAfter, err := positiveStore.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, positiveHistoryAfter.HasMore)
	assert.Equal(t, positiveHistoryBefore, positiveHistoryAfter)
	loadedPositiveAttempt, err := positiveStore.LoadAttempt(ctx, positiveAttempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptPrepared, loadedPositiveAttempt.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, loadedPositiveAttempt.Outcome)
	positiveAttemptHistory, err := positiveStore.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, positiveAttemptHistory.HasMore)
	require.Len(t, positiveAttemptHistory.Attempts, 2)
	var foundPositiveAttempt bool
	for _, entry := range positiveAttemptHistory.Attempts {
		if entry.ID == positiveAttempt.ID {
			foundPositiveAttempt = true
			assert.Equal(t, AttemptPrepared, entry.Lifecycle)
			assert.Equal(t, OutcomeNotSubmitted, entry.Outcome)
		}
	}
	assert.True(t, foundPositiveAttempt)
	positiveCandidateMaterial, err := positiveStore.ReadCandidate(ctx, positiveAttempt.ID)
	require.NoError(t, err)
	assert.Equal(t, positiveSuccessorCandidate.SnapshotRecord, positiveCandidateMaterial.SnapshotRecord)
	assert.Equal(t, positiveSuccessorCandidate.HeadRecord, positiveCandidateMaterial.HeadRecord)
	assert.Equal(t, acceptedPayload(positiveSuccessorCandidate), acceptedPayload(positiveCandidateMaterial))
	positivePositionLimitsAfter, positiveAttemptLimitsAfter := readAcceptedMaterialCapacityLimitBytes(
		t,
		positiveStore,
		positiveAttemptLimits,
	)
	assert.Equal(t, positivePositionLimitsBefore, positivePositionLimitsAfter)
	assert.Equal(t, positiveAttemptLimitsBefore, positiveAttemptLimitsAfter)
	assertAcceptedMaterialCapacityPositiveInventory(
		t,
		positiveStore,
		positiveDirectory,
		positiveBaseAttempt.ID,
		positiveAttempt.ID,
		positiveFloor,
		baseCandidate,
		positiveSuccessorCandidate,
	)
}

type acceptedMaterialCapacityEvidence struct {
	Public             acceptedMaterialState
	LogicalRows        map[string]string
	CatalogCount       int64
	CatalogBytes       int64
	CatalogCID         []byte
	CatalogSize        int64
	CatalogBasename    string
	RetainedReferences int64
	AttemptReferences  int64
	ActiveAttempts     int64
	AttemptCount       int64
	FileNames          []string
	File               acceptedMaterialPayloadFileState
	PositionLimitBytes []byte
	AttemptLimitBytes  []byte
}

func readAcceptedMaterialCapacityEvidence(
	t *testing.T,
	store *Store,
	directory string,
	attemptID [16]byte,
	expectedFloor Floor,
	expectedCandidate CandidateInput,
	attemptLimits AttemptLimits,
) acceptedMaterialCapacityEvidence {
	t.Helper()
	ctx := context.Background()
	public := acceptedMaterialObservedState(t, store, attemptID)
	require.Equal(t, expectedFloor, public.Floor)
	require.True(t, public.HasFloor)
	require.False(t, public.History.HasMore)
	require.Len(t, public.History.Events, 1)
	require.False(t, public.AttemptHistory.HasMore)
	require.Len(t, public.AttemptHistory.Attempts, 1)
	require.Equal(t, AttemptRetiredSuccess, public.Attempt.Lifecycle)
	require.Equal(t, OutcomeCurrent, public.Attempt.Outcome)
	require.Equal(t, expectedCandidate.SnapshotRecord, public.Candidate.SnapshotRecord)
	require.Equal(t, expectedCandidate.HeadRecord, public.Candidate.HeadRecord)
	require.Equal(t, acceptedPayload(expectedCandidate), acceptedPayload(public.Candidate))

	var catalogCount, catalogBytes int64
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(size),0) FROM payload_objects").
			Scan(&catalogCount, &catalogBytes),
	)
	require.Equal(t, int64(1), catalogCount)
	var catalogCID []byte
	var catalogSize int64
	var catalogBasename string
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT blob_cid,size,basename FROM payload_objects").
			Scan(&catalogCID, &catalogSize, &catalogBasename),
	)
	require.Equal(t, testBlobCID(expectedFloor), catalogCID)
	require.Equal(t, int64(testBlobSize(expectedFloor)), catalogSize)
	require.Equal(t, int64(testBlobSize(expectedFloor)), catalogBytes)
	wantedBasename, err := payloadBasenameFromCID(testBlobCID(expectedFloor))
	require.NoError(t, err)
	require.True(t, validPayloadBasename(wantedBasename))
	require.Equal(t, wantedBasename, catalogBasename)

	var retainedReferences, attemptReferences, activeAttempts, attemptCount int64
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", int64(expectedFloor.Revision)).
			Scan(&retainedReferences),
	)
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attemptID[:]).
			Scan(&attemptReferences),
	)
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM active_publication_attempt").Scan(&activeAttempts),
	)
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attemptCount))
	require.Equal(t, int64(1), retainedReferences)
	require.Zero(t, attemptReferences)
	require.Zero(t, activeAttempts)
	require.Equal(t, int64(1), attemptCount)

	payloadDirectory := filepath.Join(directory, payloadDirectoryName)
	fd, err := unix.Open(
		payloadDirectory,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	require.NoError(t, err)
	var directoryStat unix.Stat_t
	statErr := unix.Fstat(fd, &directoryStat)
	file := os.NewFile(uintptr(fd), payloadDirectoryName)
	fileNames, readErr := file.Readdirnames(2)
	closeErr := file.Close()
	require.NoError(t, statErr)
	require.True(t, readErr == nil || readErr == io.EOF)
	require.NoError(t, closeErr)
	require.Equal(t, uint32(unix.S_IFDIR|0o700), directoryStat.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint32(os.Geteuid()), directoryStat.Uid)
	require.Len(t, fileNames, 1)
	sort.Strings(fileNames)
	require.Equal(t, []string{wantedBasename}, fileNames)

	payloadPath := filepath.Join(payloadDirectory, wantedBasename)
	physical, err := observeAcceptedMaterialPayloadFile(payloadPath, int(testBlobSize(expectedFloor)))
	require.NoError(t, err)
	require.True(t, physical.Exists)
	require.Equal(t, acceptedPayload(expectedCandidate), physical.Bytes)
	require.Equal(t, uint32(unix.S_IFREG|0o600), physical.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint32(os.Geteuid()), physical.UID)
	require.Equal(t, uint64(1), physical.Nlink)

	positionLimitBytes, attemptLimitBytes := readAcceptedMaterialCapacityLimitBytes(t, store, attemptLimits)
	return acceptedMaterialCapacityEvidence{
		Public: public, LogicalRows: readAttemptLogicalRows(t, store),
		CatalogCount: catalogCount, CatalogBytes: catalogBytes,
		CatalogCID: bytes.Clone(catalogCID), CatalogSize: catalogSize, CatalogBasename: catalogBasename,
		RetainedReferences: retainedReferences, AttemptReferences: attemptReferences,
		ActiveAttempts: activeAttempts, AttemptCount: attemptCount,
		FileNames: append([]string(nil), fileNames...), File: physical,
		PositionLimitBytes: positionLimitBytes, AttemptLimitBytes: attemptLimitBytes,
	}
}

func readAcceptedMaterialCapacityLimitBytes(t *testing.T, store *Store, attemptLimits AttemptLimits) ([]byte, []byte) {
	t.Helper()
	ctx := context.Background()
	positionLimitBytes, err := readValueBounded(ctx, store.conn, "limits", 16384)
	require.NoError(t, err)
	attemptLimitBytes, err := readValueBounded(ctx, store.conn, "attempt_limits", 16384)
	require.NoError(t, err)
	wantPositionLimitBytes, err := encodeLimits(DefaultLimits())
	require.NoError(t, err)
	wantAttemptLimitBytes, err := encodeAttemptLimits(attemptLimits)
	require.NoError(t, err)
	require.Equal(t, wantPositionLimitBytes, positionLimitBytes)
	require.Equal(t, wantAttemptLimitBytes, attemptLimitBytes)
	return bytes.Clone(positionLimitBytes), bytes.Clone(attemptLimitBytes)
}

func assertAcceptedMaterialCapacityPositiveInventory(
	t *testing.T,
	store *Store,
	directory string,
	baseAttemptID, successorAttemptID [16]byte,
	floor Floor,
	baseCandidate, successorCandidate CandidateInput,
) {
	t.Helper()
	ctx := context.Background()
	var objectCount, objectBytes int64
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(size),0) FROM payload_objects").
			Scan(&objectCount, &objectBytes),
	)
	assert.Equal(t, int64(2), objectCount)
	assert.Equal(t, int64(len(acceptedPayload(baseCandidate))+len(acceptedPayload(successorCandidate))), objectBytes)
	var matchingObjects int64
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects WHERE blob_cid IN (?,?)", testBlobCID(floor), blobForCandidate(t, successorCandidate).CID).
			Scan(&matchingObjects),
	)
	assert.Equal(t, int64(2), matchingObjects)

	var retainedReferences, baseAttemptReferences, successorAttemptReferences, activeAttempts, attemptCount int64
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", int64(floor.Revision)).
			Scan(&retainedReferences),
	)
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", baseAttemptID[:]).
			Scan(&baseAttemptReferences),
	)
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", successorAttemptID[:]).
			Scan(&successorAttemptReferences),
	)
	require.NoError(
		t,
		store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM active_publication_attempt").Scan(&activeAttempts),
	)
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attemptCount))
	assert.Equal(t, int64(1), retainedReferences)
	assert.Zero(t, baseAttemptReferences)
	assert.Equal(t, int64(1), successorAttemptReferences)
	assert.Equal(t, int64(1), activeAttempts)
	assert.Equal(t, int64(2), attemptCount)

	payloadDirectory := filepath.Join(directory, payloadDirectoryName)
	fileNames := readAcceptedMaterialCapacityDirectoryNames(t, payloadDirectory, 2)
	wantNames := []string{payloadBasename(acceptedPayload(baseCandidate)), payloadBasename(acceptedPayload(successorCandidate))}
	sort.Strings(wantNames)
	assert.Equal(t, wantNames, fileNames)
	for _, candidate := range []CandidateInput{baseCandidate, successorCandidate} {
		path := filepath.Join(payloadDirectory, payloadBasename(acceptedPayload(candidate)))
		physical, err := observeAcceptedMaterialPayloadFile(path, len(acceptedPayload(candidate)))
		require.NoError(t, err)
		assert.True(t, physical.Exists)
		assert.Equal(t, acceptedPayload(candidate), physical.Bytes)
		assert.Equal(t, uint32(unix.S_IFREG|0o600), physical.Mode&uint32(unix.S_IFMT|0o777))
		assert.Equal(t, uint32(os.Geteuid()), physical.UID)
		assert.Equal(t, uint64(1), physical.Nlink)
	}
}

func readAcceptedMaterialCapacityDirectoryNames(t *testing.T, path string, maximum uint32) []string {
	t.Helper()
	require.Positive(t, maximum)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	names, readErr := file.Readdirnames(int(maximum) + 1)
	closeErr := file.Close()
	require.True(t, readErr == nil || readErr == io.EOF)
	require.NoError(t, closeErr)
	require.LessOrEqual(t, uint32(len(names)), maximum)
	sort.Strings(names)
	return names
}

func assertAcceptedMaterialCapacitySuccessor(
	t *testing.T,
	f fixture,
	baseCandidate, successorCandidate CandidateInput,
) {
	t.Helper()
	require.NotEmpty(t, acceptedPayload(baseCandidate))
	require.NotEmpty(t, acceptedPayload(successorCandidate))
	require.NotEqual(t, acceptedPayload(baseCandidate), acceptedPayload(successorCandidate))
	require.NotEqual(t, blobForCandidate(t, baseCandidate).CID, blobForCandidate(t, successorCandidate).CID)
	require.NoError(t, publication.VerifyPayload(acceptedPayload(successorCandidate), blobForCandidate(t, successorCandidate)))
	_, err := publication.DecodePayload(acceptedPayload(successorCandidate), blobForCandidate(t, successorCandidate))
	require.NoError(t, err)
	baseRecord, err := publication.DecodeSnapshot(baseCandidate.SnapshotRecord)
	require.NoError(t, err)
	baseCID, err := publication.RecordCID(baseCandidate.SnapshotRecord)
	require.NoError(t, err)
	successorRecord, err := publication.DecodeSnapshot(successorCandidate.SnapshotRecord)
	require.NoError(t, err)
	successorCID, err := publication.RecordCID(successorCandidate.SnapshotRecord)
	require.NoError(t, err)
	require.Equal(t, uint64(0), baseRecord.PublicationSeq)
	require.Equal(t, uint64(1), successorRecord.PublicationSeq)
	require.Equal(t, baseCID, successorRecord.Parent)
	require.Equal(t, f.binding.Vault, successorRecord.Vault)
	require.Equal(t, uint64(len(acceptedPayload(successorCandidate))), testBlob(successorRecord).Size)
	require.Equal(t, f.blocks[1].Key, successorCandidate.SnapshotKey)
	wantSuccessorCID, err := publication.RawPayloadCID(acceptedPayload(successorCandidate))
	require.NoError(t, err)
	require.Equal(t, wantSuccessorCID, testBlob(successorRecord).CID)
	wantHead, err := publication.DecodeHead(successorCandidate.HeadRecord)
	require.NoError(t, err)
	require.Equal(t, wantHead.PublicationSeq, successorRecord.PublicationSeq)
	require.Equal(t, wantHead.Vault, successorRecord.Vault)
	require.Equal(t, wantHead.SnapshotCID, successorCID)
}

func mustSuccessorParent(t *testing.T, candidate CandidateInput) []byte {
	t.Helper()
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	return bytes.Clone(record.Parent)
}

func cloneAcceptedMaterialCapacityCandidate(candidate CandidateInput) CandidateInput {
	segments := make([]CandidateSegment, 0, len(candidate.Segments))
	for _, segment := range candidate.Segments {
		cloned := segment
		if segment.Blob != nil {
			blob := *segment.Blob
			blob.CID = bytes.Clone(segment.Blob.CID)
			cloned.Blob = &blob
		}
		cloned.Entries = append([]PayloadEntryReference(nil), segment.Entries...)
		for index := range cloned.Entries {
			cloned.Entries[index].CID = bytes.Clone(segment.Entries[index].CID)
		}
		segments = append(segments, cloned)
	}
	payloads := make([][]byte, 0, len(candidate.Payloads))
	for _, payload := range candidate.Payloads {
		payloads = append(payloads, bytes.Clone(payload))
	}
	return CandidateInput{
		SnapshotKey:    candidate.SnapshotKey,
		SnapshotRecord: bytes.Clone(candidate.SnapshotRecord),
		HeadRecord:     bytes.Clone(candidate.HeadRecord),
		Segments:       segments,
		Payloads:       payloads,
	}
}
