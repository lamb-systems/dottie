package publicationstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPublicationReadAcceptedMaterialDoesNotBorrowActiveCandidatePayload(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	require.Len(t, f.blocks, 2)
	store, directory := newStore(t, f)
	defer store.Close()

	positionObservation := f.observation(1)
	positionProposal, err := store.Prepare(ctx, ModeFirstUse, positionObservation, f.payload)
	require.NoError(t, err)
	positionFloor, err := store.Accept(ctx, ModeFirstUse, positionProposal.StateToken, positionObservation, f.payload, positionProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(0), positionFloor.Sequence)

	candidate := attemptCandidate(f, 1)
	candidateView := attemptView(f, positionObservation, false)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, candidateView, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, candidateView, review, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptPrepared, attempt.Lifecycle)
	require.Equal(t, OutcomeNotSubmitted, attempt.Outcome)
	require.Equal(t, AttemptSuccessor, attempt.Kind)
	require.Equal(t, proposal.AttemptID, attempt.ID)
	require.NotNil(t, attempt.CapturedFloor)
	require.Equal(t, positionFloor, *attempt.CapturedFloor)
	require.Equal(t, positionFloor.Revision, attempt.CapturedRevision)
	require.Equal(t, positionFloor.Generation, attempt.CapturedGeneration)

	candidateRecord, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	candidateCID, err := publication.RecordCID(candidate.SnapshotRecord)
	require.NoError(t, err)
	candidateBlob := blobForCandidate(t, candidate)
	require.Equal(t, positionFloor.RecordCID, candidateRecord.Parent)
	require.NotEqual(t, positionFloor.RecordCID, candidateCID)
	require.Equal(t, positionFloor.BlobCID, candidateBlob.CID)
	require.Equal(t, positionFloor.BlobSize, candidateBlob.Size)
	require.Equal(t, f.payload, candidate.Payload)
	require.NoError(t, publication.VerifyPayload(candidate.Payload, candidateBlob))
	_, err = publication.DecodePayload(candidate.Payload, candidateBlob)
	require.NoError(t, err)

	before := observeAcceptedMaterialActiveCandidate(t, store, directory, attempt.ID, positionFloor, f.blocks[0].Raw, candidate)
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, before.Floor)
	require.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	after := observeAcceptedMaterialActiveCandidate(t, store, directory, attempt.ID, positionFloor, f.blocks[0].Raw, candidate)
	require.Equal(t, before, after)
}

type acceptedMaterialUnownedCounts struct {
	Attempts       int64
	Active         int64
	Objects        int64
	AttemptRefs    int64
	Retained       int64
	Reservations   int64
	PendingGenesis int64
}

func readAcceptedMaterialUnownedCounts(t *testing.T, store *Store) acceptedMaterialUnownedCounts {
	t.Helper()
	ctx := context.Background()
	var counts acceptedMaterialUnownedCounts
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&counts.Attempts))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM active_publication_attempt").Scan(&counts.Active))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&counts.Objects))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&counts.AttemptRefs))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&counts.Retained))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_reservations").Scan(&counts.Reservations))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_genesis").Scan(&counts.PendingGenesis))
	return counts
}

type acceptedMaterialActiveCandidateState struct {
	Floor          Floor
	History        HistoryPage
	Attempt        Attempt
	Active         Attempt
	ActivePresent  bool
	AttemptHistory AttemptPage
	Candidate      CandidateMaterial
	Counts         acceptedMaterialUnownedCounts
	File           acceptedMaterialPayloadFileState
	LogicalRows    map[string]string
}

func observeAcceptedMaterialActiveCandidate(t *testing.T, store *Store, directory string, attemptID [16]byte, expectedFloor Floor, expectedFloorRecord []byte, expectedCandidate CandidateInput) acceptedMaterialActiveCandidateState {
	t.Helper()
	ctx := context.Background()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, expectedFloor, floor)
	require.Equal(t, uint64(0), floor.Sequence)

	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Len(t, history.Events, 1)
	require.Equal(t, floor, history.Events[0].NewFloor)
	require.Equal(t, "first_use", history.Events[0].Stop)
	var historyRecord []byte
	for _, record := range history.Records {
		if record.Reference.Key == floor.SnapshotKey && bytes.Equal(record.Reference.CID, floor.RecordCID) && record.Reference.Sequence == floor.Sequence {
			historyRecord = bytes.Clone(record.Raw)
		}
	}
	require.NotEmpty(t, historyRecord)
	require.Equal(t, expectedFloorRecord, historyRecord)

	active, activePresent, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, activePresent)
	require.Equal(t, attemptID, active.ID)
	require.Equal(t, AttemptPrepared, active.Lifecycle)
	require.Equal(t, OutcomeNotSubmitted, active.Outcome)
	require.NotNil(t, active.CapturedFloor)
	require.Equal(t, floor, *active.CapturedFloor)
	attempt, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	require.Equal(t, active, attempt)
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attemptHistory.HasMore)
	require.Len(t, attemptHistory.Attempts, 1)
	require.Equal(t, attemptID, attemptHistory.Attempts[0].ID)
	require.Equal(t, AttemptPrepared, attemptHistory.Attempts[0].Lifecycle)
	require.Equal(t, OutcomeNotSubmitted, attemptHistory.Attempts[0].Outcome)

	candidate, err := store.ReadCandidate(ctx, attemptID)
	require.NoError(t, err)
	require.Equal(t, expectedCandidate.SnapshotKey, candidate.SnapshotKey)
	require.Equal(t, expectedCandidate.SnapshotRecord, candidate.SnapshotRecord)
	require.Equal(t, expectedCandidate.HeadRecord, candidate.HeadRecord)
	require.Equal(t, expectedCandidate.Payload, candidate.Payload)
	candidateBlob := blobForCandidate(t, expectedCandidate)
	require.Equal(t, candidateBlob, candidate.Blob)
	var attemptReference []byte
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT blob_cid FROM attempt_payload_refs WHERE attempt_id=?", attemptID[:]).Scan(&attemptReference))
	require.Equal(t, candidateBlob.CID, attemptReference)
	require.Equal(t, floor.BlobCID, candidate.Blob.CID)
	require.Equal(t, floor.BlobSize, candidate.Blob.Size)

	counts := readAcceptedMaterialUnownedCounts(t, store)
	require.Equal(t, acceptedMaterialUnownedCounts{Attempts: 1, Active: 1, Objects: 1, AttemptRefs: 1, Reservations: 1}, counts)

	basename, err := payloadBasenameFromCID(floor.BlobCID)
	require.NoError(t, err)
	require.True(t, validPayloadBasename(basename))
	require.Equal(t, payloadBasename(expectedCandidate.Payload), basename)
	require.GreaterOrEqual(t, store.payloadFD, 0)
	var directoryStat unix.Stat_t
	require.NoError(t, unix.Fstat(store.payloadFD, &directoryStat))
	require.Equal(t, uint32(unix.S_IFDIR|0o700), directoryStat.Mode&uint32(unix.S_IFMT|0o777))
	file, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, basename), len(expectedCandidate.Payload))
	require.NoError(t, err)
	require.True(t, file.Exists)
	require.Equal(t, expectedCandidate.Payload, file.Bytes)
	require.Equal(t, uint32(unix.S_IFREG|0o600), file.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint32(os.Geteuid()), file.UID)
	require.Equal(t, uint64(1), file.Nlink)

	return acceptedMaterialActiveCandidateState{
		Floor: floor, History: history, Attempt: attempt, Active: active, ActivePresent: activePresent,
		AttemptHistory: attemptHistory, Candidate: candidate, Counts: counts, File: file,
		LogicalRows: readAttemptLogicalRows(t, store),
	}
}

func TestPublicationReadAcceptedMaterialRejectsPositionOnlyFloorBackedByValidOrphan(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	require.Len(t, f.blocks, 1)
	store, directory := newStore(t, f)
	defer store.Close()

	candidate := attemptCandidate(f, 0)
	candidateBlob := blobForCandidate(t, candidate)
	require.NotEmpty(t, candidate.Payload)
	require.LessOrEqual(t, uint64(len(candidate.Payload)), publication.MaxBlobBytes)
	require.NoError(t, publication.VerifyPayload(candidate.Payload, candidateBlob))
	_, err := publication.DecodePayload(candidate.Payload, candidateBlob)
	require.NoError(t, err)
	basename, err := payloadBasenameFromCID(candidateBlob.CID)
	require.NoError(t, err)
	require.True(t, validPayloadBasename(basename))
	require.Equal(t, payloadBasename(candidate.Payload), basename)
	require.NoError(t, assertPayloadDirectoryAbsent(directory))

	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	beforeRows := readAttemptLogicalRows(t, store)
	originalCustodyOps := store.custodyOps
	require.NotNil(t, originalCustodyOps.sync)
	var regularSyncs int
	var injections int
	var probeErr error
	var observations []acceptedMaterialFileSyncObservation
	t.Cleanup(func() { store.custodyOps = originalCustodyOps })
	store.custodyOps.sync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			probeErr = err
			return err
		}
		kind := stat.Mode & unix.S_IFMT
		if kind == unix.S_IFDIR {
			return originalCustodyOps.sync(fd)
		}
		if kind != unix.S_IFREG {
			probeErr = errors.New("unexpected custody sync object")
			return probeErr
		}
		regularSyncs++
		observation := acceptedMaterialFileSyncObservation{
			Device: uint64(stat.Dev), Inode: stat.Ino, Mode: stat.Mode,
			Nlink: uint64(stat.Nlink), Size: stat.Size,
		}
		if regularSyncs == 2 {
			if store.payloadFD < 0 {
				probeErr = errors.New("payload directory is not pinned")
				return probeErr
			}
			var named unix.Stat_t
			if err := unix.Fstatat(store.payloadFD, basename, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				probeErr = err
				return err
			}
			observation.Named = true
			observation.NamedDevice = uint64(named.Dev)
			observation.NamedInode = named.Ino
			observation.NamedMode = named.Mode
			observation.NamedNlink = uint64(named.Nlink)
			observation.NamedSize = named.Size
			observations = append(observations, observation)
			injections++
			return unix.EIO
		}
		observations = append(observations, observation)
		return originalCustodyOps.sync(fd)
	}

	created, createErr := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	store.custodyOps = originalCustodyOps
	require.Equal(t, Attempt{}, created)
	requireErrorMetadata(t, createErr, ErrStorage, StageCustody, ReasonIO)
	require.NoError(t, probeErr)
	require.Equal(t, 2, regularSyncs)
	require.Equal(t, 1, injections)
	require.Len(t, observations, 2)
	secondSync := observations[1]
	require.True(t, secondSync.Named)
	require.Equal(t, secondSync.Device, secondSync.NamedDevice)
	require.Equal(t, secondSync.Inode, secondSync.NamedInode)
	require.Equal(t, uint32(unix.S_IFREG), secondSync.Mode&unix.S_IFMT)
	require.Equal(t, uint32(unix.S_IFREG), secondSync.NamedMode&unix.S_IFMT)
	require.Equal(t, uint64(1), secondSync.Nlink)
	require.Equal(t, uint64(1), secondSync.NamedNlink)
	require.Equal(t, int64(len(candidate.Payload)), secondSync.Size)
	require.Equal(t, int64(len(candidate.Payload)), secondSync.NamedSize)

	require.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
	require.Equal(t, acceptedMaterialUnownedCounts{}, readAcceptedMaterialUnownedCounts(t, store))
	payloadDirectory := filepath.Join(directory, payloadDirectoryName)
	require.GreaterOrEqual(t, store.payloadFD, 0)
	var directoryStat unix.Stat_t
	require.NoError(t, unix.Fstat(store.payloadFD, &directoryStat))
	require.Equal(t, uint32(unix.S_IFDIR|0o700), directoryStat.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, []string{basename}, readAcceptedMaterialCapacityDirectoryNames(t, payloadDirectory, 1))
	orphanPath := filepath.Join(payloadDirectory, basename)
	orphan, err := observeAcceptedMaterialPayloadFile(orphanPath, len(candidate.Payload))
	require.NoError(t, err)
	require.True(t, orphan.Exists)
	require.Equal(t, candidate.Payload, orphan.Bytes)
	require.Equal(t, uint32(unix.S_IFREG|0o600), orphan.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint32(os.Geteuid()), orphan.UID)
	require.Equal(t, uint64(1), orphan.Nlink)
	require.NoError(t, publication.VerifyPayload(orphan.Bytes, candidateBlob))
	_, err = publication.DecodePayload(orphan.Bytes, candidateBlob)
	require.NoError(t, err)

	observation := f.observation(1)
	positionProposal, err := store.Prepare(ctx, ModeFirstUse, observation, f.payload)
	require.NoError(t, err)
	acceptedFloor, err := store.Accept(ctx, ModeFirstUse, positionProposal.StateToken, observation, f.payload, positionProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(0), acceptedFloor.Sequence)
	acceptedRecord, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	acceptedRecordCID, err := publication.RecordCID(candidate.SnapshotRecord)
	require.NoError(t, err)
	require.Equal(t, acceptedRecordCID, acceptedFloor.RecordCID)
	require.Equal(t, candidateBlob.CID, acceptedFloor.BlobCID)
	require.Equal(t, candidateBlob.Size, acceptedFloor.BlobSize)
	require.Equal(t, candidate.SnapshotKey, acceptedFloor.SnapshotKey)
	require.Equal(t, acceptedRecord.PublicationID, acceptedFloor.PublicationID)
	require.Len(t, observation.Snapshots, 1)
	require.Equal(t, candidate.SnapshotRecord, observation.Snapshots[0].Raw)
	loadedFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, acceptedFloor, loadedFloor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Len(t, history.Events, 1)
	require.Equal(t, acceptedFloor, history.Events[0].NewFloor)
	require.Equal(t, acceptedMaterialUnownedCounts{}, readAcceptedMaterialUnownedCounts(t, store))
	beforeReadRows := readAttemptLogicalRows(t, store)
	beforeReadFile, err := observeAcceptedMaterialPayloadFile(orphanPath, len(candidate.Payload))
	require.NoError(t, err)
	require.Equal(t, orphan, beforeReadFile)

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, loadedFloor)
	require.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	require.Equal(t, loadedFloor, acceptedFloor)
	require.Equal(t, beforeReadRows, readAttemptLogicalRows(t, store))
	require.Equal(t, acceptedMaterialUnownedCounts{}, readAcceptedMaterialUnownedCounts(t, store))
	afterFloor, afterPresent, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, afterPresent)
	require.Equal(t, loadedFloor, afterFloor)
	afterHistory, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Equal(t, history, afterHistory)
	afterReadFile, err := observeAcceptedMaterialPayloadFile(orphanPath, len(candidate.Payload))
	require.NoError(t, err)
	require.Equal(t, orphan, afterReadFile)
}

type acceptedMaterialFileSyncObservation struct {
	Device      uint64
	Inode       uint64
	Mode        uint32
	Nlink       uint64
	Size        int64
	Named       bool
	NamedDevice uint64
	NamedInode  uint64
	NamedMode   uint32
	NamedNlink  uint64
	NamedSize   int64
}

func TestPublicationReadAcceptedMaterialRejectsCorruptAuditBeforeOwnerAndPayloadAccess(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	attempt, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, candidate)
	expectedFloor := cloneFloor(finalized.Floor)
	positive, err := store.ReadAcceptedMaterial(ctx, f.binding, expectedFloor)
	require.NoError(t, err)
	require.Equal(t, expectedFloor, positive.Floor)
	require.Equal(t, candidate.SnapshotRecord, positive.SnapshotRecord)
	require.Equal(t, candidate.Payload, positive.Payload)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	require.Equal(t, -1, reopened.payloadFD)
	healthyPublic := observeAcceptedMaterialAuditPublicState(t, reopened, attempt.ID)
	require.Equal(t, expectedFloor, healthyPublic.Floor)
	healthyRows := readAttemptLogicalRows(t, reopened)
	basename, err := payloadBasenameFromCID(expectedFloor.BlobCID)
	require.NoError(t, err)
	require.True(t, validPayloadBasename(basename))
	require.Equal(t, payloadBasename(candidate.Payload), basename)
	payloadPath := filepath.Join(directory, payloadDirectoryName, basename)
	healthyFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
	require.NoError(t, err)
	require.True(t, healthyFile.Exists)
	require.Equal(t, candidate.Payload, healthyFile.Bytes)
	require.Equal(t, uint32(unix.S_IFREG|0o600), healthyFile.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint32(os.Geteuid()), healthyFile.UID)
	require.Equal(t, uint64(1), healthyFile.Nlink)
	healthyEvent := readAcceptedMaterialAuditEvent(t, reopened, int64(expectedFloor.Revision))
	require.NotEmpty(t, healthyEvent.Body)
	require.NotEqual(t, []byte("{}"), healthyEvent.Body)

	corruptBody := []byte("{}")
	result, err := reopened.conn.ExecContext(ctx, "UPDATE accepted_events SET body=? WHERE revision=?", corruptBody, int64(expectedFloor.Revision))
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected)
	faultedEvent := readAcceptedMaterialAuditEvent(t, reopened, int64(expectedFloor.Revision))
	require.Equal(t, corruptBody, faultedEvent.Body)
	require.Equal(t, healthyEvent.Revision, faultedEvent.Revision)
	require.Equal(t, healthyEvent.Mode, faultedEvent.Mode)
	require.Equal(t, healthyEvent.Reason, faultedEvent.Reason)
	require.Equal(t, healthyEvent.Stop, faultedEvent.Stop)
	require.Equal(t, healthyEvent.OldFloor, faultedEvent.OldFloor)
	require.Equal(t, healthyEvent.NewFloor, faultedEvent.NewFloor)
	require.Equal(t, healthyEvent.Digest, faultedEvent.Digest)
	require.Equal(t, healthyEvent.LogicalBytes, faultedEvent.LogicalBytes)
	faultedRows := readAttemptLogicalRows(t, reopened)
	require.NotEqual(t, healthyRows, faultedRows)
	require.Equal(t, -1, reopened.payloadFD)
	faultedFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
	require.NoError(t, err)
	require.Equal(t, healthyFile, faultedFile)

	callerFloor := cloneFloor(expectedFloor)
	material, err := reopened.ReadAcceptedMaterial(ctx, f.binding, expectedFloor)
	require.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	require.Equal(t, callerFloor, expectedFloor)
	require.Equal(t, -1, reopened.payloadFD)
	require.Equal(t, faultedRows, readAttemptLogicalRows(t, reopened))
	require.Equal(t, faultedEvent, readAcceptedMaterialAuditEvent(t, reopened, int64(expectedFloor.Revision)))
	afterFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
	require.NoError(t, err)
	require.Equal(t, faultedFile, afterFile)
}

type acceptedMaterialAuditPublicState struct {
	Floor          Floor
	History        HistoryPage
	Attempt        Attempt
	AttemptHistory AttemptPage
}

func observeAcceptedMaterialAuditPublicState(t *testing.T, store *Store, attemptID [16]byte) acceptedMaterialAuditPublicState {
	t.Helper()
	ctx := context.Background()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Len(t, history.Events, 1)
	attempt, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	require.Equal(t, AttemptRetiredSuccess, attempt.Lifecycle)
	require.Equal(t, OutcomeCurrent, attempt.Outcome)
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attemptHistory.HasMore)
	require.Len(t, attemptHistory.Attempts, 1)
	require.Equal(t, attemptID, attemptHistory.Attempts[0].ID)
	require.Equal(t, AttemptRetiredSuccess, attemptHistory.Attempts[0].Lifecycle)
	return acceptedMaterialAuditPublicState{Floor: floor, History: history, Attempt: attempt, AttemptHistory: attemptHistory}
}

type acceptedMaterialAuditEvent struct {
	Revision     int64
	Mode         string
	Reason       string
	Stop         string
	OldFloor     []byte
	NewFloor     []byte
	Body         []byte
	Digest       []byte
	LogicalBytes int64
}

func readAcceptedMaterialAuditEvent(t *testing.T, store *Store, revision int64) acceptedMaterialAuditEvent {
	t.Helper()
	var event acceptedMaterialAuditEvent
	err := store.conn.QueryRowContext(context.Background(), "SELECT revision,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes FROM accepted_events WHERE revision=?", revision).Scan(
		&event.Revision, &event.Mode, &event.Reason, &event.Stop, &event.OldFloor, &event.NewFloor, &event.Body, &event.Digest, &event.LogicalBytes,
	)
	require.NoError(t, err)
	event.OldFloor = bytes.Clone(event.OldFloor)
	event.NewFloor = bytes.Clone(event.NewFloor)
	event.Body = bytes.Clone(event.Body)
	event.Digest = bytes.Clone(event.Digest)
	return event
}
