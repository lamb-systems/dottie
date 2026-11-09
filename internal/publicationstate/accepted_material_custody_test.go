package publicationstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPublicationReadAcceptedMaterialRefusesFaultedOwnedPayload(t *testing.T) {
	for _, fault := range []string{"missing", "truncated", "same-size-corruption", "unsafe-mode"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			defer store.Close()

			candidate := attemptCandidate(f, 0)
			require.NotEmpty(t, candidate.Payload)
			require.GreaterOrEqual(t, len(candidate.Payload), 2)
			attempt, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, candidate)
			expectedFloor := cloneFloor(finalized.Floor)
			heldFloor := cloneFloor(finalized.Floor)
			heldRecord := bytes.Clone(candidate.SnapshotRecord)
			heldPayload := bytes.Clone(candidate.Payload)

			basename, err := payloadBasenameFromCID(finalized.Floor.BlobCID)
			require.NoError(t, err)
			require.True(t, validPayloadBasename(basename))
			require.Equal(t, payloadBasename(candidate.Payload), basename)
			payloadPath := filepath.Join(directory, payloadDirectoryName, basename)

			material, err := store.ReadAcceptedMaterial(ctx, f.binding, expectedFloor)
			require.NoError(t, err)
			require.Equal(t, expectedFloor, material.Floor)
			require.Equal(t, candidate.SnapshotRecord, material.SnapshotRecord)
			require.Equal(t, candidate.Payload, material.Payload)

			healthyFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
			require.NoError(t, err)
			require.True(t, healthyFile.Exists)
			require.Equal(t, candidate.Payload, healthyFile.Bytes)
			require.Equal(t, uint32(unix.S_IFREG|0o600), healthyFile.Mode&uint32(unix.S_IFMT|0o777))
			require.Equal(t, uint64(1), healthyFile.Nlink)
			healthyState := readAcceptedMaterialCustodyState(t, store, attempt.ID, candidate)
			require.Equal(t, expectedFloor, healthyState.Floor)

			var wantMaterialReason Reason
			var wantCandidateReason Reason
			switch fault {
			case "missing":
				require.NoError(t, os.Remove(payloadPath))
				wantMaterialReason = ReasonMaterialMissing
				wantCandidateReason = ReasonCandidateMissing
			case "truncated":
				require.NoError(t, os.Truncate(payloadPath, int64(len(candidate.Payload)-1)))
				wantMaterialReason = ReasonMaterialUnsafe
				wantCandidateReason = ReasonCandidateUnsafe
			case "same-size-corruption":
				changedByte := candidate.Payload[0] ^ 0xff
				file, openErr := os.OpenFile(payloadPath, os.O_WRONLY, 0)
				require.NoError(t, openErr)
				written, writeErr := file.WriteAt([]byte{changedByte}, 0)
				syncErr := file.Sync()
				closeErr := file.Close()
				require.NoError(t, writeErr)
				require.Equal(t, 1, written)
				require.NoError(t, syncErr)
				require.NoError(t, closeErr)
				wantMaterialReason = ReasonMaterialCorrupt
				wantCandidateReason = ReasonCandidateCorrupt
			case "unsafe-mode":
				require.NoError(t, os.Chmod(payloadPath, 0o400))
				wantMaterialReason = ReasonMaterialUnsafe
				wantCandidateReason = ReasonCandidateUnsafe
			default:
				require.FailNow(t, "unexpected fault case")
			}

			faultedFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
			require.NoError(t, err)
			if fault == "missing" {
				require.False(t, faultedFile.Exists)
			} else {
				require.True(t, faultedFile.Exists)
				require.Equal(t, healthyFile.Device, faultedFile.Device)
				require.Equal(t, healthyFile.Inode, faultedFile.Inode)
				require.Equal(t, uint32(unix.S_IFREG), faultedFile.Mode&uint32(unix.S_IFMT))
				require.Equal(t, uint32(os.Geteuid()), faultedFile.UID)
				require.Equal(t, uint64(1), faultedFile.Nlink)
				switch fault {
				case "truncated":
					require.Equal(t, int64(len(candidate.Payload)-1), faultedFile.Size)
					require.Equal(t, candidate.Payload[:len(candidate.Payload)-1], faultedFile.Bytes)
					require.Equal(t, uint32(0o600), faultedFile.Mode&0o777)
				case "same-size-corruption":
					wantBytes := bytes.Clone(candidate.Payload)
					wantBytes[0] = candidate.Payload[0] ^ 0xff
					require.Equal(t, int64(len(candidate.Payload)), faultedFile.Size)
					require.NotEqual(t, candidate.Payload, faultedFile.Bytes)
					require.Equal(t, wantBytes, faultedFile.Bytes)
					require.Equal(t, uint32(0o600), faultedFile.Mode&0o777)
				case "unsafe-mode":
					require.Equal(t, int64(len(candidate.Payload)), faultedFile.Size)
					require.Equal(t, candidate.Payload, faultedFile.Bytes)
					require.Equal(t, uint32(0o400), faultedFile.Mode&0o777)
				}
			}

			material, err = store.ReadAcceptedMaterial(ctx, f.binding, expectedFloor)
			assert.Equal(t, AcceptedMaterial{}, material)
			requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, wantMaterialReason)
			afterReadFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
			require.NoError(t, err)
			assert.Equal(t, faultedFile, afterReadFile)

			assertAcceptedMaterialCustodyPublicState(t, store, attempt.ID, healthyState)
			assert.Equal(t, healthyState.LogicalRows, readAttemptLogicalRows(t, store))

			candidateMaterial, err := store.ReadCandidate(ctx, attempt.ID)
			assert.Equal(t, CandidateMaterial{}, candidateMaterial)
			requireErrorMetadata(t, err, ErrStorage, StageCustody, wantCandidateReason)
			afterCandidateFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
			require.NoError(t, err)
			assert.Equal(t, faultedFile, afterCandidateFile)
			assert.Equal(t, heldFloor, finalized.Floor)
			assert.Equal(t, heldFloor, expectedFloor)
			assert.Equal(t, heldRecord, candidate.SnapshotRecord)
			assert.Equal(t, heldPayload, candidate.Payload)
		})
	}
}

type acceptedMaterialCustodyState struct {
	Floor          Floor
	History        HistoryPage
	Attempt        Attempt
	AttemptHistory AttemptPage
	Candidate      CandidateMaterial
	LogicalRows    map[string]string
}

func readAcceptedMaterialCustodyState(t *testing.T, store *Store, attemptID [16]byte, expected CandidateInput) acceptedMaterialCustodyState {
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
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attemptHistory.HasMore)
	require.Len(t, attemptHistory.Attempts, 1)
	candidate, err := store.ReadCandidate(ctx, attemptID)
	require.NoError(t, err)
	require.Equal(t, expected.SnapshotRecord, candidate.SnapshotRecord)
	require.Equal(t, expected.Payload, candidate.Payload)
	return acceptedMaterialCustodyState{
		Floor: floor, History: history, Attempt: attempt, AttemptHistory: attemptHistory,
		Candidate: candidate, LogicalRows: readAttemptLogicalRows(t, store),
	}
}

func assertAcceptedMaterialCustodyPublicState(t *testing.T, store *Store, attemptID [16]byte, expected acceptedMaterialCustodyState) {
	t.Helper()
	ctx := context.Background()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, expected.Floor, floor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Len(t, history.Events, len(expected.History.Events))
	assert.Equal(t, expected.History, history)
	attempt, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	assert.Equal(t, expected.Attempt, attempt)
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attemptHistory.HasMore)
	require.Len(t, attemptHistory.Attempts, len(expected.AttemptHistory.Attempts))
	assert.Equal(t, expected.AttemptHistory, attemptHistory)
}

type acceptedMaterialPayloadFileState struct {
	Exists bool
	Device uint64
	Inode  uint64
	UID    uint32
	Nlink  uint64
	Mode   uint32
	Size   int64
	Bytes  []byte
}

func observeAcceptedMaterialPayloadFile(path string, maximumBytes int) (acceptedMaterialPayloadFileState, error) {
	if maximumBytes < 0 || uint64(maximumBytes) > publication.MaxBlobBytes {
		return acceptedMaterialPayloadFileState{}, errors.New("invalid fixture payload bound")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return acceptedMaterialPayloadFileState{}, nil
	}
	if err != nil {
		return acceptedMaterialPayloadFileState{}, err
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	if statErr != nil {
		_ = unix.Close(fd)
		return acceptedMaterialPayloadFileState{}, statErr
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || stat.Size > int64(maximumBytes+1) {
		_ = unix.Close(fd)
		return acceptedMaterialPayloadFileState{}, errors.New("unexpected fixture payload file metadata")
	}
	buffer := make([]byte, maximumBytes+1)
	offset := 0
	var readErr error
	for offset < len(buffer) {
		count, err := unix.Pread(fd, buffer[offset:], int64(offset))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			readErr = err
			break
		}
		if count == 0 {
			break
		}
		offset += count
	}
	closeErr := unix.Close(fd)
	if readErr != nil {
		return acceptedMaterialPayloadFileState{}, readErr
	}
	if closeErr != nil {
		return acceptedMaterialPayloadFileState{}, closeErr
	}
	if int64(offset) != stat.Size {
		return acceptedMaterialPayloadFileState{}, errors.New("fixture payload changed while observed")
	}
	return acceptedMaterialPayloadFileState{
		Exists: true, Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid,
		Nlink: uint64(stat.Nlink), Mode: stat.Mode, Size: stat.Size, Bytes: bytes.Clone(buffer[:offset]),
	}, nil
}
