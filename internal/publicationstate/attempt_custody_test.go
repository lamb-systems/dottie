package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPublicationAttemptCreatePersistsExactCandidateWithAnonymousCustody(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	observation := f.observation(1)
	view := attemptView(f, observation, true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, proposal.AttemptID, attempt.ID)
	assert.Equal(t, AttemptPrepared, attempt.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, attempt.Outcome)
	assert.Equal(t, AvailabilityAvailable, attempt.Availability)
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, payloadBasename(f.payload), entries[0].Name())
	info, err := entries[0].Info()
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	material, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidate.SnapshotRecord, material.SnapshotRecord)
	assert.Equal(t, candidate.HeadRecord, material.HeadRecord)
	assert.Equal(t, candidate.Payload, material.Payload)
	assert.Equal(t, proposal.CandidateRecordCID, mustRecordCID(t, candidate.SnapshotRecord))
	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, attempt.ID, active.ID)
}

func TestPublicationAttemptRestartRetainsExactCandidate(t *testing.T) {
	for _, kind := range []string{"genesis", "successor"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			sourceDir := t.TempDir()
			sourcePath := filepath.Join(sourceDir, "init.lua")
			sourceA := []byte("synthetic source A with distinct packed content")
			sourceB := []byte("synthetic source B with different packed content")
			require.NoError(t, os.WriteFile(sourcePath, sourceA, 0o600))
			f.payload = packFixtureSource(t, f.payload, sourcePath)
			f.appendRecord(t, 0)
			if kind == "successor" {
				f.appendRecord(t, 1)
			}
			store, directory := newStore(t, f)
			var view SuppliedRepositoryView
			sequence := uint64(0)
			if kind == "successor" {
				floorObservation := f.observation(1)
				first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
				require.NoError(t, err)
				_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
				require.NoError(t, err)
				view = attemptView(f, floorObservation, false)
				sequence = 1
			} else {
				view = attemptView(f, f.observation(1), true)
			}
			candidateA := attemptCandidate(f, sequence)
			review := attemptReview()
			proposal, err := store.PrepareAttempt(ctx, candidateA, view, review)
			require.NoError(t, err)
			attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidateA, view, review, proposal.Confirmation)
			require.NoError(t, err)
			require.NoError(t, store.Close())

			require.NoError(t, os.WriteFile(sourcePath, sourceB, 0o600))
			candidateB := candidateWithPayload(t, candidateA, f.binding, packFixtureSource(t, candidateA.Payload, sourcePath))
			assert.NotEqual(t, candidateA.Payload, candidateB.Payload)
			require.NoError(t, publication.VerifyPayload(candidateB.Payload, blobForCandidate(t, candidateB)))
			_, err = publication.DecodePayload(candidateB.Payload, blobForCandidate(t, candidateB))
			require.NoError(t, err)
			require.NoError(t, os.Remove(sourcePath))

			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			loaded, err := reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, attempt.SnapshotRecordCID, loaded.SnapshotRecordCID)
			material, err := reopened.ReadCandidate(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, candidateA.SnapshotRecord, material.SnapshotRecord)
			assert.Equal(t, candidateA.HeadRecord, material.HeadRecord)
			assert.Equal(t, candidateA.Payload, material.Payload)
			assert.NotEqual(t, candidateB.Payload, material.Payload)
			_, err = reopened.PrepareAttempt(ctx, candidateB, view, review)
			requireErrorMetadata(t, err, ErrConsent, StageAttempt, ReasonActiveAttempt)

			uploadProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
			require.NoError(t, err)
			upload, err := reopened.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, candidateA.Payload, upload.Payload)
			submissionProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
			require.NoError(t, err)
			submission, err := reopened.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, candidateA.SnapshotRecord, submission.SnapshotRecord)
			assert.Equal(t, candidateA.HeadRecord, submission.HeadRecord)
		})
	}
}

func TestPublicationAttemptReuseSyncPrecedesReferenceCommit(t *testing.T) {
	for _, reuse := range []string{"orphan", "registered-shared"} {
		t.Run(reuse, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			candidate := attemptCandidate(f, 0)
			view := attemptView(f, f.observation(1), true)
			review := attemptReview()
			var store *Store
			var directory string
			if reuse == "orphan" {
				directory = t.TempDir()
				require.NoError(t, os.Chmod(directory, 0o700))
				payloadDirectory := filepath.Join(directory, payloadDirectoryName)
				require.NoError(t, os.Mkdir(payloadDirectory, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(payloadDirectory, payloadBasename(candidate.Payload)), candidate.Payload, 0o600))
				var err error
				store, err = Open(directory, f.binding)
				require.NoError(t, err)
			} else {
				store, directory = newStore(t, f)
				firstProposal, err := store.PrepareAttempt(ctx, candidate, view, review)
				require.NoError(t, err)
				first, err := store.CreateAttempt(ctx, firstProposal.StateToken, candidate, view, review, firstProposal.Confirmation)
				require.NoError(t, err)
				abandon, err := store.PrepareAbandon(ctx, first.ID, nil)
				require.NoError(t, err)
				_, err = store.AbandonAttempt(ctx, first.ID, abandon.StateToken, nil, abandon.Confirmation)
				require.NoError(t, err)
				candidate = candidateWithPublicationID(t, candidate, [16]byte{0x55})
			}
			t.Cleanup(func() { _ = store.Close() })
			sentinel := filepath.Join(directory, "sync-sentinel")
			sentinelBytes := []byte("unchanged custody sync sentinel")
			require.NoError(t, os.WriteFile(sentinel, sentinelBytes, 0o600))
			proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
			require.NoError(t, err)

			var syncOrder []string
			originalSync := store.custodyOps.sync
			store.custodyOps.sync = func(fd int) error {
				var stat unix.Stat_t
				if err := unix.Fstat(fd, &stat); err != nil {
					return err
				}
				kind := ""
				switch stat.Mode & unix.S_IFMT {
				case unix.S_IFREG:
					kind = "file"
				case unix.S_IFDIR:
					var root unix.Stat_t
					if err := unix.Fstat(store.rootFD, &root); err != nil {
						return err
					}
					if stat.Dev == root.Dev && stat.Ino == root.Ino {
						kind = "root"
					} else if store.payloadFD >= 0 {
						var payload unix.Stat_t
						if err := unix.Fstat(store.payloadFD, &payload); err != nil {
							return err
						}
						if stat.Dev != payload.Dev || stat.Ino != payload.Ino {
							return errors.New("unexpected sync directory")
						}
						kind = "payload-directory"
					} else {
						return errors.New("unexpected sync directory")
					}
				default:
					return errors.New("unexpected sync object")
				}
				syncOrder = append(syncOrder, kind)
				return originalSync(fd)
			}
			commitSeen := false
			store.commitTransaction = func(tx *sql.Tx) error {
				orderOK := assert.GreaterOrEqual(t, len(syncOrder), 3, "file, payload-directory, and root fsyncs must precede reference commit")
				if orderOK {
					orderOK = assert.Equal(t, []string{"file", "payload-directory", "root"}, syncOrder[:3], "custody fsync order must precede reference commit")
				}
				var refs int
				refErr := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", proposal.AttemptID[:]).Scan(&refs)
				refsOK := assert.NoError(t, refErr) && assert.Equal(t, 1, refs, "attempt reference must be in the transaction before commit")
				if !orderOK || !refsOK {
					rollbackErr := tx.Rollback()
					assert.NoError(t, rollbackErr)
					return errors.New("custody sync ordering assertion failed")
				}
				commitSeen = true
				return tx.Commit()
			}
			attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
			require.NoError(t, err)
			assert.True(t, commitSeen)
			require.GreaterOrEqual(t, len(syncOrder), 4)
			assert.Equal(t, []string{"file", "payload-directory", "root"}, syncOrder[:3])
			assert.Equal(t, proposal.AttemptID, attempt.ID)
			payload, err := os.ReadFile(filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload)))
			require.NoError(t, err)
			assert.Equal(t, candidate.Payload, payload)
			afterSentinel, err := os.ReadFile(sentinel)
			require.NoError(t, err)
			assert.Equal(t, sentinelBytes, afterSentinel)
		})
	}
}

func TestPublicationAttemptAnonymousCustodyFaultPlacement(t *testing.T) {
	faults := []struct {
		name      string
		postlink  bool
		configure func(*Store, custodyOperations)
	}{
		{"open-unsupported", false, func(store *Store, _ custodyOperations) {
			store.custodyOps.openTemp = func(int, uint32) (int, error) { return -1, unix.EOPNOTSUPP }
		}},
		{"open-error", false, func(store *Store, _ custodyOperations) {
			store.custodyOps.openTemp = func(int, uint32) (int, error) { return -1, unix.EIO }
		}},
		{"zero-progress-write", false, func(store *Store, _ custodyOperations) {
			store.custodyOps.write = func(int, []byte) (int, error) { return 0, nil }
		}},
		{"file-sync", false, nil},
		{"linked-file-sync", true, nil},
		{"payload-directory-sync", true, nil},
		{"root-sync", true, nil},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { _ = store.Close() })
			candidate := attemptCandidate(f, 0)
			view := attemptView(f, f.observation(1), true)
			review := attemptReview()
			proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
			require.NoError(t, err)
			payloadDirectory := filepath.Join(directory, payloadDirectoryName)
			beforeRows := readAttemptLogicalRows(t, store)
			sentinel := filepath.Join(directory, "sync-sentinel")
			sentinelBytes := []byte("unchanged custody fault sentinel")
			require.NoError(t, os.WriteFile(sentinel, sentinelBytes, 0o600))
			original := store.custodyOps
			if fault.configure != nil {
				fault.configure(store, original)
			} else {
				regularSyncs := 0
				payloadDirectorySynced := false
				store.custodyOps.sync = func(fd int) error {
					var stat unix.Stat_t
					if err := unix.Fstat(fd, &stat); err != nil {
						return err
					}
					switch stat.Mode & unix.S_IFMT {
					case unix.S_IFREG:
						regularSyncs++
						if fault.name == "file-sync" && regularSyncs == 1 || fault.name == "linked-file-sync" && regularSyncs == 2 {
							return unix.EIO
						}
					case unix.S_IFDIR:
						var root unix.Stat_t
						if err := unix.Fstat(store.rootFD, &root); err != nil {
							return err
						}
						if stat.Dev == root.Dev && stat.Ino == root.Ino {
							if fault.name == "root-sync" && payloadDirectorySynced {
								return unix.EIO
							}
						} else if store.payloadFD >= 0 {
							var payload unix.Stat_t
							if err := unix.Fstat(store.payloadFD, &payload); err != nil {
								return err
							}
							if stat.Dev != payload.Dev || stat.Ino != payload.Ino {
								return errors.New("unexpected sync directory")
							}
							if fault.name == "payload-directory-sync" {
								return unix.EIO
							}
							if err := original.sync(fd); err != nil {
								return err
							}
							payloadDirectorySynced = true
							return nil
						} else {
							return errors.New("unexpected sync directory")
						}
					default:
						return errors.New("unexpected sync object")
					}
					return original.sync(fd)
				}
			}
			result, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
			requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonIO)
			assert.Equal(t, Attempt{}, result)
			assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
			entries, err := os.ReadDir(payloadDirectory)
			require.NoError(t, err)
			payloadPath := filepath.Join(payloadDirectory, payloadBasename(candidate.Payload))
			if fault.postlink {
				require.Len(t, entries, 1)
				assert.Equal(t, payloadBasename(candidate.Payload), entries[0].Name())
				payloadBytes, readErr := os.ReadFile(payloadPath)
				require.NoError(t, readErr)
				assert.Equal(t, candidate.Payload, payloadBytes)
				require.NoError(t, publication.VerifyPayload(payloadBytes, blobForCandidate(t, candidate)))
			} else {
				assert.Empty(t, entries)
				_, statErr := os.Lstat(payloadPath)
				assert.ErrorIs(t, statErr, os.ErrNotExist)
			}
			afterSentinel, err := os.ReadFile(sentinel)
			require.NoError(t, err)
			assert.Equal(t, sentinelBytes, afterSentinel)
			var attempts, objects, refs int
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&refs))
			assert.Zero(t, attempts)
			assert.Zero(t, objects)
			assert.Zero(t, refs)
		})
	}
}

func TestPublicationAttemptReuseSyncsFilePayloadDirectoryAndRootBeforeReference(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	calls := 0
	originalSync := store.custodyOps.sync
	store.custodyOps.sync = func(fd int) error {
		calls++
		if calls == 3 {
			return errors.New("sync canary")
		}
		return originalSync(fd)
	}
	_, err = store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonIO)
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, payloadBasename(candidate.Payload), entries[0].Name())

	var syncOrder []string
	store.custodyOps.sync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			syncOrder = append(syncOrder, "file")
		case unix.S_IFDIR:
			if stat.Ino == rootInode(t, store.rootFD) {
				syncOrder = append(syncOrder, "root")
			} else {
				syncOrder = append(syncOrder, "payload-directory")
			}
		default:
			return errors.New("unexpected sync object")
		}
		return originalSync(fd)
	}
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, proposal.AttemptID, attempt.ID)
	require.GreaterOrEqual(t, len(syncOrder), 4)
	assert.Equal(t, []string{"file", "payload-directory", "root"}, syncOrder[:3])

	abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	_, err = store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	require.NoError(t, err)
	shared := candidateWithPublicationID(t, candidate, [16]byte{0x54})
	sharedCID, err := publication.RecordCID(shared.SnapshotRecord)
	require.NoError(t, err)
	assert.NotEqual(t, attempt.SnapshotRecordCID, sharedCID)
	sharedRecord, err := publication.DecodeSnapshot(shared.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, attempt.BlobCID, sharedRecord.Blob.CID)
	sharedView := view
	sharedProposal, err := store.PrepareAttempt(ctx, shared, sharedView, review)
	require.NoError(t, err)
	syncOrder = nil
	sharedAttempt, err := store.CreateAttempt(ctx, sharedProposal.StateToken, shared, sharedView, review, sharedProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, candidate.SnapshotKey, sharedAttempt.SnapshotKey)
	require.GreaterOrEqual(t, len(syncOrder), 4)
	assert.Equal(t, []string{"file", "payload-directory", "root"}, syncOrder[:3])
}

func TestPublicationAttemptPostlinkDatabaseAbortLeavesReusableCompleteOrphan(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "CREATE TEMP TRIGGER abort_attempt_insert BEFORE INSERT ON main.publication_attempts BEGIN SELECT RAISE(ABORT,'attempt-row-canary'); END")
	require.NoError(t, err)
	_, err = store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageAttempt, ReasonIO)
	assert.NotContains(t, err.Error(), "attempt-row-canary")
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, payloadBasename(candidate.Payload), entries[0].Name())
	var attempts, objects int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	assert.Equal(t, 0, attempts)
	assert.Equal(t, 0, objects)
	_, err = store.conn.ExecContext(ctx, "DROP TRIGGER abort_attempt_insert")
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, proposal.AttemptID, attempt.ID)
	var registered int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&registered))
	assert.Equal(t, 1, registered)
}

func TestPublicationAttemptPrelinkFaultsLeaveNoNamedPartialFile(t *testing.T) {
	for _, fault := range []string{"short-write", "no-space", "file-sync", "link", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			defer store.Close()
			candidate := attemptCandidate(f, 0)
			view := attemptView(f, f.observation(1), true)
			review := attemptReview()
			proposal, err := store.PrepareAttempt(context.Background(), candidate, view, review)
			require.NoError(t, err)
			original := store.custodyOps
			switch fault {
			case "short-write":
				writes := 0
				store.custodyOps.write = func(fd int, data []byte) (int, error) {
					writes++
					if writes == 1 {
						return original.write(fd, data[:len(data)/2])
					}
					return 0, unix.EIO
				}
			case "no-space":
				store.custodyOps.write = func(int, []byte) (int, error) { return 0, unix.ENOSPC }
			case "file-sync":
				store.custodyOps.sync = func(fd int) error {
					var stat unix.Stat_t
					if err := unix.Fstat(fd, &stat); err != nil {
						return err
					}
					if stat.Mode&unix.S_IFMT == unix.S_IFREG {
						return unix.EIO
					}
					return original.sync(fd)
				}
			case "link":
				store.custodyOps.link = func(int, int, string) error { return unix.EOPNOTSUPP }
			case "cancel":
				writes := 0
				store.custodyOps.write = func(fd int, data []byte) (int, error) {
					writes++
					if writes == 1 {
						written, err := original.write(fd, data[:len(data)/2])
						cancel()
						return written, err
					}
					return original.write(fd, data)
				}
			}
			_, err = store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
			require.Error(t, err)
			entries, readErr := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
			require.NoError(t, readErr)
			assert.Empty(t, entries)
			var rows int
			require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM publication_attempts").Scan(&rows))
			assert.Equal(t, 0, rows)
		})
	}
}

func TestPublicationAttemptProcessExitBeforeLinkLeavesNoNamedCandidate(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	require.NoError(t, store.Close())
	command := exec.Command(os.Args[0], "-test.run=^TestPublicationAttemptExitBeforeLinkHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "PUBLICATION_ATTEMPT_EXIT_DIR="+directory)
	err := command.Run()
	var exitError *exec.ExitError
	require.ErrorAs(t, err, &exitError)
	assert.Equal(t, 73, exitError.ExitCode())
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	assert.Empty(t, entries)
	check, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer check.Close()
	var attempts, objects int
	require.NoError(t, check.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
	require.NoError(t, check.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	assert.Equal(t, 0, attempts)
	assert.Equal(t, 0, objects)
}

func TestPublicationAttemptExitBeforeLinkHelper(t *testing.T) {
	directory := os.Getenv("PUBLICATION_ATTEMPT_EXIT_DIR")
	if directory == "" {
		return
	}
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(context.Background(), candidate, view, review)
	require.NoError(t, err)
	normalSync := store.custodyOps.sync
	store.custodyOps.sync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFREG {
			os.Exit(73)
		}
		return normalSync(fd)
	}
	_, err = store.CreateAttempt(context.Background(), proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.Error(t, err)
}

func TestPublicationAttemptNewFilesRespectPrivateModesUnderRestrictiveUmask(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestPublicationAttemptUmaskHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "PUBLICATION_ATTEMPT_UMASK_HELPER=1")
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
}

func TestPublicationAttemptUmaskHelper(t *testing.T) {
	if os.Getenv("PUBLICATION_ATTEMPT_UMASK_HELPER") != "1" {
		return
	}
	baseDirectory := t.TempDir()
	old := syscall.Umask(0o277)
	defer syscall.Umask(old)
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	directory := filepath.Join(baseDirectory, "state")
	require.NoError(t, os.Mkdir(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(context.Background(), candidate, view, review)
	require.NoError(t, err)
	_, err = store.CreateAttempt(context.Background(), proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	for _, path := range []string{filepath.Join(directory, "publication.db"), filepath.Join(directory, payloadDirectoryName), filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))} {
		info, err := os.Lstat(path)
		require.NoError(t, err)
		if info.IsDir() {
			assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
		} else {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
	}
}

func TestPublicationAttemptRejectsUnsafePayloadObjectsWithoutRepair(t *testing.T) {
	for _, damage := range []string{"fifo", "directory", "hardlink", "mode", "special-mode"} {
		t.Run(damage, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			candidate := attemptCandidate(f, 0)
			view := attemptView(f, f.observation(1), true)
			review := attemptReview()
			proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
			require.NoError(t, err)
			attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
			require.NoError(t, err)
			require.NoError(t, store.Close())
			path := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
			sentinel := filepath.Join(directory, "sentinel")
			switch damage {
			case "fifo":
				require.NoError(t, os.Remove(path))
				require.NoError(t, syscall.Mkfifo(path, 0o600))
			case "directory":
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Mkdir(path, 0o700))
			case "hardlink":
				require.NoError(t, os.Link(path, sentinel))
			case "mode":
				require.NoError(t, os.Chmod(path, 0o644))
			case "special-mode":
				require.NoError(t, os.Chmod(path, os.ModeSetuid|0o600))
			}
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			_, err = reopened.ReadCandidate(ctx, attempt.ID)
			requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateUnsafe)
			if damage == "mode" || damage == "special-mode" {
				info, statErr := os.Stat(path)
				require.NoError(t, statErr)
				if damage == "mode" {
					assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
				} else {
					assert.NotZero(t, info.Mode()&os.ModeSetuid)
				}
			}
		})
	}
}

func packFixtureSource(t *testing.T, packed []byte, sourcePath string) []byte {
	t.Helper()
	content, err := os.ReadFile(sourcePath)
	require.NoError(t, err)
	return packFixtureContent(t, packed, content)
}

func packFixtureContent(t *testing.T, packed, content []byte) []byte {
	t.Helper()
	snapshot, err := vault.UnpackPayload(packed)
	require.NoError(t, err)
	require.NotEmpty(t, snapshot.Entries)
	require.NotNil(t, snapshot.Entries[0].File)
	snapshot.Entries[0].File.Content = bytes.Clone(content)
	blob, err := vault.Pack(snapshot)
	require.NoError(t, err)
	return bytes.Clone(blob.Payload)
}

func candidateWithPayload(t *testing.T, candidate CandidateInput, binding Binding, payload []byte) CandidateInput {
	t.Helper()
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	record.Blob = publication.BlobReference{CID: blobCID, Size: uint64(len(payload))}
	snapshotRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotRaw)
	require.NoError(t, err)
	headRaw, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: record.PublicationSeq, SnapshotCID: snapshotCID, BlobCID: blobCID})
	require.NoError(t, err)
	return CandidateInput{SnapshotKey: candidate.SnapshotKey, SnapshotRecord: snapshotRaw, HeadRecord: headRaw, Payload: bytes.Clone(payload)}
}

func candidateWithPublicationID(t *testing.T, candidate CandidateInput, id [16]byte) CandidateInput {
	t.Helper()
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	record.PublicationID = id
	snapshotRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotRaw)
	require.NoError(t, err)
	headRaw, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: record.Vault, PublicationSeq: record.PublicationSeq, SnapshotCID: snapshotCID, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	return CandidateInput{SnapshotKey: candidate.SnapshotKey, SnapshotRecord: snapshotRaw, HeadRecord: headRaw, Payload: bytes.Clone(candidate.Payload)}
}

func blobForCandidate(t *testing.T, candidate CandidateInput) publication.BlobReference {
	t.Helper()
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	return record.Blob
}

func rootInode(t *testing.T, fd int) uint64 {
	t.Helper()
	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(fd, &stat))
	return stat.Ino
}

func mustRecordCID(t *testing.T, raw []byte) []byte {
	t.Helper()
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	return cid
}
