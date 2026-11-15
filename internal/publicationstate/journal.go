package publicationstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/lamb-systems/dottie/internal/platform"
	"golang.org/x/sys/unix"
)

const journalApplicationID = 0x44544a31

const (
	StageJournalOpen Stage = "journal_open"
	StageJournal     Stage = "journal"

	ReasonJournalEntry       Reason = "journal_entry"
	ReasonJournalBackup      Reason = "journal_backup"
	ReasonJournalObservation Reason = "journal_observation"
	ReasonJournalBlocked     Reason = "journal_blocked"
	ReasonJournalIntent      Reason = "journal_intent"
)

const (
	journalDatabaseName = "journal.db"
	journalLockName     = "journal.db.lock"
	journalWalName      = "journal.db-wal"
	journalShmName      = "journal.db-shm"
	journalLeaseName    = "journal.db.apply.lock"
)

const (
	journalSchemaVersion        = 1
	journalMaxBackupBytes int64 = 8 << 20
	journalMaxTotalBytes  int64 = 256 << 20
	journalMaxEntries           = 4096
	journalMaxPathBytes         = 4096
	journalMaxTextBytes         = 64
)

const (
	journalBackupsStatement = "CREATE TABLE backups (digest BLOB PRIMARY KEY, size INTEGER NOT NULL, data BLOB NOT NULL)"
	journalEntriesStatement = "CREATE TABLE journal (entry INTEGER PRIMARY KEY, vault BLOB NOT NULL, operation TEXT NOT NULL, stage TEXT NOT NULL, state TEXT NOT NULL, destination_dir BLOB NOT NULL, destination_path TEXT NOT NULL, anchor_path BLOB NOT NULL, anchor_device INTEGER NOT NULL, anchor_inode INTEGER NOT NULL, preimage_digest BLOB, preimage_size INTEGER, postimage_digest BLOB, postimage_size INTEGER, backup_digest BLOB REFERENCES backups(digest), seen_floor_revision INTEGER NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL)"
	journalLiveStatement    = "CREATE INDEX journal_live ON journal(state, stage)"
)

var journalSchemaStatements = []string{journalBackupsStatement, journalEntriesStatement, journalLiveStatement}

var journalSchemaObjects = map[string]string{
	"backups":      "table",
	"journal":      "table",
	"journal_live": "index",
}

type JournalState string
type JournalStage string
type JournalOutcome string

const (
	JournalStatePending       JournalState = "pending"
	JournalStateApplied       JournalState = "applied"
	JournalStateFailed        JournalState = "failed"
	JournalStateIndeterminate JournalState = "indeterminate"
	JournalStateRolledBack    JournalState = "rolled-back"
)

const (
	JournalStageApplyPending     JournalStage = "apply-pending"
	JournalStageApplyComplete    JournalStage = "apply-complete"
	JournalStageApplyFailed      JournalStage = "apply-failed"
	JournalStageIndeterminate    JournalStage = "indeterminate"
	JournalStageRollbackPending  JournalStage = "rollback-pending"
	JournalStageRollbackComplete JournalStage = "rollback-complete"
)

const (
	JournalOutcomeApplied         JournalOutcome = "applied"
	JournalOutcomeFailed          JournalOutcome = "failed"
	JournalOutcomeRolledBack      JournalOutcome = "rolled-back"
	JournalOutcomeIndeterminate   JournalOutcome = "indeterminate"
	JournalOutcomeRollbackPending JournalOutcome = "rollback-pending"
	JournalOutcomeUnobserved      JournalOutcome = "unobserved"
)

type ObservedFile struct {
	Present bool
	Digest  [32]byte
	Size    uint64
}

type JournalAnchor struct {
	Path   string
	Device int64
	Inode  int64
}

func NewJournalAnchor(path string, info os.FileInfo) (JournalAnchor, bool) {
	if info == nil {
		return JournalAnchor{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return JournalAnchor{}, false
	}
	return JournalAnchor{Path: path, Device: int64(stat.Dev), Inode: int64(stat.Ino)}, true
}

type JournalIntent struct {
	Vault             [32]byte
	Operation         string
	DestinationDir    string
	DestinationPath   string
	Anchor            JournalAnchor
	Preimage          *ObservedFile
	PreimageBytes     []byte
	Postimage         ObservedFile
	SeenFloorRevision uint64
}

type JournalEntry struct {
	Entry             int64
	Vault             [32]byte
	Operation         string
	Stage             JournalStage
	State             JournalState
	DestinationDir    string
	DestinationPath   string
	Anchor            JournalAnchor
	Preimage          *ObservedFile
	Postimage         ObservedFile
	BackupDigest      *[32]byte
	SeenFloorRevision uint64
	Created           int64
	Updated           int64
}

type JournalLease struct {
	lock *platform.Lock
}

type JournalResolution struct {
	Entry   int64
	Outcome JournalOutcome
}

type JournalBlockedError struct {
	Entry             int64
	State             JournalState
	Stage             JournalStage
	SeenFloorRevision uint64
	FloorRevision     uint64
}

func (e *JournalBlockedError) Error() string {
	return fmt.Sprintf("publication state: %s/%s/%s: entry %d is %s/%s at seen floor revision %d above %d", className(ErrContinuity), StageJournal, ReasonJournalBlocked, e.Entry, e.State, e.Stage, e.SeenFloorRevision, e.FloorRevision)
}

func (e *JournalBlockedError) Unwrap() error {
	return classified(ErrContinuity, StageJournal, ReasonJournalBlocked)
}

type Journal struct {
	mu        sync.Mutex
	db        *sql.DB
	conn      *sql.Conn
	lock      *platform.Lock
	directory string
	rootFD    int
	closed    bool
}

func ObservedJournalFile(data []byte) ObservedFile {
	return ObservedFile{Present: true, Digest: sha256.Sum256(data), Size: uint64(len(data))}
}

func (e JournalEntry) Path() string {
	return filepath.Join(e.DestinationDir, e.DestinationPath)
}

func OpenJournal(directory string) (*Journal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, classified(ErrInvalid, StageJournalOpen, ReasonBinding)
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return nil, classified(ErrInvalid, StageJournalOpen, ReasonBinding)
	}
	journal := &Journal{directory: directory, rootFD: -1}
	transferred := false
	defer func() {
		if !transferred {
			_ = journal.Close()
		}
	}()
	rootFD, err := openStoreRoot(directory)
	if err != nil {
		return nil, classified(ErrInvalid, StageJournalOpen, ReasonBinding)
	}
	journal.rootFD = rootFD
	if err := preflightJournalFiles(directory); err != nil {
		return nil, classified(ErrInvalid, StageJournalOpen, ReasonBinding)
	}
	lock, err := platform.LockFile(filepath.Join(directory, journalLockName))
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, classified(ErrLocked, StageJournalOpen, ReasonLocked)
		}
		return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
	}
	journal.lock = lock
	if err := preflightJournalFiles(directory); err != nil {
		return nil, classified(ErrInvalid, StageJournalOpen, ReasonBinding)
	}
	databasePath := filepath.Join(directory, journalDatabaseName)
	created, err := createDatabaseFile(databasePath)
	if err != nil {
		return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
	}
	if created {
		if err := unix.Fsync(journal.rootFD); err != nil {
			return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
		}
	}
	probe, err := probeJournalSchema(databasePath)
	if err != nil {
		var classifiedErr *Error
		if errors.As(err, &classifiedErr) {
			return nil, err
		}
		return nil, storageFailure(context.Background(), StageJournalOpen, err)
	}
	if !probe.initial && !probe.recognized {
		return nil, classified(ErrSchema, StageJournalOpen, ReasonSchema)
	}
	db, err := sql.Open("sqlite", dbDSN(databasePath, false))
	if err != nil {
		return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	journal.db = db
	conn, err := db.Conn(context.Background())
	if err != nil {
		return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
	}
	journal.conn = conn
	if err := configureConnection(context.Background(), conn); err != nil {
		return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
	}
	if probe.initial {
		if err := initializeJournalSchema(context.Background(), conn, journal.rootFD); err != nil {
			return nil, schemaOrStorageError(context.Background(), StageJournalOpen, err)
		}
	} else if err := checkJournalSchemaVersion(context.Background(), conn); err != nil {
		return nil, schemaOrStorageError(context.Background(), StageJournalOpen, err)
	}
	if created {
		if err := os.Chmod(databasePath, 0o600); err != nil {
			return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
		}
	}
	if err := secureJournalSidecars(directory); err != nil {
		return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
	}
	if err := unix.Fsync(journal.rootFD); err != nil {
		return nil, classified(ErrStorage, StageJournalOpen, ReasonIO)
	}
	if err := preflightJournalFiles(directory); err != nil {
		return nil, classified(ErrInvalid, StageJournalOpen, ReasonBinding)
	}
	transferred = true
	return journal, nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	var failed bool
	if j.conn != nil && j.conn.Close() != nil {
		failed = true
	}
	if j.db != nil && j.db.Close() != nil {
		failed = true
	}
	if j.lock != nil && j.lock.Close() != nil {
		failed = true
	}
	if j.rootFD >= 0 && unix.Close(j.rootFD) != nil {
		failed = true
	}
	j.rootFD = -1
	if failed {
		return classified(ErrStorage, StageJournal, ReasonIO)
	}
	return nil
}

func (j *Journal) AcquireApplyLease(ctx context.Context) (*JournalLease, error) {
	if err := j.checkContext(ctx, StageJournal); err != nil {
		return nil, err
	}
	lock, err := platform.LockFile(filepath.Join(j.directory, journalLeaseName))
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, classified(ErrLocked, StageJournal, ReasonLocked)
		}
		return nil, classified(ErrStorage, StageJournal, ReasonIO)
	}
	return &JournalLease{lock: lock}, nil
}

func (l *JournalLease) Close() error {
	if l == nil || l.lock == nil {
		return nil
	}
	lock := l.lock
	l.lock = nil
	if err := lock.Close(); err != nil {
		return classified(ErrStorage, StageJournal, ReasonIO)
	}
	return nil
}

func (j *Journal) EntryCount(ctx context.Context) (int64, error) {
	if err := j.checkContext(ctx, StageJournal); err != nil {
		return 0, err
	}
	count, err := queryInt64(ctx, j.conn, "SELECT count(*) FROM journal")
	if err != nil {
		return 0, queryReadError(ctx, StageJournal, err)
	}
	return count, nil
}

func (j *Journal) checkContext(ctx context.Context, stage Stage) error {
	if err := ctx.Err(); err != nil {
		return canceled(stage, err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return classified(ErrClosed, stage, ReasonClosed)
	}
	return nil
}

func (j *Journal) withTx(ctx context.Context, stage Stage, fn func(*sql.Tx) error) error {
	if err := j.checkContext(ctx, stage); err != nil {
		return err
	}
	tx, err := j.conn.BeginTx(ctx, nil)
	if err != nil {
		return storageFailure(ctx, stage, err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return canceled(stage, ctxErr)
		}
		var classifiedErr *Error
		if errors.As(err, &classifiedErr) {
			return err
		}
		return storageFailure(ctx, stage, err)
	}
	if err := ctx.Err(); err != nil {
		_ = tx.Rollback()
		return canceled(stage, err)
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return classified(ErrStorage, stage, ReasonCommitUnknown)
	}
	return nil
}

func (j *Journal) BeginJournal(ctx context.Context, intent JournalIntent) (JournalEntry, error) {
	if err := validateJournalIntent(intent); err != nil {
		return JournalEntry{}, err
	}
	var written JournalEntry
	err := j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
		rows, err := queryInt64(ctx, tx, "SELECT count(*) FROM journal")
		if err != nil {
			return queryReadError(ctx, StageJournal, err)
		}
		if rows >= journalMaxEntries {
			return classified(ErrLimit, StageJournal, ReasonCapacity)
		}
		var backupSize int64
		if intent.Preimage != nil {
			backupSize = int64(len(intent.PreimageBytes))
			existing, found, err := readBackupSize(ctx, tx, intent.Preimage.Digest)
			if err != nil {
				return err
			}
			if found {
				if existing != backupSize {
					return classified(ErrSchema, StageJournal, ReasonCorrupt)
				}
				stored, err := readBackupData(ctx, tx, intent.Preimage.Digest, backupSize)
				if err != nil {
					return err
				}
				if sha256.Sum256(stored) != intent.Preimage.Digest {
					return classified(ErrSchema, StageJournal, ReasonCorrupt)
				}
			} else {
				total, err := queryInt64(ctx, tx, "SELECT COALESCE(SUM(size),0) FROM backups")
				if err != nil {
					return queryReadError(ctx, StageJournal, err)
				}
				if total < 0 || backupSize < 0 || total > journalMaxTotalBytes-backupSize {
					return classified(ErrLimit, StageJournal, ReasonCapacity)
				}
				if _, err := tx.ExecContext(ctx, "INSERT INTO backups(digest,size,data) VALUES (?,?,?)", intent.Preimage.Digest[:], backupSize, intent.PreimageBytes); err != nil {
					return err
				}
			}
		}
		now := time.Now().Unix()
		var preimageDigest, preimageSize, backupDigest, postimageDigest, postimageSize any
		if intent.Preimage != nil {
			preimageDigest = intent.Preimage.Digest[:]
			preimageSize = int64(intent.Preimage.Size)
			backupDigest = intent.Preimage.Digest[:]
		}
		if intent.Postimage.Present {
			postimageDigest = intent.Postimage.Digest[:]
			postimageSize = int64(intent.Postimage.Size)
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO journal(entry,vault,operation,stage,state,destination_dir,destination_path,anchor_path,anchor_device,anchor_inode,preimage_digest,preimage_size,postimage_digest,postimage_size,backup_digest,seen_floor_revision,created,updated) VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			intent.Vault[:], intent.Operation, string(JournalStageApplyPending), string(JournalStatePending),
			[]byte(intent.DestinationDir), intent.DestinationPath,
			[]byte(intent.Anchor.Path), intent.Anchor.Device, intent.Anchor.Inode,
			preimageDigest, preimageSize,
			postimageDigest, postimageSize, backupDigest, int64(intent.SeenFloorRevision), now, now)
		if err != nil {
			return err
		}
		id, err := result.LastInsertId()
		if err != nil {
			return err
		}
		written, err = readJournalEntry(ctx, tx, id)
		return err
	})
	if err != nil {
		return JournalEntry{}, err
	}
	return written, nil
}

func (j *Journal) CompleteJournal(ctx context.Context, entry JournalEntry, observed ObservedFile) error {
	if err := validateObservedFile(observed, StageJournal); err != nil {
		return err
	}
	return j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
		current, err := readJournalEntry(ctx, tx, entry.Entry)
		if err != nil {
			return err
		}
		if current.State != JournalStatePending || current.Stage != JournalStageApplyPending {
			return classified(ErrInvalid, StageJournal, ReasonTransition)
		}
		if !observedFileMatches(current.Postimage, observed) {
			return classified(ErrInvalid, StageJournal, ReasonJournalObservation)
		}
		return transitionJournalEntry(ctx, tx, entry.Entry, JournalStatePending, JournalStageApplyPending, JournalStateApplied, JournalStageApplyComplete)
	})
}

func (j *Journal) MarkIndeterminate(ctx context.Context, entry JournalEntry) error {
	return j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
		return transitionJournalEntry(ctx, tx, entry.Entry, JournalStatePending, JournalStageApplyPending, JournalStateIndeterminate, JournalStageIndeterminate)
	})
}

func (j *Journal) BeginRollback(ctx context.Context, entry JournalEntry) error {
	return j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
		return transitionJournalEntry(ctx, tx, entry.Entry, JournalStateApplied, JournalStageApplyComplete, JournalStateApplied, JournalStageRollbackPending)
	})
}

func (j *Journal) CompleteRollback(ctx context.Context, entry JournalEntry, observed ObservedFile) error {
	if err := validateObservedFile(observed, StageJournal); err != nil {
		return err
	}
	return j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
		current, err := readJournalEntry(ctx, tx, entry.Entry)
		if err != nil {
			return err
		}
		if current.State != JournalStateApplied || current.Stage != JournalStageRollbackPending {
			return classified(ErrInvalid, StageJournal, ReasonTransition)
		}
		if !observedPreimageMatches(current.Preimage, observed) {
			return classified(ErrInvalid, StageJournal, ReasonJournalObservation)
		}
		return transitionJournalEntry(ctx, tx, entry.Entry, JournalStateApplied, JournalStageRollbackPending, JournalStateRolledBack, JournalStageRollbackComplete)
	})
}

func (j *Journal) ResolveIndeterminate(ctx context.Context, entry JournalEntry, observed ObservedFile) (JournalState, error) {
	if err := validateObservedFile(observed, StageJournal); err != nil {
		return "", err
	}
	var resolved JournalState
	err := j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
		current, err := readJournalEntry(ctx, tx, entry.Entry)
		if err != nil {
			return err
		}
		if current.State != JournalStateIndeterminate {
			return classified(ErrInvalid, StageJournal, ReasonTransition)
		}
		switch {
		case observedFileMatches(current.Postimage, observed):
			resolved = JournalStateApplied
			return transitionJournalEntry(ctx, tx, entry.Entry, JournalStateIndeterminate, JournalStageIndeterminate, JournalStateApplied, JournalStageApplyComplete)
		case observedPreimageMatches(current.Preimage, observed):
			resolved = JournalStateFailed
			return transitionJournalEntry(ctx, tx, entry.Entry, JournalStateIndeterminate, JournalStageIndeterminate, JournalStateFailed, JournalStageApplyFailed)
		default:
			return classified(ErrInvalid, StageJournal, ReasonJournalObservation)
		}
	})
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func (j *Journal) CheckAdmission(ctx context.Context, floorRevision uint64) error {
	if err := j.checkContext(ctx, StageJournal); err != nil {
		return err
	}
	rows, err := j.conn.QueryContext(ctx, "SELECT entry,state,stage,seen_floor_revision FROM journal WHERE state IN (?,?,?) ORDER BY entry", string(JournalStatePending), string(JournalStateApplied), string(JournalStateIndeterminate))
	if err != nil {
		return storageFailure(ctx, StageJournal, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var entryValue, stateValue, stageValue, seenValue any
		if err := rows.Scan(&entryValue, &stateValue, &stageValue, &seenValue); err != nil {
			return storageFailure(ctx, StageJournal, err)
		}
		id, idOK := rawInt64(entryValue)
		seen, seenOK := rawInt64(seenValue)
		stateText, stateOK := rawText(stateValue)
		stageText, stageOK := rawText(stageValue)
		if !idOK || !seenOK || !stateOK || !stageOK || seen < 0 {
			return classified(ErrSchema, StageJournal, ReasonCorrupt)
		}
		state := JournalState(stateText)
		stage := JournalStage(stageText)
		if !journalPairLegal(state, stage) {
			return classified(ErrSchema, StageJournal, ReasonCorrupt)
		}
		blocking := state != JournalStateApplied || stage == JournalStageRollbackPending || uint64(seen) > floorRevision
		if blocking {
			return &JournalBlockedError{Entry: id, State: state, Stage: stage, SeenFloorRevision: uint64(seen), FloorRevision: floorRevision}
		}
	}
	if err := rows.Err(); err != nil {
		return storageFailure(ctx, StageJournal, err)
	}
	return nil
}

func (j *Journal) ResolveInterrupted(ctx context.Context, observe func(JournalEntry) (ObservedFile, error)) ([]JournalResolution, error) {
	if observe == nil {
		return nil, classified(ErrInvalid, StageJournal, ReasonBinding)
	}
	if err := j.checkContext(ctx, StageJournal); err != nil {
		return nil, err
	}
	entries, err := j.liveEntries(ctx)
	if err != nil {
		return nil, err
	}
	resolutions := make([]JournalResolution, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, canceled(StageJournal, err)
		}
		resolution := JournalResolution{Entry: entry.Entry, Outcome: JournalOutcomeUnobserved}
		observed, observeErr := observe(entry)
		if observeErr == nil && validateObservedFile(observed, StageJournal) == nil {
			resolution.Outcome, err = j.resolveObserved(ctx, entry, observed)
			if err != nil {
				return nil, err
			}
		}
		resolutions = append(resolutions, resolution)
	}
	return resolutions, nil
}

func (j *Journal) resolveObserved(ctx context.Context, entry JournalEntry, observed ObservedFile) (JournalOutcome, error) {
	postimage := observedFileMatches(entry.Postimage, observed)
	preimage := observedPreimageMatches(entry.Preimage, observed)
	switch entry.State {
	case JournalStatePending:
		switch {
		case postimage:
			return JournalOutcomeApplied, j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
				return transitionJournalEntry(ctx, tx, entry.Entry, JournalStatePending, JournalStageApplyPending, JournalStateApplied, JournalStageApplyComplete)
			})
		case preimage:
			return JournalOutcomeFailed, j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
				return transitionJournalEntry(ctx, tx, entry.Entry, JournalStatePending, JournalStageApplyPending, JournalStateFailed, JournalStageApplyFailed)
			})
		default:
			return JournalOutcomeIndeterminate, j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
				return transitionJournalEntry(ctx, tx, entry.Entry, JournalStatePending, JournalStageApplyPending, JournalStateIndeterminate, JournalStageIndeterminate)
			})
		}
	case JournalStateIndeterminate:
		switch {
		case postimage:
			return JournalOutcomeApplied, j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
				return transitionJournalEntry(ctx, tx, entry.Entry, JournalStateIndeterminate, JournalStageIndeterminate, JournalStateApplied, JournalStageApplyComplete)
			})
		case preimage:
			return JournalOutcomeFailed, j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
				return transitionJournalEntry(ctx, tx, entry.Entry, JournalStateIndeterminate, JournalStageIndeterminate, JournalStateFailed, JournalStageApplyFailed)
			})
		default:
			return JournalOutcomeIndeterminate, nil
		}
	case JournalStateApplied:
		if preimage {
			return JournalOutcomeRolledBack, j.withTx(ctx, StageJournal, func(tx *sql.Tx) error {
				return transitionJournalEntry(ctx, tx, entry.Entry, JournalStateApplied, JournalStageRollbackPending, JournalStateRolledBack, JournalStageRollbackComplete)
			})
		}
		return JournalOutcomeRollbackPending, nil
	default:
		return "", classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
}

func (j *Journal) BackupBytes(ctx context.Context, digest [32]byte) ([]byte, error) {
	if err := j.checkContext(ctx, StageJournal); err != nil {
		return nil, err
	}
	var sizeValue, lengthValue any
	err := j.conn.QueryRowContext(ctx, "SELECT size,length(data) FROM backups WHERE digest=?", digest[:]).Scan(&sizeValue, &lengthValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, classified(ErrInvalid, StageJournal, ReasonJournalBackup)
	}
	if err != nil {
		return nil, storageFailure(ctx, StageJournal, err)
	}
	size, sizeOK := rawInt64(sizeValue)
	length, lengthOK := rawInt64(lengthValue)
	if !sizeOK || !lengthOK || size < 0 || size > journalMaxBackupBytes || length != size {
		return nil, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	var dataValue any
	if err := j.conn.QueryRowContext(ctx, "SELECT data FROM backups WHERE digest=?", digest[:]).Scan(&dataValue); err != nil {
		return nil, storageFailure(ctx, StageJournal, err)
	}
	data, dataOK := rawBytes(dataValue)
	if !dataOK || int64(len(data)) != size {
		return nil, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	if sha256.Sum256(data) != digest {
		return nil, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	return bytes.Clone(data), nil
}

func (j *Journal) liveEntries(ctx context.Context) ([]JournalEntry, error) {
	rows, err := j.conn.QueryContext(ctx, "SELECT "+journalEntryColumns+" FROM journal WHERE state=? OR state=? OR (state=? AND stage=?) ORDER BY entry", string(JournalStatePending), string(JournalStateIndeterminate), string(JournalStateApplied), string(JournalStageRollbackPending))
	if err != nil {
		return nil, storageFailure(ctx, StageJournal, err)
	}
	defer func() { _ = rows.Close() }()
	entries := make([]JournalEntry, 0)
	for rows.Next() {
		entry, err := scanJournalEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, storageFailure(ctx, StageJournal, err)
	}
	return entries, nil
}

const journalEntryColumns = "entry,vault,operation,stage,state,destination_dir,destination_path,anchor_path,anchor_device,anchor_inode,preimage_digest,preimage_size,postimage_digest,postimage_size,backup_digest,seen_floor_revision,created,updated"

func readJournalEntry(ctx context.Context, tx *sql.Tx, entry int64) (JournalEntry, error) {
	row := tx.QueryRowContext(ctx, "SELECT "+journalEntryColumns+" FROM journal WHERE entry=?", entry)
	read, err := scanJournalEntry(row)
	if errors.Is(err, sql.ErrNoRows) {
		return JournalEntry{}, classified(ErrInvalid, StageJournal, ReasonJournalEntry)
	}
	if err != nil {
		return JournalEntry{}, err
	}
	return read, nil
}

func scanJournalEntry(source interface{ Scan(...any) error }) (JournalEntry, error) {
	var entryValue, vaultValue, operationValue, stageValue, stateValue, directoryValue, pathValue, anchorValue any
	var anchorDeviceValue, anchorInodeValue any
	var preimageDigestValue, preimageSizeValue, postimageDigestValue, postimageSizeValue, backupDigestValue any
	var seenValue, createdValue, updatedValue any
	if err := source.Scan(&entryValue, &vaultValue, &operationValue, &stageValue, &stateValue, &directoryValue, &pathValue, &anchorValue, &anchorDeviceValue, &anchorInodeValue, &preimageDigestValue, &preimageSizeValue, &postimageDigestValue, &postimageSizeValue, &backupDigestValue, &seenValue, &createdValue, &updatedValue); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return JournalEntry{}, err
		}
		return JournalEntry{}, storageFailure(context.Background(), StageJournal, err)
	}
	id, idOK := rawInt64(entryValue)
	vault, vaultOK := rawBytes(vaultValue)
	directory, directoryOK := rawBytes(directoryValue)
	anchor, anchorOK := rawBytes(anchorValue)
	anchorDevice, anchorDeviceOK := rawInt64(anchorDeviceValue)
	anchorInode, anchorInodeOK := rawInt64(anchorInodeValue)
	path, pathOK := rawText(pathValue)
	operation, operationOK := rawText(operationValue)
	stage, stageOK := rawText(stageValue)
	state, stateOK := rawText(stateValue)
	preimageDigest, preimagePresent, preimageOK := journalStoredDigest(preimageDigestValue)
	postimageDigest, postimagePresent, postimageOK := journalStoredDigest(postimageDigestValue)
	backupDigest, backupPresent, backupOK := journalStoredDigest(backupDigestValue)
	seen, seenOK := rawInt64(seenValue)
	created, createdOK := rawInt64(createdValue)
	updated, updatedOK := rawInt64(updatedValue)
	if !idOK || !vaultOK || !directoryOK || !anchorOK || !anchorDeviceOK || !anchorInodeOK || !pathOK || !operationOK || !stageOK || !stateOK || !preimageOK || !postimageOK || !backupOK || !seenOK || !createdOK || !updatedOK {
		return JournalEntry{}, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	if len(vault) != 32 || !journalPathValid(string(directory)) || !journalPathValid(string(anchor)) || anchorDevice < 0 || anchorInode <= 0 || !journalRelativePathValid(path) || len(operation) == 0 || len(operation) > journalMaxTextBytes || !utf8.ValidString(operation) || seen < 0 || created < 0 || updated < 0 {
		return JournalEntry{}, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	read := JournalEntry{Entry: id, Operation: operation, Stage: JournalStage(stage), State: JournalState(state), DestinationDir: string(directory), DestinationPath: path, Anchor: JournalAnchor{Path: string(anchor), Device: anchorDevice, Inode: anchorInode}, SeenFloorRevision: uint64(seen), Created: created, Updated: updated}
	copy(read.Vault[:], vault)
	if !journalPairLegal(read.State, read.Stage) {
		return JournalEntry{}, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	if preimagePresent {
		preimageSize, sizeOK := rawInt64(preimageSizeValue)
		if !sizeOK || preimageSize < 0 {
			return JournalEntry{}, classified(ErrSchema, StageJournal, ReasonCorrupt)
		}
		read.Preimage = &ObservedFile{Present: true, Digest: preimageDigest, Size: uint64(preimageSize)}
	} else if preimageSizeValue != nil {
		return JournalEntry{}, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	if postimagePresent {
		postimageSize, sizeOK := rawInt64(postimageSizeValue)
		if !sizeOK || postimageSize < 0 {
			return JournalEntry{}, classified(ErrSchema, StageJournal, ReasonCorrupt)
		}
		read.Postimage = ObservedFile{Present: true, Digest: postimageDigest, Size: uint64(postimageSize)}
	} else if postimageSizeValue != nil {
		return JournalEntry{}, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	if backupPresent {
		read.BackupDigest = &backupDigest
	}
	return read, nil
}

func journalStoredDigest(value any) ([32]byte, bool, bool) {
	if value == nil {
		return [32]byte{}, false, true
	}
	data, ok := rawBytes(value)
	if !ok || len(data) != sha256.Size {
		return [32]byte{}, false, false
	}
	var digest [32]byte
	copy(digest[:], data)
	return digest, true, true
}

func transitionJournalEntry(ctx context.Context, tx *sql.Tx, entry int64, fromState JournalState, fromStage JournalStage, toState JournalState, toStage JournalStage) error {
	result, err := tx.ExecContext(ctx, "UPDATE journal SET state=?,stage=?,updated=? WHERE entry=? AND state=? AND stage=?", string(toState), string(toStage), time.Now().Unix(), entry, string(fromState), string(fromStage))
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return classified(ErrInvalid, StageJournal, ReasonTransition)
	}
	return nil
}

func readBackupSize(ctx context.Context, tx *sql.Tx, digest [32]byte) (int64, bool, error) {
	var sizeValue any
	err := tx.QueryRowContext(ctx, "SELECT size FROM backups WHERE digest=?", digest[:]).Scan(&sizeValue)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	size, ok := rawInt64(sizeValue)
	if !ok || size < 0 {
		return 0, false, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	return size, true, nil
}

func readBackupData(ctx context.Context, tx *sql.Tx, digest [32]byte, size int64) ([]byte, error) {
	var lengthValue any
	if err := tx.QueryRowContext(ctx, "SELECT length(data) FROM backups WHERE digest=?", digest[:]).Scan(&lengthValue); err != nil {
		return nil, err
	}
	length, lengthOK := rawInt64(lengthValue)
	if !lengthOK || length != size || size < 0 || size > journalMaxBackupBytes {
		return nil, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	var dataValue any
	if err := tx.QueryRowContext(ctx, "SELECT data FROM backups WHERE digest=?", digest[:]).Scan(&dataValue); err != nil {
		return nil, err
	}
	data, dataOK := rawBytes(dataValue)
	if !dataOK || int64(len(data)) != size {
		return nil, classified(ErrSchema, StageJournal, ReasonCorrupt)
	}
	return data, nil
}

func validateJournalIntent(intent JournalIntent) error {
	if allZero(intent.Vault[:]) {
		return classified(ErrInvalid, StageJournal, ReasonBinding)
	}
	if len(intent.Operation) == 0 || len(intent.Operation) > journalMaxTextBytes || !utf8.ValidString(intent.Operation) {
		return classified(ErrInvalid, StageJournal, ReasonJournalIntent)
	}
	if !journalPathValid(intent.DestinationDir) || !journalRelativePathValid(intent.DestinationPath) {
		return classified(ErrInvalid, StageJournal, ReasonBinding)
	}
	if !journalAnchorValid(intent.Anchor) {
		return classified(ErrInvalid, StageJournal, ReasonBinding)
	}
	if err := validateObservedFile(intent.Postimage, StageJournal); err != nil {
		return err
	}
	if intent.SeenFloorRevision > uint64(math.MaxInt64) {
		return classified(ErrInvalid, StageJournal, ReasonJournalIntent)
	}
	if intent.Preimage == nil {
		if len(intent.PreimageBytes) != 0 {
			return classified(ErrInvalid, StageJournal, ReasonJournalObservation)
		}
		return nil
	}
	if !intent.Preimage.Present {
		return classified(ErrInvalid, StageJournal, ReasonJournalObservation)
	}
	if intent.Preimage.Size > uint64(journalMaxBackupBytes) {
		return classified(ErrLimit, StageJournal, ReasonCapacity)
	}
	if int64(len(intent.PreimageBytes)) != int64(intent.Preimage.Size) || sha256.Sum256(intent.PreimageBytes) != intent.Preimage.Digest {
		return classified(ErrInvalid, StageJournal, ReasonJournalObservation)
	}
	return nil
}

func validateObservedFile(observed ObservedFile, stage Stage) error {
	if !observed.Present {
		if observed.Digest != ([32]byte{}) || observed.Size != 0 {
			return classified(ErrInvalid, stage, ReasonJournalObservation)
		}
		return nil
	}
	if observed.Digest == ([32]byte{}) {
		return classified(ErrInvalid, stage, ReasonJournalObservation)
	}
	return nil
}

func observedFileMatches(expected, observed ObservedFile) bool {
	return expected.Present == observed.Present && expected.Digest == observed.Digest && expected.Size == observed.Size
}

func observedPreimageMatches(preimage *ObservedFile, observed ObservedFile) bool {
	if preimage == nil {
		return !observed.Present
	}
	return observedFileMatches(*preimage, observed)
}

func journalPairLegal(state JournalState, stage JournalStage) bool {
	switch state {
	case JournalStatePending:
		return stage == JournalStageApplyPending
	case JournalStateApplied:
		return stage == JournalStageApplyComplete || stage == JournalStageRollbackPending
	case JournalStateFailed:
		return stage == JournalStageApplyFailed
	case JournalStateIndeterminate:
		return stage == JournalStageIndeterminate
	case JournalStateRolledBack:
		return stage == JournalStageRollbackComplete
	default:
		return false
	}
}

func journalPathValid(path string) bool {
	return path != "" && len(path) <= journalMaxPathBytes && utf8.ValidString(path) && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func journalAnchorValid(anchor JournalAnchor) bool {
	return journalPathValid(anchor.Path) && anchor.Device >= 0 && anchor.Inode > 0
}

func journalRelativePathValid(path string) bool {
	return path != "" && len(path) <= journalMaxPathBytes && utf8.ValidString(path) && !filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.HasPrefix(path, "..")
}

func rawText(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case []byte:
		return string(typed), true
	default:
		return "", false
	}
}

func preflightJournalFiles(directory string) error {
	for _, name := range []string{journalLockName, journalLeaseName, journalDatabaseName, journalWalName, journalShmName} {
		if err := preflightFile(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	return nil
}

func secureJournalSidecars(directory string) error {
	for _, name := range []string{journalWalName, journalShmName} {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("sidecar")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("sidecar")
		}
		if info.Mode().Perm() != 0o600 {
			if err := os.Chmod(path, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func probeJournalSchema(path string) (schemaProbe, error) {
	info, err := os.Stat(path)
	if err != nil {
		return schemaProbe{}, err
	}
	if info.Size() == 0 {
		if _, walErr := os.Lstat(path + "-wal"); errors.Is(walErr, os.ErrNotExist) {
			return schemaProbe{initial: true}, nil
		} else if walErr != nil {
			return schemaProbe{}, walErr
		}
	}
	db, err := sql.Open("sqlite", dbDSN(path, true))
	if err != nil {
		return schemaProbe{}, err
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	var appID, version int
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return schemaProbe{}, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return schemaProbe{}, err
	}
	objects, definitions, err := readSchemaObjects(ctx, db)
	if err != nil {
		return schemaProbe{}, err
	}
	if appID == 0 && version == 0 && len(objects) == 0 {
		return schemaProbe{initial: true}, nil
	}
	recognized := appID == journalApplicationID && version == journalSchemaVersion && sameObjects(objects, journalSchemaObjects)
	if recognized {
		for _, statement := range journalSchemaStatements {
			if strings.TrimSpace(definitions[statementTableName(statement)]) != statement {
				recognized = false
				break
			}
		}
	}
	return schemaProbe{recognized: recognized, version: version}, nil
}

func initializeJournalSchema(ctx context.Context, conn *sql.Conn, rootFD int) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	for _, statement := range journalSchemaStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d", journalApplicationID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", journalSchemaVersion)); err != nil {
		return err
	}
	if err := checkJournalSchemaVersion(ctx, tx); err != nil {
		return err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classified(ErrStorage, StageJournalOpen, ReasonCommitUnknown)
	}
	rollback = false
	return nil
}

func checkJournalSchemaVersion(ctx context.Context, conn schemaReader) error {
	var appID, version int
	if err := conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if appID != journalApplicationID || version != journalSchemaVersion {
		return errSchemaMismatch
	}
	objects, definitions, err := readSchemaObjects(ctx, conn)
	if err != nil {
		return err
	}
	if !sameObjects(objects, journalSchemaObjects) {
		return errSchemaMismatch
	}
	for _, statement := range journalSchemaStatements {
		if strings.TrimSpace(definitions[statementTableName(statement)]) != statement {
			return errSchemaMismatch
		}
	}
	return nil
}
