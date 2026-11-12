package publicationstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/lamb-systems/dottie/internal/platform"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const applicationID = 0x44545032

const (
	openRootAcquiredFault         = 101
	openLockAcquiredFault         = 102
	openConnectionAcquiredFault   = 103
	openCreatedDatabaseChmodFault = 104
)

var (
	errStoredValue    = errors.New("invalid stored value")
	errSchemaMismatch = errors.New("unsupported schema")
)

var schemaV1Statements = []string{
	"CREATE TABLE store_meta (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL)",
	"CREATE TABLE cache_records (cid BLOB PRIMARY KEY NOT NULL, record_key TEXT NOT NULL, sequence INTEGER NOT NULL, raw BLOB NOT NULL, logical_bytes INTEGER NOT NULL)",
	"CREATE TABLE cache_observations (observation_id BLOB PRIMARY KEY NOT NULL, metadata BLOB NOT NULL, logical_bytes INTEGER NOT NULL)",
	"CREATE TABLE accepted_records (cid BLOB PRIMARY KEY NOT NULL, record_key TEXT NOT NULL, sequence INTEGER NOT NULL, raw BLOB NOT NULL, logical_bytes INTEGER NOT NULL)",
	"CREATE TABLE accepted_events (revision INTEGER PRIMARY KEY NOT NULL, mode TEXT NOT NULL, reason TEXT NOT NULL, stop TEXT NOT NULL, old_floor BLOB, new_floor BLOB NOT NULL, body BLOB NOT NULL, digest BLOB NOT NULL, logical_bytes INTEGER NOT NULL)",
	"CREATE TABLE active_floor (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1), floor BLOB NOT NULL)",
}

var schemaV1Objects = map[string]string{
	"store_meta":         "table",
	"cache_records":      "table",
	"cache_observations": "table",
	"accepted_records":   "table",
	"accepted_events":    "table",
	"active_floor":       "table",
}

type Store struct {
	mu                      sync.Mutex
	db                      *sql.DB
	conn                    *sql.Conn
	lock                    *platform.Lock
	directory               string
	binding                 Binding
	limits                  Limits
	attemptLimits           AttemptLimits
	databaseID              [32]byte
	attemptMutationRevision uint64
	closed                  bool
	needsReadback           bool
	rootFD                  int
	payloadFD               int
	schemaVersion           int
	custodyOps              custodyOperations
	commitTransaction       func(*sql.Tx) error
}

func Open(directory string, binding Binding) (*Store, error) {
	return OpenWithOptions(directory, binding, DefaultOpenOptions())
}

func OpenWithLimits(directory string, binding Binding, limits Limits) (*Store, error) {
	options := DefaultOpenOptions()
	options.PositionLimits = limits
	return OpenWithOptions(directory, binding, options)
}

func OpenWithOptions(directory string, binding Binding, options OpenOptions) (*Store, error) {
	limits := options.PositionLimits
	attemptLimits := options.AttemptLimits
	if err := validateBinding(binding); err != nil {
		return nil, classified(ErrInvalid, StageOpen, ReasonBinding)
	}
	if err := validateLimits(limits); err != nil {
		return nil, classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	if err := validateAttemptLimits(attemptLimits); err != nil {
		return nil, classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, classified(ErrInvalid, StageOpen, ReasonBinding)
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return nil, classified(ErrInvalid, StageOpen, ReasonBinding)
	}
	store := &Store{directory: directory, binding: binding, limits: limits, attemptLimits: attemptLimits, rootFD: -1, payloadFD: -1, custodyOps: defaultCustodyOperations(), commitTransaction: func(tx *sql.Tx) error { return tx.Commit() }}
	transferred := false
	defer func() {
		if !transferred {
			_ = store.Close()
		}
	}()
	rootFD, err := openStoreRoot(directory)
	if err != nil {
		return nil, classified(ErrInvalid, StageOpen, ReasonBinding)
	}
	store.rootFD = rootFD
	if options.openFault != nil {
		if err := options.openFault(openRootAcquiredFault, store); err != nil {
			return nil, storageFailure(context.Background(), StageOpen, err)
		}
	}
	for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		if err := preflightFile(filepath.Join(directory, name)); err != nil {
			return nil, classified(ErrInvalid, StageOpen, ReasonBinding)
		}
	}
	lock, err := platform.LockFile(filepath.Join(directory, "publication.db.lock"))
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, classified(ErrLocked, StageOpen, ReasonLocked)
		}
		return nil, classified(ErrStorage, StageOpen, ReasonIO)
	}
	store.lock = lock
	if options.openFault != nil {
		if err := options.openFault(openLockAcquiredFault, store); err != nil {
			return nil, storageFailure(context.Background(), StageOpen, err)
		}
	}
	for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		if err := preflightFile(filepath.Join(directory, name)); err != nil {
			return nil, classified(ErrInvalid, StageOpen, ReasonBinding)
		}
	}
	dbPath := filepath.Join(directory, "publication.db")
	createdDB, err := createDatabaseFile(dbPath)
	if err != nil {
		return nil, classified(ErrStorage, StageOpen, ReasonIO)
	}
	if createdDB {
		if err := unix.Fsync(store.rootFD); err != nil {
			return nil, classified(ErrStorage, StageOpen, ReasonIO)
		}
	}
	probe, err := probeSchema(dbPath, binding, limits, attemptLimits)
	if err != nil {
		var classifiedErr *Error
		if errors.As(err, &classifiedErr) {
			return nil, err
		}
		return nil, storageFailure(context.Background(), StageOpen, err)
	}
	if !probe.initial && !probe.recognized {
		return nil, classified(ErrSchema, StageOpen, ReasonSchema)
	}
	if probe.version == 1 && (!options.UpgradeFromPositions || !options.UpgradeFromAttempts) {
		return nil, classified(ErrSchema, StageOpen, ReasonUpgradeRequired)
	}
	if probe.version == 2 && !options.UpgradeFromAttempts {
		return nil, classified(ErrSchema, StageOpen, ReasonUpgradeRequired)
	}
	db, err := sql.Open("sqlite", dbDSN(dbPath, false))
	if err != nil {
		return nil, classified(ErrStorage, StageOpen, ReasonIO)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store.db = db
	conn, err := db.Conn(context.Background())
	if err != nil {
		return nil, classified(ErrStorage, StageOpen, ReasonIO)
	}
	store.conn = conn
	if options.openFault != nil {
		if err := options.openFault(openConnectionAcquiredFault, store); err != nil {
			return nil, storageFailure(context.Background(), StageOpen, err)
		}
	}
	if err := configureConnection(context.Background(), conn); err != nil {
		return nil, classified(ErrStorage, StageOpen, ReasonIO)
	}
	if probe.initial {
		if err := initializeSchema(context.Background(), conn, binding, limits, attemptLimits, store.rootFD); err != nil {
			return nil, schemaOrStorageError(context.Background(), StageOpen, err)
		}
	} else if probe.version == 1 || probe.version == 2 {
		source, sourceErr := readIncomingMaterialUpgradeSource(context.Background(), conn, probe.version, binding, limits, attemptLimits)
		if sourceErr != nil {
			return nil, sourceErr
		}
		outcome, upgradeErr := upgradeIncomingMaterial(context.Background(), conn, source, store.rootFD, options.upgradeFault, options.upgradeCommit)
		if outcome != incomingMaterialUpgradeCommitted || upgradeErr != nil {
			if outcome == incomingMaterialUpgradeNotAttempted && upgradeErr == nil {
				return nil, classified(ErrStorage, StageOpen, ReasonIO)
			}
			return nil, incomingMaterialOpenError(outcome, upgradeErr)
		}
		var completionFault func(int) error
		if options.openFault != nil {
			completionFault = func(point int) error { return options.openFault(point, store) }
		}
		transferred = true
		return completeIncomingMaterialUpgradeOpen(context.Background(), store, source, outcome, completionFault)
	} else if err := checkSchema(context.Background(), conn); err != nil {
		return nil, schemaOrStorageError(context.Background(), StageOpen, err)
	}
	if options.openFault != nil {
		if err := options.openFault(incomingMaterialOpenDestinationFault, store); err != nil {
			return nil, storageFailure(context.Background(), StageOpen, err)
		}
	}
	if err := checkSchema(context.Background(), conn); err != nil {
		return nil, schemaOrStorageError(context.Background(), StageOpen, err)
	}
	if err := compareMetadata(context.Background(), conn, binding, limits); err != nil {
		return nil, err
	}
	if err := checkAttemptMetadata(context.Background(), conn, attemptLimits); err != nil {
		return nil, err
	}
	dbidBytes, dbidErr := readValueBounded(context.Background(), conn, "database_id", 32)
	if dbidErr != nil {
		return nil, storedOrQueryError(context.Background(), StageOpen, dbidErr)
	}
	if len(dbidBytes) != 32 || allZero(dbidBytes) {
		return nil, classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	mutationBytes, mutationErr := readValueBounded(context.Background(), conn, "attempt_mutation_revision", 8)
	if mutationErr != nil || len(mutationBytes) != 8 {
		return nil, classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	store.attemptMutationRevision = binary.BigEndian.Uint64(mutationBytes)
	copy(store.databaseID[:], dbidBytes)
	store.schemaVersion = 3
	if _, err := store.readState(context.Background(), conn, StageOpen); err != nil {
		var stateError *Error
		if errors.As(err, &stateError) {
			return nil, err
		}
		return nil, storageFailure(context.Background(), StageOpen, err)
	}
	if createdDB {
		if options.openFault != nil {
			if err := options.openFault(openCreatedDatabaseChmodFault, store); err != nil {
				return nil, storageFailure(context.Background(), StageOpen, err)
			}
		}
		if options.createdDatabaseChmod != nil {
			if err := options.createdDatabaseChmod(dbPath); err != nil {
				return nil, classified(ErrStorage, StageOpen, ReasonIO)
			}
		} else if err := os.Chmod(dbPath, 0o600); err != nil {
			return nil, classified(ErrStorage, StageOpen, ReasonIO)
		}
	}
	if options.openFault != nil {
		if err := options.openFault(incomingMaterialOpenSidecarsFault, store); err != nil {
			return nil, storageFailure(context.Background(), StageOpen, err)
		}
	}
	if err := secureCreatedSidecars(directory); err != nil {
		return nil, classified(ErrStorage, StageOpen, ReasonIO)
	}
	if options.openFault != nil {
		if err := options.openFault(incomingMaterialOpenRootSyncFault, store); err != nil {
			return nil, storageFailure(context.Background(), StageOpen, err)
		}
	}
	if err := unix.Fsync(store.rootFD); err != nil {
		return nil, classified(ErrStorage, StageOpen, ReasonIO)
	}
	if options.openFault != nil {
		if err := options.openFault(incomingMaterialOpenPreflightFault, store); err != nil {
			return nil, storageFailure(context.Background(), StageOpen, err)
		}
	}
	for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		if err := preflightFile(filepath.Join(directory, name)); err != nil {
			return nil, classified(ErrInvalid, StageOpen, ReasonBinding)
		}
	}
	transferred = true
	return store, nil
}

type schemaProbe struct {
	initial    bool
	recognized bool
	version    int
}

func schemaOrStorageError(ctx context.Context, stage Stage, err error) error {
	if errors.Is(err, errSchemaMismatch) {
		return classified(ErrSchema, stage, ReasonSchema)
	}
	var stateError *Error
	if errors.As(err, &stateError) {
		return err
	}
	return storageFailure(ctx, stage, err)
}

func probeSchema(path string, binding Binding, limits Limits, attemptLimits AttemptLimits) (schemaProbe, error) {
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
	defer db.Close()
	ctx := context.Background()
	var appID, version int
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return schemaProbe{}, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return schemaProbe{}, err
	}
	rows, err := db.QueryContext(ctx, "SELECT name, type, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name")
	if err != nil {
		return schemaProbe{}, err
	}
	objects := map[string]string{}
	definitions := map[string]string{}
	for rows.Next() {
		var name, kind, definition string
		if err := rows.Scan(&name, &kind, &definition); err != nil {
			_ = rows.Close()
			return schemaProbe{}, err
		}
		objects[name] = kind
		definitions[name] = definition
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return schemaProbe{}, err
	}
	if err := rows.Close(); err != nil {
		return schemaProbe{}, err
	}
	mode := ""
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return schemaProbe{}, err
	}
	if appID == 0 && version == 0 && len(objects) == 0 {
		return schemaProbe{initial: true}, nil
	}
	inventory, inventoryErr := schemaInventoryForVersion(version)
	recognized := appID == applicationID && inventoryErr == nil && sameObjects(objects, inventory.objects)
	if recognized {
		for _, statement := range inventory.statements {
			name := statementTableName(statement)
			if strings.TrimSpace(definitions[name]) != statement {
				recognized = false
				break
			}
		}
	}
	if recognized {
		metaRows, metaErr := db.QueryContext(ctx, "SELECT key FROM store_meta ORDER BY key")
		if metaErr != nil {
			return schemaProbe{}, metaErr
		}
		metaKeys := make([]string, 0, 7)
		for metaRows.Next() {
			var key string
			if err := metaRows.Scan(&key); err != nil {
				_ = metaRows.Close()
				return schemaProbe{}, err
			}
			metaKeys = append(metaKeys, key)
		}
		if err := metaRows.Err(); err != nil {
			_ = metaRows.Close()
			return schemaProbe{}, err
		}
		if err := metaRows.Close(); err != nil {
			return schemaProbe{}, err
		}
		if !equalStrings(metaKeys, inventory.metadataKeys) {
			return schemaProbe{}, classified(ErrSchema, StageOpen, ReasonSchema)
		}
		wantedBinding, _ := encodeBinding(binding)
		wantedLimits, _ := encodeLimits(limits)
		storedBinding, bindingErr := readValueBounded(ctx, db, "binding", 16384)
		storedLimits, limitsErr := readValueBounded(ctx, db, "limits", 16384)
		dbid, dbidErr := readValueBounded(ctx, db, "database_id", 32)
		revision, revisionErr := readValueBounded(ctx, db, "revision", 8)
		generation, generationErr := readValueBounded(ctx, db, "generation", 8)
		for _, readErr := range []error{bindingErr, limitsErr, dbidErr, revisionErr, generationErr} {
			if readErr != nil {
				return schemaProbe{}, storedOrQueryError(ctx, StageOpen, readErr)
			}
		}
		if len(dbid) != 32 || allZero(dbid) || len(revision) != 8 || len(generation) != 8 {
			return schemaProbe{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
		if !bytes.Equal(storedBinding, wantedBinding) {
			return schemaProbe{}, classified(ErrInvalid, StageOpen, ReasonBinding)
		}
		if !bytes.Equal(storedLimits, wantedLimits) {
			return schemaProbe{}, classified(ErrInvalid, StageOpen, ReasonLimits)
		}
		var mutationRevision uint64
		if version == 2 || version == 3 {
			storedAttemptLimits, attemptErr := readValueBounded(ctx, db, "attempt_limits", 16384)
			storedMutationRevision, mutationErr := readValueBounded(ctx, db, "attempt_mutation_revision", 8)
			if attemptErr != nil || mutationErr != nil || len(storedMutationRevision) != 8 {
				return schemaProbe{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
			}
			mutationRevision = binary.BigEndian.Uint64(storedMutationRevision)
			if mutationRevision > uint64(^uint64(0)>>1) {
				return schemaProbe{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
			}
			wantedAttemptLimits, _ := encodeAttemptLimits(attemptLimits)
			if !bytes.Equal(storedAttemptLimits, wantedAttemptLimits) {
				return schemaProbe{}, classified(ErrInvalid, StageOpen, ReasonLimits)
			}
		}
		var id [32]byte
		copy(id[:], dbid)
		tempStore := &Store{binding: binding, limits: limits, attemptLimits: attemptLimits, databaseID: id, attemptMutationRevision: mutationRevision, schemaVersion: version}
		if _, err := tempStore.readState(ctx, db, StageOpen); err != nil {
			return schemaProbe{}, err
		}
	}
	return schemaProbe{recognized: recognized, version: version}, nil
}

func dbDSN(path string, readOnly bool) string {
	query := ""
	if readOnly {
		query = "mode=ro"
	}
	return (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String()
}

func configureConnection(ctx context.Context, conn *sql.Conn) error {
	var mode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return err
	}
	if !strings.EqualFold(mode, "wal") {
		return errors.New("journal mode")
	}
	for _, pragma := range []string{"PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	return nil
}

func initializeSchema(ctx context.Context, conn *sql.Conn, bindingValue Binding, limitsValue Limits, attemptLimitsValue AttemptLimits, rootFD int) error {
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
	inventory, err := schemaInventoryForVersion(3)
	if err != nil {
		return err
	}
	for _, statement := range inventory.statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	binding, err := encodeBinding(bindingValue)
	if err != nil {
		return err
	}
	limits, err := encodeLimits(limitsValue)
	if err != nil {
		return err
	}
	attemptLimits, err := encodeAttemptLimits(attemptLimitsValue)
	if err != nil {
		return err
	}
	var dbid [32]byte
	for allZero(dbid[:]) {
		if _, err := rand.Read(dbid[:]); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO store_meta(key,value) VALUES ('database_id',?),('revision',?),('generation',?),('binding',?),('limits',?),('attempt_limits',?),('attempt_mutation_revision',?)", dbid[:], uint64Bytes(0), uint64Bytes(0), binding, limits, attemptLimits, uint64Bytes(0)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA application_id=1146376242"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version=3"); err != nil {
		return err
	}
	if err := checkSchemaVersion(ctx, tx, 3); err != nil {
		return err
	}
	if err := checkAttemptMetadata(ctx, tx, attemptLimitsValue); err != nil {
		return err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classified(ErrStorage, StageOpen, ReasonCommitUnknown)
	}
	rollback = false
	return nil
}

func compareMetadata(ctx context.Context, conn queryer, binding Binding, limits Limits) error {
	wantedBinding, _ := encodeBinding(binding)
	wantedLimits, _ := encodeLimits(limits)
	gotBinding, bindingErr := readValueBounded(ctx, conn, "binding", 16384)
	gotLimits, limitsErr := readValueBounded(ctx, conn, "limits", 16384)
	if bindingErr != nil {
		return storedOrQueryError(ctx, StageOpen, bindingErr)
	}
	if limitsErr != nil {
		return storedOrQueryError(ctx, StageOpen, limitsErr)
	}
	if !bytes.Equal(gotBinding, wantedBinding) {
		return classified(ErrInvalid, StageOpen, ReasonBinding)
	}
	if !bytes.Equal(gotLimits, wantedLimits) {
		return classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	return nil
}

func checkSchema(ctx context.Context, conn *sql.Conn) error {
	var appID, version int
	if err := conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if appID != applicationID || version != 3 {
		return errSchemaMismatch
	}
	rows, err := conn.QueryContext(ctx, "SELECT name,type,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name")
	if err != nil {
		return err
	}
	objects := map[string]string{}
	definitions := map[string]string{}
	for rows.Next() {
		var name, kind, sql string
		if err := rows.Scan(&name, &kind, &sql); err != nil {
			_ = rows.Close()
			return err
		}
		objects[name] = kind
		definitions[name] = sql
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	inventory, err := schemaInventoryForVersion(3)
	if err != nil {
		return err
	}
	if !sameObjects(objects, inventory.objects) {
		return errSchemaMismatch
	}
	metaRows, err := conn.QueryContext(ctx, "SELECT key FROM store_meta ORDER BY key")
	if err != nil {
		return err
	}
	metaKeys := make([]string, 0, 7)
	for metaRows.Next() {
		var key string
		if err := metaRows.Scan(&key); err != nil {
			_ = metaRows.Close()
			return err
		}
		metaKeys = append(metaKeys, key)
	}
	if err := metaRows.Err(); err != nil {
		_ = metaRows.Close()
		return err
	}
	if err := metaRows.Close(); err != nil {
		return err
	}
	if !equalStrings(metaKeys, inventory.metadataKeys) {
		return errSchemaMismatch
	}
	for _, statement := range inventory.statements {
		name := statementTableName(statement)
		if strings.TrimSpace(definitions[name]) != statement {
			return errSchemaMismatch
		}
	}
	return nil
}

func statementTableName(statement string) string {
	parts := strings.Fields(statement)
	if len(parts) > 2 {
		return strings.Trim(parts[2], "(")
	}
	return ""
}

func sameObjects(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range b {
		if a[key] != value {
			return false
		}
	}
	return true
}

func uint64Bytes(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}

func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory owner")
	}
	return nil
}

func preflightFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || (stat.Nlink > 1) {
		return errors.New("file owner")
	}
	return nil
}

func createDatabaseFile(path string) (bool, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if errors.Is(err, syscall.EEXIST) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		_ = syscall.Close(fd)
		return false, err
	}
	file := os.NewFile(uintptr(fd), path)
	return true, file.Close()
}

func secureCreatedSidecars(directory string) error {
	for _, name := range []string{"publication.db-wal", "publication.db-shm"} {
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

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var failed bool
	if s.conn != nil && s.conn.Close() != nil {
		failed = true
	}
	if s.db != nil && s.db.Close() != nil {
		failed = true
	}
	if s.lock != nil && s.lock.Close() != nil {
		failed = true
	}
	if s.payloadFD >= 0 && unix.Close(s.payloadFD) != nil {
		failed = true
	}
	if s.rootFD >= 0 && unix.Close(s.rootFD) != nil {
		failed = true
	}
	if failed {
		return classified(ErrStorage, StageClose, ReasonIO)
	}
	return nil
}

func (s *Store) checkOpen(stage Stage) error {
	if s.closed {
		return classified(ErrClosed, stage, ReasonClosed)
	}
	return nil
}

func (s *Store) checkContext(ctx context.Context, stage Stage) error {
	if err := ctx.Err(); err != nil {
		return canceled(stage, err)
	}
	return s.checkOpen(stage)
}

func (s *Store) withTx(ctx context.Context, stage Stage, fn func(*sql.Tx) error) error {
	if err := s.checkContext(ctx, stage); err != nil {
		return err
	}
	tx, err := s.conn.BeginTx(ctx, nil)
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
	if err := s.syncCustodyFD(s.rootFD); err != nil {
		_ = tx.Rollback()
		return storageFailure(ctx, stage, err)
	}
	commit := s.commitTransaction
	if commit == nil {
		commit = func(tx *sql.Tx) error { return tx.Commit() }
	}
	if err := commit(tx); err != nil {
		_ = tx.Rollback()
		s.needsReadback = true
		return classified(ErrStorage, stage, ReasonCommitUnknown)
	}
	return nil
}

func (s *Store) requireReadback(stage Stage) error {
	if s.needsReadback {
		return classified(ErrStorage, stage, ReasonCommitUnknown)
	}
	return nil
}

func readMeta(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) ([]byte, error) {
	return readValueBounded(ctx, q, key, 8)
}

func readValueBounded(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string, max int64) ([]byte, error) {
	var sizeValue any
	if err := q.QueryRowContext(ctx, "SELECT length(value) FROM store_meta WHERE key=?", key).Scan(&sizeValue); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errStoredValue
		}
		return nil, err
	}
	size, ok := sizeValue.(int64)
	if !ok || size < 0 || size > max {
		return nil, errStoredValue
	}
	var valueValue any
	if err := q.QueryRowContext(ctx, "SELECT value FROM store_meta WHERE key=?", key).Scan(&valueValue); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errStoredValue
		}
		return nil, err
	}
	value, ok := valueValue.([]byte)
	if !ok || int64(len(value)) != size {
		return nil, errStoredValue
	}
	return bytes.Clone(value), nil
}

func storedOrQueryError(ctx context.Context, stage Stage, err error) error {
	if errors.Is(err, errStoredValue) {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return storageFailure(ctx, stage, err)
}
