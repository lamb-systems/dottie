package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/lamb-systems/dottie/internal/publication"
)

const (
	StageInspect         Stage  = "inspect"
	ReasonPositionAbsent Reason = "position_absent"
)

type Inspection struct {
	Floor   Floor
	Present bool
}

func Inspect(ctx context.Context, directory string, binding Binding) (Inspection, error) {
	if err := ctx.Err(); err != nil {
		return Inspection{}, canceled(StageInspect, err)
	}
	if err := validateBinding(binding); err != nil {
		return Inspection{}, classified(ErrInvalid, StageInspect, ReasonBinding)
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return Inspection{}, classified(ErrInvalid, StageInspect, ReasonBinding)
	}
	if _, err := os.Lstat(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Inspection{}, classified(ErrSchema, StageInspect, ReasonPositionAbsent)
		}
		return Inspection{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return Inspection{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	databasePath := filepath.Join(directory, "publication.db")
	if _, err := os.Lstat(databasePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Inspection{}, classified(ErrSchema, StageInspect, ReasonPositionAbsent)
		}
		return Inspection{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	if err := preflightFile(databasePath); err != nil {
		return Inspection{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	if err := probeStoreLifetimeLock(directory); err != nil {
		return Inspection{}, err
	}
	if err := refuseUncheckpointedWAL(databasePath); err != nil {
		return Inspection{}, err
	}
	probe, err := probeSchemaImmutable(databasePath, binding, DefaultLimits(), DefaultAttemptLimits())
	if err != nil {
		return Inspection{}, inspectionProbeError(err)
	}
	if probe.initial {
		return Inspection{}, classified(ErrSchema, StageInspect, ReasonPositionAbsent)
	}
	if !probe.recognized {
		return Inspection{}, classified(ErrSchema, StageInspect, ReasonSchema)
	}
	if probe.version != 4 {
		return Inspection{}, classified(ErrSchema, StageInspect, ReasonRebuildRequired)
	}
	return readInspection(ctx, databasePath, binding)
}

func probeStoreLifetimeLock(directory string) error {
	path := filepath.Join(directory, "publication.db.lock")
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return classified(ErrStorage, StageInspect, ReasonIO)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return classified(ErrStorage, StageInspect, ReasonIO)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Flock(fd, syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return classified(ErrLocked, StageInspect, ReasonLocked)
		}
		return classified(ErrStorage, StageInspect, ReasonIO)
	}
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		return classified(ErrStorage, StageInspect, ReasonIO)
	}
	return nil
}

func refuseUncheckpointedWAL(databasePath string) error {
	info, err := os.Lstat(databasePath + "-wal")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return classified(ErrStorage, StageInspect, ReasonIO)
	}
	if info.Size() > 0 {
		return classified(ErrStorage, StageInspect, ReasonIO)
	}
	return nil
}

func inspectionProbeError(err error) error {
	if stateError, ok := errors.AsType[*Error](err); ok {
		return &Error{
			class:        stateError.Class(),
			stage:        StageInspect,
			reason:       stateError.Reason(),
			cancellation: stateError.cancellation,
		}
	}
	return classified(ErrStorage, StageInspect, ReasonIO)
}

func readInspection(ctx context.Context, databasePath string, binding Binding) (Inspection, error) {
	db, err := sql.Open("sqlite", dbImmutableDSN(databasePath))
	if err != nil {
		return Inspection{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(ctx)
	if err != nil {
		return Inspection{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	defer func() { _ = conn.Close() }()
	wantedBinding, err := encodeBinding(binding)
	if err != nil {
		return Inspection{}, classified(ErrInvalid, StageInspect, ReasonBinding)
	}
	storedBinding, err := readValueBounded(ctx, conn, "binding", 16384)
	if err != nil {
		return Inspection{}, storedOrQueryError(ctx, StageInspect, err)
	}
	if !bytes.Equal(storedBinding, wantedBinding) {
		return Inspection{}, classified(ErrInvalid, StageInspect, ReasonBinding)
	}
	databaseID, err := readValueBounded(ctx, conn, "database_id", 32)
	if err != nil {
		return Inspection{}, storedOrQueryError(ctx, StageInspect, err)
	}
	if len(databaseID) != 32 || allZero(databaseID) {
		return Inspection{}, classified(ErrSchema, StageInspect, ReasonCorrupt)
	}
	revision, err := readStoredCount(ctx, conn, "revision")
	if err != nil {
		return Inspection{}, err
	}
	generation, err := readStoredCount(ctx, conn, "generation")
	if err != nil {
		return Inspection{}, err
	}
	encodedFloor, present, err := readStoredFloor(ctx, conn)
	if err != nil {
		return Inspection{}, err
	}
	if !present {
		return Inspection{Floor: zeroFloor(), Present: false}, nil
	}
	floor, err := decodeFloor(encodedFloor)
	if err != nil {
		return Inspection{}, classified(ErrSchema, StageInspect, ReasonCorrupt)
	}
	var id [32]byte
	copy(id[:], databaseID)
	if validatePersistedFloor(floor, binding, id, DefaultLimits()) != nil || floor.Revision != revision ||
		floor.Generation != generation {
		return Inspection{}, classified(ErrSchema, StageInspect, ReasonCorrupt)
	}
	return Inspection{Floor: cloneFloor(floor), Present: true}, nil
}

func readStoredCount(ctx context.Context, conn *sql.Conn, key string) (uint64, error) {
	raw, err := readMeta(ctx, conn, key)
	if err != nil {
		return 0, storedOrQueryError(ctx, StageInspect, err)
	}
	if len(raw) != 8 {
		return 0, classified(ErrSchema, StageInspect, ReasonCorrupt)
	}
	value := binary.BigEndian.Uint64(raw)
	if value > publication.MaxSequence {
		return 0, classified(ErrSchema, StageInspect, ReasonCorrupt)
	}
	return value, nil
}

func readStoredFloor(ctx context.Context, conn *sql.Conn) ([]byte, bool, error) {
	var lengthValue any
	err := conn.QueryRowContext(ctx, "SELECT length(floor) FROM active_floor WHERE singleton=1").Scan(&lengthValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, storageFailure(ctx, StageInspect, err)
	}
	length, ok := lengthValue.(int64)
	if !ok || length <= 0 || length > 65536 {
		return nil, false, classified(ErrSchema, StageInspect, ReasonCorrupt)
	}
	var value any
	if err := conn.QueryRowContext(ctx, "SELECT floor FROM active_floor WHERE singleton=1").Scan(&value); err != nil {
		return nil, false, storageFailure(ctx, StageInspect, err)
	}
	encoded, ok := value.([]byte)
	if !ok || int64(len(encoded)) != length {
		return nil, false, classified(ErrSchema, StageInspect, ReasonCorrupt)
	}
	return encoded, true, nil
}

func ReadBinding(directory string) (Binding, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return Binding{}, classified(ErrInvalid, StageInspect, ReasonBinding)
	}
	if _, err := os.Lstat(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Binding{}, classified(ErrSchema, StageInspect, ReasonPositionAbsent)
		}
		return Binding{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return Binding{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	databasePath := filepath.Join(directory, "publication.db")
	if _, err := os.Lstat(databasePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Binding{}, classified(ErrSchema, StageInspect, ReasonPositionAbsent)
		}
		return Binding{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	if err := preflightFile(databasePath); err != nil {
		return Binding{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	db, err := sql.Open("sqlite", dbImmutableDSN(databasePath))
	if err != nil {
		return Binding{}, classified(ErrStorage, StageInspect, ReasonIO)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	raw, err := readValueBoundedInspection(ctx, db, "binding")
	if err != nil {
		return Binding{}, classified(ErrSchema, StageInspect, ReasonSchema)
	}
	var wire bindingWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Binding{}, classified(ErrSchema, StageInspect, ReasonSchema)
	}
	binding, err := bindingFromWire(wire)
	if err != nil || validateBinding(binding) != nil {
		return Binding{}, classified(ErrSchema, StageInspect, ReasonSchema)
	}
	return binding, nil
}

func readValueBoundedInspection(ctx context.Context, q queryer, key string) ([]byte, error) {
	var value any
	if err := q.QueryRowContext(ctx, "SELECT value FROM store_meta WHERE key=?", key).Scan(&value); err != nil {
		return nil, err
	}
	data, ok := rawBytes(value)
	if !ok || len(data) == 0 || len(data) > 16384 {
		return nil, errors.New("stored value")
	}
	return data, nil
}
