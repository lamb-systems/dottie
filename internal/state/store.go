package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	_ "modernc.org/sqlite"

	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
)

type Store struct {
	mu         sync.Mutex
	db         *sql.DB
	conn       *sql.Conn
	lock       *platform.Lock
	stateDir   string
	payloadDir string
	closed     bool
}

func Open(paths platform.Paths) (*Store, error) {
	return openWithMigrations(paths, embeddedMigrations)
}

func openWithMigrations(paths platform.Paths, migrationFS fs.FS) (*Store, error) {
	stateDir := paths.AppStateDir()
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("state directory must be absolute")
	}
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return nil, fmt.Errorf("secure state directory: %w", err)
	}
	lock, err := platform.LockFile(filepath.Join(stateDir, "state.db.lock"))
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %v", ErrStateLocked, err)
		}
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = lock.Close()
		}
	}()
	dbPath := filepath.Join(stateDir, "state.db")
	if err := prepareDatabaseFile(dbPath); err != nil {
		return nil, fmt.Errorf("secure state database: %w", err)
	}
	payloadDir := filepath.Join(stateDir, "payloads")
	if err := ensurePrivateDirectory(payloadDir); err != nil {
		return nil, fmt.Errorf("secure payload directory: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: dbPath}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect state database: %w", err)
	}
	cleanupDB := func() {
		_ = conn.Close()
		_ = db.Close()
	}
	if err := ensureSupportedSchema(context.Background(), conn, migrationFS); err != nil {
		cleanupDB()
		return nil, err
	}
	if err := setPragmas(context.Background(), conn); err != nil {
		cleanupDB()
		return nil, fmt.Errorf("configure state database: %w", err)
	}
	if err := migrate(context.Background(), conn, migrationFS); err != nil {
		cleanupDB()
		return nil, err
	}
	store := &Store{db: db, conn: conn, lock: lock, stateDir: stateDir, payloadDir: payloadDir}
	if err := store.secureSidecars(); err != nil {
		cleanupDB()
		return nil, err
	}
	failed = false
	return store, nil
}

func setPragmas(ctx context.Context, conn *sql.Conn) error {
	var journal string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&journal); err != nil {
		return err
	}
	if !strings.EqualFold(journal, "wal") {
		return fmt.Errorf("SQLite selected journal mode %q instead of WAL", journal)
	}
	for _, pragma := range []string{"PRAGMA synchronous = FULL", "PRAGMA foreign_keys = ON", "PRAGMA busy_timeout = 5000"} {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	return nil
}

func prepareDatabaseFile(path string) error {
	info, inspectErr := os.Lstat(path)
	if inspectErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("state database path is not a regular file")
	}
	if inspectErr != nil && !errors.Is(inspectErr, os.ErrNotExist) {
		return inspectErr
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return statErr
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return errors.New("state database path is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("directory path must be absolute")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("directory path is not a real directory")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory is not owned by the current user")
	}
	if info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
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
	var result error
	if s.conn != nil {
		result = errors.Join(result, s.conn.Close())
	}
	if s.db != nil {
		result = errors.Join(result, s.db.Close())
	}
	if s.lock != nil {
		result = errors.Join(result, s.lock.Close())
	}
	return result
}

func (s *Store) SchemaVersion() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return 0, err
	}
	return currentSchemaVersion(context.Background(), s.conn)
}

func (s *Store) PutTarget(ctx context.Context, descriptor TargetDescriptor) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var version int64
		var source string
		var sourceVersion int64
		var logicalBase, logicalPath, kind, mode string
		err := tx.QueryRowContext(ctx, "SELECT descriptor_version, source, source_version, logical_base, logical_path, kind, mode FROM targets WHERE target_id = ?", descriptor.ID).Scan(&version, &source, &sourceVersion, &logicalBase, &logicalPath, &kind, &mode)
		if err == nil {
			if version != int64(descriptor.Version) || source != string(descriptor.Source) || sourceVersion != int64(descriptor.SourceVersion) || logicalBase != string(descriptor.LogicalBase) || logicalPath != descriptor.LogicalPath || kind != string(descriptor.Kind) || mode != descriptor.Mode {
				return fmt.Errorf("%w: target %q is already bound to a different portable descriptor", ErrTargetBindingChanged, descriptor.ID)
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO targets(target_id, descriptor_version, source, source_version, logical_base, logical_path, kind, mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", descriptor.ID, descriptor.Version, descriptor.Source, descriptor.SourceVersion, descriptor.LogicalBase, descriptor.LogicalPath, descriptor.Kind, descriptor.Mode, descriptor.CreatedAt)
		return err
	})
}

func (s *Store) PutAppliedBase(ctx context.Context, record BaseRecord, payload []byte) (BaseRecord, error) {
	if err := validateIdentity(record.Identity.TargetID, record.Identity); err != nil {
		return BaseRecord{}, err
	}
	ref, digest := payloadReference(payload)
	if record.Fingerprint.Digest == "" {
		record.Fingerprint.Digest = digest
		record.Fingerprint.Size = int64(len(payload))
	}
	if record.Fingerprint.Size != int64(len(payload)) || record.Fingerprint.Digest != digest {
		return BaseRecord{}, errors.New("base fingerprint does not match payload")
	}
	if err := record.Fingerprint.Validate(record.Identity); err != nil {
		return BaseRecord{}, err
	}
	if record.PayloadRef != "" && record.PayloadRef != ref {
		return BaseRecord{}, errors.New("base payload reference does not match payload")
	}
	if err := s.storePayload(ref, payload); err != nil {
		return BaseRecord{}, err
	}
	record.PayloadRef = ref
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO applied_base(target_id, source, file_path, schema_id, settings_path, setting_key, entry_state, kind, mode, link_target, value_type, value_text, size, digest, payload_ref, recorded_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(target_id, source, file_path, schema_id, settings_path, setting_key) DO UPDATE SET entry_state=excluded.entry_state, kind=excluded.kind, mode=excluded.mode, link_target=excluded.link_target, value_type=excluded.value_type, value_text=excluded.value_text, size=excluded.size, digest=excluded.digest, payload_ref=excluded.payload_ref, recorded_at=excluded.recorded_at`,
			record.Identity.TargetID, record.Identity.Source, record.Identity.FilePath, record.Identity.SchemaID, record.Identity.SettingsPath, record.Identity.SettingKey,
			record.Fingerprint.State, record.Fingerprint.Kind, record.Fingerprint.Mode, record.Fingerprint.LinkTarget, record.Fingerprint.ValueType, record.Fingerprint.ValueText, record.Fingerprint.Size, record.Fingerprint.Digest, record.PayloadRef, record.RecordedAt)
		return err
	})
	return record, err
}

func (s *Store) AppliedBase(ctx context.Context, targetID string) ([]BaseRecord, error) {
	var records []BaseRecord
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, `SELECT target_id, source, file_path, schema_id, settings_path, setting_key, entry_state, kind, mode, link_target, value_type, value_text, size, digest, payload_ref, recorded_at FROM applied_base WHERE target_id = ? ORDER BY source, file_path, schema_id, settings_path, setting_key`, targetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := scanBase(rows)
			if err != nil {
				return err
			}
			records = append(records, record)
		}
		return rows.Err()
	})
	return records, err
}

func (s *Store) AppendIntent(ctx context.Context, intent Intent, payload []byte) (Intent, error) {
	if err := validateID(intent.ID, "intent id"); err != nil {
		return Intent{}, err
	}
	if err := validateIdentity(intent.Identity.TargetID, intent.Identity); err != nil {
		return Intent{}, err
	}
	if err := validateID(intent.State, "intent state"); err != nil {
		return Intent{}, err
	}
	if intent.Attempts < 0 {
		return Intent{}, errors.New("intent attempts cannot be negative")
	}
	ref, _ := payloadReference(payload)
	if intent.PayloadRef != "" && intent.PayloadRef != ref {
		return Intent{}, errors.New("intent payload reference does not match payload")
	}
	if err := s.storePayload(ref, payload); err != nil {
		return Intent{}, err
	}
	intent.PayloadRef = ref
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO outbound_intent(id, target_id, source, file_path, schema_id, settings_path, setting_key, payload_ref, state, attempts, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			intent.ID, intent.Identity.TargetID, intent.Identity.Source, intent.Identity.FilePath, intent.Identity.SchemaID, intent.Identity.SettingsPath, intent.Identity.SettingKey, intent.PayloadRef, intent.State, intent.Attempts, intent.CreatedAt)
		return err
	})
	return intent, err
}

func (s *Store) Intents(ctx context.Context, targetID string) ([]Intent, error) {
	var values []Intent
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, "SELECT id, target_id, source, file_path, schema_id, settings_path, setting_key, payload_ref, state, attempts, created_at FROM outbound_intent WHERE target_id = ? ORDER BY created_at, id", targetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value Intent
			var source string
			if err := rows.Scan(&value.ID, &value.Identity.TargetID, &source, &value.Identity.FilePath, &value.Identity.SchemaID, &value.Identity.SettingsPath, &value.Identity.SettingKey, &value.PayloadRef, &value.State, &value.Attempts, &value.CreatedAt); err != nil {
				return err
			}
			value.Identity.Source = model.SourceKind(source)
			values = append(values, value)
		}
		return rows.Err()
	})
	return values, err
}

func (s *Store) RecordConflict(ctx context.Context, conflict Conflict, localPayload, remotePayload []byte) (Conflict, error) {
	if err := validateID(conflict.ID, "conflict id"); err != nil {
		return Conflict{}, err
	}
	if err := validateIdentity(conflict.Identity.TargetID, conflict.Identity); err != nil {
		return Conflict{}, err
	}
	if err := validateID(conflict.State, "conflict state"); err != nil {
		return Conflict{}, err
	}
	localRef, _ := payloadReference(localPayload)
	remoteRef, _ := payloadReference(remotePayload)
	if (conflict.LocalPayloadRef != "" && conflict.LocalPayloadRef != localRef) || (conflict.RemotePayloadRef != "" && conflict.RemotePayloadRef != remoteRef) {
		return Conflict{}, errors.New("conflict payload reference does not match payload")
	}
	if err := s.storePayload(localRef, localPayload); err != nil {
		return Conflict{}, err
	}
	if err := s.storePayload(remoteRef, remotePayload); err != nil {
		return Conflict{}, err
	}
	conflict.LocalPayloadRef = localRef
	conflict.RemotePayloadRef = remoteRef
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO conflicts(id, target_id, source, file_path, schema_id, settings_path, setting_key, local_payload_ref, remote_payload_ref, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			conflict.ID, conflict.Identity.TargetID, conflict.Identity.Source, conflict.Identity.FilePath, conflict.Identity.SchemaID, conflict.Identity.SettingsPath, conflict.Identity.SettingKey, conflict.LocalPayloadRef, conflict.RemotePayloadRef, conflict.State, conflict.CreatedAt)
		return err
	})
	return conflict, err
}

func (s *Store) Conflicts(ctx context.Context, targetID string) ([]Conflict, error) {
	var values []Conflict
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, "SELECT id, target_id, source, file_path, schema_id, settings_path, setting_key, local_payload_ref, remote_payload_ref, state, created_at FROM conflicts WHERE target_id = ? ORDER BY created_at, id", targetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value Conflict
			var source string
			if err := rows.Scan(&value.ID, &value.Identity.TargetID, &source, &value.Identity.FilePath, &value.Identity.SchemaID, &value.Identity.SettingsPath, &value.Identity.SettingKey, &value.LocalPayloadRef, &value.RemotePayloadRef, &value.State, &value.CreatedAt); err != nil {
				return err
			}
			value.Identity.Source = model.SourceKind(source)
			values = append(values, value)
		}
		return rows.Err()
	})
	return values, err
}

func (s *Store) AppendCheckpoint(ctx context.Context, checkpoint Checkpoint) error {
	if err := validateID(checkpoint.ID, "checkpoint id"); err != nil {
		return err
	}
	if err := validateID(checkpoint.CID, "checkpoint cid"); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO checkpoints(id, counter, cid, recorded_at) VALUES (?, ?, ?, ?)", checkpoint.ID, checkpoint.Counter, checkpoint.CID, checkpoint.RecordedAt)
		return err
	})
}

func (s *Store) Checkpoints(ctx context.Context) ([]Checkpoint, error) {
	var values []Checkpoint
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, "SELECT id, counter, cid, recorded_at FROM checkpoints ORDER BY counter, id")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value Checkpoint
			if err := rows.Scan(&value.ID, &value.Counter, &value.CID, &value.RecordedAt); err != nil {
				return err
			}
			values = append(values, value)
		}
		return rows.Err()
	})
	return values, err
}

func (s *Store) AppendJournal(ctx context.Context, entry JournalEntry, backup []byte) (JournalEntry, error) {
	if err := validateID(entry.ID, "journal id"); err != nil {
		return JournalEntry{}, err
	}
	if err := validateID(entry.Operation, "journal operation"); err != nil {
		return JournalEntry{}, err
	}
	if err := validateID(entry.State, "journal state"); err != nil {
		return JournalEntry{}, err
	}
	if err := validateIdentity(entry.Identity.TargetID, entry.Identity); err != nil {
		return JournalEntry{}, err
	}
	if err := entry.Preimage.Validate(entry.Identity); err != nil {
		return JournalEntry{}, fmt.Errorf("invalid preimage: %w", err)
	}
	if err := entry.Postimage.Validate(entry.Identity); err != nil {
		return JournalEntry{}, fmt.Errorf("invalid postimage: %w", err)
	}
	ref, _ := payloadReference(backup)
	if entry.BackupRef != "" && entry.BackupRef != ref {
		return JournalEntry{}, errors.New("journal backup reference does not match payload")
	}
	if err := s.storePayload(ref, backup); err != nil {
		return JournalEntry{}, err
	}
	entry.BackupRef = ref
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO apply_journal(id, operation, state, target_id, source, file_path, schema_id, settings_path, setting_key,
preimage_state, preimage_kind, preimage_mode, preimage_link_target, preimage_value_type, preimage_value_text, preimage_size, preimage_digest,
postimage_state, postimage_kind, postimage_mode, postimage_link_target, postimage_value_type, postimage_value_text, postimage_size, postimage_digest, backup_ref, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.ID, entry.Operation, entry.State, entry.Identity.TargetID, entry.Identity.Source, entry.Identity.FilePath, entry.Identity.SchemaID, entry.Identity.SettingsPath, entry.Identity.SettingKey,
			entry.Preimage.State, entry.Preimage.Kind, entry.Preimage.Mode, entry.Preimage.LinkTarget, entry.Preimage.ValueType, entry.Preimage.ValueText, entry.Preimage.Size, entry.Preimage.Digest,
			entry.Postimage.State, entry.Postimage.Kind, entry.Postimage.Mode, entry.Postimage.LinkTarget, entry.Postimage.ValueType, entry.Postimage.ValueText, entry.Postimage.Size, entry.Postimage.Digest, entry.BackupRef, entry.CreatedAt)
		return err
	})
	return entry, err
}

func (s *Store) JournalEntries(ctx context.Context, targetID string) ([]JournalEntry, error) {
	var values []JournalEntry
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, `SELECT id, operation, state, target_id, source, file_path, schema_id, settings_path, setting_key,
preimage_state, preimage_kind, preimage_mode, preimage_link_target, preimage_value_type, preimage_value_text, preimage_size, preimage_digest,
postimage_state, postimage_kind, postimage_mode, postimage_link_target, postimage_value_type, postimage_value_text, postimage_size, postimage_digest, backup_ref, created_at
FROM apply_journal WHERE target_id = ? ORDER BY created_at, id`, targetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value JournalEntry
			var source string
			var preKind, postKind string
			var preMode, postMode uint32
			if err := rows.Scan(&value.ID, &value.Operation, &value.State, &value.Identity.TargetID, &source, &value.Identity.FilePath, &value.Identity.SchemaID, &value.Identity.SettingsPath, &value.Identity.SettingKey,
				&value.Preimage.State, &preKind, &preMode, &value.Preimage.LinkTarget, &value.Preimage.ValueType, &value.Preimage.ValueText, &value.Preimage.Size, &value.Preimage.Digest,
				&value.Postimage.State, &postKind, &postMode, &value.Postimage.LinkTarget, &value.Postimage.ValueType, &value.Postimage.ValueText, &value.Postimage.Size, &value.Postimage.Digest, &value.BackupRef, &value.CreatedAt); err != nil {
				return err
			}
			value.Identity.Source = model.SourceKind(source)
			value.Preimage.Kind = model.FileKind(preKind)
			value.Preimage.Mode = preMode
			value.Postimage.Kind = model.FileKind(postKind)
			value.Postimage.Mode = postMode
			values = append(values, value)
		}
		return rows.Err()
	})
	return values, err
}

func (s *Store) Payload(reference string) ([]byte, error) {
	name, err := payloadName(reference)
	if err != nil {
		return nil, err
	}
	return readPayload(filepath.Join(s.payloadDir, name), reference)
}

func (s *Store) withTx(ctx context.Context, operation func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return err
	}
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.secureSidecars()
}

func (s *Store) query(ctx context.Context, operation func(*sql.Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return operation(s.conn)
}

func (s *Store) ensureOpen() error {
	if s.closed || s.conn == nil {
		return errors.New("state store is closed")
	}
	return nil
}

func (s *Store) secureSidecars() error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := filepath.Join(s.stateDir, "state.db") + suffix
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), path)
		info, err := file.Stat()
		if err == nil && !info.Mode().IsRegular() {
			err = fmt.Errorf("refusing non-regular SQLite file %q", path)
		}
		if err == nil && info.Mode().Perm() != 0o600 {
			err = file.Chmod(0o600)
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func (s *Store) storePayload(reference string, payload []byte) error {
	name, err := payloadName(reference)
	if err != nil {
		return err
	}
	path := filepath.Join(s.payloadDir, name)
	if data, err := readPayload(path, reference); err == nil {
		if string(data) != string(payload) {
			return errors.New("payload digest collision")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(s.payloadDir, ".payload-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	written, writeErr := file.Write(payload)
	if writeErr == nil && written != len(payload) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		_ = file.Close()
		return writeErr
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		data, readErr := readPayload(path, reference)
		if readErr != nil || string(data) != string(payload) {
			return errors.New("existing payload does not match digest reference")
		}
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	committed = true
	return syncDirectory(s.payloadDir)
}

func payloadReference(payload []byte) (string, string) {
	digest := sha256.Sum256(payload)
	encoded := hex.EncodeToString(digest[:])
	return "sha256:" + encoded, encoded
}

func payloadName(reference string) (string, error) {
	if !strings.HasPrefix(reference, "sha256:") {
		return "", errors.New("invalid durable payload reference")
	}
	digest := strings.TrimPrefix(reference, "sha256:")
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(digest) != digest {
		return "", errors.New("invalid durable payload reference")
	}
	return digest, nil
}

func readPayload(path, reference string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("durable payload is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		if err := file.Chmod(0o600); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	actual, _ := payloadReference(data)
	if actual != reference {
		return nil, errors.New("durable payload digest mismatch")
	}
	return data, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

type scanner interface {
	Scan(...any) error
}

func scanBase(row scanner) (BaseRecord, error) {
	var record BaseRecord
	var source string
	var kind string
	var mode uint32
	if err := row.Scan(&record.Identity.TargetID, &source, &record.Identity.FilePath, &record.Identity.SchemaID, &record.Identity.SettingsPath, &record.Identity.SettingKey,
		&record.Fingerprint.State, &kind, &mode, &record.Fingerprint.LinkTarget, &record.Fingerprint.ValueType, &record.Fingerprint.ValueText, &record.Fingerprint.Size, &record.Fingerprint.Digest, &record.PayloadRef, &record.RecordedAt); err != nil {
		return BaseRecord{}, err
	}
	record.Identity.Source = model.SourceKind(source)
	record.Fingerprint.Kind = model.FileKind(kind)
	record.Fingerprint.Mode = mode
	return record, nil
}
