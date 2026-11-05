package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	_ "modernc.org/sqlite"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
)

type Store struct {
	mu         sync.Mutex
	payloadMu  sync.Mutex
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
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
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

func (s *Store) LocalHistorySummaries(ctx context.Context, maxTargets int) ([]LocalHistorySummary, error) {
	if maxTargets < 1 || maxTargets > MaxLocalHistoryTargets {
		return nil, errors.New("invalid local history summary bound")
	}
	const maxJournalGroupsPerTarget = 16
	var summaries []LocalHistorySummary
	err := s.query(ctx, func(conn *sql.Conn) error {
		var targetCount int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
			SELECT target_id FROM apply_journal UNION SELECT target_id FROM applied_base
		)`).Scan(&targetCount); err != nil {
			return err
		}
		if targetCount > maxTargets {
			return errors.New("local history target limit exceeded")
		}
		targets := make(map[string]int, targetCount)
		journalGroups := 0
		rows, err := conn.QueryContext(ctx, `SELECT target_id, state, stage, COUNT(*) FROM apply_journal GROUP BY target_id, state, stage ORDER BY target_id, state, stage LIMIT ?`, maxTargets*maxJournalGroupsPerTarget+1)
		if err != nil {
			return err
		}
		for rows.Next() {
			journalGroups++
			var targetID, stateName, stage string
			var count int64
			if err := rows.Scan(&targetID, &stateName, &stage, &count); err != nil {
				_ = rows.Close()
				return err
			}
			index, exists := targets[targetID]
			if !exists {
				index = len(summaries)
				targets[targetID] = index
				summaries = append(summaries, LocalHistorySummary{TargetID: targetID})
			}
			summaries[index].JournalCounts = append(summaries[index].JournalCounts, JournalHistoryCount{State: stateName, Stage: stage, Count: count})
			summaries[index].JournalCount += count
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if journalGroups > maxTargets*maxJournalGroupsPerTarget {
			return errors.New("local history journal summary limit exceeded")
		}
		rows, err = conn.QueryContext(ctx, `SELECT target_id, COUNT(*), MAX(recorded_at) FROM applied_base GROUP BY target_id ORDER BY target_id LIMIT ?`, maxTargets+1)
		if err != nil {
			return err
		}
		for rows.Next() {
			var targetID string
			var count, latestRecorded int64
			if err := rows.Scan(&targetID, &count, &latestRecorded); err != nil {
				_ = rows.Close()
				return err
			}
			if len(targets) == 0 {
				targets[targetID] = len(summaries)
				summaries = append(summaries, LocalHistorySummary{TargetID: targetID})
			} else if _, exists := targets[targetID]; !exists {
				targets[targetID] = len(summaries)
				summaries = append(summaries, LocalHistorySummary{TargetID: targetID})
			}
			index := targets[targetID]
			summaries[index].AppliedBaseCount = count
			summaries[index].AppliedBaseRecorded = latestRecorded
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for index := range summaries {
			if summaries[index].AppliedBaseCount == 0 {
				continue
			}
			if err := conn.QueryRowContext(ctx, `SELECT digest FROM applied_base WHERE target_id = ? ORDER BY recorded_at DESC, rowid DESC LIMIT 1`, summaries[index].TargetID).Scan(&summaries[index].AppliedBaseDigest); err != nil {
				return err
			}
		}
		for index := range summaries {
			var stateName, stage string
			err := conn.QueryRowContext(ctx, `SELECT state, stage FROM apply_journal WHERE target_id = ? ORDER BY rowid DESC LIMIT 1`, summaries[index].TargetID).Scan(&stateName, &stage)
			if err == nil {
				summaries[index].LatestJournalState = stateName
				summaries[index].LatestJournalStage = stage
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].TargetID < summaries[j].TargetID })
	return summaries, nil
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
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
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
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
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

func (s *Store) PutVaultSelection(ctx context.Context, selection VaultSelection) error {
	if selection.Vault == ([32]byte{}) || selection.RecordedAt < 0 || validateID(selection.DeviceID, "device id") != nil || len(selection.DeviceID) > vault.MaxDeviceIDBytes {
		return errors.New("invalid vault selection")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM vault_selections WHERE vault = ? AND device_id = ?", selection.Vault[:], selection.DeviceID).Scan(&exists)
		if err == nil {
			return ErrVaultSelectionExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO vault_selections(vault, device_id, recorded_at) VALUES (?, ?, ?)", selection.Vault[:], selection.DeviceID, selection.RecordedAt)
		return err
	})
}

func (s *Store) VaultSelections(ctx context.Context) ([]VaultSelection, error) {
	return s.readVaultSelections(ctx, 0)
}

func (s *Store) VaultSelectionsBounded(ctx context.Context, maxSelections int) ([]VaultSelection, error) {
	if maxSelections < 1 || maxSelections > MaxLocalHistoryTargets {
		return nil, errors.New("invalid vault selection bound")
	}
	return s.readVaultSelections(ctx, maxSelections)
}

func (s *Store) readVaultSelections(ctx context.Context, maxSelections int) ([]VaultSelection, error) {
	selections := make([]VaultSelection, 0)
	err := s.query(ctx, func(conn *sql.Conn) error {
		query := "SELECT vault, device_id, recorded_at FROM vault_selections ORDER BY vault, device_id"
		var rows *sql.Rows
		var err error
		if maxSelections > 0 {
			rows, err = conn.QueryContext(ctx, query+" LIMIT ?", maxSelections+1)
		} else {
			rows, err = conn.QueryContext(ctx, query)
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var selection VaultSelection
			var vaultID []byte
			if err := rows.Scan(&vaultID, &selection.DeviceID, &selection.RecordedAt); err != nil {
				return err
			}
			if len(vaultID) != len(selection.Vault) || selection.RecordedAt < 0 || validateID(selection.DeviceID, "device id") != nil || len(selection.DeviceID) > vault.MaxDeviceIDBytes {
				return errors.New("stored vault selection is malformed")
			}
			copy(selection.Vault[:], vaultID)
			selections = append(selections, selection)
			if maxSelections > 0 && len(selections) > maxSelections {
				return errors.New("vault selection limit exceeded")
			}
		}
		return rows.Err()
	})
	return selections, err
}

func (s *Store) PutVaultCheckpoint(ctx context.Context, checkpoint VaultCheckpoint) error {
	if len(checkpoint.ControlCID) == 0 || len(checkpoint.ControlCID) > 128 || len(checkpoint.ControlBytes) == 0 || len(checkpoint.SnapshotCID) > 128 || checkpoint.Epoch > uint64(^uint64(0)>>1) {
		return errors.New("invalid vault checkpoint")
	}
	if err := validateVaultCheckpointObject(checkpoint); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var existingAnchor, existingCID, existingBytes, existingSnapshot, existingDigest []byte
		var existingEpoch int64
		err := tx.QueryRowContext(ctx, "SELECT anchor, control_cid, control_bytes, snapshot_cid, epoch, policy_digest FROM vault_checkpoints WHERE vault = ?", checkpoint.Vault[:]).Scan(&existingAnchor, &existingCID, &existingBytes, &existingSnapshot, &existingEpoch, &existingDigest)
		if err == nil {
			if checkpoint.Epoch < uint64(existingEpoch) || checkpoint.Epoch == uint64(existingEpoch) && !bytes.Equal(checkpoint.ControlCID, existingCID) {
				return ErrCheckpointBackwards
			}
			if checkpoint.Epoch == uint64(existingEpoch) && (!bytes.Equal(checkpoint.ControlBytes, existingBytes) || !bytes.Equal(checkpoint.Anchor[:], existingAnchor) || !bytes.Equal(checkpoint.SnapshotCID, existingSnapshot) || !bytes.Equal(checkpoint.PolicyDigest[:], existingDigest)) {
				return errors.New("vault checkpoint fields changed at the same position")
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO vault_checkpoints(vault, anchor, control_cid, control_bytes, snapshot_cid, epoch, policy_digest, recorded_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(vault) DO UPDATE SET anchor=excluded.anchor, control_cid=excluded.control_cid, control_bytes=excluded.control_bytes, snapshot_cid=excluded.snapshot_cid, epoch=excluded.epoch, policy_digest=excluded.policy_digest, recorded_at=excluded.recorded_at`,
			checkpoint.Vault[:], checkpoint.Anchor[:], checkpoint.ControlCID, checkpoint.ControlBytes, checkpoint.SnapshotCID, checkpoint.Epoch, checkpoint.PolicyDigest[:], checkpoint.RecordedAt)
		return err
	})
}

func validateVaultCheckpointObject(checkpoint VaultCheckpoint) error {
	encoded := checkpoint.ControlBytes
	if len(encoded) < 79 || !bytes.Equal(encoded[:3], []byte{0x44, 0x54, 0x45}) || encoded[3] != 1 || encoded[4] != 3 {
		return errors.New("vault checkpoint control object is malformed")
	}
	if !bytes.Equal(encoded[5:37], checkpoint.Vault[:]) || binary.BigEndian.Uint64(encoded[37:45]) != checkpoint.Epoch || !bytes.Equal(encoded[45:77], checkpoint.PolicyDigest[:]) {
		return errors.New("vault checkpoint fields do not match control bytes")
	}
	cidLength := int(binary.BigEndian.Uint16(encoded[77:79]))
	if cidLength > 128 || len(encoded) < 79+cidLength {
		return errors.New("vault checkpoint snapshot CID is malformed")
	}
	if !bytes.Equal(encoded[79:79+cidLength], checkpoint.SnapshotCID) {
		return errors.New("vault checkpoint snapshot CID does not match control bytes")
	}
	digest, err := multihash.Sum(encoded, multihash.SHA2_256, -1)
	if err != nil || !bytes.Equal(cid.NewCidV1(cid.Raw, digest).Bytes(), checkpoint.ControlCID) {
		return errors.New("vault checkpoint CID does not match control bytes")
	}
	return nil
}

func (s *Store) VaultCheckpoint(ctx context.Context, vault [32]byte) (VaultCheckpoint, error) {
	var checkpoint VaultCheckpoint
	err := s.query(ctx, func(conn *sql.Conn) error {
		var storedVault, anchor, policyDigest []byte
		var epoch int64
		if err := conn.QueryRowContext(ctx, `SELECT vault, anchor, control_cid, control_bytes, snapshot_cid, epoch, policy_digest, recorded_at
FROM vault_checkpoints WHERE vault = ?`, vault[:]).Scan(&storedVault, &anchor, &checkpoint.ControlCID, &checkpoint.ControlBytes, &checkpoint.SnapshotCID, &epoch, &policyDigest, &checkpoint.RecordedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrVaultCheckpointNotFound
			}
			return err
		}
		if len(storedVault) != len(checkpoint.Vault) || len(anchor) != len(checkpoint.Anchor) || len(policyDigest) != len(checkpoint.PolicyDigest) || epoch < 0 {
			return errors.New("stored vault checkpoint is malformed")
		}
		copy(checkpoint.Vault[:], storedVault)
		copy(checkpoint.Anchor[:], anchor)
		copy(checkpoint.PolicyDigest[:], policyDigest)
		checkpoint.Epoch = uint64(epoch)
		return nil
	})
	return checkpoint, err
}

func (s *Store) PutAuthenticatedPositionEvidence(ctx context.Context, evidence AuthenticatedPositionEvidence) error {
	certificates, err := validateAuthenticatedPositionEvidence(evidence)
	if err != nil {
		return err
	}
	if evidence.Epoch > uint64(^uint64(0)>>1) {
		return errors.New("invalid authenticated position epoch")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if err := putAuthenticatedPositionEvidenceTx(ctx, tx, evidence, certificates); err != nil {
			return err
		}
		return putAuthenticatedPositionHistoryTx(ctx, tx, evidence, certificates)
	})
}

func (s *Store) PutAuthenticatedPositionHistory(ctx context.Context, evidence AuthenticatedPositionEvidence) error {
	certificates, err := validateAuthenticatedPositionEvidence(evidence)
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		return putAuthenticatedPositionHistoryTx(ctx, tx, evidence, certificates)
	})
}

func putAuthenticatedPositionHistoryTx(ctx context.Context, tx *sql.Tx, evidence AuthenticatedPositionEvidence, certificates [][]byte) error {
	head, err := vault.DecodeHead(evidence.Head)
	if err != nil {
		return err
	}
	if len(head.SnapshotCID) == 0 {
		return errors.New("authenticated position history head CID is missing")
	}
	var policyBytes, controlBytes, headBytes, checkpointPosition []byte
	err = tx.QueryRowContext(ctx, `SELECT policy_bytes, control_bytes, head_bytes, checkpoint_position
FROM authenticated_position_history WHERE vault = ? AND epoch = ? AND policy_digest = ? AND head_cid = ?`,
		evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:], head.SnapshotCID).Scan(&policyBytes, &controlBytes, &headBytes, &checkpointPosition)
	if err == nil {
		if !bytes.Equal(policyBytes, evidence.Policy) || !bytes.Equal(controlBytes, evidence.Control) || !bytes.Equal(headBytes, evidence.Head) {
			return ErrAuthenticatedPositionHistoryConflict
		}
		if len(checkpointPosition) != 0 && len(evidence.CheckpointPosition) != 0 && !bytes.Equal(checkpointPosition, evidence.CheckpointPosition) {
			return ErrAuthenticatedPositionHistoryConflict
		}
		if len(checkpointPosition) == 0 && len(evidence.CheckpointPosition) != 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE authenticated_position_history SET checkpoint_position = ? WHERE vault = ? AND epoch = ? AND policy_digest = ? AND head_cid = ?`, evidence.CheckpointPosition, evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:], head.SnapshotCID); err != nil {
				return err
			}
		}
		return comparePositionHistoryCertificates(ctx, tx, evidence, head.SnapshotCID, certificates)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authenticated_position_history(vault, epoch, policy_digest, head_cid, policy_bytes, control_bytes, head_bytes, checkpoint_position)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:], head.SnapshotCID,
		evidence.Policy, evidence.Control, evidence.Head, nullableBytes(evidence.CheckpointPosition)); err != nil {
		return err
	}
	for index, certificate := range certificates {
		if _, err := tx.ExecContext(ctx, `INSERT INTO authenticated_position_history_certificates(vault, epoch, policy_digest, head_cid, certificate_index, certificate_bytes)
VALUES (?, ?, ?, ?, ?, ?)`, evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:], head.SnapshotCID, index, certificate); err != nil {
			return err
		}
	}
	return nil
}

func comparePositionHistoryCertificates(ctx context.Context, tx *sql.Tx, evidence AuthenticatedPositionEvidence, headCID []byte, expected [][]byte) error {
	rows, err := tx.QueryContext(ctx, `SELECT certificate_index, certificate_bytes FROM authenticated_position_history_certificates
WHERE vault = ? AND epoch = ? AND policy_digest = ? AND head_cid = ? ORDER BY certificate_index`, evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:], headCID)
	if err != nil {
		return err
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var storedIndex int
		var certificate []byte
		if err := rows.Scan(&storedIndex, &certificate); err != nil {
			return err
		}
		if index >= len(expected) || storedIndex != index || !bytes.Equal(certificate, expected[index]) {
			return ErrAuthenticatedPositionHistoryConflict
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if index != len(expected) {
		return ErrAuthenticatedPositionHistoryConflict
	}
	return nil
}

func (s *Store) AuthenticatedPositionHistory(ctx context.Context, vaultID [32]byte) ([]AuthenticatedPositionEvidence, error) {
	positions := make([]AuthenticatedPositionEvidence, 0)
	seen := make(map[string]struct{})
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, `SELECT epoch, policy_digest, policy_bytes, control_bytes, head_bytes, checkpoint_position
FROM authenticated_position_history WHERE vault = ? ORDER BY epoch, head_cid`, vaultID[:])
		if err != nil {
			return err
		}
		for rows.Next() {
			var evidence AuthenticatedPositionEvidence
			var digest []byte
			evidence.Vault = vaultID
			if err := rows.Scan(&evidence.Epoch, &digest, &evidence.Policy, &evidence.Control, &evidence.Head, &evidence.CheckpointPosition); err != nil {
				rows.Close()
				return err
			}
			if len(digest) != len(evidence.PolicyDigest) {
				rows.Close()
				return errors.New("stored authenticated position history digest is malformed")
			}
			copy(evidence.PolicyDigest[:], digest)
			certRows, certErr := conn.QueryContext(ctx, `SELECT certificate_index, certificate_bytes FROM authenticated_position_history_certificates
WHERE vault = ? AND epoch = ? AND policy_digest = ? AND head_cid = ? ORDER BY certificate_index`, vaultID[:], evidence.Epoch, digest, mustPositionHeadCID(evidence.Head))
			if certErr != nil {
				rows.Close()
				return certErr
			}
			for expectedIndex := 0; certRows.Next(); expectedIndex++ {
				var index int
				var certificate []byte
				if err := certRows.Scan(&index, &certificate); err != nil {
					certRows.Close()
					rows.Close()
					return err
				}
				if index != expectedIndex {
					certRows.Close()
					rows.Close()
					return errors.New("stored authenticated position history certificate order is malformed")
				}
				evidence.Certificates = append(evidence.Certificates, bytes.Clone(certificate))
			}
			if err := certRows.Err(); err != nil {
				certRows.Close()
				rows.Close()
				return err
			}
			if err := certRows.Close(); err != nil {
				rows.Close()
				return err
			}
			if _, err := validateAuthenticatedPositionEvidence(evidence); err != nil {
				rows.Close()
				return fmt.Errorf("stored authenticated position history is invalid: %w", err)
			}
			headCID := mustPositionHeadCID(evidence.Head)
			seen[positionHistoryIdentity(evidence.Vault, evidence.Epoch, evidence.PolicyDigest, headCID)] = struct{}{}
			positions = append(positions, cloneAuthenticatedPositionEvidence(evidence))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		latestRows, err := conn.QueryContext(ctx, `SELECT epoch, policy_digest, policy_bytes, control_bytes, head_bytes, checkpoint_position
FROM authenticated_position_evidence WHERE vault = ? ORDER BY epoch`, vaultID[:])
		if err != nil {
			return err
		}
		defer latestRows.Close()
		for latestRows.Next() {
			var evidence AuthenticatedPositionEvidence
			var digest []byte
			evidence.Vault = vaultID
			if err := latestRows.Scan(&evidence.Epoch, &digest, &evidence.Policy, &evidence.Control, &evidence.Head, &evidence.CheckpointPosition); err != nil {
				return err
			}
			if len(digest) != len(evidence.PolicyDigest) {
				return errors.New("stored authenticated position digest is malformed")
			}
			copy(evidence.PolicyDigest[:], digest)
			certRows, certErr := conn.QueryContext(ctx, `SELECT certificate_index, certificate_bytes FROM authenticated_position_certificates
WHERE vault = ? AND epoch = ? AND policy_digest = ? ORDER BY certificate_index`, vaultID[:], evidence.Epoch, digest)
			if certErr != nil {
				return certErr
			}
			for expectedIndex := 0; certRows.Next(); expectedIndex++ {
				var index int
				var certificate []byte
				if err := certRows.Scan(&index, &certificate); err != nil {
					certRows.Close()
					return err
				}
				if index != expectedIndex {
					certRows.Close()
					return errors.New("stored authenticated position certificate order is malformed")
				}
				evidence.Certificates = append(evidence.Certificates, bytes.Clone(certificate))
			}
			if err := certRows.Err(); err != nil {
				certRows.Close()
				return err
			}
			if err := certRows.Close(); err != nil {
				return err
			}
			if _, err := validateAuthenticatedPositionEvidence(evidence); err != nil {
				return fmt.Errorf("stored authenticated position evidence is invalid: %w", err)
			}
			headCID := mustPositionHeadCID(evidence.Head)
			identity := positionHistoryIdentity(evidence.Vault, evidence.Epoch, evidence.PolicyDigest, headCID)
			if _, exists := seen[identity]; exists {
				for index := range positions {
					if positionHistoryIdentity(positions[index].Vault, positions[index].Epoch, positions[index].PolicyDigest, mustPositionHeadCID(positions[index].Head)) != identity {
						continue
					}
					if !sameAuthenticatedPositionContent(positions[index], evidence) || len(positions[index].CheckpointPosition) != 0 && len(evidence.CheckpointPosition) != 0 && !bytes.Equal(positions[index].CheckpointPosition, evidence.CheckpointPosition) {
						return ErrAuthenticatedPositionHistoryConflict
					}
					if len(positions[index].CheckpointPosition) == 0 {
						positions[index].CheckpointPosition = bytes.Clone(evidence.CheckpointPosition)
					}
					break
				}
				continue
			}
			seen[identity] = struct{}{}
			positions = append(positions, cloneAuthenticatedPositionEvidence(evidence))
		}
		return latestRows.Err()
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(positions, func(i, j int) bool {
		if positions[i].Epoch != positions[j].Epoch {
			return positions[i].Epoch < positions[j].Epoch
		}
		left, _ := vault.DecodeHead(positions[i].Head)
		right, _ := vault.DecodeHead(positions[j].Head)
		if left.PublicationCount != right.PublicationCount {
			return left.PublicationCount < right.PublicationCount
		}
		return bytes.Compare(left.SnapshotCID, right.SnapshotCID) < 0
	})
	return positions, nil
}

func mustPositionHeadCID(encoded []byte) []byte {
	head, err := vault.DecodeHead(encoded)
	if err != nil {
		return nil
	}
	return bytes.Clone(head.SnapshotCID)
}

func positionHistoryIdentity(vaultID [32]byte, epoch uint64, digest [32]byte, headCID []byte) string {
	return string(vaultID[:]) + string(binary.BigEndian.AppendUint64(nil, epoch)) + string(digest[:]) + string(headCID)
}

func sameAuthenticatedPositionContent(left, right AuthenticatedPositionEvidence) bool {
	if left.Vault != right.Vault || left.Epoch != right.Epoch || left.PolicyDigest != right.PolicyDigest ||
		!bytes.Equal(left.Policy, right.Policy) || !bytes.Equal(left.Control, right.Control) || !bytes.Equal(left.Head, right.Head) || len(left.Certificates) != len(right.Certificates) {
		return false
	}
	for index := range left.Certificates {
		if !bytes.Equal(left.Certificates[index], right.Certificates[index]) {
			return false
		}
	}
	return true
}

func (s *Store) ImportVaultOnboarding(ctx context.Context, selection VaultSelection, checkpoint VaultCheckpoint, predecessor AuthenticatedPositionEvidence) error {
	if selection.Vault == ([32]byte{}) || selection.RecordedAt < 0 || validateID(selection.DeviceID, "device id") != nil || len(selection.DeviceID) > vault.MaxDeviceIDBytes {
		return errors.New("invalid onboarding vault selection")
	}
	if len(checkpoint.ControlCID) == 0 || len(checkpoint.ControlCID) > 128 || len(checkpoint.ControlBytes) == 0 || len(checkpoint.SnapshotCID) == 0 || len(checkpoint.SnapshotCID) > 128 || checkpoint.Epoch == 0 || checkpoint.Epoch > uint64(^uint64(0)>>1) || checkpoint.RecordedAt < 0 {
		return errors.New("invalid onboarding checkpoint")
	}
	if err := validateVaultCheckpointObject(checkpoint); err != nil {
		return err
	}
	certificates, err := validateAuthenticatedPositionEvidence(predecessor)
	if err != nil {
		return err
	}
	if checkpoint.Vault != selection.Vault || predecessor.Vault != selection.Vault || checkpoint.Anchor == ([32]byte{}) || predecessor.Epoch+1 != checkpoint.Epoch {
		return errors.New("onboarding state positions do not match")
	}
	control, err := vault.DecodeControl(checkpoint.ControlBytes)
	if err != nil || !bytes.Equal(control.PrevControlCID, authenticatedPositionRawCID(predecessor.Control)) || !bytes.Equal(control.HeadSnapshotCID, checkpoint.SnapshotCID) {
		return errors.New("onboarding checkpoint control does not follow predecessor evidence")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM vault_selections WHERE vault = ?", selection.Vault[:]).Scan(&exists)
		if err == nil {
			return ErrVaultSelectionExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = tx.QueryRowContext(ctx, "SELECT 1 FROM vault_checkpoints WHERE vault = ?", checkpoint.Vault[:]).Scan(&exists)
		if err == nil {
			return ErrOnboardingStateConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO vault_selections(vault, device_id, recorded_at) VALUES (?, ?, ?)", selection.Vault[:], selection.DeviceID, selection.RecordedAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vault_checkpoints(vault, anchor, control_cid, control_bytes, snapshot_cid, epoch, policy_digest, recorded_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, checkpoint.Vault[:], checkpoint.Anchor[:], checkpoint.ControlCID, checkpoint.ControlBytes, checkpoint.SnapshotCID, checkpoint.Epoch, checkpoint.PolicyDigest[:], checkpoint.RecordedAt); err != nil {
			return err
		}
		if err := putAuthenticatedPositionEvidenceTx(ctx, tx, predecessor, certificates); err != nil {
			return err
		}
		return putAuthenticatedPositionHistoryTx(ctx, tx, predecessor, certificates)
	})
}

func (s *Store) InitializeVaultTrust(ctx context.Context, selection VaultSelection, checkpoint VaultCheckpoint, evidence AuthenticatedPositionEvidence) error {
	if selection.Vault == ([32]byte{}) || selection.RecordedAt < 0 || validateID(selection.DeviceID, "device id") != nil || len(selection.DeviceID) > vault.MaxDeviceIDBytes {
		return errors.New("invalid genesis vault selection")
	}
	if checkpoint.Vault != selection.Vault || checkpoint.Epoch != 0 || checkpoint.RecordedAt < 0 || len(checkpoint.ControlCID) == 0 || len(checkpoint.ControlBytes) == 0 || len(checkpoint.SnapshotCID) == 0 {
		return errors.New("invalid genesis checkpoint")
	}
	if err := validateVaultCheckpointObject(checkpoint); err != nil {
		return err
	}
	certificates, err := validateAuthenticatedPositionEvidence(evidence)
	if err != nil {
		return err
	}
	if evidence.Vault != selection.Vault || evidence.Epoch != 0 || evidence.PolicyDigest != checkpoint.PolicyDigest ||
		!bytes.Equal(evidence.Control, checkpoint.ControlBytes) || len(evidence.CheckpointPosition) == 0 ||
		!bytes.Equal(authenticatedPositionRawCID(evidence.Control), checkpoint.ControlCID) {
		return errors.New("genesis trust positions do not match")
	}
	head, err := vault.DecodeHead(evidence.Head)
	if err != nil || !bytes.Equal(head.SnapshotCID, checkpoint.SnapshotCID) || checkpoint.Anchor == ([32]byte{}) {
		return errors.New("genesis checkpoint does not match authenticated position evidence")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM vault_selections WHERE vault = ?", selection.Vault[:]).Scan(&exists)
		if err == nil {
			return ErrVaultSelectionExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = tx.QueryRowContext(ctx, "SELECT 1 FROM vault_checkpoints WHERE vault = ?", checkpoint.Vault[:]).Scan(&exists)
		if err == nil {
			return ErrVaultSelectionExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO vault_selections(vault, device_id, recorded_at) VALUES (?, ?, ?)", selection.Vault[:], selection.DeviceID, selection.RecordedAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vault_checkpoints(vault, anchor, control_cid, control_bytes, snapshot_cid, epoch, policy_digest, recorded_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, checkpoint.Vault[:], checkpoint.Anchor[:], checkpoint.ControlCID, checkpoint.ControlBytes, checkpoint.SnapshotCID, checkpoint.Epoch, checkpoint.PolicyDigest[:], checkpoint.RecordedAt); err != nil {
			return err
		}
		if err := putAuthenticatedPositionEvidenceTx(ctx, tx, evidence, certificates); err != nil {
			return err
		}
		return putAuthenticatedPositionHistoryTx(ctx, tx, evidence, certificates)
	})
}

func putAuthenticatedPositionEvidenceTx(ctx context.Context, tx *sql.Tx, evidence AuthenticatedPositionEvidence, certificates [][]byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authenticated_position_evidence(vault, epoch, policy_digest, policy_bytes, control_bytes, head_bytes, checkpoint_position)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(vault, epoch, policy_digest) DO UPDATE SET policy_bytes=excluded.policy_bytes, control_bytes=excluded.control_bytes, head_bytes=excluded.head_bytes, checkpoint_position=excluded.checkpoint_position`,
		evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:], evidence.Policy, evidence.Control, evidence.Head, nullableBytes(evidence.CheckpointPosition))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM authenticated_position_certificates WHERE vault = ? AND epoch = ? AND policy_digest = ?", evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:]); err != nil {
		return err
	}
	for index, certificate := range certificates {
		if _, err := tx.ExecContext(ctx, `INSERT INTO authenticated_position_certificates(vault, epoch, policy_digest, certificate_index, certificate_bytes)
VALUES (?, ?, ?, ?, ?)`, evidence.Vault[:], evidence.Epoch, evidence.PolicyDigest[:], index, certificate); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) AuthenticatedPositionEvidenceAtEpoch(ctx context.Context, vaultID [32]byte, epoch uint64) (AuthenticatedPositionEvidence, error) {
	if epoch > uint64(^uint64(0)>>1) {
		return AuthenticatedPositionEvidence{}, errors.New("invalid authenticated position epoch")
	}
	var evidence AuthenticatedPositionEvidence
	evidence.Vault = vaultID
	evidence.Epoch = epoch
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, "SELECT policy_digest FROM authenticated_position_evidence WHERE vault = ? AND epoch = ?", vaultID[:], epoch)
		if err != nil {
			return err
		}
		var digest []byte
		if !rows.Next() {
			rows.Close()
			return ErrAuthenticatedPositionEvidenceNotFound
		}
		if err := rows.Scan(&digest); err != nil {
			rows.Close()
			return err
		}
		if rows.Next() {
			rows.Close()
			return ErrAuthenticatedPositionEvidenceAmbiguous
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(digest) != len(evidence.PolicyDigest) {
			return errors.New("stored authenticated position digest is malformed")
		}
		copy(evidence.PolicyDigest[:], digest)
		if err := conn.QueryRowContext(ctx, `SELECT policy_bytes, control_bytes, head_bytes, checkpoint_position
FROM authenticated_position_evidence WHERE vault = ? AND epoch = ? AND policy_digest = ?`, vaultID[:], epoch, digest).Scan(&evidence.Policy, &evidence.Control, &evidence.Head, &evidence.CheckpointPosition); err != nil {
			return err
		}
		rows, err = conn.QueryContext(ctx, `SELECT certificate_index, certificate_bytes
FROM authenticated_position_certificates WHERE vault = ? AND epoch = ? AND policy_digest = ? ORDER BY certificate_index`, vaultID[:], epoch, digest)
		if err != nil {
			return err
		}
		defer rows.Close()
		for expectedIndex := 0; rows.Next(); expectedIndex++ {
			var index int
			var certificate []byte
			if err := rows.Scan(&index, &certificate); err != nil {
				return err
			}
			if index != expectedIndex {
				return errors.New("stored authenticated position certificate order is malformed")
			}
			evidence.Certificates = append(evidence.Certificates, bytes.Clone(certificate))
		}
		return rows.Err()
	})
	if err != nil {
		return AuthenticatedPositionEvidence{}, err
	}
	if _, err := validateAuthenticatedPositionEvidence(evidence); err != nil {
		return AuthenticatedPositionEvidence{}, fmt.Errorf("stored authenticated position evidence is invalid: %w", err)
	}
	return cloneAuthenticatedPositionEvidence(evidence), nil
}

func (s *Store) AuthenticatedPositionEvidence(ctx context.Context, vaultID [32]byte, epoch uint64, policyDigest [32]byte) (AuthenticatedPositionEvidence, error) {
	if epoch > uint64(^uint64(0)>>1) {
		return AuthenticatedPositionEvidence{}, errors.New("invalid authenticated position epoch")
	}
	var evidence AuthenticatedPositionEvidence
	evidence.Vault = vaultID
	evidence.Epoch = epoch
	evidence.PolicyDigest = policyDigest
	err := s.query(ctx, func(conn *sql.Conn) error {
		var digest []byte
		if err := conn.QueryRowContext(ctx, `SELECT policy_digest, policy_bytes, control_bytes, head_bytes, checkpoint_position
FROM authenticated_position_evidence WHERE vault = ? AND epoch = ? AND policy_digest = ?`, vaultID[:], epoch, policyDigest[:]).Scan(&digest, &evidence.Policy, &evidence.Control, &evidence.Head, &evidence.CheckpointPosition); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAuthenticatedPositionEvidenceNotFound
			}
			return err
		}
		if len(digest) != len(policyDigest) || !bytes.Equal(digest, policyDigest[:]) {
			return errors.New("stored authenticated position digest is malformed")
		}
		rows, err := conn.QueryContext(ctx, `SELECT certificate_index, certificate_bytes
FROM authenticated_position_certificates WHERE vault = ? AND epoch = ? AND policy_digest = ? ORDER BY certificate_index`, vaultID[:], epoch, policyDigest[:])
		if err != nil {
			return err
		}
		defer rows.Close()
		for expectedIndex := 0; rows.Next(); expectedIndex++ {
			var index int
			var certificate []byte
			if err := rows.Scan(&index, &certificate); err != nil {
				return err
			}
			if index != expectedIndex {
				return errors.New("stored authenticated position certificate order is malformed")
			}
			evidence.Certificates = append(evidence.Certificates, bytes.Clone(certificate))
		}
		return rows.Err()
	})
	if err != nil {
		return AuthenticatedPositionEvidence{}, err
	}
	if _, err := validateAuthenticatedPositionEvidence(evidence); err != nil {
		return AuthenticatedPositionEvidence{}, fmt.Errorf("stored authenticated position evidence is invalid: %w", err)
	}
	return cloneAuthenticatedPositionEvidence(evidence), nil
}

func validateAuthenticatedPositionEvidence(evidence AuthenticatedPositionEvidence) ([][]byte, error) {
	if evidence.Epoch > uint64(^uint64(0)>>1) || len(evidence.Policy) == 0 || len(evidence.Policy) > vault.MaxPolicyObjectBytes || len(evidence.Control) == 0 || len(evidence.Control) > vault.MaxPolicyObjectBytes || len(evidence.Head) == 0 || len(evidence.Head) > vault.MaxPolicyObjectBytes || len(evidence.CheckpointPosition) > vault.MaxPolicyObjectBytes || len(evidence.Certificates) == 0 || len(evidence.Certificates) > vault.MaxRecipients {
		return nil, errors.New("authenticated position evidence exceeds its bounds")
	}
	policy, err := vault.DecodePolicy(evidence.Policy)
	if err != nil {
		return nil, fmt.Errorf("invalid authenticated position policy: %w", err)
	}
	policyDigest, err := vault.ComputePolicyDigest(evidence.Policy)
	if err != nil || policy.Vault != evidence.Vault || policy.EpochSeq != evidence.Epoch || policyDigest != evidence.PolicyDigest {
		return nil, errors.New("authenticated position policy does not match its key")
	}
	control, err := vault.DecodeControl(evidence.Control)
	if err != nil || control.Vault != evidence.Vault || control.EpochSeq != evidence.Epoch || control.PolicyDigest != evidence.PolicyDigest {
		return nil, errors.New("authenticated position control does not match its key")
	}
	head, err := vault.DecodeHead(evidence.Head)
	if err != nil || head.Vault != evidence.Vault || head.EpochSeq != evidence.Epoch || head.PolicyDigest != evidence.PolicyDigest {
		return nil, errors.New("authenticated position head does not match its key")
	}
	if len(head.SnapshotCID) == 0 || !bytes.Equal(head.SnapshotCID, head.BlobCID) || head.PublicationCount == 0 && !bytes.Equal(control.HeadSnapshotCID, head.SnapshotCID) {
		return nil, errors.New("authenticated position head and control do not match")
	}
	if len(evidence.CheckpointPosition) != 0 {
		checkpoint, err := vault.DecodeCheckpoint(evidence.CheckpointPosition)
		controlCID := authenticatedPositionRawCID(evidence.Control)
		if err != nil || checkpoint.Vault != evidence.Vault || checkpoint.EpochSeq != evidence.Epoch || checkpoint.PolicyDigest != evidence.PolicyDigest || !bytes.Equal(checkpoint.ControlCID, controlCID) || !bytes.Equal(checkpoint.SnapshotCID, control.HeadSnapshotCID) {
			return nil, errors.New("authenticated position checkpoint does not match its control position")
		}
	}
	if len(policy.Recipients) != len(evidence.Certificates) {
		return nil, errors.New("authenticated position certificate set does not match policy recipients")
	}
	certificates := make([][]byte, len(evidence.Certificates))
	decodedCertificates := make([]vault.Certificate, len(evidence.Certificates))
	seen := make(map[string]struct{}, len(evidence.Certificates))
	for index, encoded := range evidence.Certificates {
		if len(encoded) == 0 || len(encoded) > vault.MaxPolicyObjectBytes {
			return nil, errors.New("authenticated position certificate exceeds its bound")
		}
		certificate, err := vault.DecodeCertificate(encoded)
		if err != nil || certificate.Vault != evidence.Vault {
			return nil, errors.New("authenticated position certificate is invalid")
		}
		identity := certificate.DeviceID + "\x00" + string(certificate.KeyID)
		if _, duplicate := seen[identity]; duplicate {
			return nil, errors.New("authenticated position certificate set contains a duplicate")
		}
		seen[identity] = struct{}{}
		decodedCertificates[index] = certificate
		certificates[index] = bytes.Clone(encoded)
	}
	sort.Slice(certificates, func(i, j int) bool {
		left, _ := vault.DecodeCertificate(certificates[i])
		right, _ := vault.DecodeCertificate(certificates[j])
		if left.DeviceID != right.DeviceID {
			return left.DeviceID < right.DeviceID
		}
		return bytes.Compare(left.KeyID, right.KeyID) < 0
	})
	for _, recipient := range policy.Recipients {
		found := false
		for _, certificate := range decodedCertificates {
			if certificate.DeviceID == recipient.DeviceID && bytes.Equal(certificate.KeyID, recipient.KeyID) && bytes.Equal(certificate.EncryptionPublicKey[:], recipient.PublicKey[:]) {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("authenticated position certificate does not match policy recipient")
		}
	}
	return certificates, nil
}

func authenticatedPositionRawCID(data []byte) []byte {
	digest, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return nil
	}
	return cid.NewCidV1(cid.Raw, digest).Bytes()
}

func cloneAuthenticatedPositionEvidence(evidence AuthenticatedPositionEvidence) AuthenticatedPositionEvidence {
	certificates := evidence.Certificates
	evidence.Policy = bytes.Clone(evidence.Policy)
	evidence.Control = bytes.Clone(evidence.Control)
	evidence.Head = bytes.Clone(evidence.Head)
	evidence.CheckpointPosition = bytes.Clone(evidence.CheckpointPosition)
	evidence.Certificates = make([][]byte, len(certificates))
	for index := range certificates {
		evidence.Certificates[index] = bytes.Clone(certificates[index])
	}
	return evidence
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func (s *Store) RecordVaultEpochFirstSeen(ctx context.Context, vault [32]byte, epoch uint64, firstSeenAt int64) error {
	if epoch > uint64(^uint64(0)>>1) || firstSeenAt < 0 {
		return errors.New("invalid vault epoch first-seen time")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO vault_epoch_first_seen(vault, epoch, first_seen_at)
VALUES (?, ?, ?) ON CONFLICT(vault, epoch) DO NOTHING`, vault[:], epoch, firstSeenAt)
		return err
	})
}

func (s *Store) VaultPublicationEpoch(ctx context.Context, vault [32]byte) (uint64, bool, error) {
	var epoch int64
	err := s.query(ctx, func(conn *sql.Conn) error {
		return conn.QueryRowContext(ctx, "SELECT epoch FROM vault_publication_observations WHERE vault = ?", vault[:]).Scan(&epoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if epoch < 0 {
		return 0, false, errors.New("stored vault publication epoch is malformed")
	}
	return uint64(epoch), true, nil
}

func (s *Store) VaultEpochFirstSeen(ctx context.Context, vault [32]byte, epoch uint64) (int64, bool, error) {
	if epoch > uint64(^uint64(0)>>1) {
		return 0, false, errors.New("invalid vault epoch")
	}
	var firstSeenAt int64
	err := s.query(ctx, func(conn *sql.Conn) error {
		return conn.QueryRowContext(ctx, "SELECT first_seen_at FROM vault_epoch_first_seen WHERE vault = ? AND epoch = ?", vault[:], epoch).Scan(&firstSeenAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return firstSeenAt, true, nil
}

func (s *Store) RecordVaultPublicationObservation(ctx context.Context, observation VaultPublicationObservation) error {
	if len(observation.HeadCID) == 0 || len(observation.HeadCID) > 128 || len(observation.ControlCID) == 0 || len(observation.ControlCID) > 128 || len(observation.PrevControlCID) > 128 || observation.Epoch > uint64(^uint64(0)>>1) || observation.PublicationCount > uint64(^uint64(0)>>1) {
		return errors.New("invalid vault publication observation")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var existingEpoch, existingCount int64
		var existingHeadCID, existingControlCID []byte
		err := tx.QueryRowContext(ctx, "SELECT epoch, publication_count, head_cid, control_cid FROM vault_publication_observations WHERE vault = ?", observation.Vault[:]).Scan(&existingEpoch, &existingCount, &existingHeadCID, &existingControlCID)
		if err == nil {
			if observation.Epoch < uint64(existingEpoch) {
				return ErrVaultPublicationBackwards
			}
			if observation.Epoch > uint64(existingEpoch) && (len(existingControlCID) == 0 || !bytes.Equal(observation.PrevControlCID, existingControlCID)) {
				return ErrVaultPublicationControlAncestry
			}
			if observation.Epoch == uint64(existingEpoch) {
				idempotentReread := observation.PublicationCount == uint64(existingCount) &&
					bytes.Equal(observation.HeadCID, existingHeadCID) && bytes.Equal(observation.ControlCID, existingControlCID)
				if !idempotentReread && !bytes.Equal(observation.ControlCID, existingControlCID) {
					if len(existingControlCID) != 0 {
						return ErrVaultPublicationControlReplacement
					}
					if len(observation.ControlCID) == 0 {
						return ErrVaultPublicationControlReplacement
					}
				}
				if observation.PublicationCount < uint64(existingCount) {
					return ErrVaultPublicationBackwards
				}
				if observation.PublicationCount == uint64(existingCount) && !bytes.Equal(observation.HeadCID, existingHeadCID) {
					return ErrVaultPublicationConflict
				}
				if observation.PublicationCount > uint64(existingCount) {
					if observation.PublicationCount > uint64(existingCount)+1 {
						return ErrVaultPublicationGap
					}
					if bytes.Equal(observation.HeadCID, existingHeadCID) {
						return ErrVaultPublicationConflict
					}
					if !bytes.Equal(observation.PrevHeadCID, existingHeadCID) {
						return ErrPublicationAncestry
					}
					if observation.EnforceParent && !bytes.Equal(observation.ParentCID, existingHeadCID) {
						return ErrPublicationAncestry
					}
				}
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO vault_publication_observations(vault, epoch, publication_count, head_cid, control_cid)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(vault) DO UPDATE SET epoch=excluded.epoch, publication_count=excluded.publication_count, head_cid=excluded.head_cid, control_cid=excluded.control_cid`,
			observation.Vault[:], observation.Epoch, observation.PublicationCount, observation.HeadCID, observation.ControlCID)
		return err
	})
}

func (s *Store) BeginTransitionAttempt(ctx context.Context, attempt TransitionAttempt) error {
	if err := validateTransitionAttempt(attempt); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO transition_attempts(id, marker_collection, marker_rkey, expected_record_cid, candidate_blob_cid, epoch_seq, policy_digest, outcome, evidence, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, attempt.ID, attempt.MarkerCollection, attempt.MarkerRKey, attempt.ExpectedRecordCID, attempt.CandidateBlobCID, attempt.EpochSeq, attempt.PolicyDigest, attempt.Outcome, attempt.Evidence, attempt.CreatedAt)
		return err
	})
}

func (s *Store) UpdateTransitionAttempt(ctx context.Context, id, outcome, evidence string) error {
	if err := validateID(id, "transition attempt id"); err != nil {
		return err
	}
	if !validTransitionAttemptOutcome(outcome) {
		return errors.New("invalid transition attempt outcome")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var current string
		if err := tx.QueryRowContext(ctx, "SELECT outcome FROM transition_attempts WHERE id = ?", id).Scan(&current); err != nil {
			return err
		}
		if !validTransitionAttemptOutcomeChange(current, outcome) {
			return errors.New("transition attempt outcome cannot be changed")
		}
		_, err := tx.ExecContext(ctx, "UPDATE transition_attempts SET outcome = ?, evidence = ? WHERE id = ?", outcome, evidence, id)
		return err
	})
}

func (s *Store) TransitionAttempts(ctx context.Context) ([]TransitionAttempt, error) {
	var attempts []TransitionAttempt
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, `SELECT id, marker_collection, marker_rkey, expected_record_cid, candidate_blob_cid, epoch_seq, policy_digest, outcome, evidence, created_at
FROM transition_attempts ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var attempt TransitionAttempt
			if err := rows.Scan(&attempt.ID, &attempt.MarkerCollection, &attempt.MarkerRKey, &attempt.ExpectedRecordCID, &attempt.CandidateBlobCID, &attempt.EpochSeq, &attempt.PolicyDigest, &attempt.Outcome, &attempt.Evidence, &attempt.CreatedAt); err != nil {
				return err
			}
			attempts = append(attempts, attempt)
		}
		return rows.Err()
	})
	return attempts, err
}

func (s *Store) TransitionAttemptsByMarker(ctx context.Context, collection, rkey string) ([]TransitionAttempt, error) {
	if err := validateID(collection, "transition marker collection"); err != nil {
		return nil, err
	}
	if err := validateID(rkey, "transition marker rkey"); err != nil {
		return nil, err
	}
	var attempts []TransitionAttempt
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, `SELECT id, marker_collection, marker_rkey, expected_record_cid, candidate_blob_cid, epoch_seq, policy_digest, outcome, evidence, created_at
FROM transition_attempts WHERE marker_collection = ? AND marker_rkey = ? ORDER BY created_at, id`, collection, rkey)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var attempt TransitionAttempt
			if err := rows.Scan(&attempt.ID, &attempt.MarkerCollection, &attempt.MarkerRKey, &attempt.ExpectedRecordCID, &attempt.CandidateBlobCID, &attempt.EpochSeq, &attempt.PolicyDigest, &attempt.Outcome, &attempt.Evidence, &attempt.CreatedAt); err != nil {
				return err
			}
			attempts = append(attempts, attempt)
		}
		return rows.Err()
	})
	return attempts, err
}

func (s *Store) TransitionAttempt(ctx context.Context, id string) (TransitionAttempt, error) {
	if err := validateID(id, "transition attempt id"); err != nil {
		return TransitionAttempt{}, err
	}
	var attempt TransitionAttempt
	err := s.query(ctx, func(conn *sql.Conn) error {
		return conn.QueryRowContext(ctx, `SELECT id, marker_collection, marker_rkey, expected_record_cid, candidate_blob_cid, epoch_seq, policy_digest, outcome, evidence, created_at
FROM transition_attempts WHERE id = ?`, id).Scan(&attempt.ID, &attempt.MarkerCollection, &attempt.MarkerRKey, &attempt.ExpectedRecordCID, &attempt.CandidateBlobCID, &attempt.EpochSeq, &attempt.PolicyDigest, &attempt.Outcome, &attempt.Evidence, &attempt.CreatedAt)
	})
	return attempt, err
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
	backupReference, backupDigest := payloadReference(backup)
	if int64(len(backup)) != entry.Preimage.Size || backupDigest != entry.Preimage.Digest {
		return JournalEntry{}, errors.New("journal backup does not match the recorded preimage")
	}
	ref := backupReference
	if entry.BackupRef != "" && entry.BackupRef != ref {
		return JournalEntry{}, errors.New("journal backup reference does not match payload")
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	if err := s.storePayload(ref, backup); err != nil {
		return JournalEntry{}, err
	}
	entry.BackupRef = ref
	var retentionVault, retentionSnapshot, retentionPolicyDigest, retentionControlCID any
	var retentionEpoch any
	entry.RetentionBindingVersion = 1
	if entry.Retention != nil {
		binding := entry.Retention
		if binding.Vault == ([32]byte{}) || binding.Epoch > uint64(^uint64(0)>>1) || len(binding.SnapshotCID) == 0 || len(binding.SnapshotCID) > 128 || binding.PolicyDigest == ([32]byte{}) || len(binding.ControlCID) == 0 || len(binding.ControlCID) > 128 {
			return JournalEntry{}, errors.New("invalid journal retention binding")
		}
		retentionVault, retentionEpoch = binding.Vault[:], binding.Epoch
		retentionSnapshot, retentionPolicyDigest, retentionControlCID = binding.SnapshotCID, binding.PolicyDigest[:], binding.ControlCID
	}
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var selectedDevice string
		if entry.Retention != nil {
			rows, err := tx.QueryContext(ctx, "SELECT device_id FROM vault_selections WHERE vault = ? ORDER BY device_id LIMIT 2", entry.Retention.Vault[:])
			if err != nil {
				return err
			}
			if !rows.Next() {
				_ = rows.Close()
				return ErrVaultSelectionNotFound
			}
			if err := rows.Scan(&selectedDevice); err != nil {
				_ = rows.Close()
				return err
			}
			if rows.Next() {
				_ = rows.Close()
				return ErrVaultSelectionAmbiguous
			}
			if err := rows.Close(); err != nil {
				return err
			}
			declaration, err := retentionDeclarationTx(ctx, tx, entry.Retention.Vault, selectedDevice)
			if err != nil {
				return err
			}
			if declaration.DigestVersion != 2 {
				return ErrRetentionBoundaryNotVerified
			}
			pointFound := false
			for _, point := range declaration.RecoveryPoints {
				if point.Epoch == entry.Retention.Epoch && bytes.Equal(point.SnapshotCID, entry.Retention.SnapshotCID) && point.PolicyDigest == entry.Retention.PolicyDigest && bytes.Equal(point.ControlCID, entry.Retention.ControlCID) {
					pointFound = true
					break
				}
			}
			if !pointFound {
				return ErrRetentionBoundaryNotVerified
			}
			var markerCount int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND payload_ref = '' AND backup_ref = ''`, entry.Retention.Vault[:], selectedDevice, entry.Retention.Epoch, entry.Retention.SnapshotCID).Scan(&markerCount); err != nil {
				return err
			}
			if markerCount != 1 {
				return ErrRetentionRecoveryPointInventoryUnknown
			}
			rows, err = tx.QueryContext(ctx, `SELECT payload_ref FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND payload_ref <> '' AND backup_ref = ''`, entry.Retention.Vault[:], selectedDevice, entry.Retention.Epoch, entry.Retention.SnapshotCID)
			if err != nil {
				return err
			}
			var bodyReferences []string
			for rows.Next() {
				var reference string
				if err := rows.Scan(&reference); err != nil {
					_ = rows.Close()
					return err
				}
				bodyReferences = append(bodyReferences, reference)
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				return err
			}
			if err := rows.Close(); err != nil {
				return err
			}
			var bodyReference string
			bodyCount := 0
			for _, reference := range bodyReferences {
				if payloadReferenceMatchesSnapshot(reference, entry.Retention.SnapshotCID) {
					bodyReference = reference
					bodyCount++
				}
			}
			if bodyCount != 1 {
				return ErrRetentionRecoveryPointInventoryUnknown
			}
			name, err := payloadName(bodyReference)
			if err != nil {
				return err
			}
			body, err := readPayload(filepath.Join(s.payloadDir, name), bodyReference)
			if err != nil {
				return err
			}
			if !bytes.Equal(authenticatedPositionRawCID(body), entry.Retention.SnapshotCID) {
				return ErrRetentionRecoveryPointInventoryUnknown
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO apply_journal(id, operation, state, stage, target_id, source, file_path, schema_id, settings_path, setting_key,
root_path, destination_path, root_device, root_inode,
preimage_state, preimage_kind, preimage_mode, preimage_link_target, preimage_value_type, preimage_value_text, preimage_size, preimage_digest,
postimage_state, postimage_kind, postimage_mode, postimage_link_target, postimage_value_type, postimage_value_text, postimage_size, postimage_digest, backup_ref, vault, epoch, snapshot_cid, policy_digest, control_cid, retention_binding_version, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.ID, entry.Operation, entry.State, entry.Stage, entry.Identity.TargetID, entry.Identity.Source, entry.Identity.FilePath, entry.Identity.SchemaID, entry.Identity.SettingsPath, entry.Identity.SettingKey,
			entry.RootPath, entry.DestinationPath, entry.RootDevice, entry.RootInode,
			entry.Preimage.State, entry.Preimage.Kind, entry.Preimage.Mode, entry.Preimage.LinkTarget, entry.Preimage.ValueType, entry.Preimage.ValueText, entry.Preimage.Size, entry.Preimage.Digest,
			entry.Postimage.State, entry.Postimage.Kind, entry.Postimage.Mode, entry.Postimage.LinkTarget, entry.Postimage.ValueType, entry.Postimage.ValueText, entry.Postimage.Size, entry.Postimage.Digest, entry.BackupRef,
			retentionVault, retentionEpoch, retentionSnapshot, retentionPolicyDigest, retentionControlCID, entry.RetentionBindingVersion, entry.CreatedAt)
		if err != nil {
			return err
		}
		if entry.Retention != nil {
			binding := entry.Retention
			if _, err := tx.ExecContext(ctx, `UPDATE retention_recovery_material SET inventory_complete = 0
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND payload_ref = '' AND backup_ref = ''`, binding.Vault[:], selectedDevice, binding.Epoch, binding.SnapshotCID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
VALUES (?, ?, ?, ?, '', ?, 1) ON CONFLICT(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref) DO NOTHING`, binding.Vault[:], selectedDevice, binding.Epoch, binding.SnapshotCID, entry.BackupRef); err != nil {
				return err
			}
		}
		return nil
	})
	return entry, err
}

func (s *Store) JournalEntries(ctx context.Context, targetID string) ([]JournalEntry, error) {
	return s.readJournalEntries(ctx, `SELECT id, operation, state, stage, target_id, source, file_path, schema_id, settings_path, setting_key,
root_path, destination_path, root_device, root_inode,
preimage_state, preimage_kind, preimage_mode, preimage_link_target, preimage_value_type, preimage_value_text, preimage_size, preimage_digest,
postimage_state, postimage_kind, postimage_mode, postimage_link_target, postimage_value_type, postimage_value_text, postimage_size, postimage_digest, backup_ref, vault, epoch, snapshot_cid, policy_digest, control_cid, retention_binding_version, created_at
FROM apply_journal WHERE target_id = ? ORDER BY rowid`, targetID)
}

func (s *Store) JournalEntriesAll(ctx context.Context) ([]JournalEntry, error) {
	return s.readJournalEntries(ctx, `SELECT id, operation, state, stage, target_id, source, file_path, schema_id, settings_path, setting_key,
root_path, destination_path, root_device, root_inode,
preimage_state, preimage_kind, preimage_mode, preimage_link_target, preimage_value_type, preimage_value_text, preimage_size, preimage_digest,
postimage_state, postimage_kind, postimage_mode, postimage_link_target, postimage_value_type, postimage_value_text, postimage_size, postimage_digest, backup_ref, vault, epoch, snapshot_cid, policy_digest, control_cid, retention_binding_version, created_at
FROM apply_journal ORDER BY rowid`)
}

func (s *Store) PendingJournalEntries(ctx context.Context) ([]JournalEntry, error) {
	return s.readJournalEntries(ctx, `SELECT id, operation, state, stage, target_id, source, file_path, schema_id, settings_path, setting_key,
root_path, destination_path, root_device, root_inode,
preimage_state, preimage_kind, preimage_mode, preimage_link_target, preimage_value_type, preimage_value_text, preimage_size, preimage_digest,
postimage_state, postimage_kind, postimage_mode, postimage_link_target, postimage_value_type, postimage_value_text, postimage_size, postimage_digest, backup_ref, vault, epoch, snapshot_cid, policy_digest, control_cid, retention_binding_version, created_at
FROM apply_journal WHERE state = 'pending' ORDER BY rowid`)
}

func (s *Store) readJournalEntries(ctx context.Context, query string, args ...any) ([]JournalEntry, error) {
	var values []JournalEntry
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value JournalEntry
			var source, preKind, postKind string
			var preMode, postMode uint32
			var retentionVault, retentionSnapshot, retentionPolicyDigest, retentionControlCID []byte
			var retentionEpoch sql.NullInt64
			if err := rows.Scan(&value.ID, &value.Operation, &value.State, &value.Stage, &value.Identity.TargetID, &source, &value.Identity.FilePath, &value.Identity.SchemaID, &value.Identity.SettingsPath, &value.Identity.SettingKey,
				&value.RootPath, &value.DestinationPath, &value.RootDevice, &value.RootInode,
				&value.Preimage.State, &preKind, &preMode, &value.Preimage.LinkTarget, &value.Preimage.ValueType, &value.Preimage.ValueText, &value.Preimage.Size, &value.Preimage.Digest,
				&value.Postimage.State, &postKind, &postMode, &value.Postimage.LinkTarget, &value.Postimage.ValueType, &value.Postimage.ValueText, &value.Postimage.Size, &value.Postimage.Digest, &value.BackupRef,
				&retentionVault, &retentionEpoch, &retentionSnapshot, &retentionPolicyDigest, &retentionControlCID, &value.RetentionBindingVersion, &value.CreatedAt); err != nil {
				return err
			}
			value.Identity.Source = model.SourceKind(source)
			value.Preimage.Kind = model.FileKind(preKind)
			value.Preimage.Mode = preMode
			value.Postimage.Kind = model.FileKind(postKind)
			value.Postimage.Mode = postMode
			if len(retentionVault) != 0 || retentionEpoch.Valid || len(retentionSnapshot) != 0 || len(retentionPolicyDigest) != 0 || len(retentionControlCID) != 0 {
				if len(retentionVault) != 32 || !retentionEpoch.Valid || retentionEpoch.Int64 < 0 || len(retentionSnapshot) == 0 || len(retentionSnapshot) > 128 || len(retentionPolicyDigest) != 32 || len(retentionControlCID) == 0 || len(retentionControlCID) > 128 {
					return errors.New("stored journal retention binding is malformed")
				}
				binding := &RetentionBinding{Epoch: uint64(retentionEpoch.Int64), SnapshotCID: bytes.Clone(retentionSnapshot), ControlCID: bytes.Clone(retentionControlCID)}
				copy(binding.Vault[:], retentionVault)
				copy(binding.PolicyDigest[:], retentionPolicyDigest)
				value.Retention = binding
			}
			values = append(values, value)
		}
		return rows.Err()
	})
	return values, err
}

func (s *Store) Payload(reference string) ([]byte, error) {
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
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
