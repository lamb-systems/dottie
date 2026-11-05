package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
)

const (
	JournalStagePending               = "pending"
	JournalStagePrecondition          = "precondition"
	JournalStageCreateTemp            = "create-temp"
	JournalStageSetMode               = "set-mode"
	JournalStageWrite                 = "write"
	JournalStageSyncFile              = "sync-file"
	JournalStageClose                 = "close"
	JournalStageRename                = "rename"
	JournalStageSyncDirectory         = "sync-directory"
	JournalStageDelete                = "delete"
	JournalStageReadBack              = "read-back"
	JournalStageSettingSet            = "setting-set"
	JournalStageSettingReset          = "setting-reset"
	JournalStageSettingReadBack       = "setting-read-back"
	JournalStageVerified              = "verified"
	JournalStageIndeterminate         = "indeterminate"
	JournalStageRolledBack            = "rolled-back"
	JournalStageRollbackSkipped       = "skipped-newer-edit"
	JournalStageRollbackPending       = "rollback-pending"
	JournalStageRollbackIndeterminate = "rollback-indeterminate"
	JournalBackupRetention            = 7 * 24 * time.Hour
)

func (s *Store) TransitionJournalEntry(ctx context.Context, id, from, to, stage string) error {
	if err := validateID(id, "journal id"); err != nil {
		return err
	}
	valid := false
	switch from {
	case "pending":
		valid = (to == "applied" && stage == JournalStageVerified) ||
			(to == "failed" && validJournalFailureStage(stage)) ||
			(to == "indeterminate" && stage == JournalStageIndeterminate)
	case "applied":
		valid = to == "rolled-back" && stage == JournalStageRolledBack
	}
	if !valid {
		return fmt.Errorf("%w: %q to %q at %q", ErrInvalidJournalTransition, from, to, stage)
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		query := "UPDATE apply_journal SET state = ?, stage = ? WHERE id = ? AND state = ?"
		args := []any{to, stage, id, from}
		if from == "applied" && to == "rolled-back" {
			query += " AND stage = ?"
			args = append(args, JournalStageRollbackPending)
		}
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("%w: journal entry %q is missing or not %s", ErrInvalidJournalTransition, id, from)
		}
		return nil
	})
}

func (s *Store) RecordJournalRollbackSkipped(ctx context.Context, id string) error {
	if err := validateID(id, "journal id"); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE apply_journal SET stage = ? WHERE id = ? AND state = 'applied' AND stage IN (?, ?)", JournalStageRollbackSkipped, id, JournalStageVerified, JournalStageRollbackPending)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("%w: journal entry %q is missing or not eligible for rollback skip", ErrInvalidJournalTransition, id)
		}
		return nil
	})
}

func (s *Store) BeginJournalRollback(ctx context.Context, id string) error {
	return s.setJournalRollbackStage(ctx, id, JournalStageRollbackPending, JournalStageVerified)
}

func (s *Store) BeginJournalRollbackWithBackup(ctx context.Context, id, backupRef string) error {
	if err := validateID(id, "journal id"); err != nil {
		return err
	}
	if err := validateID(backupRef, "journal backup reference"); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE apply_journal SET stage = ? WHERE id = ? AND state = 'applied' AND stage = ? AND backup_ref = ?", JournalStageRollbackPending, id, JournalStageVerified, backupRef)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("%w: journal entry %q backup is no longer retained", ErrInvalidJournalTransition, id)
		}
		return nil
	})
}

func (s *Store) RecordJournalRollbackIndeterminate(ctx context.Context, id string) error {
	return s.setJournalRollbackStage(ctx, id, JournalStageRollbackIndeterminate, JournalStageVerified, JournalStageRollbackPending)
}

func (s *Store) setJournalRollbackStage(ctx context.Context, id, stage string, from ...string) error {
	if err := validateID(id, "journal id"); err != nil {
		return err
	}
	if len(from) == 0 {
		return ErrInvalidJournalTransition
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(from)), ",")
	args := []any{stage, id, "applied"}
	for _, current := range from {
		args = append(args, current)
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE apply_journal SET stage = ? WHERE id = ? AND state = ? AND stage IN ("+placeholders+")", args...)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("%w: journal entry %q is not eligible for rollback stage %q", ErrInvalidJournalTransition, id, stage)
		}
		return nil
	})
}

func (s *Store) PruneJournalBackup(ctx context.Context, id string, now time.Time) error {
	_, err := s.PruneJournalBackupIfEligible(ctx, id, now)
	return err
}

func (s *Store) PruneJournalBackupIfEligible(ctx context.Context, id string, now time.Time) (bool, error) {
	if err := validateID(id, "journal id"); err != nil {
		return false, err
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	var reference string
	var remove, pruned bool
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var state, stage, source string
		var createdAt int64
		var retentionVault, retentionSnapshot, retentionPolicyDigest, retentionControlCID []byte
		var retentionEpoch sql.NullInt64
		var retentionBindingVersion int
		if err := tx.QueryRowContext(ctx, "SELECT state, stage, backup_ref, created_at, source, vault, epoch, snapshot_cid, policy_digest, control_cid, retention_binding_version FROM apply_journal WHERE id = ?", id).Scan(&state, &stage, &reference, &createdAt, &source, &retentionVault, &retentionEpoch, &retentionSnapshot, &retentionPolicyDigest, &retentionControlCID, &retentionBindingVersion); err != nil {
			return err
		}
		if reference == "" {
			return nil
		}
		rolledBack := state == "rolled-back" && stage == JournalStageRolledBack
		aged := (state == "applied" && stage == JournalStageVerified || rolledBack) && !now.Before(time.Unix(createdAt, 0).Add(JournalBackupRetention))
		if !rolledBack && !aged {
			return errors.New("journal backup can only be pruned after verified rollback or seven-day expiry of a verified apply")
		}
		if !validRetentionJournalBinding(retentionVault, retentionEpoch, retentionSnapshot, retentionPolicyDigest, retentionControlCID, retentionBindingVersion) {
			return nil
		}
		deviceID, err := selectedRetentionDeviceTx(ctx, tx, retentionVault)
		if err != nil {
			return err
		}
		if deviceID == "" {
			return nil
		}
		var boundaryEpoch int64
		if err := tx.QueryRowContext(ctx, "SELECT epoch FROM vault_checkpoints WHERE vault = ?", retentionVault).Scan(&boundaryEpoch); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if boundaryEpoch < 0 || retentionEpoch.Int64 >= boundaryEpoch {
			return nil
		}
		associated, err := retentionBackupAssociationTx(ctx, tx, retentionVault, deviceID, retentionEpoch.Int64, retentionSnapshot, retentionPolicyDigest, retentionControlCID, reference)
		if err != nil {
			return err
		}
		if !associated {
			return nil
		}
		var retainedReferences int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM retention_recovery_material AS material
JOIN retention_recovery_points AS point
  ON point.vault = material.vault AND point.device_id = material.device_id
 AND point.epoch = material.epoch AND point.snapshot_cid = material.snapshot_cid
WHERE material.backup_ref = ? OR material.payload_ref = ?`, reference, reference).Scan(&retainedReferences); err != nil {
			return err
		}
		if retainedReferences != 0 {
			return nil
		}
		name, err := payloadName(reference)
		if err != nil {
			return err
		}
		if _, err := readPayload(filepath.Join(s.payloadDir, name), reference); err != nil {
			return err
		}
		query := "UPDATE apply_journal SET backup_ref = '' WHERE id = ? AND state = ?"
		if source == string(model.SourceGNOME) {
			query = "UPDATE apply_journal SET backup_ref = '', preimage_value_type = '', preimage_value_text = '', postimage_value_type = '', postimage_value_text = '' WHERE id = ? AND state = ?"
		}
		if _, err := tx.ExecContext(ctx, query, id, state); err != nil {
			return err
		}
		pruned = true
		var references int
		if err := tx.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM applied_base WHERE payload_ref = ?) +
(SELECT count(*) FROM outbound_intent WHERE payload_ref = ?) +
(SELECT count(*) FROM conflicts WHERE local_payload_ref = ? OR remote_payload_ref = ?) +
(SELECT count(*) FROM apply_journal WHERE backup_ref = ?) +
(SELECT count(*) FROM retention_recovery_material AS material
 JOIN retention_recovery_points AS point
   ON point.vault = material.vault AND point.device_id = material.device_id
  AND point.epoch = material.epoch AND point.snapshot_cid = material.snapshot_cid
 WHERE material.backup_ref = ? OR material.payload_ref = ?)`, reference, reference, reference, reference, reference, reference, reference).Scan(&references); err != nil {
			return err
		}
		remove = references == 0
		return nil
	})
	if err != nil || !pruned || !remove {
		return pruned, err
	}
	name, err := payloadName(reference)
	if err != nil {
		return pruned, err
	}
	path := filepath.Join(s.payloadDir, name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return pruned, err
	}
	return pruned, syncDirectory(s.payloadDir)
}

func (s *Store) JournalBackupUsage(ctx context.Context) (JournalBackupUsage, error) {
	entries, err := s.JournalEntriesAll(ctx)
	if err != nil {
		return JournalBackupUsage{}, err
	}
	byReference := make(map[string]*JournalBackupHolder)
	for _, entry := range entries {
		if entry.BackupRef == "" {
			continue
		}
		holder := byReference[entry.BackupRef]
		if holder == nil {
			holder = &JournalBackupHolder{Reference: entry.BackupRef, Size: entry.Preimage.Size}
			byReference[entry.BackupRef] = holder
		} else if holder.Size != entry.Preimage.Size {
			return JournalBackupUsage{}, fmt.Errorf("journal backup %q has conflicting sizes", entry.BackupRef)
		}
		holder.Entries = append(holder.Entries, entry.ID)
	}
	references := make([]string, 0, len(byReference))
	for reference := range byReference {
		references = append(references, reference)
	}
	sort.Strings(references)
	usage := JournalBackupUsage{Holders: make([]JournalBackupHolder, 0, len(references))}
	for _, reference := range references {
		holder := byReference[reference]
		if holder.Size < 0 || usage.Bytes > int64(^uint64(0)>>1)-holder.Size {
			return JournalBackupUsage{}, errors.New("journal backup size overflows")
		}
		usage.Bytes += holder.Size
		usage.Holders = append(usage.Holders, *holder)
	}
	return usage, nil
}

func (s *Store) PruneExpiredJournalBackups(ctx context.Context, now time.Time) ([]string, error) {
	entries, err := s.JournalEntriesAll(ctx)
	if err != nil {
		return nil, err
	}
	pruned := make([]string, 0)
	for _, entry := range entries {
		if entry.BackupRef == "" || (entry.State == "applied" && entry.Stage != JournalStageVerified) || (entry.State == "rolled-back" && entry.Stage != JournalStageRolledBack) || (entry.State != "applied" && entry.State != "rolled-back") {
			continue
		}
		if now.Before(time.Unix(entry.CreatedAt, 0).Add(JournalBackupRetention)) {
			continue
		}
		prunedEntry, err := s.PruneJournalBackupIfEligible(ctx, entry.ID, now)
		if err != nil {
			return pruned, fmt.Errorf("prune expired journal backup %s: %w", entry.ID, err)
		}
		if prunedEntry {
			pruned = append(pruned, entry.ID)
		}
	}
	return pruned, nil
}

func validJournalFailureStage(stage string) bool {
	switch stage {
	case JournalStagePrecondition, JournalStageCreateTemp, JournalStageSetMode, JournalStageWrite,
		JournalStageSyncFile, JournalStageClose, JournalStageRename, JournalStageSyncDirectory, JournalStageDelete,
		JournalStageReadBack, JournalStageSettingSet, JournalStageSettingReset, JournalStageSettingReadBack:
		return true
	default:
		return false
	}
}

func validJournalStage(stage string) bool {
	switch stage {
	case JournalStagePending, JournalStagePrecondition, JournalStageCreateTemp, JournalStageSetMode, JournalStageWrite,
		JournalStageSyncFile, JournalStageClose, JournalStageRename, JournalStageSyncDirectory, JournalStageDelete,
		JournalStageReadBack, JournalStageSettingSet, JournalStageSettingReset, JournalStageSettingReadBack,
		JournalStageVerified, JournalStageIndeterminate, JournalStageRolledBack, JournalStageRollbackSkipped,
		JournalStageRollbackPending, JournalStageRollbackIndeterminate:
		return true
	default:
		return false
	}
}
