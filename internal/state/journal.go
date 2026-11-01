package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	JournalStagePending       = "pending"
	JournalStagePrecondition  = "precondition"
	JournalStageCreateTemp    = "create-temp"
	JournalStageSetMode       = "set-mode"
	JournalStageWrite         = "write"
	JournalStageSyncFile      = "sync-file"
	JournalStageClose         = "close"
	JournalStageRename        = "rename"
	JournalStageSyncDirectory = "sync-directory"
	JournalStageDelete        = "delete"
	JournalStageReadBack      = "read-back"
	JournalStageVerified      = "verified"
)

func (s *Store) TransitionJournalEntry(ctx context.Context, id, from, to, stage string) error {
	if err := validateID(id, "journal id"); err != nil {
		return err
	}
	if from != "pending" || (to != "applied" && to != "failed") || !validJournalStage(stage) ||
		(to == "applied" && stage != JournalStageVerified) || (to == "failed" && stage == JournalStageVerified) {
		return fmt.Errorf("%w: %q to %q at %q", ErrInvalidJournalTransition, from, to, stage)
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE apply_journal SET state = ?, stage = ? WHERE id = ? AND state = ?", to, stage, id, from)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("%w: journal entry %q is missing or not pending", ErrInvalidJournalTransition, id)
		}
		return nil
	})
}

func (s *Store) PruneJournalBackup(ctx context.Context, id string) error {
	if err := validateID(id, "journal id"); err != nil {
		return err
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	var reference string
	var remove bool
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var state, stage string
		if err := tx.QueryRowContext(ctx, "SELECT state, stage, backup_ref FROM apply_journal WHERE id = ?", id).Scan(&state, &stage, &reference); err != nil {
			return err
		}
		if state != "applied" || stage != JournalStageVerified {
			return errors.New("journal backup can only be pruned after verification")
		}
		if reference == "" {
			return nil
		}
		if _, err := tx.ExecContext(ctx, "UPDATE apply_journal SET backup_ref = '' WHERE id = ? AND state = 'applied'", id); err != nil {
			return err
		}
		var references int
		if err := tx.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM applied_base WHERE payload_ref = ?) +
(SELECT count(*) FROM outbound_intent WHERE payload_ref = ?) +
(SELECT count(*) FROM conflicts WHERE local_payload_ref = ? OR remote_payload_ref = ?) +
(SELECT count(*) FROM apply_journal WHERE backup_ref = ?)`, reference, reference, reference, reference, reference).Scan(&references); err != nil {
			return err
		}
		remove = references == 0
		return nil
	})
	if err != nil || !remove {
		return err
	}
	name, err := payloadName(reference)
	if err != nil {
		return err
	}
	path := filepath.Join(s.payloadDir, name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.payloadDir)
}

func validJournalStage(stage string) bool {
	switch stage {
	case JournalStagePrecondition, JournalStageCreateTemp, JournalStageSetMode, JournalStageWrite,
		JournalStageSyncFile, JournalStageClose, JournalStageRename, JournalStageSyncDirectory, JournalStageDelete,
		JournalStageReadBack, JournalStageVerified:
		return true
	default:
		return false
	}
}
