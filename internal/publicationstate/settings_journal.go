package publicationstate

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const (
	StageSettingsJournal Stage = "journal"

	ReasonSettingsJournalEntry       Reason = "settings_journal_entry"
	ReasonSettingsJournalObservation Reason = "settings_journal_observation"
	ReasonSettingsJournalTransition  Reason = "settings_journal_transition"
)

const settingsJournalMaxTextBytes = 64 << 10

const settingsJournalStatement = "CREATE TABLE settings_journal (entry INTEGER PRIMARY KEY, vault BLOB NOT NULL, target_id TEXT NOT NULL, schema_id TEXT NOT NULL, path TEXT NOT NULL, key TEXT NOT NULL, prior_state TEXT NOT NULL, prior_type TEXT NOT NULL, prior_text TEXT NOT NULL, written_state TEXT NOT NULL, written_type TEXT NOT NULL, written_text TEXT NOT NULL, stage TEXT NOT NULL, state TEXT NOT NULL, seen_floor_revision INTEGER NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL)"

const settingsJournalLiveStatement = "CREATE INDEX settings_journal_live ON settings_journal(state)"

const (
	JournalSettingAbsent  = "absent"
	JournalSettingPresent = "present"
)

const (
	settingsJournalStagePending       JournalStage = "settings-pending"
	settingsJournalStageApplied       JournalStage = "settings-complete"
	settingsJournalStageFailed        JournalStage = "settings-failed"
	settingsJournalStageIndeterminate JournalStage = "settings-indeterminate"
)

type SettingsJournalAnchor struct {
	TargetID string
	SchemaID string
	Path     string
	Key      string
}

type SettingsValue struct {
	Present bool
	Type    string
	Text    string
}

type SettingsJournalIntent struct {
	Vault             [32]byte
	Anchor            SettingsJournalAnchor
	Prior             SettingsValue
	Written           SettingsValue
	SeenFloorRevision uint64
}

type SettingsJournalEntry struct {
	Entry             int64
	Vault             [32]byte
	Anchor            SettingsJournalAnchor
	Prior             SettingsValue
	Written           SettingsValue
	Stage             JournalStage
	State             JournalState
	SeenFloorRevision uint64
}

type SettingsJournalResolution struct {
	Entry   int64
	Outcome JournalOutcome
}

func (journal *Journal) BeginSettingsJournal(
	ctx context.Context,
	intent SettingsJournalIntent,
) (SettingsJournalEntry, error) {
	if err := validateSettingsJournalIntent(intent); err != nil {
		return SettingsJournalEntry{}, err
	}
	var entry SettingsJournalEntry
	err := journal.withTx(ctx, StageSettingsJournal, func(tx *sql.Tx) error {
		rows, err := queryInt64(
			ctx, tx,
			"SELECT count(*) FROM settings_journal WHERE state IN (?,?)",
			string(JournalStatePending), string(JournalStateIndeterminate),
		)
		if err != nil {
			return queryReadError(ctx, StageSettingsJournal, err)
		}
		if rows >= journalMaxEntries {
			return classified(ErrLimit, StageSettingsJournal, ReasonCapacity)
		}
		now := time.Now().Unix()
		result, err := tx.ExecContext(
			ctx,
			"INSERT INTO settings_journal(vault,target_id,schema_id,path,key,prior_state,prior_type,prior_text,written_state,written_type,written_text,stage,state,seen_floor_revision,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			intent.Vault[:],
			intent.Anchor.TargetID,
			intent.Anchor.SchemaID,
			intent.Anchor.Path,
			intent.Anchor.Key,
			settingsStateOf(intent.Prior),
			intent.Prior.Type,
			intent.Prior.Text,
			settingsStateOf(intent.Written),
			intent.Written.Type,
			intent.Written.Text,
			string(settingsJournalStagePending),
			string(JournalStatePending),
			int64(intent.SeenFloorRevision),
			now,
			now,
		)
		if err != nil {
			return storageFailure(ctx, StageSettingsJournal, err)
		}
		entryID, err := result.LastInsertId()
		if err != nil {
			return storageFailure(ctx, StageSettingsJournal, err)
		}
		entry.Entry = entryID
		entry.Vault = intent.Vault
		entry.Anchor = intent.Anchor
		entry.Prior = intent.Prior
		entry.Written = intent.Written
		entry.Stage = settingsJournalStagePending
		entry.State = JournalStatePending
		entry.SeenFloorRevision = intent.SeenFloorRevision
		return nil
	})
	if err != nil {
		return SettingsJournalEntry{}, err
	}
	return entry, nil
}

func (journal *Journal) CompleteSettingsJournal(
	ctx context.Context,
	entry SettingsJournalEntry,
	observed SettingsValue,
) error {
	if !sameSettingsValue(observed, entry.Written) {
		return classified(ErrInvalid, StageSettingsJournal, ReasonSettingsJournalObservation)
	}
	return journal.transitionSettingsEntry(
		ctx, entry.Entry, JournalStatePending, JournalStateApplied,
		settingsJournalStageApplied,
	)
}

func (journal *Journal) FailSettingsJournal(ctx context.Context, entry SettingsJournalEntry) error {
	return journal.transitionSettingsEntry(
		ctx, entry.Entry, JournalStatePending, JournalStateFailed,
		settingsJournalStageFailed,
	)
}

func (journal *Journal) MarkSettingsIndeterminate(ctx context.Context, entry SettingsJournalEntry) error {
	return journal.transitionSettingsEntry(
		ctx, entry.Entry, JournalStatePending, JournalStateIndeterminate,
		settingsJournalStageIndeterminate,
	)
}

func (journal *Journal) transitionSettingsEntry(
	ctx context.Context,
	entry int64,
	from JournalState,
	to JournalState,
	stage JournalStage,
) error {
	return journal.withTx(ctx, StageSettingsJournal, func(tx *sql.Tx) error {
		current, err := readSettingsJournalEntry(ctx, tx, entry)
		if err != nil {
			return err
		}
		if current.State != from {
			return classified(ErrInvalid, StageSettingsJournal, ReasonSettingsJournalTransition)
		}
		result, err := tx.ExecContext(
			ctx,
			"UPDATE settings_journal SET state=?, stage=?, updated=? WHERE entry=?",
			string(to), string(stage), time.Now().Unix(), entry,
		)
		if err != nil {
			return storageFailure(ctx, StageSettingsJournal, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return storageFailure(ctx, StageSettingsJournal, err)
		}
		if affected != 1 {
			return classified(ErrInvalid, StageSettingsJournal, ReasonSettingsJournalTransition)
		}
		return nil
	})
}

func readSettingsJournalEntry(
	ctx context.Context,
	tx *sql.Tx,
	entry int64,
) (SettingsJournalEntry, error) {
	rows, err := tx.QueryContext(
		ctx,
		"SELECT entry,vault,target_id,schema_id,path,key,prior_state,prior_type,prior_text,written_state,written_type,written_text,stage,state,seen_floor_revision FROM settings_journal WHERE entry=?",
		entry,
	)
	if err != nil {
		return SettingsJournalEntry{}, storageFailure(ctx, StageSettingsJournal, err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return SettingsJournalEntry{}, classified(ErrInvalid, StageSettingsJournal, ReasonSettingsJournalEntry)
	}
	value, err := scanSettingsJournalEntry(rows)
	if err != nil {
		return SettingsJournalEntry{}, err
	}
	if err := rows.Err(); err != nil {
		return SettingsJournalEntry{}, storageFailure(ctx, StageSettingsJournal, err)
	}
	return value, nil
}

type settingsJournalScanner interface {
	Scan(...any) error
}

func scanSettingsJournalEntry(scanner settingsJournalScanner) (SettingsJournalEntry, error) {
	var (
		entry      int64
		vault      []byte
		targetID   string
		schemaID   string
		path       string
		key        string
		priorState string
		priorType  string
		priorText  string
		writeState string
		writeType  string
		writeText  string
		stage      string
		state      string
		seen       int64
	)
	if err := scanner.Scan(
		&entry, &vault, &targetID, &schemaID, &path, &key,
		&priorState, &priorType, &priorText, &writeState, &writeType, &writeText,
		&stage, &state, &seen,
	); err != nil {
		return SettingsJournalEntry{}, err
	}
	if len(vault) != 32 || seen < 0 {
		return SettingsJournalEntry{}, classified(ErrSchema, StageSettingsJournal, ReasonCorrupt)
	}
	value := SettingsJournalEntry{
		Entry: entry,
		Anchor: SettingsJournalAnchor{
			TargetID: targetID, SchemaID: schemaID, Path: path, Key: key,
		},
		Prior: SettingsValue{
			Present: priorState == JournalSettingPresent, Type: priorType, Text: priorText,
		},
		Written: SettingsValue{
			Present: writeState == JournalSettingPresent, Type: writeType, Text: writeText,
		},
		Stage:             JournalStage(stage),
		State:             JournalState(state),
		SeenFloorRevision: uint64(seen),
	}
	copy(value.Vault[:], vault)
	return value, nil
}

func (journal *Journal) LiveSettingsEntries(ctx context.Context) ([]SettingsJournalEntry, error) {
	if err := journal.checkContext(ctx, StageSettingsJournal); err != nil {
		return nil, err
	}
	rows, err := journal.conn.QueryContext(
		ctx,
		"SELECT entry,vault,target_id,schema_id,path,key,prior_state,prior_type,prior_text,written_state,written_type,written_text,stage,state,seen_floor_revision FROM settings_journal WHERE state IN (?,?) ORDER BY entry",
		string(JournalStatePending),
		string(JournalStateIndeterminate),
	)
	if err != nil {
		return nil, storageFailure(ctx, StageSettingsJournal, err)
	}
	defer func() { _ = rows.Close() }()
	entries := make([]SettingsJournalEntry, 0)
	for rows.Next() {
		value, err := scanSettingsJournalEntry(rows)
		if err != nil {
			return nil, storageFailure(ctx, StageSettingsJournal, err)
		}
		entries = append(entries, value)
	}
	if err := rows.Err(); err != nil {
		return nil, storageFailure(ctx, StageSettingsJournal, err)
	}
	return entries, nil
}

func (journal *Journal) ResolveInterruptedSettings(
	ctx context.Context,
	observe func(SettingsJournalAnchor) (SettingsValue, error),
) ([]SettingsJournalResolution, error) {
	if observe == nil {
		return nil, classified(ErrInvalid, StageSettingsJournal, ReasonBinding)
	}
	entries, err := journal.LiveSettingsEntries(ctx)
	if err != nil {
		return nil, err
	}
	resolutions := make([]SettingsJournalResolution, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, canceled(StageSettingsJournal, err)
		}
		resolution := SettingsJournalResolution{Entry: entry.Entry, Outcome: JournalOutcomeUnobserved}
		observed, observeErr := observe(entry.Anchor)
		if observeErr == nil {
			switch {
			case sameSettingsValue(observed, entry.Written):
				resolution.Outcome = JournalOutcomeApplied
			case sameSettingsValue(observed, entry.Prior):
				resolution.Outcome = JournalOutcomeFailed
			default:
				resolution.Outcome = JournalOutcomeIndeterminate
			}
			if err := journal.settleSettingsEntry(ctx, entry, resolution.Outcome); err != nil {
				return nil, err
			}
		}
		resolutions = append(resolutions, resolution)
	}
	return resolutions, nil
}

func (journal *Journal) settleSettingsEntry(
	ctx context.Context,
	entry SettingsJournalEntry,
	outcome JournalOutcome,
) error {
	state := JournalStatePending
	stage := settingsJournalStagePending
	switch outcome {
	case JournalOutcomeApplied:
		state, stage = JournalStateApplied, settingsJournalStageApplied
	case JournalOutcomeFailed:
		state, stage = JournalStateFailed, settingsJournalStageFailed
	case JournalOutcomeIndeterminate:
		state, stage = JournalStateIndeterminate, settingsJournalStageIndeterminate
	default:
		return nil
	}
	if entry.State == state {
		return nil
	}
	return journal.withTx(ctx, StageSettingsJournal, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(
			ctx,
			"UPDATE settings_journal SET state=?, stage=?, updated=? WHERE entry=? AND state<>?",
			string(state), string(stage), time.Now().Unix(), entry.Entry, string(state),
		)
		if err != nil {
			return storageFailure(ctx, StageSettingsJournal, err)
		}
		if _, err := result.RowsAffected(); err != nil {
			return storageFailure(ctx, StageSettingsJournal, err)
		}
		return nil
	})
}

func (journal *Journal) CheckSettingsAdmission(ctx context.Context, floorRevision uint64) error {
	if err := journal.checkContext(ctx, StageSettingsJournal); err != nil {
		return err
	}
	rows, err := journal.conn.QueryContext(
		ctx,
		"SELECT entry,state,seen_floor_revision FROM settings_journal WHERE state IN (?,?,?) ORDER BY entry",
		string(JournalStatePending), string(JournalStateApplied), string(JournalStateIndeterminate),
	)
	if err != nil {
		return storageFailure(ctx, StageSettingsJournal, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var entryValue, stateValue, seenValue any
		if err := rows.Scan(&entryValue, &stateValue, &seenValue); err != nil {
			return storageFailure(ctx, StageSettingsJournal, err)
		}
		id, idOK := rawInt64(entryValue)
		seen, seenOK := rawInt64(seenValue)
		stateText, stateOK := rawText(stateValue)
		if !idOK || !seenOK || !stateOK || seen < 0 {
			return classified(ErrSchema, StageSettingsJournal, ReasonCorrupt)
		}
		state := JournalState(stateText)
		if state != JournalStateApplied || uint64(seen) > floorRevision {
			return &JournalBlockedError{
				Entry: id, State: state, Stage: settingsJournalStagePending,
				SeenFloorRevision: uint64(seen), FloorRevision: floorRevision,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return storageFailure(ctx, StageSettingsJournal, err)
	}
	return nil
}

func (journal *Journal) SettingsEntryCount(ctx context.Context) (int64, error) {
	if err := journal.checkContext(ctx, StageSettingsJournal); err != nil {
		return 0, err
	}
	return queryInt64(ctx, journal.conn, "SELECT count(*) FROM settings_journal")
}

func validateSettingsJournalIntent(intent SettingsJournalIntent) error {
	if intent.Vault == ([32]byte{}) {
		return classified(ErrInvalid, StageSettingsJournal, ReasonBinding)
	}
	if !validSettingsAnchor(intent.Anchor) {
		return classified(ErrInvalid, StageSettingsJournal, ReasonBinding)
	}
	for _, value := range []SettingsValue{intent.Prior, intent.Written} {
		if strings.ContainsAny(value.Type+value.Text, "\x00") {
			return classified(ErrInvalid, StageSettingsJournal, ReasonJournalEntry)
		}
		if len(value.Type) > journalMaxTextBytes || len(value.Text) > settingsJournalMaxTextBytes {
			return classified(ErrLimit, StageSettingsJournal, ReasonCapacity)
		}
		if value.Present && value.Type == "" {
			return classified(ErrInvalid, StageSettingsJournal, ReasonJournalEntry)
		}
		if !value.Present && (value.Type != "" || value.Text != "") {
			return classified(ErrInvalid, StageSettingsJournal, ReasonJournalEntry)
		}
	}
	return nil
}

func validSettingsAnchor(anchor SettingsJournalAnchor) bool {
	for _, value := range []string{anchor.TargetID, anchor.SchemaID, anchor.Path, anchor.Key} {
		if value == "" || strings.ContainsAny(value, "\x00") {
			return false
		}
	}
	return len(anchor.TargetID) <= journalMaxPathBytes && len(anchor.SchemaID) <= journalMaxPathBytes &&
		len(anchor.Path) <= journalMaxPathBytes && len(anchor.Key) <= journalMaxTextBytes
}

func settingsStateOf(value SettingsValue) string {
	if value.Present {
		return JournalSettingPresent
	}
	return JournalSettingAbsent
}

func sameSettingsValue(left, right SettingsValue) bool {
	if left.Present != right.Present {
		return false
	}
	if !left.Present {
		return true
	}
	return left.Type == right.Type && left.Text == right.Text
}
