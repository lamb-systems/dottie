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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (s *Store) PutRetentionDeclaration(ctx context.Context, declaration RetentionDeclaration) (RetentionDeclaration, error) {
	declaration, err := normalizeRetentionDeclaration(declaration)
	if err != nil {
		return RetentionDeclaration{}, err
	}
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		previous, err := retentionDeclarationTx(ctx, tx, declaration.Vault, declaration.DeviceID)
		if err != nil && !errors.Is(err, ErrRetentionDeclarationNotFound) {
			return err
		}
		if errors.Is(err, ErrRetentionDeclarationNotFound) {
			declaration.PreviousDeclaredAt = -1
			if err := insertRetentionDeclarationTx(ctx, tx, declaration); err != nil {
				return err
			}
			return insertRetentionPointsTx(ctx, tx, declaration.Vault, declaration.DeviceID, declaration.RecoveryPoints)
		}
		revision, err := nextRetentionRevision(ctx, tx, declaration.Vault, declaration.DeviceID)
		if err != nil {
			return err
		}
		if err := insertRetentionHistoryTx(ctx, tx, revision, previous); err != nil {
			return err
		}
		if err := insertRetentionHistoryPointsTx(ctx, tx, revision, previous); err != nil {
			return err
		}
		declaration.PreviousDeclarationDigest = previous.DeclarationDigest
		declaration.PreviousDeclaredAt = previous.DeclaredAt
		if _, err := tx.ExecContext(ctx, `UPDATE retention_declarations SET policy_digest = ?, retention_floor = ?, declaration_digest = ?, declared_at = ?, previous_declaration_digest = ?, previous_declared_at = ? WHERE vault = ? AND device_id = ?`,
			declaration.PolicyDigest[:], declaration.RetentionFloor, declaration.DeclarationDigest[:], declaration.DeclaredAt,
			declaration.PreviousDeclarationDigest[:], declaration.PreviousDeclaredAt, declaration.Vault[:], declaration.DeviceID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM retention_recovery_points WHERE vault = ? AND device_id = ?", declaration.Vault[:], declaration.DeviceID); err != nil {
			return err
		}
		return insertRetentionPointsTx(ctx, tx, declaration.Vault, declaration.DeviceID, declaration.RecoveryPoints)
	})
	if err != nil {
		return RetentionDeclaration{}, err
	}
	return cloneRetentionDeclaration(declaration), nil
}

func (s *Store) RetentionDeclaration(ctx context.Context, vault [32]byte, deviceID string) (RetentionDeclaration, error) {
	if err := validateRetentionSubject(deviceID); err != nil {
		return RetentionDeclaration{}, err
	}
	var declaration RetentionDeclaration
	err := s.query(ctx, func(conn *sql.Conn) error {
		var err error
		declaration, err = retentionDeclarationConn(ctx, conn, vault, deviceID)
		return err
	})
	return declaration, err
}

func (s *Store) RetentionDeclarationHistory(ctx context.Context, vault [32]byte, deviceID string) ([]RetentionDeclarationRevision, error) {
	if err := validateRetentionSubject(deviceID); err != nil {
		return nil, err
	}
	var history []RetentionDeclarationRevision
	err := s.query(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, `SELECT revision, policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at
FROM retention_declaration_history WHERE vault = ? AND device_id = ? ORDER BY revision`, vault[:], deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var revision RetentionDeclarationRevision
			var policyDigest, digest, previousDigest []byte
			var floor int64
			if err := rows.Scan(&revision.Revision, &policyDigest, &floor, &digest, &revision.DeclaredAt, &previousDigest, &revision.PreviousDeclaredAt); err != nil {
				return err
			}
			revision.Vault = vault
			revision.DeviceID = deviceID
			if err := copyRetentionDeclarationBytes(&revision.RetentionDeclaration, policyDigest, digest, previousDigest); err != nil {
				return err
			}
			if floor < 0 {
				return errors.New("stored retention floor is malformed")
			}
			revision.RetentionFloor = uint64(floor)
			history = append(history, revision)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for index := range history {
			points, err := retentionHistoryPointsConn(ctx, conn, vault, deviceID, history[index].Revision)
			if err != nil {
				return err
			}
			history[index].RecoveryPoints = points
			if err := validateStoredRetentionDeclaration(history[index].RetentionDeclaration); err != nil {
				return err
			}
		}
		return nil
	})
	return history, err
}

func normalizeRetentionDeclaration(declaration RetentionDeclaration) (RetentionDeclaration, error) {
	if err := validateRetentionSubject(declaration.DeviceID); err != nil {
		return RetentionDeclaration{}, err
	}
	if len(declaration.DeviceID) > 255 || declaration.RetentionFloor > uint64(^uint64(0)>>1) || declaration.DeclaredAt < 0 || len(declaration.RecoveryPoints) > int(^uint16(0)) {
		return RetentionDeclaration{}, errors.New("invalid retention declaration")
	}
	points := make([]RetentionRecoveryPoint, len(declaration.RecoveryPoints))
	for index, point := range declaration.RecoveryPoints {
		if point.Epoch > uint64(^uint64(0)>>1) || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > 128 {
			return RetentionDeclaration{}, errors.New("invalid retention recovery point")
		}
		points[index] = RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)}
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Epoch != points[j].Epoch {
			return points[i].Epoch < points[j].Epoch
		}
		return bytes.Compare(points[i].SnapshotCID, points[j].SnapshotCID) < 0
	})
	for index := 1; index < len(points); index++ {
		if points[index].Epoch == points[index-1].Epoch && bytes.Equal(points[index].SnapshotCID, points[index-1].SnapshotCID) {
			return RetentionDeclaration{}, errors.New("duplicate retention recovery point")
		}
	}
	declaration.RecoveryPoints = points
	declaration.DeclarationDigest = retentionDeclarationDigest(declaration)
	declaration.PreviousDeclarationDigest = [32]byte{}
	declaration.PreviousDeclaredAt = -1
	return declaration, nil
}

func retentionDeclarationDigest(declaration RetentionDeclaration) [32]byte {
	buffer := bytes.NewBufferString("dottie/v1/retention-declaration\x00")
	buffer.Write(declaration.Vault[:])
	writeRetentionBytes(buffer, []byte(declaration.DeviceID))
	buffer.Write(declaration.PolicyDigest[:])
	writeRetentionUint64(buffer, declaration.RetentionFloor)
	writeRetentionUint64(buffer, uint64(declaration.DeclaredAt))
	writeRetentionUint64(buffer, uint64(len(declaration.RecoveryPoints)))
	for _, point := range declaration.RecoveryPoints {
		writeRetentionUint64(buffer, point.Epoch)
		writeRetentionBytes(buffer, point.SnapshotCID)
	}
	return sha256.Sum256(buffer.Bytes())
}

func writeRetentionUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeRetentionBytes(buffer *bytes.Buffer, value []byte) {
	writeRetentionUint64(buffer, uint64(len(value)))
	buffer.Write(value)
}

func validateRetentionSubject(deviceID string) error {
	if err := validateID(deviceID, "retention device id"); err != nil {
		return err
	}
	return nil
}

func insertRetentionDeclarationTx(ctx context.Context, tx *sql.Tx, declaration RetentionDeclaration) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO retention_declarations(vault, device_id, policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, declaration.Vault[:], declaration.DeviceID, declaration.PolicyDigest[:], declaration.RetentionFloor,
		declaration.DeclarationDigest[:], declaration.DeclaredAt, declaration.PreviousDeclarationDigest[:], declaration.PreviousDeclaredAt)
	return err
}

func insertRetentionPointsTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string, points []RetentionRecoveryPoint) error {
	for ordinal, point := range points {
		if _, err := tx.ExecContext(ctx, "INSERT INTO retention_recovery_points(vault, device_id, ordinal, epoch, snapshot_cid) VALUES (?, ?, ?, ?, ?)", vault[:], deviceID, ordinal, point.Epoch, point.SnapshotCID); err != nil {
			return err
		}
	}
	return nil
}

func nextRetentionRevision(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string) (int64, error) {
	var revision int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(revision), 0) + 1 FROM retention_declaration_history WHERE vault = ? AND device_id = ?", vault[:], deviceID).Scan(&revision); err != nil {
		return 0, err
	}
	return revision, nil
}

func insertRetentionHistoryTx(ctx context.Context, tx *sql.Tx, revision int64, declaration RetentionDeclaration) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO retention_declaration_history(vault, device_id, revision, policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, declaration.Vault[:], declaration.DeviceID, revision, declaration.PolicyDigest[:], declaration.RetentionFloor,
		declaration.DeclarationDigest[:], declaration.DeclaredAt, declaration.PreviousDeclarationDigest[:], declaration.PreviousDeclaredAt)
	return err
}

func insertRetentionHistoryPointsTx(ctx context.Context, tx *sql.Tx, revision int64, declaration RetentionDeclaration) error {
	for ordinal, point := range declaration.RecoveryPoints {
		if _, err := tx.ExecContext(ctx, "INSERT INTO retention_declaration_history_points(vault, device_id, revision, ordinal, epoch, snapshot_cid) VALUES (?, ?, ?, ?, ?, ?)", declaration.Vault[:], declaration.DeviceID, revision, ordinal, point.Epoch, point.SnapshotCID); err != nil {
			return err
		}
	}
	return nil
}

func retentionDeclarationTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string) (RetentionDeclaration, error) {
	var declaration RetentionDeclaration
	var policyDigest, digest, previousDigest []byte
	var floor int64
	err := tx.QueryRowContext(ctx, `SELECT policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at
FROM retention_declarations WHERE vault = ? AND device_id = ?`, vault[:], deviceID).Scan(&policyDigest, &floor, &digest, &declaration.DeclaredAt, &previousDigest, &declaration.PreviousDeclaredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RetentionDeclaration{}, ErrRetentionDeclarationNotFound
	}
	if err != nil {
		return RetentionDeclaration{}, err
	}
	declaration.Vault = vault
	declaration.DeviceID = deviceID
	if floor < 0 {
		return RetentionDeclaration{}, errors.New("stored retention floor is malformed")
	}
	declaration.RetentionFloor = uint64(floor)
	if err := copyRetentionDeclarationBytes(&declaration, policyDigest, digest, previousDigest); err != nil {
		return RetentionDeclaration{}, err
	}
	declaration.RecoveryPoints, err = retentionPointsTx(ctx, tx, vault, deviceID)
	if err != nil {
		return RetentionDeclaration{}, err
	}
	if err := validateStoredRetentionDeclaration(declaration); err != nil {
		return RetentionDeclaration{}, err
	}
	return declaration, nil
}

func retentionDeclarationConn(ctx context.Context, conn *sql.Conn, vault [32]byte, deviceID string) (RetentionDeclaration, error) {
	var declaration RetentionDeclaration
	var policyDigest, digest, previousDigest []byte
	var floor int64
	err := conn.QueryRowContext(ctx, `SELECT policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at
FROM retention_declarations WHERE vault = ? AND device_id = ?`, vault[:], deviceID).Scan(&policyDigest, &floor, &digest, &declaration.DeclaredAt, &previousDigest, &declaration.PreviousDeclaredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RetentionDeclaration{}, ErrRetentionDeclarationNotFound
	}
	if err != nil {
		return RetentionDeclaration{}, err
	}
	declaration.Vault = vault
	declaration.DeviceID = deviceID
	if floor < 0 {
		return RetentionDeclaration{}, errors.New("stored retention floor is malformed")
	}
	declaration.RetentionFloor = uint64(floor)
	if err := copyRetentionDeclarationBytes(&declaration, policyDigest, digest, previousDigest); err != nil {
		return RetentionDeclaration{}, err
	}
	declaration.RecoveryPoints, err = retentionPointsConn(ctx, conn, vault, deviceID)
	if err != nil {
		return RetentionDeclaration{}, err
	}
	if err := validateStoredRetentionDeclaration(declaration); err != nil {
		return RetentionDeclaration{}, err
	}
	return declaration, nil
}

func validateStoredRetentionDeclaration(declaration RetentionDeclaration) error {
	if retentionDeclarationDigest(declaration) != declaration.DeclarationDigest {
		return errors.New("stored retention declaration digest does not match its fields")
	}
	return nil
}

func copyRetentionDeclarationBytes(declaration *RetentionDeclaration, policyDigest, digest, previousDigest []byte) error {
	if len(policyDigest) != 32 || len(digest) != 32 || len(previousDigest) != 32 {
		return errors.New("stored retention declaration is malformed")
	}
	copy(declaration.PolicyDigest[:], policyDigest)
	copy(declaration.DeclarationDigest[:], digest)
	copy(declaration.PreviousDeclarationDigest[:], previousDigest)
	return nil
}

func retentionPointsTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string) ([]RetentionRecoveryPoint, error) {
	rows, err := tx.QueryContext(ctx, "SELECT epoch, snapshot_cid FROM retention_recovery_points WHERE vault = ? AND device_id = ? ORDER BY ordinal", vault[:], deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRetentionPoints(rows)
}

func retentionPointsConn(ctx context.Context, conn *sql.Conn, vault [32]byte, deviceID string) ([]RetentionRecoveryPoint, error) {
	rows, err := conn.QueryContext(ctx, "SELECT epoch, snapshot_cid FROM retention_recovery_points WHERE vault = ? AND device_id = ? ORDER BY ordinal", vault[:], deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRetentionPoints(rows)
}

func retentionHistoryPointsConn(ctx context.Context, conn *sql.Conn, vault [32]byte, deviceID string, revision int64) ([]RetentionRecoveryPoint, error) {
	rows, err := conn.QueryContext(ctx, "SELECT epoch, snapshot_cid FROM retention_declaration_history_points WHERE vault = ? AND device_id = ? AND revision = ? ORDER BY ordinal", vault[:], deviceID, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRetentionPoints(rows)
}

func scanRetentionPoints(rows *sql.Rows) ([]RetentionRecoveryPoint, error) {
	var points []RetentionRecoveryPoint
	for rows.Next() {
		var epoch int64
		var point RetentionRecoveryPoint
		if err := rows.Scan(&epoch, &point.SnapshotCID); err != nil {
			return nil, err
		}
		if epoch < 0 || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > 128 {
			return nil, errors.New("stored retention recovery point is malformed")
		}
		point.Epoch = uint64(epoch)
		point.SnapshotCID = bytes.Clone(point.SnapshotCID)
		points = append(points, point)
	}
	return points, rows.Err()
}

func cloneRetentionDeclaration(declaration RetentionDeclaration) RetentionDeclaration {
	cloned := declaration
	cloned.RecoveryPoints = make([]RetentionRecoveryPoint, len(declaration.RecoveryPoints))
	for index, point := range declaration.RecoveryPoints {
		cloned.RecoveryPoints[index] = RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)}
	}
	return cloned
}

func (s *Store) PlanRetentionPrune(ctx context.Context, request RetentionPruneRequest) (RetentionPrunePlan, error) {
	if err := validateRetentionPruneRequest(request); err != nil {
		return RetentionPrunePlan{}, err
	}
	var plan RetentionPrunePlan
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		plan, err = s.planRetentionPruneTx(ctx, tx, request)
		return err
	})
	return plan, err
}

func (s *Store) ApplyRetentionPrune(ctx context.Context, request RetentionPruneRequest, confirmed bool) (RetentionPruneReport, error) {
	if !confirmed {
		return RetentionPruneReport{}, ErrRetentionConfirmationRequired
	}
	if err := validateRetentionPruneRequest(request); err != nil {
		return RetentionPruneReport{}, err
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	var plan RetentionPrunePlan
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		plan, err = s.planRetentionPruneTx(ctx, tx, request)
		if err != nil {
			return err
		}
		for _, id := range plan.ExpiredBackupIDs {
			result, err := tx.ExecContext(ctx, `UPDATE apply_journal SET backup_ref = '' WHERE id = ? AND backup_ref <> '' AND ((state = 'applied' AND stage = ?) OR (state = 'rolled-back' AND stage = ?))`, id, JournalStageVerified, JournalStageRolledBack)
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed != 1 {
				return errors.New("retention plan journal entry changed inside transaction")
			}
		}
		return nil
	})
	if err != nil {
		return RetentionPruneReport{}, err
	}
	deleted := make([]string, 0, len(plan.PayloadReferences))
	for _, reference := range plan.PayloadReferences {
		name, err := payloadName(reference)
		if err != nil {
			return RetentionPruneReport{Plan: plan, DeletedPayloads: deleted, PrunedBackupIDs: append([]string(nil), plan.ExpiredBackupIDs...), EpochScope: RetentionPruneScope}, err
		}
		path := filepath.Join(s.payloadDir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return RetentionPruneReport{Plan: plan, DeletedPayloads: deleted, PrunedBackupIDs: append([]string(nil), plan.ExpiredBackupIDs...), EpochScope: RetentionPruneScope}, fmt.Errorf("delete unreferenced payload %s: %w", reference, err)
		}
		deleted = append(deleted, reference)
	}
	if len(deleted) > 0 {
		if err := syncDirectory(s.payloadDir); err != nil {
			return RetentionPruneReport{Plan: plan, DeletedPayloads: deleted, PrunedBackupIDs: append([]string(nil), plan.ExpiredBackupIDs...), EpochScope: RetentionPruneScope}, err
		}
	}
	return RetentionPruneReport{Plan: plan, DeletedPayloads: deleted, PrunedBackupIDs: append([]string(nil), plan.ExpiredBackupIDs...), EpochScope: RetentionPruneScope}, nil
}

func validateRetentionPruneRequest(request RetentionPruneRequest) error {
	if err := validateRetentionSubject(request.DeviceID); err != nil {
		return err
	}
	if request.Boundary.Epoch > uint64(^uint64(0)>>1) || len(request.Boundary.SnapshotCID) == 0 || len(request.Boundary.SnapshotCID) > 128 || request.Now.IsZero() {
		return errors.New("invalid retention prune request")
	}
	return nil
}

func (s *Store) planRetentionPruneTx(ctx context.Context, tx *sql.Tx, request RetentionPruneRequest) (RetentionPrunePlan, error) {
	declaration, err := retentionDeclarationTx(ctx, tx, request.Vault, request.DeviceID)
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	pointFound := false
	for _, point := range declaration.RecoveryPoints {
		if point.Epoch == request.Boundary.Epoch && bytes.Equal(point.SnapshotCID, request.Boundary.SnapshotCID) {
			pointFound = true
			break
		}
	}
	if !pointFound {
		return RetentionPrunePlan{}, ErrRetentionBoundaryNotVerified
	}
	var checkpointEpoch int64
	var checkpointSnapshotCID, checkpointPolicyDigest []byte
	err = tx.QueryRowContext(ctx, "SELECT epoch, snapshot_cid, policy_digest FROM vault_checkpoints WHERE vault = ?", request.Vault[:]).Scan(&checkpointEpoch, &checkpointSnapshotCID, &checkpointPolicyDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return RetentionPrunePlan{}, ErrRetentionBoundaryNotVerified
	}
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	if checkpointEpoch < 0 || uint64(checkpointEpoch) != request.Boundary.Epoch ||
		!bytes.Equal(checkpointSnapshotCID, request.Boundary.SnapshotCID) || !bytes.Equal(checkpointPolicyDigest, declaration.PolicyDigest[:]) {
		return RetentionPrunePlan{}, ErrRetentionBoundaryNotVerified
	}
	var liveEpoch int64
	err = tx.QueryRowContext(ctx, "SELECT epoch FROM vault_publication_observations WHERE vault = ?", request.Vault[:]).Scan(&liveEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return RetentionPrunePlan{}, ErrRetentionLiveHead
	}
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	if liveEpoch < 0 || request.Boundary.Epoch >= uint64(liveEpoch) {
		return RetentionPrunePlan{}, ErrRetentionLiveHead
	}
	plan := RetentionPrunePlan{
		Vault: request.Vault, DeviceID: request.DeviceID, Boundary: RetentionRecoveryPoint{Epoch: request.Boundary.Epoch, SnapshotCID: bytes.Clone(request.Boundary.SnapshotCID)},
		PolicyDigest: declaration.PolicyDigest, RetentionFloor: declaration.RetentionFloor,
		RecoveryPoints: cloneRetentionDeclaration(declaration).RecoveryPoints, EpochScope: RetentionPruneScope,
	}
	expiredBackupIDs := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT id, created_at FROM apply_journal
WHERE backup_ref <> '' AND ((state = 'applied' AND stage = ?) OR (state = 'rolled-back' AND stage = ?)) ORDER BY id`, JournalStageVerified, JournalStageRolledBack)
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	for rows.Next() {
		var id string
		var createdAt int64
		if err := rows.Scan(&id, &createdAt); err != nil {
			_ = rows.Close()
			return RetentionPrunePlan{}, err
		}
		if !request.Now.Before(time.Unix(createdAt, 0).Add(JournalBackupRetention)) {
			plan.ExpiredBackupIDs = append(plan.ExpiredBackupIDs, id)
			expiredBackupIDs[id] = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return RetentionPrunePlan{}, err
	}
	if err := rows.Close(); err != nil {
		return RetentionPrunePlan{}, err
	}
	held := make(map[string]bool)
	for _, query := range []string{
		"SELECT payload_ref FROM applied_base WHERE payload_ref <> ''",
		"SELECT payload_ref FROM outbound_intent WHERE payload_ref <> ''",
		"SELECT local_payload_ref FROM conflicts WHERE local_payload_ref <> '' UNION SELECT remote_payload_ref FROM conflicts WHERE remote_payload_ref <> ''",
	} {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return RetentionPrunePlan{}, err
		}
		for rows.Next() {
			var reference string
			if err := rows.Scan(&reference); err != nil {
				_ = rows.Close()
				return RetentionPrunePlan{}, err
			}
			held[reference] = true
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return RetentionPrunePlan{}, err
		}
		if err := rows.Close(); err != nil {
			return RetentionPrunePlan{}, err
		}
	}
	journalRows, err := tx.QueryContext(ctx, "SELECT id, backup_ref FROM apply_journal WHERE backup_ref <> ''")
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	for journalRows.Next() {
		var id, reference string
		if err := journalRows.Scan(&id, &reference); err != nil {
			_ = journalRows.Close()
			return RetentionPrunePlan{}, err
		}
		if !expiredBackupIDs[id] {
			held[reference] = true
		}
	}
	if err := journalRows.Err(); err != nil {
		_ = journalRows.Close()
		return RetentionPrunePlan{}, err
	}
	if err := journalRows.Close(); err != nil {
		return RetentionPrunePlan{}, err
	}
	entries, err := os.ReadDir(s.payloadDir)
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 64 || strings.ToLower(name) != name {
			continue
		}
		if _, err := hex.DecodeString(name); err != nil {
			continue
		}
		info, err := os.Lstat(filepath.Join(s.payloadDir, name))
		if err != nil {
			return RetentionPrunePlan{}, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		reference := "sha256:" + name
		if !held[reference] {
			plan.PayloadReferences = append(plan.PayloadReferences, reference)
		}
	}
	sort.Strings(plan.PayloadReferences)
	sort.Strings(plan.ExpiredBackupIDs)
	return plan, nil
}
