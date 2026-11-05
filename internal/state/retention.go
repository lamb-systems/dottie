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

	"github.com/lamb-systems/dottie/internal/vault"
)

func (s *Store) PutRetentionMaterialPayload(ctx context.Context, payload []byte) (string, error) {
	if len(payload) == 0 || len(payload) > vault.MaxEnvelopeBytes {
		return "", errors.New("retention material payload exceeds its bounds")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	reference, _ := payloadReference(payload)
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	if err := s.storePayload(reference, payload); err != nil {
		return "", err
	}
	return reference, nil
}

func (s *Store) ReplaceRetentionDeclarationWithMaterials(ctx context.Context, declaration RetentionDeclaration, materials []RetentionRecoveryPointMaterials) (RetentionDeclaration, error) {
	declaration, err := normalizeRetentionDeclaration(declaration)
	if err != nil {
		return RetentionDeclaration{}, err
	}
	if declaration.DigestVersion != 2 || len(materials) != len(declaration.RecoveryPoints) {
		return RetentionDeclaration{}, errors.New("complete bound retention materials are required")
	}
	if err := validateRetentionSubject(declaration.DeviceID); err != nil {
		return RetentionDeclaration{}, err
	}
	byPoint := make(map[string]RetentionRecoveryPointMaterials, len(materials))
	for _, item := range materials {
		key := retentionPointIdentity(item.Point)
		if _, exists := byPoint[key]; exists {
			return RetentionDeclaration{}, errors.New("duplicate retention point materials")
		}
		byPoint[key] = item
	}
	staged := make(map[string][][]byte, len(materials))
	for _, point := range declaration.RecoveryPoints {
		item, exists := byPoint[retentionPointIdentity(point)]
		if !exists || item.Point.PolicyDigest != point.PolicyDigest || !bytes.Equal(item.Point.ControlCID, point.ControlCID) {
			return RetentionDeclaration{}, ErrRetentionBoundaryNotVerified
		}
		bodyCount := 0
		seen := make(map[string]bool)
		for _, payload := range item.Payloads {
			if len(payload) == 0 || len(payload) > vault.MaxEnvelopeBytes {
				return RetentionDeclaration{}, errors.New("retention material payload exceeds its bounds")
			}
			if bytes.Equal(authenticatedPositionRawCID(payload), point.SnapshotCID) {
				bodyCount++
			}
			reference, _ := payloadReference(payload)
			if seen[reference] {
				return RetentionDeclaration{}, errors.New("duplicate retention material payload")
			}
			seen[reference] = true
			staged[reference] = append(staged[reference], bytes.Clone(payload))
		}
		if bodyCount != 1 {
			return RetentionDeclaration{}, errors.New("retention point must have exactly one snapshot body")
		}
		seenBackups := make(map[string]bool)
		for _, reference := range item.BackupReferences {
			if _, err := payloadName(reference); err != nil {
				return RetentionDeclaration{}, err
			}
			if seenBackups[reference] {
				return RetentionDeclaration{}, errors.New("duplicate retention recovery material reference")
			}
			seenBackups[reference] = true
		}
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	for reference, payloads := range staged {
		for _, payload := range payloads {
			if err := s.storePayload(reference, payload); err != nil {
				return RetentionDeclaration{}, err
			}
		}
	}
	for _, item := range materials {
		for _, reference := range item.BackupReferences {
			name, err := payloadName(reference)
			if err != nil {
				return RetentionDeclaration{}, err
			}
			if _, err := readPayload(filepath.Join(s.payloadDir, name), reference); err != nil {
				return RetentionDeclaration{}, err
			}
		}
	}
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		previous, previousErr := retentionDeclarationTx(ctx, tx, declaration.Vault, declaration.DeviceID)
		if previousErr != nil && !errors.Is(previousErr, ErrRetentionDeclarationNotFound) {
			return previousErr
		}
		if errors.Is(previousErr, ErrRetentionDeclarationNotFound) {
			declaration.PreviousDeclaredAt = -1
			if err := insertRetentionDeclarationTx(ctx, tx, declaration); err != nil {
				return err
			}
		} else {
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
			if _, err := tx.ExecContext(ctx, `UPDATE retention_declarations SET policy_digest = ?, retention_floor = ?, declaration_digest = ?, declared_at = ?, previous_declaration_digest = ?, previous_declared_at = ?, digest_version = ? WHERE vault = ? AND device_id = ?`,
				declaration.PolicyDigest[:], declaration.RetentionFloor, declaration.DeclarationDigest[:], declaration.DeclaredAt,
				declaration.PreviousDeclarationDigest[:], declaration.PreviousDeclaredAt, declaration.DigestVersion, declaration.Vault[:], declaration.DeviceID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM retention_recovery_points WHERE vault = ? AND device_id = ?", declaration.Vault[:], declaration.DeviceID); err != nil {
			return err
		}
		for _, point := range declaration.RecoveryPoints {
			if _, err := tx.ExecContext(ctx, `DELETE FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ?`, declaration.Vault[:], declaration.DeviceID, point.Epoch, point.SnapshotCID); err != nil {
				return err
			}
		}
		if err := insertRetentionPointsTx(ctx, tx, declaration.Vault, declaration.DeviceID, declaration.RecoveryPoints); err != nil {
			return err
		}
		for _, point := range declaration.RecoveryPoints {
			item := byPoint[retentionPointIdentity(point)]
			if _, err := tx.ExecContext(ctx, `UPDATE retention_recovery_material SET inventory_complete = 1
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND payload_ref = '' AND backup_ref = ''`, declaration.Vault[:], declaration.DeviceID, point.Epoch, point.SnapshotCID); err != nil {
				return err
			}
			for _, payload := range item.Payloads {
				reference, _ := payloadReference(payload)
				if _, err := tx.ExecContext(ctx, `INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
VALUES (?, ?, ?, ?, ?, '', 1)`, declaration.Vault[:], declaration.DeviceID, point.Epoch, point.SnapshotCID, reference); err != nil {
					return err
				}
			}
			for _, reference := range item.BackupReferences {
				if _, err := tx.ExecContext(ctx, `INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
VALUES (?, ?, ?, ?, '', ?, 1)`, declaration.Vault[:], declaration.DeviceID, point.Epoch, point.SnapshotCID, reference); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return RetentionDeclaration{}, err
	}
	return cloneRetentionDeclaration(declaration), nil
}

func retentionPointIdentity(point RetentionRecoveryPoint) string {
	buffer := bytes.NewBuffer(nil)
	writeRetentionUint64(buffer, point.Epoch)
	writeRetentionBytes(buffer, point.SnapshotCID)
	buffer.Write(point.PolicyDigest[:])
	writeRetentionBytes(buffer, point.ControlCID)
	return buffer.String()
}

func (s *Store) PutRetentionDeclaration(ctx context.Context, declaration RetentionDeclaration) (RetentionDeclaration, error) {
	declaration, err := normalizeRetentionDeclaration(declaration)
	if err != nil {
		return RetentionDeclaration{}, err
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		if err := s.requireRetentionPointMaterialFilesTx(ctx, tx, declaration.Vault, declaration.DeviceID, declaration.RecoveryPoints); err != nil {
			return err
		}
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
		if _, err := tx.ExecContext(ctx, `UPDATE retention_declarations SET policy_digest = ?, retention_floor = ?, declaration_digest = ?, declared_at = ?, previous_declaration_digest = ?, previous_declared_at = ?, digest_version = ? WHERE vault = ? AND device_id = ?`,
			declaration.PolicyDigest[:], declaration.RetentionFloor, declaration.DeclarationDigest[:], declaration.DeclaredAt,
			declaration.PreviousDeclarationDigest[:], declaration.PreviousDeclaredAt, declaration.DigestVersion, declaration.Vault[:], declaration.DeviceID); err != nil {
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
		rows, err := conn.QueryContext(ctx, `SELECT revision, policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at, digest_version
FROM retention_declaration_history WHERE vault = ? AND device_id = ? ORDER BY revision`, vault[:], deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var revision RetentionDeclarationRevision
			var policyDigest, digest, previousDigest []byte
			var floor int64
			var digestVersion int
			if err := rows.Scan(&revision.Revision, &policyDigest, &floor, &digest, &revision.DeclaredAt, &previousDigest, &revision.PreviousDeclaredAt, &digestVersion); err != nil {
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
			if digestVersion != 1 && digestVersion != 2 {
				return errors.New("stored retention declaration digest version is malformed")
			}
			revision.DigestVersion = uint8(digestVersion)
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
	legacyPoints := 0
	boundPoints := 0
	for index, point := range declaration.RecoveryPoints {
		if point.Epoch > uint64(^uint64(0)>>1) || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > 128 {
			return RetentionDeclaration{}, errors.New("invalid retention recovery point")
		}
		if point.PolicyDigest == ([32]byte{}) && len(point.ControlCID) == 0 {
			legacyPoints++
			point.PolicyDigest = declaration.PolicyDigest
		} else if point.PolicyDigest != ([32]byte{}) && len(point.ControlCID) != 0 && len(point.ControlCID) <= 128 {
			boundPoints++
		} else {
			return RetentionDeclaration{}, errors.New("incomplete retention recovery point binding")
		}
		controlCID := bytes.Clone(point.ControlCID)
		points[index] = RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: controlCID}
	}
	if legacyPoints != 0 && boundPoints != 0 {
		return RetentionDeclaration{}, errors.New("retention declaration mixes legacy and bound points")
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
	declaration.DigestVersion = 2
	if legacyPoints != 0 {
		declaration.DigestVersion = 1
	}
	declaration.DeclarationDigest = retentionDeclarationDigest(declaration)
	declaration.PreviousDeclarationDigest = [32]byte{}
	declaration.PreviousDeclaredAt = -1
	return declaration, nil
}

func retentionDeclarationDigest(declaration RetentionDeclaration) [32]byte {
	version := declaration.DigestVersion
	if version == 0 {
		version = 2
	}
	domain := "dottie/v1/retention-declaration\x00"
	if version == 2 {
		domain = "dottie/v2/retention-declaration\x00"
	}
	buffer := bytes.NewBufferString(domain)
	buffer.Write(declaration.Vault[:])
	writeRetentionBytes(buffer, []byte(declaration.DeviceID))
	buffer.Write(declaration.PolicyDigest[:])
	writeRetentionUint64(buffer, declaration.RetentionFloor)
	writeRetentionUint64(buffer, uint64(declaration.DeclaredAt))
	writeRetentionUint64(buffer, uint64(len(declaration.RecoveryPoints)))
	for _, point := range declaration.RecoveryPoints {
		writeRetentionUint64(buffer, point.Epoch)
		writeRetentionBytes(buffer, point.SnapshotCID)
		if version == 2 {
			buffer.Write(point.PolicyDigest[:])
			writeRetentionBytes(buffer, point.ControlCID)
		}
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
	_, err := tx.ExecContext(ctx, `INSERT INTO retention_declarations(vault, device_id, policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at, digest_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, declaration.Vault[:], declaration.DeviceID, declaration.PolicyDigest[:], declaration.RetentionFloor,
		declaration.DeclarationDigest[:], declaration.DeclaredAt, declaration.PreviousDeclarationDigest[:], declaration.PreviousDeclaredAt, declaration.DigestVersion)
	return err
}

func insertRetentionPointsTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string, points []RetentionRecoveryPoint) error {
	for ordinal, point := range points {
		controlCID := point.ControlCID
		if controlCID == nil {
			controlCID = []byte{}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO retention_recovery_points(vault, device_id, ordinal, epoch, snapshot_cid, policy_digest, control_cid) VALUES (?, ?, ?, ?, ?, ?, ?)", vault[:], deviceID, ordinal, point.Epoch, point.SnapshotCID, point.PolicyDigest[:], controlCID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
VALUES (?, ?, ?, ?, '', '', 0) ON CONFLICT(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref) DO NOTHING`, vault[:], deviceID, point.Epoch, point.SnapshotCID); err != nil {
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
	_, err := tx.ExecContext(ctx, `INSERT INTO retention_declaration_history(vault, device_id, revision, policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at, digest_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, declaration.Vault[:], declaration.DeviceID, revision, declaration.PolicyDigest[:], declaration.RetentionFloor,
		declaration.DeclarationDigest[:], declaration.DeclaredAt, declaration.PreviousDeclarationDigest[:], declaration.PreviousDeclaredAt, declaration.DigestVersion)
	return err
}

func insertRetentionHistoryPointsTx(ctx context.Context, tx *sql.Tx, revision int64, declaration RetentionDeclaration) error {
	for ordinal, point := range declaration.RecoveryPoints {
		controlCID := point.ControlCID
		if controlCID == nil {
			controlCID = []byte{}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO retention_declaration_history_points(vault, device_id, revision, ordinal, epoch, snapshot_cid, policy_digest, control_cid) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", declaration.Vault[:], declaration.DeviceID, revision, ordinal, point.Epoch, point.SnapshotCID, point.PolicyDigest[:], controlCID); err != nil {
			return err
		}
	}
	return nil
}

func retentionDeclarationTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string) (RetentionDeclaration, error) {
	var declaration RetentionDeclaration
	var policyDigest, digest, previousDigest []byte
	var floor int64
	var digestVersion int
	err := tx.QueryRowContext(ctx, `SELECT policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at, digest_version
FROM retention_declarations WHERE vault = ? AND device_id = ?`, vault[:], deviceID).Scan(&policyDigest, &floor, &digest, &declaration.DeclaredAt, &previousDigest, &declaration.PreviousDeclaredAt, &digestVersion)
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
	if digestVersion != 1 && digestVersion != 2 {
		return RetentionDeclaration{}, errors.New("stored retention declaration digest version is malformed")
	}
	declaration.DigestVersion = uint8(digestVersion)
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
	var digestVersion int
	err := conn.QueryRowContext(ctx, `SELECT policy_digest, retention_floor, declaration_digest, declared_at, previous_declaration_digest, previous_declared_at, digest_version
FROM retention_declarations WHERE vault = ? AND device_id = ?`, vault[:], deviceID).Scan(&policyDigest, &floor, &digest, &declaration.DeclaredAt, &previousDigest, &declaration.PreviousDeclaredAt, &digestVersion)
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
	if digestVersion != 1 && digestVersion != 2 {
		return RetentionDeclaration{}, errors.New("stored retention declaration digest version is malformed")
	}
	declaration.DigestVersion = uint8(digestVersion)
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
	if declaration.DigestVersion != 1 && declaration.DigestVersion != 2 {
		return errors.New("stored retention declaration digest version is malformed")
	}
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
	rows, err := tx.QueryContext(ctx, "SELECT epoch, snapshot_cid, policy_digest, control_cid FROM retention_recovery_points WHERE vault = ? AND device_id = ? ORDER BY ordinal", vault[:], deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRetentionPoints(rows)
}

func retentionPointsConn(ctx context.Context, conn *sql.Conn, vault [32]byte, deviceID string) ([]RetentionRecoveryPoint, error) {
	rows, err := conn.QueryContext(ctx, "SELECT epoch, snapshot_cid, policy_digest, control_cid FROM retention_recovery_points WHERE vault = ? AND device_id = ? ORDER BY ordinal", vault[:], deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRetentionPoints(rows)
}

func retentionHistoryPointsConn(ctx context.Context, conn *sql.Conn, vault [32]byte, deviceID string, revision int64) ([]RetentionRecoveryPoint, error) {
	rows, err := conn.QueryContext(ctx, "SELECT epoch, snapshot_cid, policy_digest, control_cid FROM retention_declaration_history_points WHERE vault = ? AND device_id = ? AND revision = ? ORDER BY ordinal", vault[:], deviceID, revision)
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
		var digest []byte
		var point RetentionRecoveryPoint
		if err := rows.Scan(&epoch, &point.SnapshotCID, &digest, &point.ControlCID); err != nil {
			return nil, err
		}
		if epoch < 0 || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > 128 {
			return nil, errors.New("stored retention recovery point is malformed")
		}
		if len(digest) != len(point.PolicyDigest) {
			return nil, errors.New("stored retention point policy digest is malformed")
		}
		point.Epoch = uint64(epoch)
		copy(point.PolicyDigest[:], digest)
		point.SnapshotCID = bytes.Clone(point.SnapshotCID)
		point.ControlCID = bytes.Clone(point.ControlCID)
		if point.ControlCID == nil {
			point.ControlCID = []byte{}
		}
		points = append(points, point)
	}
	return points, rows.Err()
}

func cloneRetentionDeclaration(declaration RetentionDeclaration) RetentionDeclaration {
	cloned := declaration
	cloned.RecoveryPoints = make([]RetentionRecoveryPoint, len(declaration.RecoveryPoints))
	for index, point := range declaration.RecoveryPoints {
		cloned.RecoveryPoints[index] = RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID)}
	}
	return cloned
}

func (s *Store) SetRetentionRecoveryPointMaterial(ctx context.Context, vault [32]byte, deviceID string, point RetentionRecoveryPoint, payloadReferences, backupReferences []string) error {
	if err := validateRetentionSubject(deviceID); err != nil {
		return err
	}
	if point.Epoch > uint64(^uint64(0)>>1) || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > 128 {
		return errors.New("invalid retention recovery point material")
	}
	for _, references := range [][]string{payloadReferences, backupReferences} {
		seen := make(map[string]bool, len(references))
		for _, reference := range references {
			if _, err := payloadName(reference); err != nil {
				return err
			}
			if seen[reference] {
				return errors.New("duplicate retention recovery material reference")
			}
			seen[reference] = true
		}
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	return s.withTx(ctx, func(tx *sql.Tx) error {
		declaration, err := retentionDeclarationTx(ctx, tx, vault, deviceID)
		if err != nil {
			return err
		}
		var declaredPoint *RetentionRecoveryPoint
		for index := range declaration.RecoveryPoints {
			candidate := &declaration.RecoveryPoints[index]
			if candidate.Epoch == point.Epoch && bytes.Equal(candidate.SnapshotCID, point.SnapshotCID) {
				declaredPoint = candidate
				break
			}
		}
		if declaredPoint == nil || declaration.DigestVersion == 2 && (declaredPoint.PolicyDigest != point.PolicyDigest || !bytes.Equal(declaredPoint.ControlCID, point.ControlCID)) {
			return ErrRetentionBoundaryNotVerified
		}
		bodyCount := 0
		payloadRefSet := make(map[string]bool, len(payloadReferences))
		for _, reference := range payloadReferences {
			payloadRefSet[reference] = true
		}
		for _, reference := range append(append([]string(nil), payloadReferences...), backupReferences...) {
			name, err := payloadName(reference)
			if err != nil {
				return err
			}
			payload, err := readPayload(filepath.Join(s.payloadDir, name), reference)
			if err != nil {
				return err
			}
			if payloadRefSet[reference] && bytes.Equal(authenticatedPositionRawCID(payload), point.SnapshotCID) {
				bodyCount++
			}
		}
		if declaration.DigestVersion == 2 && bodyCount != 1 {
			return errors.New("retention point must have exactly one snapshot body")
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND (payload_ref <> '' OR backup_ref <> '')`, vault[:], deviceID, point.Epoch, point.SnapshotCID); err != nil {
			return err
		}
		complete := 1
		if declaration.DigestVersion == 1 {
			complete = 0
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
VALUES (?, ?, ?, ?, '', '', ?) ON CONFLICT(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref) DO UPDATE SET inventory_complete = excluded.inventory_complete`, vault[:], deviceID, point.Epoch, point.SnapshotCID, complete); err != nil {
			return err
		}
		for _, reference := range payloadReferences {
			if _, err := tx.ExecContext(ctx, `INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
VALUES (?, ?, ?, ?, ?, '', 1)`, vault[:], deviceID, point.Epoch, point.SnapshotCID, reference); err != nil {
				return err
			}
		}
		for _, reference := range backupReferences {
			if _, err := tx.ExecContext(ctx, `INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
VALUES (?, ?, ?, ?, '', ?, 1)`, vault[:], deviceID, point.Epoch, point.SnapshotCID, reference); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PlanRetentionPrune(ctx context.Context, request RetentionPruneRequest) (RetentionPrunePlan, error) {
	if err := validateRetentionPruneRequest(request); err != nil {
		return RetentionPrunePlan{}, err
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
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
			result, err := tx.ExecContext(ctx, `UPDATE apply_journal SET backup_ref = '',
preimage_value_type = CASE WHEN source = 'gnome' THEN '' ELSE preimage_value_type END,
preimage_value_text = CASE WHEN source = 'gnome' THEN '' ELSE preimage_value_text END,
postimage_value_type = CASE WHEN source = 'gnome' THEN '' ELSE postimage_value_type END,
postimage_value_text = CASE WHEN source = 'gnome' THEN '' ELSE postimage_value_text END
WHERE id = ? AND backup_ref <> '' AND ((state = 'applied' AND stage = ?) OR (state = 'rolled-back' AND stage = ?))`, id, JournalStageVerified, JournalStageRolledBack)
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
	if request.Boundary.Epoch > uint64(^uint64(0)>>1) || len(request.Boundary.SnapshotCID) == 0 || len(request.Boundary.SnapshotCID) > 128 || request.Boundary.PolicyDigest == ([32]byte{}) || len(request.Boundary.ControlCID) == 0 || len(request.Boundary.ControlCID) > 128 || request.Now.IsZero() {
		return errors.New("invalid retention prune request")
	}
	return nil
}

type retentionJournalBackup struct {
	id             string
	reference      string
	createdAt      int64
	terminal       bool
	aged           bool
	bound          bool
	associated     bool
	legacy         bool
	bindingVault   []byte
	bindingEpoch   sql.NullInt64
	bindingCID     []byte
	bindingDigest  []byte
	bindingControl []byte
	bindingVersion int
	eligible       bool
}

func validRetentionJournalBinding(vault []byte, epoch sql.NullInt64, snapshotCID, policyDigest, controlCID []byte, version int) bool {
	return version == 1 && len(vault) == 32 && epoch.Valid && epoch.Int64 >= 0 &&
		len(snapshotCID) > 0 && len(snapshotCID) <= 128 && len(policyDigest) == 32 &&
		len(controlCID) > 0 && len(controlCID) <= 128
}

func retentionBackupAssociationTx(ctx context.Context, tx *sql.Tx, vault []byte, deviceID string, epoch int64, snapshotCID, policyDigest, controlCID []byte, reference string) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM retention_recovery_material AS material
WHERE material.vault = ? AND material.device_id = ? AND material.epoch = ? AND material.snapshot_cid = ? AND material.backup_ref = ?
AND (
 EXISTS (SELECT 1 FROM retention_recovery_points AS point
  WHERE point.vault = material.vault AND point.device_id = material.device_id AND point.epoch = material.epoch AND point.snapshot_cid = material.snapshot_cid
    AND point.policy_digest = ? AND point.control_cid = ?)
 OR EXISTS (SELECT 1 FROM retention_declaration_history_points AS point
  WHERE point.vault = material.vault AND point.device_id = material.device_id AND point.epoch = material.epoch AND point.snapshot_cid = material.snapshot_cid
    AND point.policy_digest = ? AND point.control_cid = ?)
)`, vault, deviceID, epoch, snapshotCID, reference, policyDigest, controlCID, policyDigest, controlCID).Scan(&count)
	return count == 1, err
}

func selectedRetentionDeviceTx(ctx context.Context, tx *sql.Tx, vault []byte) (string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT device_id FROM vault_selections WHERE vault = ? ORDER BY device_id LIMIT 2", vault)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var deviceID string
	if !rows.Next() {
		return "", rows.Err()
	}
	if err := rows.Scan(&deviceID); err != nil {
		return "", err
	}
	if rows.Next() {
		return "", nil
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return deviceID, nil
}

func retainedRecoveryMaterialTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string, points []RetentionRecoveryPoint) (map[string]bool, map[string]bool, error) {
	payloadReferences := make(map[string]bool)
	backupReferences := make(map[string]bool)
	for _, point := range points {
		rows, err := tx.QueryContext(ctx, `SELECT payload_ref, backup_ref, inventory_complete FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ?`, vault[:], deviceID, point.Epoch, point.SnapshotCID)
		if err != nil {
			return nil, nil, err
		}
		markerFound := false
		markerComplete := false
		for rows.Next() {
			var payloadRef, backupRef string
			var complete int
			if err := rows.Scan(&payloadRef, &backupRef, &complete); err != nil {
				_ = rows.Close()
				return nil, nil, err
			}
			if payloadRef == "" && backupRef == "" {
				markerFound = true
				markerComplete = complete == 1
			}
			if payloadRef != "" {
				payloadReferences[payloadRef] = true
			}
			if backupRef != "" {
				backupReferences[backupRef] = true
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, nil, err
		}
		if !markerFound || !markerComplete {
			return nil, nil, ErrRetentionRecoveryPointInventoryUnknown
		}
	}
	return payloadReferences, backupReferences, nil
}

func (s *Store) revalidateRetentionMaterialDigestsTx(ctx context.Context, tx *sql.Tx, vaultID [32]byte, deviceID string, points []RetentionRecoveryPoint) error {
	for _, point := range points {
		rows, err := tx.QueryContext(ctx, `SELECT payload_ref, backup_ref FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ?`, vaultID[:], deviceID, point.Epoch, point.SnapshotCID)
		if err != nil {
			return err
		}
		bodyCount := 0
		for rows.Next() {
			var payloadRef, backupRef string
			if err := rows.Scan(&payloadRef, &backupRef); err != nil {
				_ = rows.Close()
				return err
			}
			if payloadRef != "" {
				name, err := payloadName(payloadRef)
				if err != nil {
					_ = rows.Close()
					return err
				}
				payload, err := readPayload(filepath.Join(s.payloadDir, name), payloadRef)
				if err != nil {
					_ = rows.Close()
					return err
				}
				if bytes.Equal(authenticatedPositionRawCID(payload), point.SnapshotCID) {
					bodyCount++
				}
			}
			if backupRef != "" {
				name, err := payloadName(backupRef)
				if err != nil {
					_ = rows.Close()
					return err
				}
				if _, err := readPayload(filepath.Join(s.payloadDir, name), backupRef); err != nil {
					_ = rows.Close()
					return err
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if bodyCount != 1 {
			return errors.New("retention recovery point must have exactly one CID-matching body")
		}
	}
	return nil
}

func (s *Store) requireRetentionPointMaterialFilesTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string, points []RetentionRecoveryPoint) error {
	for _, point := range points {
		rows, err := tx.QueryContext(ctx, `SELECT payload_ref, backup_ref FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND (payload_ref <> '' OR backup_ref <> '')`, vault[:], deviceID, point.Epoch, point.SnapshotCID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var payloadRef, backupRef string
			if err := rows.Scan(&payloadRef, &backupRef); err != nil {
				_ = rows.Close()
				return err
			}
			for _, reference := range []string{payloadRef, backupRef} {
				if reference != "" {
					name, err := payloadName(reference)
					if err != nil {
						_ = rows.Close()
						return err
					}
					if _, err := readPayload(filepath.Join(s.payloadDir, name), reference); err != nil {
						_ = rows.Close()
						return err
					}
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

func globallyRetainedRecoveryReferencesTx(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT material.payload_ref, material.backup_ref
FROM retention_recovery_material AS material
JOIN retention_recovery_points AS point
  ON point.vault = material.vault AND point.device_id = material.device_id
 AND point.epoch = material.epoch AND point.snapshot_cid = material.snapshot_cid
WHERE material.payload_ref <> '' OR material.backup_ref <> ''`)
	if err != nil {
		return nil, err
	}
	references := make(map[string]bool)
	for rows.Next() {
		var payloadRef, backupRef string
		if err := rows.Scan(&payloadRef, &backupRef); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if payloadRef != "" {
			references[payloadRef] = true
		}
		if backupRef != "" {
			references[backupRef] = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return references, nil
}

func recoveryMaterialEpochsTx(ctx context.Context, tx *sql.Tx, vault [32]byte, deviceID string) (map[string]map[uint64]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT epoch, payload_ref, backup_ref FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND (payload_ref <> '' OR backup_ref <> '')`, vault[:], deviceID)
	if err != nil {
		return nil, err
	}
	epochs := make(map[string]map[uint64]bool)
	for rows.Next() {
		var epoch int64
		var payloadRef, backupRef string
		if err := rows.Scan(&epoch, &payloadRef, &backupRef); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if epoch < 0 {
			_ = rows.Close()
			return nil, errors.New("stored recovery material epoch is malformed")
		}
		for _, reference := range []string{payloadRef, backupRef} {
			if reference == "" {
				continue
			}
			if epochs[reference] == nil {
				epochs[reference] = make(map[uint64]bool)
			}
			epochs[reference][uint64(epoch)] = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return epochs, nil
}

func sortedMaterialEpochs(values map[uint64]bool) []uint64 {
	epochs := make([]uint64, 0, len(values))
	for epoch := range values {
		epochs = append(epochs, epoch)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	return epochs
}

func allEpochsBefore(epochs []uint64, boundary uint64) bool {
	if len(epochs) == 0 {
		return false
	}
	for _, epoch := range epochs {
		if epoch >= boundary {
			return false
		}
	}
	return true
}

func recoveryPointAllowsPruning(epochs []uint64, boundary uint64, tiedToRetainedPoint bool) bool {
	return !tiedToRetainedPoint && allEpochsBefore(epochs, boundary)
}

func (s *Store) planRetentionPruneTx(ctx context.Context, tx *sql.Tx, request RetentionPruneRequest) (RetentionPrunePlan, error) {
	declaration, err := retentionDeclarationTx(ctx, tx, request.Vault, request.DeviceID)
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	if declaration.DigestVersion != 2 {
		return RetentionPrunePlan{}, ErrRetentionRecoveryPointInventoryUnknown
	}
	pointFound := false
	oldestEpoch := uint64(^uint64(0))
	var oldestPoint RetentionRecoveryPoint
	for _, point := range declaration.RecoveryPoints {
		if point.Epoch < oldestEpoch {
			oldestEpoch = point.Epoch
			oldestPoint = point
		}
		if point.Epoch == request.Boundary.Epoch && bytes.Equal(point.SnapshotCID, request.Boundary.SnapshotCID) &&
			point.PolicyDigest == request.Boundary.PolicyDigest && bytes.Equal(point.ControlCID, request.Boundary.ControlCID) {
			pointFound = true
		}
	}
	if !pointFound {
		return RetentionPrunePlan{}, ErrRetentionBoundaryNotVerified
	}
	if request.Boundary.Epoch > oldestEpoch {
		return RetentionPrunePlan{}, ErrRetentionBoundaryNewerThanFloor
	}
	if request.Boundary.Epoch == oldestEpoch && (!bytes.Equal(oldestPoint.SnapshotCID, request.Boundary.SnapshotCID) ||
		oldestPoint.PolicyDigest != request.Boundary.PolicyDigest || !bytes.Equal(oldestPoint.ControlCID, request.Boundary.ControlCID)) {
		return RetentionPrunePlan{}, ErrRetentionBoundaryNotVerified
	}
	var checkpointEpoch int64
	var checkpointSnapshotCID, checkpointPolicyDigest, checkpointControlCID []byte
	err = tx.QueryRowContext(ctx, "SELECT epoch, snapshot_cid, policy_digest, control_cid FROM vault_checkpoints WHERE vault = ?", request.Vault[:]).Scan(&checkpointEpoch, &checkpointSnapshotCID, &checkpointPolicyDigest, &checkpointControlCID)
	if errors.Is(err, sql.ErrNoRows) {
		return RetentionPrunePlan{}, ErrRetentionBoundaryNotVerified
	}
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	if checkpointEpoch < 0 || uint64(checkpointEpoch) != request.Boundary.Epoch ||
		!bytes.Equal(checkpointSnapshotCID, request.Boundary.SnapshotCID) || !bytes.Equal(checkpointPolicyDigest, request.Boundary.PolicyDigest[:]) ||
		!bytes.Equal(checkpointControlCID, request.Boundary.ControlCID) {
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
	if _, _, err := retainedRecoveryMaterialTx(ctx, tx, request.Vault, request.DeviceID, declaration.RecoveryPoints); err != nil {
		return RetentionPrunePlan{}, err
	}
	if err := s.revalidateRetentionMaterialDigestsTx(ctx, tx, request.Vault, request.DeviceID, declaration.RecoveryPoints); err != nil {
		return RetentionPrunePlan{}, err
	}
	retainedReferences, err := globallyRetainedRecoveryReferencesTx(ctx, tx)
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	materialEpochs, err := recoveryMaterialEpochsTx(ctx, tx, request.Vault, request.DeviceID)
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	plan := RetentionPrunePlan{
		Vault: request.Vault, DeviceID: request.DeviceID, Boundary: RetentionRecoveryPoint{Epoch: request.Boundary.Epoch, SnapshotCID: bytes.Clone(request.Boundary.SnapshotCID), PolicyDigest: request.Boundary.PolicyDigest, ControlCID: bytes.Clone(request.Boundary.ControlCID)},
		PolicyDigest: declaration.PolicyDigest, RetentionFloor: declaration.RetentionFloor,
		RecoveryPoints: cloneRetentionDeclaration(declaration).RecoveryPoints, EpochScope: RetentionPruneScope,
	}
	refsByClass := map[string]map[string]bool{
		"applied base":    {},
		"outbound intent": {},
		"conflict":        {},
	}
	for class, query := range map[string]string{
		"applied base":    "SELECT payload_ref FROM applied_base WHERE payload_ref <> ''",
		"outbound intent": "SELECT payload_ref FROM outbound_intent WHERE payload_ref <> ''",
		"conflict":        "SELECT local_payload_ref FROM conflicts WHERE local_payload_ref <> '' UNION SELECT remote_payload_ref FROM conflicts WHERE remote_payload_ref <> ''",
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
			refsByClass[class][reference] = true
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return RetentionPrunePlan{}, err
		}
		if err := rows.Close(); err != nil {
			return RetentionPrunePlan{}, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, backup_ref, created_at, state, stage, vault, epoch, snapshot_cid, policy_digest, control_cid, retention_binding_version FROM apply_journal
WHERE backup_ref <> '' ORDER BY id`)
	if err != nil {
		return RetentionPrunePlan{}, err
	}
	var backups []retentionJournalBackup
	for rows.Next() {
		var backup retentionJournalBackup
		var stateValue, stage string
		var retentionVault, retentionSnapshot, retentionPolicyDigest, retentionControlCID []byte
		var retentionEpoch sql.NullInt64
		var retentionBindingVersion int
		if err := rows.Scan(&backup.id, &backup.reference, &backup.createdAt, &stateValue, &stage, &retentionVault, &retentionEpoch, &retentionSnapshot, &retentionPolicyDigest, &retentionControlCID, &retentionBindingVersion); err != nil {
			_ = rows.Close()
			return RetentionPrunePlan{}, err
		}
		backup.terminal = (stateValue == "applied" && stage == JournalStageVerified) || (stateValue == "rolled-back" && stage == JournalStageRolledBack)
		backup.aged = !request.Now.Before(time.Unix(backup.createdAt, 0).Add(JournalBackupRetention))
		backup.legacy = retentionBindingVersion == 0
		backup.bound = len(retentionVault) != 0 || retentionEpoch.Valid || len(retentionSnapshot) != 0 || len(retentionPolicyDigest) != 0 || len(retentionControlCID) != 0
		backup.bindingVault = bytes.Clone(retentionVault)
		backup.bindingEpoch = retentionEpoch
		backup.bindingCID = bytes.Clone(retentionSnapshot)
		backup.bindingDigest = bytes.Clone(retentionPolicyDigest)
		backup.bindingControl = bytes.Clone(retentionControlCID)
		backup.bindingVersion = retentionBindingVersion
		backups = append(backups, backup)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return RetentionPrunePlan{}, err
	}
	if err := rows.Close(); err != nil {
		return RetentionPrunePlan{}, err
	}
	for index := range backups {
		backup := &backups[index]
		if backup.bound && validRetentionJournalBinding(backup.bindingVault, backup.bindingEpoch, backup.bindingCID, backup.bindingDigest, backup.bindingControl, backup.bindingVersion) && bytes.Equal(backup.bindingVault, request.Vault[:]) {
			associated, err := retentionBackupAssociationTx(ctx, tx, request.Vault[:], request.DeviceID, backup.bindingEpoch.Int64, backup.bindingCID, backup.bindingDigest, backup.bindingControl, backup.reference)
			if err != nil {
				return RetentionPrunePlan{}, err
			}
			backup.associated = associated
			if backup.associated {
				if epochs := materialEpochs[backup.reference]; epochs == nil {
					materialEpochs[backup.reference] = map[uint64]bool{uint64(backup.bindingEpoch.Int64): true}
				} else {
					epochs[uint64(backup.bindingEpoch.Int64)] = true
				}
			}
		}
		if backup.reference != "" {
			name, err := payloadName(backup.reference)
			if err != nil {
				return RetentionPrunePlan{}, err
			}
			if _, err := readPayload(filepath.Join(s.payloadDir, name), backup.reference); err != nil {
				return RetentionPrunePlan{}, err
			}
		}
		epochs := sortedMaterialEpochs(materialEpochs[backup.reference])
		recoveryEligible := recoveryPointAllowsPruning(epochs, request.Boundary.Epoch, retainedReferences[backup.reference])
		bindingKnown := backup.bindingVersion == 1 && backup.bound && backup.associated
		backup.eligible = backup.terminal && backup.aged && recoveryEligible && bindingKnown && !backup.legacy &&
			!refsByClass["applied base"][backup.reference] && !refsByClass["outbound intent"][backup.reference] && !refsByClass["conflict"][backup.reference]
	}
	for index := range backups {
		backup := &backups[index]
		if backup.eligible {
			for otherIndex, other := range backups {
				if otherIndex != index && other.reference == backup.reference && !other.eligible {
					backup.eligible = false
					break
				}
			}
		}
		epochs := sortedMaterialEpochs(materialEpochs[backup.reference])
		classifiedBeforeBoundary := len(epochs) > 0 && allEpochsBefore(epochs, request.Boundary.Epoch)
		reasons := []string{}
		if backup.legacy {
			reasons = append(reasons, "legacy journal row has no retention-binding version")
		} else if backup.bound && backup.associated {
			reasons = append(reasons, "journal backup has an authenticated binding and recovery-material association")
		} else if backup.bound {
			reasons = append(reasons, "journal backup has an authenticated binding without a recovery-material association")
		} else {
			reasons = append(reasons, "journal backup has no retention binding")
		}
		if backup.terminal {
			reasons = append(reasons, "verified applied or rolled-back journal entry")
		} else {
			reasons = append(reasons, "journal entry is not in a verified applied or rolled-back state")
		}
		if backup.aged {
			reasons = append(reasons, "journal backup age bound elapsed")
		} else {
			reasons = append(reasons, "journal backup is within age bound")
		}
		for _, class := range []string{"applied base", "outbound intent", "conflict"} {
			if refsByClass[class][backup.reference] {
				reasons = append(reasons, "referenced by "+class)
			} else {
				reasons = append(reasons, "unreferenced by "+class)
			}
		}
		if retainedReferences[backup.reference] {
			reasons = append(reasons, "tied to a retained recovery point")
		} else {
			reasons = append(reasons, "not tied to a retained recovery point")
		}
		if len(epochs) == 0 {
			reasons = append(reasons, "recovery-point epoch is unclassified")
		} else if classifiedBeforeBoundary {
			reasons = append(reasons, "all associated recovery-point epochs are below the boundary")
		} else {
			reasons = append(reasons, "associated recovery-point epoch is at or above the boundary")
		}
		if backup.eligible {
			reasons = append(reasons, "not shared by a non-prunable journal backup")
			plan.ExpiredBackupIDs = append(plan.ExpiredBackupIDs, backup.id)
		} else if backup.terminal && backup.aged && !retainedReferences[backup.reference] {
			for otherIndex, other := range backups {
				if otherIndex != index && other.reference == backup.reference && !other.eligible {
					reasons = append(reasons, "shared with a non-prunable journal backup")
					break
				}
			}
		}
		plan.Candidates = append(plan.Candidates, RetentionPruneCandidate{
			Kind: RetentionPruneCandidateBackup, Reference: backup.reference, JournalID: backup.id,
			RecoveryPointEpochs: epochs, RecoveryPointEpochKnown: len(epochs) > 0, Eligible: backup.eligible, Reasons: reasons,
		})
	}
	heldByBackup := map[string]bool{}
	for _, backup := range backups {
		if !backup.eligible {
			heldByBackup[backup.reference] = true
		}
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
		if _, err := readPayload(filepath.Join(s.payloadDir, name), reference); err != nil {
			return RetentionPrunePlan{}, err
		}
		epochs := sortedMaterialEpochs(materialEpochs[reference])
		classifiedBeforeBoundary := len(epochs) > 0 && allEpochsBefore(epochs, request.Boundary.Epoch)
		eligible := recoveryPointAllowsPruning(epochs, request.Boundary.Epoch, retainedReferences[reference])
		reasons := []string{}
		for _, class := range []string{"applied base", "outbound intent", "conflict"} {
			if refsByClass[class][reference] {
				eligible = false
				reasons = append(reasons, "referenced by "+class)
			} else {
				reasons = append(reasons, "unreferenced by "+class)
			}
		}
		if heldByBackup[reference] {
			eligible = false
			reasons = append(reasons, "referenced by a non-prunable journal backup")
		} else {
			reasons = append(reasons, "unreferenced by non-prunable journal backups")
		}
		if retainedReferences[reference] {
			reasons = append(reasons, "tied to a retained recovery point")
		} else {
			reasons = append(reasons, "not tied to a retained recovery point")
		}
		if len(epochs) == 0 {
			reasons = append(reasons, "recovery-point epoch is unclassified")
		} else if classifiedBeforeBoundary {
			reasons = append(reasons, "all associated recovery-point epochs are below the boundary")
		} else {
			reasons = append(reasons, "associated recovery-point epoch is at or above the boundary")
		}
		plan.Candidates = append(plan.Candidates, RetentionPruneCandidate{
			Kind: RetentionPruneCandidatePayload, Reference: reference, RecoveryPointEpochs: epochs,
			RecoveryPointEpochKnown: len(epochs) > 0, Eligible: eligible, Reasons: reasons,
		})
		if eligible {
			plan.PayloadReferences = append(plan.PayloadReferences, reference)
		}
	}
	sort.Strings(plan.PayloadReferences)
	sort.Strings(plan.ExpiredBackupIDs)
	sort.Slice(plan.Candidates, func(i, j int) bool {
		if plan.Candidates[i].Kind != plan.Candidates[j].Kind {
			return plan.Candidates[i].Kind < plan.Candidates[j].Kind
		}
		if plan.Candidates[i].Reference != plan.Candidates[j].Reference {
			return plan.Candidates[i].Reference < plan.Candidates[j].Reference
		}
		return plan.Candidates[i].JournalID < plan.Candidates[j].JournalID
	})
	return plan, nil
}
