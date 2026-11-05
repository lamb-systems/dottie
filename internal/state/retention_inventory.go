package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	cid "github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
)

func (s *Store) RetentionInventory(ctx context.Context, vaultID [32]byte, deviceID string) (RetentionInventory, error) {
	if err := validateRetentionSubject(deviceID); err != nil {
		return RetentionInventory{}, err
	}
	inventory := RetentionInventory{Vault: vaultID, DeviceID: deviceID}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		knownEpochs := make(map[uint64]bool)
		knownReferences := make(map[string]bool)
		allRecoveryReferences := make(map[string]bool)
		unclassifiedReferences := make(map[string]bool)
		unknownReasons := make(map[string]bool)
		addUnknown := func(reason string) { unknownReasons[reason] = true }
		if err := readRetentionInventoryPoints(ctx, tx, vaultID, deviceID, &inventory, addUnknown); err != nil {
			return err
		}
		if err := readRetentionInventoryMaterials(ctx, tx, vaultID, deviceID, &inventory, knownReferences, addUnknown); err != nil {
			return err
		}
		if err := readRetentionInventoryGlobalReferences(ctx, tx, allRecoveryReferences, addUnknown); err != nil {
			return err
		}
		if err := readRetentionInventoryJournal(ctx, tx, s.payloadDir, vaultID, knownEpochs, knownReferences, allRecoveryReferences, addUnknown); err != nil {
			return err
		}
		if err := readRetentionInventoryOtherReferences(ctx, tx, allRecoveryReferences, unclassifiedReferences, addUnknown); err != nil {
			return err
		}
		if err := s.reconcileRetentionInventoryFiles(&inventory, knownEpochs, knownReferences, allRecoveryReferences, unclassifiedReferences, unknownReasons); err != nil {
			return err
		}
		for epoch := range knownEpochs {
			inventory.KnownMaterialEpochs = append(inventory.KnownMaterialEpochs, epoch)
		}
		sort.Slice(inventory.KnownMaterialEpochs, func(i, j int) bool { return inventory.KnownMaterialEpochs[i] < inventory.KnownMaterialEpochs[j] })
		for reason := range unknownReasons {
			inventory.UnknownHoldingReasons = append(inventory.UnknownHoldingReasons, reason)
		}
		sort.Strings(inventory.UnknownHoldingReasons)
		return nil
	})
	if err != nil {
		return RetentionInventory{}, err
	}
	return inventory, nil
}

func readRetentionInventoryPoints(ctx context.Context, tx *sql.Tx, vaultID [32]byte, deviceID string, inventory *RetentionInventory, addUnknown func(string)) error {
	rows, err := tx.QueryContext(ctx, `SELECT epoch, snapshot_cid, policy_digest, control_cid
FROM retention_recovery_points WHERE vault = ? AND device_id = ? ORDER BY ordinal LIMIT ?`, vaultID[:], deviceID, MaxRetentionInventoryRows+1)
	if err != nil {
		return err
	}
	for rows.Next() {
		var epoch int64
		var point RetentionInventoryPoint
		var digest []byte
		if err := rows.Scan(&epoch, &point.SnapshotCID, &digest, &point.ControlCID); err != nil {
			_ = rows.Close()
			return err
		}
		if epoch < 0 || len(point.SnapshotCID) == 0 || len(point.SnapshotCID) > 128 || len(digest) != 32 || len(point.ControlCID) > 128 {
			_ = rows.Close()
			return errors.New("stored retention inventory point is malformed")
		}
		point.Epoch = uint64(epoch)
		copy(point.PolicyDigest[:], digest)
		point.SnapshotCID = bytes.Clone(point.SnapshotCID)
		point.ControlCID = bytes.Clone(point.ControlCID)
		if point.ControlCID == nil {
			point.ControlCID = []byte{}
		}
		inventory.Points = append(inventory.Points, point)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(inventory.Points) > MaxRetentionInventoryRows {
		inventory.Points = inventory.Points[:MaxRetentionInventoryRows]
		addUnknown("retention-point-row-limit")
	}
	return nil
}

func readRetentionInventoryMaterials(ctx context.Context, tx *sql.Tx, vaultID [32]byte, deviceID string, inventory *RetentionInventory, knownReferences map[string]bool, addUnknown func(string)) error {
	rows, err := tx.QueryContext(ctx, `SELECT epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete
FROM retention_recovery_material WHERE vault = ? AND device_id = ? ORDER BY epoch, snapshot_cid, payload_ref, backup_ref LIMIT ?`, vaultID[:], deviceID, MaxRetentionInventoryRows+1)
	if err != nil {
		return err
	}
	for rows.Next() {
		var epoch int64
		var material RetentionRecoveryMaterial
		var complete int
		if err := rows.Scan(&epoch, &material.SnapshotCID, &material.PayloadReference, &material.BackupReference, &complete); err != nil {
			_ = rows.Close()
			return err
		}
		if epoch < 0 || len(material.SnapshotCID) == 0 || len(material.SnapshotCID) > 128 || complete < 0 || complete > 1 {
			_ = rows.Close()
			addUnknown("malformed-recovery-material-binding")
			continue
		}
		material.Epoch = uint64(epoch)
		material.SnapshotCID = bytes.Clone(material.SnapshotCID)
		material.InventoryComplete = complete == 1
		inventory.Materials = append(inventory.Materials, material)
		for _, reference := range []string{material.PayloadReference, material.BackupReference} {
			if reference == "" {
				continue
			}
			if _, err := payloadName(reference); err != nil {
				addUnknown("malformed-recovery-material-reference")
				continue
			}
			knownReferences[reference] = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	materialsTruncated := len(inventory.Materials) > MaxRetentionInventoryRows
	if materialsTruncated {
		inventory.Materials = inventory.Materials[:MaxRetentionInventoryRows]
		addUnknown("retention-material-row-limit")
	}
	for index := range inventory.Points {
		point := &inventory.Points[index]
		marker, complete, bodyCount := 0, 0, 0
		for _, material := range inventory.Materials {
			if material.Epoch != point.Epoch || !bytes.Equal(material.SnapshotCID, point.SnapshotCID) {
				continue
			}
			if material.PayloadReference == "" && material.BackupReference == "" {
				marker++
				if material.InventoryComplete {
					complete++
				}
			}
			if material.PayloadReference != "" && payloadReferenceMatchesSnapshot(material.PayloadReference, point.SnapshotCID) {
				bodyCount++
			}
		}
		point.InventoryComplete = !materialsTruncated && marker == 1 && complete == 1 && bodyCount == 1
	}
	return nil
}

func readRetentionInventoryGlobalReferences(ctx context.Context, tx *sql.Tx, references map[string]bool, addUnknown func(string)) error {
	rows, err := tx.QueryContext(ctx, `SELECT payload_ref FROM retention_recovery_material WHERE payload_ref <> ''
UNION SELECT backup_ref FROM retention_recovery_material WHERE backup_ref <> '' LIMIT ?`, MaxRetentionInventoryRows+1)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var reference string
		if err := rows.Scan(&reference); err != nil {
			_ = rows.Close()
			return err
		}
		count++
		references[reference] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if count > MaxRetentionInventoryRows {
		addUnknown("global-retention-reference-limit")
	}
	return nil
}

func readRetentionInventoryJournal(ctx context.Context, tx *sql.Tx, payloadDir string, vaultID [32]byte, knownEpochs map[uint64]bool, knownReferences, allRecoveryReferences map[string]bool, addUnknown func(string)) error {
	rows, err := tx.QueryContext(ctx, `SELECT backup_ref, vault, epoch, snapshot_cid, policy_digest, control_cid, retention_binding_version
FROM apply_journal WHERE backup_ref <> '' ORDER BY id LIMIT ?`, MaxRetentionInventoryRows+1)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var reference string
		var boundVault, snapshotCID, policyDigest, controlCID []byte
		var epoch sql.NullInt64
		var bindingVersion int
		if err := rows.Scan(&reference, &boundVault, &epoch, &snapshotCID, &policyDigest, &controlCID, &bindingVersion); err != nil {
			_ = rows.Close()
			return err
		}
		count++
		if _, err := payloadName(reference); err != nil {
			if retentionPayloadExists(payloadDir, reference) {
				addUnknown("malformed-journal-backup-reference")
			}
			continue
		}
		allRecoveryReferences[reference] = true
		if !retentionPayloadExists(payloadDir, reference) {
			continue
		}
		if len(boundVault) == 32 && bytes.Equal(boundVault, vaultID[:]) && epoch.Valid && epoch.Int64 >= 0 && bindingVersion != 0 && len(snapshotCID) > 0 && len(policyDigest) == 32 && len(controlCID) > 0 {
			knownEpochs[uint64(epoch.Int64)] = true
			knownReferences[reference] = true
			continue
		}
		if len(boundVault) == 0 && !epoch.Valid && len(snapshotCID) == 0 && len(policyDigest) == 0 && len(controlCID) == 0 {
			addUnknown("legacy-unbound-journal-backup")
			continue
		}
		if len(boundVault) == 0 || !epoch.Valid || epoch.Int64 < 0 || bindingVersion == 0 {
			addUnknown("journal-backup-epoch-unknown")
			continue
		}
		if len(boundVault) != 32 || len(snapshotCID) == 0 || len(policyDigest) != 32 || len(controlCID) == 0 {
			addUnknown("malformed-journal-backup-binding")
			continue
		}
		if !bytes.Equal(boundVault, vaultID[:]) {
			continue
		}
		knownEpochs[uint64(epoch.Int64)] = true
		knownReferences[reference] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if count > MaxRetentionInventoryRows {
		addUnknown("journal-backup-row-limit")
	}
	return nil
}

func readRetentionInventoryOtherReferences(ctx context.Context, tx *sql.Tx, allRecoveryReferences, unclassifiedReferences map[string]bool, addUnknown func(string)) error {
	queries := []string{
		"SELECT payload_ref FROM applied_base WHERE payload_ref <> '' LIMIT ?",
		"SELECT payload_ref FROM outbound_intent WHERE payload_ref <> '' LIMIT ?",
		"SELECT local_payload_ref FROM conflicts WHERE local_payload_ref <> '' UNION SELECT remote_payload_ref FROM conflicts WHERE remote_payload_ref <> '' LIMIT ?",
	}
	for _, query := range queries {
		rows, err := tx.QueryContext(ctx, query, MaxRetentionInventoryRows+1)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			var reference string
			if err := rows.Scan(&reference); err != nil {
				_ = rows.Close()
				return err
			}
			count++
			allRecoveryReferences[reference] = true
			unclassifiedReferences[reference] = true
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if count > MaxRetentionInventoryRows {
			addUnknown("other-payload-reference-limit")
		}
	}
	return nil
}

func (s *Store) reconcileRetentionInventoryFiles(inventory *RetentionInventory, knownEpochs map[uint64]bool, knownReferences, allRecoveryReferences, unclassifiedReferences map[string]bool, unknownReasons map[string]bool) error {
	for _, material := range inventory.Materials {
		for _, reference := range []string{material.PayloadReference, material.BackupReference} {
			if reference == "" || !retentionPayloadExists(s.payloadDir, reference) {
				continue
			}
			knownEpochs[material.Epoch] = true
			if !retentionPayloadDigestValid(s.payloadDir, reference) {
				unknownReasons["corrupt-associated-payload"] = true
			}
		}
	}
	for reference := range knownReferences {
		if !retentionPayloadExists(s.payloadDir, reference) {
			continue
		}
		for _, material := range inventory.Materials {
			if material.PayloadReference == reference || material.BackupReference == reference {
				knownEpochs[material.Epoch] = true
			}
		}
	}
	for reference := range unclassifiedReferences {
		if retentionPayloadExists(s.payloadDir, reference) && !knownReferences[reference] {
			unknownReasons["unclassified-associated-payload"] = true
		}
	}
	if err := s.inspectUnclassifiedPayloadFiles(allRecoveryReferences, unknownReasons); err != nil {
		return err
	}
	for index := range inventory.Points {
		point := &inventory.Points[index]
		if !point.InventoryComplete {
			continue
		}
		for _, material := range inventory.Materials {
			if material.Epoch != point.Epoch || !bytes.Equal(material.SnapshotCID, point.SnapshotCID) {
				continue
			}
			for _, reference := range []string{material.PayloadReference, material.BackupReference} {
				if reference != "" && (!retentionPayloadExists(s.payloadDir, reference) || !retentionPayloadDigestValid(s.payloadDir, reference)) {
					point.InventoryComplete = false
				}
			}
		}
	}
	return nil
}

func (s *Store) inspectUnclassifiedPayloadFiles(classified map[string]bool, unknownReasons map[string]bool) error {
	directory, err := os.Open(s.payloadDir)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(MaxRetentionInventoryFiles + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > MaxRetentionInventoryFiles {
		unknownReasons["payload-directory-entry-limit"] = true
		entries = entries[:MaxRetentionInventoryFiles]
	}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 64 || strings.ToLower(name) != name {
			unknownReasons["unexpected-payload-directory-entry"] = true
			continue
		}
		if _, err := hex.DecodeString(name); err != nil {
			unknownReasons["unexpected-payload-directory-entry"] = true
			continue
		}
		info, err := os.Lstat(filepath.Join(s.payloadDir, name))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if !info.Mode().IsRegular() {
			unknownReasons["unexpected-payload-directory-entry"] = true
			continue
		}
		reference := "sha256:" + name
		if !classified[reference] {
			unknownReasons["unclassified-payload-file"] = true
		}
	}
	return nil
}

func retentionPayloadExists(directory, reference string) bool {
	name, err := payloadName(reference)
	if err != nil {
		return false
	}
	info, err := os.Lstat(filepath.Join(directory, name))
	return err == nil && info.Mode().IsRegular()
}

func retentionPayloadDigestValid(directory, reference string) bool {
	name, err := payloadName(reference)
	if err != nil {
		return false
	}
	fd, err := syscall.Open(filepath.Join(directory, name), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > vault.MaxEnvelopeBytes {
		return false
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, info.Size()); err != nil {
		return false
	}
	return hex.EncodeToString(hash.Sum(nil)) == name
}

func payloadReferenceMatchesSnapshot(reference string, snapshotCID []byte) bool {
	name, err := payloadName(reference)
	if err != nil {
		return false
	}
	parsed, err := cid.Cast(snapshotCID)
	if err != nil || parsed.Prefix().Codec != cid.Raw {
		return false
	}
	decoded, err := multihash.Decode(parsed.Hash())
	if err != nil || decoded.Code != multihash.SHA2_256 || len(decoded.Digest) != 32 {
		return false
	}
	return hex.EncodeToString(decoded.Digest) == name
}
