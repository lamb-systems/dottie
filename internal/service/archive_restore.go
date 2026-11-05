package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/lamb-systems/dottie/internal/vault"
)

type ArchiveRestoreRequest struct {
	Selection VaultSelection
	Path      string
	Anchor    [32]byte
	Kit       []byte
	TargetID  string
	Confirm   string
}

func (coordinator *Coordinator) RestoreFromArchive(ctx context.Context, request ArchiveRestoreRequest) (RestoreReport, error) {
	if err := coordinator.lock(ctx); err != nil {
		return RestoreReport{}, err
	}
	defer coordinator.mu.Unlock()
	if request.TargetID == "" {
		return RestoreReport{}, errors.New("target ID is required")
	}
	if request.Anchor == ([32]byte{}) || len(request.Kit) != 32 {
		return RestoreReport{}, fmt.Errorf("%w: expected anchor and 32-byte recovery kit are required", vault.ErrAuthorization)
	}
	selected, err := coordinator.selectVault(ctx, request.Selection)
	if err != nil {
		return RestoreReport{}, err
	}
	file, err := os.Open(request.Path)
	if err != nil {
		return RestoreReport{}, fmt.Errorf("open export archive: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return RestoreReport{}, fmt.Errorf("%w: export archive must be a regular file", vault.ErrIncompleteExport)
	}
	kit := bytes.Clone(request.Kit)
	defer clear(kit)
	archive, err := vault.ReadExportArchive(file, vault.ImportOptions{
		ExpectedVaultID: selected.Vault, ExpectedAnchor: request.Anchor, RecoveryKit: kit,
	})
	if err != nil {
		if errors.Is(err, vault.ErrAuthorization) || errors.Is(err, vault.ErrExportPolicy) {
			return RestoreReport{}, fmt.Errorf("%w: %w", ErrRecoveryKitMismatch, err)
		}
		return RestoreReport{}, err
	}
	checkpoint, position, err := checkpointExportPosition(archive, kit)
	if err != nil {
		return RestoreReport{}, err
	}
	if coordinator.deps.DeviceKeys == nil {
		return RestoreReport{}, ErrDeviceKeyMissing
	}
	device, err := coordinator.deps.DeviceKeys.LoadDeviceKeys(ctx, selected.Vault, selected.DeviceID)
	if err != nil || device.Recipient == nil {
		return RestoreReport{}, ErrDeviceKeyMissing
	}
	if err := validateCheckpointRecipient(position.Policy, selected, device); err != nil {
		return RestoreReport{}, err
	}
	plaintext, err := openCheckpointSnapshot(archive, checkpoint, position, device)
	if err != nil {
		return RestoreReport{}, err
	}
	defer clear(plaintext)
	blob, err := snapshotBlob(plaintext)
	if err != nil {
		return RestoreReport{}, err
	}
	snapshot, err := vault.Unpack(blob)
	if err != nil {
		return RestoreReport{}, err
	}
	if coordinator.deps.Config == nil {
		return RestoreReport{}, errors.New("coordinator config port is required")
	}
	configuration, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return RestoreReport{}, err
	}
	filtered, untracked, err := filterSnapshot(ctx, configuration, coordinator.deps.Settings, snapshot)
	if err != nil {
		return RestoreReport{}, err
	}
	candidate, err := coordinator.buildCandidateLocked(ctx, selected, request.TargetID, configuration, candidatePosition{
		Snapshot: filtered, VerifiedSnapshot: snapshot, Untracked: untracked,
		Epoch: checkpoint.EpochSeq, SnapshotCID: checkpoint.SnapshotCID,
		PolicyDigest: bytes.Clone(checkpoint.PolicyDigest[:]), ControlCID: checkpoint.ControlCID, Archive: true,
	})
	if err != nil {
		return RestoreReport{}, err
	}
	return coordinator.applyCandidateLocked(ctx, candidate, request.Confirm)
}

func checkpointExportPosition(archive vault.ExportArchive, kit []byte) (vault.Checkpoint, vault.ExportPosition, error) {
	kitPublic, err := vault.RecoveryKitSigningPublicKey(kit, archive.VaultID)
	if err != nil {
		return vault.Checkpoint{}, vault.ExportPosition{}, fmt.Errorf("%w: %w", ErrRecoveryKitMismatch, err)
	}
	checkpoint, err := vault.VerifyCheckpoint(archive.Checkpoint, kitPublic)
	if err != nil {
		return vault.Checkpoint{}, vault.ExportPosition{}, fmt.Errorf("%w: %w", ErrRecoveryKitMismatch, err)
	}
	positions := make([]vault.ExportPosition, 0, 1+len(archive.Lineage)+len(archive.RecoveryPoints))
	positions = append(positions, archive.Current)
	positions = append(positions, archive.Lineage...)
	positions = append(positions, archive.RecoveryPoints...)
	for _, position := range positions {
		controlCID := rawVaultCID(position.Control)
		if !bytes.Equal(controlCID, checkpoint.ControlCID) {
			continue
		}
		control, controlErr := vault.DecodeControl(position.Control)
		head, headErr := vault.DecodeHead(position.Head)
		if controlErr != nil || headErr != nil || control.EpochSeq != checkpoint.EpochSeq || control.PolicyDigest != checkpoint.PolicyDigest || !bytes.Equal(control.HeadSnapshotCID, checkpoint.SnapshotCID) || !bytes.Equal(head.SnapshotCID, checkpoint.SnapshotCID) {
			return vault.Checkpoint{}, vault.ExportPosition{}, vault.ErrExportPolicy
		}
		return checkpoint, position, nil
	}
	return vault.Checkpoint{}, vault.ExportPosition{}, vault.ErrExportBlob
}

func validateCheckpointRecipient(encodedPolicy []byte, selection VaultSelection, device vault.DeviceMaterial) error {
	policy, err := vault.DecodePolicy(encodedPolicy)
	if err != nil {
		return err
	}
	if device.DeviceID != selection.DeviceID || len(device.KeyID) == 0 {
		return ErrDeviceKeyMissing
	}
	for _, recipient := range policy.Recipients {
		if recipient.DeviceID == selection.DeviceID && recipient.DeviceID == device.DeviceID && bytes.Equal(recipient.KeyID, device.KeyID) {
			return nil
		}
	}
	return ErrDeviceKeyMissing
}

func openCheckpointSnapshot(archive vault.ExportArchive, checkpoint vault.Checkpoint, position vault.ExportPosition, device vault.DeviceMaterial) ([]byte, error) {
	var snapshot []byte
	for _, blob := range archive.Blobs {
		if bytes.Equal(blob.CID, checkpoint.SnapshotCID) {
			snapshot = blob.Data
			break
		}
	}
	if len(snapshot) == 0 {
		return nil, vault.ErrExportBlob
	}
	envelope, err := vault.DecodeEnvelope(snapshot)
	if err != nil {
		return nil, err
	}
	if envelope.Purpose != vault.PurposeSnapshot {
		return nil, vault.ErrExportPolicy
	}
	return vault.Open(envelope, vault.OpenRequest{
		Vault: archive.VaultID, EpochSeq: checkpoint.EpochSeq, PolicyDigest: checkpoint.PolicyDigest,
		Policy: position.Policy, Control: position.Control, TrustAnchor: archive.Anchor,
		Certificates: position.Certificates, DeviceKeyID: device.KeyID, DeviceKey: device.Recipient,
	})
}
