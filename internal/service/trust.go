package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

type DeviceKeySource interface {
	LoadDeviceKeys(context.Context, [32]byte, string) (vault.DeviceMaterial, error)
}

type StateTrustSource struct {
	State   *state.Store
	Keyring DeviceKeySource
}

func (source StateTrustSource) Resolve(ctx context.Context, selection VaultSelection) (TrustMaterial, error) {
	if source.State == nil || source.Keyring == nil {
		return TrustMaterial{}, errors.New("trust source state and keyring are required")
	}
	checkpoint, err := source.State.VaultCheckpoint(ctx, selection.Vault)
	if err != nil {
		if errors.Is(err, state.ErrVaultCheckpointNotFound) {
			return TrustMaterial{}, ErrNoCheckpoint
		}
		return TrustMaterial{}, err
	}
	evidence, err := source.State.AuthenticatedPositionEvidence(ctx, checkpoint.Vault, checkpoint.Epoch, checkpoint.PolicyDigest)
	if err != nil && !errors.Is(err, state.ErrAuthenticatedPositionEvidenceNotFound) {
		return TrustMaterial{}, err
	}
	trust := TrustMaterial{Selection: selection, Anchor: checkpoint.Anchor, Checkpoint: checkpoint}
	if err == nil {
		trust.Held = vault.ControlEvidence{Policy: evidence.Policy, Control: evidence.Control, Certificates: evidence.Certificates}
		if err := validateHeldEvidence(trust); err != nil {
			return TrustMaterial{}, fmt.Errorf("%w: local held checkpoint is torn or inconsistent", ErrTrustEvidenceInvalid)
		}
	} else if checkpoint.Epoch == 0 {
		trust.Held.Control = checkpoint.ControlBytes
	} else {
		predecessor, predecessorErr := source.State.AuthenticatedPositionEvidenceAtEpoch(ctx, checkpoint.Vault, checkpoint.Epoch-1)
		if predecessorErr != nil {
			if errors.Is(predecessorErr, state.ErrAuthenticatedPositionEvidenceNotFound) || errors.Is(predecessorErr, state.ErrAuthenticatedPositionEvidenceAmbiguous) {
				return TrustMaterial{}, fmt.Errorf("%w: imported predecessor position", ErrMissingPredecessorEvidence)
			}
			return TrustMaterial{}, predecessorErr
		}
		trust.Held = vault.ControlEvidence{Policy: predecessor.Policy, Control: predecessor.Control, Certificates: predecessor.Certificates}
		trust.ImportedCheckpoint = true
		if err := validateImportedCheckpointPredecessor(trust); err != nil {
			return TrustMaterial{}, fmt.Errorf("%w: imported checkpoint predecessor is invalid", ErrTrustEvidenceInvalid)
		}
	}
	if len(trust.Held.Policy) == 0 && (checkpoint.Epoch != 0 || !bytes.Equal(trust.Held.Control, checkpoint.ControlBytes)) {
		return TrustMaterial{}, fmt.Errorf("%w: local checkpoint is incomplete", ErrTrustEvidenceInvalid)
	}
	if checkpoint.Epoch > 0 && !trust.ImportedCheckpoint {
		policy, err := vault.DecodePolicy(evidence.Policy)
		if err != nil || policy.EpochSeq != checkpoint.Epoch || policy.PrevPolicyDigest == ([32]byte{}) {
			return TrustMaterial{}, fmt.Errorf("%w: held policy predecessor", ErrMissingPredecessorEvidence)
		}
		predecessor, err := source.State.AuthenticatedPositionEvidence(ctx, selection.Vault, checkpoint.Epoch-1, policy.PrevPolicyDigest)
		if err != nil {
			if errors.Is(err, state.ErrAuthenticatedPositionEvidenceNotFound) {
				return TrustMaterial{}, fmt.Errorf("%w: epoch %d", ErrMissingPredecessorEvidence, checkpoint.Epoch-1)
			}
			return TrustMaterial{}, err
		}
		trust.PredecessorPolicy = predecessor.Policy
		trust.PredecessorControl = predecessor.Control
	}
	device, err := source.Keyring.LoadDeviceKeys(ctx, selection.Vault, selection.DeviceID)
	if err != nil {
		return TrustMaterial{}, fmt.Errorf("%w: %w", ErrDeviceKeyMissing, err)
	}
	if device.DeviceID != selection.DeviceID || device.Recipient == nil || len(device.KeyID) == 0 {
		return TrustMaterial{}, fmt.Errorf("%w: stored key item is invalid", ErrDeviceKeyMissing)
	}
	trust.Device = device
	return trust, nil
}

func (coordinator *Coordinator) ResolveSelection(ctx context.Context, requested VaultSelection) (VaultSelection, error) {
	if err := coordinator.lock(ctx); err != nil {
		return VaultSelection{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.selectVault(ctx, requested)
}
