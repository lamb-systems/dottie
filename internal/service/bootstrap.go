package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

type BootstrapOutcome string

const (
	BootstrapLocalIdentityRecorded BootstrapOutcome = "local-identity-recorded"
	BootstrapNotRecorded           BootstrapOutcome = "not-recorded"
)

type BootstrapRequest struct {
	VaultName string
	Device    vault.DeviceMaterial
}

type BootstrapResult struct {
	Outcome   BootstrapOutcome
	Bootstrap vault.BootstrapResult
}

type bootstrapDeviceKeyStore interface {
	DeviceKeySource
	StoreDeviceKeys(context.Context, [32]byte, vault.DeviceMaterial) error
	DeleteDeviceKeys(context.Context, [32]byte, string) error
}

func (coordinator *Coordinator) PreflightVault(ctx context.Context) error {
	if err := coordinator.lock(ctx); err != nil {
		return err
	}
	defer coordinator.mu.Unlock()
	if coordinator.deps.GenesisPreflight == nil {
		return errors.New("genesis preflight port is unavailable")
	}
	return coordinator.deps.GenesisPreflight.Preflight(ctx)
}

func (coordinator *Coordinator) InitializeVault(ctx context.Context, request BootstrapRequest) (BootstrapResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return BootstrapResult{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.initializeVaultLocked(ctx, request)
}

func (coordinator *Coordinator) initializeVaultLocked(ctx context.Context, request BootstrapRequest) (BootstrapResult, error) {
	if coordinator.deps.State == nil {
		return BootstrapResult{}, errors.New("bootstrap coordinator state port is unavailable")
	}
	keyStore, ok := coordinator.deps.DeviceKeys.(bootstrapDeviceKeyStore)
	if !ok {
		return BootstrapResult{}, errors.New("device key store does not support bootstrap custody")
	}
	if request.VaultName == "" {
		return BootstrapResult{}, errors.New("bootstrap vault name is required")
	}
	boot, err := vault.Bootstrap(request.VaultName, request.Device)
	if err != nil {
		return BootstrapResult{}, err
	}
	result := BootstrapResult{Outcome: BootstrapNotRecorded, Bootstrap: boot}
	if _, err := keyStore.LoadDeviceKeys(ctx, boot.Vault, request.Device.DeviceID); err == nil {
		return result, errors.New("device keys already exist for this vault and device")
	} else if !errors.Is(err, platform.ErrKeyringItemNotFound) {
		return result, fmt.Errorf("load existing device keys: %w", err)
	}
	if err := keyStore.StoreDeviceKeys(ctx, boot.Vault, request.Device); err != nil {
		_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
		return result, fmt.Errorf("store device keys before bootstrap: %w", err)
	}
	if err := coordinator.deps.State.PutVaultSelection(ctx, state.VaultSelection{
		Vault: boot.Vault, DeviceID: request.Device.DeviceID, RecordedAt: coordinator.deps.Clock().Unix(),
	}); err != nil {
		_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
		return result, fmt.Errorf("record the local vault selection: %w", err)
	}
	result.Outcome = BootstrapLocalIdentityRecorded
	return result, nil
}
