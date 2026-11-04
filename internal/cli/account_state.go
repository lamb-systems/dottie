package cli

import (
	"context"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/state"
)

func recordVaultSelection(ctx context.Context, env func(string) string, vaultID [32]byte, deviceID string) error {
	paths, err := platform.Resolve(env)
	if err != nil {
		return err
	}
	store, err := state.Open(paths)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.PutVaultSelection(ctx, state.VaultSelection{Vault: vaultID, DeviceID: deviceID, RecordedAt: time.Now().Unix()})
}
