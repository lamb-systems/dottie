package service

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

type Coordinator struct {
	deps Dependencies
	mu   sync.Mutex
}

func NewCoordinator(deps Dependencies) (*Coordinator, error) {
	if deps.State == nil {
		return nil, errors.New("coordinator state port is required")
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	return &Coordinator{deps: deps}, nil
}

func (coordinator *Coordinator) Status(ctx context.Context) (Status, error) {
	if err := coordinator.lock(ctx); err != nil {
		return Status{}, err
	}
	defer coordinator.mu.Unlock()
	if coordinator.deps.Config == nil {
		return Status{}, errors.New("coordinator config port is required")
	}
	configuration, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return Status{}, err
	}
	selections, err := coordinator.deps.State.VaultSelections(ctx)
	if err != nil {
		return Status{}, err
	}
	journals, err := coordinator.deps.State.JournalEntriesAll(ctx)
	if err != nil {
		return Status{}, err
	}
	latest := make(map[string]TargetStatus, len(configuration.Targets))
	for _, target := range configuration.Targets {
		latest[target.ID] = TargetStatus{
			ID:     target.ID,
			Source: string(target.Source),
			Mode:   target.ModeOrDefault(configuration.Defaults),
			State:  StatusUnknown,
		}
	}
	for _, entry := range journals {
		status, ok := latest[entry.Identity.TargetID]
		if !ok {
			continue
		}
		status.Items++
		switch entry.State {
		case "pending", "indeterminate":
			status.State = StatusPending
			status.Reason = entry.State
		case "applied":
			if status.State != StatusPending {
				status.State = StatusApplied
				status.Reason = "journal-applied"
			}
		case "failed":
			if status.State != StatusPending {
				status.State = StatusUnknown
				status.Reason = "journal-failed"
			}
		case "rolled-back":
			status.State = StatusSkipped
			status.Reason = "rolled-back"
		}
		latest[entry.Identity.TargetID] = status
	}
	result := Status{
		Vaults:  make([]VaultSelection, 0, len(selections)),
		Targets: make([]TargetStatus, 0, len(configuration.Targets)),
	}
	for _, selection := range selections {
		result.Vaults = append(result.Vaults, VaultSelection{Vault: selection.Vault, DeviceID: selection.DeviceID})
	}
	for _, target := range configuration.Targets {
		result.Targets = append(result.Targets, latest[target.ID])
	}
	sort.Slice(result.Targets, func(i, j int) bool { return result.Targets[i].ID < result.Targets[j].ID })
	return result, nil
}

func (coordinator *Coordinator) selectVault(ctx context.Context, requested VaultSelection) (VaultSelection, error) {
	selections, err := coordinator.deps.State.VaultSelections(ctx)
	if err != nil {
		return VaultSelection{}, err
	}
	if requested.Vault != ([32]byte{}) {
		matches := make([]state.VaultSelection, 0, 1)
		for _, selection := range selections {
			if selection.Vault == requested.Vault &&
				(requested.DeviceID == "" || requested.DeviceID == selection.DeviceID) {
				matches = append(matches, selection)
			}
		}
		if len(matches) == 1 {
			return VaultSelection{Vault: matches[0].Vault, DeviceID: matches[0].DeviceID}, nil
		}
		if len(matches) > 1 {
			return VaultSelection{}, ErrAmbiguousVaultSelection
		}
		return VaultSelection{}, ErrNoVaultSelection
	}
	if len(selections) == 0 {
		return VaultSelection{}, ErrNoVaultSelection
	}
	if len(selections) != 1 {
		return VaultSelection{}, ErrAmbiguousVaultSelection
	}
	return VaultSelection{Vault: selections[0].Vault, DeviceID: selections[0].DeviceID}, nil
}

func (coordinator *Coordinator) ResolveSelection(
	ctx context.Context,
	requested VaultSelection,
) (VaultSelection, error) {
	if err := coordinator.lock(ctx); err != nil {
		return VaultSelection{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.selectVault(ctx, requested)
}

func (coordinator *Coordinator) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	coordinator.mu.Lock()
	if err := ctx.Err(); err != nil {
		coordinator.mu.Unlock()
		return err
	}
	return nil
}

func snapshotBlob(plaintext []byte) (vault.Blob, error) {
	reader := tar.NewReader(bytes.NewReader(plaintext))
	header, err := reader.Next()
	if err != nil || header.Name != "000000" || header.Size < 0 || header.Size > 16<<20 {
		return vault.Blob{}, errors.New("authenticated snapshot manifest is unavailable or exceeds its limit")
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
	if err != nil || int64(len(manifestBytes)) != header.Size {
		return vault.Blob{}, errors.New("authenticated snapshot manifest is truncated")
	}
	var manifest struct {
		Entries []struct {
			Source string `json:"source"`
			State  string `json:"state"`
			Kind   string `json:"kind"`
			Size   int64  `json:"size"`
		} `json:"entries"`
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	if err := decoder.Decode(&manifest); err != nil {
		return vault.Blob{}, errors.New("authenticated snapshot manifest cannot be inspected")
	}
	var plaintextBytes int64
	for _, entry := range manifest.Entries {
		if entry.Source == string(model.SourceFiles) && entry.State == string(model.FilePresent) &&
			entry.Kind == string(model.FileRegular) {
			if entry.Size < 0 || plaintextBytes > vault.DefaultLimits().MaxTotalBytes-entry.Size {
				return vault.Blob{}, errors.New("authenticated snapshot exceeds its plaintext limit")
			}
			plaintextBytes += entry.Size
		}
	}
	return vault.Blob{
		Version:        vault.Version,
		Codec:          vault.CodecNone,
		Payload:        bytes.Clone(plaintext),
		Digest:         sha256.Sum256(plaintext),
		EntryCount:     len(manifest.Entries),
		PlaintextBytes: plaintextBytes,
	}, nil
}

func filterSnapshot(
	ctx context.Context,
	configuration config.Config,
	settings SettingsPort,
	snapshot model.Snapshot,
) (model.Snapshot, []model.EntryKey, error) {
	configured := make(map[string]config.Target, len(configuration.Targets))
	approved := make(map[string]map[model.EntryKey]struct{})
	for _, target := range configuration.Targets {
		configured[target.ID] = target
		if target.Source != model.SourceGNOME {
			continue
		}
		if settings == nil {
			return model.Snapshot{}, nil, errors.New("GNOME settings source is unavailable")
		}
		refs, err := approvedSettings(ctx, settings, target)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		approved[target.ID] = make(map[model.EntryKey]struct{}, len(refs))
		for _, ref := range refs {
			approved[target.ID][model.EntryKey{TargetID: target.ID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}] = struct{}{}
		}
	}
	untracked := make([]model.EntryKey, 0)
	entries := make([]model.Entry, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		target, exists := configured[entry.TargetID]
		if !exists || target.Source != entry.Identity().Source {
			untracked = append(untracked, entry.Identity())
			continue
		}
		if entry.Setting != nil {
			if _, ok := approved[entry.TargetID][entry.Identity()]; !ok {
				untracked = append(untracked, entry.Identity())
				continue
			}
		}
		entries = append(entries, entry)
	}
	snapshot.Entries = entries
	return snapshot, untracked, nil
}

func approvedSettings(ctx context.Context, settings SettingsPort, target config.Target) ([]SettingRef, error) {
	policy := target.GNOMEPolicy
	if policy == nil || policy.Approval != config.GNOMEApprovalApproved {
		return nil, fmt.Errorf("%w: target %q has pending category approval", ErrGNOMEReapproval, target.ID)
	}
	if policy.MatrixVersion != matrix.Version {
		return nil, fmt.Errorf("%w: target %q matrix version changed", ErrGNOMEReapproval, target.ID)
	}
	keys, err := matrix.SelectCategories(policy.Categories)
	if err != nil {
		return nil, fmt.Errorf("%w: target %q categories are invalid", ErrGNOMEReapproval, target.ID)
	}
	digest, err := matrix.KeySetDigest(keys)
	if err != nil || hex.EncodeToString(digest[:]) != policy.KeyDigest {
		return nil, fmt.Errorf(
			"%w: target %q key digest does not match stored categories",
			ErrGNOMEReapproval,
			target.ID,
		)
	}
	refs := make([]SettingRef, 0, len(keys))
	for _, key := range keys {
		path, err := settings.Resolve(ctx, target.ID, key.SchemaID, key.Path)
		if err != nil || path == "" {
			return nil, fmt.Errorf("%w: target %q schema path could not be resolved", ErrGNOMEReapproval, target.ID)
		}
		refs = append(refs, SettingRef{SchemaID: key.SchemaID, Path: path, Key: key.Key})
	}
	return refs, nil
}

func targetFromConfig(target config.Target) (model.Target, error) {
	return target.Model()
}
