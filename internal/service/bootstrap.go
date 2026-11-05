package service

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

type BootstrapOutcome string

const (
	BootstrapVerifiedCommit    BootstrapOutcome = "verified-commit"
	BootstrapPrecommitFailure  BootstrapOutcome = "precommit-failure"
	BootstrapVerifiedAbsence   BootstrapOutcome = "verified-absence"
	BootstrapUnresolved        BootstrapOutcome = "unresolved"
	BootstrapFinalizationError BootstrapOutcome = "finalization-failure"
)

type BootstrapRequest struct {
	VaultName  string
	Kit        []byte
	Device     vault.DeviceMaterial
	DeliverKit func(vault.BootstrapResult, []byte) error
}

type BootstrapResult struct {
	Outcome       BootstrapOutcome
	Bootstrap     vault.BootstrapResult
	Genesis       atproto.GenesisCommitResult
	RecordTargets []atproto.GenesisRecordTarget
}

type FinalizeResult struct {
	Selection          VaultSelection
	Checkpoint         state.VaultCheckpoint
	CheckpointPosition []byte
	NoOp               bool
}

type vaultDeviceKeyLister interface {
	LoadDeviceKeysForVault(context.Context, [32]byte) ([]vault.DeviceMaterial, error)
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
	if coordinator.deps.Genesis == nil {
		return errors.New("genesis coordinator port is unavailable")
	}
	return coordinator.deps.Genesis.Preflight(ctx)
}

func (coordinator *Coordinator) InitializeVault(ctx context.Context, request BootstrapRequest) (BootstrapResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return BootstrapResult{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.initializeVaultLocked(ctx, request)
}

func (coordinator *Coordinator) initializeVaultLocked(ctx context.Context, request BootstrapRequest) (BootstrapResult, error) {
	if coordinator.deps.Genesis == nil || coordinator.deps.State == nil {
		return BootstrapResult{}, errors.New("genesis coordinator ports are unavailable")
	}
	keyStore, ok := coordinator.deps.DeviceKeys.(bootstrapDeviceKeyStore)
	if !ok {
		return BootstrapResult{}, errors.New("device key store does not support bootstrap custody")
	}
	if len(request.Kit) != 32 || request.DeliverKit == nil {
		return BootstrapResult{}, errors.New("bootstrap kit and delivery are required")
	}
	boot, err := vault.Bootstrap(request.Kit, request.VaultName, request.Device)
	if err != nil {
		return BootstrapResult{}, err
	}
	if _, err := keyStore.LoadDeviceKeys(ctx, boot.Vault, request.Device.DeviceID); err == nil {
		return BootstrapResult{}, errors.New("device keys already exist for this vault and device")
	} else if !errors.Is(err, platform.ErrKeyringItemNotFound) {
		return BootstrapResult{}, fmt.Errorf("load existing device keys: %w", err)
	}
	if err := keyStore.StoreDeviceKeys(ctx, boot.Vault, request.Device); err != nil {
		_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
		return BootstrapResult{}, fmt.Errorf("store device keys before bootstrap: %w", err)
	}
	result := BootstrapResult{Bootstrap: boot}
	if err := request.DeliverKit(boot, request.Kit); err != nil {
		_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
		result.Outcome = BootstrapPrecommitFailure
		return result, fmt.Errorf("%w: %w", ErrBootstrapKitDeliveryFailed, err)
	}
	blobLimit, err := coordinator.deps.Genesis.BlobUploadLimit(ctx)
	if err != nil || blobLimit <= 0 {
		_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
		result.Outcome = BootstrapPrecommitFailure
		if err == nil {
			err = errors.New("provider did not advertise a usable blob upload limit")
		}
		return result, fmt.Errorf("cannot determine provider blob upload limit: %w", err)
	}
	genesis, err := composeBootstrapGenesis(request.Kit, request.VaultName, request.Device)
	if err != nil {
		_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
		result.Outcome = BootstrapPrecommitFailure
		return result, err
	}
	defer clear(genesis.Snapshot)
	commit, commitErr := coordinator.deps.Genesis.CommitGenesis(ctx, blobLimit, request.Kit, request.Device, genesis)
	result.Genesis = commit
	result.RecordTargets = append([]atproto.GenesisRecordTarget(nil), commit.RecordTargets...)
	if commitErr != nil || commit.Phase != atproto.GenesisVerified {
		switch {
		case errors.Is(commitErr, atproto.ErrBatchRejected), errors.Is(commitErr, atproto.ErrGenesisRepositoryNotEmpty), commit.Phase == atproto.GenesisNotSubmitted:
			result.Outcome = BootstrapPrecommitFailure
			_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
			if commitErr == nil {
				commitErr = errors.New("genesis port did not submit a publication")
			}
		case errors.Is(commitErr, atproto.ErrGenesisNotLanded) && commit.Phase == atproto.GenesisSubmitted:
			result.Outcome = BootstrapVerifiedAbsence
			_ = keyStore.DeleteDeviceKeys(ctx, boot.Vault, request.Device.DeviceID)
		default:
			result.Outcome = BootstrapUnresolved
			if commitErr == nil {
				commitErr = errors.New("genesis publication was not fully verified")
			}
		}
		return result, commitErr
	}
	if commit.ReadResult.Revision == nil || len(commit.RecordTargets) != 6 {
		result.Outcome = BootstrapUnresolved
		return result, errors.New("genesis port returned incomplete verified evidence")
	}
	checkpoint := state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: append([]byte(nil), genesis.ControlCID...),
		ControlBytes: append([]byte(nil), genesis.Control...), SnapshotCID: append([]byte(nil), genesis.SnapshotCID...),
		Epoch: 0, PolicyDigest: genesis.PolicyDigest, RecordedAt: coordinator.deps.Clock().Unix(),
	}
	evidence := state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest, Policy: append([]byte(nil), genesis.Policy...),
		Control: append([]byte(nil), genesis.Control...), Head: append([]byte(nil), genesis.Head...),
		Certificates: [][]byte{append([]byte(nil), genesis.Certificate...)}, CheckpointPosition: append([]byte(nil), genesis.Checkpoint...),
	}
	if err := coordinator.deps.State.InitializeVaultTrust(ctx, state.VaultSelection{
		Vault: genesis.Vault, DeviceID: request.Device.DeviceID, RecordedAt: checkpoint.RecordedAt,
	}, checkpoint, evidence); err != nil {
		result.Outcome = BootstrapFinalizationError
		return result, fmt.Errorf("%w: %w", ErrBootstrapTrustFinalizationFailed, err)
	}
	result.Outcome = BootstrapVerifiedCommit
	return result, nil
}

func (coordinator *Coordinator) FinalizeVaultTrust(ctx context.Context, vaultID [32]byte) (FinalizeResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return FinalizeResult{}, err
	}
	defer coordinator.mu.Unlock()
	if vaultID == ([32]byte{}) || coordinator.deps.State == nil || coordinator.deps.Session == nil || coordinator.deps.Remote == nil {
		return FinalizeResult{}, errors.New("vault finalization coordinator ports are unavailable")
	}
	selections, err := coordinator.deps.State.VaultSelections(ctx)
	if err != nil {
		return FinalizeResult{}, err
	}
	var selection *state.VaultSelection
	for index := range selections {
		if selections[index].Vault != vaultID {
			continue
		}
		if selection != nil {
			return FinalizeResult{}, ErrFinalizeStateIncomplete
		}
		copySelection := selections[index]
		selection = &copySelection
	}
	checkpoint, checkpointErr := coordinator.deps.State.VaultCheckpoint(ctx, vaultID)
	if checkpointErr != nil && !errors.Is(checkpointErr, state.ErrVaultCheckpointNotFound) {
		return FinalizeResult{}, checkpointErr
	}
	if selection != nil || checkpointErr == nil {
		if selection == nil || checkpointErr != nil || checkpoint.Vault != vaultID || coordinator.deps.Trust == nil {
			return FinalizeResult{}, ErrFinalizeStateIncomplete
		}
		selected := VaultSelection{Vault: vaultID, DeviceID: selection.DeviceID}
		trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
		if errors.Is(err, ErrDeviceKeyMissing) {
			return FinalizeResult{}, ErrFinalizeKeysMissing
		}
		if err != nil {
			return FinalizeResult{}, err
		}
		read, err := coordinator.readForFinalize(ctx, selected, trust)
		if err != nil {
			return FinalizeResult{}, err
		}
		if read.EpochSeq != checkpoint.Epoch || read.Policy.EpochSeq != checkpoint.Epoch ||
			!bytes.Equal(read.ControlCID, checkpoint.ControlCID) || !bytes.Equal(read.HeadCID, checkpoint.SnapshotCID) ||
			!bytes.Equal(read.Control.PolicyDigest, checkpoint.PolicyDigest[:]) || !bytes.Equal(read.Head.PolicyDigest, checkpoint.PolicyDigest[:]) {
			return FinalizeResult{}, ErrFinalizeStateConflict
		}
		remoteCheckpoint, remoteEvidence, err := atproto.TrustMaterialFromVerifiedRead(read, trust.Anchor)
		if err != nil {
			return FinalizeResult{}, err
		}
		localEvidence, err := coordinator.deps.State.AuthenticatedPositionEvidence(ctx, vaultID, checkpoint.Epoch, checkpoint.PolicyDigest)
		if err != nil || !sameFinalizeCheckpoint(checkpoint, remoteCheckpoint) || !sameFinalizePosition(localEvidence, remoteEvidence) {
			return FinalizeResult{}, ErrFinalizeStateConflict
		}
		return FinalizeResult{
			Selection: selected, Checkpoint: checkpoint, CheckpointPosition: bytes.Clone(localEvidence.CheckpointPosition), NoOp: true,
		}, nil
	}
	keyLister, ok := coordinator.deps.DeviceKeys.(vaultDeviceKeyLister)
	if !ok {
		return FinalizeResult{}, ErrFinalizeKeysMissing
	}
	devices, err := keyLister.LoadDeviceKeysForVault(ctx, vaultID)
	if err != nil {
		if errors.Is(err, platform.ErrKeyringItemNotFound) {
			return FinalizeResult{}, ErrFinalizeKeysMissing
		}
		return FinalizeResult{}, fmt.Errorf("load device keys for vault finalization: %w", err)
	}
	var lastReadErr error
	for _, device := range devices {
		if device.DeviceID == "" || len(device.Signing) != ed25519.PrivateKeySize || device.Recipient == nil || len(device.KeyID) == 0 {
			continue
		}
		publicKey, ok := device.Signing.Public().(ed25519.PublicKey)
		if !ok {
			continue
		}
		anchor := sha256.Sum256(publicKey)
		selected := VaultSelection{Vault: vaultID, DeviceID: device.DeviceID}
		request, requestErr := coordinator.deps.Session.ReadRequest(ctx, selected, device, anchor, nil, nil)
		if requestErr != nil {
			lastReadErr = requestErr
			continue
		}
		request.Vault = vaultID
		request.TrustAnchor = anchor
		request.DeviceKeyID = bytes.Clone(device.KeyID)
		request.DeviceKey = device.Recipient
		read, readErr := coordinator.deps.Remote.Read(ctx, request)
		if readErr != nil {
			lastReadErr = readErr
			continue
		}
		remoteCheckpoint, evidence, evidenceErr := atproto.TrustMaterialFromVerifiedRead(read, anchor)
		if evidenceErr != nil {
			lastReadErr = evidenceErr
			continue
		}
		if remoteCheckpoint.Vault != vaultID {
			lastReadErr = ErrOnboardingVaultMismatch
			continue
		}
		remoteCheckpoint.RecordedAt = coordinator.deps.Clock().Unix()
		if err := coordinator.deps.State.InitializeVaultTrust(ctx, state.VaultSelection{
			Vault: vaultID, DeviceID: device.DeviceID, RecordedAt: remoteCheckpoint.RecordedAt,
		}, remoteCheckpoint, evidence); err != nil {
			return FinalizeResult{}, fmt.Errorf("record verified vault trust atomically: %w", err)
		}
		return FinalizeResult{
			Selection: selected, Checkpoint: remoteCheckpoint, CheckpointPosition: bytes.Clone(evidence.CheckpointPosition),
		}, nil
	}
	if lastReadErr != nil {
		return FinalizeResult{}, fmt.Errorf("verified remote genesis could not be read for finalization: %w", lastReadErr)
	}
	return FinalizeResult{}, ErrFinalizeKeysMissing
}

func (coordinator *Coordinator) readForFinalize(ctx context.Context, selection VaultSelection, trust TrustMaterial) (atproto.ReadResult, error) {
	if coordinator.deps.Session == nil || coordinator.deps.Remote == nil {
		return atproto.ReadResult{}, errors.New("verified read ports are unavailable")
	}
	var predecessorPolicy, predecessorControl []byte
	var err error
	if trust.ImportedCheckpoint {
		predecessorPolicy, predecessorControl, err = encodePositionRecords(trust.Held.Policy, trust.Held.Control)
	} else {
		predecessorPolicy, predecessorControl, err = encodePredecessorRecords(trust)
	}
	if err != nil {
		return atproto.ReadResult{}, err
	}
	pairs := [][2][]byte{{predecessorPolicy, predecessorControl}}
	if len(trust.Held.Policy) != 0 {
		heldPolicy, heldControl, encodeErr := encodePositionRecords(trust.Held.Policy, trust.Held.Control)
		if encodeErr != nil {
			return atproto.ReadResult{}, encodeErr
		}
		if !bytes.Equal(heldPolicy, predecessorPolicy) || !bytes.Equal(heldControl, predecessorControl) {
			pairs = append(pairs, [2][]byte{heldPolicy, heldControl})
		}
	}
	var lastErr error
	for _, pair := range pairs {
		request, requestErr := coordinator.deps.Session.ReadRequest(ctx, selection, trust.Device, trust.Anchor, pair[0], pair[1])
		if requestErr != nil {
			lastErr = requestErr
			continue
		}
		request.Vault = selection.Vault
		request.TrustAnchor = trust.Anchor
		request.DeviceKeyID = bytes.Clone(trust.Device.KeyID)
		request.DeviceKey = trust.Device.Recipient
		request.PreviousPolicy = bytes.Clone(pair[0])
		request.PreviousControl = bytes.Clone(pair[1])
		read, readErr := coordinator.deps.Remote.Read(ctx, request)
		if readErr == nil {
			return read, nil
		}
		lastErr = readErr
	}
	return atproto.ReadResult{}, lastErr
}

func sameFinalizeCheckpoint(local, remote state.VaultCheckpoint) bool {
	return local.Vault == remote.Vault && local.Anchor == remote.Anchor && local.Epoch == remote.Epoch &&
		local.PolicyDigest == remote.PolicyDigest && bytes.Equal(local.ControlCID, remote.ControlCID) &&
		bytes.Equal(local.ControlBytes, remote.ControlBytes) && bytes.Equal(local.SnapshotCID, remote.SnapshotCID)
}

func sameFinalizePosition(local, remote state.AuthenticatedPositionEvidence) bool {
	if local.Vault != remote.Vault || local.Epoch != remote.Epoch || local.PolicyDigest != remote.PolicyDigest ||
		!bytes.Equal(local.Policy, remote.Policy) || !bytes.Equal(local.Control, remote.Control) ||
		!bytes.Equal(local.Head, remote.Head) || !bytes.Equal(local.CheckpointPosition, remote.CheckpointPosition) ||
		len(local.Certificates) != len(remote.Certificates) {
		return false
	}
	for index := range local.Certificates {
		if !bytes.Equal(local.Certificates[index], remote.Certificates[index]) {
			return false
		}
	}
	return true
}

func composeBootstrapGenesis(kit []byte, vaultName string, device vault.DeviceMaterial) (vault.Genesis, error) {
	contentKey := make([]byte, 32)
	defer clear(contentKey)
	if _, err := rand.Read(contentKey); err != nil {
		return vault.Genesis{}, fmt.Errorf("generate genesis content key: %w", err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return vault.Genesis{}, fmt.Errorf("generate genesis recipient wrap key: %w", err)
	}
	var wrap vault.RecipientWrapInput
	wrap.KeyID = append([]byte(nil), device.KeyID...)
	copy(wrap.EphemeralPrivate[:], ephemeral.Bytes())
	defer clear(wrap.EphemeralPrivate[:])
	if _, err := rand.Read(wrap.WrapNonce[:]); err != nil {
		return vault.Genesis{}, fmt.Errorf("generate genesis recipient wrap nonce: %w", err)
	}
	var publicationID [16]byte
	var nonce [24]byte
	if _, err := rand.Read(publicationID[:]); err != nil {
		return vault.Genesis{}, fmt.Errorf("generate genesis publication identity: %w", err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return vault.Genesis{}, fmt.Errorf("generate genesis publication nonce: %w", err)
	}
	defer clear(nonce[:])
	return vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: vaultName, RootDevice: device, ContentKey: contentKey,
		Wraps: []vault.RecipientWrapInput{wrap}, PublicationID: publicationID, Nonce: nonce,
	})
}
