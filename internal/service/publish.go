package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
)

var ErrPushBlocked = errors.New("push refused because reconciliation has unresolved entries")

type PushBlockedError struct {
	Identities []model.EntryKey
}

func (e *PushBlockedError) Error() string {
	return fmt.Sprintf("%v: %s", ErrPushBlocked, formatEntryIdentities(e.Identities))
}

func (e *PushBlockedError) Unwrap() error { return ErrPushBlocked }

type PushResult struct {
	Status              StatusState
	PublicationStatus   atproto.PublicationRetryStatus
	NoOp                bool
	BaseRecordingFailed bool
	PublicationCount    uint64
	HeadCID             []byte
	Retention           RetentionReport
}

type pushTargetPlan struct {
	target config.Target
}

func (coordinator *Coordinator) Push(ctx context.Context, selection VaultSelection) (PushResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return PushResult{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.pushLocked(ctx, selection)
}

func (coordinator *Coordinator) Publish(ctx context.Context, selection VaultSelection) (PushResult, error) {
	return coordinator.Push(ctx, selection)
}

func (coordinator *Coordinator) pushLocked(ctx context.Context, requested VaultSelection) (PushResult, error) {
	selected, err := coordinator.selectVault(ctx, requested)
	if err != nil {
		return PushResult{}, err
	}
	if coordinator.deps.Trust == nil {
		return PushResult{}, errors.New("read coordinator ports are unavailable")
	}
	trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
	if err != nil {
		return PushResult{}, err
	}
	pulled, err := coordinator.pullLockedWithTrust(ctx, selected, &trust)
	if err != nil {
		return PushResult{}, err
	}
	if pulled.Currency.Outcome != vault.CheckpointCurrent && pulled.Currency.Outcome != vault.CheckpointDescendant {
		return PushResult{}, ErrCheckpointNotCurrent
	}
	if pulled.InspectOnly {
		return PushResult{}, ErrCheckpointNotCurrent
	}
	configuration, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return PushResult{}, err
	}
	if err := configuration.Validate(); err != nil {
		return PushResult{}, err
	}
	candidate, targetPlans, err := coordinator.pushCandidate(ctx, configuration, pulled)
	if err != nil {
		var blocked *PushBlockedError
		if errors.As(err, &blocked) {
			return PushResult{Status: StatusConflicted}, err
		}
		return PushResult{}, err
	}
	packed, err := vault.Pack(candidate)
	if err != nil {
		return PushResult{}, err
	}
	remotePacked, err := vault.Pack(pulled.VerifiedSnapshot)
	if err != nil {
		return PushResult{}, fmt.Errorf("pack verified remote snapshot: %w", err)
	}
	if bytes.Equal(packed.Payload, remotePacked.Payload) {
		return PushResult{Status: StatusNoOp, NoOp: true, PublicationCount: pulled.Read.PublicationCount, HeadCID: bytes.Clone(pulled.Read.HeadCID)}, nil
	}
	if coordinator.deps.Publisher == nil {
		return PushResult{}, errors.New("publication coordinator port is unavailable")
	}
	if trust.Selection.Vault != selected.Vault || trust.Selection.DeviceID != selected.DeviceID || trust.Device.DeviceID != selected.DeviceID {
		return PushResult{}, ErrDeviceKeyMissing
	}

	predecessor, err := publicationPredecessor(pulled.Read, trust.Anchor)
	if err != nil {
		return PushResult{}, err
	}
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil {
		return PushResult{}, err
	}
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		return PushResult{}, fmt.Errorf("generate publication content key: %w", err)
	}
	defer clear(contentKey)
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PushResult{}, fmt.Errorf("generate publication nonce: %w", err)
	}
	wraps, err := freshRecipientWraps(policy)
	if err != nil {
		clear(nonce[:])
		return PushResult{}, err
	}
	defer clearRecipientWraps(wraps)
	var publicationID [16]byte
	if _, err := rand.Read(publicationID[:]); err != nil {
		clear(nonce[:])
		return PushResult{}, fmt.Errorf("generate publication identity: %w", err)
	}
	intent := vault.PublicationIntent{
		Vault: trust.Selection.Vault, Signer: trust.Device, ContentKey: contentKey, Wraps: wraps,
		Plaintext: packed.Payload, PublicationID: publicationID, Nonce: nonce,
		EpochFirstSeen: coordinator.deps.State, Clock: coordinator.deps.Clock,
	}
	publication, err := vault.PreparePublication(predecessor, intent)
	clear(intent.ContentKey)
	clear(intent.Nonce[:])
	clearRecipientWraps(intent.Wraps)
	clear(nonce[:])
	clear(publicationID[:])
	if err != nil {
		return PushResult{}, err
	}
	publicationIO, err := coordinator.deps.Publisher.PublicationIO(ctx, selected, trust, pulled)
	if err != nil {
		return PushResult{}, err
	}
	if publicationIO.Transport == nil || publicationIO.DID == "" {
		return PushResult{}, errors.New("publication I/O transport and account DID are required")
	}
	if publicationIO.Reader.Transport == nil {
		publicationIO.Reader.Transport = publicationIO.Transport
	}
	publicationIO.TrustAnchor = trust.Anchor
	publicationIO.ObservationStore = coordinator.deps.State
	publicationIO.Clock = coordinator.deps.Clock
	publicationIO.PreviousPolicies = nil
	publicationIO.PreviousControls = nil
	previousPolicy, previousControl, err := coordinator.publicationPredecessorRecords(ctx, selected.Vault, trust, pulled.Read)
	if err != nil {
		return PushResult{}, err
	}
	if len(previousPolicy) != 0 {
		publicationIO.PreviousPolicies = [][]byte{previousPolicy}
		publicationIO.PreviousControls = [][]byte{previousControl}
	}
	publicationResult, publishErr := atproto.PublishWithRetry(ctx, publication, trust.Device.Signing, atproto.PublicationRetryOptions{
		IO: publicationIO, Store: coordinator.deps.State, Clock: coordinator.deps.Clock,
	})
	result := PushResult{
		PublicationStatus: publicationResult.Status, Status: pushStatus(publicationResult.Status),
		NoOp: publicationResult.NoOp,
	}
	if publishErr != nil || publicationResult.Status != atproto.PublicationCommitted {
		return result, publishErr
	}
	if publicationResult.NoOp {
		result.Status = StatusNoOp
		result.NoOp = true
		return result, nil
	}
	readBack, err := coordinator.pullLocked(ctx, selected)
	if err != nil {
		result.Status = StatusUnavailable
		return result, fmt.Errorf("verify committed publication read-back: %w", err)
	}
	result.PublicationCount = readBack.Read.PublicationCount
	result.HeadCID = bytes.Clone(readBack.Read.HeadCID)
	result.Retention = readBack.Retention
	if !bytes.Equal(readBack.Read.HeadCID, publication.SnapshotCID) || !snapshotsEqual(candidate, readBack.VerifiedSnapshot) {
		result.Status = StatusSuperseded
		return result, atproto.ErrPublicationSuperseded
	}
	if err := coordinator.recordPushedBases(ctx, targetPlans, candidate); err != nil {
		result.Status = StatusBaseRecordingFailed
		result.BaseRecordingFailed = true
		return result, fmt.Errorf("%w: %w", ErrBaseRecordingFailed, err)
	}
	result.Status = StatusCommitted
	return result, nil
}

func (coordinator *Coordinator) pushCandidate(ctx context.Context, configuration config.Config, pulled ReadOutcome) (model.Snapshot, []pushTargetPlan, error) {
	candidate := model.Snapshot{Version: model.SnapshotVersion, Targets: make([]model.Target, 0, len(configuration.Targets))}
	plans := make([]pushTargetPlan, 0, len(configuration.Targets))
	blocked := append([]model.EntryKey(nil), pulled.Untracked...)
	for _, target := range configuration.Targets {
		portable, err := targetFromConfig(target)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		candidate.Targets = append(candidate.Targets, portable)
		_, localEntries, unknown, untracked, coverage, err := coordinator.captureLocal(ctx, target)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		baseEntries, baseStatus, baseUntracked, err := coordinator.loadBase(ctx, target, portable, configuration)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		untracked = append(untracked, baseUntracked...)
		for _, identity := range pulled.Untracked {
			if identity.TargetID == target.ID {
				untracked = append(untracked, identity)
			}
		}
		binding, err := syncengine.NewTargetBinding(portable)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		remoteEntries := make([]model.Entry, 0)
		for _, entry := range pulled.Snapshot.Entries {
			if entry.TargetID == target.ID {
				remoteEntries = append(remoteEntries, entry)
			}
		}
		plan, err := syncengine.Reconcile(syncengine.BaseView{Entries: baseEntries, Status: baseStatus},
			syncengine.LocalView{Entries: localEntries, Unknown: unknown, Untracked: untracked, Coverage: coverage},
			remoteEntries, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		plans = append(plans, pushTargetPlan{target: target})
		for _, decision := range plan.Decisions {
			switch decision.Action {
			case syncengine.ActionConflict, syncengine.ActionBlocked:
				blocked = append(blocked, decision.Key)
			case syncengine.ActionUpload, syncengine.ActionUnchanged:
				if decision.Local != nil && !entryIsFileTombstone(*decision.Local) {
					candidate.Entries = append(candidate.Entries, *decision.Local)
				}
			case syncengine.ActionDownload:
				if decision.Remote != nil && !entryIsFileTombstone(*decision.Remote) {
					candidate.Entries = append(candidate.Entries, *decision.Remote)
				}
			case syncengine.ActionDeleteLocal, syncengine.ActionDeleteRemote:
			default:
				return model.Snapshot{}, nil, errors.New("reconciliation produced an unsupported push action")
			}
		}
	}
	if len(blocked) != 0 {
		return model.Snapshot{}, nil, newPushBlockedError(blocked)
	}
	if err := candidate.Validate(); err != nil {
		return model.Snapshot{}, nil, fmt.Errorf("validate publication snapshot: %w", err)
	}
	return candidate, plans, nil
}

func (coordinator *Coordinator) recordPushedBases(ctx context.Context, plans []pushTargetPlan, candidate model.Snapshot) error {
	for _, targetPlan := range plans {
		entries := make([]model.Entry, 0)
		present := make(map[model.EntryKey]struct{})
		for _, entry := range candidate.Entries {
			if entry.TargetID == targetPlan.target.ID {
				entries = append(entries, entry)
				present[entry.Identity()] = struct{}{}
			}
		}
		oldBases, err := coordinator.deps.State.AppliedBase(ctx, targetPlan.target.ID)
		if err != nil {
			return err
		}
		for _, old := range oldBases {
			if _, exists := present[old.Identity]; exists || old.Identity.Source != model.SourceFiles {
				continue
			}
			entries = append(entries, model.Entry{TargetID: targetPlan.target.ID, File: &model.FileEntry{Path: old.Identity.FilePath, State: model.FileDeleted}})
		}
		if err := coordinator.recordBaseLocked(ctx, targetPlan.target.ID, entries); err != nil {
			return err
		}
	}
	return nil
}

func (coordinator *Coordinator) publicationPredecessorRecords(ctx context.Context, vaultID [32]byte, trust TrustMaterial, read atproto.ReadResult) ([]byte, []byte, error) {
	currentPolicy := policyObject(read.Policy)
	currentControl := controlObject(read.Control)
	if currentPolicy.EpochSeq == 0 && currentPolicy.PrevPolicyDigest == ([32]byte{}) && len(currentControl.PrevControlCID) == 0 {
		return nil, nil, nil
	}
	var evidence state.AuthenticatedPositionEvidence
	for _, candidate := range []vault.ControlEvidence{trust.Held, {Policy: trust.PredecessorPolicy, Control: trust.PredecessorControl}} {
		if len(candidate.Policy) == 0 || len(candidate.Control) == 0 {
			continue
		}
		policy, policyErr := vault.DecodePolicy(candidate.Policy)
		_, controlErr := vault.DecodeControl(candidate.Control)
		if policyErr != nil || controlErr != nil || policy.EpochSeq+1 != currentPolicy.EpochSeq {
			continue
		}
		digest, digestErr := vault.ComputePolicyDigest(candidate.Policy)
		if digestErr == nil && digest == currentPolicy.PrevPolicyDigest && policy.Vault == vaultID {
			evidence = state.AuthenticatedPositionEvidence{Vault: vaultID, Epoch: policy.EpochSeq, PolicyDigest: digest, Policy: bytes.Clone(candidate.Policy), Control: bytes.Clone(candidate.Control)}
			break
		}
	}
	if len(evidence.Policy) == 0 {
		if currentPolicy.EpochSeq == 0 {
			return nil, nil, atproto.ErrReadControlLinkage
		}
		loaded, err := coordinator.deps.State.AuthenticatedPositionEvidence(ctx, vaultID, currentPolicy.EpochSeq-1, currentPolicy.PrevPolicyDigest)
		if err != nil {
			if errors.Is(err, state.ErrAuthenticatedPositionEvidenceNotFound) {
				return nil, nil, ErrMissingPredecessorEvidence
			}
			return nil, nil, err
		}
		evidence = loaded
	}
	previousPolicy, previousControl, err := encodePositionRecords(evidence.Policy, evidence.Control)
	if err != nil {
		return nil, nil, fmt.Errorf("encode authenticated predecessor: %w", err)
	}
	previousPolicyObject, err := vault.DecodePolicy(evidence.Policy)
	if err != nil || evidence.Vault != vaultID || previousPolicyObject.EpochSeq+1 != currentPolicy.EpochSeq || previousPolicyObject.Vault != vaultID || evidence.PolicyDigest != currentPolicy.PrevPolicyDigest {
		return nil, nil, ErrMissingPredecessorEvidence
	}
	previousControlObject, err := vault.DecodeControl(evidence.Control)
	if err != nil || previousControlObject.Vault != vaultID || previousControlObject.EpochSeq != previousPolicyObject.EpochSeq || len(currentControl.PrevControlCID) == 0 {
		return nil, nil, ErrMissingPredecessorEvidence
	}
	return previousPolicy, previousControl, nil
}

func publicationPredecessor(read atproto.ReadResult, anchor [32]byte) (vault.Predecessor, error) {
	policyBytes, err := vault.EncodePolicy(policyObject(read.Policy))
	if err != nil {
		return vault.Predecessor{}, err
	}
	controlBytes, err := vault.EncodeControl(controlObject(read.Control))
	if err != nil {
		return vault.Predecessor{}, err
	}
	head := vault.Head{
		Vault: [32]byte(read.Head.Vault), EpochSeq: read.Head.EpochSeq, PolicyDigest: [32]byte(read.Head.PolicyDigest),
		SnapshotCID: bytes.Clone(read.Head.SnapshotCID), BlobCID: bytes.Clone(read.Head.BlobCID),
		PublicationCount: read.Head.PublicationCount, PrevHeadCID: bytes.Clone(read.Head.PrevHeadCID),
		Signer: vault.Signer{DeviceID: read.Head.SignerDeviceID, KeyID: bytes.Clone(read.Head.SignerKeyID)},
	}
	copy(head.Signature[:], read.Head.Signature)
	headBytes, err := vault.EncodeHead(head)
	if err != nil {
		return vault.Predecessor{}, err
	}
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	if err != nil {
		return vault.Predecessor{}, err
	}
	policy := policyObject(read.Policy)
	certificates, err := certificateObjectsForPolicy(read.Revision, policy)
	if err != nil {
		return vault.Predecessor{}, err
	}
	control, err := vault.DecodeControl(controlBytes)
	if err != nil || len(read.ControlCID) == 0 || len(read.Control.PolicyDigest) != 32 || control.Vault != policy.Vault || control.EpochSeq != read.EpochSeq || control.PolicyDigest != policyDigest || policy.EpochSeq != read.EpochSeq || read.Control.EpochSeq != read.EpochSeq || read.Head.EpochSeq != read.EpochSeq || read.Head.PublicationCount != read.PublicationCount || !bytes.Equal(read.Policy.Vault, policy.Vault[:]) || !bytes.Equal(read.Control.Vault, policy.Vault[:]) || !bytes.Equal(read.Head.Vault, policy.Vault[:]) || !bytes.Equal(read.Head.SnapshotCID, read.HeadCID) || !bytes.Equal(read.Head.PolicyDigest, read.Control.PolicyDigest) || !bytes.Equal(read.Control.PolicyDigest, policyDigest[:]) {
		return vault.Predecessor{}, atproto.ErrReadVaultAuthentication
	}
	return vault.Predecessor{
		ControlCID: bytes.Clone(read.ControlCID), PolicyDigest: policyDigest, EpochSeq: read.EpochSeq,
		HeadCID: bytes.Clone(read.HeadCID), Head: headBytes, Control: controlBytes, Policy: policyBytes,
		Certificates: certificates, TrustAnchor: anchor,
	}, nil
}

func freshRecipientWraps(policy vault.Policy) ([]vault.RecipientWrapInput, error) {
	wraps := make([]vault.RecipientWrapInput, 0, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		var wrap vault.RecipientWrapInput
		wrap.KeyID = bytes.Clone(recipient.KeyID)
		if _, err := rand.Read(wrap.EphemeralPrivate[:]); err != nil {
			clearRecipientWraps(wraps)
			return nil, fmt.Errorf("generate recipient ephemeral key: %w", err)
		}
		if _, err := rand.Read(wrap.WrapNonce[:]); err != nil {
			clear(wrap.EphemeralPrivate[:])
			clearRecipientWraps(wraps)
			return nil, fmt.Errorf("generate recipient wrap nonce: %w", err)
		}
		wraps = append(wraps, wrap)
	}
	return wraps, nil
}

func clearRecipientWraps(wraps []vault.RecipientWrapInput) {
	for index := range wraps {
		clear(wraps[index].EphemeralPrivate[:])
		clear(wraps[index].WrapNonce[:])
	}
}

func snapshotsEqual(left, right model.Snapshot) bool {
	leftPacked, leftErr := vault.Pack(left)
	rightPacked, rightErr := vault.Pack(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPacked.Payload, rightPacked.Payload)
}

func entryIsFileTombstone(entry model.Entry) bool {
	return entry.File != nil && entry.File.State == model.FileDeleted
}

func newPushBlockedError(identities []model.EntryKey) error {
	unique := make(map[model.EntryKey]struct{}, len(identities))
	ordered := make([]model.EntryKey, 0, len(identities))
	for _, identity := range identities {
		if _, exists := unique[identity]; exists {
			continue
		}
		unique[identity] = struct{}{}
		ordered = append(ordered, identity)
	}
	sort.Slice(ordered, func(i, j int) bool {
		left := identitySortKey(ordered[i])
		right := identitySortKey(ordered[j])
		return left < right
	})
	return &PushBlockedError{Identities: ordered}
}

func pushStatus(status atproto.PublicationRetryStatus) StatusState {
	switch status {
	case atproto.PublicationCommitted:
		return StatusCommitted
	case atproto.PublicationQueued:
		return StatusQueued
	case atproto.PublicationStarved:
		return StatusStarved
	case atproto.PublicationFenceLost:
		return StatusFenceLost
	case atproto.PublicationSuperseded:
		return StatusSuperseded
	case atproto.PublicationRejected:
		return StatusRejected
	case atproto.PublicationUnavailable:
		return StatusUnavailable
	default:
		return StatusUnavailable
	}
}

func identitySortKey(identity model.EntryKey) string {
	return identity.TargetID + "\x00" + string(identity.Source) + "\x00" + identity.FilePath + "\x00" + identity.SchemaID + "\x00" + identity.SettingsPath + "\x00" + identity.SettingKey
}

func formatEntryIdentities(identities []model.EntryKey) string {
	parts := make([]string, 0, len(identities))
	for _, identity := range identities {
		if identity.Source == model.SourceFiles {
			parts = append(parts, fmt.Sprintf("%s/%s:%s", identity.TargetID, identity.Source, identity.FilePath))
		} else {
			parts = append(parts, fmt.Sprintf("%s/%s:%s:%s:%s", identity.TargetID, identity.Source, identity.SchemaID, identity.SettingsPath, identity.SettingKey))
		}
	}
	return fmt.Sprintf("%v", parts)
}
