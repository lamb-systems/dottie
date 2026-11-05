package service

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
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
	journals, err := coordinator.deps.State.JournalEntriesAll(ctx)
	if err != nil {
		return Status{}, err
	}
	latest := make(map[string]TargetStatus, len(configuration.Targets))
	for _, target := range configuration.Targets {
		latest[target.ID] = TargetStatus{ID: target.ID, Source: string(target.Source), Mode: target.ModeOrDefault(configuration.Defaults), State: StatusUnknown}
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
	result := Status{Targets: make([]TargetStatus, 0, len(configuration.Targets))}
	for _, target := range configuration.Targets {
		result.Targets = append(result.Targets, latest[target.ID])
	}
	sort.Slice(result.Targets, func(i, j int) bool { return result.Targets[i].ID < result.Targets[j].ID })
	return result, nil
}

func (coordinator *Coordinator) Pull(ctx context.Context, selection VaultSelection) (ReadOutcome, error) {
	if err := coordinator.lock(ctx); err != nil {
		return ReadOutcome{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.pullLocked(ctx, selection)
}

func (coordinator *Coordinator) pullLocked(ctx context.Context, selection VaultSelection) (ReadOutcome, error) {
	return coordinator.pullLockedWithTrust(ctx, selection, nil)
}

func (coordinator *Coordinator) pullLockedWithTrust(ctx context.Context, selection VaultSelection, suppliedTrust *TrustMaterial) (ReadOutcome, error) {
	if coordinator.deps.Trust == nil || coordinator.deps.Session == nil || coordinator.deps.Remote == nil {
		return ReadOutcome{}, errors.New("read coordinator ports are unavailable")
	}
	if coordinator.deps.Config == nil {
		return ReadOutcome{}, errors.New("coordinator config port is required")
	}
	configuration, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return ReadOutcome{}, err
	}
	selection, err = coordinator.selectVault(ctx, selection)
	if err != nil {
		return ReadOutcome{}, err
	}
	var trust TrustMaterial
	if suppliedTrust == nil {
		trust, err = coordinator.deps.Trust.Resolve(ctx, selection)
	} else {
		trust = *suppliedTrust
	}
	if err != nil {
		return ReadOutcome{}, err
	}
	if trust.Selection != selection {
		return ReadOutcome{}, ErrDeviceKeyMissing
	}
	if trust.Checkpoint.Vault != selection.Vault || trust.Anchor == ([32]byte{}) || trust.Anchor != trust.Checkpoint.Anchor || len(trust.Held.Control) == 0 {
		return ReadOutcome{}, ErrNoCheckpoint
	}
	if trust.ImportedCheckpoint {
		if err := validateImportedCheckpointPredecessor(trust); err != nil {
			return ReadOutcome{}, fmt.Errorf("%w: imported checkpoint predecessor", ErrTrustEvidenceInvalid)
		}
	} else if !bytes.Equal(trust.Held.Control, trust.Checkpoint.ControlBytes) {
		return ReadOutcome{}, ErrNoCheckpoint
	}
	if len(trust.Held.Policy) != 0 && !trust.ImportedCheckpoint {
		if err := validateHeldEvidence(trust); err != nil {
			return ReadOutcome{}, fmt.Errorf("%w: %v", ErrTrustEvidenceInvalid, err)
		}
	} else if len(trust.Held.Policy) == 0 && trust.Checkpoint.Epoch != 0 {
		return ReadOutcome{}, ErrMissingPredecessorEvidence
	}
	var previousPolicy, previousControl []byte
	if trust.ImportedCheckpoint {
		previousPolicy, previousControl, err = encodePositionRecords(trust.Held.Policy, trust.Held.Control)
	} else {
		previousPolicy, previousControl, err = encodePredecessorRecords(trust)
	}
	if err != nil {
		return ReadOutcome{}, fmt.Errorf("%w: %v", ErrMissingPredecessorEvidence, err)
	}
	pairs := make([][2][]byte, 0, 3)
	pairs = append(pairs, [2][]byte{previousPolicy, previousControl})
	if len(trust.Held.Policy) != 0 && !trust.ImportedCheckpoint {
		heldPolicy, heldControl, encodeErr := encodePositionRecords(trust.Held.Policy, trust.Held.Control)
		if encodeErr != nil {
			return ReadOutcome{}, fmt.Errorf("%w: held checkpoint records", ErrMissingPredecessorEvidence)
		}
		pairs = append(pairs, [2][]byte{heldPolicy, heldControl})
	} else if len(trust.Held.Policy) == 0 && trust.Checkpoint.Epoch == 0 {
		pairs = append(pairs, [2][]byte{})
	}
	history, historyErr := coordinator.deps.State.AuthenticatedPositionHistory(ctx, selection.Vault)
	if historyErr != nil {
		return ReadOutcome{}, historyErr
	}
	var latestPredecessor *state.AuthenticatedPositionEvidence
	for index := range history {
		if history[index].Epoch <= trust.Checkpoint.Epoch {
			continue
		}
		if latestPredecessor == nil || history[index].Epoch > latestPredecessor.Epoch {
			latestPredecessor = &history[index]
		}
	}
	if latestPredecessor != nil {
		previousPolicy, previousControl, encodeErr := encodePositionRecords(latestPredecessor.Policy, latestPredecessor.Control)
		if encodeErr != nil {
			return ReadOutcome{}, fmt.Errorf("encode latest authenticated predecessor: %w", encodeErr)
		}
		duplicate := false
		for _, pair := range pairs {
			if bytes.Equal(pair[0], previousPolicy) && bytes.Equal(pair[1], previousControl) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			pairs = append(pairs, [2][]byte{previousPolicy, previousControl})
		}
	}
	var read atproto.ReadResult
	var readErr error
	for _, pair := range pairs {
		request, requestErr := coordinator.deps.Session.ReadRequest(ctx, selection, trust.Device, trust.Anchor, pair[0], pair[1])
		if requestErr != nil {
			return ReadOutcome{}, requestErr
		}
		request.Vault = selection.Vault
		request.TrustAnchor = trust.Anchor
		request.DeviceKeyID = append([]byte(nil), trust.Device.KeyID...)
		request.DeviceKey = trust.Device.Recipient
		request.PreviousPolicy = append([]byte(nil), pair[0]...)
		request.PreviousControl = append([]byte(nil), pair[1]...)
		read, readErr = coordinator.deps.Remote.Read(ctx, request)
		if readErr == nil {
			break
		}
	}
	if readErr != nil {
		return ReadOutcome{}, readErr
	}
	if trust.ImportedCheckpoint {
		if err := verifyImportedCheckpointRead(trust, read); err != nil {
			return ReadOutcome{}, err
		}
	}
	if err := coordinator.recordPosition(ctx, selection.Vault, read); err != nil {
		return ReadOutcome{}, fmt.Errorf("record authenticated position evidence: %w", err)
	}
	if len(read.Plaintext) == 0 {
		return ReadOutcome{}, errors.New("verified read did not return decrypted snapshot content")
	}
	blob, err := snapshotBlob(read.Plaintext)
	if err != nil {
		return ReadOutcome{}, err
	}
	snapshot, err := vault.UnpackWithLimits(blob, vault.DefaultLimits())
	if err != nil {
		return ReadOutcome{}, fmt.Errorf("unpack authenticated remote snapshot: %w", err)
	}
	snapshotBeforePolicyFilter := snapshot
	snapshot, untracked, err := filterSnapshot(ctx, configuration, coordinator.deps.Settings, snapshot)
	if err != nil {
		return ReadOutcome{}, err
	}
	currency, err := verifyCurrency(ctx, coordinator.deps.State, selection.Vault, trust, read)
	if err != nil {
		return ReadOutcome{}, err
	}
	retention := coordinator.refreshRetention(ctx, selection, trust, read, currency)
	return ReadOutcome{Snapshot: snapshot, VerifiedSnapshot: snapshotBeforePolicyFilter, Read: read, Currency: currency, Freshness: read.Freshness,
		InspectOnly: currency.Outcome != vault.CheckpointCurrent && currency.Outcome != vault.CheckpointDescendant, Untracked: untracked, Retention: retention}, nil
}

func (coordinator *Coordinator) selectVault(ctx context.Context, requested VaultSelection) (VaultSelection, error) {
	selections, err := coordinator.deps.State.VaultSelections(ctx)
	if err != nil {
		return VaultSelection{}, err
	}
	if requested.Vault != ([32]byte{}) {
		matches := make([]state.VaultSelection, 0, 1)
		for _, selection := range selections {
			if selection.Vault == requested.Vault && (requested.DeviceID == "" || requested.DeviceID == selection.DeviceID) {
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

func validateHeldEvidence(trust TrustMaterial) error {
	control, err := vault.DecodeControl(trust.Held.Control)
	if err != nil {
		return err
	}
	policy, err := vault.DecodePolicy(trust.Held.Policy)
	if err != nil {
		return err
	}
	digest, err := vault.ComputePolicyDigest(trust.Held.Policy)
	if err != nil || control.Vault != trust.Selection.Vault || policy.Vault != trust.Selection.Vault || policy.EpochSeq != trust.Checkpoint.Epoch || control.EpochSeq != trust.Checkpoint.Epoch || digest != trust.Checkpoint.PolicyDigest || digest != control.PolicyDigest || !bytes.Equal(trust.Checkpoint.ControlBytes, trust.Held.Control) || !bytes.Equal(trust.Checkpoint.SnapshotCID, control.HeadSnapshotCID) {
		return errors.New("local checkpoint does not match held authenticated position")
	}
	context := vault.NewTrustedContext(trust.Selection.Vault, trust.Anchor)
	if err := context.SetHeldCheckpoint(trust.Held); err != nil {
		return err
	}
	result, err := vault.VerifyControlState(context, vault.VerificationRequest{Supplied: trust.Held})
	if err != nil {
		return err
	}
	if result.Outcome != vault.CheckpointCurrent {
		return errors.New("local held checkpoint did not verify as current")
	}
	return nil
}

func encodePredecessorRecords(trust TrustMaterial) ([]byte, []byte, error) {
	if trust.Checkpoint.Epoch == 0 {
		return nil, nil, nil
	}
	if len(trust.PredecessorPolicy) == 0 || len(trust.PredecessorControl) == 0 {
		return nil, nil, ErrMissingPredecessorEvidence
	}
	return encodePositionRecords(trust.PredecessorPolicy, trust.PredecessorControl)
}

func encodePositionRecords(policyBytes, controlBytes []byte) ([]byte, []byte, error) {
	policy, err := vault.DecodePolicy(policyBytes)
	if err != nil {
		return nil, nil, err
	}
	control, err := vault.DecodeControl(controlBytes)
	if err != nil {
		return nil, nil, err
	}
	policyRecord := atproto.PolicyRecord{
		SchemaVersion: 1, Vault: bytes.Clone(policy.Vault[:]), EpochSeq: policy.EpochSeq,
		PolicyRetentionFloor: policy.PolicyRetentionFloor, RetainedRecoveryPoints: policy.RetainedRecoveryPoints,
		MaxPublications: policy.MaxPublications, MaxEpochAge: policy.MaxEpochAge,
		RecoveryAnchor: bytes.Clone(policy.RecoveryAnchor[:]), PrevPolicyDigest: bytes.Clone(policy.PrevPolicyDigest[:]),
		SignerDeviceID: policy.Signer.DeviceID, SignerKeyID: bytes.Clone(policy.Signer.KeyID), Signature: bytes.Clone(policy.Signature[:]),
	}
	for _, role := range policy.Roles {
		policyRecord.Roles = append(policyRecord.Roles, atproto.PolicyRoleRecord{DeviceID: role.DeviceID, Role: uint8(role.Role)})
	}
	for _, recipient := range policy.Recipients {
		policyRecord.Recipients = append(policyRecord.Recipients, atproto.PolicyRecipientRecord{DeviceID: recipient.DeviceID, KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:])})
	}
	encodedPolicy, err := atproto.EncodeRecord(policyRecord)
	if err != nil {
		return nil, nil, err
	}
	controlRecord := atproto.ControlRecord{
		SchemaVersion: 1, Vault: bytes.Clone(control.Vault[:]), EpochSeq: control.EpochSeq,
		PolicyDigest: bytes.Clone(control.PolicyDigest[:]), HeadSnapshotCID: bytes.Clone(control.HeadSnapshotCID),
		PrevControlCID: bytes.Clone(control.PrevControlCID), SignerDeviceID: control.Signer.DeviceID,
		SignerKeyID: bytes.Clone(control.Signer.KeyID), Signature: bytes.Clone(control.Signature[:]),
	}
	for _, revoked := range control.Revoked {
		controlRecord.Revoked = append(controlRecord.Revoked, atproto.RevokedDeviceRecord{DeviceID: revoked.DeviceID, CertEpoch: revoked.CertEpoch})
	}
	encodedControl, err := atproto.EncodeRecord(controlRecord)
	if err != nil {
		return nil, nil, err
	}
	return encodedPolicy, encodedControl, nil
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
		if entry.Source == string(model.SourceFiles) && entry.State == string(model.FilePresent) && entry.Kind == string(model.FileRegular) {
			if entry.Size < 0 || plaintextBytes > vault.DefaultLimits().MaxTotalBytes-entry.Size {
				return vault.Blob{}, errors.New("authenticated snapshot exceeds its plaintext limit")
			}
			plaintextBytes += entry.Size
		}
	}
	return vault.Blob{Version: vault.Version, Codec: vault.CodecNone, Payload: bytes.Clone(plaintext), Digest: sha256.Sum256(plaintext), EntryCount: len(manifest.Entries), PlaintextBytes: plaintextBytes}, nil
}

func filterSnapshot(ctx context.Context, configuration config.Config, settings SettingsPort, snapshot model.Snapshot) (model.Snapshot, []model.EntryKey, error) {
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
	if err != nil || fmt.Sprintf("%x", digest) != policy.KeyDigest {
		return nil, fmt.Errorf("%w: target %q key digest does not match stored categories", ErrGNOMEReapproval, target.ID)
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

func verifyCurrency(ctx context.Context, store *state.Store, vaultID [32]byte, trust TrustMaterial, read atproto.ReadResult) (vault.VerificationResult, error) {
	if trust.ImportedCheckpoint {
		if err := verifyImportedCheckpointRead(trust, read); err != nil {
			return vault.VerificationResult{}, err
		}
		return vault.VerificationResult{Outcome: vault.CheckpointCurrent, ReasonCode: "onboarding-checkpoint", Reason: "the authenticated read matches the imported checkpoint"}, nil
	}
	policyBytes, err := vault.EncodePolicy(policyObject(read.Policy))
	if err != nil {
		return vault.VerificationResult{}, err
	}
	controlBytes, err := vault.EncodeControl(controlObject(read.Control))
	if err != nil {
		return vault.VerificationResult{}, err
	}
	certificates, err := certificateObjectsForPolicy(read.Revision, policyObject(read.Policy))
	if err != nil {
		return vault.VerificationResult{}, err
	}
	held := trust.Held
	if len(held.Policy) == 0 {
		digest, digestErr := vault.ComputePolicyDigest(policyBytes)
		if digestErr != nil || read.EpochSeq != trust.Checkpoint.Epoch || digest != trust.Checkpoint.PolicyDigest || !bytes.Equal(controlBytes, trust.Checkpoint.ControlBytes) {
			return vault.VerificationResult{}, ErrMissingPredecessorEvidence
		}
		held = vault.ControlEvidence{Policy: policyBytes, Control: trust.Checkpoint.ControlBytes, Certificates: certificates}
	}
	trusted := vault.NewTrustedContext(vaultID, trust.Anchor)
	if err := trusted.SetHeldCheckpoint(held); err != nil {
		return vault.VerificationResult{}, err
	}
	supplied := vault.ControlEvidence{Policy: policyBytes, Control: controlBytes, Certificates: certificates}
	var intermediates []vault.ControlEvidence
	if len(held.Policy) != 0 {
		positions, historyErr := retentionPositions(ctx, store, vaultID)
		if historyErr != nil {
			return vault.VerificationResult{}, historyErr
		}
		selectedEvidence, evidenceErr := positionEvidenceFromRead(vaultID, read)
		selectedControl, controlErr := vault.DecodeControl(controlBytes)
		checkpointControl, checkpointControlErr := vault.DecodeControl(held.Control)
		checkpointPolicyDigest, digestErr := vault.ComputePolicyDigest(held.Policy)
		if evidenceErr == nil && controlErr == nil && checkpointControlErr == nil && digestErr == nil {
			selected := retentionPosition{
				evidence: selectedEvidence, control: selectedControl, controlCID: rawVaultCID(controlBytes),
			}
			checkpointPosition := retentionPosition{control: checkpointControl, controlCID: rawVaultCID(held.Control)}
			if len(checkpointPosition.controlCID) != 0 && checkpointPolicyDigest != ([32]byte{}) {
				if path, ok := buildRetentionControlIntermediates(positions, selected, checkpointPosition); ok {
					intermediates = path
				}
			}
		}
	}
	result, err := vault.VerifyControlState(trusted, vault.VerificationRequest{Supplied: supplied, Intermediates: intermediates})
	if err != nil {
		return vault.VerificationResult{}, err
	}
	return result, nil
}

func policyObject(record atproto.PolicyRecord) vault.Policy {
	policy := vault.Policy{
		Vault: [32]byte(record.Vault), EpochSeq: record.EpochSeq,
		PolicyRetentionFloor: record.PolicyRetentionFloor, RetainedRecoveryPoints: record.RetainedRecoveryPoints,
		MaxPublications: record.MaxPublications, MaxEpochAge: record.MaxEpochAge,
		RecoveryAnchor: [32]byte(record.RecoveryAnchor), PrevPolicyDigest: [32]byte(record.PrevPolicyDigest),
		Signer: vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)},
	}
	copy(policy.Signature[:], record.Signature)
	for _, role := range record.Roles {
		policy.Roles = append(policy.Roles, vault.RoleBinding{DeviceID: role.DeviceID, Role: vault.Role(role.Role)})
	}
	for _, recipient := range record.Recipients {
		var public [32]byte
		copy(public[:], recipient.PublicKey)
		policy.Recipients = append(policy.Recipients, vault.PolicyRecipient{DeviceID: recipient.DeviceID, KeyID: bytes.Clone(recipient.KeyID), PublicKey: public})
	}
	return policy
}

func controlObject(record atproto.ControlRecord) vault.Control {
	control := vault.Control{
		Vault: [32]byte(record.Vault), EpochSeq: record.EpochSeq, PolicyDigest: [32]byte(record.PolicyDigest),
		HeadSnapshotCID: bytes.Clone(record.HeadSnapshotCID), PrevControlCID: bytes.Clone(record.PrevControlCID),
		Signer: vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)},
	}
	copy(control.Signature[:], record.Signature)
	for _, revoked := range record.Revoked {
		control.Revoked = append(control.Revoked, vault.RevokedDevice{DeviceID: revoked.DeviceID, CertEpoch: revoked.CertEpoch})
	}
	return control
}

func certificateObjects(revision *atproto.Revision) ([][]byte, error) {
	if revision == nil {
		return nil, errors.New("verified revision is missing")
	}
	records := revision.Records()
	certificates := make([][]byte, 0)
	for key, proven := range records {
		if key.Collection != atproto.VaultCertificateNSID {
			continue
		}
		record, err := atproto.DecodeRecord(proven.Data)
		if err != nil {
			return nil, err
		}
		certificateRecord, ok := record.(atproto.CertificateRecord)
		if !ok {
			return nil, errors.New("verified certificate record has an unexpected type")
		}
		certificate := vault.Certificate{
			Vault: [32]byte(certificateRecord.Vault), DeviceID: certificateRecord.DeviceID,
			KeyID: bytes.Clone(certificateRecord.KeyID), Role: vault.Role(certificateRecord.Role),
			CertEpoch: certificateRecord.CertEpoch, Issuer: certificateRecord.Issuer,
			RevocationRef: bytes.Clone(certificateRecord.RevocationRef),
			Signer:        vault.Signer{DeviceID: certificateRecord.SignerDeviceID, KeyID: bytes.Clone(certificateRecord.SignerKeyID)},
		}
		copy(certificate.SigningPublicKey[:], certificateRecord.SigningPublicKey)
		copy(certificate.EncryptionPublicKey[:], certificateRecord.EncryptionPublicKey)
		copy(certificate.Signature[:], certificateRecord.Signature)
		encoded, err := vault.EncodeCertificate(certificate)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, encoded)
	}
	if len(certificates) == 0 {
		return nil, errors.New("verified revision has no certificates")
	}
	sort.Slice(certificates, func(i, j int) bool { return bytes.Compare(certificates[i], certificates[j]) < 0 })
	return certificates, nil
}

func (coordinator *Coordinator) recordPosition(ctx context.Context, vaultID [32]byte, read atproto.ReadResult) error {
	evidence, err := positionEvidenceFromRead(vaultID, read)
	if err != nil {
		return err
	}
	stored, storedErr := coordinator.deps.State.AuthenticatedPositionEvidence(ctx, evidence.Vault, evidence.Epoch, evidence.PolicyDigest)
	if storedErr == nil {
		evidence.CheckpointPosition = bytes.Clone(stored.CheckpointPosition)
	} else if !errors.Is(storedErr, state.ErrAuthenticatedPositionEvidenceNotFound) {
		return storedErr
	}
	return coordinator.deps.State.PutAuthenticatedPositionEvidence(ctx, evidence)
}

func positionEvidenceFromRead(vaultID [32]byte, read atproto.ReadResult) (state.AuthenticatedPositionEvidence, error) {
	policyBytes, err := vault.EncodePolicy(policyObject(read.Policy))
	if err != nil {
		return state.AuthenticatedPositionEvidence{}, err
	}
	controlBytes, err := vault.EncodeControl(controlObject(read.Control))
	if err != nil {
		return state.AuthenticatedPositionEvidence{}, err
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
		return state.AuthenticatedPositionEvidence{}, err
	}
	certificates, err := certificateObjectsForPolicy(read.Revision, policyObject(read.Policy))
	if err != nil {
		return state.AuthenticatedPositionEvidence{}, err
	}
	digest, err := vault.ComputePolicyDigest(policyBytes)
	if err != nil {
		return state.AuthenticatedPositionEvidence{}, err
	}
	return state.AuthenticatedPositionEvidence{
		Vault: vaultID, Epoch: read.EpochSeq, PolicyDigest: digest,
		Policy: policyBytes, Control: controlBytes, Head: headBytes, Certificates: certificates,
	}, nil
}

func certificateObjectsForPolicy(revision *atproto.Revision, policy vault.Policy) ([][]byte, error) {
	all, err := certificateObjects(revision)
	if err != nil {
		return nil, err
	}
	active := make([][]byte, 0, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		found := false
		for _, encoded := range all {
			certificate, decodeErr := vault.DecodeCertificate(encoded)
			if decodeErr != nil {
				return nil, decodeErr
			}
			if certificate.DeviceID == recipient.DeviceID && bytes.Equal(certificate.KeyID, recipient.KeyID) && certificate.EncryptionPublicKey == recipient.PublicKey {
				if found {
					return nil, errors.New("verified revision has duplicate active device certificates")
				}
				active = append(active, bytes.Clone(encoded))
				found = true
			}
		}
		if !found {
			return nil, errors.New("verified revision omits an active device certificate")
		}
	}
	return active, nil
}

func targetFromConfig(target config.Target) (model.Target, error) {
	return target.Model()
}
