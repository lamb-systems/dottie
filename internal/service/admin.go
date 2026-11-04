package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
)

func (coordinator *Coordinator) Enroll(ctx context.Context, request EnrollRequest) (AdministrativeResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return AdministrativeResult{}, err
	}
	defer coordinator.mu.Unlock()
	selected, trust, pulled, predecessor, err := coordinator.administrativePredecessor(ctx, request.Selection, request.Kit)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	wrappingPolicy := policy
	wrappingPolicy.Recipients = append(append([]vault.PolicyRecipient(nil), policy.Recipients...), vault.PolicyRecipient{DeviceID: request.Device.DeviceID, KeyID: bytes.Clone(request.Device.KeyID)})
	contentKey, wraps, publicationID, nonce, err := coordinator.freshAdministrativeMaterial(wrappingPolicy)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	defer clear(contentKey)
	defer clearRecipientWraps(wraps)
	defer clear(publicationID[:])
	defer clear(nonce[:])
	transition, err := vault.PreparePublicEnrollment(predecessor, vault.PublicEnrollmentIntent{
		Vault: selected.Vault, RootSigner: trust.Device, NewDevice: request.Device, RequestedRole: request.Role,
		ApprovalFingerprint: request.ApprovalFingerprint, ContentKey: contentKey,
		Recipients: cloneServiceByteSlices(predecessor.Certificates), Wraps: wraps,
		Plaintext: bytes.Clone(pulled.Read.Plaintext), PublicationID: publicationID, Nonce: nonce,
	})
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	return coordinator.commitAdministrativeTransition(ctx, selected, trust, pulled, predecessor, transition, request.Kit)
}

func (coordinator *Coordinator) RevokeApproval(ctx context.Context, requested VaultSelection, deviceID string, kit []byte) (RevokeApprovalTranscript, error) {
	if err := coordinator.lock(ctx); err != nil {
		return RevokeApprovalTranscript{}, err
	}
	defer coordinator.mu.Unlock()
	selected, _, pulled, _, err := coordinator.administrativePredecessor(ctx, requested, kit)
	if err != nil {
		return RevokeApprovalTranscript{}, err
	}
	return buildRevokeApprovalTranscript(selected, deviceID, pulled, kit)
}

func (coordinator *Coordinator) Revoke(ctx context.Context, request RevokeRequest) (AdministrativeResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return AdministrativeResult{}, err
	}
	defer coordinator.mu.Unlock()
	selected, trust, pulled, predecessor, err := coordinator.administrativePredecessor(ctx, request.Selection, request.Kit)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	if request.ApprovalFingerprint != ([32]byte{}) {
		transcript, transcriptErr := buildRevokeApprovalTranscript(selected, request.DeviceID, pulled, request.Kit)
		if transcriptErr != nil {
			if errors.Is(transcriptErr, ErrRecoveryKitMismatch) || errors.Is(transcriptErr, ErrAdministrativeRootRequired) {
				return AdministrativeResult{Status: StatusRejected}, transcriptErr
			}
			return AdministrativeResult{Status: StatusRejected}, RevokeApprovalMismatchError{}
		}
		if transcript.ApprovalFingerprint != request.ApprovalFingerprint {
			return AdministrativeResult{Status: StatusRejected}, RevokeApprovalMismatchError{}
		}
	}
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	recipients := make([][]byte, 0, len(predecessor.Certificates)-1)
	wrappingPolicy := policy
	wrappingPolicy.Recipients = make([]vault.PolicyRecipient, 0, len(policy.Recipients)-1)
	for _, certificateBytes := range predecessor.Certificates {
		certificate, decodeErr := vault.DecodeCertificate(certificateBytes)
		if decodeErr != nil {
			return AdministrativeResult{Status: StatusRejected}, decodeErr
		}
		if certificate.DeviceID == request.DeviceID {
			continue
		}
		recipients = append(recipients, bytes.Clone(certificateBytes))
	}
	for _, recipient := range policy.Recipients {
		if recipient.DeviceID != request.DeviceID {
			wrappingPolicy.Recipients = append(wrappingPolicy.Recipients, recipient)
		}
	}
	contentKey, wraps, publicationID, nonce, err := coordinator.freshAdministrativeMaterial(wrappingPolicy)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	defer clear(contentKey)
	defer clearRecipientWraps(wraps)
	defer clear(publicationID[:])
	defer clear(nonce[:])
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionRevoke, Vault: selected.Vault, Signer: trust.Device, RevokeDeviceID: request.DeviceID,
		ContentKey: contentKey, Recipients: recipients, Wraps: wraps, Plaintext: bytes.Clone(pulled.Read.Plaintext),
		PublicationID: publicationID, Nonce: nonce,
	})
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	return coordinator.commitAdministrativeTransition(ctx, selected, trust, pulled, predecessor, transition, request.Kit)
}

type RevokeApprovalMismatchError struct{}

func (RevokeApprovalMismatchError) Error() string { return ErrRevokeApprovalMismatch.Error() }

func (RevokeApprovalMismatchError) Unwrap() error { return ErrRevokeApprovalMismatch }

func buildRevokeApprovalTranscript(selection VaultSelection, deviceID string, pulled ReadOutcome, kit []byte) (RevokeApprovalTranscript, error) {
	predecessor, err := publicationPredecessor(pulled.Read, [32]byte{})
	if err != nil {
		return RevokeApprovalTranscript{}, err
	}
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil || policy.Signer.DeviceID != selection.DeviceID || !servicePolicyRole(policy, selection.DeviceID, vault.RoleRoot) {
		return RevokeApprovalTranscript{}, ErrAdministrativeRootRequired
	}
	if deviceID == "" {
		return RevokeApprovalTranscript{}, errors.New("revocation device identifier is required")
	}
	var role vault.Role
	for _, binding := range policy.Roles {
		if binding.DeviceID == deviceID {
			role = binding.Role
			break
		}
	}
	if role == 0 {
		return RevokeApprovalTranscript{}, errors.New("revocation target is not an active device")
	}
	for _, revoked := range pulled.Read.Control.Revoked {
		if revoked.DeviceID == deviceID {
			return RevokeApprovalTranscript{}, errors.New("revocation target is already revoked")
		}
	}
	var recipient *vault.PolicyRecipient
	for index := range policy.Recipients {
		if policy.Recipients[index].DeviceID == deviceID {
			recipient = &policy.Recipients[index]
			break
		}
	}
	if recipient == nil {
		return RevokeApprovalTranscript{}, errors.New("revocation target recipient is unavailable")
	}
	var certificate *vault.Certificate
	for _, encoded := range predecessor.Certificates {
		decoded, decodeErr := vault.DecodeCertificate(encoded)
		if decodeErr != nil {
			return RevokeApprovalTranscript{}, errors.New("verified device certificate is unavailable")
		}
		if decoded.DeviceID == deviceID {
			certificate = &decoded
			break
		}
	}
	if certificate == nil || certificate.Vault != selection.Vault || certificate.Role != role || !bytes.Equal(certificate.KeyID, recipient.KeyID) || !bytes.Equal(certificate.EncryptionPublicKey[:], recipient.PublicKey[:]) {
		return RevokeApprovalTranscript{}, errors.New("revocation target public keys are unavailable")
	}
	kitFingerprint, err := vault.RecoveryKitPublicKeyFingerprint(kit, selection.Vault)
	if err != nil || kitFingerprint != policy.RecoveryAnchor {
		return RevokeApprovalTranscript{}, ErrRecoveryKitMismatch
	}
	if policy.EpochSeq == ^uint64(0) {
		return RevokeApprovalTranscript{}, errors.New("revocation successor epoch is unavailable")
	}
	transcript := RevokeApprovalTranscript{
		Vault: selection.Vault, DeviceID: deviceID, Role: role,
		SigningKeyFingerprint:   sha256.Sum256(certificate.SigningPublicKey[:]),
		RecipientKeyFingerprint: sha256.Sum256(recipient.PublicKey[:]),
		CurrentEpoch:            policy.EpochSeq, SuccessorEpoch: policy.EpochSeq + 1,
		KitSigningKeyFingerprint: kitFingerprint,
	}
	approval := []byte("dottie/v1/revocation-approval")
	approval = append(approval, selection.Vault[:]...)
	approval = appendApprovalField(approval, []byte(deviceID))
	approval = append(approval, byte(role))
	approval = appendApprovalUint64(approval, transcript.CurrentEpoch)
	approval = appendApprovalUint64(approval, transcript.SuccessorEpoch)
	approval = append(approval, transcript.SigningKeyFingerprint[:]...)
	approval = append(approval, transcript.RecipientKeyFingerprint[:]...)
	approval = append(approval, transcript.KitSigningKeyFingerprint[:]...)
	transcript.ApprovalFingerprint = sha256.Sum256(approval)
	clear(approval)
	return transcript, nil
}

func appendApprovalField(buffer, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buffer = append(buffer, length[:]...)
	return append(buffer, value...)
}

func appendApprovalUint64(buffer []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(buffer, encoded[:]...)
}

func (coordinator *Coordinator) administrativePredecessor(ctx context.Context, requested VaultSelection, kit []byte) (VaultSelection, TrustMaterial, ReadOutcome, vault.Predecessor, error) {
	selected, err := coordinator.selectVault(ctx, requested)
	if err != nil {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, err
	}
	if coordinator.deps.Trust == nil || coordinator.deps.Publisher == nil {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, errors.New("administrative coordinator ports are unavailable")
	}
	trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
	if err != nil {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, err
	}
	if trust.Selection != selected || trust.Device.DeviceID != selected.DeviceID || len(trust.Device.Signing) == 0 {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, ErrAdministrativeRootRequired
	}
	pulled, err := coordinator.pullLockedWithTrust(ctx, selected, &trust)
	if err != nil {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, err
	}
	if pulled.Currency.Outcome != vault.CheckpointCurrent && pulled.Currency.Outcome != vault.CheckpointDescendant || pulled.InspectOnly {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, ErrCheckpointNotCurrent
	}
	predecessor, err := publicationPredecessor(pulled.Read, trust.Anchor)
	if err != nil {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, err
	}
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, err
	}
	if policy.Signer.DeviceID != selected.DeviceID || !servicePolicyRole(policy, selected.DeviceID, vault.RoleRoot) {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, ErrAdministrativeRootRequired
	}
	if len(kit) != 32 {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, ErrRecoveryKitMismatch
	}
	kitFingerprint, err := vault.RecoveryKitPublicKeyFingerprint(kit, selected.Vault)
	if err != nil || kitFingerprint != policy.RecoveryAnchor {
		return VaultSelection{}, TrustMaterial{}, ReadOutcome{}, vault.Predecessor{}, ErrRecoveryKitMismatch
	}
	return selected, trust, pulled, predecessor, nil
}

func (coordinator *Coordinator) commitAdministrativeTransition(ctx context.Context, selected VaultSelection, trust TrustMaterial, pulled ReadOutcome, predecessor vault.Predecessor, transition vault.Transition, kit []byte) (AdministrativeResult, error) {
	publicationIO, err := coordinator.deps.Publisher.PublicationIO(ctx, selected, trust, pulled)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	if publicationIO.Transport == nil || publicationIO.DID == "" {
		return AdministrativeResult{Status: StatusRejected}, errors.New("transition I/O transport and account DID are required")
	}
	if publicationIO.Reader.Transport == nil {
		publicationIO.Reader.Transport = publicationIO.Transport
	}
	previousPolicy, previousControl, err := coordinator.publicationPredecessorRecords(ctx, selected.Vault, trust, pulled.Read)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	currentPolicy, currentControl, err := encodePositionRecords(predecessor.Policy, predecessor.Control)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected}, err
	}
	transitionIO := atproto.ATProtoTransitionIO{
		Reader: publicationIO.Reader, Transport: publicationIO.Transport, BlobUploadLimit: publicationIO.BlobUploadLimit,
		DID: publicationIO.DID, TrustAnchor: trust.Anchor, ObservationStore: coordinator.deps.State, Clock: coordinator.deps.Clock,
	}
	if len(previousPolicy) != 0 {
		transitionIO.PreviousPolicies = append(transitionIO.PreviousPolicies, previousPolicy)
		transitionIO.PreviousControls = append(transitionIO.PreviousControls, previousControl)
	}
	transitionIO.PreviousPolicies = append(transitionIO.PreviousPolicies, currentPolicy)
	transitionIO.PreviousControls = append(transitionIO.PreviousControls, currentControl)
	commit, commitErr := atproto.CommitTransition(ctx, transitionIO, coordinator.deps.State, transition, trust.Device.Signing, coordinator.deps.Clock())
	if commitErr != nil || commit.Outcome != atproto.TransitionOutcomeCommitted {
		status := transitionStatus(commit.Outcome)
		if commitErr == nil {
			commitErr = atproto.ErrTransitionUnavailable
		}
		return AdministrativeResult{Status: status, TransitionOutcome: commit.Outcome}, commitErr
	}
	readBack, err := coordinator.pullLocked(ctx, selected)
	if err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, fmt.Errorf("verify administrative transition read-back: %w", err)
	}
	policyBytes, err := vault.EncodePolicy(policyObject(readBack.Read.Policy))
	if err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	controlBytes, err := vault.EncodeControl(controlObject(readBack.Read.Control))
	if err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	transitionPolicy, transitionPolicyErr := vault.DecodePolicy(transition.Policy)
	transitionDigest, transitionDigestErr := vault.ComputePolicyDigest(transition.Policy)
	if err != nil || transitionPolicyErr != nil || transitionDigestErr != nil || readBack.Read.EpochSeq != transitionPolicy.EpochSeq || policyDigest != transitionDigest || !bytes.Equal(policyBytes, transition.Policy) || !bytes.Equal(controlBytes, transition.Control) || !bytes.Equal(readBack.Read.ControlCID, rawVaultCID(transition.Control)) {
		return AdministrativeResult{Status: StatusSuperseded, TransitionOutcome: commit.Outcome}, atproto.ErrTransitionSuperseded
	}
	control, err := vault.DecodeControl(controlBytes)
	if err != nil || !bytes.Equal(control.HeadSnapshotCID, transition.SnapshotCID) {
		return AdministrativeResult{Status: StatusSuperseded, TransitionOutcome: commit.Outcome}, atproto.ErrTransitionSuperseded
	}
	checkpointBytes, err := vault.SignRecoveryKitCheckpoint(kit, selected.Vault, trust.Anchor, readBack.Read.EpochSeq, policyDigest, readBack.Read.ControlCID, control.HeadSnapshotCID)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected, TransitionOutcome: commit.Outcome}, err
	}
	kitPublic, err := vault.RecoveryKitSigningPublicKey(kit, selected.Vault)
	if err != nil {
		return AdministrativeResult{Status: StatusRejected, TransitionOutcome: commit.Outcome}, err
	}
	checkpointObject, err := vault.VerifyCheckpoint(checkpointBytes, kitPublic)
	if err != nil || checkpointObject.Vault != selected.Vault || checkpointObject.Anchor != trust.Anchor || checkpointObject.EpochSeq != readBack.Read.EpochSeq || checkpointObject.PolicyDigest != policyDigest || !bytes.Equal(checkpointObject.ControlCID, readBack.Read.ControlCID) || !bytes.Equal(checkpointObject.SnapshotCID, control.HeadSnapshotCID) {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, ErrOnboardingCheckpoint
	}
	position, err := positionEvidenceFromRead(selected.Vault, readBack.Read)
	if err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	position.CheckpointPosition = bytes.Clone(checkpointBytes)
	predecessorPosition, err := positionEvidenceFromRead(selected.Vault, pulled.Read)
	if err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	bundle, err := vault.NewOnboardingBundle(selected.Vault, trust.Anchor, checkpointBytes, transition.Policy, transition.Control,
		predecessorPosition.Policy, predecessorPosition.Control, predecessorPosition.Head, predecessorPosition.Snapshot, predecessorPosition.Certificates)
	if err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	encodedBundle, err := vault.EncodeOnboardingBundle(bundle)
	if err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	now := coordinator.deps.Clock().Unix()
	if err := coordinator.deps.State.PutAuthenticatedPositionEvidence(ctx, position); err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	checkpoint := state.VaultCheckpoint{
		Vault: selected.Vault, Anchor: trust.Anchor, ControlCID: bytes.Clone(readBack.Read.ControlCID), ControlBytes: controlBytes,
		SnapshotCID: bytes.Clone(control.HeadSnapshotCID), Epoch: readBack.Read.EpochSeq, PolicyDigest: policyDigest, RecordedAt: now,
	}
	if err := coordinator.deps.State.PutVaultCheckpoint(ctx, checkpoint); err != nil {
		return AdministrativeResult{Status: StatusUnavailable, TransitionOutcome: commit.Outcome}, err
	}
	return AdministrativeResult{Status: StatusCommitted, TransitionOutcome: commit.Outcome, Bundle: bundle, EncodedBundle: encodedBundle}, nil
}

func (coordinator *Coordinator) ExportOnboarding(ctx context.Context, requested VaultSelection, kit []byte) (vault.OnboardingBundle, error) {
	if err := coordinator.lock(ctx); err != nil {
		return vault.OnboardingBundle{}, err
	}
	defer coordinator.mu.Unlock()
	selected, err := coordinator.selectVault(ctx, requested)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	if coordinator.deps.Trust == nil {
		return vault.OnboardingBundle{}, errors.New("onboarding export trust port is unavailable")
	}
	trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	readBack, err := coordinator.pullLockedWithTrust(ctx, selected, &trust)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	if readBack.Currency.Outcome != vault.CheckpointCurrent && readBack.Currency.Outcome != vault.CheckpointDescendant {
		return vault.OnboardingBundle{}, ErrCheckpointNotCurrent
	}
	current, err := positionEvidenceFromRead(selected.Vault, readBack.Read)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	checkpoint, err := coordinator.deps.State.VaultCheckpoint(ctx, selected.Vault)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	policy, err := vault.DecodePolicy(current.Policy)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	if checkpoint.Epoch != current.Epoch || checkpoint.PolicyDigest != current.PolicyDigest || !bytes.Equal(checkpoint.ControlBytes, current.Control) || len(kit) != 32 {
		return vault.OnboardingBundle{}, ErrOnboardingCheckpoint
	}
	fingerprint, err := vault.RecoveryKitPublicKeyFingerprint(kit, selected.Vault)
	if err != nil || fingerprint != policy.RecoveryAnchor {
		return vault.OnboardingBundle{}, ErrRecoveryKitMismatch
	}
	kitPublic, err := vault.RecoveryKitSigningPublicKey(kit, selected.Vault)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	checkpointBytes, err := vault.SignRecoveryKitCheckpoint(kit, selected.Vault, trust.Anchor, checkpoint.Epoch, checkpoint.PolicyDigest, checkpoint.ControlCID, checkpoint.SnapshotCID)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	verified, err := vault.VerifyCheckpoint(checkpointBytes, kitPublic)
	if err != nil {
		return vault.OnboardingBundle{}, err
	}
	if verified.Vault != selected.Vault || verified.Anchor != trust.Anchor || verified.EpochSeq != current.Epoch || verified.PolicyDigest != current.PolicyDigest || !bytes.Equal(verified.ControlCID, checkpoint.ControlCID) || !bytes.Equal(verified.SnapshotCID, policyPositionSnapshot(current.Control)) {
		return vault.OnboardingBundle{}, ErrOnboardingCheckpoint
	}
	if current.Epoch == 0 {
		return vault.OnboardingBundle{}, errors.New("onboarding export requires a successor administrative epoch")
	}
	predecessor, err := coordinator.deps.State.AuthenticatedPositionEvidence(ctx, selected.Vault, current.Epoch-1, policy.PrevPolicyDigest)
	if err != nil {
		return vault.OnboardingBundle{}, fmt.Errorf("%w: onboarding predecessor evidence", ErrMissingPredecessorEvidence)
	}
	trusted := vault.NewTrustedContext(selected.Vault, trust.Anchor)
	preEvidence := vault.ControlEvidence{Policy: predecessor.Policy, Control: predecessor.Control, Certificates: predecessor.Certificates}
	if err := trusted.SetHeldCheckpoint(preEvidence); err != nil {
		return vault.OnboardingBundle{}, err
	}
	result, err := vault.VerifyControlState(trusted, vault.VerificationRequest{Supplied: vault.ControlEvidence{Policy: current.Policy, Control: current.Control, Certificates: current.Certificates}})
	if err != nil || result.Outcome != vault.CheckpointDescendant {
		return vault.OnboardingBundle{}, ErrOnboardingChain
	}
	return vault.NewOnboardingBundle(selected.Vault, trust.Anchor, checkpointBytes, current.Policy, current.Control,
		predecessor.Policy, predecessor.Control, predecessor.Head, predecessor.Snapshot, predecessor.Certificates)
}

func (coordinator *Coordinator) ImportOnboarding(ctx context.Context, encoded []byte, expectedVault, expectedAnchor [32]byte, deviceID string) error {
	if err := coordinator.lock(ctx); err != nil {
		return err
	}
	defer coordinator.mu.Unlock()
	if coordinator.deps.DeviceKeys == nil {
		return ErrDeviceKeyMissing
	}
	bundle, err := vault.DecodeOnboardingBundle(encoded)
	if err != nil {
		return err
	}
	if expectedVault == ([32]byte{}) || bundle.Vault != expectedVault {
		return ErrOnboardingVaultMismatch
	}
	if expectedAnchor == ([32]byte{}) || bundle.Anchor != expectedAnchor {
		return ErrOnboardingAnchorMismatch
	}
	checkpoint, err := vault.DecodeCheckpoint(bundle.Checkpoint)
	if err != nil {
		return err
	}
	successorControl, err := vault.DecodeControl(bundle.SuccessorControl)
	if err != nil {
		return err
	}
	if checkpoint.Anchor != expectedAnchor || checkpoint.Vault != expectedVault || checkpoint.EpochSeq != successorControl.EpochSeq || checkpoint.PolicyDigest != successorControl.PolicyDigest || !bytes.Equal(checkpoint.ControlCID, rawVaultCID(bundle.SuccessorControl)) || !bytes.Equal(checkpoint.SnapshotCID, successorControl.HeadSnapshotCID) {
		return ErrOnboardingCheckpoint
	}
	predecessor := vault.ControlEvidence{Policy: bundle.PredecessorPolicy, Control: bundle.PredecessorControl, Certificates: cloneServiceByteSlices(bundle.PredecessorCertificates)}
	trusted := vault.NewTrustedContext(expectedVault, expectedAnchor)
	if err := trusted.SetHeldCheckpoint(predecessor); err != nil {
		return err
	}
	predecessorResult, err := vault.VerifyControlState(trusted, vault.VerificationRequest{Supplied: predecessor})
	if err != nil || predecessorResult.Outcome != vault.CheckpointCurrent {
		return ErrOnboardingChain
	}
	successorResult, err := vault.VerifyControlState(trusted, vault.VerificationRequest{Supplied: vault.ControlEvidence{
		Policy: bundle.SuccessorPolicy, Control: bundle.SuccessorControl, Certificates: bundle.PredecessorCertificates,
	}})
	if err != nil || successorResult.Outcome != vault.CheckpointDescendant {
		return ErrOnboardingChain
	}
	successorPolicy, err := vault.DecodePolicy(bundle.SuccessorPolicy)
	if err != nil {
		return err
	}
	device, err := coordinator.deps.DeviceKeys.LoadDeviceKeys(ctx, expectedVault, deviceID)
	if err != nil || device.DeviceID != deviceID || device.Recipient == nil || len(device.KeyID) == 0 {
		return ErrDeviceKeyMissing
	}
	if !servicePolicyHasRecipient(successorPolicy, deviceID, device.KeyID, device.Recipient.PublicKey().Bytes()) {
		return ErrOnboardingDeviceMismatch
	}
	if err := ensureNoConflictingOnboardingState(ctx, coordinator.deps.State, expectedVault); err != nil {
		return err
	}
	predecessorPolicyDigest, err := vault.ComputePolicyDigest(bundle.PredecessorPolicy)
	if err != nil {
		return err
	}
	position := state.AuthenticatedPositionEvidence{
		Vault: expectedVault, Epoch: successorControl.EpochSeq - 1, PolicyDigest: predecessorPolicyDigest,
		Policy: bytes.Clone(bundle.PredecessorPolicy), Control: bytes.Clone(bundle.PredecessorControl),
		Head: bytes.Clone(bundle.PredecessorHead), Snapshot: bytes.Clone(bundle.PredecessorSnapshot),
		Certificates: cloneServiceByteSlices(bundle.PredecessorCertificates),
	}
	checkpointState := state.VaultCheckpoint{
		Vault: expectedVault, Anchor: expectedAnchor, ControlCID: bytes.Clone(checkpoint.ControlCID), ControlBytes: bytes.Clone(bundle.SuccessorControl),
		SnapshotCID: bytes.Clone(checkpoint.SnapshotCID), Epoch: checkpoint.EpochSeq, PolicyDigest: checkpoint.PolicyDigest, RecordedAt: coordinator.deps.Clock().Unix(),
	}
	now := coordinator.deps.Clock().Unix()
	err = coordinator.deps.State.ImportVaultOnboarding(ctx, state.VaultSelection{Vault: expectedVault, DeviceID: deviceID, RecordedAt: now}, checkpointState, position)
	if errors.Is(err, state.ErrVaultSelectionExists) || errors.Is(err, state.ErrOnboardingStateConflict) {
		return ErrOnboardingStateConflict
	}
	return err
}

func (coordinator *Coordinator) freshAdministrativeMaterial(policy vault.Policy) ([]byte, []vault.RecipientWrapInput, [16]byte, [24]byte, error) {
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, nil, [16]byte{}, [24]byte{}, fmt.Errorf("generate administrative content key: %w", err)
	}
	var nonce [24]byte
	var publicationID [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		clear(contentKey)
		return nil, nil, publicationID, nonce, fmt.Errorf("generate administrative nonce: %w", err)
	}
	if _, err := rand.Read(publicationID[:]); err != nil {
		clear(contentKey)
		clear(nonce[:])
		return nil, nil, publicationID, nonce, fmt.Errorf("generate administrative publication identity: %w", err)
	}
	wraps, err := freshRecipientWraps(policy)
	if err != nil {
		clear(contentKey)
		clear(nonce[:])
		clear(publicationID[:])
		return nil, nil, [16]byte{}, [24]byte{}, err
	}
	return contentKey, wraps, publicationID, nonce, nil
}

func transitionStatus(outcome atproto.TransitionOutcome) StatusState {
	switch outcome {
	case atproto.TransitionOutcomeCommitted:
		return StatusCommitted
	case atproto.TransitionOutcomeFenceLost:
		return StatusFenceLost
	case atproto.TransitionOutcomeSuperseded:
		return StatusSuperseded
	case atproto.TransitionOutcomeUnavailable:
		return StatusUnavailable
	default:
		return StatusRejected
	}
}

func servicePolicyRole(policy vault.Policy, deviceID string, role vault.Role) bool {
	for _, binding := range policy.Roles {
		if binding.DeviceID == deviceID {
			return binding.Role == role
		}
	}
	return false
}

func servicePolicyHasRecipient(policy vault.Policy, deviceID string, keyID, publicKey []byte) bool {
	for _, recipient := range policy.Recipients {
		if recipient.DeviceID == deviceID && bytes.Equal(recipient.KeyID, keyID) && bytes.Equal(recipient.PublicKey[:], publicKey) {
			return true
		}
	}
	return false
}

func cloneServiceByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func rawVaultCID(data []byte) []byte {
	digest, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return nil
	}
	return cid.NewCidV1(cid.Raw, digest).Bytes()
}

func validateImportedCheckpointPredecessor(trust TrustMaterial) error {
	if !trust.ImportedCheckpoint || len(trust.Held.Policy) == 0 || len(trust.Held.Control) == 0 || trust.Checkpoint.Epoch == 0 {
		return ErrMissingPredecessorEvidence
	}
	policy, err := vault.DecodePolicy(trust.Held.Policy)
	if err != nil {
		return err
	}
	control, err := vault.DecodeControl(trust.Held.Control)
	if err != nil || policy.Vault != trust.Selection.Vault || control.Vault != trust.Selection.Vault || policy.EpochSeq+1 != trust.Checkpoint.Epoch || control.EpochSeq != policy.EpochSeq {
		return ErrOnboardingChain
	}
	checkpointControl, err := vault.DecodeControl(trust.Checkpoint.ControlBytes)
	if err != nil || checkpointControl.Vault != trust.Selection.Vault || checkpointControl.EpochSeq != trust.Checkpoint.Epoch || checkpointControl.PolicyDigest != trust.Checkpoint.PolicyDigest || !bytes.Equal(checkpointControl.PrevControlCID, rawVaultCID(trust.Held.Control)) || !bytes.Equal(checkpointControl.HeadSnapshotCID, trust.Checkpoint.SnapshotCID) || !bytes.Equal(trust.Checkpoint.ControlCID, rawVaultCID(trust.Checkpoint.ControlBytes)) {
		return ErrOnboardingChain
	}
	trusted := vault.NewTrustedContext(trust.Selection.Vault, trust.Anchor)
	if err := trusted.SetHeldCheckpoint(trust.Held); err != nil {
		return err
	}
	result, err := vault.VerifyControlState(trusted, vault.VerificationRequest{Supplied: trust.Held})
	if err != nil || result.Outcome != vault.CheckpointCurrent {
		return ErrOnboardingChain
	}
	return nil
}

func verifyImportedCheckpointRead(trust TrustMaterial, read atproto.ReadResult) error {
	if err := validateImportedCheckpointPredecessor(trust); err != nil {
		return err
	}
	policyBytes, err := vault.EncodePolicy(policyObject(read.Policy))
	if err != nil {
		return err
	}
	controlBytes, err := vault.EncodeControl(controlObject(read.Control))
	if err != nil {
		return err
	}
	policy, err := vault.DecodePolicy(policyBytes)
	if err != nil {
		return err
	}
	digest, err := vault.ComputePolicyDigest(policyBytes)
	if err != nil {
		return err
	}
	if read.EpochSeq != trust.Checkpoint.Epoch || policy.Vault != trust.Checkpoint.Vault || digest != trust.Checkpoint.PolicyDigest || policy.RecoveryAnchor == ([32]byte{}) || !bytes.Equal(trust.Checkpoint.ControlBytes, controlBytes) || !bytes.Equal(trust.Checkpoint.ControlCID, read.ControlCID) || !bytes.Equal(trust.Checkpoint.SnapshotCID, policyPositionSnapshot(controlBytes)) {
		return ErrOnboardingCheckpoint
	}
	return nil
}

func policyPositionSnapshot(controlBytes []byte) []byte {
	control, err := vault.DecodeControl(controlBytes)
	if err != nil {
		return nil
	}
	return bytes.Clone(control.HeadSnapshotCID)
}

func ensureNoConflictingOnboardingState(ctx context.Context, store *state.Store, vaultID [32]byte) error {
	selections, err := store.VaultSelections(ctx)
	if err != nil {
		return err
	}
	for _, selection := range selections {
		if selection.Vault == vaultID {
			return ErrOnboardingStateConflict
		}
	}
	if _, err := store.VaultCheckpoint(ctx, vaultID); err == nil {
		return ErrOnboardingStateConflict
	} else if !errors.Is(err, state.ErrVaultCheckpointNotFound) {
		return err
	}
	return nil
}
