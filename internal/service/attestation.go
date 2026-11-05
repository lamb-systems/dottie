package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/vault"
)

type AttestationPublicationResult struct {
	Status     StatusState
	RKey       string
	RecordCID  string
	CommitCID  string
	Idempotent bool
}

var ErrAttestationInventoryIncomplete = errors.New("retention attestation inventory is unknown or incomplete")

func (coordinator *Coordinator) PublishAttestation(ctx context.Context, requested VaultSelection, signedBytes []byte) (AttestationPublicationResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return AttestationPublicationResult{}, err
	}
	defer coordinator.mu.Unlock()

	selected, err := coordinator.selectVault(ctx, requested)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	trust, pulled, err := coordinator.attestationContextLocked(ctx, selected)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	predecessor, err := publicationPredecessor(pulled.Read, trust.Anchor)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	if _, _, err := coordinator.retentionAttestationInventory(ctx, selected, policy); err != nil {
		return AttestationPublicationResult{}, err
	}
	return coordinator.publishAttestationLocked(ctx, selected, trust, pulled, signedBytes)
}

func (coordinator *Coordinator) PublishRetentionAttestation(ctx context.Context, requested VaultSelection) (AttestationPublicationResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return AttestationPublicationResult{}, err
	}
	defer coordinator.mu.Unlock()

	selected, err := coordinator.selectVault(ctx, requested)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	trust, pulled, err := coordinator.attestationContextLocked(ctx, selected)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	predecessor, err := publicationPredecessor(pulled.Read, trust.Anchor)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	policy, err := vault.DecodePolicy(predecessor.Policy)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	floor, recoveryPoints, err := coordinator.retentionAttestationInventory(ctx, selected, policy)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	certificate, found := serviceCertificateForSigner(predecessor.Certificates, selected.DeviceID, trust.Device.KeyID)
	if !found {
		return AttestationPublicationResult{}, ErrDeviceKeyMissing
	}
	certificateBytes, err := vault.EncodeCertificate(certificate)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	signedBytes, err := vault.BuildAttestation(vault.AttestationBuildRequest{
		VaultID: selected.Vault, TrustAnchor: trust.Anchor,
		State:             vault.ControlEvidence{Policy: predecessor.Policy, Control: predecessor.Control, Certificates: predecessor.Certificates},
		SignerCertificate: certificateBytes,
		SigningKey:        trust.Device.Signing, RetentionFloor: floor,
		RetainedRecoveryPoints: uint16(len(recoveryPoints)), RecoveryPoints: recoveryPoints,
	})
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	return coordinator.publishAttestationLocked(ctx, selected, trust, pulled, signedBytes)
}

func (coordinator *Coordinator) retentionAttestationInventory(ctx context.Context, selected VaultSelection, policy vault.Policy) (uint64, []vault.RetentionRecoveryPoint, error) {
	inventory, err := coordinator.deps.State.RetentionInventory(ctx, selected.Vault, selected.DeviceID)
	if err != nil {
		return 0, nil, err
	}
	floors := retentionFloors(inventory, policy.PolicyRetentionFloor)
	if floors.Status == RetentionFloorUnknown || floors.Status == RetentionFloorNoMaterial || !floors.HasConfidentialityFloor || len(inventory.Points) == 0 || len(inventory.Points) > int(^uint16(0)) {
		return 0, nil, ErrAttestationInventoryIncomplete
	}
	recoveryPoints := make([]vault.RetentionRecoveryPoint, 0, len(inventory.Points))
	for _, point := range inventory.Points {
		if !point.InventoryComplete {
			return 0, nil, ErrAttestationInventoryIncomplete
		}
		bodyCount := 0
		for _, material := range inventory.Materials {
			if material.Epoch != point.Epoch || !bytes.Equal(material.SnapshotCID, point.SnapshotCID) {
				continue
			}
			if !material.InventoryComplete {
				return 0, nil, ErrAttestationInventoryIncomplete
			}
			if material.PayloadReference == "" {
				continue
			}
			if !payloadReferenceMatchesCID(material.PayloadReference, point.SnapshotCID) {
				return 0, nil, ErrAttestationInventoryIncomplete
			}
			body, err := coordinator.deps.State.Payload(material.PayloadReference)
			if err != nil || !bytes.Equal(rawVaultCID(body), point.SnapshotCID) {
				return 0, nil, ErrAttestationInventoryIncomplete
			}
			bodyCount++
		}
		if bodyCount != 1 {
			return 0, nil, ErrAttestationInventoryIncomplete
		}
		recoveryPoints = append(recoveryPoints, vault.RetentionRecoveryPoint{
			Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID),
			PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID),
		})
	}
	return floors.ConfidentialityFloor, recoveryPoints, nil
}

func (coordinator *Coordinator) attestationContextLocked(ctx context.Context, selected VaultSelection) (TrustMaterial, ReadOutcome, error) {
	if coordinator.deps.Trust == nil || coordinator.deps.Publisher == nil {
		return TrustMaterial{}, ReadOutcome{}, errors.New("attestation publication ports are unavailable")
	}
	trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
	if err != nil {
		return TrustMaterial{}, ReadOutcome{}, err
	}
	if trust.Selection != selected || trust.Device.DeviceID != selected.DeviceID || len(trust.Device.Signing) != ed25519.PrivateKeySize {
		return TrustMaterial{}, ReadOutcome{}, ErrDeviceKeyMissing
	}
	pulled, err := coordinator.pullLockedWithTrust(ctx, selected, &trust)
	if err != nil {
		return TrustMaterial{}, ReadOutcome{}, err
	}
	if pulled.Currency.Outcome != vault.CheckpointCurrent && pulled.Currency.Outcome != vault.CheckpointDescendant || pulled.InspectOnly {
		return TrustMaterial{}, ReadOutcome{}, ErrCheckpointNotCurrent
	}
	return trust, pulled, nil
}

func (coordinator *Coordinator) publishAttestationLocked(ctx context.Context, selected VaultSelection, trust TrustMaterial, pulled ReadOutcome, signedBytes []byte) (AttestationPublicationResult, error) {
	predecessor, err := publicationPredecessor(pulled.Read, trust.Anchor)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	attestation, err := vault.DecodeAttestation(signedBytes)
	if err != nil {
		return AttestationPublicationResult{}, fmt.Errorf("%w: attestation object", atproto.ErrBatchRejected)
	}
	if attestation.DeviceID != selected.DeviceID || attestation.Signer.DeviceID != selected.DeviceID || !bytes.Equal(attestation.Signer.KeyID, trust.Device.KeyID) {
		return AttestationPublicationResult{}, fmt.Errorf("%w: attestation subject is not the selected local device", atproto.ErrBatchRejected)
	}
	certificate, found := serviceCertificateForSigner(predecessor.Certificates, selected.DeviceID, trust.Device.KeyID)
	if !found || !bytes.Equal(trust.Device.Signing.Public().(ed25519.PublicKey), certificate.SigningPublicKey[:]) {
		return AttestationPublicationResult{}, ErrDeviceKeyMissing
	}
	verification := vault.AttestationVerificationRequest{
		VaultID: selected.Vault, TrustAnchor: trust.Anchor,
		State: vault.ControlEvidence{Policy: predecessor.Policy, Control: predecessor.Control, Certificates: predecessor.Certificates},
	}
	if _, err := vault.VerifyAttestation(signedBytes, verification); err != nil {
		return AttestationPublicationResult{}, fmt.Errorf("%w: attestation signature or current control context", atproto.ErrBatchRejected)
	}
	publicationIO, err := coordinator.deps.Publisher.PublicationIO(ctx, selected, trust, pulled)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	if publicationIO.Transport == nil || publicationIO.DID == "" {
		return AttestationPublicationResult{}, errors.New("attestation publication transport and account DID are required")
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
		return AttestationPublicationResult{}, err
	}
	if len(previousPolicy) != 0 {
		publicationIO.PreviousPolicies = [][]byte{previousPolicy}
		publicationIO.PreviousControls = [][]byte{previousControl}
	}
	result, err := atproto.PublishAttestation(ctx, publicationIO, selected.DeviceID, trust.Device.KeyID, signedBytes)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	return AttestationPublicationResult{
		Status: StatusCommitted, RKey: result.RKey, RecordCID: result.RecordCID,
		CommitCID: result.CommitCID, Idempotent: result.Idempotent,
	}, nil
}

func serviceCertificateForSigner(certificates [][]byte, deviceID string, keyID []byte) (vault.Certificate, bool) {
	for _, encoded := range certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		if err != nil {
			continue
		}
		if certificate.DeviceID == deviceID && bytes.Equal(certificate.KeyID, keyID) {
			return certificate, true
		}
	}
	return vault.Certificate{}, false
}
