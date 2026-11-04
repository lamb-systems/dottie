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

func (coordinator *Coordinator) PublishAttestation(ctx context.Context, requested VaultSelection, signedBytes []byte) (AttestationPublicationResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return AttestationPublicationResult{}, err
	}
	defer coordinator.mu.Unlock()

	selected, err := coordinator.selectVault(ctx, requested)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	if coordinator.deps.Trust == nil || coordinator.deps.Publisher == nil {
		return AttestationPublicationResult{}, errors.New("attestation publication ports are unavailable")
	}
	trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	if trust.Selection != selected || trust.Device.DeviceID != selected.DeviceID || len(trust.Device.Signing) != ed25519.PrivateKeySize {
		return AttestationPublicationResult{}, ErrDeviceKeyMissing
	}
	pulled, err := coordinator.pullLockedWithTrust(ctx, selected, &trust)
	if err != nil {
		return AttestationPublicationResult{}, err
	}
	if pulled.Currency.Outcome != vault.CheckpointCurrent && pulled.Currency.Outcome != vault.CheckpointDescendant || pulled.InspectOnly {
		return AttestationPublicationResult{}, ErrCheckpointNotCurrent
	}
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
