package vault

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

type AttestationBuildRequest struct {
	VaultID                [32]byte
	TrustAnchor            [32]byte
	State                  ControlEvidence
	SignerCertificate      []byte
	SigningKey             ed25519.PrivateKey
	RetentionFloor         uint64
	RetainedRecoveryPoints uint16
}

type AttestationVerificationRequest struct {
	VaultID     [32]byte
	TrustAnchor [32]byte
	State       ControlEvidence
}

type AttestationStatus uint8

const (
	AttestationStatusMeetsPolicy AttestationStatus = iota + 1
	AttestationStatusBelowPolicyFloor
)

type AttestationJudgement struct {
	Attestation                   Attestation
	Status                        AttestationStatus
	CompromisedForConfidentiality bool
}

func BuildAttestation(request AttestationBuildRequest) ([]byte, error) {
	certificate, err := DecodeCertificate(request.SignerCertificate)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation signer certificate", ErrAuthorization)
	}
	state := request.State
	state.Certificates = certificatesWithSigner(state.Certificates, request.SignerCertificate)
	position, controlCID, err := verifyControlPositionEvidence(request.VaultID, request.TrustAnchor, state)
	if err != nil {
		return nil, err
	}
	certificate, err = authorizeAttestationSigner(certificate.DeviceID, certificate.KeyID, position, request.TrustAnchor, state.Certificates)
	if err != nil {
		return nil, err
	}
	if len(request.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(request.SigningKey.Public().(ed25519.PublicKey), certificate.SigningPublicKey[:]) {
		return nil, fmt.Errorf("%w: attestation signing key", ErrAuthorization)
	}
	attestation := Attestation{
		Vault: position.policy.Vault, DeviceID: certificate.DeviceID, PolicyDigest: position.policyDigest,
		RetentionFloor: request.RetentionFloor, RetainedRecoveryPoints: request.RetainedRecoveryPoints,
		ControlCID: bytes.Clone(controlCID), Signer: Signer{DeviceID: certificate.DeviceID, KeyID: bytes.Clone(certificate.KeyID)},
	}
	prefix, err := encodeAttestationPrefix(attestation)
	if err != nil {
		return nil, err
	}
	signature, err := Sign(contextForPurpose(PurposeAttestation), objectSignaturePreimage(prefix), request.SigningKey)
	if err != nil {
		return nil, err
	}
	copy(attestation.Signature[:], signature)
	return EncodeAttestation(attestation)
}

func VerifyAttestation(encoded []byte, request AttestationVerificationRequest) (AttestationJudgement, error) {
	position, controlCID, err := verifyControlPositionEvidence(request.VaultID, request.TrustAnchor, request.State)
	if err != nil {
		return AttestationJudgement{}, err
	}
	attestation, err := DecodeAttestation(encoded)
	if err != nil {
		return AttestationJudgement{}, err
	}
	if attestation.Vault != position.policy.Vault || attestation.PolicyDigest != position.policyDigest ||
		attestation.PolicyDigest != position.control.PolicyDigest || !bytes.Equal(attestation.ControlCID, controlCID) ||
		attestation.Signer.DeviceID != attestation.DeviceID {
		return AttestationJudgement{}, fmt.Errorf("%w: attestation state or subject", ErrAuthorization)
	}
	certificate, err := authorizeAttestationSigner(attestation.Signer.DeviceID, attestation.Signer.KeyID, position, request.TrustAnchor, request.State.Certificates)
	if err != nil {
		return AttestationJudgement{}, err
	}
	prefix, err := encodeAttestationPrefix(attestation)
	if err != nil {
		return AttestationJudgement{}, err
	}
	if err := Verify(contextForPurpose(PurposeAttestation), objectSignaturePreimage(prefix), attestation.Signature[:], certificate.SigningPublicKey[:]); err != nil {
		return AttestationJudgement{}, fmt.Errorf("%w: attestation", ErrSignature)
	}
	judgement := AttestationJudgement{Attestation: attestation, Status: AttestationStatusMeetsPolicy}
	if attestation.RetentionFloor < position.policy.PolicyRetentionFloor {
		judgement.Status = AttestationStatusBelowPolicyFloor
		judgement.CompromisedForConfidentiality = true
	}
	return judgement, nil
}

func authorizeAttestationSigner(deviceID string, keyID []byte, position authenticatedControlPosition, trustAnchor [32]byte, certificates [][]byte) (Certificate, error) {
	request := OpenRequest{
		Vault: position.policy.Vault, EpochSeq: position.control.EpochSeq, PolicyDigest: position.policyDigest,
		TrustAnchor: trustAnchor, Certificates: certificates,
	}
	certificate, err := resolveTrustedCertificate(deviceID, keyID, request)
	role, exists := policyRole(position.policy, deviceID)
	if err != nil || !exists || role != certificate.Role || signerRevoked(certificate, position.control) {
		return Certificate{}, fmt.Errorf("%w: attestation signer authorization", ErrAuthorization)
	}
	return certificate, nil
}

func certificatesWithSigner(certificates [][]byte, signerCertificate []byte) [][]byte {
	result := make([][]byte, len(certificates))
	found := false
	for index, certificate := range certificates {
		result[index] = bytes.Clone(certificate)
		if bytes.Equal(certificate, signerCertificate) {
			found = true
		}
	}
	if !found {
		result = append(result, bytes.Clone(signerCertificate))
	}
	return result
}
