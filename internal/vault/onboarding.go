package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/ipfs/go-cid"
)

const (
	OnboardingBundleVersion  uint64 = 1
	MaxOnboardingBundleBytes        = 2*(MaxEnvelopeBytes+(MaxRecipients+5)*MaxPolicyObjectBytes) + 1<<20
)

type OnboardingBundle struct {
	Version                 uint64
	Vault                   [32]byte
	Anchor                  [32]byte
	RecoveryAnchor          [32]byte
	Checkpoint              []byte
	SuccessorPolicy         []byte
	SuccessorControl        []byte
	PredecessorPolicy       []byte
	PredecessorControl      []byte
	PredecessorHead         []byte
	PredecessorSnapshot     []byte
	PredecessorCertificates [][]byte
}

type onboardingBundleWire struct {
	Version                 uint64   `json:"version"`
	Vault                   string   `json:"vault_id"`
	Anchor                  string   `json:"anchor_fingerprint"`
	RecoveryAnchor          string   `json:"recovery_anchor"`
	Checkpoint              string   `json:"successor_checkpoint"`
	SuccessorPolicy         string   `json:"successor_policy"`
	SuccessorControl        string   `json:"successor_control"`
	PredecessorPolicy       string   `json:"predecessor_policy"`
	PredecessorControl      string   `json:"predecessor_control"`
	PredecessorHead         string   `json:"predecessor_head"`
	PredecessorSnapshot     string   `json:"predecessor_snapshot"`
	PredecessorCertificates []string `json:"predecessor_certificates"`
}

func NewOnboardingBundle(vaultID, anchor [32]byte, checkpoint, successorPolicy, successorControl, predecessorPolicy, predecessorControl, predecessorHead, predecessorSnapshot []byte, predecessorCertificates [][]byte) (OnboardingBundle, error) {
	if err := validateOnboardingObjectSizes(checkpoint, successorPolicy, successorControl, predecessorPolicy, predecessorControl, predecessorHead); err != nil {
		return OnboardingBundle{}, err
	}
	if len(predecessorSnapshot) == 0 || len(predecessorSnapshot) > MaxEnvelopeBytes {
		return OnboardingBundle{}, fmt.Errorf("%w: onboarding predecessor snapshot size", ErrLimit)
	}
	policy, err := DecodePolicy(successorPolicy)
	if err != nil {
		return OnboardingBundle{}, fmt.Errorf("%w: onboarding successor policy", ErrFormat)
	}
	bundle := OnboardingBundle{
		Version: OnboardingBundleVersion, Vault: vaultID, Anchor: anchor, RecoveryAnchor: policy.RecoveryAnchor,
		Checkpoint: bytes.Clone(checkpoint), SuccessorPolicy: bytes.Clone(successorPolicy), SuccessorControl: bytes.Clone(successorControl),
		PredecessorPolicy: bytes.Clone(predecessorPolicy), PredecessorControl: bytes.Clone(predecessorControl),
		PredecessorHead: bytes.Clone(predecessorHead), PredecessorSnapshot: bytes.Clone(predecessorSnapshot),
		PredecessorCertificates: cloneByteSlices(predecessorCertificates),
	}
	sortOnboardingCertificates(bundle.PredecessorCertificates)
	if err := validateOnboardingBundle(bundle); err != nil {
		return OnboardingBundle{}, err
	}
	return bundle, nil
}

func EncodeOnboardingBundle(bundle OnboardingBundle) ([]byte, error) {
	if err := validateOnboardingBundle(bundle); err != nil {
		return nil, err
	}
	wire := onboardingBundleWire{
		Version: bundle.Version, Vault: hex.EncodeToString(bundle.Vault[:]), Anchor: hex.EncodeToString(bundle.Anchor[:]),
		RecoveryAnchor: hex.EncodeToString(bundle.RecoveryAnchor[:]), Checkpoint: hex.EncodeToString(bundle.Checkpoint),
		SuccessorPolicy: hex.EncodeToString(bundle.SuccessorPolicy), SuccessorControl: hex.EncodeToString(bundle.SuccessorControl),
		PredecessorPolicy: hex.EncodeToString(bundle.PredecessorPolicy), PredecessorControl: hex.EncodeToString(bundle.PredecessorControl),
		PredecessorHead: hex.EncodeToString(bundle.PredecessorHead), PredecessorSnapshot: hex.EncodeToString(bundle.PredecessorSnapshot),
		PredecessorCertificates: make([]string, len(bundle.PredecessorCertificates)),
	}
	for index, certificate := range bundle.PredecessorCertificates {
		wire.PredecessorCertificates[index] = hex.EncodeToString(certificate)
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: onboarding bundle encoding", ErrFormat)
	}
	if len(encoded) > MaxOnboardingBundleBytes {
		return nil, fmt.Errorf("%w: onboarding bundle", ErrLimit)
	}
	return encoded, nil
}

func DecodeOnboardingBundle(encoded []byte) (OnboardingBundle, error) {
	if len(encoded) == 0 || len(encoded) > MaxOnboardingBundleBytes {
		return OnboardingBundle{}, fmt.Errorf("%w: onboarding bundle", ErrLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire onboardingBundleWire
	if err := decoder.Decode(&wire); err != nil {
		return OnboardingBundle{}, fmt.Errorf("%w: onboarding bundle JSON", ErrFormat)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return OnboardingBundle{}, fmt.Errorf("%w: onboarding bundle trailing value", ErrFormat)
	}
	if wire.Version != OnboardingBundleVersion {
		return OnboardingBundle{}, fmt.Errorf("%w: onboarding bundle version", ErrUnsupportedVersion)
	}
	vaultBytes, err := decodeOnboardingHex(wire.Vault, 32, "vault id")
	if err != nil {
		return OnboardingBundle{}, err
	}
	anchorBytes, err := decodeOnboardingHex(wire.Anchor, 32, "anchor fingerprint")
	if err != nil {
		return OnboardingBundle{}, err
	}
	recoveryAnchorBytes, err := decodeOnboardingHex(wire.RecoveryAnchor, 32, "recovery anchor")
	if err != nil {
		return OnboardingBundle{}, err
	}
	checkpoint, err := decodeOnboardingObject(wire.Checkpoint, "successor checkpoint", MaxPolicyObjectBytes)
	if err != nil {
		return OnboardingBundle{}, err
	}
	successorPolicy, err := decodeOnboardingObject(wire.SuccessorPolicy, "successor policy", MaxPolicyObjectBytes)
	if err != nil {
		return OnboardingBundle{}, err
	}
	successorControl, err := decodeOnboardingObject(wire.SuccessorControl, "successor control", MaxPolicyObjectBytes)
	if err != nil {
		return OnboardingBundle{}, err
	}
	predecessorPolicy, err := decodeOnboardingObject(wire.PredecessorPolicy, "predecessor policy", MaxPolicyObjectBytes)
	if err != nil {
		return OnboardingBundle{}, err
	}
	predecessorControl, err := decodeOnboardingObject(wire.PredecessorControl, "predecessor control", MaxPolicyObjectBytes)
	if err != nil {
		return OnboardingBundle{}, err
	}
	predecessorHead, err := decodeOnboardingObject(wire.PredecessorHead, "predecessor head", MaxPolicyObjectBytes)
	if err != nil {
		return OnboardingBundle{}, err
	}
	predecessorSnapshot, err := decodeOnboardingObject(wire.PredecessorSnapshot, "predecessor snapshot", MaxEnvelopeBytes)
	if err != nil {
		return OnboardingBundle{}, err
	}
	if len(wire.PredecessorCertificates) == 0 || len(wire.PredecessorCertificates) > MaxRecipients {
		return OnboardingBundle{}, fmt.Errorf("%w: onboarding predecessor certificate count", ErrLimit)
	}
	certificates := make([][]byte, len(wire.PredecessorCertificates))
	for index, encodedCertificate := range wire.PredecessorCertificates {
		certificates[index], err = decodeOnboardingObject(encodedCertificate, "predecessor certificate", MaxPolicyObjectBytes)
		if err != nil {
			return OnboardingBundle{}, err
		}
	}
	bundle := OnboardingBundle{
		Version: wire.Version, Checkpoint: checkpoint, SuccessorPolicy: successorPolicy, SuccessorControl: successorControl,
		PredecessorPolicy: predecessorPolicy, PredecessorControl: predecessorControl, PredecessorHead: predecessorHead,
		PredecessorSnapshot: predecessorSnapshot, PredecessorCertificates: certificates,
	}
	copy(bundle.Vault[:], vaultBytes)
	copy(bundle.Anchor[:], anchorBytes)
	copy(bundle.RecoveryAnchor[:], recoveryAnchorBytes)
	if err := validateOnboardingBundle(bundle); err != nil {
		return OnboardingBundle{}, err
	}
	canonical, err := EncodeOnboardingBundle(bundle)
	if err != nil {
		return OnboardingBundle{}, err
	}
	if !bytes.Equal(canonical, encoded) {
		return OnboardingBundle{}, fmt.Errorf("%w: non-canonical onboarding bundle", ErrFormat)
	}
	return bundle, nil
}

func validateOnboardingObjectSizes(objects ...[]byte) error {
	for _, object := range objects {
		if len(object) == 0 || len(object) > MaxPolicyObjectBytes {
			return fmt.Errorf("%w: onboarding bundle object size", ErrLimit)
		}
	}
	return nil
}

func decodeOnboardingHex(value string, expectedLength int, field string) ([]byte, error) {
	if len(value) != expectedLength*2 {
		return nil, fmt.Errorf("%w: onboarding bundle %s length", ErrFormat, field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: onboarding bundle %s encoding", ErrFormat, field)
	}
	return decoded, nil
}

func decodeOnboardingObject(value, field string, maxLength int) ([]byte, error) {
	if len(value) == 0 || len(value) > 2*maxLength {
		return nil, fmt.Errorf("%w: onboarding bundle %s size", ErrLimit, field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: onboarding bundle %s encoding", ErrFormat, field)
	}
	if len(decoded) == 0 || len(decoded) > maxLength {
		return nil, fmt.Errorf("%w: onboarding bundle %s size", ErrLimit, field)
	}
	return decoded, nil
}

func sortOnboardingCertificates(certificates [][]byte) {
	sort.Slice(certificates, func(i, j int) bool {
		left, _ := DecodeCertificate(certificates[i])
		right, _ := DecodeCertificate(certificates[j])
		if left.DeviceID != right.DeviceID {
			return left.DeviceID < right.DeviceID
		}
		return bytes.Compare(left.KeyID, right.KeyID) < 0
	})
}

func validateOnboardingBundle(bundle OnboardingBundle) error {
	if bundle.Version != OnboardingBundleVersion {
		return fmt.Errorf("%w: onboarding bundle version", ErrUnsupportedVersion)
	}
	if err := validateOnboardingObjectSizes(bundle.Checkpoint, bundle.SuccessorPolicy, bundle.SuccessorControl, bundle.PredecessorPolicy, bundle.PredecessorControl, bundle.PredecessorHead); err != nil {
		return err
	}
	if len(bundle.PredecessorSnapshot) == 0 || len(bundle.PredecessorSnapshot) > MaxEnvelopeBytes || len(bundle.PredecessorCertificates) == 0 || len(bundle.PredecessorCertificates) > MaxRecipients {
		return fmt.Errorf("%w: onboarding predecessor evidence bounds", ErrLimit)
	}
	for _, certificate := range bundle.PredecessorCertificates {
		if len(certificate) == 0 || len(certificate) > MaxPolicyObjectBytes {
			return fmt.Errorf("%w: onboarding predecessor certificate size", ErrLimit)
		}
	}
	checkpoint, err := DecodeCheckpoint(bundle.Checkpoint)
	if err != nil {
		return fmt.Errorf("%w: onboarding checkpoint", ErrFormat)
	}
	successorPolicy, err := DecodePolicy(bundle.SuccessorPolicy)
	if err != nil {
		return fmt.Errorf("%w: onboarding successor policy", ErrFormat)
	}
	successorControl, err := DecodeControl(bundle.SuccessorControl)
	if err != nil {
		return fmt.Errorf("%w: onboarding successor control", ErrFormat)
	}
	predecessorPolicy, err := DecodePolicy(bundle.PredecessorPolicy)
	if err != nil {
		return fmt.Errorf("%w: onboarding predecessor policy", ErrFormat)
	}
	predecessorControl, err := DecodeControl(bundle.PredecessorControl)
	if err != nil {
		return fmt.Errorf("%w: onboarding predecessor control", ErrFormat)
	}
	predecessorHead, err := DecodeHead(bundle.PredecessorHead)
	if err != nil {
		return fmt.Errorf("%w: onboarding predecessor head", ErrFormat)
	}
	predecessorSnapshot, err := DecodeEnvelope(bundle.PredecessorSnapshot)
	if err != nil {
		return fmt.Errorf("%w: onboarding predecessor snapshot", ErrFormat)
	}
	if checkpoint.Vault != bundle.Vault || successorPolicy.Vault != bundle.Vault || successorControl.Vault != bundle.Vault || predecessorPolicy.Vault != bundle.Vault || predecessorControl.Vault != bundle.Vault || predecessorHead.Vault != bundle.Vault || predecessorSnapshot.Vault != bundle.Vault {
		return fmt.Errorf("%w: onboarding vault binding", ErrAuthorization)
	}
	if checkpoint.Anchor != bundle.Anchor {
		return fmt.Errorf("%w: onboarding root anchor binding", ErrCheckpointAnchor)
	}
	if checkpoint.Signer.DeviceID != "recovery-kit" || !bytes.Equal(checkpoint.Signer.KeyID, bundle.RecoveryAnchor[:]) {
		return fmt.Errorf("%w: onboarding checkpoint recovery signer binding", ErrAuthorization)
	}
	if successorPolicy.RecoveryAnchor != bundle.RecoveryAnchor || predecessorPolicy.RecoveryAnchor != bundle.RecoveryAnchor {
		return fmt.Errorf("%w: onboarding recovery anchor binding", ErrAuthorization)
	}
	successorEpoch := checkpoint.EpochSeq
	if successorEpoch == 0 || successorPolicy.EpochSeq != successorEpoch || successorControl.EpochSeq != successorEpoch || predecessorPolicy.EpochSeq+1 != successorEpoch || predecessorControl.EpochSeq+1 != successorEpoch || predecessorHead.EpochSeq != predecessorPolicy.EpochSeq || predecessorSnapshot.EpochSeq != predecessorPolicy.EpochSeq {
		return fmt.Errorf("%w: onboarding epoch relation", ErrTransitionEpoch)
	}
	successorDigest, err := ComputePolicyDigest(bundle.SuccessorPolicy)
	if err != nil {
		return fmt.Errorf("%w: onboarding successor policy digest", ErrAuthorization)
	}
	predecessorDigest, err := ComputePolicyDigest(bundle.PredecessorPolicy)
	if err != nil {
		return fmt.Errorf("%w: onboarding predecessor policy digest", ErrAuthorization)
	}
	if checkpoint.PolicyDigest != successorDigest || successorControl.PolicyDigest != successorDigest || predecessorControl.PolicyDigest != predecessorDigest || predecessorHead.PolicyDigest != predecessorDigest || predecessorSnapshot.PolicyDigest != predecessorDigest || successorPolicy.PrevPolicyDigest != predecessorDigest {
		return fmt.Errorf("%w: onboarding policy digest relation", ErrPolicyAncestry)
	}
	if checkpoint.SnapshotCID == nil || !bytes.Equal(checkpoint.SnapshotCID, successorControl.HeadSnapshotCID) {
		return fmt.Errorf("%w: onboarding successor snapshot binding", ErrHeadLinkage)
	}
	successorControlCID, err := rawCID(bundle.SuccessorControl)
	if err != nil || !bytes.Equal(checkpoint.ControlCID, successorControlCID) {
		return fmt.Errorf("%w: onboarding successor control binding", ErrHeadLinkage)
	}
	predecessorControlCID, err := rawCID(bundle.PredecessorControl)
	if err != nil || !bytes.Equal(successorControl.PrevControlCID, predecessorControlCID) {
		return fmt.Errorf("%w: onboarding predecessor control binding", ErrControlAncestry)
	}
	predecessorSnapshotCID, err := rawCID(bundle.PredecessorSnapshot)
	if err != nil || predecessorSnapshot.Purpose != PurposeSnapshot || !bytes.Equal(predecessorHead.SnapshotCID, predecessorSnapshotCID) || !bytes.Equal(predecessorHead.BlobCID, predecessorSnapshotCID) || !bytes.Equal(predecessorSnapshot.Parent, predecessorHead.PrevHeadCID) || predecessorHead.PublicationCount == 0 && !bytes.Equal(predecessorControl.HeadSnapshotCID, predecessorHead.SnapshotCID) {
		return fmt.Errorf("%w: onboarding predecessor snapshot binding", ErrHeadLinkage)
	}
	if _, err := cid.Cast(checkpoint.ControlCID); err != nil {
		return fmt.Errorf("%w: onboarding checkpoint control CID", ErrFormat)
	}
	if err := validateOnboardingCertificates(bundle); err != nil {
		return err
	}
	if err := validateOnboardingPositionSignatures(bundle); err != nil {
		return err
	}
	return nil
}

func validateOnboardingCertificates(bundle OnboardingBundle) error {
	policy, _ := DecodePolicy(bundle.PredecessorPolicy)
	certificates := make([]Certificate, len(bundle.PredecessorCertificates))
	for index, encoded := range bundle.PredecessorCertificates {
		certificate, err := DecodeCertificate(encoded)
		if err != nil || certificate.Vault != bundle.Vault {
			return fmt.Errorf("%w: onboarding predecessor certificate", ErrAuthorization)
		}
		if index > 0 {
			previous := certificates[index-1]
			if previous.DeviceID > certificate.DeviceID || previous.DeviceID == certificate.DeviceID && bytes.Compare(previous.KeyID, certificate.KeyID) >= 0 {
				return fmt.Errorf("%w: onboarding predecessor certificate ordering", ErrFormat)
			}
		}
		certificates[index] = certificate
	}
	if len(certificates) != len(policy.Recipients) {
		return fmt.Errorf("%w: onboarding predecessor certificate set", ErrTransitionRecipients)
	}
	for _, recipient := range policy.Recipients {
		found := false
		for _, certificate := range certificates {
			role, roleExists := policyRole(policy, recipient.DeviceID)
			if roleExists && certificate.DeviceID == recipient.DeviceID && bytes.Equal(certificate.KeyID, recipient.KeyID) && certificate.Role == role && certificate.EncryptionPublicKey == recipient.PublicKey && certificate.CertEpoch <= policy.EpochSeq {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: onboarding predecessor certificate recipient mismatch", ErrTransitionRecipients)
		}
	}
	request := OpenRequest{Vault: bundle.Vault, EpochSeq: policy.EpochSeq, TrustAnchor: bundle.Anchor, Certificates: bundle.PredecessorCertificates}
	for _, certificate := range certificates {
		if err := verifyCertificateChain(certificate, request, 1, make(map[string]bool)); err != nil {
			return fmt.Errorf("%w: onboarding predecessor certificate chain", ErrAuthorization)
		}
	}
	return nil
}

func validateOnboardingPositionSignatures(bundle OnboardingBundle) error {
	policy, err := DecodePolicy(bundle.PredecessorPolicy)
	if err != nil {
		return err
	}
	request := OpenRequest{Vault: bundle.Vault, EpochSeq: policy.EpochSeq, TrustAnchor: bundle.Anchor, Certificates: bundle.PredecessorCertificates}
	head, err := DecodeHead(bundle.PredecessorHead)
	if err != nil {
		return err
	}
	headSigner, err := resolveTrustedCertificate(head.Signer.DeviceID, head.Signer.KeyID, request)
	if err != nil || headSigner.Role != policyRoleMust(policy, headSigner.DeviceID) || !roleAllowed(PurposeSnapshot, headSigner.Role) {
		return fmt.Errorf("%w: onboarding predecessor head signer", ErrAuthorization)
	}
	if len(bundle.PredecessorHead) < ed25519.SignatureSize || Verify("dottie/v1/sig-head", append([]byte(preimageSig), bundle.PredecessorHead[:len(bundle.PredecessorHead)-ed25519.SignatureSize]...), head.Signature[:], headSigner.SigningPublicKey[:]) != nil {
		return fmt.Errorf("%w: onboarding predecessor head signature", ErrSignature)
	}
	envelope, err := DecodeEnvelope(bundle.PredecessorSnapshot)
	if err != nil {
		return err
	}
	snapshotSigner, err := resolveTrustedCertificate(envelope.DeviceID, envelope.KeyID, request)
	if err != nil || snapshotSigner.Role != policyRoleMust(policy, snapshotSigner.DeviceID) || !roleAllowed(PurposeSnapshot, snapshotSigner.Role) {
		return fmt.Errorf("%w: onboarding predecessor snapshot signer", ErrAuthorization)
	}
	if len(bundle.PredecessorSnapshot) < ed25519.SignatureSize || Verify("dottie/v1/sig-snapshot", append([]byte(preimageSig), bundle.PredecessorSnapshot[:len(bundle.PredecessorSnapshot)-ed25519.SignatureSize]...), envelope.Signature[:], snapshotSigner.SigningPublicKey[:]) != nil {
		return fmt.Errorf("%w: onboarding predecessor snapshot signature", ErrSignature)
	}
	return nil
}
