package vault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/multiformats/go-multihash"
)

var (
	ErrPredecessor           = errors.New("transition predecessor verification failed")
	ErrObservedRevision      = errors.New("transition observed revision changed")
	ErrProposerRole          = errors.New("transition proposer is not authorized")
	ErrTransitionEpoch       = errors.New("transition epoch sequence is invalid")
	ErrPolicyAncestry        = errors.New("transition policy ancestry is invalid")
	ErrControlAncestry       = errors.New("transition control ancestry is invalid")
	ErrCertificateAuthority  = errors.New("transition certificate authority is invalid")
	ErrTransitionRecipients  = errors.New("transition recipients are invalid")
	ErrTransitionDelta       = errors.New("transition changes more than the requested enrollment")
	ErrRevokedDevice         = errors.New("device is revoked at the successor epoch")
	ErrPublicationAuthority  = errors.New("publication signer is not authorized by the current policy")
	ErrPublicationCount      = errors.New("publication count is not the predecessor count plus one")
	ErrPublicationHead       = errors.New("publication head does not match its predecessor")
	ErrEpochRotationRequired = errors.New("publication requires epoch rotation because max_epoch_age is reached")
	ErrEpochFirstSeenMissing = errors.New("publication requires epoch rotation because local first-seen state is missing")
	ErrSnapshotEpoch         = errors.New("transition snapshot epoch is invalid")
	ErrHeadLinkage           = errors.New("transition head linkage is invalid")
	ErrCheckpointAnchor      = errors.New("transition checkpoint anchor is invalid")
	ErrTransitionSignature   = errors.New("transition object signature is invalid")
	ErrTransitionDigest      = errors.New("transition digest is invalid")
	ErrEnrollmentApproval    = errors.New("enrollment approval does not match public device input")
	ErrUnsupportedTransition = errors.New("transition kind is unsupported")
)

const (
	TransitionEnroll TransitionKind = 1 + iota
	TransitionPolicyChange
	TransitionRevoke
	TransitionRotate
	TransitionRootRotation
)

type TransitionKind uint8

type DeviceMaterial struct {
	DeviceID  string
	KeyID     []byte
	Signing   ed25519.PrivateKey
	Recipient *ecdh.PrivateKey
}

type BootstrapResult struct {
	Vault       [32]byte
	Anchor      [32]byte
	Policy      []byte
	Control     []byte
	Certificate []byte
	Checkpoint  []byte
}

type GenesisIntent struct {
	Kit           []byte
	VaultName     string
	RootDevice    DeviceMaterial
	ContentKey    []byte
	Wraps         []RecipientWrapInput
	PublicationID [16]byte
	Nonce         [24]byte
}

type Genesis struct {
	BootstrapResult
	Head         []byte
	Snapshot     []byte
	SnapshotCID  []byte
	ControlCID   []byte
	PolicyDigest [32]byte
}

type GenesisDefaults struct {
	PolicyRetentionFloor   uint64
	RetainedRecoveryPoints uint16
	MaxPublications        uint32
	MaxEpochAge            uint32
}

func GenesisPolicyDefaults() GenesisDefaults {
	return GenesisDefaults{PolicyRetentionFloor: 0, RetainedRecoveryPoints: 3, MaxPublications: 100, MaxEpochAge: 86400}
}

type Predecessor struct {
	ControlCID   []byte
	PolicyDigest [32]byte
	EpochSeq     uint64
	HeadCID      []byte
	Head         []byte
	Control      []byte
	Policy       []byte
	Certificates [][]byte
	TrustAnchor  [32]byte
}

type PredecessorRef struct {
	ControlCID   []byte
	PolicyDigest [32]byte
	EpochSeq     uint64
	HeadCID      []byte
}

type RecipientWrapInput struct {
	KeyID            []byte
	EphemeralPrivate [32]byte
	WrapNonce        [24]byte
}

type TransitionIntent struct {
	Kind           TransitionKind
	Vault          [32]byte
	Signer         DeviceMaterial
	NewDevice      *DeviceMaterial
	RevokeDeviceID string
	RequestedRole  Role
	ContentKey     []byte
	Recipients     [][]byte
	Wraps          []RecipientWrapInput
	Plaintext      []byte
	PublicationID  [16]byte
	Nonce          [24]byte
}

type PublicDeviceInput struct {
	DeviceID           string
	KeyID              []byte
	SigningPublicKey   []byte
	RecipientPublicKey []byte
}

type PublicEnrollmentIntent struct {
	Vault               [32]byte
	RootSigner          DeviceMaterial
	NewDevice           PublicDeviceInput
	RequestedRole       Role
	ApprovalFingerprint [32]byte
	ContentKey          []byte
	Recipients          [][]byte
	Wraps               []RecipientWrapInput
	Plaintext           []byte
	PublicationID       [16]byte
	Nonce               [24]byte
}

type Transition struct {
	Kind        TransitionKind
	Predecessor PredecessorRef
	Policy      []byte
	Control     []byte
	Certificate []byte
	Head        []byte
	Snapshot    []byte
	SnapshotCID []byte
	BlobCID     []byte
	Recipients  [][]byte
	Checkpoint  []byte
	Digest      [32]byte
}

type EpochFirstSeenStore interface {
	VaultEpochFirstSeen(context.Context, [32]byte, uint64) (int64, bool, error)
}

type PublicationIntent struct {
	Vault          [32]byte
	Signer         DeviceMaterial
	ContentKey     []byte
	Wraps          []RecipientWrapInput
	Plaintext      []byte
	PublicationID  [16]byte
	Nonce          [24]byte
	EpochFirstSeen EpochFirstSeenStore
	Clock          func() time.Time
}

type PublicationAgeTriggerStatus string

const (
	PublicationAgeTriggerEvaluated                  PublicationAgeTriggerStatus = "evaluated"
	PublicationAgeTriggerNotEvaluatedNoTrustedClock PublicationAgeTriggerStatus = "not-evaluated-no-trusted-clock"
)

type Publication struct {
	Predecessor      PredecessorRef
	PolicyDigest     [32]byte
	Head             []byte
	Snapshot         []byte
	SnapshotCID      []byte
	BlobCID          []byte
	Digest           [32]byte
	AgeTriggerStatus PublicationAgeTriggerStatus
}

func GenerateDeviceKeys() (ed25519.PrivateKey, *ecdh.PrivateKey, error) {
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate device signing key: %w", err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate device recipient key: %w", err)
	}
	return signing, recipient, nil
}

func Bootstrap(kit []byte, vaultName string, rootDevice DeviceMaterial) (BootstrapResult, error) {
	if len(kit) != 32 || vaultName == "" || !utf8.ValidString(vaultName) {
		return BootstrapResult{}, fmt.Errorf("%w: kit or vault name", ErrFormat)
	}
	if err := validateDeviceMaterial(rootDevice); err != nil {
		return BootstrapResult{}, err
	}
	vaultID, err := deriveVaultID(kit, vaultName)
	if err != nil {
		return BootstrapResult{}, err
	}
	rootPublic := rootDevice.Signing.Public().(ed25519.PublicKey)
	anchor := sha256.Sum256(rootPublic)
	kitPrivate, err := deriveKitSigningKey(kit, vaultID)
	if err != nil {
		return BootstrapResult{}, err
	}
	kitFingerprint := sha256.Sum256(kitPrivate.Public().(ed25519.PublicKey))
	rootRecipient := rootDevice.Recipient.PublicKey().Bytes()
	var recipientPublic [32]byte
	copy(recipientPublic[:], rootRecipient)

	certificate := Certificate{
		Vault: vaultID, DeviceID: rootDevice.DeviceID, KeyID: bytes.Clone(rootDevice.KeyID),
		SigningPublicKey: [ed25519.PublicKeySize]byte(rootPublic), EncryptionPublicKey: recipientPublic,
		Role: RoleRoot, CertEpoch: 0, Issuer: rootDevice.DeviceID,
		Signer: Signer{DeviceID: rootDevice.DeviceID, KeyID: bytes.Clone(rootDevice.KeyID)},
	}
	certificateBytes, err := signCertificate(certificate, rootDevice.Signing)
	if err != nil {
		return BootstrapResult{}, err
	}

	defaults := GenesisPolicyDefaults()
	policy := Policy{
		Vault: vaultID, EpochSeq: 0,
		Roles:                []RoleBinding{{DeviceID: rootDevice.DeviceID, Role: RoleRoot}},
		Recipients:           []PolicyRecipient{{DeviceID: rootDevice.DeviceID, KeyID: bytes.Clone(rootDevice.KeyID), PublicKey: recipientPublic}},
		PolicyRetentionFloor: defaults.PolicyRetentionFloor, RetainedRecoveryPoints: defaults.RetainedRecoveryPoints,
		MaxPublications: defaults.MaxPublications, MaxEpochAge: defaults.MaxEpochAge, RecoveryAnchor: kitFingerprint,
		Signer: Signer{DeviceID: rootDevice.DeviceID, KeyID: bytes.Clone(rootDevice.KeyID)},
	}
	policyBytes, err := signPolicy(policy, rootDevice.Signing)
	if err != nil {
		return BootstrapResult{}, err
	}
	policyDigest, err := ComputePolicyDigest(policyBytes)
	if err != nil {
		return BootstrapResult{}, err
	}
	control := Control{
		Vault: vaultID, EpochSeq: 0, PolicyDigest: policyDigest,
		Signer: Signer{DeviceID: rootDevice.DeviceID, KeyID: bytes.Clone(rootDevice.KeyID)},
	}
	controlBytes, err := signControl(control, rootDevice.Signing)
	if err != nil {
		return BootstrapResult{}, err
	}
	controlCID, err := rawCID(controlBytes)
	if err != nil {
		return BootstrapResult{}, err
	}
	checkpoint := Checkpoint{
		Vault: vaultID, EpochSeq: 0, PolicyDigest: policyDigest, Anchor: anchor, ControlCID: controlCID,
		Signer: Signer{DeviceID: "recovery-kit", KeyID: kitFingerprint[:]},
	}
	checkpointBytes, err := signCheckpoint(checkpoint, kitPrivate)
	if err != nil {
		return BootstrapResult{}, err
	}
	return BootstrapResult{
		Vault: vaultID, Anchor: anchor, Policy: policyBytes, Control: controlBytes,
		Certificate: certificateBytes, Checkpoint: checkpointBytes,
	}, nil
}

func ComposeGenesis(intent GenesisIntent) (Genesis, error) {
	bootstrap, err := Bootstrap(intent.Kit, intent.VaultName, intent.RootDevice)
	if err != nil {
		return Genesis{}, err
	}
	if len(intent.ContentKey) != 32 {
		return Genesis{}, fmt.Errorf("%w: genesis content key", ErrFormat)
	}
	policy, err := DecodePolicy(bootstrap.Policy)
	if err != nil {
		return Genesis{}, err
	}
	policyDigest, err := ComputePolicyDigest(bootstrap.Policy)
	if err != nil {
		return Genesis{}, err
	}
	packed, err := Pack(model.Snapshot{Version: model.SnapshotVersion})
	if err != nil {
		return Genesis{}, fmt.Errorf("pack empty genesis snapshot: %w", err)
	}
	wraps, err := prepareRecipientWraps(policy, intent.Wraps)
	if err != nil {
		return Genesis{}, err
	}
	recipients, err := prepareSealRecipients(policy, wraps)
	if err != nil {
		return Genesis{}, err
	}
	sealed, err := SealPrepared(PreparedSeal{
		Purpose: PurposeSnapshot, Vault: bootstrap.Vault, PublicationID: intent.PublicationID,
		EpochSeq: 0, PolicyDigest: policyDigest, DeviceID: intent.RootDevice.DeviceID,
		KeyID: bytes.Clone(intent.RootDevice.KeyID), Plaintext: packed.Payload,
		SigningKey: intent.RootDevice.Signing, ContentKey: bytes.Clone(intent.ContentKey),
		Nonce: intent.Nonce, Recipients: recipients, Policy: policy,
	})
	if err != nil {
		return Genesis{}, err
	}
	snapshotBytes, err := EncodeEnvelope(sealed)
	if err != nil {
		return Genesis{}, err
	}
	snapshotCID, err := rawCID(snapshotBytes)
	if err != nil {
		return Genesis{}, err
	}
	control, err := DecodeControl(bootstrap.Control)
	if err != nil {
		return Genesis{}, err
	}
	control.HeadSnapshotCID = bytes.Clone(snapshotCID)
	controlBytes, err := signControl(control, intent.RootDevice.Signing)
	if err != nil {
		return Genesis{}, err
	}
	controlCID, err := rawCID(controlBytes)
	if err != nil {
		return Genesis{}, err
	}
	checkpoint, err := DecodeCheckpoint(bootstrap.Checkpoint)
	if err != nil {
		return Genesis{}, err
	}
	checkpoint.SnapshotCID = bytes.Clone(snapshotCID)
	checkpoint.ControlCID = bytes.Clone(controlCID)
	kitKey, err := deriveKitSigningKey(intent.Kit, bootstrap.Vault)
	if err != nil {
		return Genesis{}, err
	}
	checkpointBytes, err := signCheckpoint(checkpoint, kitKey)
	if err != nil {
		return Genesis{}, err
	}
	head, err := signHead(Head{
		Vault: bootstrap.Vault, EpochSeq: 0, PolicyDigest: policyDigest,
		SnapshotCID: bytes.Clone(snapshotCID), BlobCID: bytes.Clone(snapshotCID),
		PublicationCount: 0, Signer: Signer{DeviceID: intent.RootDevice.DeviceID, KeyID: bytes.Clone(intent.RootDevice.KeyID)},
	}, intent.RootDevice.Signing)
	if err != nil {
		return Genesis{}, err
	}
	bootstrap.Control = controlBytes
	bootstrap.Checkpoint = checkpointBytes
	genesis := Genesis{BootstrapResult: bootstrap, Head: head, Snapshot: snapshotBytes, SnapshotCID: snapshotCID, ControlCID: controlCID, PolicyDigest: policyDigest}
	if err := ValidateGenesis(genesis, intent.Kit); err != nil {
		return Genesis{}, err
	}
	return genesis, nil
}

func ValidateGenesis(genesis Genesis, kit []byte) error {
	policy, err := DecodePolicy(genesis.Policy)
	if err != nil {
		return fmt.Errorf("%w: genesis policy", ErrAuthorization)
	}
	control, err := DecodeControl(genesis.Control)
	if err != nil {
		return fmt.Errorf("%w: genesis control", ErrAuthorization)
	}
	certificate, err := DecodeCertificate(genesis.Certificate)
	if err != nil {
		return fmt.Errorf("%w: genesis certificate", ErrAuthorization)
	}
	checkpoint, err := DecodeCheckpoint(genesis.Checkpoint)
	if err != nil {
		return fmt.Errorf("%w: genesis checkpoint", ErrAuthorization)
	}
	head, err := DecodeHead(genesis.Head)
	if err != nil {
		return fmt.Errorf("%w: genesis head", ErrAuthorization)
	}
	envelope, err := DecodeEnvelope(genesis.Snapshot)
	if err != nil {
		return fmt.Errorf("%w: genesis snapshot", ErrAuthorization)
	}
	policyDigest, err := ComputePolicyDigest(genesis.Policy)
	if err != nil || policyDigest != genesis.PolicyDigest {
		return fmt.Errorf("%w: genesis policy digest", ErrAuthorization)
	}
	snapshotCID, err := rawCID(genesis.Snapshot)
	if err != nil || !bytes.Equal(snapshotCID, genesis.SnapshotCID) || !bytes.Equal(snapshotCID, head.SnapshotCID) || !bytes.Equal(snapshotCID, head.BlobCID) || !bytes.Equal(snapshotCID, control.HeadSnapshotCID) || !bytes.Equal(snapshotCID, checkpoint.SnapshotCID) {
		return fmt.Errorf("%w: genesis snapshot binding", ErrHeadLinkage)
	}
	controlCID, err := rawCID(genesis.Control)
	if err != nil || !bytes.Equal(controlCID, genesis.ControlCID) || !bytes.Equal(controlCID, checkpoint.ControlCID) {
		return fmt.Errorf("%w: genesis control binding", ErrHeadLinkage)
	}
	if policy.Vault != genesis.Vault || policy.EpochSeq != 0 || policy.PrevPolicyDigest != [32]byte{} || control.Vault != genesis.Vault || control.EpochSeq != 0 || control.PolicyDigest != policyDigest || len(control.PrevControlCID) != 0 || len(control.Revoked) != 0 || head.Vault != genesis.Vault || head.EpochSeq != 0 || head.PolicyDigest != policyDigest || head.PublicationCount != 0 || len(head.PrevHeadCID) != 0 || envelope.Vault != genesis.Vault || envelope.EpochSeq != 0 || envelope.PolicyDigest != policyDigest || envelope.Purpose != PurposeSnapshot || len(envelope.Parent) != 0 || checkpoint.Vault != genesis.Vault || checkpoint.EpochSeq != 0 || checkpoint.PolicyDigest != policyDigest {
		return fmt.Errorf("%w: genesis objects do not describe the count-zero epoch", ErrAuthorization)
	}
	if certificate.Vault != genesis.Vault || certificate.Role != RoleRoot || certificate.CertEpoch != 0 || certificate.DeviceID != policy.Signer.DeviceID || certificate.DeviceID != control.Signer.DeviceID || certificate.DeviceID != head.Signer.DeviceID || certificate.DeviceID != envelope.DeviceID || !bytes.Equal(certificate.KeyID, policy.Signer.KeyID) || !bytes.Equal(certificate.KeyID, control.Signer.KeyID) || !bytes.Equal(certificate.KeyID, head.Signer.KeyID) || !bytes.Equal(certificate.KeyID, envelope.KeyID) || certificate.Issuer != certificate.DeviceID || certificate.Signer.DeviceID != certificate.DeviceID || !bytes.Equal(certificate.Signer.KeyID, certificate.KeyID) {
		return fmt.Errorf("%w: genesis root certificate binding", ErrAuthorization)
	}
	anchor := sha256.Sum256(certificate.SigningPublicKey[:])
	if anchor != genesis.Anchor || checkpoint.Anchor != anchor {
		return ErrCheckpointAnchor
	}
	for _, binding := range policy.Roles {
		if binding.DeviceID != certificate.DeviceID || binding.Role != RoleRoot {
			return fmt.Errorf("%w: genesis policy role", ErrAuthorization)
		}
	}
	if len(policy.Roles) != 1 || len(policy.Recipients) != 1 || policy.Recipients[0].DeviceID != certificate.DeviceID || !bytes.Equal(policy.Recipients[0].KeyID, certificate.KeyID) || !bytes.Equal(policy.Recipients[0].PublicKey[:], certificate.EncryptionPublicKey[:]) || !publicationRecipientsMatch(policy, envelope) {
		return fmt.Errorf("%w: genesis recipient set", ErrAuthorization)
	}
	kitAnchor, err := RecoveryKitCheckpointAnchor(kit, genesis.Vault, genesis.Checkpoint)
	kitFingerprint, fingerprintErr := RecoveryKitPublicKeyFingerprint(kit, genesis.Vault)
	if err != nil || fingerprintErr != nil || kitAnchor != genesis.Anchor || policy.RecoveryAnchor != kitFingerprint {
		return fmt.Errorf("%w: genesis checkpoint authentication", ErrCheckpointAnchor)
	}
	objects := []struct {
		context   string
		prefix    []byte
		signature []byte
	}{
		{context: "dottie/v1/sig-policy", signature: policy.Signature[:]},
		{context: "dottie/v1/sig-control", signature: control.Signature[:]},
		{context: "dottie/v1/sig-certificate", signature: certificate.Signature[:]},
		{context: "dottie/v1/sig-head", signature: head.Signature[:]},
	}
	prefixes := [][]byte{}
	policyPrefix, policyErr := encodePolicyPrefix(policy)
	controlPrefix, controlErr := encodeControlPrefix(control)
	certificatePrefix, certificateErr := encodeCertificatePrefix(certificate)
	headPrefix, headErr := encodeHeadPrefix(head)
	if policyErr != nil || controlErr != nil || certificateErr != nil || headErr != nil {
		return fmt.Errorf("%w: genesis object encoding", ErrAuthorization)
	}
	prefixes = append(prefixes, policyPrefix, controlPrefix, certificatePrefix, headPrefix)
	for index := range objects {
		objects[index].prefix = prefixes[index]
		if err := Verify(objects[index].context, objectSignaturePreimage(objects[index].prefix), objects[index].signature, certificate.SigningPublicKey[:]); err != nil {
			return fmt.Errorf("%w: genesis object signature", ErrTransitionSignature)
		}
	}
	if len(genesis.Snapshot) < ed25519.SignatureSize || Verify("dottie/v1/sig-snapshot", objectSignaturePreimage(genesis.Snapshot[:len(genesis.Snapshot)-ed25519.SignatureSize]), envelope.Signature[:], certificate.SigningPublicKey[:]) != nil {
		return fmt.Errorf("%w: genesis snapshot signature", ErrTransitionSignature)
	}
	return nil
}

func certificateForEnrollment(vaultID [32]byte, device DeviceMaterial, role Role, certEpoch uint64, rootDevice DeviceMaterial, revocationRef []byte) ([]byte, error) {
	if err := validateDeviceMaterial(rootDevice); err != nil {
		return nil, err
	}
	if err := validateDeviceMaterial(device); err != nil {
		return nil, err
	}
	if role != RolePublisher && role != RoleRestoreOnly {
		return nil, fmt.Errorf("%w: enrollment role", ErrAuthorization)
	}
	if len(revocationRef) != 0 && len(revocationRef) > MaxParentBytes {
		return nil, fmt.Errorf("%w: revocation reference", ErrFormat)
	}
	var encryptionPublic [32]byte
	copy(encryptionPublic[:], device.Recipient.PublicKey().Bytes())
	certificate := Certificate{
		Vault: vaultID, DeviceID: device.DeviceID, KeyID: bytes.Clone(device.KeyID),
		SigningPublicKey:    [ed25519.PublicKeySize]byte(device.Signing.Public().(ed25519.PublicKey)),
		EncryptionPublicKey: encryptionPublic, Role: role, CertEpoch: certEpoch, Issuer: rootDevice.DeviceID,
		RevocationRef: nil,
		Signer:        Signer{DeviceID: rootDevice.DeviceID, KeyID: bytes.Clone(rootDevice.KeyID)},
	}
	return signCertificate(certificate, rootDevice.Signing)
}

func certificateForPublicEnrollment(vaultID [32]byte, device PublicDeviceInput, role Role, certEpoch uint64, rootDevice DeviceMaterial, revocationRef []byte) ([]byte, error) {
	if err := validateDeviceMaterial(rootDevice); err != nil {
		return nil, err
	}
	if err := validatePublicDeviceInput(device); err != nil {
		return nil, err
	}
	if role != RolePublisher && role != RoleRestoreOnly {
		return nil, fmt.Errorf("%w: enrollment role", ErrAuthorization)
	}
	if len(revocationRef) != 0 && len(revocationRef) > MaxParentBytes {
		return nil, fmt.Errorf("%w: revocation reference", ErrFormat)
	}
	var signingPublic [ed25519.PublicKeySize]byte
	var encryptionPublic [32]byte
	copy(signingPublic[:], device.SigningPublicKey)
	copy(encryptionPublic[:], device.RecipientPublicKey)
	certificate := Certificate{
		Vault: vaultID, DeviceID: device.DeviceID, KeyID: bytes.Clone(device.KeyID),
		SigningPublicKey: signingPublic, EncryptionPublicKey: encryptionPublic,
		Role: role, CertEpoch: certEpoch, Issuer: rootDevice.DeviceID,
		Signer: Signer{DeviceID: rootDevice.DeviceID, KeyID: bytes.Clone(rootDevice.KeyID)},
	}
	return signCertificate(certificate, rootDevice.Signing)
}

func publicDeviceFromMaterial(material DeviceMaterial) PublicDeviceInput {
	return PublicDeviceInput{
		DeviceID: material.DeviceID, KeyID: bytes.Clone(material.KeyID),
		SigningPublicKey:   bytes.Clone(material.Signing.Public().(ed25519.PublicKey)),
		RecipientPublicKey: bytes.Clone(material.Recipient.PublicKey().Bytes()),
	}
}

func clonePublicDeviceInput(device PublicDeviceInput) PublicDeviceInput {
	return PublicDeviceInput{
		DeviceID: device.DeviceID, KeyID: bytes.Clone(device.KeyID),
		SigningPublicKey: bytes.Clone(device.SigningPublicKey), RecipientPublicKey: bytes.Clone(device.RecipientPublicKey),
	}
}

func validatePublicDeviceInput(device PublicDeviceInput) error {
	if device.DeviceID == "" || len(device.DeviceID) > MaxDeviceIDBytes || !utf8.ValidString(device.DeviceID) || len(device.KeyID) == 0 || len(device.KeyID) > MaxKeyIDBytes {
		return fmt.Errorf("%w: device identity", ErrFormat)
	}
	if len(device.SigningPublicKey) != ed25519.PublicKeySize || len(device.RecipientPublicKey) != 32 {
		return fmt.Errorf("%w: public device keys", ErrFormat)
	}
	publicKey, err := ecdh.X25519().NewPublicKey(device.RecipientPublicKey)
	if err != nil {
		return fmt.Errorf("%w: recipient public key", ErrFormat)
	}
	privateKeyBytes := bytes.Repeat([]byte{0x42}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("%w: recipient validation key", ErrFormat)
	}
	if _, err := privateKey.ECDH(publicKey); err != nil {
		return fmt.Errorf("%w: recipient public key", ErrFormat)
	}
	return nil
}

func PrepareTransition(predecessor Predecessor, intent TransitionIntent) (Transition, error) {
	if intent.Kind == TransitionRevoke {
		return prepareRevocation(predecessor, intent)
	}
	if intent.Kind != TransitionEnroll {
		return Transition{}, fmt.Errorf("%w: kind", ErrUnsupportedTransition)
	}
	if intent.NewDevice == nil {
		return Transition{}, fmt.Errorf("%w: new device", ErrFormat)
	}
	return prepareEnrollmentTransition(predecessor, intent, func() (PublicDeviceInput, error) {
		if err := validateDeviceMaterial(*intent.NewDevice); err != nil {
			return PublicDeviceInput{}, err
		}
		return publicDeviceFromMaterial(*intent.NewDevice), nil
	}, nil)
}

func PreparePublicEnrollment(predecessor Predecessor, intent PublicEnrollmentIntent) (Transition, error) {
	transitionIntent := TransitionIntent{
		Kind: TransitionEnroll, Vault: intent.Vault, Signer: intent.RootSigner, RequestedRole: intent.RequestedRole,
		ContentKey: intent.ContentKey, Recipients: intent.Recipients, Wraps: intent.Wraps, Plaintext: intent.Plaintext,
		PublicationID: intent.PublicationID, Nonce: intent.Nonce,
	}
	approval := intent.ApprovalFingerprint
	return prepareEnrollmentTransition(predecessor, transitionIntent, func() (PublicDeviceInput, error) {
		if err := validatePublicDeviceInput(intent.NewDevice); err != nil {
			return PublicDeviceInput{}, err
		}
		return clonePublicDeviceInput(intent.NewDevice), nil
	}, &approval)
}

func prepareEnrollmentTransition(predecessor Predecessor, intent TransitionIntent, prepareDevice func() (PublicDeviceInput, error), approval *[32]byte) (Transition, error) {
	if err := validatePredecessor(predecessor); err != nil {
		return Transition{}, err
	}
	oldPolicy, err := DecodePolicy(predecessor.Policy)
	if err != nil {
		return Transition{}, fmt.Errorf("%w: policy", ErrPredecessor)
	}
	if intent.Vault != oldPolicy.Vault {
		return Transition{}, fmt.Errorf("%w: vault", ErrAuthorization)
	}
	if err := validateDeviceMaterial(intent.Signer); err != nil {
		return Transition{}, err
	}
	newDevice, err := prepareDevice()
	if err != nil {
		return Transition{}, err
	}
	if intent.RequestedRole != RolePublisher && intent.RequestedRole != RoleRestoreOnly {
		return Transition{}, fmt.Errorf("%w: enrollment role", ErrAuthorization)
	}
	if approval != nil && *approval != EnrollmentTranscriptFingerprint(intent.Vault, newDevice.DeviceID, newDevice.KeyID, intent.RequestedRole, newDevice.SigningPublicKey, newDevice.RecipientPublicKey) {
		return Transition{}, ErrEnrollmentApproval
	}
	if oldPolicy.EpochSeq == ^uint64(0) {
		return Transition{}, fmt.Errorf("%w: epoch overflow", ErrAuthorization)
	}
	if _, ok := policyRole(oldPolicy, intent.Signer.DeviceID); !ok {
		return Transition{}, fmt.Errorf("%w: signer role", ErrAuthorization)
	}
	if signerRole, _ := policyRole(oldPolicy, intent.Signer.DeviceID); signerRole != RoleRoot {
		return Transition{}, fmt.Errorf("%w: signer role", ErrAuthorization)
	}
	if intent.Signer.DeviceID != oldPolicy.Signer.DeviceID || !bytes.Equal(intent.Signer.KeyID, oldPolicy.Signer.KeyID) {
		return Transition{}, fmt.Errorf("%w: proposer identity", ErrAuthorization)
	}
	if len(intent.ContentKey) != 32 {
		return Transition{}, fmt.Errorf("%w: content key", ErrFormat)
	}
	if len(newDevice.KeyID) == 0 || bytes.Equal(newDevice.KeyID, intent.Signer.KeyID) {
		return Transition{}, fmt.Errorf("%w: key id", ErrAuthorization)
	}
	for _, binding := range oldPolicy.Roles {
		if binding.DeviceID == newDevice.DeviceID {
			return Transition{}, fmt.Errorf("%w: duplicate device id", ErrAuthorization)
		}
	}
	for _, recipient := range oldPolicy.Recipients {
		if bytes.Equal(recipient.KeyID, newDevice.KeyID) {
			return Transition{}, fmt.Errorf("%w: duplicate key id", ErrAuthorization)
		}
	}

	oldCertificates, err := decodeCertificateSet(predecessor.Certificates)
	if err != nil {
		return Transition{}, fmt.Errorf("%w: predecessor certificate set", ErrAuthorization)
	}
	rootCertificate, ok := oldCertificates[oldPolicy.Signer.DeviceID]
	if !ok || rootCertificate.Role != RoleRoot || rootCertificate.Vault != oldPolicy.Vault {
		return Transition{}, fmt.Errorf("%w: predecessor root", ErrAuthorization)
	}
	if !bytes.Equal(rootCertificate.SigningPublicKey[:], intent.Signer.Signing.Public().(ed25519.PublicKey)) || !bytes.Equal(rootCertificate.KeyID, intent.Signer.KeyID) {
		return Transition{}, fmt.Errorf("%w: proposer key", ErrAuthorization)
	}

	oldControl, err := DecodeControl(predecessor.Control)
	if err != nil {
		return Transition{}, fmt.Errorf("%w: predecessor control", ErrPredecessor)
	}
	newEpoch := oldPolicy.EpochSeq + 1
	newCertificateBytes, err := certificateForPublicEnrollment(oldPolicy.Vault, newDevice, intent.RequestedRole, newEpoch, intent.Signer, predecessor.ControlCID)
	if err != nil {
		return Transition{}, err
	}
	newCertificate, err := DecodeCertificate(newCertificateBytes)
	if err != nil {
		return Transition{}, err
	}

	recipientCertificates := cloneByteSlices(intent.Recipients)
	oldRecipientCertificates, err := decodeCertificateSet(recipientCertificates)
	if err != nil || len(oldRecipientCertificates) != len(oldPolicy.Recipients) {
		return Transition{}, fmt.Errorf("%w: predecessor recipient certificates", ErrAuthorization)
	}
	predecessorRequest := OpenRequest{Vault: oldPolicy.Vault, EpochSeq: predecessor.EpochSeq, TrustAnchor: predecessor.TrustAnchor, Certificates: predecessor.Certificates}
	for _, policyRecipient := range oldPolicy.Recipients {
		certificate, exists := oldRecipientCertificates[policyRecipient.DeviceID]
		role, hasRole := policyRole(oldPolicy, policyRecipient.DeviceID)
		if !exists || !hasRole || certificate.Role != role || !bytes.Equal(certificate.KeyID, policyRecipient.KeyID) || !bytes.Equal(certificate.EncryptionPublicKey[:], policyRecipient.PublicKey[:]) || verifyCertificateChain(certificate, predecessorRequest, 1, make(map[string]bool)) != nil {
			return Transition{}, fmt.Errorf("%w: predecessor recipient certificate", ErrAuthorization)
		}
	}
	if _, exists := oldCertificates[newDevice.DeviceID]; exists {
		return Transition{}, fmt.Errorf("%w: duplicate device id", ErrAuthorization)
	}
	for _, existing := range predecessor.Certificates {
		certificate, decodeErr := DecodeCertificate(existing)
		if decodeErr == nil && bytes.Equal(certificate.KeyID, newDevice.KeyID) {
			return Transition{}, fmt.Errorf("%w: duplicate key id", ErrAuthorization)
		}
	}
	recipientCertificates = append(recipientCertificates, newCertificateBytes)
	if _, err := decodeCertificateSet(recipientCertificates); err != nil {
		return Transition{}, err
	}

	newPolicy := oldPolicy
	newPolicy.EpochSeq = newEpoch
	newPolicy.Roles = append(append([]RoleBinding(nil), oldPolicy.Roles...), RoleBinding{DeviceID: newCertificate.DeviceID, Role: newCertificate.Role})
	newPolicy.Recipients = append(append([]PolicyRecipient(nil), oldPolicy.Recipients...), PolicyRecipient{
		DeviceID: newCertificate.DeviceID, KeyID: bytes.Clone(newCertificate.KeyID), PublicKey: newCertificate.EncryptionPublicKey,
	})
	sort.Slice(newPolicy.Roles, func(i, j int) bool { return newPolicy.Roles[i].DeviceID < newPolicy.Roles[j].DeviceID })
	sort.Slice(newPolicy.Recipients, func(i, j int) bool {
		return bytes.Compare(newPolicy.Recipients[i].KeyID, newPolicy.Recipients[j].KeyID) < 0
	})
	newPolicy.PrevPolicyDigest = predecessor.PolicyDigest
	newPolicy.Signer = Signer{DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID)}
	policyBytes, err := signPolicy(newPolicy, intent.Signer.Signing)
	if err != nil {
		return Transition{}, err
	}
	newPolicy, err = DecodePolicy(policyBytes)
	if err != nil {
		return Transition{}, err
	}
	policyDigest, err := ComputePolicyDigest(policyBytes)
	if err != nil {
		return Transition{}, err
	}

	wraps, err := prepareRecipientWraps(newPolicy, intent.Wraps)
	if err != nil {
		return Transition{}, err
	}
	parent := bytes.Clone(predecessor.HeadCID)
	preparedRecipients, err := prepareSealRecipients(newPolicy, wraps)
	if err != nil {
		return Transition{}, err
	}
	prepared := PreparedSeal{
		Purpose: PurposeSnapshot, Vault: newPolicy.Vault, PublicationID: intent.PublicationID, EpochSeq: newEpoch,
		PolicyDigest: policyDigest, Parent: parent, DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID),
		Plaintext: bytes.Clone(intent.Plaintext), SigningKey: intent.Signer.Signing, ContentKey: bytes.Clone(intent.ContentKey),
		Nonce: intent.Nonce, Recipients: preparedRecipients, Policy: newPolicy,
	}
	sealed, err := SealPrepared(prepared)
	if err != nil {
		return Transition{}, err
	}
	snapshotBytes, err := EncodeEnvelope(sealed)
	if err != nil {
		return Transition{}, err
	}
	snapshotCID, err := rawCID(snapshotBytes)
	if err != nil {
		return Transition{}, err
	}
	blobCID := bytes.Clone(snapshotCID)
	control := Control{
		Vault: newPolicy.Vault, EpochSeq: newEpoch, PolicyDigest: policyDigest,
		HeadSnapshotCID: bytes.Clone(snapshotCID), Revoked: append([]RevokedDevice(nil), oldControl.Revoked...),
		PrevControlCID: bytes.Clone(predecessor.ControlCID),
		Signer:         Signer{DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID)},
	}
	controlBytes, err := signControl(control, intent.Signer.Signing)
	if err != nil {
		return Transition{}, err
	}
	head := Head{
		Vault: newPolicy.Vault, EpochSeq: newEpoch, PolicyDigest: policyDigest,
		SnapshotCID: bytes.Clone(snapshotCID), BlobCID: bytes.Clone(blobCID), PublicationCount: 0,
		PrevHeadCID: bytes.Clone(predecessor.HeadCID),
		Signer:      Signer{DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID)},
	}
	headBytes, err := signHead(head, intent.Signer.Signing)
	if err != nil {
		return Transition{}, err
	}
	transition := Transition{
		Kind:        intent.Kind,
		Predecessor: PredecessorRef{ControlCID: bytes.Clone(predecessor.ControlCID), PolicyDigest: predecessor.PolicyDigest, EpochSeq: predecessor.EpochSeq, HeadCID: bytes.Clone(predecessor.HeadCID)},
		Policy:      policyBytes, Control: controlBytes, Certificate: newCertificateBytes, Head: headBytes,
		Snapshot: snapshotBytes, SnapshotCID: snapshotCID, BlobCID: blobCID,
		Recipients: recipientCertificates,
	}
	transition.Digest = ComputeTransitionDigest(transition)
	if err := ValidateTransition(transition, predecessor); err != nil {
		return Transition{}, err
	}
	return transition, nil
}

func PreparePublication(predecessor Predecessor, intent PublicationIntent) (Publication, error) {
	if err := validatePredecessor(predecessor); err != nil {
		return Publication{}, fmt.Errorf("%w: %v", ErrPredecessor, err)
	}
	policy, err := DecodePolicy(predecessor.Policy)
	if err != nil {
		return Publication{}, fmt.Errorf("%w: policy", ErrPredecessor)
	}
	control, err := DecodeControl(predecessor.Control)
	if err != nil {
		return Publication{}, fmt.Errorf("%w: control", ErrPredecessor)
	}
	if intent.Vault != policy.Vault {
		return Publication{}, fmt.Errorf("%w: vault", ErrPublicationAuthority)
	}
	if err := validateDeviceMaterial(intent.Signer); err != nil {
		return Publication{}, err
	}
	if len(intent.ContentKey) != 32 {
		return Publication{}, fmt.Errorf("%w: content key", ErrFormat)
	}
	if len(predecessor.HeadCID) == 0 || len(predecessor.Head) == 0 {
		return Publication{}, fmt.Errorf("%w: ordinary publication requires a current head", ErrPublicationHead)
	}
	signer, err := validatePublicationSigner(predecessor, policy, control, intent.Signer.DeviceID, intent.Signer.KeyID)
	if err != nil {
		return Publication{}, err
	}
	if err := validatePublicationRecipients(predecessor, policy); err != nil {
		return Publication{}, err
	}
	if !bytes.Equal(signer.SigningPublicKey[:], intent.Signer.Signing.Public().(ed25519.PublicKey)) {
		return Publication{}, fmt.Errorf("%w: signer key", ErrPublicationAuthority)
	}
	currentHead, err := currentHeadForPublication(predecessor, policy, control)
	if err != nil {
		return Publication{}, err
	}
	if currentHead.PublicationCount == ^uint64(0) || currentHead.PublicationCount >= uint64(policy.MaxPublications) {
		return Publication{}, ErrPublicationCount
	}
	ageTriggerStatus, err := validateEpochAge(intent, policy)
	if err != nil {
		return Publication{}, err
	}
	wraps, err := prepareRecipientWraps(policy, intent.Wraps)
	if err != nil {
		return Publication{}, err
	}
	preparedRecipients, err := prepareSealRecipients(policy, wraps)
	if err != nil {
		return Publication{}, err
	}
	prepared := PreparedSeal{
		Purpose: PurposeSnapshot, Vault: policy.Vault, PublicationID: intent.PublicationID, EpochSeq: policy.EpochSeq,
		PolicyDigest: predecessor.PolicyDigest, Parent: bytes.Clone(currentHead.SnapshotCID), DeviceID: intent.Signer.DeviceID,
		KeyID: bytes.Clone(intent.Signer.KeyID), Plaintext: bytes.Clone(intent.Plaintext), SigningKey: intent.Signer.Signing,
		ContentKey: bytes.Clone(intent.ContentKey), Nonce: intent.Nonce, Recipients: preparedRecipients, Policy: policy,
	}
	sealed, err := SealPrepared(prepared)
	if err != nil {
		return Publication{}, err
	}
	snapshotBytes, err := EncodeEnvelope(sealed)
	if err != nil {
		return Publication{}, err
	}
	snapshotCID, err := rawCID(snapshotBytes)
	if err != nil {
		return Publication{}, err
	}
	head := Head{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: predecessor.PolicyDigest,
		SnapshotCID: bytes.Clone(snapshotCID), BlobCID: bytes.Clone(snapshotCID), PublicationCount: currentHead.PublicationCount + 1,
		PrevHeadCID: bytes.Clone(currentHead.SnapshotCID), Signer: Signer{DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID)},
	}
	headBytes, err := signHead(head, intent.Signer.Signing)
	if err != nil {
		return Publication{}, err
	}
	publication := Publication{
		Predecessor:  PredecessorRef{ControlCID: bytes.Clone(predecessor.ControlCID), PolicyDigest: predecessor.PolicyDigest, EpochSeq: predecessor.EpochSeq, HeadCID: bytes.Clone(predecessor.HeadCID)},
		PolicyDigest: predecessor.PolicyDigest, Head: headBytes, Snapshot: snapshotBytes, SnapshotCID: snapshotCID, BlobCID: bytes.Clone(snapshotCID),
		AgeTriggerStatus: ageTriggerStatus,
	}
	publication.Digest = ComputePublicationDigest(publication)
	if err := ValidatePublication(publication, predecessor); err != nil {
		return Publication{}, err
	}
	return publication, nil
}

func validateEpochAge(intent PublicationIntent, policy Policy) (PublicationAgeTriggerStatus, error) {
	if intent.Clock == nil {
		return PublicationAgeTriggerNotEvaluatedNoTrustedClock, nil
	}
	if intent.EpochFirstSeen == nil {
		return "", ErrEpochFirstSeenMissing
	}
	firstSeenAt, found, err := intent.EpochFirstSeen.VaultEpochFirstSeen(context.Background(), policy.Vault, policy.EpochSeq)
	if err != nil {
		return "", fmt.Errorf("read epoch first-seen time: %w", err)
	}
	if !found {
		return "", ErrEpochFirstSeenMissing
	}
	if intent.Clock().Sub(time.Unix(firstSeenAt, 0)) >= time.Duration(policy.MaxEpochAge)*time.Second {
		return "", ErrEpochRotationRequired
	}
	return PublicationAgeTriggerEvaluated, nil
}

func ValidatePublication(publication Publication, predecessor Predecessor) error {
	if err := validatePredecessor(predecessor); err != nil {
		return fmt.Errorf("%w: %v", ErrPredecessor, err)
	}
	if publication.Predecessor.PolicyDigest != predecessor.PolicyDigest || publication.PolicyDigest != predecessor.PolicyDigest {
		return ErrPolicyAncestry
	}
	if !bytes.Equal(publication.Predecessor.ControlCID, predecessor.ControlCID) || publication.Predecessor.EpochSeq != predecessor.EpochSeq || !bytes.Equal(publication.Predecessor.HeadCID, predecessor.HeadCID) {
		return ErrObservedRevision
	}
	policy, err := DecodePolicy(predecessor.Policy)
	if err != nil {
		return ErrPredecessor
	}
	control, err := DecodeControl(predecessor.Control)
	if err != nil {
		return ErrPredecessor
	}
	head, err := DecodeHead(publication.Head)
	if err != nil {
		return ErrPublicationHead
	}
	envelope, err := DecodeEnvelope(publication.Snapshot)
	if err != nil {
		return ErrSnapshotEpoch
	}
	if head.Vault != policy.Vault || head.EpochSeq != policy.EpochSeq || head.PolicyDigest != predecessor.PolicyDigest || envelope.Vault != policy.Vault || envelope.EpochSeq != policy.EpochSeq || envelope.PolicyDigest != predecessor.PolicyDigest || envelope.Purpose != PurposeSnapshot {
		return ErrSnapshotEpoch
	}
	if !bytes.Equal(envelope.Parent, predecessor.HeadCID) || !bytes.Equal(head.PrevHeadCID, predecessor.HeadCID) || !bytes.Equal(head.SnapshotCID, publication.SnapshotCID) || !bytes.Equal(head.BlobCID, publication.BlobCID) || !bytes.Equal(publication.SnapshotCID, publication.BlobCID) {
		return ErrPublicationHead
	}
	actualCID, err := rawCID(publication.Snapshot)
	if err != nil || !bytes.Equal(actualCID, publication.SnapshotCID) {
		return ErrPublicationHead
	}
	previousHead, err := currentHeadForPublication(predecessor, policy, control)
	if err != nil {
		return err
	}
	if previousHead.PublicationCount == ^uint64(0) || head.PublicationCount != previousHead.PublicationCount+1 || head.PublicationCount > uint64(policy.MaxPublications) {
		return ErrPublicationCount
	}
	signer, err := validatePublicationSigner(predecessor, policy, control, envelope.DeviceID, envelope.KeyID)
	if err != nil {
		return err
	}
	if err := validatePublicationRecipients(predecessor, policy); err != nil {
		return err
	}
	if head.Signer.DeviceID != envelope.DeviceID || !bytes.Equal(head.Signer.KeyID, envelope.KeyID) {
		return ErrPublicationAuthority
	}
	if err := verifyHeadAndEnvelopeSignatures(publication, head, envelope, signer); err != nil {
		return err
	}
	if !publicationRecipientsMatch(policy, envelope) {
		return ErrTransitionRecipients
	}
	if publication.Digest != ComputePublicationDigest(publication) {
		return ErrTransitionDigest
	}
	return nil
}

func ComputePublicationDigest(publication Publication) [32]byte {
	var buffer bytes.Buffer
	for _, encoded := range [][]byte{publication.Head, publication.Snapshot} {
		buffer.Write(appendU32(nil, uint32(len(encoded))))
		buffer.Write(encoded)
	}
	return sha256.Sum256(buffer.Bytes())
}

func currentHeadForPublication(predecessor Predecessor, policy Policy, control Control) (Head, error) {
	if len(predecessor.HeadCID) == 0 || len(predecessor.Head) == 0 {
		return Head{}, ErrPublicationHead
	}
	head, err := DecodeHead(predecessor.Head)
	if err != nil || head.Vault != policy.Vault || head.EpochSeq != policy.EpochSeq || head.PolicyDigest != predecessor.PolicyDigest || !bytes.Equal(head.SnapshotCID, predecessor.HeadCID) || !bytes.Equal(head.BlobCID, head.SnapshotCID) || head.PublicationCount == 0 && !bytes.Equal(head.SnapshotCID, control.HeadSnapshotCID) {
		return Head{}, ErrPublicationHead
	}
	signer, err := validatePublicationSigner(predecessor, policy, control, head.Signer.DeviceID, head.Signer.KeyID)
	if err != nil {
		return Head{}, ErrPublicationHead
	}
	prefix := predecessor.Head[:len(predecessor.Head)-ed25519.SignatureSize]
	if Verify("dottie/v1/sig-head", objectSignaturePreimage(prefix), head.Signature[:], signer.SigningPublicKey[:]) != nil {
		return Head{}, ErrPublicationHead
	}
	return head, nil
}

func validatePublicationRecipients(predecessor Predecessor, policy Policy) error {
	certificates, err := decodeCertificateSet(predecessor.Certificates)
	if err != nil || len(certificates) != len(policy.Recipients) || len(policy.Roles) != len(policy.Recipients) {
		return ErrTransitionRecipients
	}
	request := OpenRequest{Vault: policy.Vault, EpochSeq: policy.EpochSeq, TrustAnchor: predecessor.TrustAnchor, Certificates: predecessor.Certificates}
	for _, recipient := range policy.Recipients {
		certificate, exists := certificates[recipient.DeviceID]
		role, hasRole := policyRole(policy, recipient.DeviceID)
		if !exists || !hasRole || certificate.Role != role || !bytes.Equal(certificate.KeyID, recipient.KeyID) || !bytes.Equal(certificate.EncryptionPublicKey[:], recipient.PublicKey[:]) || verifyCertificateChain(certificate, request, 1, make(map[string]bool)) != nil {
			return ErrTransitionRecipients
		}
	}
	return nil
}

func validatePublicationSigner(predecessor Predecessor, policy Policy, control Control, deviceID string, keyID []byte) (Certificate, error) {
	certificate, found := findCertificate(predecessor.Certificates, deviceID, keyID)
	if !found || !rolePermitsPublication(policy, certificate) {
		return Certificate{}, ErrPublicationAuthority
	}
	for _, revoked := range control.Revoked {
		if revoked.DeviceID == certificate.DeviceID && revoked.CertEpoch >= certificate.CertEpoch {
			return Certificate{}, ErrPublicationAuthority
		}
	}
	request := OpenRequest{Vault: policy.Vault, EpochSeq: policy.EpochSeq, TrustAnchor: predecessor.TrustAnchor, Certificates: predecessor.Certificates}
	if verifyCertificateChain(certificate, request, 1, make(map[string]bool)) != nil {
		return Certificate{}, ErrPublicationAuthority
	}
	return certificate, nil
}

func rolePermitsPublication(policy Policy, certificate Certificate) bool {
	role, exists := policyRole(policy, certificate.DeviceID)
	return exists && role == certificate.Role && (role == RolePublisher || role == RoleRoot)
}

func verifyHeadAndEnvelopeSignatures(publication Publication, head Head, envelope Envelope, signer Certificate) error {
	headPrefix := publication.Head[:len(publication.Head)-ed25519.SignatureSize]
	if Verify("dottie/v1/sig-head", objectSignaturePreimage(headPrefix), head.Signature[:], signer.SigningPublicKey[:]) != nil {
		return ErrTransitionSignature
	}
	envelopePrefix, err := encodeEnvelopePrefix(envelope)
	if err != nil || Verify(contextForPurpose(envelope.Purpose), append([]byte(preimageSig), envelopePrefix...), envelope.Signature[:], signer.SigningPublicKey[:]) != nil {
		return ErrTransitionSignature
	}
	return nil
}

func publicationRecipientsMatch(policy Policy, envelope Envelope) bool {
	if len(envelope.Recipients) != len(policy.Recipients) {
		return false
	}
	allowed := make(map[string]bool, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		allowed[string(recipient.KeyID)] = true
	}
	for _, recipient := range envelope.Recipients {
		if !allowed[string(recipient.KeyID)] {
			return false
		}
		delete(allowed, string(recipient.KeyID))
	}
	return len(allowed) == 0
}

func prepareRevocation(predecessor Predecessor, intent TransitionIntent) (Transition, error) {
	if intent.RevokeDeviceID == "" {
		return Transition{}, fmt.Errorf("%w: revoked device id", ErrFormat)
	}
	if err := validatePredecessor(predecessor); err != nil {
		return Transition{}, fmt.Errorf("%w: %v", ErrPredecessor, err)
	}
	oldPolicy, err := DecodePolicy(predecessor.Policy)
	if err != nil {
		return Transition{}, fmt.Errorf("%w: policy", ErrPredecessor)
	}
	oldControl, err := DecodeControl(predecessor.Control)
	if err != nil {
		return Transition{}, fmt.Errorf("%w: control", ErrPredecessor)
	}
	if err := validatePublicationRecipients(predecessor, oldPolicy); err != nil {
		return Transition{}, fmt.Errorf("%w: active recipient set", ErrPredecessor)
	}
	if intent.Vault != oldPolicy.Vault {
		return Transition{}, fmt.Errorf("%w: vault", ErrAuthorization)
	}
	if err := validateDeviceMaterial(intent.Signer); err != nil {
		return Transition{}, err
	}
	if oldPolicy.EpochSeq == ^uint64(0) || len(predecessor.HeadCID) == 0 || len(predecessor.Head) == 0 {
		return Transition{}, fmt.Errorf("%w: predecessor head or epoch", ErrAuthorization)
	}
	if role, exists := policyRole(oldPolicy, intent.Signer.DeviceID); !exists || role != RoleRoot || intent.Signer.DeviceID != oldPolicy.Signer.DeviceID || !bytes.Equal(intent.Signer.KeyID, oldPolicy.Signer.KeyID) {
		return Transition{}, fmt.Errorf("%w: signer role", ErrAuthorization)
	}
	if len(intent.ContentKey) != 32 {
		return Transition{}, fmt.Errorf("%w: content key", ErrFormat)
	}
	oldCertificates, err := decodeCertificateSet(predecessor.Certificates)
	if err != nil {
		return Transition{}, fmt.Errorf("%w: predecessor certificate set", ErrAuthorization)
	}
	targetCertificate, found := oldCertificates[intent.RevokeDeviceID]
	if !found || targetCertificate.DeviceID == intent.Signer.DeviceID {
		return Transition{}, fmt.Errorf("%w: revoked device is not revocable", ErrAuthorization)
	}
	if _, ok := policyRole(oldPolicy, intent.RevokeDeviceID); !ok {
		return Transition{}, fmt.Errorf("%w: revoked device is not active", ErrAuthorization)
	}
	for _, revoked := range oldControl.Revoked {
		if revoked.DeviceID == targetCertificate.DeviceID && revoked.CertEpoch >= targetCertificate.CertEpoch {
			return Transition{}, ErrRevokedDevice
		}
	}
	oldHead, err := currentHeadForPublication(predecessor, oldPolicy, oldControl)
	if err != nil {
		return Transition{}, err
	}
	rootCertificate, found := oldCertificates[oldPolicy.Signer.DeviceID]
	if !found || rootCertificate.Role != RoleRoot || rootCertificate.Vault != oldPolicy.Vault || !bytes.Equal(rootCertificate.SigningPublicKey[:], intent.Signer.Signing.Public().(ed25519.PublicKey)) || !bytes.Equal(rootCertificate.KeyID, intent.Signer.KeyID) {
		return Transition{}, fmt.Errorf("%w: proposer key", ErrAuthorization)
	}
	activeRecipients, err := decodeCertificateSet(intent.Recipients)
	if err != nil || len(activeRecipients) != len(oldPolicy.Recipients)-1 {
		return Transition{}, ErrTransitionRecipients
	}
	newEpoch := oldPolicy.EpochSeq + 1
	newPolicy := oldPolicy
	newPolicy.EpochSeq = newEpoch
	newPolicy.Roles = make([]RoleBinding, 0, len(oldPolicy.Roles)-1)
	for _, binding := range oldPolicy.Roles {
		if binding.DeviceID != intent.RevokeDeviceID {
			newPolicy.Roles = append(newPolicy.Roles, binding)
		}
	}
	newPolicy.Recipients = make([]PolicyRecipient, 0, len(oldPolicy.Recipients)-1)
	for _, recipient := range oldPolicy.Recipients {
		if recipient.DeviceID != intent.RevokeDeviceID {
			newPolicy.Recipients = append(newPolicy.Recipients, recipient)
		}
	}
	if len(newPolicy.Roles) == len(oldPolicy.Roles) || len(newPolicy.Recipients) == len(oldPolicy.Recipients) {
		return Transition{}, ErrTransitionDelta
	}
	newControlRevoked := append(append([]RevokedDevice(nil), oldControl.Revoked...), RevokedDevice{DeviceID: targetCertificate.DeviceID, CertEpoch: targetCertificate.CertEpoch})
	newPolicy.PrevPolicyDigest = predecessor.PolicyDigest
	newPolicy.Signer = Signer{DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID)}
	policyBytes, err := signPolicy(newPolicy, intent.Signer.Signing)
	if err != nil {
		return Transition{}, err
	}
	newPolicy, err = DecodePolicy(policyBytes)
	if err != nil {
		return Transition{}, err
	}
	policyDigest, err := ComputePolicyDigest(policyBytes)
	if err != nil {
		return Transition{}, err
	}
	wraps, err := prepareRecipientWraps(newPolicy, intent.Wraps)
	if err != nil {
		return Transition{}, err
	}
	preparedRecipients, err := prepareSealRecipients(newPolicy, wraps)
	if err != nil {
		return Transition{}, err
	}
	prepared := PreparedSeal{
		Purpose: PurposeSnapshot, Vault: newPolicy.Vault, PublicationID: intent.PublicationID, EpochSeq: newEpoch,
		PolicyDigest: policyDigest, Parent: bytes.Clone(oldHead.SnapshotCID), DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID),
		Plaintext: bytes.Clone(intent.Plaintext), SigningKey: intent.Signer.Signing, ContentKey: bytes.Clone(intent.ContentKey),
		Nonce: intent.Nonce, Recipients: preparedRecipients, Policy: newPolicy,
	}
	sealed, err := SealPrepared(prepared)
	if err != nil {
		return Transition{}, err
	}
	snapshotBytes, err := EncodeEnvelope(sealed)
	if err != nil {
		return Transition{}, err
	}
	snapshotCID, err := rawCID(snapshotBytes)
	if err != nil {
		return Transition{}, err
	}
	control := Control{
		Vault: newPolicy.Vault, EpochSeq: newEpoch, PolicyDigest: policyDigest,
		HeadSnapshotCID: bytes.Clone(snapshotCID), Revoked: newControlRevoked, PrevControlCID: bytes.Clone(predecessor.ControlCID),
		Signer: Signer{DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID)},
	}
	controlBytes, err := signControl(control, intent.Signer.Signing)
	if err != nil {
		return Transition{}, err
	}
	head := Head{
		Vault: newPolicy.Vault, EpochSeq: newEpoch, PolicyDigest: policyDigest,
		SnapshotCID: bytes.Clone(snapshotCID), BlobCID: bytes.Clone(snapshotCID), PublicationCount: 0,
		PrevHeadCID: bytes.Clone(oldHead.SnapshotCID), Signer: Signer{DeviceID: intent.Signer.DeviceID, KeyID: bytes.Clone(intent.Signer.KeyID)},
	}
	headBytes, err := signHead(head, intent.Signer.Signing)
	if err != nil {
		return Transition{}, err
	}
	transition := Transition{
		Kind:        TransitionRevoke,
		Predecessor: PredecessorRef{ControlCID: bytes.Clone(predecessor.ControlCID), PolicyDigest: predecessor.PolicyDigest, EpochSeq: predecessor.EpochSeq, HeadCID: bytes.Clone(predecessor.HeadCID)},
		Policy:      policyBytes, Control: controlBytes, Head: headBytes, Snapshot: snapshotBytes,
		SnapshotCID: snapshotCID, BlobCID: bytes.Clone(snapshotCID), Recipients: cloneByteSlices(intent.Recipients),
	}
	transition.Digest = ComputeTransitionDigest(transition)
	if err := ValidateTransition(transition, predecessor); err != nil {
		return Transition{}, err
	}
	return transition, nil
}

func validateRevocationTransition(transition Transition, predecessor Predecessor) error {
	if err := validatePredecessor(predecessor); err != nil {
		return fmt.Errorf("%w: %v", ErrPredecessor, err)
	}
	if transition.Certificate != nil && len(transition.Certificate) != 0 {
		return ErrCertificateAuthority
	}
	if !bytes.Equal(transition.Predecessor.ControlCID, predecessor.ControlCID) || transition.Predecessor.PolicyDigest != predecessor.PolicyDigest || transition.Predecessor.EpochSeq != predecessor.EpochSeq || !bytes.Equal(transition.Predecessor.HeadCID, predecessor.HeadCID) {
		return ErrObservedRevision
	}
	oldPolicy, _ := DecodePolicy(predecessor.Policy)
	oldControl, _ := DecodeControl(predecessor.Control)
	if err := validatePublicationRecipients(predecessor, oldPolicy); err != nil {
		return fmt.Errorf("%w: predecessor recipients", ErrPredecessor)
	}
	if _, err := currentHeadForPublication(predecessor, oldPolicy, oldControl); err != nil {
		return err
	}
	proposer, ok := findCertificate(predecessor.Certificates, oldControl.Signer.DeviceID, oldControl.Signer.KeyID)
	if !ok || proposer.Role != RoleRoot || policyRoleMust(oldPolicy, proposer.DeviceID) != RoleRoot {
		return ErrProposerRole
	}
	if err := verifyTransitionSignatures(transition, proposer); err != nil {
		return err
	}
	policy, err := DecodePolicy(transition.Policy)
	if err != nil {
		return fmt.Errorf("%w: policy", ErrTransitionSignature)
	}
	control, err := DecodeControl(transition.Control)
	if err != nil {
		return fmt.Errorf("%w: control", ErrTransitionSignature)
	}
	head, err := DecodeHead(transition.Head)
	if err != nil {
		return fmt.Errorf("%w: head", ErrTransitionSignature)
	}
	envelope, err := DecodeEnvelope(transition.Snapshot)
	if err != nil {
		return fmt.Errorf("%w: snapshot", ErrTransitionSignature)
	}
	if predecessor.EpochSeq == ^uint64(0) || policy.EpochSeq != predecessor.EpochSeq+1 {
		return ErrTransitionEpoch
	}
	if policy.Vault != oldPolicy.Vault || policy.PrevPolicyDigest != predecessor.PolicyDigest || policy.Signer.DeviceID != proposer.DeviceID || !bytes.Equal(policy.Signer.KeyID, proposer.KeyID) {
		return ErrPolicyAncestry
	}
	policyDigest := mustPolicyDigest(transition.Policy)
	if control.Vault != policy.Vault || control.EpochSeq != policy.EpochSeq || control.PolicyDigest != policyDigest || !bytes.Equal(control.PrevControlCID, predecessor.ControlCID) || control.Signer.DeviceID != proposer.DeviceID || !bytes.Equal(control.Signer.KeyID, proposer.KeyID) {
		return ErrControlAncestry
	}
	if err := validateRevocationDelta(oldPolicy, policy, oldControl, control, predecessor.Certificates); err != nil {
		return err
	}
	if err := validateTransitionRecipients(transition, policy, predecessor, proposer, envelope); err != nil {
		return err
	}
	if envelope.Purpose != PurposeSnapshot || envelope.EpochSeq != policy.EpochSeq || envelope.PolicyDigest != policyDigest || envelope.Vault != policy.Vault || !bytes.Equal(envelope.Parent, predecessor.HeadCID) {
		return ErrSnapshotEpoch
	}
	if head.Vault != policy.Vault || head.EpochSeq != policy.EpochSeq || head.PolicyDigest != policyDigest || head.PublicationCount != 0 || !bytes.Equal(head.SnapshotCID, transition.SnapshotCID) || !bytes.Equal(head.BlobCID, transition.BlobCID) || !bytes.Equal(head.PrevHeadCID, predecessor.HeadCID) || !bytes.Equal(control.HeadSnapshotCID, transition.SnapshotCID) {
		return ErrHeadLinkage
	}
	actualSnapshotCID, err := rawCID(transition.Snapshot)
	if err != nil || !bytes.Equal(actualSnapshotCID, transition.SnapshotCID) || !bytes.Equal(actualSnapshotCID, transition.BlobCID) {
		return ErrHeadLinkage
	}
	if transition.Checkpoint != nil && len(transition.Checkpoint) > 0 {
		return ErrCheckpointAnchor
	}
	if transition.Digest != ComputeTransitionDigest(transition) {
		return ErrTransitionDigest
	}
	return nil
}

func validateRevocationDelta(oldPolicy, policy Policy, oldControl, control Control, predecessorCertificates [][]byte) error {
	if !nonRosterPolicyFieldsEqual(oldPolicy, policy) {
		return ErrTransitionDelta
	}
	if len(policy.Roles) != len(oldPolicy.Roles)-1 || len(policy.Recipients) != len(oldPolicy.Recipients)-1 || len(control.Revoked) != len(oldControl.Revoked)+1 {
		return ErrTransitionDelta
	}
	removedDevice := ""
	for _, binding := range oldPolicy.Roles {
		role, exists := policyRole(policy, binding.DeviceID)
		if exists {
			if role != binding.Role {
				return ErrTransitionDelta
			}
			continue
		}
		if removedDevice != "" || binding.DeviceID == oldControl.Signer.DeviceID {
			return ErrTransitionDelta
		}
		removedDevice = binding.DeviceID
	}
	if removedDevice == "" {
		return ErrTransitionDelta
	}
	for _, binding := range policy.Roles {
		if _, exists := policyRole(oldPolicy, binding.DeviceID); !exists {
			return ErrTransitionDelta
		}
	}
	removedRecipient := ""
	for _, recipient := range oldPolicy.Recipients {
		current, exists := policyRecipient(policy, recipient.DeviceID)
		if exists {
			if !bytes.Equal(current.KeyID, recipient.KeyID) || current.PublicKey != recipient.PublicKey {
				return ErrTransitionDelta
			}
			continue
		}
		if removedRecipient != "" {
			return ErrTransitionDelta
		}
		removedRecipient = recipient.DeviceID
	}
	if removedRecipient != removedDevice {
		return ErrTransitionDelta
	}
	for _, recipient := range policy.Recipients {
		if _, exists := policyRecipient(oldPolicy, recipient.DeviceID); !exists {
			return ErrTransitionDelta
		}
	}
	var target Certificate
	found := false
	for _, encoded := range predecessorCertificates {
		certificate, err := DecodeCertificate(encoded)
		if err == nil && certificate.DeviceID == removedDevice {
			target = certificate
			found = true
			break
		}
	}
	if !found {
		return ErrCertificateAuthority
	}
	for index, revoked := range oldControl.Revoked {
		if control.Revoked[index] != revoked {
			return ErrRevokedDevice
		}
	}
	added := control.Revoked[len(control.Revoked)-1]
	if added.DeviceID != target.DeviceID || added.CertEpoch != target.CertEpoch {
		return ErrRevokedDevice
	}
	return nil
}

func policyRecipient(policy Policy, deviceID string) (PolicyRecipient, bool) {
	for _, recipient := range policy.Recipients {
		if recipient.DeviceID == deviceID {
			return recipient, true
		}
	}
	return PolicyRecipient{}, false
}

func policyRoleMust(policy Policy, deviceID string) Role {
	role, _ := policyRole(policy, deviceID)
	return role
}

func ValidateTransition(transition Transition, predecessor Predecessor) error {
	if transition.Kind == TransitionRevoke {
		return validateRevocationTransition(transition, predecessor)
	}
	if transition.Kind != TransitionEnroll {
		return fmt.Errorf("%w: kind", ErrUnsupportedTransition)
	}
	if err := validatePredecessor(predecessor); err != nil {
		return fmt.Errorf("%w: %v", ErrPredecessor, err)
	}
	if !bytes.Equal(transition.Predecessor.ControlCID, predecessor.ControlCID) || transition.Predecessor.PolicyDigest != predecessor.PolicyDigest || transition.Predecessor.EpochSeq != predecessor.EpochSeq || !bytes.Equal(transition.Predecessor.HeadCID, predecessor.HeadCID) {
		return ErrObservedRevision
	}
	oldPolicy, _ := DecodePolicy(predecessor.Policy)
	oldControl, _ := DecodeControl(predecessor.Control)
	proposer, ok := findCertificate(predecessor.Certificates, oldControl.Signer.DeviceID, oldControl.Signer.KeyID)
	if !ok || proposer.Role != RoleRoot {
		return ErrProposerRole
	}
	if role, exists := policyRole(oldPolicy, proposer.DeviceID); !exists || role != RoleRoot {
		return ErrProposerRole
	}
	if err := verifyTransitionSignatures(transition, proposer); err != nil {
		return err
	}
	policy, err := DecodePolicy(transition.Policy)
	if err != nil {
		return fmt.Errorf("%w: policy", ErrTransitionSignature)
	}
	control, err := DecodeControl(transition.Control)
	if err != nil {
		return fmt.Errorf("%w: control", ErrTransitionSignature)
	}
	certificate, err := DecodeCertificate(transition.Certificate)
	if err != nil {
		return fmt.Errorf("%w: certificate", ErrTransitionSignature)
	}
	head, err := DecodeHead(transition.Head)
	if err != nil {
		return fmt.Errorf("%w: head", ErrTransitionSignature)
	}
	envelope, err := DecodeEnvelope(transition.Snapshot)
	if err != nil {
		return fmt.Errorf("%w: snapshot", ErrTransitionSignature)
	}
	if predecessor.EpochSeq == ^uint64(0) || policy.EpochSeq != predecessor.EpochSeq+1 {
		return ErrTransitionEpoch
	}
	if policy.Vault != oldPolicy.Vault || policy.PrevPolicyDigest != predecessor.PolicyDigest || policy.Signer.DeviceID != proposer.DeviceID || !bytes.Equal(policy.Signer.KeyID, proposer.KeyID) {
		return ErrPolicyAncestry
	}
	if control.Vault != policy.Vault || control.EpochSeq != policy.EpochSeq || control.PolicyDigest != mustPolicyDigest(transition.Policy) || !bytes.Equal(control.PrevControlCID, predecessor.ControlCID) || control.Signer.DeviceID != proposer.DeviceID || !bytes.Equal(control.Signer.KeyID, proposer.KeyID) {
		return ErrControlAncestry
	}
	if certificate.Vault != policy.Vault || certificate.Issuer != proposer.DeviceID || certificate.Signer.DeviceID != proposer.DeviceID || !bytes.Equal(certificate.Signer.KeyID, proposer.KeyID) || len(certificate.RevocationRef) != 0 || certificate.CertEpoch != policy.EpochSeq || certificate.Role != RolePublisher && certificate.Role != RoleRestoreOnly {
		return ErrCertificateAuthority
	}
	role, exists := policyRole(policy, certificate.DeviceID)
	if !exists || role != certificate.Role {
		return ErrCertificateAuthority
	}
	if err := validateEnrollmentDelta(oldPolicy, policy, oldControl, control, certificate); err != nil {
		return err
	}
	if err := validateTransitionRecipients(transition, policy, predecessor, proposer, envelope); err != nil {
		return err
	}
	policyDigest := mustPolicyDigest(transition.Policy)
	if envelope.Purpose != PurposeSnapshot || envelope.EpochSeq != policy.EpochSeq || envelope.PolicyDigest != policyDigest || envelope.Vault != policy.Vault || !bytes.Equal(envelope.Parent, predecessor.HeadCID) {
		return ErrSnapshotEpoch
	}
	if head.Vault != policy.Vault || head.EpochSeq != policy.EpochSeq || head.PolicyDigest != policyDigest || head.PublicationCount != 0 || !bytes.Equal(head.SnapshotCID, transition.SnapshotCID) || !bytes.Equal(head.BlobCID, transition.BlobCID) || !bytes.Equal(head.PrevHeadCID, predecessor.HeadCID) || !bytes.Equal(control.HeadSnapshotCID, transition.SnapshotCID) {
		return ErrHeadLinkage
	}
	actualSnapshotCID, err := rawCID(transition.Snapshot)
	if err != nil || !bytes.Equal(actualSnapshotCID, transition.SnapshotCID) || !bytes.Equal(actualSnapshotCID, transition.BlobCID) {
		return ErrHeadLinkage
	}
	if len(transition.Checkpoint) > 0 {
		return ErrCheckpointAnchor
	}
	if transition.Digest != ComputeTransitionDigest(transition) {
		return ErrTransitionDigest
	}
	return nil
}

func ComputeTransitionDigest(transition Transition) [32]byte {
	var buffer bytes.Buffer
	buffer.WriteByte(byte(transition.Kind))
	for _, encoded := range [][]byte{transition.Policy, transition.Control, transition.Certificate, transition.Head, transition.Snapshot} {
		buffer.Write(appendU32(nil, uint32(len(encoded))))
		buffer.Write(encoded)
	}
	return sha256.Sum256(buffer.Bytes())
}

func EnrollmentTranscriptFingerprint(vaultID [32]byte, deviceID string, keyID []byte, role Role, signingPublic, recipientPublic []byte) [32]byte {
	buffer := append([]byte("dottie/v1/enrollment"), vaultID[:]...)
	buffer = appendBytes16(buffer, []byte(deviceID))
	buffer = appendBytes16(buffer, keyID)
	buffer = append(buffer, byte(role))
	buffer = appendBytes16(buffer, signingPublic)
	buffer = appendBytes16(buffer, recipientPublic)
	return sha256.Sum256(buffer)
}

func validatePredecessor(predecessor Predecessor) error {
	if len(predecessor.ControlCID) == 0 || len(predecessor.ControlCID) > MaxParentBytes || len(predecessor.HeadCID) > MaxParentBytes {
		return fmt.Errorf("%w: predecessor identifiers", ErrAuthorization)
	}
	if _, err := decodeCertificateSet(predecessor.Certificates); err != nil {
		return err
	}
	policy, err := DecodePolicy(predecessor.Policy)
	if err != nil {
		return err
	}
	control, err := DecodeControl(predecessor.Control)
	if err != nil {
		return err
	}
	if (len(predecessor.HeadCID) == 0) != (len(control.HeadSnapshotCID) == 0) {
		return fmt.Errorf("%w: predecessor head marker", ErrAuthorization)
	}
	computedControlCID, err := rawCID(predecessor.Control)
	if err != nil || !bytes.Equal(computedControlCID, predecessor.ControlCID) {
		return fmt.Errorf("%w: predecessor control identifier", ErrAuthorization)
	}
	policyDigest, err := ComputePolicyDigest(predecessor.Policy)
	if err != nil || policyDigest != predecessor.PolicyDigest || control.PolicyDigest != policyDigest || policy.Vault != control.Vault || policy.EpochSeq != predecessor.EpochSeq || control.EpochSeq != predecessor.EpochSeq {
		return fmt.Errorf("%w: predecessor policy or control fields", ErrAuthorization)
	}
	request := OpenRequest{Vault: policy.Vault, EpochSeq: predecessor.EpochSeq, TrustAnchor: predecessor.TrustAnchor, Certificates: predecessor.Certificates}
	policySigner, ok := findCertificate(predecessor.Certificates, policy.Signer.DeviceID, policy.Signer.KeyID)
	if !ok || policySigner.Role != RoleRoot || verifyCertificateChain(policySigner, request, 1, make(map[string]bool)) != nil {
		return fmt.Errorf("%w: predecessor policy signer", ErrAuthorization)
	}
	policyPrefix, err := encodePolicyPrefix(policy)
	if err != nil || Verify("dottie/v1/sig-policy", objectSignaturePreimage(policyPrefix), policy.Signature[:], policySigner.SigningPublicKey[:]) != nil {
		return fmt.Errorf("%w: predecessor policy signature", ErrSignature)
	}
	controlSigner, ok := findCertificate(predecessor.Certificates, control.Signer.DeviceID, control.Signer.KeyID)
	if !ok || controlSigner.Role != RoleRoot || verifyCertificateChain(controlSigner, request, 1, make(map[string]bool)) != nil {
		return fmt.Errorf("%w: predecessor control signer", ErrAuthorization)
	}
	controlPrefix, err := encodeControlPrefix(control)
	if err != nil || Verify("dottie/v1/sig-control", objectSignaturePreimage(controlPrefix), control.Signature[:], controlSigner.SigningPublicKey[:]) != nil {
		return fmt.Errorf("%w: predecessor control signature", ErrSignature)
	}
	if policy.Signer.DeviceID != control.Signer.DeviceID || !bytes.Equal(policy.Signer.KeyID, control.Signer.KeyID) {
		return fmt.Errorf("%w: predecessor signer mismatch", ErrAuthorization)
	}
	return nil
}

func verifyTransitionSignatures(transition Transition, proposer Certificate) error {
	objects := []struct {
		encoded []byte
		kind    byte
	}{
		{transition.Policy, objectKindPolicy}, {transition.Control, objectKindControl}, {transition.Head, objectKindHead},
	}
	if transition.Kind != TransitionRevoke {
		objects = append(objects, struct {
			encoded []byte
			kind    byte
		}{transition.Certificate, objectKindCertificate})
	}
	for _, object := range objects {
		if err := validateHeader(object.encoded, object.kind, false); err != nil {
			return fmt.Errorf("%w: object encoding", ErrTransitionSignature)
		}
		var signer Signer
		var signature []byte
		switch object.kind {
		case objectKindPolicy:
			value, err := DecodePolicy(object.encoded)
			if err != nil {
				return fmt.Errorf("%w: policy: %w", ErrTransitionSignature, err)
			}
			signer, signature = value.Signer, value.Signature[:]
		case objectKindControl:
			value, err := DecodeControl(object.encoded)
			if err != nil {
				return fmt.Errorf("%w: control: %w", ErrTransitionSignature, err)
			}
			signer, signature = value.Signer, value.Signature[:]
		case objectKindCertificate:
			value, err := DecodeCertificate(object.encoded)
			if err != nil {
				return fmt.Errorf("%w: certificate: %w", ErrTransitionSignature, err)
			}
			signer, signature = value.Signer, value.Signature[:]
		case objectKindHead:
			value, err := DecodeHead(object.encoded)
			if err != nil {
				return fmt.Errorf("%w: head: %w", ErrTransitionSignature, err)
			}
			signer, signature = value.Signer, value.Signature[:]
		}
		if signer.DeviceID != proposer.DeviceID || !bytes.Equal(signer.KeyID, proposer.KeyID) {
			return fmt.Errorf("%w: signer", ErrTransitionSignature)
		}
		prefix := object.encoded[:len(object.encoded)-ed25519.SignatureSize]
		if Verify(objectSignatureContext(object.kind), objectSignaturePreimage(prefix), signature, proposer.SigningPublicKey[:]) != nil {
			return fmt.Errorf("%w: signature", ErrTransitionSignature)
		}
	}
	envelope, err := DecodeEnvelope(transition.Snapshot)
	if err != nil || envelope.DeviceID != proposer.DeviceID || !bytes.Equal(envelope.KeyID, proposer.KeyID) {
		return fmt.Errorf("%w: snapshot signer", ErrTransitionSignature)
	}
	prefix, err := encodeEnvelopePrefix(envelope)
	if err != nil || Verify(contextForPurpose(envelope.Purpose), append([]byte(preimageSig), prefix...), envelope.Signature[:], proposer.SigningPublicKey[:]) != nil {
		return fmt.Errorf("%w: snapshot signature", ErrTransitionSignature)
	}
	return nil
}

func validateEnrollmentDelta(oldPolicy, policy Policy, oldControl, control Control, certificate Certificate) error {
	if !nonRosterPolicyFieldsEqual(oldPolicy, policy) {
		return ErrTransitionDelta
	}
	if len(policy.Roles) != len(oldPolicy.Roles)+1 || len(policy.Recipients) != len(oldPolicy.Recipients)+1 {
		return ErrTransitionDelta
	}
	if len(control.Revoked) != len(oldControl.Revoked) {
		return ErrRevokedDevice
	}
	for index, revoked := range oldControl.Revoked {
		if control.Revoked[index] != revoked {
			return ErrRevokedDevice
		}
	}
	added := 0
	for _, binding := range policy.Roles {
		existing, exists := policyRole(oldPolicy, binding.DeviceID)
		if exists {
			if existing != binding.Role {
				return ErrTransitionDelta
			}
			continue
		}
		added++
		if binding.DeviceID != certificate.DeviceID || binding.Role != certificate.Role {
			return ErrTransitionDelta
		}
	}
	if added != 1 {
		return ErrTransitionDelta
	}
	for _, binding := range oldPolicy.Roles {
		if _, exists := policyRole(policy, binding.DeviceID); !exists {
			return ErrTransitionDelta
		}
	}
	addedRecipient := 0
	for _, recipient := range policy.Recipients {
		known := false
		for _, previous := range oldPolicy.Recipients {
			if previous.DeviceID == recipient.DeviceID {
				if !bytes.Equal(previous.KeyID, recipient.KeyID) || previous.PublicKey != recipient.PublicKey {
					return ErrTransitionDelta
				}
				known = true
				break
			}
		}
		if known {
			continue
		}
		addedRecipient++
		if recipient.DeviceID != certificate.DeviceID {
			return ErrTransitionDelta
		}
	}
	if addedRecipient != 1 {
		return ErrTransitionDelta
	}
	for _, revoked := range oldControl.Revoked {
		if revoked.DeviceID == certificate.DeviceID && revoked.CertEpoch >= certificate.CertEpoch {
			return ErrRevokedDevice
		}
	}
	return nil
}

func nonRosterPolicyFieldsEqual(oldPolicy, policy Policy) bool {
	return oldPolicy.PolicyRetentionFloor == policy.PolicyRetentionFloor &&
		oldPolicy.RetainedRecoveryPoints == policy.RetainedRecoveryPoints &&
		oldPolicy.MaxPublications == policy.MaxPublications &&
		oldPolicy.MaxEpochAge == policy.MaxEpochAge &&
		oldPolicy.RecoveryAnchor == policy.RecoveryAnchor
}

func validateTransitionRecipients(transition Transition, policy Policy, predecessor Predecessor, proposer Certificate, envelope Envelope) error {
	certificates, err := decodeCertificateSet(transition.Recipients)
	if err != nil || len(certificates) != len(policy.Recipients) {
		return ErrTransitionRecipients
	}
	request := OpenRequest{Vault: policy.Vault, EpochSeq: policy.EpochSeq, TrustAnchor: predecessor.TrustAnchor, Certificates: transition.Recipients}
	policyKeyIDs := make(map[string]PolicyRecipient, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		key := string(recipient.KeyID)
		if _, exists := policyKeyIDs[key]; exists {
			return ErrTransitionRecipients
		}
		certificate, exists := certificates[recipient.DeviceID]
		if !exists || !bytes.Equal(certificate.KeyID, recipient.KeyID) || !bytes.Equal(certificate.EncryptionPublicKey[:], recipient.PublicKey[:]) || certificate.Vault != policy.Vault {
			return ErrTransitionRecipients
		}
		if err := verifyCertificateChain(certificate, request, 1, make(map[string]bool)); err != nil {
			return ErrTransitionRecipients
		}
		role, exists := policyRole(policy, recipient.DeviceID)
		if !exists || role != certificate.Role {
			return ErrTransitionRecipients
		}
		policyKeyIDs[key] = recipient
	}
	if len(envelope.Recipients) != len(policyKeyIDs) {
		return ErrTransitionRecipients
	}
	for _, wrapped := range envelope.Recipients {
		if _, exists := policyKeyIDs[string(wrapped.KeyID)]; !exists {
			return ErrTransitionRecipients
		}
	}
	if transition.Kind != TransitionRevoke {
		transitionCertificate, err := DecodeCertificate(transition.Certificate)
		if err != nil {
			return ErrTransitionRecipients
		}
		if recipientCertificate, exists := certificates[transitionCertificate.DeviceID]; !exists || !bytes.Equal(recipientCertificate.KeyID, transitionCertificate.KeyID) || recipientCertificate.SigningPublicKey != transitionCertificate.SigningPublicKey || recipientCertificate.EncryptionPublicKey != transitionCertificate.EncryptionPublicKey || recipientCertificate.Role != transitionCertificate.Role || recipientCertificate.CertEpoch != transitionCertificate.CertEpoch || recipientCertificate.Issuer != transitionCertificate.Issuer || !bytes.Equal(recipientCertificate.RevocationRef, transitionCertificate.RevocationRef) || recipientCertificate.Signer.DeviceID != transitionCertificate.Signer.DeviceID || !bytes.Equal(recipientCertificate.Signer.KeyID, transitionCertificate.Signer.KeyID) || recipientCertificate.Signature != transitionCertificate.Signature {
			return ErrTransitionRecipients
		}
	}
	return nil
}

func prepareRecipientWraps(policy Policy, supplied []RecipientWrapInput) ([]RecipientWrapInput, error) {
	if len(supplied) != len(policy.Recipients) || len(supplied) == 0 {
		return nil, fmt.Errorf("%w: wrap set", ErrAuthorization)
	}
	byID := make(map[string]RecipientWrapInput, len(supplied))
	ephemeralKeys := make(map[[32]byte]bool, len(supplied))
	for _, wrap := range supplied {
		key := string(wrap.KeyID)
		if key == "" {
			return nil, fmt.Errorf("%w: empty wrap key id", ErrAuthorization)
		}
		if _, exists := byID[key]; exists {
			return nil, fmt.Errorf("%w: duplicate wrap key id", ErrAuthorization)
		}
		if ephemeralKeys[wrap.EphemeralPrivate] {
			return nil, fmt.Errorf("%w: duplicate ephemeral key", ErrAuthorization)
		}
		ephemeralKeys[wrap.EphemeralPrivate] = true
		byID[key] = wrap
	}
	ordered := make([]RecipientWrapInput, 0, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		wrap, exists := byID[string(recipient.KeyID)]
		if !exists {
			return nil, fmt.Errorf("%w: missing wrap key id", ErrAuthorization)
		}
		ordered = append(ordered, wrap)
		delete(byID, string(recipient.KeyID))
	}
	if len(byID) != 0 {
		return nil, fmt.Errorf("%w: extra wrap key id", ErrAuthorization)
	}
	return ordered, nil
}

func prepareSealRecipients(policy Policy, wraps []RecipientWrapInput) ([]PreparedRecipient, error) {
	prepared := make([]PreparedRecipient, 0, len(policy.Recipients))
	for index, recipient := range policy.Recipients {
		if index >= len(wraps) || !bytes.Equal(wraps[index].KeyID, recipient.KeyID) {
			return nil, fmt.Errorf("%w: wrap ordering", ErrAuthorization)
		}
		prepared = append(prepared, PreparedRecipient{
			KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:]),
			EphemeralPrivate: bytes.Clone(wraps[index].EphemeralPrivate[:]), WrapNonce: wraps[index].WrapNonce,
		})
	}
	return prepared, nil
}

func decodeCertificateSet(encoded [][]byte) (map[string]Certificate, error) {
	result := make(map[string]Certificate, len(encoded))
	keyIDs := make(map[string]bool, len(encoded))
	for _, item := range encoded {
		certificate, err := DecodeCertificate(item)
		if err != nil {
			return nil, err
		}
		if _, exists := result[certificate.DeviceID]; exists || keyIDs[string(certificate.KeyID)] {
			return nil, fmt.Errorf("%w: duplicate certificate", ErrAuthorization)
		}
		result[certificate.DeviceID] = certificate
		keyIDs[string(certificate.KeyID)] = true
	}
	return result, nil
}

func findCertificate(encoded [][]byte, deviceID string, keyID []byte) (Certificate, bool) {
	for _, item := range encoded {
		certificate, err := DecodeCertificate(item)
		if err == nil && certificate.DeviceID == deviceID && bytes.Equal(certificate.KeyID, keyID) {
			return certificate, true
		}
	}
	return Certificate{}, false
}

func signPolicy(value Policy, key ed25519.PrivateKey) ([]byte, error) {
	prefix, err := encodePolicyPrefix(value)
	if err != nil {
		return nil, err
	}
	value.Signature, err = signObject("dottie/v1/sig-policy", prefix, key)
	if err != nil {
		return nil, err
	}
	return EncodePolicy(value)
}

func signControl(value Control, key ed25519.PrivateKey) ([]byte, error) {
	prefix, err := encodeControlPrefix(value)
	if err != nil {
		return nil, err
	}
	value.Signature, err = signObject("dottie/v1/sig-control", prefix, key)
	if err != nil {
		return nil, err
	}
	return EncodeControl(value)
}

func signCertificate(value Certificate, key ed25519.PrivateKey) ([]byte, error) {
	prefix, err := encodeCertificatePrefix(value)
	if err != nil {
		return nil, err
	}
	value.Signature, err = signObject("dottie/v1/sig-certificate", prefix, key)
	if err != nil {
		return nil, err
	}
	return EncodeCertificate(value)
}

func signCheckpoint(value Checkpoint, key ed25519.PrivateKey) ([]byte, error) {
	prefix, err := encodeCheckpointPrefix(value)
	if err != nil {
		return nil, err
	}
	value.Signature, err = signObject("dottie/v1/sig-checkpoint", prefix, key)
	if err != nil {
		return nil, err
	}
	return EncodeCheckpoint(value)
}

func signHead(value Head, key ed25519.PrivateKey) ([]byte, error) {
	prefix, err := encodeHeadPrefix(value)
	if err != nil {
		return nil, err
	}
	value.Signature, err = signObject("dottie/v1/sig-head", prefix, key)
	if err != nil {
		return nil, err
	}
	return EncodeHead(value)
}

func deriveVaultID(kit []byte, vaultName string) ([32]byte, error) {
	info := "dottie/v1/vault/" + vaultName
	derived, err := hkdf.Key[hash.Hash](sha256.New, kit, nil, info, 32)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: vault identity derivation", ErrFormat)
	}
	return sha256.Sum256(derived), nil
}

func RecoveryKitSigningPublicKey(kit []byte, vaultID [32]byte) (ed25519.PublicKey, error) {
	if len(kit) != 32 {
		return nil, fmt.Errorf("%w: recovery kit", ErrFormat)
	}
	privateKey, err := deriveKitSigningKey(kit, vaultID)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(privateKey.Public().(ed25519.PublicKey)), nil
}

func VerifyCheckpoint(encoded []byte, kitPublic ed25519.PublicKey) (Checkpoint, error) {
	checkpoint, err := DecodeCheckpoint(encoded)
	if err != nil {
		return Checkpoint{}, err
	}
	if len(kitPublic) != ed25519.PublicKeySize || checkpoint.Signer.DeviceID != "recovery-kit" {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint kit signer", ErrAuthorization)
	}
	fingerprint := sha256.Sum256(kitPublic)
	if !bytes.Equal(checkpoint.Signer.KeyID, fingerprint[:]) {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint kit key id", ErrAuthorization)
	}
	prefix := encoded[:len(encoded)-ed25519.SignatureSize]
	if err := Verify("dottie/v1/sig-checkpoint", objectSignaturePreimage(prefix), checkpoint.Signature[:], kitPublic); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func deriveKitSigningKey(kit []byte, vaultID [32]byte) (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key[hash.Hash](sha256.New, kit, vaultID[:], "dottie/v1/recovery-signing", ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("%w: kit key derivation", ErrFormat)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func rawCID(data []byte) ([]byte, error) {
	digest, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return nil, fmt.Errorf("%w: CID digest", ErrFormat)
	}
	return cid.NewCidV1(cid.Raw, digest).Bytes(), nil
}

func validateDeviceMaterial(material DeviceMaterial) error {
	if material.DeviceID == "" || len(material.DeviceID) > MaxDeviceIDBytes || !utf8.ValidString(material.DeviceID) || len(material.KeyID) == 0 || len(material.KeyID) > MaxKeyIDBytes {
		return fmt.Errorf("%w: device identity", ErrFormat)
	}
	if len(material.Signing) != ed25519.PrivateKeySize || material.Recipient == nil || len(material.Recipient.Bytes()) != 32 {
		return fmt.Errorf("%w: device keys", ErrFormat)
	}
	derived := ed25519.NewKeyFromSeed(material.Signing[:ed25519.SeedSize])
	if !bytes.Equal(derived, material.Signing) {
		return fmt.Errorf("%w: device signing key", ErrFormat)
	}
	return nil
}

func cloneByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func mustPolicyDigest(encoded []byte) [32]byte {
	digest, _ := ComputePolicyDigest(encoded)
	return digest
}
