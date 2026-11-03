package vault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
)

type devicesFixture struct {
	kit         []byte
	root        DeviceMaterial
	newDevice   DeviceMaterial
	bootstrap   BootstrapResult
	predecessor Predecessor
	intent      TransitionIntent
	transition  Transition
}

func newDevicesFixture(t *testing.T) devicesFixture {
	t.Helper()
	root := DeviceMaterial{DeviceID: "device-root", KeyID: []byte("root-key"), Signing: fixedSigningKey(11), Recipient: fixedX25519Key(21)}
	kit := fixtureBytes(1, 32)
	boot, err := Bootstrap(kit, "synthetic vault", root)
	require.NoError(t, err)
	policy, err := DecodePolicy(boot.Policy)
	require.NoError(t, err)
	control, err := DecodeControl(boot.Control)
	require.NoError(t, err)
	controlCID, err := rawCID(boot.Control)
	require.NoError(t, err)
	predecessor := Predecessor{
		ControlCID: controlCID, PolicyDigest: mustPolicyDigest(boot.Policy), EpochSeq: control.EpochSeq,
		Control: boot.Control, Policy: boot.Policy, Certificates: [][]byte{boot.Certificate}, TrustAnchor: boot.Anchor,
	}
	_ = policy
	newDevice := DeviceMaterial{DeviceID: "device-new", KeyID: []byte("new-key"), Signing: fixedSigningKey(12), Recipient: fixedX25519Key(22)}
	modelSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}}
	packed, err := Pack(modelSnapshot)
	require.NoError(t, err)
	wraps := []RecipientWrapInput{
		{KeyID: []byte("new-key"), EphemeralPrivate: [32]byte(fixtureBytes(31, 32)), WrapNonce: [24]byte(fixtureBytes(63, 24))},
		{KeyID: []byte("root-key"), EphemeralPrivate: [32]byte(fixtureBytes(87, 32)), WrapNonce: [24]byte(fixtureBytes(111, 24))},
	}
	newRecipientPrivate, err := ecdhPrivateForFixture(33)
	require.NoError(t, err)
	wraps[0].EphemeralPrivate = [32]byte(newRecipientPrivate.Bytes())
	rootRecipientPrivate, err := ecdhPrivateForFixture(34)
	require.NoError(t, err)
	wraps[1].EphemeralPrivate = [32]byte(rootRecipientPrivate.Bytes())
	intent := TransitionIntent{
		Kind: TransitionEnroll, Vault: boot.Vault, Signer: root, NewDevice: &newDevice, RequestedRole: RolePublisher,
		ContentKey: fixtureBytes(121, 32), Recipients: [][]byte{boot.Certificate}, Wraps: wraps,
		Plaintext: packed.Payload, PublicationID: [16]byte(fixtureBytes(153, 16)), Nonce: [24]byte(fixtureBytes(169, 24)),
	}
	transition, err := PrepareTransition(predecessor, intent)
	require.NoError(t, err)
	return devicesFixture{kit: kit, root: root, newDevice: newDevice, bootstrap: boot, predecessor: predecessor, intent: intent, transition: transition}
}

func ecdhPrivateForFixture(seed byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
}

func predecessorAfterTransition(t *testing.T, predecessor Predecessor, transition Transition) Predecessor {
	t.Helper()
	policyDigest, err := ComputePolicyDigest(transition.Policy)
	require.NoError(t, err)
	controlCID, err := rawCID(transition.Control)
	require.NoError(t, err)
	head, err := DecodeHead(transition.Head)
	require.NoError(t, err)
	return Predecessor{
		ControlCID: controlCID, PolicyDigest: policyDigest, EpochSeq: head.EpochSeq,
		HeadCID: bytes.Clone(head.SnapshotCID), Head: bytes.Clone(transition.Head), Control: bytes.Clone(transition.Control),
		Policy: bytes.Clone(transition.Policy), Certificates: cloneByteSlices(transition.Recipients), TrustAnchor: predecessor.TrustAnchor,
	}
}

type epochFirstSeenKey struct {
	vault [32]byte
	epoch uint64
}

type epochFirstSeenFixture map[epochFirstSeenKey]int64

func (store epochFirstSeenFixture) VaultEpochFirstSeen(_ context.Context, vaultID [32]byte, epoch uint64) (int64, bool, error) {
	firstSeenAt, found := store[epochFirstSeenKey{vault: vaultID, epoch: epoch}]
	return firstSeenAt, found, nil
}

func publicationTestIntent(fixture devicesFixture, predecessor Predecessor) PublicationIntent {
	firstSeen := epochFirstSeenFixture{
		epochFirstSeenKey{vault: fixture.bootstrap.Vault, epoch: predecessor.EpochSeq}: 1_700_000_000,
	}
	return PublicationIntent{
		Vault: fixture.bootstrap.Vault, Signer: fixture.newDevice, ContentKey: fixtureBytes(191, 32),
		Wraps: []RecipientWrapInput{
			{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(31, 32)), WrapNonce: [24]byte(fixtureBytes(63, 24))},
			{KeyID: bytes.Clone(fixture.newDevice.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(87, 32)), WrapNonce: [24]byte(fixtureBytes(111, 24))},
		},
		Plaintext: []byte("synthetic publication payload"), PublicationID: [16]byte(fixtureBytes(223, 16)), Nonce: [24]byte(fixtureBytes(239, 24)),
		EpochFirstSeen: firstSeen, Clock: func() time.Time { return time.Unix(1_700_000_001, 0) },
	}
}

func TestPreparePublicationUsesCountOnlyWithoutTrustedClock(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	intent := publicationTestIntent(fixture, predecessor)
	intent.Clock = nil
	publication, err := PreparePublication(predecessor, intent)
	require.NoError(t, err)
	assert.Equal(t, PublicationAgeTriggerNotEvaluatedNoTrustedClock, publication.AgeTriggerStatus)

	policy, err := DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	head, err := DecodeHead(predecessor.Head)
	require.NoError(t, err)
	head.PublicationCount = uint64(policy.MaxPublications)
	predecessor.Head, err = signHead(head, fixture.root.Signing)
	require.NoError(t, err)
	intent = publicationTestIntent(fixture, predecessor)
	intent.Clock = nil
	_, err = PreparePublication(predecessor, intent)
	assert.ErrorIs(t, err, ErrPublicationCount)
}

func newPublicationTestFixture(t *testing.T) (devicesFixture, Predecessor, Publication, PublicationIntent) {
	t.Helper()
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	intent := publicationTestIntent(fixture, predecessor)
	publication, err := PreparePublication(predecessor, intent)
	require.NoError(t, err)
	return fixture, predecessor, publication, intent
}

func TestPreparePublicationRefusesAtAndOverEpochAge(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	firstSeenAt := int64(1_700_000_000)
	intent := publicationTestIntent(fixture, predecessor)
	policy, err := DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	intent.Clock = func() time.Time { return time.Unix(firstSeenAt+int64(policy.MaxEpochAge)-1, 0) }
	publication, err := PreparePublication(predecessor, intent)
	require.NoError(t, err, "an epoch one second under its age limit permits publication")
	assert.Equal(t, PublicationAgeTriggerEvaluated, publication.AgeTriggerStatus)

	for _, age := range []int64{int64(policy.MaxEpochAge), int64(policy.MaxEpochAge) + 1} {
		intent.Clock = func() time.Time { return time.Unix(firstSeenAt+age, 0) }
		_, err = PreparePublication(predecessor, intent)
		assert.ErrorIs(t, err, ErrEpochRotationRequired)
	}
}

func TestPreparePublicationFailsClosedWhenEpochFirstSeenIsMissing(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	intent := publicationTestIntent(fixture, predecessor)
	intent.EpochFirstSeen = epochFirstSeenFixture{}
	_, err := PreparePublication(predecessor, intent)
	assert.ErrorIs(t, err, ErrEpochFirstSeenMissing)
}

func TestPreparePublicationUsesPublisherWithoutRootPrivateKey(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	intent := publicationTestIntent(fixture, predecessor)
	fixture.root = DeviceMaterial{}
	publication, err := PreparePublication(predecessor, intent)
	require.NoError(t, err)
	head, err := DecodeHead(publication.Head)
	require.NoError(t, err)
	assert.Equal(t, fixture.newDevice.DeviceID, head.Signer.DeviceID)
	assert.Equal(t, uint64(1), head.PublicationCount)
	assert.Equal(t, predecessor.EpochSeq, head.EpochSeq)
	assert.NoError(t, ValidatePublication(publication, predecessor))
}

func TestPreparePublicationRejectsCertificateNotNamedByPolicy(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	rogue := DeviceMaterial{DeviceID: "unlisted-publisher", KeyID: []byte("unlisted-key"), Signing: fixedSigningKey(77), Recipient: fixedX25519Key(78)}
	certificate, err := certificateForEnrollment(fixture.bootstrap.Vault, rogue, RolePublisher, predecessor.EpochSeq, fixture.root, predecessor.ControlCID)
	require.NoError(t, err)
	predecessor.Certificates = append(predecessor.Certificates, certificate)
	intent := publicationTestIntent(fixture, predecessor)
	intent.Signer = rogue
	_, err = PreparePublication(predecessor, intent)
	assert.ErrorIs(t, err, ErrPublicationAuthority)
}

func TestValidatePublicationRejectsCountSkipAndRepeat(t *testing.T) {
	fixture, predecessor, publication, _ := newPublicationTestFixture(t)
	for _, count := range []uint64{0, 2} {
		t.Run(fmt.Sprintf("count-%d", count), func(t *testing.T) {
			candidate := publication
			head, err := DecodeHead(candidate.Head)
			require.NoError(t, err)
			head.PublicationCount = count
			candidate.Head, err = signHead(head, fixture.newDevice.Signing)
			require.NoError(t, err)
			candidate.Digest = ComputePublicationDigest(candidate)
			assert.ErrorIs(t, ValidatePublication(candidate, predecessor), ErrPublicationCount)
		})
	}
}

func TestPrepareRevocationAdvancesEpochAndWithdrawsDevice(t *testing.T) {
	fixture, predecessor, _, _ := newPublicationTestFixture(t)
	intent := TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root, RevokeDeviceID: fixture.newDevice.DeviceID,
		ContentKey: fixtureBytes(31, 32), Recipients: [][]byte{predecessor.Certificates[0]},
		Wraps:     []RecipientWrapInput{{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(91, 32)), WrapNonce: [24]byte(fixtureBytes(123, 24))}},
		Plaintext: []byte("complete current snapshot"), PublicationID: [16]byte(fixtureBytes(157, 16)), Nonce: [24]byte(fixtureBytes(173, 24)),
	}
	transition, err := PrepareTransition(predecessor, intent)
	require.NoError(t, err)
	policy, err := DecodePolicy(transition.Policy)
	require.NoError(t, err)
	control, err := DecodeControl(transition.Control)
	require.NoError(t, err)
	head, err := DecodeHead(transition.Head)
	require.NoError(t, err)
	assert.Equal(t, predecessor.EpochSeq+1, policy.EpochSeq)
	assert.Equal(t, uint64(0), head.PublicationCount)
	assert.NotContains(t, deviceIDs(policy.Roles), fixture.newDevice.DeviceID)
	assert.NotContains(t, recipientDeviceIDs(policy.Recipients), fixture.newDevice.DeviceID)
	require.Len(t, control.Revoked, 1)
	assert.Equal(t, fixture.newDevice.DeviceID, control.Revoked[0].DeviceID)
	assert.Empty(t, transition.Certificate)
	assert.NoError(t, ValidateTransition(transition, predecessor))
}

func TestEnrollmentPreservesPredecessorRevocations(t *testing.T) {
	fixture := newDevicesFixture(t)
	firstPredecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	revocation, err := PrepareTransition(firstPredecessor, TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root, RevokeDeviceID: fixture.newDevice.DeviceID,
		ContentKey: fixtureBytes(31, 32), Recipients: [][]byte{firstPredecessor.Certificates[0]},
		Wraps:     []RecipientWrapInput{{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(91, 32)), WrapNonce: [24]byte(fixtureBytes(123, 24))}},
		Plaintext: []byte("state after revocation"), PublicationID: [16]byte(fixtureBytes(157, 16)), Nonce: [24]byte(fixtureBytes(169, 24)),
	})
	require.NoError(t, err)
	revokedPredecessor := predecessorAfterTransition(t, firstPredecessor, revocation)
	revokedControl, err := DecodeControl(revocation.Control)
	require.NoError(t, err)
	require.Len(t, revokedControl.Revoked, 1)

	next := DeviceMaterial{DeviceID: "device-next", KeyID: []byte("next-key"), Signing: fixedSigningKey(13), Recipient: fixedX25519Key(23)}
	enrollment, err := PrepareTransition(revokedPredecessor, TransitionIntent{
		Kind: TransitionEnroll, Vault: fixture.bootstrap.Vault, Signer: fixture.root, NewDevice: &next, RequestedRole: RolePublisher,
		ContentKey: fixtureBytes(41, 32), Recipients: cloneByteSlices(revokedPredecessor.Certificates),
		Wraps: []RecipientWrapInput{
			{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(51, 32)), WrapNonce: [24]byte(fixtureBytes(83, 24))},
			{KeyID: bytes.Clone(next.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(115, 32)), WrapNonce: [24]byte(fixtureBytes(147, 24))},
		},
		Plaintext: []byte("state after the next enrollment"), PublicationID: [16]byte(fixtureBytes(179, 16)), Nonce: [24]byte(fixtureBytes(195, 24)),
	})
	require.NoError(t, err)
	control, err := DecodeControl(enrollment.Control)
	require.NoError(t, err)
	assert.Equal(t, revokedControl.Revoked, control.Revoked)
	require.NoError(t, ValidateTransition(enrollment, revokedPredecessor))

	stripped := enrollment
	control.Revoked = nil
	stripped.Control = signControlValue(t, control, fixture.root.Signing)
	stripped.Digest = ComputeTransitionDigest(stripped)
	assert.ErrorIs(t, ValidateTransition(stripped, revokedPredecessor), ErrRevokedDevice)
}

func TestRevokedCertificateCannotPrepareLaterPublication(t *testing.T) {
	fixture, predecessor, _, _ := newPublicationTestFixture(t)
	intent := TransitionIntent{
		Kind: TransitionRevoke, Vault: fixture.bootstrap.Vault, Signer: fixture.root, RevokeDeviceID: fixture.newDevice.DeviceID,
		ContentKey: fixtureBytes(31, 32), Recipients: [][]byte{predecessor.Certificates[0]},
		Wraps:     []RecipientWrapInput{{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(91, 32)), WrapNonce: [24]byte(fixtureBytes(123, 24))}},
		Plaintext: []byte("complete current snapshot"), PublicationID: [16]byte(fixtureBytes(157, 16)), Nonce: [24]byte(fixtureBytes(173, 24)),
	}
	revocation, err := PrepareTransition(predecessor, intent)
	require.NoError(t, err)
	after := predecessorAfterTransition(t, predecessor, revocation)
	publicationIntent := PublicationIntent{
		Vault: fixture.bootstrap.Vault, Signer: fixture.newDevice, ContentKey: fixtureBytes(121, 32),
		Wraps:     []RecipientWrapInput{{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(201, 32)), WrapNonce: [24]byte(fixtureBytes(17, 24))}},
		Plaintext: []byte("must not publish"), PublicationID: [16]byte(fixtureBytes(41, 16)), Nonce: [24]byte(fixtureBytes(57, 24)),
	}
	_, err = PreparePublication(after, publicationIntent)
	assert.ErrorIs(t, err, ErrPublicationAuthority)
}

func deviceIDs(bindings []RoleBinding) []string {
	result := make([]string, len(bindings))
	for index, binding := range bindings {
		result[index] = binding.DeviceID
	}
	return result
}

func recipientDeviceIDs(recipients []PolicyRecipient) []string {
	result := make([]string, len(recipients))
	for index, recipient := range recipients {
		result[index] = recipient.DeviceID
	}
	return result
}

func TestBootstrapIsDeterministicAndPinsSelfSignedRoot(t *testing.T) {
	root := DeviceMaterial{DeviceID: "device-root", KeyID: []byte("root-key"), Signing: fixedSigningKey(11), Recipient: fixedX25519Key(21)}
	kit := fixtureBytes(1, 32)
	first, err := Bootstrap(kit, "vault-a", root)
	require.NoError(t, err)
	second, err := Bootstrap(kit, "vault-a", root)
	require.NoError(t, err)
	assert.Equal(t, first, second, "identical bootstrap inputs must produce identical signed bytes")
	other, err := Bootstrap(kit, "vault-b", root)
	require.NoError(t, err)
	assert.NotEqual(t, first.Vault, other.Vault, "vault names must derive distinct identities")

	certificate, err := DecodeCertificate(first.Certificate)
	require.NoError(t, err)
	assert.Equal(t, certificate.DeviceID, certificate.Issuer, "genesis root must be self-issued")
	request := OpenRequest{Vault: first.Vault, EpochSeq: 0, TrustAnchor: first.Anchor, Certificates: [][]byte{first.Certificate}}
	require.NoError(t, verifyCertificateChain(certificate, request, 1, make(map[string]bool)))
	policy, err := DecodePolicy(first.Policy)
	require.NoError(t, err)
	kitFingerprint, err := RecoveryKitPublicKeyFingerprint(kit, first.Vault)
	require.NoError(t, err)
	assert.Equal(t, kitFingerprint, policy.RecoveryAnchor, "bootstrap policy recovery anchor must identify the kit signing key")
	assert.NotEqual(t, first.Anchor, policy.RecoveryAnchor, "policy kit anchor must differ from the root signing-key anchor")
	policyPrefix, err := encodePolicyPrefix(policy)
	require.NoError(t, err)
	require.NoError(t, Verify("dottie/v1/sig-policy", objectSignaturePreimage(policyPrefix), policy.Signature[:], certificate.SigningPublicKey[:]))
	control, err := DecodeControl(first.Control)
	require.NoError(t, err)
	controlPrefix, err := encodeControlPrefix(control)
	require.NoError(t, err)
	require.NoError(t, Verify("dottie/v1/sig-control", objectSignaturePreimage(controlPrefix), control.Signature[:], certificate.SigningPublicKey[:]))
	checkpoint, err := DecodeCheckpoint(first.Checkpoint)
	require.NoError(t, err)
	assert.Equal(t, first.Anchor, checkpoint.Anchor, "checkpoint anchor")
	kitPublic, err := RecoveryKitSigningPublicKey(kit, first.Vault)
	require.NoError(t, err)
	kitKeyID := sha256.Sum256(kitPublic)
	assert.Equal(t, kitKeyID[:], checkpoint.Signer.KeyID, "checkpoint signer key id")
	verified, err := VerifyCheckpoint(first.Checkpoint, kitPublic)
	require.NoError(t, err)
	assert.Equal(t, checkpoint, verified, "verified checkpoint")
}

func TestRecoveryKitCheckpointVerificationAndDerivation(t *testing.T) {
	fixture := newDevicesFixture(t)
	public, err := RecoveryKitSigningPublicKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	repeated, err := RecoveryKitSigningPublicKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	assert.Equal(t, public, repeated, "kit signing public key derivation is deterministic")
	otherVault := fixture.bootstrap.Vault
	otherVault[0] ^= 1
	otherPublic, err := RecoveryKitSigningPublicKey(fixture.kit, otherVault)
	require.NoError(t, err)
	assert.NotEqual(t, public, otherPublic, "different vault ids derive different kit signing keys")
	_, err = RecoveryKitSigningPublicKey(fixture.kit[:31], fixture.bootstrap.Vault)
	assert.ErrorIs(t, err, ErrFormat, "short kit is rejected")

	verified, err := VerifyCheckpoint(fixture.bootstrap.Checkpoint, public)
	require.NoError(t, err)
	assert.Equal(t, fixture.bootstrap.Anchor, verified.Anchor, "checkpoint continues to carry the root signing-key anchor")
	kitFingerprint, err := RecoveryKitPublicKeyFingerprint(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	assert.NotEqual(t, kitFingerprint, verified.Anchor, "checkpoint root anchor remains distinct from the kit fingerprint")

	otherKit := fixture.kit
	otherKit[0] ^= 1
	otherPublic, err = RecoveryKitSigningPublicKey(otherKit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	_, err = VerifyCheckpoint(fixture.bootstrap.Checkpoint, otherPublic)
	assert.ErrorIs(t, err, ErrAuthorization, "a different kit cannot verify the checkpoint")

	checkpoint, err := DecodeCheckpoint(fixture.bootstrap.Checkpoint)
	require.NoError(t, err)
	checkpoint.Anchor[0] ^= 1
	private, err := deriveKitSigningKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	alteredAnchor, err := signCheckpointBytes(checkpoint, private)
	require.NoError(t, err)
	_, err = VerifyCheckpoint(alteredAnchor, public)
	assert.ErrorIs(t, err, ErrSignature, "altered checkpoint anchor invalidates its signature")

	checkpoint, err = DecodeCheckpoint(fixture.bootstrap.Checkpoint)
	require.NoError(t, err)
	checkpoint.Signer.KeyID[0] ^= 1
	alteredKeyID, err := signCheckpointBytes(checkpoint, private)
	require.NoError(t, err)
	_, err = VerifyCheckpoint(alteredKeyID, public)
	assert.ErrorIs(t, err, ErrAuthorization, "claimed kit key fingerprint mismatch")
}

func TestPrepareTransitionFirstEnrollmentCreatesFirstSnapshot(t *testing.T) {
	fixture := newDevicesFixture(t)
	genesisControl, err := DecodeControl(fixture.bootstrap.Control)
	require.NoError(t, err)
	assert.Empty(t, genesisControl.HeadSnapshotCID, "genesis has no snapshot")
	transition, err := PrepareTransition(fixture.predecessor, fixture.intent)
	require.NoError(t, err)
	assert.Equal(t, fixture.transition, transition, "explicit transition entropy must reproduce the same bundle")
	assert.NotEmpty(t, transition.Snapshot, "enrollment must seal the packed state")
	head, err := DecodeHead(transition.Head)
	require.NoError(t, err)
	assert.NotEmpty(t, head.SnapshotCID, "first transition must publish a snapshot CID")
	assert.Equal(t, uint64(0), head.PublicationCount, "administrative head starts at zero publications")
	envelope, err := DecodeEnvelope(transition.Snapshot)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), envelope.EpochSeq, "first snapshot uses the successor epoch")
	assert.Equal(t, fixture.intent.Plaintext, openTransitionSnapshot(t, fixture, transition, fixture.root), "root recipient opens the packed first snapshot")
	assert.Equal(t, fixture.intent.Plaintext, openTransitionSnapshot(t, fixture, transition, fixture.newDevice), "enrolled recipient opens the packed first snapshot")
	require.NoError(t, ValidateTransition(transition, fixture.predecessor))
}

func TestPrepareTransitionReencryptsCallerStateForExistingHead(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := fixture.predecessor
	predecessor.HeadCID = fixtureCIDBytes(t)
	control, err := DecodeControl(predecessor.Control)
	require.NoError(t, err)
	control.HeadSnapshotCID = fixtureCIDBytes(t)
	predecessor.Control = signControlValue(t, control, fixture.root.Signing)
	predecessor.ControlCID, err = rawCID(predecessor.Control)
	require.NoError(t, err)
	transition, err := PrepareTransition(predecessor, fixture.intent)
	require.NoError(t, err)
	envelope, err := DecodeEnvelope(transition.Snapshot)
	require.NoError(t, err)
	assert.Equal(t, predecessor.HeadCID, envelope.Parent, "successor snapshot carries the observed predecessor head")
	head, err := DecodeHead(transition.Head)
	require.NoError(t, err)
	assert.Equal(t, predecessor.HeadCID, head.PrevHeadCID, "successor head links to the observed predecessor head")
	assert.Equal(t, fixture.intent.Plaintext, openTransitionSnapshot(t, fixture, transition, fixture.root), "existing current state was re-encrypted")
}

func TestPrepareTransitionRejectsEscalationNonRootAndDuplicateDevice(t *testing.T) {
	fixture := newDevicesFixture(t)
	escalation := fixture.intent
	escalation.RequestedRole = RoleRoot
	_, err := PrepareTransition(fixture.predecessor, escalation)
	assert.ErrorIs(t, err, ErrAuthorization, "enrollment cannot issue a root certificate")

	nonRoot := fixture.intent
	nonRoot.Signer = fixture.newDevice
	_, err = PrepareTransition(fixture.predecessor, nonRoot)
	assert.ErrorIs(t, err, ErrAuthorization, "a non-root device cannot authorize enrollment")

	duplicate := fixture.intent
	duplicateDevice := fixture.newDevice
	duplicateDevice.DeviceID = fixture.root.DeviceID
	duplicate.NewDevice = &duplicateDevice
	_, err = PrepareTransition(fixture.predecessor, duplicate)
	assert.ErrorIs(t, err, ErrAuthorization, "duplicate device identifiers are rejected")
}

func TestEnrollmentTranscriptFingerprintBindsEveryRequestedField(t *testing.T) {
	fixture := newDevicesFixture(t)
	device := fixture.newDevice
	signingPublic := device.Signing.Public().(ed25519.PublicKey)
	recipientPublic := device.Recipient.PublicKey().Bytes()
	base := EnrollmentTranscriptFingerprint(fixture.bootstrap.Vault, device.DeviceID, device.KeyID, RolePublisher, signingPublic, recipientPublic)
	roleChange := EnrollmentTranscriptFingerprint(fixture.bootstrap.Vault, device.DeviceID, device.KeyID, RoleRestoreOnly, signingPublic, recipientPublic)
	deviceChange := EnrollmentTranscriptFingerprint(fixture.bootstrap.Vault, "other-device", device.KeyID, RolePublisher, signingPublic, recipientPublic)
	assert.NotEqual(t, base, roleChange, "role substitution changes transcript fingerprint")
	assert.NotEqual(t, base, deviceChange, "device substitution changes transcript fingerprint")
}

func TestValidateTransitionRevalidationChecksReturnSpecificErrors(t *testing.T) {
	fixture := newDevicesFixture(t)

	t.Run("1 observed revision mismatch", func(t *testing.T) {
		transition := fixture.transition
		transition.Predecessor.EpochSeq++
		err := ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrObservedRevision, "check 1 error")
	})

	t.Run("1 unauthenticated predecessor", func(t *testing.T) {
		predecessor := fixture.predecessor
		predecessor.Control = bytes.Clone(predecessor.Control)
		predecessor.Control[len(predecessor.Control)-1] ^= 1
		err := ValidateTransition(fixture.transition, predecessor)
		assert.ErrorIs(t, err, ErrPredecessor, "check 1 authentication error")
	})

	t.Run("2 proposer role", func(t *testing.T) {
		predecessor := fixture.predecessor
		policy, err := DecodePolicy(predecessor.Policy)
		require.NoError(t, err)
		policy.Roles[0].Role = RolePublisher
		predecessor.Policy = signPolicyValue(t, policy, fixture.root.Signing)
		predecessor.PolicyDigest = mustPolicyDigest(predecessor.Policy)
		control, err := DecodeControl(predecessor.Control)
		require.NoError(t, err)
		control.PolicyDigest = predecessor.PolicyDigest
		predecessor.Control = signControlValue(t, control, fixture.root.Signing)
		predecessor.ControlCID, err = rawCID(predecessor.Control)
		require.NoError(t, err)
		transition := fixture.transition
		transition.Predecessor = predecessorReference(predecessor)
		err = ValidateTransition(transition, predecessor)
		assert.ErrorIs(t, err, ErrProposerRole, "check 2 error")
	})

	t.Run("3 epoch increments exactly once", func(t *testing.T) {
		transition := remakeTransition(t, fixture, fixture.transition, func(policy *Policy, _ *Certificate, _ *Envelope) {
			policy.EpochSeq = 2
		})
		err := ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrTransitionEpoch, "check 3 error")
	})

	t.Run("4 policy ancestry", func(t *testing.T) {
		transition := remakeTransition(t, fixture, fixture.transition, func(policy *Policy, _ *Certificate, _ *Envelope) {
			policy.PrevPolicyDigest[0] ^= 1
		})
		err := ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrPolicyAncestry, "check 4 error")
	})

	t.Run("5 control ancestry", func(t *testing.T) {
		transition := fixture.transition
		control, err := DecodeControl(transition.Control)
		require.NoError(t, err)
		control.PrevControlCID = []byte("wrong-parent")
		transition.Control = signControlValue(t, control, fixture.root.Signing)
		transition.Digest = ComputeTransitionDigest(transition)
		err = ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrControlAncestry, "check 5 error")
	})

	t.Run("6 certificate issuer and role", func(t *testing.T) {
		transition := remakeTransition(t, fixture, fixture.transition, func(_ *Policy, certificate *Certificate, _ *Envelope) {
			certificate.Issuer = "not-root"
		})
		err := ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrCertificateAuthority, "check 6 error")
	})

	t.Run("7 certified recipient set", func(t *testing.T) {
		transition := fixture.transition
		transition.Recipients = transition.Recipients[:1]
		transition.Digest = ComputeTransitionDigest(transition)
		err := ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrTransitionRecipients, "check 7 error")
	})

	t.Run("8 snapshot old epoch", func(t *testing.T) {
		transition := remakeTransition(t, fixture, fixture.transition, func(_ *Policy, _ *Certificate, envelope *Envelope) {
			envelope.EpochSeq = 0
		})
		err := ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrSnapshotEpoch, "check 8 error")
	})

	t.Run("9 head snapshot linkage and count", func(t *testing.T) {
		transition := fixture.transition
		head, err := DecodeHead(transition.Head)
		require.NoError(t, err)
		head.PublicationCount = 1
		transition.Head = signHeadValue(t, head, fixture.root.Signing)
		transition.Digest = ComputeTransitionDigest(transition)
		err = ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrHeadLinkage, "check 9 error")
	})

	t.Run("10 checkpoint anchor", func(t *testing.T) {
		checkpoint, err := DecodeCheckpoint(fixture.bootstrap.Checkpoint)
		require.NoError(t, err)
		checkpoint.Anchor[0] ^= 1
		kitKey, err := deriveKitSigningKey(fixture.kit, fixture.bootstrap.Vault)
		require.NoError(t, err)
		checkpointBytes, err := signCheckpointBytes(checkpoint, kitKey)
		require.NoError(t, err)
		transition := fixture.transition
		transition.Checkpoint = checkpointBytes
		err = ValidateTransition(transition, fixture.predecessor)
		assert.ErrorIs(t, err, ErrCheckpointAnchor, "check 10 error")
	})
}

func TestPrepareTransitionRejectsSnapshotUnderOldEpoch(t *testing.T) {
	fixture := newDevicesFixture(t)
	transition := remakeTransition(t, fixture, fixture.transition, func(_ *Policy, _ *Certificate, envelope *Envelope) {
		envelope.EpochSeq = fixture.predecessor.EpochSeq
	})
	err := ValidateTransition(transition, fixture.predecessor)
	assert.ErrorIs(t, err, ErrSnapshotEpoch, "old-epoch envelope must fail check 8")
}

func TestEnrollmentCertificateUsesRootSignerAndRequestedRole(t *testing.T) {
	fixture := newDevicesFixture(t)
	encoded, err := certificateForEnrollment(fixture.bootstrap.Vault, fixture.newDevice, RolePublisher, 1, fixture.root, fixture.predecessor.ControlCID)
	require.NoError(t, err)
	certificate, err := DecodeCertificate(encoded)
	require.NoError(t, err)
	assert.Equal(t, fixture.root.DeviceID, certificate.Issuer, "issuer device id")
	assert.Equal(t, RolePublisher, certificate.Role, "requested role")
	assert.Equal(t, fixture.root.DeviceID, certificate.Signer.DeviceID, "certificate signer")
}

func openTransitionSnapshot(t *testing.T, fixture devicesFixture, transition Transition, device DeviceMaterial) []byte {
	t.Helper()
	envelope, err := DecodeEnvelope(transition.Snapshot)
	require.NoError(t, err)
	request := OpenRequest{
		Vault: fixture.bootstrap.Vault, EpochSeq: 1, PolicyDigest: mustPolicyDigest(transition.Policy),
		Policy: transition.Policy, TrustAnchor: fixture.bootstrap.Anchor, Certificates: transition.Recipients,
		DeviceKeyID: device.KeyID, DeviceKey: device.Recipient,
	}
	plaintext, err := Open(envelope, request)
	require.NoError(t, err)
	return plaintext
}

func predecessorReference(predecessor Predecessor) PredecessorRef {
	return PredecessorRef{ControlCID: bytes.Clone(predecessor.ControlCID), PolicyDigest: predecessor.PolicyDigest, EpochSeq: predecessor.EpochSeq, HeadCID: bytes.Clone(predecessor.HeadCID)}
}

func remakeTransition(t *testing.T, fixture devicesFixture, transition Transition, mutate func(*Policy, *Certificate, *Envelope)) Transition {
	t.Helper()
	policy, err := DecodePolicy(transition.Policy)
	require.NoError(t, err)
	certificate, err := DecodeCertificate(transition.Certificate)
	require.NoError(t, err)
	envelope, err := DecodeEnvelope(transition.Snapshot)
	require.NoError(t, err)
	mutate(&policy, &certificate, &envelope)
	certificate.CertEpoch = policy.EpochSeq
	transition.Policy = signPolicyValue(t, policy, fixture.root.Signing)
	transition.Certificate = signCertificateValue(t, certificate, fixture.root.Signing)
	for index, encoded := range transition.Recipients {
		current, decodeErr := DecodeCertificate(encoded)
		require.NoError(t, decodeErr)
		if current.DeviceID == certificate.DeviceID {
			transition.Recipients[index] = transition.Certificate
		}
	}
	transitionPolicy, err := DecodePolicy(transition.Policy)
	require.NoError(t, err)
	policyDigest := mustPolicyDigest(transition.Policy)
	envelope.PolicyDigest = policyDigest
	envelope.Signature = signEnvelopeForFixture(t, envelope, fixture.root.Signing)
	transition.Snapshot, err = EncodeEnvelope(envelope)
	require.NoError(t, err)
	transition.SnapshotCID, err = rawCID(transition.Snapshot)
	require.NoError(t, err)
	transition.BlobCID = bytes.Clone(transition.SnapshotCID)
	control, err := DecodeControl(transition.Control)
	require.NoError(t, err)
	control.EpochSeq = transitionPolicy.EpochSeq
	control.PolicyDigest = policyDigest
	control.HeadSnapshotCID = bytes.Clone(transition.SnapshotCID)
	transition.Control = signControlValue(t, control, fixture.root.Signing)
	head, err := DecodeHead(transition.Head)
	require.NoError(t, err)
	head.EpochSeq = transitionPolicy.EpochSeq
	head.PolicyDigest = policyDigest
	head.SnapshotCID = bytes.Clone(transition.SnapshotCID)
	head.BlobCID = bytes.Clone(transition.BlobCID)
	transition.Head = signHeadValue(t, head, fixture.root.Signing)
	transition.Digest = ComputeTransitionDigest(transition)
	return transition
}

func signEnvelopeForFixture(t *testing.T, envelope Envelope, key ed25519.PrivateKey) [ed25519.SignatureSize]byte {
	t.Helper()
	prefix, err := encodeEnvelopePrefix(envelope)
	require.NoError(t, err)
	signature, err := Sign(contextForPurpose(envelope.Purpose), append([]byte(preimageSig), prefix...), key)
	require.NoError(t, err)
	var result [ed25519.SignatureSize]byte
	copy(result[:], signature)
	return result
}

func signCheckpointBytes(checkpoint Checkpoint, key ed25519.PrivateKey) ([]byte, error) {
	prefix, err := encodeCheckpointPrefix(checkpoint)
	if err != nil {
		return nil, err
	}
	checkpoint.Signature, err = signObject("dottie/v1/sig-checkpoint", prefix, key)
	if err != nil {
		return nil, err
	}
	return EncodeCheckpoint(checkpoint)
}

func TestValidateTransitionRejectsDeltaBeyondTheEnrollment(t *testing.T) {
	fixture := newDevicesFixture(t)
	baseline, err := PrepareTransition(fixture.predecessor, fixture.intent)
	require.NoError(t, err)

	extraRootDevice := DeviceMaterial{
		DeviceID: "device-extra-root", KeyID: []byte("extra-root-key"),
		Signing: fixedSigningKey(13), Recipient: fixedX25519Key(23),
	}
	rootPolicy, err := DecodePolicy(fixture.bootstrap.Policy)
	require.NoError(t, err)
	extraRootCertificate := Certificate{
		Vault: rootPolicy.Vault, DeviceID: extraRootDevice.DeviceID, KeyID: extraRootDevice.KeyID,
		SigningPublicKey:    [ed25519.PublicKeySize]byte(extraRootDevice.Signing.Public().(ed25519.PublicKey)),
		EncryptionPublicKey: [32]byte(extraRootDevice.Recipient.PublicKey().Bytes()),
		Role:                RoleRoot, CertEpoch: 1, Issuer: fixture.root.DeviceID,
		Signer: Signer{DeviceID: fixture.root.DeviceID, KeyID: fixture.root.KeyID},
	}
	extraRootBytes := signCertificateValue(t, extraRootCertificate, fixture.root.Signing)

	addRoot := rebuildTransition(t, baseline, fixture.root.Signing, func(policy *Policy, control *Control) {
		policy.Roles = append(policy.Roles, RoleBinding{DeviceID: "device-extra-root", Role: RoleRoot})
		policy.Recipients = append(policy.Recipients, PolicyRecipient{
			DeviceID: "device-extra-root", KeyID: extraRootDevice.KeyID, PublicKey: [32]byte(extraRootDevice.Recipient.PublicKey().Bytes()),
		})
		control.PolicyDigest = mustPolicyDigestForTest(t, *policy, fixture)
	})
	addRoot.Recipients = append(addRoot.Recipients, extraRootBytes)
	assert.ErrorIs(t, ValidateTransition(addRoot, fixture.predecessor), ErrTransitionDelta,
		"an enrollment may not add a second root device")

	roleSwap := rebuildTransition(t, baseline, fixture.root.Signing, func(policy *Policy, control *Control) {
		for index := range policy.Roles {
			if policy.Roles[index].DeviceID == fixture.root.DeviceID {
				policy.Roles[index].Role = RolePublisher
			}
		}
		control.PolicyDigest = mustPolicyDigestForTest(t, *policy, fixture)
	})
	assert.ErrorIs(t, ValidateTransition(roleSwap, fixture.predecessor), ErrTransitionDelta,
		"an enrollment may not change an existing role")

	removal := rebuildTransition(t, baseline, fixture.root.Signing, func(policy *Policy, control *Control) {
		kept := policy.Roles[:0]
		for _, binding := range policy.Roles {
			if binding.DeviceID != fixture.root.DeviceID {
				kept = append(kept, binding)
			}
		}
		policy.Roles = kept
		control.PolicyDigest = mustPolicyDigestForTest(t, *policy, fixture)
	})
	assert.ErrorIs(t, ValidateTransition(removal, fixture.predecessor), ErrTransitionDelta,
		"an enrollment may not remove a device")
}

func TestValidateTransitionRejectsRevokedDeviceAndCheckpoint(t *testing.T) {
	fixture := newDevicesFixture(t)
	baseline, err := PrepareTransition(fixture.predecessor, fixture.intent)
	require.NoError(t, err)

	revokedPredecessor := fixture.predecessor
	revokedControl, err := DecodeControl(revokedPredecessor.Control)
	require.NoError(t, err)
	revokedControl.Revoked = append(revokedControl.Revoked, RevokedDevice{
		DeviceID: fixture.newDevice.DeviceID, CertEpoch: 1,
	})
	revokedBytes := signControlValue(t, revokedControl, fixture.root.Signing)
	revokedPredecessor.Control = revokedBytes
	revokedCID, err := rawCID(revokedBytes)
	require.NoError(t, err)
	revokedPredecessor.ControlCID = revokedCID
	bundleControl, err := DecodeControl(baseline.Control)
	require.NoError(t, err)
	bundleControl.PrevControlCID = revokedCID
	certificate, err := DecodeCertificate(baseline.Certificate)
	require.NoError(t, err)
	signedCertificate := signCertificateValue(t, certificate, fixture.root.Signing)
	bundle := baseline
	bundle.Predecessor.ControlCID = revokedCID
	bundle.Control = signControlValue(t, bundleControl, fixture.root.Signing)
	bundle.Certificate = signedCertificate
	replaced := make([][]byte, 0, len(bundle.Recipients))
	for _, encoded := range bundle.Recipients {
		candidate, decodeErr := DecodeCertificate(encoded)
		if decodeErr == nil && candidate.DeviceID == certificate.DeviceID {
			replaced = append(replaced, signedCertificate)
			continue
		}
		replaced = append(replaced, encoded)
	}
	bundle.Recipients = replaced
	bundle.Digest = ComputeTransitionDigest(bundle)
	assert.ErrorIs(t, ValidateTransition(bundle, revokedPredecessor), ErrRevokedDevice,
		"a device revoked at the successor epoch cannot be enrolled")

	withCheckpoint := baseline
	withCheckpoint.Checkpoint = []byte{0x44, 0x54, 0x45, 0x01, 0x05}
	assert.ErrorIs(t, ValidateTransition(withCheckpoint, fixture.predecessor), ErrCheckpointAnchor,
		"an enrollment writes no checkpoint, so a supplied one cannot be authenticated")
}

func TestValidateTransitionRejectsUnauthenticatedPredecessorIdentifier(t *testing.T) {
	fixture := newDevicesFixture(t)
	baseline, err := PrepareTransition(fixture.predecessor, fixture.intent)
	require.NoError(t, err)

	claimed := baseline
	claimed.Predecessor.ControlCID = fixtureCIDBytes(t)
	claimed.Digest = ComputeTransitionDigest(claimed)
	assert.ErrorIs(t, ValidateTransition(claimed, fixture.predecessor), ErrObservedRevision,
		"a bundle claiming a different predecessor is rejected at check 1")

	unauthenticated := fixture.predecessor
	unauthenticated.ControlCID = fixtureCIDBytes(t)
	assert.ErrorIs(t, ValidateTransition(baseline, unauthenticated), ErrPredecessor,
		"a predecessor whose identifier does not match its control bytes is not authenticated")
}

func mustPolicyDigestForTest(t *testing.T, policy Policy, fixture devicesFixture) [32]byte {
	t.Helper()
	encoded := signPolicyValue(t, policy, fixture.root.Signing)
	digest, err := ComputePolicyDigest(encoded)
	require.NoError(t, err)
	return digest
}

func rebuildTransition(t *testing.T, baseline Transition, rootKey ed25519.PrivateKey, mutate func(*Policy, *Control)) Transition {
	t.Helper()
	policy, err := DecodePolicy(baseline.Policy)
	require.NoError(t, err)
	control, err := DecodeControl(baseline.Control)
	require.NoError(t, err)
	mutate(&policy, &control)
	rebuilt := baseline
	rebuilt.Policy = signPolicyValue(t, policy, rootKey)
	digest, err := ComputePolicyDigest(rebuilt.Policy)
	require.NoError(t, err)
	control.PolicyDigest = digest
	rebuilt.Control = signControlValue(t, control, rootKey)
	rebuilt.Digest = ComputeTransitionDigest(rebuilt)
	return rebuilt
}

func TestEnrolledCertificateCarriesNoRevocationReference(t *testing.T) {
	fixture := newDevicesFixture(t)
	transition, err := PrepareTransition(fixture.predecessor, fixture.intent)
	require.NoError(t, err)
	certificate, err := DecodeCertificate(transition.Certificate)
	require.NoError(t, err)
	assert.Empty(t, certificate.RevocationRef,
		"an active certificate records the epoch it was issued at, not a revocation reference")
	assert.Equal(t, transition.Predecessor.EpochSeq+1, certificate.CertEpoch,
		"issuance is bound by cert_epoch")

	revoked := certificate
	revoked.RevocationRef = transition.Predecessor.ControlCID
	revokedBytes := signCertificateValue(t, revoked, fixture.root.Signing)
	replaced := make([][]byte, 0, len(transition.Recipients))
	for _, encoded := range transition.Recipients {
		candidate, decodeErr := DecodeCertificate(encoded)
		if decodeErr == nil && candidate.DeviceID == revoked.DeviceID {
			replaced = append(replaced, revokedBytes)
			continue
		}
		replaced = append(replaced, encoded)
	}
	bundle := transition
	bundle.Certificate = revokedBytes
	bundle.Recipients = replaced
	bundle.Digest = ComputeTransitionDigest(bundle)
	assert.ErrorIs(t, ValidateTransition(bundle, fixture.predecessor), ErrCertificateAuthority,
		"a non-empty revocation reference marks the certificate revoked and must be refused")
}
