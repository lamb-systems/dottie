package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type policyRangeCase struct {
	name   string
	field  string
	mutate func(*Policy)
}

func outOfRangePolicyCases() []policyRangeCase {
	return []policyRangeCase{
		{name: "max_publications_below_minimum", field: "max_publications", mutate: func(policy *Policy) { policy.MaxPublications = 0 }},
		{name: "max_publications_above_maximum", field: "max_publications", mutate: func(policy *Policy) { policy.MaxPublications = 100001 }},
		{name: "max_epoch_age_below_minimum", field: "max_epoch_age", mutate: func(policy *Policy) { policy.MaxEpochAge = 3599 }},
		{name: "max_epoch_age_above_maximum", field: "max_epoch_age", mutate: func(policy *Policy) { policy.MaxEpochAge = 31536001 }},
	}
}

func outOfRangePolicyDigest(encoded []byte) [32]byte {
	return sha256.Sum256(append([]byte(preimagePolicy), encoded...))
}

func outOfRangePolicyWire(t *testing.T, value Policy, key ed25519.PrivateKey) []byte {
	t.Helper()
	prefix, err := encodePolicyPrefix(value)
	require.NoError(t, err)
	signature, err := signObject("dottie/v1/sig-policy", prefix, key)
	require.NoError(t, err)
	value.Signature = signature
	encoded, err := EncodePolicy(value)
	require.NoError(t, err)
	return encoded
}

func rebuildEnrollmentRaw(t *testing.T, fixture devicesFixture, mutate func(*Policy)) Transition {
	t.Helper()
	policy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	mutate(&policy)
	policyBytes := outOfRangePolicyWire(t, policy, fixture.root.Signing)
	copy(policy.Signature[:], policyBytes[len(policyBytes)-ed25519.SignatureSize:])
	digest := outOfRangePolicyDigest(policyBytes)
	wraps, err := prepareRecipientWraps(policy, fixture.intent.Wraps)
	require.NoError(t, err)
	recipients, err := prepareSealRecipients(policy, wraps)
	require.NoError(t, err)
	envelope, err := SealPrepared(PreparedSeal{
		Purpose: PurposeSnapshot, Vault: policy.Vault, PublicationID: fixture.intent.PublicationID, EpochSeq: policy.EpochSeq,
		PolicyDigest: digest, Parent: bytes.Clone(fixture.predecessor.HeadCID), DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID),
		Plaintext: fixture.intent.Plaintext, SigningKey: fixture.root.Signing, ContentKey: fixture.intent.ContentKey, Nonce: fixture.intent.Nonce, Recipients: recipients, Policy: policy,
	})
	require.NoError(t, err)
	envelopeBytes, err := EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshotCID, err := rawCID(envelopeBytes)
	require.NoError(t, err)
	oldControl, err := DecodeControl(fixture.transition.Control)
	require.NoError(t, err)
	control := Control{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: digest, HeadSnapshotCID: bytes.Clone(snapshotCID),
		Revoked: oldControl.Revoked, PrevControlCID: bytes.Clone(fixture.predecessor.ControlCID),
		Signer: Signer{DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID)},
	}
	controlBytes, err := signControl(control, fixture.root.Signing)
	require.NoError(t, err)
	head := Head{
		Vault: policy.Vault, EpochSeq: policy.EpochSeq, PolicyDigest: digest, SnapshotCID: bytes.Clone(snapshotCID),
		BlobCID: bytes.Clone(snapshotCID), PublicationCount: 0, PrevHeadCID: bytes.Clone(fixture.predecessor.HeadCID),
		Signer: Signer{DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID)},
	}
	headBytes, err := signHead(head, fixture.root.Signing)
	require.NoError(t, err)
	transition := Transition{
		Kind: TransitionEnroll, Predecessor: fixture.transition.Predecessor, Policy: policyBytes, Control: controlBytes,
		Certificate: fixture.transition.Certificate, Head: headBytes, Snapshot: envelopeBytes, SnapshotCID: snapshotCID,
		BlobCID: bytes.Clone(snapshotCID), Recipients: fixture.transition.Recipients,
	}
	transition.Digest = ComputeTransitionDigest(transition)
	return transition
}

func TestPolicyDecoderAcceptsRangeEndpoints(t *testing.T) {
	for _, check := range []struct {
		name   string
		value  uint32
		mutate func(*Policy)
		read   func(Policy) uint32
	}{
		{name: "max_publications_minimum", value: 1, mutate: func(policy *Policy) { policy.MaxPublications = 1 }, read: func(policy Policy) uint32 { return policy.MaxPublications }},
		{name: "max_publications_maximum", value: 100000, mutate: func(policy *Policy) { policy.MaxPublications = 100000 }, read: func(policy Policy) uint32 { return policy.MaxPublications }},
		{name: "max_epoch_age_minimum", value: 3600, mutate: func(policy *Policy) { policy.MaxEpochAge = 3600 }, read: func(policy Policy) uint32 { return policy.MaxEpochAge }},
		{name: "max_epoch_age_maximum", value: 31536000, mutate: func(policy *Policy) { policy.MaxEpochAge = 31536000 }, read: func(policy Policy) uint32 { return policy.MaxEpochAge }},
	} {
		t.Run(check.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			policy, err := DecodePolicy(fixture.transition.Policy)
			require.NoError(t, err)
			check.mutate(&policy)
			encoded := outOfRangePolicyWire(t, policy, fixture.root.Signing)

			decoded, err := DecodePolicy(encoded)
			require.NoError(t, err, "DecodePolicy accepts the %s endpoint", check.name)
			assert.Equal(t, check.value, check.read(decoded))
		})
	}
}

func TestPolicyDecoderRefusesOutOfRangeBounds(t *testing.T) {
	for _, check := range outOfRangePolicyCases() {
		t.Run(check.name, func(t *testing.T) {
			fixture := newDevicesFixture(t)
			policy, err := DecodePolicy(fixture.transition.Policy)
			require.NoError(t, err)
			check.mutate(&policy)
			encoded := outOfRangePolicyWire(t, policy, fixture.root.Signing)

			_, decodeErr := DecodePolicy(encoded)
			require.ErrorIs(t, decodeErr, ErrLimit, "DecodePolicy rejects out-of-range %s", check.name)
			assert.ErrorContains(t, decodeErr, check.field, "DecodePolicy identifies out-of-range %s", check.field)

			transition := rebuildEnrollmentRaw(t, fixture, check.mutate)
			transitionErr := ValidateTransition(transition, fixture.predecessor)
			require.ErrorIs(t, transitionErr, ErrTransitionSignature,
				"ValidateTransition rejects out-of-range %s", check.name)
			assert.ErrorIs(t, transitionErr, ErrLimit, "ValidateTransition preserves the policy range error")
			assert.ErrorContains(t, transitionErr, check.field, "ValidateTransition identifies out-of-range %s", check.field)
		})
	}
}
