package vault

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func onboardingBundleFixture(t *testing.T) (devicesFixture, OnboardingBundle) {
	t.Helper()
	fixture := newDevicesFixture(t)
	genesis, err := ComposeGenesis(GenesisIntent{
		Kit: fixture.kit, VaultName: "synthetic vault", RootDevice: fixture.root, ContentKey: fixtureBytes(201, 32),
		Wraps:         []RecipientWrapInput{{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(202, 32)), WrapNonce: [24]byte(fixtureBytes(203, 24))}},
		PublicationID: [16]byte(fixtureBytes(204, 16)), Nonce: [24]byte(fixtureBytes(205, 24)),
	})
	require.NoError(t, err)
	predecessor := Predecessor{
		ControlCID: bytes.Clone(genesis.ControlCID), PolicyDigest: genesis.PolicyDigest, EpochSeq: 0, HeadCID: bytes.Clone(genesis.SnapshotCID),
		Head: bytes.Clone(genesis.Head), Control: bytes.Clone(genesis.Control), Policy: bytes.Clone(genesis.Policy),
		Certificates: [][]byte{bytes.Clone(genesis.Certificate)}, TrustAnchor: genesis.Anchor,
	}
	intent := fixture.intent
	intent.Vault = genesis.Vault
	intent.Recipients = [][]byte{bytes.Clone(genesis.Certificate)}
	intent.Wraps = []RecipientWrapInput{
		{KeyID: bytes.Clone(fixture.newDevice.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(31, 32)), WrapNonce: [24]byte(fixtureBytes(63, 24))},
		{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(87, 32)), WrapNonce: [24]byte(fixtureBytes(111, 24))},
	}
	transition, err := PrepareTransition(predecessor, intent)
	require.NoError(t, err)
	fixture.bootstrap = genesis.BootstrapResult
	fixture.predecessor = predecessor
	fixture.transition = transition
	successorPolicy, err := DecodePolicy(fixture.transition.Policy)
	require.NoError(t, err)
	successorControl, err := DecodeControl(fixture.transition.Control)
	require.NoError(t, err)
	successorPolicyDigest, err := ComputePolicyDigest(fixture.transition.Policy)
	require.NoError(t, err)
	controlCID, err := rawCID(fixture.transition.Control)
	require.NoError(t, err)
	checkpointBytes, err := SignRecoveryKitCheckpoint(fixture.kit, fixture.bootstrap.Vault, fixture.bootstrap.Anchor,
		successorControl.EpochSeq, successorPolicyDigest, controlCID, fixture.transition.SnapshotCID)
	require.NoError(t, err)
	bundle, err := NewOnboardingBundle(fixture.bootstrap.Vault, fixture.bootstrap.Anchor, checkpointBytes, fixture.transition.Policy,
		fixture.transition.Control, fixture.bootstrap.Policy, fixture.bootstrap.Control, genesis.Head, genesis.Snapshot, fixture.predecessor.Certificates)
	require.NoError(t, err)
	require.NotEqual(t, bundle.Anchor, bundle.RecoveryAnchor, "root trust anchor and kit recovery fingerprint are independent")
	require.Equal(t, successorPolicy.RecoveryAnchor, bundle.RecoveryAnchor)
	return fixture, bundle
}

func TestOnboardingBundleRoundTripsDeterministically(t *testing.T) {
	_, bundle := onboardingBundleFixture(t)
	encoded, err := EncodeOnboardingBundle(bundle)
	require.NoError(t, err)
	encodedAgain, err := EncodeOnboardingBundle(bundle)
	require.NoError(t, err)
	assert.Equal(t, encoded, encodedAgain)
	decoded, err := DecodeOnboardingBundle(encoded)
	require.NoError(t, err)
	assert.Equal(t, bundle, decoded)
	assert.LessOrEqual(t, len(encoded), MaxOnboardingBundleBytes)
}

func TestOnboardingBundleRejectsVersionUnknownDuplicateTrailingAndAbsentFields(t *testing.T) {
	_, bundle := onboardingBundleFixture(t)
	encoded, err := EncodeOnboardingBundle(bundle)
	require.NoError(t, err)

	unsupported := bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":2`), 1)
	_, err = DecodeOnboardingBundle(unsupported)
	assert.ErrorIs(t, err, ErrUnsupportedVersion)

	unknown := append(bytes.TrimSuffix(encoded, []byte("}")), []byte(`,"unexpected":true}`)...)
	_, err = DecodeOnboardingBundle(unknown)
	assert.Error(t, err)

	duplicate := append(bytes.TrimSuffix(encoded, []byte("}")), []byte(`,"version":1}`)...)
	_, err = DecodeOnboardingBundle(duplicate)
	assert.Error(t, err)

	_, err = DecodeOnboardingBundle(append(bytes.Clone(encoded), []byte(` {}`)...))
	assert.Error(t, err)

	absent := bytes.Replace(encoded, []byte(`,"successor_policy":"`), []byte(`,"removed_successor_policy":"`), 1)
	_, err = DecodeOnboardingBundle(absent)
	assert.Error(t, err, "the bundle has no optional object fields")

	_, err = DecodeOnboardingBundle(make([]byte, MaxOnboardingBundleBytes+1))
	assert.ErrorIs(t, err, ErrLimit)

	oversized := bundle
	oversized.Checkpoint = make([]byte, MaxPolicyObjectBytes+1)
	_, err = EncodeOnboardingBundle(oversized)
	assert.ErrorIs(t, err, ErrLimit)
}

func TestOnboardingBundleRejectsVaultAnchorEpochDigestAndSnapshotMismatches(t *testing.T) {
	_, baseline := onboardingBundleFixture(t)
	cases := []struct {
		name   string
		change func(*OnboardingBundle) error
	}{
		{"vault", func(bundle *OnboardingBundle) error { bundle.Vault[0] ^= 1; return nil }},
		{"root anchor", func(bundle *OnboardingBundle) error { bundle.Anchor[0] ^= 1; return nil }},
		{"recovery anchor", func(bundle *OnboardingBundle) error { bundle.RecoveryAnchor[0] ^= 1; return nil }},
		{"checkpoint vault", func(bundle *OnboardingBundle) error {
			checkpoint, err := DecodeCheckpoint(bundle.Checkpoint)
			if err != nil {
				return err
			}
			checkpoint.Vault[0] ^= 1
			bundle.Checkpoint, err = EncodeCheckpoint(checkpoint)
			return err
		}},
		{"successor policy vault", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.SuccessorPolicy)
			if err != nil {
				return err
			}
			policy.Vault[0] ^= 1
			bundle.SuccessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"successor control vault", func(bundle *OnboardingBundle) error {
			control, err := DecodeControl(bundle.SuccessorControl)
			if err != nil {
				return err
			}
			control.Vault[0] ^= 1
			bundle.SuccessorControl, err = EncodeControl(control)
			return err
		}},
		{"predecessor policy vault", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.PredecessorPolicy)
			if err != nil {
				return err
			}
			policy.Vault[0] ^= 1
			bundle.PredecessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"predecessor control vault", func(bundle *OnboardingBundle) error {
			control, err := DecodeControl(bundle.PredecessorControl)
			if err != nil {
				return err
			}
			control.Vault[0] ^= 1
			bundle.PredecessorControl, err = EncodeControl(control)
			return err
		}},
		{"predecessor head vault", func(bundle *OnboardingBundle) error {
			head, err := DecodeHead(bundle.PredecessorHead)
			if err != nil {
				return err
			}
			head.Vault[0] ^= 1
			bundle.PredecessorHead, err = EncodeHead(head)
			return err
		}},
		{"predecessor snapshot vault", func(bundle *OnboardingBundle) error {
			envelope, err := DecodeEnvelope(bundle.PredecessorSnapshot)
			if err != nil {
				return err
			}
			envelope.Vault[0] ^= 1
			bundle.PredecessorSnapshot, err = EncodeEnvelope(envelope)
			return err
		}},
		{"missing predecessor policy", func(bundle *OnboardingBundle) error { bundle.PredecessorPolicy = nil; return nil }},
		{"missing predecessor control", func(bundle *OnboardingBundle) error { bundle.PredecessorControl = nil; return nil }},
		{"missing predecessor head", func(bundle *OnboardingBundle) error { bundle.PredecessorHead = nil; return nil }},
		{"missing predecessor snapshot", func(bundle *OnboardingBundle) error { bundle.PredecessorSnapshot = nil; return nil }},
		{"missing predecessor certificates", func(bundle *OnboardingBundle) error { bundle.PredecessorCertificates = nil; return nil }},
		{"mismatched predecessor head signature", func(bundle *OnboardingBundle) error {
			bundle.PredecessorHead = bytes.Clone(bundle.PredecessorHead)
			bundle.PredecessorHead[len(bundle.PredecessorHead)-1] ^= 1
			return nil
		}},
		{"mismatched predecessor snapshot signature", func(bundle *OnboardingBundle) error {
			bundle.PredecessorSnapshot = bytes.Clone(bundle.PredecessorSnapshot)
			bundle.PredecessorSnapshot[len(bundle.PredecessorSnapshot)-1] ^= 1
			return nil
		}},
		{"mismatched predecessor certificate signature", func(bundle *OnboardingBundle) error {
			bundle.PredecessorCertificates = cloneByteSlices(bundle.PredecessorCertificates)
			bundle.PredecessorCertificates[0][len(bundle.PredecessorCertificates[0])-1] ^= 1
			return nil
		}},

		{"mismatched predecessor head digest", func(bundle *OnboardingBundle) error {
			head, err := DecodeHead(bundle.PredecessorHead)
			if err != nil {
				return err
			}
			head.PolicyDigest[0] ^= 1
			bundle.PredecessorHead, err = EncodeHead(head)
			return err
		}},
		{"mismatched predecessor snapshot CID", func(bundle *OnboardingBundle) error {
			bundle.PredecessorSnapshot = bytes.Clone(bundle.PredecessorSnapshot)
			bundle.PredecessorSnapshot[len(bundle.PredecessorSnapshot)-1] ^= 1
			return nil
		}},
		{"mismatched predecessor certificate key", func(bundle *OnboardingBundle) error {
			certificate, err := DecodeCertificate(bundle.PredecessorCertificates[0])
			if err != nil {
				return err
			}
			certificate.KeyID[0] ^= 1
			bundle.PredecessorCertificates[0], err = EncodeCertificate(certificate)
			return err
		}},

		{"checkpoint root anchor", func(bundle *OnboardingBundle) error {
			checkpoint, err := DecodeCheckpoint(bundle.Checkpoint)
			if err != nil {
				return err
			}
			checkpoint.Anchor[0] ^= 1
			bundle.Checkpoint, err = EncodeCheckpoint(checkpoint)
			return err
		}},
		{"successor recovery anchor", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.SuccessorPolicy)
			if err != nil {
				return err
			}
			policy.RecoveryAnchor[0] ^= 1
			bundle.SuccessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"predecessor recovery anchor", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.PredecessorPolicy)
			if err != nil {
				return err
			}
			policy.RecoveryAnchor[0] ^= 1
			bundle.PredecessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"successor epoch", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.SuccessorPolicy)
			if err != nil {
				return err
			}
			policy.EpochSeq++
			bundle.SuccessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"successor control epoch", func(bundle *OnboardingBundle) error {
			control, err := DecodeControl(bundle.SuccessorControl)
			if err != nil {
				return err
			}
			control.EpochSeq++
			bundle.SuccessorControl, err = EncodeControl(control)
			return err
		}},
		{"checkpoint epoch", func(bundle *OnboardingBundle) error {
			checkpoint, err := DecodeCheckpoint(bundle.Checkpoint)
			if err != nil {
				return err
			}
			checkpoint.EpochSeq++
			bundle.Checkpoint, err = EncodeCheckpoint(checkpoint)
			return err
		}},
		{"predecessor policy epoch", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.PredecessorPolicy)
			if err != nil {
				return err
			}
			policy.EpochSeq++
			bundle.PredecessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"predecessor control epoch", func(bundle *OnboardingBundle) error {
			control, err := DecodeControl(bundle.PredecessorControl)
			if err != nil {
				return err
			}
			control.EpochSeq++
			bundle.PredecessorControl, err = EncodeControl(control)
			return err
		}},
		{"successor policy predecessor digest", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.SuccessorPolicy)
			if err != nil {
				return err
			}
			policy.PrevPolicyDigest[0] ^= 1
			bundle.SuccessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"successor control policy digest", func(bundle *OnboardingBundle) error {
			control, err := DecodeControl(bundle.SuccessorControl)
			if err != nil {
				return err
			}
			control.PolicyDigest[0] ^= 1
			bundle.SuccessorControl, err = EncodeControl(control)
			return err
		}},
		{"predecessor policy digest", func(bundle *OnboardingBundle) error {
			policy, err := DecodePolicy(bundle.PredecessorPolicy)
			if err != nil {
				return err
			}
			policy.PolicyRetentionFloor++
			bundle.PredecessorPolicy, err = EncodePolicy(policy)
			return err
		}},
		{"predecessor control policy digest", func(bundle *OnboardingBundle) error {
			control, err := DecodeControl(bundle.PredecessorControl)
			if err != nil {
				return err
			}
			control.PolicyDigest[0] ^= 1
			bundle.PredecessorControl, err = EncodeControl(control)
			return err
		}},
		{"checkpoint policy digest", func(bundle *OnboardingBundle) error {
			checkpoint, err := DecodeCheckpoint(bundle.Checkpoint)
			if err != nil {
				return err
			}
			checkpoint.PolicyDigest[0] ^= 1
			bundle.Checkpoint, err = EncodeCheckpoint(checkpoint)
			return err
		}},
		{"checkpoint snapshot", func(bundle *OnboardingBundle) error {
			checkpoint, err := DecodeCheckpoint(bundle.Checkpoint)
			if err != nil {
				return err
			}
			checkpoint.SnapshotCID = []byte("different-snapshot")
			bundle.Checkpoint, err = EncodeCheckpoint(checkpoint)
			return err
		}},
		{"snapshot binding", func(bundle *OnboardingBundle) error {
			control, err := DecodeControl(bundle.SuccessorControl)
			if err != nil {
				return err
			}
			control.HeadSnapshotCID = []byte("different-snapshot")
			bundle.SuccessorControl, err = EncodeControl(control)
			return err
		}},
		{"successor control bytes", func(bundle *OnboardingBundle) error {
			bundle.SuccessorControl = bytes.Clone(bundle.SuccessorControl)
			bundle.SuccessorControl[len(bundle.SuccessorControl)-1] ^= 1
			return nil
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			bundle := baseline
			err := test.change(&bundle)
			require.NoError(t, err)
			_, err = EncodeOnboardingBundle(bundle)
			assert.Error(t, err)
		})
	}
}

func TestOnboardingBundlePublicEvidenceCanAuthenticateSuccessorAncestry(t *testing.T) {
	fixture, bundle := onboardingBundleFixture(t)
	encoded, err := EncodeOnboardingBundle(bundle)
	require.NoError(t, err)
	decoded, err := DecodeOnboardingBundle(encoded)
	require.NoError(t, err)

	trusted := NewTrustedContext(decoded.Vault, decoded.Anchor)
	require.NoError(t, trusted.SetHeldCheckpoint(ControlEvidence{
		Control: decoded.PredecessorControl, Policy: decoded.PredecessorPolicy, Certificates: fixture.predecessor.Certificates,
	}))
	result, err := VerifyControlState(trusted, VerificationRequest{Supplied: ControlEvidence{
		Control: decoded.SuccessorControl, Policy: decoded.SuccessorPolicy, Certificates: fixture.transition.Recipients,
	}})
	require.NoError(t, err)
	assert.Equal(t, CheckpointDescendant, result.Outcome)
	assert.NotEmpty(t, decoded.Checkpoint, "the bundle contributes only public checkpoint evidence")
}

func TestOnboardingBundleDecodeRejectsNonCanonicalAndMalformedJSON(t *testing.T) {
	_, bundle := onboardingBundleFixture(t)
	encoded, err := EncodeOnboardingBundle(bundle)
	require.NoError(t, err)

	for _, test := range []struct {
		name string
		data []byte
	}{
		{"whitespace", append([]byte(" "), encoded...)},
		{"truncated", encoded[:len(encoded)-1]},
		{"not json", []byte("not json")},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeOnboardingBundle(test.data)
			assert.Error(t, err)
		})
	}
}

func TestOnboardingBundleJSONHasNoApprovalOrSecretFields(t *testing.T) {
	_, bundle := onboardingBundleFixture(t)
	encoded, err := EncodeOnboardingBundle(bundle)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	assert.Equal(t, []string{"anchor_fingerprint", "predecessor_certificates", "predecessor_control", "predecessor_head", "predecessor_policy", "predecessor_snapshot", "recovery_anchor", "successor_checkpoint", "successor_control", "successor_policy", "vault_id", "version"}, onboardingFieldNames(fields))
	for _, field := range []string{"kit", "private_key", "token", "approval", "plaintext"} {
		assert.NotContains(t, fields, field)
	}
}

func onboardingFieldNames(fields map[string]json.RawMessage) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestOnboardingBundleFieldObjectBoundIsReused(t *testing.T) {
	_, bundle := onboardingBundleFixture(t)
	bundle.PredecessorControl = bytes.Repeat([]byte{0}, MaxPolicyObjectBytes+1)
	_, err := EncodeOnboardingBundle(bundle)
	assert.ErrorIs(t, err, ErrLimit)
}
