package atproto

import (
	"testing"

	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateVaultRequiresMatchingPolicyPosition(t *testing.T) {
	fixture := newReadFixture(t)
	policyRecord := fixturePolicyRecord(t, fixture)
	controlRecord, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	headRecord, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultHeadNSID, RKey: "self"}])
	require.NoError(t, err)
	policy, _, _ := fixturePolicyParts(t, fixture)
	control := controlFromRecord(controlRecord.(ControlRecord))
	head := headFromRecord(headRecord.(HeadRecord))
	envelope, err := vault.DecodeEnvelope(fixture.transport.blob)
	require.NoError(t, err)

	checks := []struct {
		name   string
		mutate func(*vault.Policy, *vault.Control, *vault.Head, *vault.Envelope)
	}{
		{name: "policy epoch", mutate: func(policy *vault.Policy, _ *vault.Control, _ *vault.Head, _ *vault.Envelope) { policy.EpochSeq++ }},
		{name: "control epoch", mutate: func(_ *vault.Policy, control *vault.Control, _ *vault.Head, _ *vault.Envelope) { control.EpochSeq++ }},
		{name: "head epoch", mutate: func(_ *vault.Policy, _ *vault.Control, head *vault.Head, _ *vault.Envelope) { head.EpochSeq++ }},
		{name: "envelope epoch", mutate: func(_ *vault.Policy, _ *vault.Control, _ *vault.Head, envelope *vault.Envelope) { envelope.EpochSeq++ }},
		{name: "control policy digest", mutate: func(_ *vault.Policy, control *vault.Control, _ *vault.Head, _ *vault.Envelope) {
			control.PolicyDigest[0] ^= 0xff
		}},
		{name: "head policy digest", mutate: func(_ *vault.Policy, _ *vault.Control, head *vault.Head, _ *vault.Envelope) {
			head.PolicyDigest[0] ^= 0xff
		}},
		{name: "envelope policy digest", mutate: func(_ *vault.Policy, _ *vault.Control, _ *vault.Head, envelope *vault.Envelope) {
			envelope.PolicyDigest[0] ^= 0xff
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			changedPolicy := policy
			changedControl := control
			changedHead := head
			changedEnvelope := envelope
			check.mutate(&changedPolicy, &changedControl, &changedHead, &changedEnvelope)
			policyBytes, err := vault.EncodePolicy(changedPolicy)
			require.NoError(t, err)
			controlBytes, err := vault.EncodeControl(changedControl)
			require.NoError(t, err)
			headBytes, err := vault.EncodeHead(changedHead)
			require.NoError(t, err)
			envelopeBytes, err := vault.EncodeEnvelope(changedEnvelope)
			require.NoError(t, err)

			err = authenticateVault(
				fixture.request, policyRecord, policyBytes,
				controlRecord.(ControlRecord), controlBytes,
				headRecord.(HeadRecord), headBytes,
				changedEnvelope, envelopeBytes, fixtureCertificates(t, fixture),
			)
			require.ErrorContains(t, err, "epoch or policy digest disagrees")
		})
	}
}

func TestAuthorizePolicyPredecessorRequiresAdjacentEpoch(t *testing.T) {
	fixture := newReadFixture(t)
	current, _, _ := fixturePolicyParts(t, fixture)
	previousRecord, err := DecodeRecord(fixture.request.PreviousPolicy)
	require.NoError(t, err)
	previousBytes, err := vault.EncodePolicy(policyFromRecord(previousRecord.(PolicyRecord)))
	require.NoError(t, err)
	previousDigest, err := vault.ComputePolicyDigest(previousBytes)
	require.NoError(t, err)
	current.EpochSeq = 2
	current.PrevPolicyDigest = previousDigest
	currentBytes := signReadPolicy(t, current, fixtureSigningKey(11))
	current, err = vault.DecodePolicy(currentBytes)
	require.NoError(t, err)
	certificates := fixtureCertificates(t, fixture)
	currentSigner := certificates[certificateIdentity("root", []byte("root-sign"))]

	err = authorizePolicyPredecessor(fixture.request, current, currentBytes, currentSigner, certificates)
	require.ErrorContains(t, err, "predecessor policy identity or epoch is invalid")
}
