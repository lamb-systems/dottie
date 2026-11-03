package vault

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealPreparedRejectsMissingRecipientKeyID(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	prepared := fixture.prepared
	prepared.Recipients = append([]PreparedRecipient(nil), fixture.prepared.Recipients...)
	prepared.Recipients[0].KeyID = []byte("absent-recipient")
	prepared.Recipients[0].PublicKey = make([]byte, 32)

	_, err := SealPrepared(prepared)
	assert.ErrorIs(t, err, ErrRecipient)
}

func TestSealPreparedRejectsDuplicateRecipientKeyID(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	secondKey := fixedX25519Key(25)
	policy := fixture.policy
	policy.Recipients = append(policy.Recipients, PolicyRecipient{
		DeviceID: "device-second", KeyID: []byte("recipient-b"), PublicKey: [32]byte(secondKey.PublicKey().Bytes()),
	})
	policyBytes := signPolicyValue(t, policy, fixture.signingKey)
	policy, err := DecodePolicy(policyBytes)
	require.NoError(t, err)
	digest, err := ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	prepared := fixture.prepared
	prepared.Policy = policy
	prepared.PolicyDigest = digest
	prepared.Recipients = append([]PreparedRecipient(nil), fixture.prepared.Recipients...)
	prepared.Recipients = append(prepared.Recipients, fixture.prepared.Recipients[0])

	_, err = SealPrepared(prepared)
	assert.ErrorIs(t, err, ErrRecipient)
}

func TestSealAuthorizedRequestVaultIsCheckedByPreparedSeal(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	request := SealRequest{
		Purpose: PurposeSnapshot, Vault: fixture.policy.Vault, PublicationID: fixture.prepared.PublicationID,
		EpochSeq: fixture.policy.EpochSeq, PolicyDigest: fixture.prepared.PolicyDigest,
		Parent: bytes.Clone(fixture.prepared.Parent), DeviceID: fixture.certificate.DeviceID,
		KeyID: bytes.Clone(fixture.certificate.KeyID), Plaintext: bytes.Clone(fixture.prepared.Plaintext),
		SigningKey: fixture.publisherKey,
		Recipients: []RecipientPublicKey{{KeyID: []byte("recipient-a"), PublicKey: fixture.recipientKey.PublicKey().Bytes()}},
	}
	request.Vault[0] ^= 1

	_, err := SealAuthorized(request, fixture.certificate, fixture.policy)
	assert.ErrorIs(t, err, ErrAuthorization)
}
