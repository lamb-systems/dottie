package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTransitionEnrollmentCertificateEpochMatchesPolicy(t *testing.T) {
	fixture := newDevicesFixture(t)
	transition := fixture.transition
	certificate, err := DecodeCertificate(transition.Certificate)
	require.NoError(t, err)
	certificate.CertEpoch--
	transition.Certificate = signCertificateValue(t, certificate, fixture.root.Signing)
	for index, encoded := range transition.Recipients {
		recipient, decodeErr := DecodeCertificate(encoded)
		require.NoError(t, decodeErr)
		if recipient.DeviceID == certificate.DeviceID {
			transition.Recipients[index] = transition.Certificate
		}
	}
	transition.Digest = ComputeTransitionDigest(transition)

	err = ValidateTransition(transition, fixture.predecessor)
	require.ErrorIs(t, err, ErrCertificateAuthority)
}

func TestValidateTransitionEnrollmentCertificateRoleIsRestricted(t *testing.T) {
	fixture := newDevicesFixture(t)
	transition := remakeTransition(t, fixture, fixture.transition, func(policy *Policy, certificate *Certificate, _ *Envelope) {
		certificate.Role = RoleRoot
		for index := range policy.Roles {
			if policy.Roles[index].DeviceID == certificate.DeviceID {
				policy.Roles[index].Role = RoleRoot
			}
		}
	})

	err := ValidateTransition(transition, fixture.predecessor)
	require.ErrorIs(t, err, ErrCertificateAuthority)
}

func TestValidateTransitionEnrollmentCertificateRoleMatchesPolicy(t *testing.T) {
	fixture := newDevicesFixture(t)
	transition := remakeTransition(t, fixture, fixture.transition, func(_ *Policy, certificate *Certificate, _ *Envelope) {
		certificate.Role = RoleRestoreOnly
	})

	err := ValidateTransition(transition, fixture.predecessor)
	require.ErrorIs(t, err, ErrCertificateAuthority)
	assert.NotErrorIs(t, err, ErrTransitionDelta)
}

func TestValidatePublicationRecipientsRequiresCertificateRoleToMatchPolicy(t *testing.T) {
	fixture := newDevicesFixture(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	policy, err := DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	require.NoError(t, validatePublicationRecipients(predecessor, policy))

	for index := range policy.Roles {
		if policy.Roles[index].DeviceID == fixture.newDevice.DeviceID {
			policy.Roles[index].Role = RoleRestoreOnly
		}
	}
	predecessor.Policy = signPolicyValue(t, policy, fixture.root.Signing)
	predecessor.PolicyDigest = mustPolicyDigest(predecessor.Policy)
	control, err := DecodeControl(predecessor.Control)
	require.NoError(t, err)
	control.PolicyDigest = predecessor.PolicyDigest
	predecessor.Control = signControlValue(t, control, fixture.root.Signing)
	predecessor.ControlCID, err = rawCID(predecessor.Control)
	require.NoError(t, err)
	require.NoError(t, validatePredecessor(predecessor))
	policy, err = DecodePolicy(predecessor.Policy)
	require.NoError(t, err)

	err = validatePublicationRecipients(predecessor, policy)
	require.ErrorIs(t, err, ErrTransitionRecipients)
}
