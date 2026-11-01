package vault

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publisherAuthorizationFixture struct {
	rootCertificate []byte
	publisherCert   Certificate
	publisherBytes  []byte
	envelope        Envelope
	controlBytes    []byte
	request         OpenRequest
	plaintext       []byte
}

func newPublisherAuthorizationFixture(t *testing.T) publisherAuthorizationFixture {
	t.Helper()
	base := newEnvelopeFixture(t)
	controlBytes := signControlValue(t, Control{
		Vault: base.envelope.Vault, EpochSeq: base.envelope.EpochSeq, PolicyDigest: base.prepared.PolicyDigest,
		Revoked: []RevokedDevice{{DeviceID: base.certificate.DeviceID, CertEpoch: base.certificate.CertEpoch}},
		Signer:  Signer{DeviceID: "device-root", KeyID: []byte("signer-root")},
	}, base.signingKey)
	request := base.openRequest
	request.Control = controlBytes
	return publisherAuthorizationFixture{
		rootCertificate: base.rootCertificateBytes, publisherCert: base.certificate,
		publisherBytes: base.certificateBytes, envelope: base.envelope,
		controlBytes: controlBytes, request: request, plaintext: base.prepared.Plaintext,
	}
}

func TestOpenControlRejectsRevokedPublisherButSkipsCheckWithoutControl(t *testing.T) {
	fixture := newPublisherAuthorizationFixture(t)
	_, err := Open(fixture.envelope, fixture.request)
	assert.ErrorIs(t, err, ErrAuthorization)
	withoutControl := fixture.request
	withoutControl.Control = nil
	plaintext, err := Open(fixture.envelope, withoutControl)
	require.NoError(t, err)
	assert.Equal(t, fixture.plaintext, plaintext)
}

func TestOpenControlOlderRevocationDoesNotRevokeReenrolledCertificate(t *testing.T) {
	fixture := newPublisherAuthorizationFixture(t)
	reenrolled := fixture.publisherCert
	reenrolled.CertEpoch = 6
	rootKey := fixedSigningKey(11)
	reenrolledBytes := signCertificateValue(t, reenrolled, rootKey)
	request := fixture.request
	request.Certificates = [][]byte{fixture.rootCertificate, reenrolledBytes}
	plaintext, err := Open(fixture.envelope, request)
	require.NoError(t, err)
	assert.Equal(t, fixture.plaintext, plaintext)
}

func TestOpenControlRejectsEditedRevocationListSignature(t *testing.T) {
	fixture := newPublisherAuthorizationFixture(t)
	control, err := DecodeControl(fixture.controlBytes)
	require.NoError(t, err)
	control.Revoked = nil
	edited, err := EncodeControl(control)
	require.NoError(t, err)
	request := fixture.request
	request.Control = edited
	_, err = Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrSignature)
}

func TestOpenRejectsMissingIssuerAndUntrustedRoot(t *testing.T) {
	fixture := newEnvelopeFixture(t)
	missingIssuer := fixture.certificate
	missingIssuer.Issuer = "missing-root"
	missingIssuer.Signer = Signer{DeviceID: "missing-root", KeyID: []byte("missing-key")}
	missingIssuerBytes := signCertificateValue(t, missingIssuer, fixture.signingKey)
	request := fixture.openRequest
	request.Certificates = [][]byte{fixture.rootCertificateBytes, missingIssuerBytes}
	_, err := Open(fixture.envelope, request)
	assert.ErrorIs(t, err, ErrAuthorization)
	wrongAnchor := fixture.openRequest
	wrongAnchor.TrustAnchor[0] ^= 1
	_, err = Open(fixture.envelope, wrongAnchor)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func TestChainRejectsNonRootIssuer(t *testing.T) {
	base := newEnvelopeFixture(t)
	forged := signCertificateValue(t, Certificate{
		Vault: base.policy.Vault, DeviceID: "device-forged", KeyID: []byte("signer-forged"),
		SigningPublicKey:    [ed25519.PublicKeySize]byte(base.publisherKey.Public().(ed25519.PublicKey)),
		EncryptionPublicKey: [32]byte(base.recipientKey.PublicKey().Bytes()),
		Role:                RolePublisher, CertEpoch: 5,
		Issuer: "device-publisher",
		Signer: Signer{DeviceID: "device-publisher", KeyID: []byte("signer-publisher")},
	}, base.publisherKey)
	decoded, err := DecodeCertificate(forged)
	require.NoError(t, err)
	request := base.openRequest
	request.Certificates = [][]byte{base.rootCertificateBytes, base.certificateBytes, forged}
	err = verifyCertificateChain(decoded, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization, "a publisher certificate must not issue trusted certificates")
}

func TestChainRejectsFutureCertEpoch(t *testing.T) {
	base := newEnvelopeFixture(t)
	future := base.certificate
	future.CertEpoch = base.openRequest.EpochSeq + 1
	signed := signCertificateValue(t, future, base.signingKey)
	decoded, err := DecodeCertificate(signed)
	require.NoError(t, err)
	request := base.openRequest
	request.Certificates = [][]byte{base.rootCertificateBytes, signed}
	err = verifyCertificateChain(decoded, request, 1, make(map[string]bool))
	assert.ErrorIs(t, err, ErrAuthorization, "a signed certificate issued after the accepted epoch must not be trusted")

	accepted := base.openRequest
	accepted.EpochSeq = decoded.CertEpoch
	accepted.Certificates = [][]byte{base.rootCertificateBytes, signed}
	require.NoError(t, verifyCertificateChain(decoded, accepted, 1, make(map[string]bool)),
		"the same certificate must verify once the accepted epoch reaches its cert_epoch")
}

func TestChainAcceptsEnrolledPublisher(t *testing.T) {
	base := newEnvelopeFixture(t)
	decoded, err := DecodeCertificate(base.certificateBytes)
	require.NoError(t, err)
	require.NoError(t, verifyCertificateChain(decoded, base.openRequest, 1, make(map[string]bool)))
}
