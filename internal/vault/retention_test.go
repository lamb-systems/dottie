package vault

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type retentionDeclarationFixture struct {
	base          envelopeFixture
	state         ControlEvidence
	point         RetentionRecoveryPoint
	pointEvidence RetentionRecoveryPointEvidence
}

func newRetentionDeclarationFixture(t *testing.T) retentionDeclarationFixture {
	t.Helper()
	base := newEnvelopeFixture(t)
	snapshot, err := EncodeEnvelope(base.envelope)
	require.NoError(t, err)
	snapshotCID, err := rawCID(snapshot)
	require.NoError(t, err)
	head := signHeadValue(t, Head{
		Vault: base.policy.Vault, EpochSeq: base.policy.EpochSeq, PolicyDigest: base.prepared.PolicyDigest,
		SnapshotCID: snapshotCID, BlobCID: snapshotCID, PrevHeadCID: bytes.Clone(base.envelope.Parent),
		Signer: Signer{DeviceID: base.certificate.DeviceID, KeyID: bytes.Clone(base.certificate.KeyID)},
	}, base.publisherKey)
	control := signControlValue(t, Control{
		Vault: base.policy.Vault, EpochSeq: base.policy.EpochSeq, PolicyDigest: base.prepared.PolicyDigest,
		HeadSnapshotCID: snapshotCID,
		Signer:          Signer{DeviceID: base.rootCertificate.DeviceID, KeyID: bytes.Clone(base.rootCertificate.KeyID)},
	}, base.signingKey)
	controlCID, err := rawCID(control)
	require.NoError(t, err)
	state := ControlEvidence{
		Control: control, Policy: bytes.Clone(base.policyBytes),
		Certificates: [][]byte{bytes.Clone(base.rootCertificateBytes), bytes.Clone(base.certificateBytes)},
	}
	point := RetentionRecoveryPoint{
		Epoch: base.policy.EpochSeq, SnapshotCID: snapshotCID,
		PolicyDigest: base.prepared.PolicyDigest, ControlCID: controlCID,
	}
	return retentionDeclarationFixture{
		base: base, state: state, point: point,
		pointEvidence: RetentionRecoveryPointEvidence{
			Point: point, Position: state, EpochStartHead: head, EpochStartSnapshot: snapshot,
		},
	}
}

func retentionOrdinaryPointEvidence(t *testing.T, fixture retentionDeclarationFixture) (RetentionRecoveryPoint, RetentionRecoveryPointEvidence) {
	t.Helper()
	prepared := fixture.base.prepared
	prepared.Parent = bytes.Clone(fixture.point.SnapshotCID)
	prepared.PublicationID = [16]byte(fixtureBytes(201, 16))
	prepared.Plaintext = []byte("synthetic ordinary publication body")
	prepared.ContentKey = fixtureBytes(211, 32)
	prepared.Nonce = [24]byte(fixtureBytes(221, 24))
	prepared.Recipients[0].EphemeralPrivate = fixedX25519Key(42).Bytes()
	prepared.Recipients[0].WrapNonce = [24]byte(fixtureBytes(231, 24))
	ordinaryEnvelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	ordinaryBody, err := EncodeEnvelope(ordinaryEnvelope)
	require.NoError(t, err)
	ordinaryCID, err := rawCID(ordinaryBody)
	require.NoError(t, err)
	ordinaryHead := signHeadValue(t, Head{
		Vault: fixture.base.policy.Vault, EpochSeq: fixture.base.policy.EpochSeq,
		PolicyDigest: fixture.base.prepared.PolicyDigest, SnapshotCID: ordinaryCID,
		BlobCID: ordinaryCID, PublicationCount: 1, PrevHeadCID: bytes.Clone(fixture.point.SnapshotCID),
		Signer: Signer{DeviceID: fixture.base.certificate.DeviceID, KeyID: bytes.Clone(fixture.base.certificate.KeyID)},
	}, fixture.base.publisherKey)
	point := RetentionRecoveryPoint{
		Epoch: fixture.base.policy.EpochSeq, SnapshotCID: ordinaryCID,
		PolicyDigest: fixture.base.prepared.PolicyDigest, ControlCID: bytes.Clone(fixture.point.ControlCID),
	}
	return point, RetentionRecoveryPointEvidence{
		Point: point, Position: fixture.state,
		EpochStartHead: fixture.pointEvidence.EpochStartHead, EpochStartSnapshot: fixture.pointEvidence.EpochStartSnapshot,
		Head: ordinaryHead, Ciphertext: ordinaryBody,
	}
}

func TestVerifyRetentionSnapshotPositionRequiresTrustAnchor(t *testing.T) {
	fixture := newRetentionDeclarationFixture(t)
	position, _, err := verifyControlPositionEvidence(fixture.base.policy.Vault, fixture.base.trustAnchor, fixture.state)
	require.NoError(t, err)

	for _, test := range []struct {
		name        string
		trustAnchor [32]byte
		wantErr     bool
	}{
		{name: "correct", trustAnchor: fixture.base.trustAnchor},
		{name: "wrong", trustAnchor: [32]byte(fixtureBytes(31, 32)), wantErr: true},
		{name: "zero", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := verifyRetentionSnapshotPosition(
				position, test.trustAnchor, fixture.state.Certificates,
				fixture.pointEvidence.EpochStartHead, fixture.pointEvidence.EpochStartSnapshot, true,
			)
			if test.wantErr {
				assert.ErrorIs(t, err, ErrAuthorization)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRetentionSnapshotAuthenticationEnforcesPointAuthorization(t *testing.T) {
	fixture := newRetentionDeclarationFixture(t)
	position, _, err := verifyControlPositionEvidence(fixture.base.policy.Vault, fixture.base.trustAnchor, fixture.state)
	require.NoError(t, err)
	_, ordinaryEvidence := retentionOrdinaryPointEvidence(t, fixture)

	_, _, _, err = verifyRetentionSnapshotPosition(position, fixture.base.trustAnchor, fixture.state.Certificates,
		fixture.pointEvidence.EpochStartHead, fixture.pointEvidence.EpochStartSnapshot, true)
	require.NoError(t, err)
	_, _, _, err = verifyRetentionSnapshotPosition(position, fixture.base.trustAnchor, fixture.state.Certificates,
		ordinaryEvidence.Head, ordinaryEvidence.Ciphertext, false)
	require.NoError(t, err)

	t.Run("revoked by point control", func(t *testing.T) {
		control, err := DecodeControl(fixture.state.Control)
		require.NoError(t, err)
		control.Revoked = append(control.Revoked, RevokedDevice{DeviceID: fixture.base.certificate.DeviceID, CertEpoch: fixture.base.certificate.CertEpoch})
		hostileState := fixture.state
		hostileState.Control = signControlValue(t, control, fixture.base.signingKey)
		hostilePosition, _, err := verifyControlPositionEvidence(fixture.base.policy.Vault, fixture.base.trustAnchor, hostileState)
		require.NoError(t, err)
		_, _, _, err = verifyRetentionSnapshotPosition(hostilePosition, fixture.base.trustAnchor, hostileState.Certificates,
			fixture.pointEvidence.EpochStartHead, fixture.pointEvidence.EpochStartSnapshot, true)
		assert.ErrorIs(t, err, ErrAuthorization)
		_, _, _, err = verifyRetentionSnapshotPosition(hostilePosition, fixture.base.trustAnchor, hostileState.Certificates,
			ordinaryEvidence.Head, ordinaryEvidence.Ciphertext, false)
		assert.ErrorIs(t, err, ErrAuthorization)
	})

	t.Run("signer absent from point policy", func(t *testing.T) {
		policy := fixture.base.policy
		policy.Roles = []RoleBinding{{DeviceID: fixture.base.rootCertificate.DeviceID, Role: RoleRoot}}
		policyBytes := signPolicyValue(t, policy, fixture.base.signingKey)
		policyDigest, err := ComputePolicyDigest(policyBytes)
		require.NoError(t, err)
		startEnvelope, err := DecodeEnvelope(fixture.pointEvidence.EpochStartSnapshot)
		require.NoError(t, err)
		startEnvelope.PolicyDigest = policyDigest
		startEnvelope = signTestEnvelope(t, startEnvelope, fixture.base.publisherKey)
		startBody, err := EncodeEnvelope(startEnvelope)
		require.NoError(t, err)
		startCID, err := rawCID(startBody)
		require.NoError(t, err)
		startHead, err := DecodeHead(fixture.pointEvidence.EpochStartHead)
		require.NoError(t, err)
		startHead.PolicyDigest = policyDigest
		startHead.SnapshotCID = startCID
		startHead.BlobCID = startCID
		startHeadBytes := signHeadValue(t, startHead, fixture.base.publisherKey)
		control, err := DecodeControl(fixture.state.Control)
		require.NoError(t, err)
		control.PolicyDigest = policyDigest
		control.HeadSnapshotCID = startCID
		hostileState := fixture.state
		hostileState.Policy = policyBytes
		hostileState.Control = signControlValue(t, control, fixture.base.signingKey)
		hostilePosition, _, err := verifyControlPositionEvidence(fixture.base.policy.Vault, fixture.base.trustAnchor, hostileState)
		require.NoError(t, err)
		_, _, _, err = verifyRetentionSnapshotPosition(hostilePosition, fixture.base.trustAnchor, hostileState.Certificates,
			startHeadBytes, startBody, true)
		assert.ErrorIs(t, err, ErrAuthorization)
		envelope, err := DecodeEnvelope(ordinaryEvidence.Ciphertext)
		require.NoError(t, err)
		envelope.PolicyDigest = policyDigest
		envelope = signTestEnvelope(t, envelope, fixture.base.publisherKey)
		body, err := EncodeEnvelope(envelope)
		require.NoError(t, err)
		bodyCID, err := rawCID(body)
		require.NoError(t, err)
		head, err := DecodeHead(ordinaryEvidence.Head)
		require.NoError(t, err)
		head.PolicyDigest = policyDigest
		head.SnapshotCID = bodyCID
		head.BlobCID = bodyCID
		headBytes := signHeadValue(t, head, fixture.base.publisherKey)
		_, _, _, err = verifyRetentionSnapshotPosition(hostilePosition, fixture.base.trustAnchor, hostileState.Certificates,
			headBytes, body, false)
		assert.ErrorIs(t, err, ErrAuthorization)
	})

	t.Run("head and envelope signer mismatch", func(t *testing.T) {
		envelope, err := DecodeEnvelope(ordinaryEvidence.Ciphertext)
		require.NoError(t, err)
		envelope.DeviceID = fixture.base.rootCertificate.DeviceID
		envelope.KeyID = bytes.Clone(fixture.base.rootCertificate.KeyID)
		envelope = signTestEnvelope(t, envelope, fixture.base.signingKey)
		body, err := EncodeEnvelope(envelope)
		require.NoError(t, err)
		bodyCID, err := rawCID(body)
		require.NoError(t, err)
		head, err := DecodeHead(ordinaryEvidence.Head)
		require.NoError(t, err)
		head.SnapshotCID = bodyCID
		head.BlobCID = bodyCID
		headBytes := signHeadValue(t, head, fixture.base.publisherKey)
		_, _, _, err = verifyRetentionSnapshotPosition(position, fixture.base.trustAnchor, fixture.state.Certificates,
			headBytes, body, false)
		assert.ErrorIs(t, err, ErrAuthorization)
	})

	t.Run("substituted recipient set", func(t *testing.T) {
		envelope, err := DecodeEnvelope(ordinaryEvidence.Ciphertext)
		require.NoError(t, err)
		envelope.Recipients[0].KeyID = []byte("substituted-recipient")
		envelope = signTestEnvelope(t, envelope, fixture.base.publisherKey)
		body, err := EncodeEnvelope(envelope)
		require.NoError(t, err)
		bodyCID, err := rawCID(body)
		require.NoError(t, err)
		head, err := DecodeHead(ordinaryEvidence.Head)
		require.NoError(t, err)
		head.SnapshotCID = bodyCID
		head.BlobCID = bodyCID
		headBytes := signHeadValue(t, head, fixture.base.publisherKey)
		_, _, _, err = verifyRetentionSnapshotPosition(position, fixture.base.trustAnchor, fixture.state.Certificates,
			headBytes, body, false)
		assert.ErrorIs(t, err, ErrRecipient)
	})

	t.Run("publication count above policy maximum", func(t *testing.T) {
		head, err := DecodeHead(ordinaryEvidence.Head)
		require.NoError(t, err)
		head.PublicationCount = uint64(position.policy.MaxPublications) + 1
		headBytes := signHeadValue(t, head, fixture.base.publisherKey)
		_, _, _, err = verifyRetentionSnapshotPosition(position, fixture.base.trustAnchor, fixture.state.Certificates,
			headBytes, ordinaryEvidence.Ciphertext, false)
		assert.ErrorIs(t, err, ErrAuthorization)
	})

}

func TestEvaluateRetentionDeclarationReportsPolicyFloor(t *testing.T) {
	for _, test := range []struct {
		name        string
		floor       uint64
		status      AttestationStatus
		compromised bool
	}{
		{name: "above", floor: 3, status: AttestationStatusMeetsPolicy},
		{name: "at", floor: 2, status: AttestationStatusMeetsPolicy},
		{name: "below", floor: 1, status: AttestationStatusBelowPolicyFloor, compromised: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetentionDeclarationFixture(t)
			result, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
				VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
				DeviceID: "device-restore", RetentionFloor: test.floor,
				RecoveryPoints: []RetentionRecoveryPoint{fixture.point},
				PointEvidence:  []RetentionRecoveryPointEvidence{fixture.pointEvidence},
			})
			require.NoError(t, err)
			assert.Equal(t, test.status, result.Status)
			assert.Equal(t, test.compromised, result.CompromisedForConfidentiality)
			assert.Equal(t, test.floor, result.Declaration.RetentionFloor)
			assert.Equal(t, "device-restore", result.Declaration.DeviceID)
			assert.Equal(t, fixture.base.policy.Vault, result.Declaration.Vault)
			assert.Equal(t, fixture.point, result.Declaration.RecoveryPoints[0])
		})
	}
}

func TestEvaluateRetentionDeclarationRequiresAuthenticatedPolicyControl(t *testing.T) {
	fixture := newRetentionDeclarationFixture(t)
	request := RetentionDeclarationRequest{
		VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
		DeviceID: "device-restore", RetentionFloor: 2,
		RecoveryPoints: []RetentionRecoveryPoint{fixture.point},
		PointEvidence:  []RetentionRecoveryPointEvidence{fixture.pointEvidence},
	}
	request.State.Control = bytes.Clone(request.State.Control)
	request.State.Control[len(request.State.Control)-1] ^= 0x80
	_, err := EvaluateRetentionDeclaration(request)
	assert.ErrorIs(t, err, ErrInvalidVerification)
}

func TestEvaluateRetentionDeclarationRequiresPerPointAuthenticatedEvidence(t *testing.T) {
	fixture := newRetentionDeclarationFixture(t)
	_, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
		VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
		DeviceID: "device-restore", RetentionFloor: 2,
		RecoveryPoints: []RetentionRecoveryPoint{fixture.point},
	})
	assert.ErrorContains(t, err, "invalid retention declaration")
}

func TestEvaluateRetentionDeclarationRejectsOrdinaryPointParentAndCIDMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *RetentionRecoveryPoint, *RetentionRecoveryPointEvidence, retentionDeclarationFixture)
	}{
		{
			name: "parent",
			mutate: func(t *testing.T, point *RetentionRecoveryPoint, evidence *RetentionRecoveryPointEvidence, fixture retentionDeclarationFixture) {
				head, err := DecodeHead(evidence.Head)
				require.NoError(t, err)
				head.PrevHeadCID = []byte("different-parent")
				evidence.Head = signHeadValue(t, head, fixture.base.publisherKey)
			},
		},
		{
			name: "snapshot CID",
			mutate: func(_ *testing.T, point *RetentionRecoveryPoint, evidence *RetentionRecoveryPointEvidence, _ retentionDeclarationFixture) {
				point.SnapshotCID = []byte("different-snapshot-cid")
				evidence.Point = *point
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetentionDeclarationFixture(t)
			point, evidence := retentionOrdinaryPointEvidence(t, fixture)
			_, err := EvaluateRetentionDeclaration(RetentionDeclarationRequest{
				VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
				DeviceID: "device-restore", RetentionFloor: 2,
				RecoveryPoints: []RetentionRecoveryPoint{fixture.point, point},
				PointEvidence:  []RetentionRecoveryPointEvidence{fixture.pointEvidence, evidence},
			})
			require.NoError(t, err)
			test.mutate(t, &point, &evidence, fixture)
			_, err = EvaluateRetentionDeclaration(RetentionDeclarationRequest{
				VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
				DeviceID: "device-restore", RetentionFloor: 2,
				RecoveryPoints: []RetentionRecoveryPoint{fixture.point, point},
				PointEvidence:  []RetentionRecoveryPointEvidence{fixture.pointEvidence, evidence},
			})
			assert.ErrorContains(t, err, "ordinary-publication recovery point head and envelope do not match")
		})
	}
}

func TestEvaluateRetentionDeclarationRejectsUnverifiablePointControl(t *testing.T) {
	fixture := newRetentionDeclarationFixture(t)
	baseSnapshotCID := bytes.Clone(fixture.point.SnapshotCID)
	alternateControl := signControlValue(t, Control{
		Vault: fixture.base.policy.Vault, EpochSeq: fixture.base.policy.EpochSeq,
		PolicyDigest: fixture.base.prepared.PolicyDigest, HeadSnapshotCID: baseSnapshotCID,
		PrevControlCID: []byte("missing-control"),
		Signer:         Signer{DeviceID: fixture.base.rootCertificate.DeviceID, KeyID: bytes.Clone(fixture.base.rootCertificate.KeyID)},
	}, fixture.base.signingKey)
	alternateControlCID, err := rawCID(alternateControl)
	require.NoError(t, err)
	alternatePosition := fixture.state
	alternatePosition.Control = alternateControl

	prepared := fixture.base.prepared
	prepared.Parent = baseSnapshotCID
	prepared.PublicationID = [16]byte(fixtureBytes(201, 16))
	prepared.Plaintext = []byte("synthetic ordinary publication body")
	prepared.ContentKey = fixtureBytes(211, 32)
	prepared.Nonce = [24]byte(fixtureBytes(221, 24))
	prepared.Recipients[0].EphemeralPrivate = fixedX25519Key(42).Bytes()
	prepared.Recipients[0].WrapNonce = [24]byte(fixtureBytes(231, 24))
	ordinaryEnvelope, err := SealPrepared(prepared)
	require.NoError(t, err)
	ordinaryBody, err := EncodeEnvelope(ordinaryEnvelope)
	require.NoError(t, err)
	ordinaryCID, err := rawCID(ordinaryBody)
	require.NoError(t, err)
	ordinaryHead := signHeadValue(t, Head{
		Vault: fixture.base.policy.Vault, EpochSeq: fixture.base.policy.EpochSeq,
		PolicyDigest: fixture.base.prepared.PolicyDigest, SnapshotCID: ordinaryCID,
		BlobCID: ordinaryCID, PublicationCount: 1, PrevHeadCID: baseSnapshotCID,
		Signer: Signer{DeviceID: fixture.base.certificate.DeviceID, KeyID: bytes.Clone(fixture.base.certificate.KeyID)},
	}, fixture.base.publisherKey)
	unverifiablePoint := RetentionRecoveryPoint{
		Epoch: fixture.base.policy.EpochSeq, SnapshotCID: ordinaryCID,
		PolicyDigest: fixture.base.prepared.PolicyDigest, ControlCID: alternateControlCID,
	}
	unverifiableEvidence := RetentionRecoveryPointEvidence{
		Point: unverifiablePoint, Position: alternatePosition,
		EpochStartHead:     fixture.pointEvidence.EpochStartHead,
		EpochStartSnapshot: fixture.pointEvidence.EpochStartSnapshot,
		Head:               ordinaryHead, Ciphertext: ordinaryBody,
	}
	_, err = EvaluateRetentionDeclaration(RetentionDeclarationRequest{
		VaultID: fixture.base.policy.Vault, TrustAnchor: fixture.base.trustAnchor, State: fixture.state,
		DeviceID: "device-restore", RetentionFloor: 2,
		RecoveryPoints: []RetentionRecoveryPoint{fixture.point, unverifiablePoint},
		PointEvidence:  []RetentionRecoveryPointEvidence{fixture.pointEvidence, unverifiableEvidence},
	})
	assert.ErrorContains(t, err, "not current or descendant")
}
