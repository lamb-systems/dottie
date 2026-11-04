package vault

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAttestationVersionTwoCanonicalRecoveryPointsAndSignature(t *testing.T) {
	fixture := newAttestationFixture(t)
	fixture.request.RetentionFloor = 0
	fixture.request.RetainedRecoveryPoints = 3
	fixture.request.RecoveryPoints = []RetentionRecoveryPoint{
		{Epoch: 7, SnapshotCID: []byte("snapshot-z")},
		{Epoch: 3, SnapshotCID: []byte("snapshot-old")},
		{Epoch: 7, SnapshotCID: []byte("snapshot-a")},
	}
	encoded, err := BuildAttestation(fixture.request)
	require.NoError(t, err)
	assert.Equal(t, byte(1), encoded[3])
	attestation, err := DecodeAttestation(encoded)
	require.NoError(t, err)
	assert.Equal(t, AttestationVersion2, attestation.SchemaVersion)
	assert.Equal(t, []RetentionRecoveryPoint{
		{Epoch: 3, SnapshotCID: []byte("snapshot-old")},
		{Epoch: 7, SnapshotCID: []byte("snapshot-a")},
		{Epoch: 7, SnapshotCID: []byte("snapshot-z")},
	}, attestation.RecoveryPoints)
	assert.Equal(t, len(attestation.RecoveryPoints), int(attestation.RetainedRecoveryPoints))
	assert.Equal(t, encoded, mustEncodeAttestation(t, attestation))
	_, err = VerifyAttestation(encoded, fixture.verify)
	require.NoError(t, err)

	attestation.RecoveryPoints[0].SnapshotCID[0] ^= 0x80
	tampered, err := EncodeAttestation(attestation)
	require.NoError(t, err)
	_, err = VerifyAttestation(tampered, fixture.verify)
	assert.ErrorIs(t, err, ErrSignature)

	unknownBodyVersion := bytes.Clone(encoded)
	unknownBodyVersion[5], unknownBodyVersion[6] = 0, 3
	_, err = DecodeAttestation(unknownBodyVersion)
	assert.ErrorIs(t, err, ErrUnsupportedVersion)
}

func TestDecodeAttestationV1RoundTripsExactCountOnlyBytes(t *testing.T) {
	encoded := vectorSeed("attestation-root-signed-chain.hex")
	assert.Equal(t, byte(1), encoded[3])
	attestation, err := DecodeAttestation(encoded)
	require.NoError(t, err)
	assert.Equal(t, AttestationVersion1, attestation.SchemaVersion)
	assert.Empty(t, attestation.RecoveryPoints)
	reencoded, err := EncodeAttestation(attestation)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)
}

func TestAttestationVersionTwoRejectsNoncanonicalAndInconsistentRecoveryPoints(t *testing.T) {
	base := Attestation{
		SchemaVersion: AttestationVersion2, DeviceID: "device", RetainedRecoveryPoints: 2,
		RecoveryPoints: []RetentionRecoveryPoint{
			{Epoch: 1, SnapshotCID: []byte("a")}, {Epoch: 2, SnapshotCID: []byte("b")},
		}, Signer: Signer{DeviceID: "device", KeyID: []byte("key")},
	}
	for _, test := range []struct {
		name   string
		mutate func(*Attestation)
	}{
		{name: "count mismatch", mutate: func(value *Attestation) { value.RetainedRecoveryPoints++ }},
		{name: "out of order", mutate: func(value *Attestation) {
			value.RecoveryPoints[0], value.RecoveryPoints[1] = value.RecoveryPoints[1], value.RecoveryPoints[0]
		}},
		{name: "duplicate", mutate: func(value *Attestation) {
			value.RecoveryPoints[1] = RetentionRecoveryPoint{Epoch: 1, SnapshotCID: []byte("a")}
		}},
		{name: "empty cid", mutate: func(value *Attestation) { value.RecoveryPoints[0].SnapshotCID = nil }},
		{name: "oversized cid", mutate: func(value *Attestation) {
			value.RecoveryPoints[0].SnapshotCID = bytes.Repeat([]byte{1}, MaxParentBytes+1)
		}},
		{name: "unsafe epoch", mutate: func(value *Attestation) { value.RecoveryPoints[0].Epoch = uint64(^uint64(0)>>1) + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.RecoveryPoints = append([]RetentionRecoveryPoint(nil), base.RecoveryPoints...)
			for index := range value.RecoveryPoints {
				value.RecoveryPoints[index].SnapshotCID = bytes.Clone(base.RecoveryPoints[index].SnapshotCID)
			}
			test.mutate(&value)
			_, err := EncodeAttestation(value)
			assert.Error(t, err)
		})
	}
}

func TestBuildAttestationRejectsRecoveryPointNewerThanControl(t *testing.T) {
	fixture := newAttestationFixture(t)
	fixture.request.RetainedRecoveryPoints = 1
	fixture.request.RecoveryPoints = []RetentionRecoveryPoint{{Epoch: 8, SnapshotCID: []byte("future")}}
	_, err := BuildAttestation(fixture.request)
	assert.ErrorIs(t, err, ErrAuthorization)
}

func mustEncodeAttestation(t *testing.T, value Attestation) []byte {
	t.Helper()
	encoded, err := EncodeAttestation(value)
	require.NoError(t, err)
	return encoded
}
