package atproto

import (
	"bytes"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationLexiconKeepsRecoveryPointsOptionalAndVersioned(t *testing.T) {
	lexicons := readLexicons(t)
	var attestation lexiconDocument
	for _, lexicon := range lexicons {
		if lexicon.ID == VaultAttestationNSID {
			attestation = lexicon
			break
		}
	}
	require.Equal(t, VaultAttestationNSID, attestation.ID)
	properties := attestation.Defs["main"].Record["properties"].(map[string]any)
	version := properties["schemaVersion"].(map[string]any)
	assert.Equal(t, float64(1), version["minimum"])
	assert.Equal(t, float64(2), version["maximum"])
	assert.NotContains(t, attestation.Defs["main"].Record["required"], "recoveryPoints")
	points := properties["recoveryPoints"].(map[string]any)
	assert.Equal(t, float64(65535), points["maxLength"])
	item := points["items"].(map[string]any)
	assert.Equal(t, []any{"epoch", "snapshotCid"}, item["required"])
	assert.Equal(t, 2, len(item["properties"].(map[string]any)))
}

func TestAttestationVersionTwoRecordBindingContextAndLexiconStrictness(t *testing.T) {
	fixture := newReadFixture(t)
	verification := readAttestationVerification(t, fixture)
	policy, policyBytes, digest := fixturePolicyParts(t, fixture)
	attestation := vault.Attestation{
		SchemaVersion: vault.AttestationVersion2, Vault: policy.Vault, DeviceID: "root", PolicyDigest: digest,
		RetentionFloor: policy.PolicyRetentionFloor, RetainedRecoveryPoints: 3,
		RecoveryPoints: []vault.RetentionRecoveryPoint{
			{Epoch: 0, SnapshotCID: []byte("snapshot-zero")},
			{Epoch: 1, SnapshotCID: []byte("snapshot-one-a")},
			{Epoch: 1, SnapshotCID: []byte("snapshot-one-b")},
		},
		ControlCID: readRawCID(t, verification.State.Control),
		Signer:     vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	objectBytes := signReadAttestation(t, attestation, fixtureSigningKey(11))
	object, err := vault.DecodeAttestation(objectBytes)
	require.NoError(t, err)
	recordBytes, err := EncodeRecord(attestationRecordFromVault(object))
	require.NoError(t, err)
	decoded, err := DecodeRecord(recordBytes)
	require.NoError(t, err)
	record := decoded.(AttestationRecord)
	assert.Equal(t, int64(2), record.SchemaVersion)
	assert.Len(t, record.RecoveryPoints, 3)
	assert.NoError(t, VerifyRecordBinding(recordBytes, objectBytes))
	_, err = VerifyAttestationRecord(recordBytes, verification)
	assert.NoError(t, err)

	control, err := vault.DecodeControl(verification.State.Control)
	require.NoError(t, err)
	controlBytes, err := EncodeRecord(toControlRecord(control))
	require.NoError(t, err)
	policyObject, err := vault.DecodePolicy(policyBytes)
	require.NoError(t, err)
	policyRecordBytes, err := EncodeRecord(toPolicyRecord(policyObject))
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(recordBytes, RecordContext{Policy: policyRecordBytes, Control: controlBytes}))

	objectMap, err := atdata.UnmarshalCBOR(recordBytes)
	require.NoError(t, err)
	delete(objectMap, "recoveryPoints")
	missingList, err := atdata.MarshalCBOR(objectMap)
	require.NoError(t, err)
	_, err = DecodeRecord(missingList)
	assert.Error(t, err)

	objectMap, err = atdata.UnmarshalCBOR(recordBytes)
	require.NoError(t, err)
	points := objectMap["recoveryPoints"].([]any)
	points[0], points[1] = points[1], points[0]
	outOfOrder, err := atdata.MarshalCBOR(objectMap)
	require.NoError(t, err)
	_, err = DecodeRecord(outOfOrder)
	assert.Error(t, err)

	objectMap, err = atdata.UnmarshalCBOR(recordBytes)
	require.NoError(t, err)
	points = objectMap["recoveryPoints"].([]any)
	points[0].(map[string]any)["unexpected"] = []byte("strict")
	unknownField, err := atdata.MarshalCBOR(objectMap)
	require.NoError(t, err)
	_, err = DecodeRecord(unknownField)
	assert.Error(t, err)

	mismatched := attestationRecordFromVault(object)
	mismatched.RecoveryPoints = mismatched.RecoveryPoints[:2]
	_, err = EncodeRecord(mismatched)
	assert.Error(t, err)

	mismatched = attestationRecordFromVault(object)
	mismatched.RecoveryPoints[0].SnapshotCID = []byte("other-snapshot")
	mismatchedBytes, err := EncodeRecord(mismatched)
	require.NoError(t, err)
	assert.Error(t, VerifyRecordBinding(mismatchedBytes, objectBytes))

	tampered := bytes.Clone(objectBytes)
	tampered[len(tampered)-1] ^= 0x80
	tamperedObject, err := vault.DecodeAttestation(tampered)
	require.NoError(t, err)
	tamperedRecord, err := EncodeRecord(attestationRecordFromVault(tamperedObject))
	require.NoError(t, err)
	_, err = VerifyAttestationRecord(tamperedRecord, verification)
	assert.ErrorIs(t, err, vault.ErrSignature)
}
