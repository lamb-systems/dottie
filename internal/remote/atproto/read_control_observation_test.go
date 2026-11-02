package atproto

import (
	"bytes"
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func forkReadControlRecord(t *testing.T, fixture readFixture) ([]byte, []byte) {
	t.Helper()
	current, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	control := controlFromRecord(current.(ControlRecord))
	control.HeadSnapshotCID = readRawCID(t, []byte("competing branch snapshot"))
	encoded := signReadControl(t, control, fixtureSigningKey(11))
	return encodeReadControlRecord(t, encoded), readRawCID(t, encoded)
}

func installReadEpochTwo(t *testing.T, fixture *readFixture, predecessorControlRecord, predecessorControlCID []byte) []byte {
	t.Helper()
	policyKey := RecordKey{Collection: VaultPolicyNSID, RKey: "self"}
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	previousPolicyRecord := bytes.Clone(fixture.records[policyKey])
	_, _, previousPolicyDigest := fixturePolicyParts(t, *fixture)
	policyRecord, policy, policyDigest := craftSuccessorPolicy(t, *fixture, 2, previousPolicyDigest)
	envelope, snapshot := sealSnapshotAtEpoch(t, *fixture, policy, policyDigest, 2, nil, 0xF2, []byte("epoch two payload"))
	envelopeCID := readRawCID(t, envelope)
	controlRecord := craftControl(t, *fixture, 2, policyDigest, envelopeCID, predecessorControlCID)
	head := craftHead(t, *fixture, 2, policyDigest, envelopeCID, nil, 1, publisherSigner(), fixtureSigningKey(12))
	fixture.records[policyKey] = policyRecord
	putReadRecord(t, fixture.records, controlKey, controlRecord)
	installSnapshot(t, fixture, envelope, snapshot, head)
	fixture.request.PreviousPolicy = previousPolicyRecord
	fixture.request.PreviousControl = bytes.Clone(predecessorControlRecord)
	return bytes.Clone(previousPolicyRecord)
}

func TestVaultReaderJoinsEpochAdvanceToObservedControl(t *testing.T) {
	fixture := newReadFixture(t)
	reader := fixture.reader()
	_, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err)
	observedControlRecord := bytes.Clone(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	observedControlObject, err := DecodeRecord(observedControlRecord)
	require.NoError(t, err)
	observedControlBytes, err := vault.EncodeControl(controlFromRecord(observedControlObject.(ControlRecord)))
	require.NoError(t, err)
	observedControlCID := readRawCID(t, observedControlBytes)

	forkControlRecord, forkControlCID := forkReadControlRecord(t, fixture)
	installReadEpochTwo(t, &fixture, forkControlRecord, forkControlCID)
	_, err = reader.Read(context.Background(), fixture.request)
	require.ErrorIs(t, err, ErrVaultPublicationControlAncestry,
		"an authenticated epoch-two control on a competing branch does not join the observed epoch-one control")
	var readError *ReadError
	require.ErrorAs(t, err, &readError)
	assert.Equal(t, ReadStageVaultAuth, readError.Stage)

	currentControlRecord, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	currentControl := controlFromRecord(currentControlRecord.(ControlRecord))
	currentControl.PrevControlCID = bytes.Clone(observedControlCID)
	currentControlBytes := signReadControl(t, currentControl, fixtureSigningKey(11))
	currentControl, err = vault.DecodeControl(currentControlBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, controlRecordFromObject(currentControl))
	fixture.request.PreviousControl = observedControlRecord
	replaceReadCAR(t, &fixture, fixture.records)
	joined, err := reader.Read(context.Background(), fixture.request)
	require.NoError(t, err, "the epoch advance succeeds when its authenticated control edge joins the observed control")
	assert.Equal(t, uint64(2), joined.EpochSeq)
	assert.Equal(t, observedControlCID, joined.Control.PrevControlCID)
}

func TestVaultReaderAllowsFirstObservationAtHigherEpochWithAuthenticatedControlEdge(t *testing.T) {
	fixture := newReadFixture(t)
	forkControlRecord, forkControlCID := forkReadControlRecord(t, fixture)
	installReadEpochTwo(t, &fixture, forkControlRecord, forkControlCID)

	result, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err, "a first observation has no older locally observed control to join")
	assert.Equal(t, uint64(2), result.EpochSeq)
	assert.Equal(t, forkControlCID, result.Control.PrevControlCID)
}
