package atproto

import (
	"context"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/stretchr/testify/require"
)

func TestRevisionReaderRejectsRecordBytesMismatchBeforeMembershipChecks(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	recordPath := "systems.lamb.dottie.vaultSnapshot/r0"
	recordCID := fixture.recordBlocks[recordPath]
	changedRecord, err := atdata.MarshalCBOR(map[string]any{
		"$type": "systems.lamb.dottie.vaultSnapshot",
		"probe": "changed-but-valid-CBOR",
	})
	require.NoError(t, err)
	blocks := append([]proofBlock(nil), fixture.blocks...)
	found := false
	for index := range blocks {
		if blocks[index].cid.Equals(recordCID) {
			blocks[index].data = changedRecord
			found = true
			break
		}
	}
	require.True(t, found, "fixture did not contain record block %s", recordPath)
	transport := &proofTransport{
		carBytes: encodeProofCAR(t, fixture.root, blocks), latestCIDs: []string{fixture.root.String()}, streamStatus: 200,
	}

	_, err = proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	require.ErrorIs(t, err, ErrUntrustedCar)
	require.ErrorContains(t, err, "malformed CAR block")
}
