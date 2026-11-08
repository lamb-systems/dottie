package publication

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/stretchr/testify/require"
)

func FuzzRecordToJSON(f *testing.F) {
	_, snapshotCBOR := fixtureSnapshot(f, []byte("record JSON fuzz seed"), 0, nil, 1)
	f.Add(snapshotCBOR)
	parentCID, err := RecordCID(snapshotCBOR)
	require.NoError(f, err)
	successor, successorCBOR := fixtureSnapshot(f, []byte("record JSON successor seed"), 1, parentCID, 2)
	f.Add(successorCBOR)
	successorCID, err := RecordCID(successorCBOR)
	require.NoError(f, err)
	headCBOR, err := EncodeHead(HeadRecord{
		SchemaVersion:  SchemaVersion,
		Vault:          successor.Vault,
		PublicationSeq: successor.PublicationSeq,
		SnapshotCID:    successorCID,
		BlobCID:        bytes.Clone(successor.Blob.CID),
	})
	require.NoError(f, err)
	f.Add(headCBOR)

	f.Fuzz(func(t *testing.T, data []byte) {
		expectedCID, validationErr := RecordCID(data)
		encoded, err := RecordToJSON(data)
		if validationErr != nil {
			require.Nil(t, encoded)
			cause := errors.Unwrap(validationErr)
			require.NotNil(t, cause)
			require.ErrorIs(t, err, cause)
			var expected *Violation
			var actual *Violation
			require.ErrorAs(t, validationErr, &expected)
			require.ErrorAs(t, err, &actual)
			require.Equal(t, expected.Field(), actual.Field())
			require.Equal(t, expected.Reason(), actual.Reason())
			require.NotErrorIs(t, err, ErrRecordJSON)
			return
		}

		require.NoError(t, err)
		require.NotNil(t, encoded)
		require.LessOrEqual(t, len(encoded), maxRecordJSONBytes)
		parsed, err := atdata.UnmarshalJSON(encoded)
		require.NoError(t, err)
		reconstructed, err := atdata.MarshalCBOR(parsed)
		require.NoError(t, err)
		require.True(t, bytes.Equal(data, reconstructed))
		actualCID, err := RecordCID(reconstructed)
		require.NoError(t, err)
		require.True(t, bytes.Equal(expectedCID, actualCID))
	})
}
