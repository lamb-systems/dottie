package publicationstate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func requireErrorMetadata(t *testing.T, err error, class error, stage Stage, reason Reason) {
	t.Helper()
	require.Error(t, err)
	var stateError *Error
	require.ErrorAs(t, err, &stateError)
	require.Equal(t, class, stateError.Class())
	require.Equal(t, stage, stateError.Stage())
	require.Equal(t, reason, stateError.Reason())
}
