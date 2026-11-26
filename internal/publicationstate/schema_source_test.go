package publicationstate

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSchema2UnitStore(t *testing.T, f fixture, limits ...Limits) (*Store, string) {
	t.Helper()
	require.LessOrEqual(t, len(limits), 1)
	positionLimits := DefaultLimits()
	if len(limits) == 1 {
		positionLimits = limits[0]
	}
	return newSchema2UnitStoreWithLimits(t, f, positionLimits, DefaultAttemptLimits())
}

func newSchema2UnitStoreWithLimits(
	t *testing.T,
	f fixture,
	limits Limits,
	attemptLimits AttemptLimits,
) (*Store, string) {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := OpenWithOptions(directory, f.binding, OpenOptions{
		PositionLimits: limits,
		AttemptLimits:  attemptLimits,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	_, err = os.Lstat(directory + "/" + payloadDirectoryName)
	require.ErrorIs(t, err, os.ErrNotExist)
	return store, directory
}
