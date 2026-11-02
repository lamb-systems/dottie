package vault

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type exportGuardReader struct {
	data []byte
	read int64
}

func (reader *exportGuardReader) Read(buffer []byte) (int, error) {
	if reader.read >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	count := copy(buffer, reader.data[reader.read:])
	reader.read += int64(count)
	return count, nil
}

func manifestRegionEnd(t *testing.T, manifest ExportManifest) int64 {
	t.Helper()
	manifestBytes, err := encodeExportManifest(manifest)
	require.NoError(t, err)
	size := int64(len(manifestBytes))
	return int64(len(exportMagic)) + 512 + size + blockPadding(size) + 512
}

func TestExportRefusesOverCapAndMismatchedMembers(t *testing.T) {
	t.Run("over-cap inventory", func(t *testing.T) {
		input, fixture := exportTestInput(t)
		genuine, err := EncodeExportArchive(input)
		require.NoError(t, err)
		manifest, members := splitExportArchive(t, genuine)
		template := manifest.Entries[0]
		for len(manifest.Entries) <= maxExportEntries {
			manifest.Entries = append(manifest.Entries, template)
		}
		require.Greater(t, len(manifest.Entries), maxExportEntries)
		hostile := buildHostileExportArchive(t, manifest, members)
		threshold := manifestRegionEnd(t, manifest)

		guard := &exportGuardReader{data: hostile}
		_, err = ReadExportArchive(guard, exportTestOptions(fixture))
		require.ErrorIs(t, err, ErrIncompleteExport)
		assert.LessOrEqual(t, guard.read, threshold, "the inventory bound must return before any member header is read")
		assert.Less(t, guard.read, int64(len(hostile)), "no member payload is read past the manifest")
	})

	t.Run("within-cap first-member header mismatch", func(t *testing.T) {
		input, fixture := exportTestInput(t)
		genuine, err := EncodeExportArchive(input)
		require.NoError(t, err)
		manifest, members := splitExportArchive(t, genuine)
		require.LessOrEqual(t, len(manifest.Entries), maxExportEntries)
		require.NotEmpty(t, members)
		require.Equal(t, ordinal(1), members[0].name)
		members[0].name = "000042"
		hostile := buildHostileExportArchive(t, manifest, members)
		threshold := manifestRegionEnd(t, manifest)

		guard := &exportGuardReader{data: hostile}
		_, err = ReadExportArchive(guard, exportTestOptions(fixture))
		require.ErrorIs(t, err, ErrExportIntegrity)
		assert.LessOrEqual(t, guard.read, threshold, "the header check must fire before the first member payload is read")
		assert.Less(t, guard.read, int64(len(hostile)), "no member payload is read past the manifest")
	})
}
