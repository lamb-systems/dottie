package publicationstate

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

func TestFileSetMaterialCapacityCountsDistinctCIDsNotEntryCount(t *testing.T) {
	limits := DefaultAttemptLimits()
	limits.ManagedObjects = 1
	entries := make([]publication.PayloadEntry, 0, publication.MaxSnapshotEntries)
	for index := range publication.MaxSnapshotEntries {
		entries = append(entries, publication.PayloadEntry{
			Path: "entry-" + string(rune('a'+index%26)) + ".lua",
			Mode: 0o600, Size: 1, Content: []byte("same"),
		})
	}
	payload := &FileSetPayload{Entries: make([]PayloadEntryReference, 0, len(entries))}
	for _, entry := range entries {
		payload.Entries = append(payload.Entries, PayloadEntryReference{
			Path: entry.Path, CID: []byte{0x01}, Size: 1,
		})
	}
	require.NoError(t, validateFileSetMaterialLimits(payload, limits))

	payload.Entries[len(payload.Entries)-1].CID = []byte{0x02}
	err := validateFileSetMaterialLimits(payload, limits)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
	assert.Contains(t, err.Error(), "file-set managed objects: 2 exceeds 1")
}

func TestFileSetMaterialCapacityRefusesAtTheSharedObjectLimit(t *testing.T) {
	limits := DefaultAttemptLimits()
	payload := &FileSetPayload{Entries: make([]PayloadEntryReference, 0, publication.MaxSnapshotEntries)}
	for index := range DefaultAttemptLimits().ManagedObjects {
		payload.Entries = append(payload.Entries, PayloadEntryReference{
			Path: "entry-" + strconv.FormatUint(uint64(index), 10) + ".lua",
			CID:  []byte{byte(index + 1)}, Size: 1,
		})
	}
	require.NoError(t, validateFileSetMaterialLimits(payload, limits))

	limits.ManagedObjects--
	err := validateFileSetMaterialLimits(payload, limits)
	requireErrorMetadata(t, err, ErrLimit, StageInput, ReasonCapacity)
	assert.Contains(t, err.Error(), "file-set managed objects: 64 exceeds 63")
}
