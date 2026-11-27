package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
)

func publicationProposalStoreDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	return directory
}

func publicationProposalSummaries(t *testing.T, segments, entries, pathBytes int) []byte {
	t.Helper()
	summaries := make([]publicationstate.SegmentSummary, 0, segments)
	for segment := range segments {
		references := make([]publicationstate.PayloadEntryReference, 0, entries)
		for index := range entries {
			references = append(references, publicationstate.PayloadEntryReference{
				Path: fmt.Sprintf("%s%03d", strings.Repeat("f", pathBytes), index),
				CID:  []byte{0x01, 0x55, 0x12, byte(index >> 8), byte(index)},
				Size: uint64(index + 1),
			})
		}
		summaries = append(summaries, publicationstate.SegmentSummary{
			TargetID: fmt.Sprintf("target-%03d", segment),
			Form:     publicationstate.PayloadFormFileSet,
			Entries:  references,
		})
	}
	encoded, err := publicationstate.EncodeSegmentSummaries(summaries)
	require.NoError(t, err)
	return encoded
}

func publicationProposalRecordFor(
	segments []byte,
	form publication.PayloadForm,
	publicationID [16]byte,
) service.PublicationProposalRecord {
	return service.PublicationProposalRecord{
		Version: 2,
		Binding: publicationstate.Binding{
			AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
			Backend:    publicationstate.BackendPublicRepo,
			Repository: "at://did:plc:abcdefghijklmnopqrstuvwx",
			Vault:      [32]byte{0x62},
		},
		DatabaseID: [32]byte{0x64}, Generation: 1, FloorRevision: 0,
		CandidateRecordCID: []byte{0x66},
		Form:               form,
		Segments:           segments,
		PayloadsDigest:     [32]byte{0x67},
		Review: publicationstate.LocalReviewContext{
			SelectionDigest: [32]byte{0x68}, SelectionRevision: 1,
			ApprovalDigest: [32]byte{0x69}, ApprovalRevision: 1,
		},
		PublicationID: publicationID,
		Lifecycle:     publicationstate.AttemptPrepared,
		Confirmation:  [32]byte{0x6a},
	}
}

func TestPublicationProposalAcceptsASummarySetAboveTheFormerFileBound(t *testing.T) {
	store := newPublicationProposalStore(publicationProposalStoreDirectory(t))
	segments := publicationProposalSummaries(t, 1, 64, 1000)
	require.Greater(t, len(segments), 8<<10, "the fixture does not exceed the former bound")
	require.Less(t, len(segments), publicationProposalFileLimit)
	record := publicationProposalRecordFor(segments, publication.PayloadFormFileSet, [16]byte{0x71, 0x01})
	require.NoError(t, store.Issue(context.Background(), record))

	listed, err := store.List(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, record.Segments, listed[0].Segments)
	assert.Equal(t, record.PublicationID, listed[0].PublicationID)
	assert.Equal(t, record.Form, listed[0].Form)
}

func TestPublicationProposalRefusesAnOversizedRecordWithoutWriting(t *testing.T) {
	directory := publicationProposalStoreDirectory(t)
	store := newPublicationProposalStore(directory)
	segments := publicationProposalSummaries(t, 40, 64, 1000)
	require.Greater(t, len(segments), publicationProposalFileLimit)
	record := publicationProposalRecordFor(segments, publication.PayloadFormMixed, [16]byte{0x71, 0x02})

	err := store.Issue(context.Background(), record)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errProposalRecordTooLarge))

	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "an oversized proposal was written")

	listed, listErr := store.List(context.Background())
	require.NoError(t, listErr)
	assert.Empty(t, listed, "an oversized proposal poisoned the listing")
}

func TestPublicationProposalRefusesAFileAboveTheBoundOnRead(t *testing.T) {
	directory := publicationProposalStoreDirectory(t)
	store := newPublicationProposalStore(directory)
	record := publicationProposalRecordFor(cliEncodedPackedSegments(t), publication.PayloadFormPacked, [16]byte{0x71, 0x03})
	encoded, err := encodeProposalRecord(record)
	require.NoError(t, err)
	oversized := append(encoded, bytes.Repeat([]byte(" "), publicationProposalFileLimit)...)
	require.NoError(t, os.WriteFile(store.path(record.PublicationID), oversized, 0o600))

	_, err = store.List(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, errProposalRecordInvalid))
}

func TestPublicationProposalReadsALegacyHexSegmentsField(t *testing.T) {
	directory := publicationProposalStoreDirectory(t)
	store := newPublicationProposalStore(directory)
	segments := publicationProposalSummaries(t, 1, 4, 8)
	record := publicationProposalRecordFor(segments, publication.PayloadFormFileSet, [16]byte{0x71, 0x04})

	encoded, err := encodeProposalRecord(record)
	require.NoError(t, err)
	legacy := bytes.Replace(
		encoded,
		[]byte(`"segments":"`+base64.StdEncoding.EncodeToString(segments)+`"`),
		[]byte(`"segments":"`+hex.EncodeToString(segments)+`"`),
		1,
	)
	require.NotEqual(t, encoded, legacy, "the fixture did not rewrite the segments field")
	require.NoError(t, os.WriteFile(store.path(record.PublicationID), legacy, 0o600))

	listed, err := store.List(context.Background())
	require.NoError(t, err, "a legacy hex proposal was rejected")
	require.Len(t, listed, 1)
	assert.Equal(t, segments, listed[0].Segments)
}

func TestPublicationProposalRefusesAnArraySegmentsField(t *testing.T) {
	directory := publicationProposalStoreDirectory(t)
	store := newPublicationProposalStore(directory)
	record := publicationProposalRecordFor(cliEncodedPackedSegments(t), publication.PayloadFormPacked, [16]byte{0x71, 0x05})
	encoded, err := encodeProposalRecord(record)
	require.NoError(t, err)
	segments, err := decodeProposalSegments(
		string(cliEncodedPackedSegments(t)),
	)
	require.Error(t, err)
	assert.Nil(t, segments)

	array := bytes.Replace(encoded, []byte(`"segments":"`), []byte(`"segments":[`), 1)
	require.NoError(t, os.WriteFile(store.path(record.PublicationID), array, 0o600))
	_, listErr := store.List(context.Background())
	require.Error(t, listErr)
}

func TestPublicationProposalConsumeKeepsTheFileReadable(t *testing.T) {
	directory := publicationProposalStoreDirectory(t)
	store := newPublicationProposalStore(directory)
	segments := publicationProposalSummaries(t, 1, 64, 32)
	record := publicationProposalRecordFor(segments, publication.PayloadFormFileSet, [16]byte{0x71, 0x06})
	require.NoError(t, store.Issue(context.Background(), record))
	require.NoError(t, store.Consume(context.Background(), record.PublicationID))

	listed, err := store.List(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.True(t, listed[0].Consumed)
	assert.Equal(t, segments, listed[0].Segments)

	info, err := os.Stat(store.path(record.PublicationID))
	require.NoError(t, err)
	assert.LessOrEqual(t, info.Size(), int64(publicationProposalFileLimit))
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
