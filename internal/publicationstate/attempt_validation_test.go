package publicationstate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptAdmissionRejectsMalformedJoinsWithoutCustodyMutation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	cases := []struct {
		name      string
		candidate CandidateInput
		view      SuppliedRepositoryView
	}{
		{"wrong-key", func() CandidateInput { value := candidate; value.SnapshotKey = "0000000000000001"; return value }(), view},
		{"wrong-head-binding", func() CandidateInput {
			value := candidate
			record, err := publication.DecodeSnapshot(value.SnapshotRecord)
			require.NoError(t, err)
			record.PublicationID[15] = 0x7f
			otherRecord, err := publication.EncodeSnapshot(record)
			require.NoError(t, err)
			otherCID, err := publication.RecordCID(otherRecord)
			require.NoError(t, err)
			value.HeadRecord, err = publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: 0, SnapshotCID: otherCID, BlobCID: record.Blob.CID})
			require.NoError(t, err)
			return value
		}(), view},
		{"malformed-hash-matching-payload", func() CandidateInput {
			return candidateWithPayload(t, candidate, f.binding, []byte("not a packed snapshot payload"))
		}(), view},
		{"wrong-origin", candidate, func() SuppliedRepositoryView {
			value := view
			value.Origin.AccountDID = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
			value.Origin.Repository = "at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
			return value
		}()},
		{"wrong-scope", candidate, func() SuppliedRepositoryView {
			value := view
			value.Scope = ViewScopeDedicatedSpace
			return value
		}()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := store.PrepareAttempt(ctx, test.candidate, test.view, review)
			require.Error(t, err)
			var attempts int
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
			assert.Equal(t, 0, attempts)
			_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName))
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	_, err = store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, [32]byte{})
	requireErrorMetadata(t, err, ErrConsent, StageAttempt, ReasonConfirmation)
	_, statErr := os.Stat(filepath.Join(directory, payloadDirectoryName))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}
