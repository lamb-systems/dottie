package atproto

import (
	"context"
	"errors"
	"io"
	"net/url"
	"testing"

	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/require"
)

type publicationFailureTransport struct {
	status int
	body   []byte
	calls  int
}

func (transport *publicationFailureTransport) Do(context.Context, string, string, url.Values, []byte, string) (int, []byte, error) {
	transport.calls++
	return transport.status, append([]byte(nil), transport.body...), nil
}

func (*publicationFailureTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("unexpected stream request")
}

func TestPublicationPredecessorMatchesRevisionRequiresControlBytes(t *testing.T) {
	_, _, predecessor, _ := newAtprotoPublicationFixture(t)
	revision, err := publicationRevisionForPredecessor(predecessor)
	require.NoError(t, err)
	control, err := vault.DecodeControl(predecessor.Control)
	require.NoError(t, err)
	control.HeadSnapshotCID[0] ^= 0xff
	predecessor.Control, err = vault.EncodeControl(control)
	require.NoError(t, err)

	err = publicationPredecessorMatchesRevision(revision, predecessor)
	require.ErrorIs(t, err, ErrBatchRejected)
}

func TestPublicationPredecessorMatchesRevisionRequiresHeadAndSnapshotCID(t *testing.T) {
	for _, check := range []struct {
		name   string
		mutate func(*testing.T, *vault.Predecessor)
	}{
		{
			name: "head record bytes",
			mutate: func(t *testing.T, predecessor *vault.Predecessor) {
				head, err := vault.DecodeHead(predecessor.Head)
				require.NoError(t, err)
				head.PublicationCount++
				predecessor.Head, err = vault.EncodeHead(head)
				require.NoError(t, err)
			},
		},
		{
			name: "head snapshot CID",
			mutate: func(_ *testing.T, predecessor *vault.Predecessor) {
				predecessor.HeadCID = append([]byte(nil), predecessor.HeadCID...)
				predecessor.HeadCID[0] ^= 0xff
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			_, _, predecessor, _ := newAtprotoPublicationFixture(t)
			revision, err := publicationRevisionForPredecessor(predecessor)
			require.NoError(t, err)
			check.mutate(t, &predecessor)

			err = publicationPredecessorMatchesRevision(revision, predecessor)
			require.ErrorIs(t, err, ErrBatchRejected)
		})
	}
}

func TestPublishSnapshotFencedSignalsCandidateDisclosureAfterRejection(t *testing.T) {
	_, publisher, predecessor, publication := newAtprotoPublicationFixture(t)
	revision := publicationTestRevision()
	fenced, err := snapshotPublication(publication, publisher.Signing, blobJSONFromCID(publication.SnapshotCID, len(publication.Snapshot)), revision, predecessor)
	require.NoError(t, err)
	transport := &publicationFailureTransport{status: 400, body: []byte(`{"error":"InvalidRequest"}`)}

	_, err = publishSnapshotFenced(context.Background(), transport, revision, fenced)
	require.ErrorIs(t, err, ErrBatchRejected)
	require.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	require.Equal(t, 1, transport.calls)
}
