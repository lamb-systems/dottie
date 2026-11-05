package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const blobLimitTestDID = "did:plc:abcdefghijklmnopqrstuvwx"

type blobLimitPortTransport struct {
	describeStatus int
	describeBody   []byte
	describeErr    error
	describeCalls  int
	uploadCalls    int
}

func (transport *blobLimitPortTransport) Do(_ context.Context, method, endpoint string, _ url.Values, body []byte, _ string) (int, []byte, error) {
	switch endpoint {
	case "com.atproto.server.describeServer":
		transport.describeCalls++
		if method != "GET" {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return transport.describeStatus, bytes.Clone(transport.describeBody), transport.describeErr
	case "com.atproto.repo.uploadBlob":
		transport.uploadCalls++
		digest, err := multihash.Sum(body, multihash.SHA2_256, -1)
		if err != nil {
			return 0, nil, err
		}
		blob := atdata.Blob{
			Ref: atdata.CIDLink(cid.NewCidV1(cid.Raw, digest)), MimeType: "application/octet-stream", Size: int64(len(body)),
		}
		response, err := json.Marshal(struct {
			Blob atdata.Blob `json:"blob"`
		}{Blob: blob})
		return 200, response, err
	default:
		return 0, nil, io.ErrUnexpectedEOF
	}
}

func (*blobLimitPortTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, io.ErrUnexpectedEOF
}

func TestSessionPublicationPortUsesAdvertisedBlobUploadLimit(t *testing.T) {
	snapshot, policy, certificates := newBlobLimitPortCandidate(t)
	ctx := context.Background()
	identity := atproto.Identity{
		DID: blobLimitTestDID, DIDDocumentID: blobLimitTestDID,
		VerificationMethods: []atproto.VerificationMethod{{ID: blobLimitTestDID + "#atproto", Type: "Multikey", Controller: blobLimitTestDID, PublicKeyMultibase: "synthetic"}},
	}
	portAndStage := func(transport *blobLimitPortTransport) (atproto.ATProtoPublicationIO, error) {
		publicationIO, err := (sessionPublicationPort{identity: identity, transport: transport}).PublicationIO(ctx, service.VaultSelection{}, service.TrustMaterial{}, service.ReadOutcome{})
		if err != nil {
			return atproto.ATProtoPublicationIO{}, err
		}
		_, _, err = publicationIO.StageCandidate(ctx, snapshot, policy, certificates)
		return publicationIO, err
	}

	t.Run("unadvertised", func(t *testing.T) {
		transport := &blobLimitPortTransport{describeStatus: 200, describeBody: []byte(`{}`)}
		_, err := portAndStage(transport)
		require.ErrorIs(t, err, atproto.ErrBlobUploadLimitUnadvertised)
		var limitError *atproto.BlobUploadLimitError
		require.ErrorAs(t, err, &limitError)
		assert.Zero(t, transport.uploadCalls)
		assert.Equal(t, 1, transport.describeCalls)
	})

	t.Run("unparseable", func(t *testing.T) {
		transport := &blobLimitPortTransport{describeStatus: 200, describeBody: []byte(`{"blobUploadLimit":"large"}`)}
		_, err := portAndStage(transport)
		require.ErrorIs(t, err, atproto.ErrBlobUploadLimitUnavailable)
		var limitError *atproto.BlobUploadLimitError
		require.ErrorAs(t, err, &limitError)
		assert.Zero(t, transport.uploadCalls)
	})

	t.Run("advertised below candidate", func(t *testing.T) {
		limit := len(snapshot) - 1
		transport := &blobLimitPortTransport{describeStatus: 200, describeBody: []byte(fmt.Sprintf(`{"blobUploadLimit":%d}`, limit))}
		_, err := portAndStage(transport)
		require.ErrorIs(t, err, atproto.ErrCandidateExceedsBlobUploadLimit)
		assert.Zero(t, transport.uploadCalls)
	})

	t.Run("advertised sufficient", func(t *testing.T) {
		limit := len(snapshot) + 1
		transport := &blobLimitPortTransport{describeStatus: 200, describeBody: []byte(fmt.Sprintf(`{"blobUploadLimit":%d}`, limit))}
		publicationIO, err := portAndStage(transport)
		require.NoError(t, err)
		assert.Equal(t, int64(limit), publicationIO.BlobUploadLimit)
		assert.Equal(t, 1, transport.uploadCalls)
	})

	t.Run("local cap is upper bound", func(t *testing.T) {
		transport := &blobLimitPortTransport{describeStatus: 200, describeBody: []byte(fmt.Sprintf(`{"blobUploadLimit":%d}`, vault.MaxEnvelopeBytes+1))}
		publicationIO, err := (sessionPublicationPort{identity: identity, transport: transport}).PublicationIO(ctx, service.VaultSelection{}, service.TrustMaterial{}, service.ReadOutcome{})
		require.NoError(t, err)
		assert.Equal(t, int64(vault.MaxEnvelopeBytes), publicationIO.BlobUploadLimit)
		_, _, err = publicationIO.StageCandidate(ctx, snapshot, policy, certificates)
		require.NoError(t, err)
		assert.Equal(t, 1, transport.uploadCalls)
	})
}

func newBlobLimitPortCandidate(t *testing.T) ([]byte, vault.Policy, [][]byte) {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	keyID := bytes.Clone(signing.Public().(ed25519.PublicKey))
	device := vault.DeviceMaterial{DeviceID: "blob-limit-root", KeyID: keyID, Signing: signing, Recipient: recipient}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: bytes.Repeat([]byte{1}, 32), VaultName: "blob limit synthetic fixture", RootDevice: device,
		ContentKey: bytes.Repeat([]byte{2}, 32),
		Wraps: []vault.RecipientWrapInput{{
			KeyID: bytes.Clone(keyID), EphemeralPrivate: [32]byte(ephemeral.Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{3}, 24)),
		}},
		PublicationID: [16]byte(bytes.Repeat([]byte{4}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{5}, 24)),
	})
	require.NoError(t, err)
	policy, err := vault.DecodePolicy(genesis.Policy)
	require.NoError(t, err)
	return genesis.Snapshot, policy, [][]byte{genesis.Certificate}
}
