package atproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func transitionReadIO(fixture *readFixture, store PublicationObservationStore, previousControls [][]byte) ATProtoTransitionIO {
	return ATProtoTransitionIO{
		Reader: RevisionReader{
			Transport: fixture.transport, DIDDocumentID: fixture.request.DIDDocumentID,
			VerificationMethods: fixture.request.VerificationMethods,
		},
		Transport: fixture.transport, DID: fixture.request.DID, TrustAnchor: fixture.request.TrustAnchor,
		PreviousPolicies: [][]byte{bytes.Clone(fixture.request.PreviousPolicy)}, PreviousControls: previousControls,
		ObservationStore: store, Clock: func() time.Time { return time.Unix(1_700_000_123, 0) },
	}
}

func assertNoTransitionReadPersistence(t *testing.T, tracker *transitionObservationTracker) {
	t.Helper()
	assert.Zero(t, tracker.calls, "a refused current read does not persist a publication observation")
	attempts, err := tracker.store.(*state.Store).TransitionAttempts(context.Background())
	require.NoError(t, err)
	assert.Empty(t, attempts, "a refused current read does not persist a transition attempt")
}

func TestReadCurrentAuthenticatesControlPredecessorBeforeReturningPredecessor(t *testing.T) {
	fixture := newReadFixture(t)
	controlKey := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	decoded, err := DecodeRecord(fixture.records[controlKey])
	require.NoError(t, err)
	control := controlFromRecord(decoded.(ControlRecord))
	control.PrevControlCID = readRawCID(t, []byte("unjoinable predecessor control"))
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	control, err = vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, controlKey, controlRecordFromObject(control))
	replaceReadCAR(t, &fixture, fixture.records)

	tracker := &transitionObservationTracker{store: fixture.observationStore}
	adapter := transitionReadIO(&fixture, tracker, [][]byte{bytes.Clone(fixture.request.PreviousControl)})
	revision, predecessor, err := adapter.ReadCurrent(context.Background())
	require.ErrorIs(t, err, ErrReadControlLinkage)
	assert.Nil(t, revision)
	assert.Equal(t, vault.Predecessor{}, predecessor)
	assertNoTransitionReadPersistence(t, tracker)

	positive := newReadFixture(t)
	positiveTracker := &transitionObservationTracker{store: positive.observationStore}
	positiveAdapter := transitionReadIO(&positive, positiveTracker, [][]byte{bytes.Clone(positive.request.PreviousControl)})
	_, genuine, err := positiveAdapter.ReadCurrent(context.Background())
	require.NoError(t, err, "a genuine current state with its predecessor control reads")
	assert.NotEmpty(t, genuine.Control)
	assert.Equal(t, 1, positiveTracker.calls)
	assert.Equal(t, 1, positiveTracker.firstSeenCalls)
	firstSeenAt, found, err := positive.observationStore.VaultEpochFirstSeen(context.Background(), positive.request.Vault, genuine.EpochSeq)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(1_700_000_123), firstSeenAt)

	positiveAdapter.Clock = func() time.Time { return time.Unix(1_701_000_123, 0) }
	_, _, err = positiveAdapter.ReadCurrent(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, positiveTracker.firstSeenCalls, "a repeated same-epoch read does not attempt to restamp first-seen time")
	firstSeenAt, found, err = positive.observationStore.VaultEpochFirstSeen(context.Background(), positive.request.Vault, genuine.EpochSeq)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(1_700_000_123), firstSeenAt, "a repeated authenticated read cannot reset the epoch clock")
}

func TestReadCurrentRequiresPreviousControlEvidence(t *testing.T) {
	fixture := newReadFixture(t)
	tracker := &transitionObservationTracker{store: fixture.observationStore}
	adapter := transitionReadIO(&fixture, tracker, nil)
	_, predecessor, err := adapter.ReadCurrent(context.Background())
	require.ErrorIs(t, err, ErrReadControlRequired)
	assert.Equal(t, vault.Predecessor{}, predecessor)
	assertNoTransitionReadPersistence(t, tracker)

	publicationIO := ATProtoPublicationIO{
		Reader: adapter.Reader, Transport: fixture.transport, DID: fixture.request.DID, TrustAnchor: fixture.request.TrustAnchor,
		PreviousPolicies: adapter.PreviousPolicies, ObservationStore: tracker,
	}
	_, predecessor, err = publicationIO.ReadCurrent(context.Background())
	require.ErrorIs(t, err, ErrReadControlRequired, "the shared publication adapter refuses non-genesis state without PreviousControls")
	assert.Equal(t, vault.Predecessor{}, predecessor)
	assertNoTransitionReadPersistence(t, tracker)
}

func TestReadCurrentVerifiesReferencedEnvelopeBeforeObservation(t *testing.T) {
	for _, test := range []struct {
		name      string
		prepare   func(*testing.T, *readFixture)
		want      error
		wantCalls int
	}{
		{
			name: "missing blob",
			prepare: func(_ *testing.T, fixture *readFixture) {
				fixture.transport.blobStatus = 404
			},
			want: ErrReadBlobMissing, wantCalls: 1,
		},
		{
			name: "tampered blob",
			prepare: func(_ *testing.T, fixture *readFixture) {
				fixture.transport.blob = bytes.Clone(fixture.transport.blob)
				fixture.transport.blob[len(fixture.transport.blob)-1] ^= 0xff
			},
			want: ErrReadBlobCIDMismatch, wantCalls: 1,
		},
		{
			name: "unauthorized envelope signature",
			prepare: func(t *testing.T, fixture *readFixture) {
				envelope, err := vault.DecodeEnvelope(fixture.transport.blob)
				require.NoError(t, err)
				envelope.Signature = [ed25519.SignatureSize]byte{}
				unsigned, err := vault.EncodeEnvelope(envelope)
				require.NoError(t, err)
				preimage := append([]byte("dottie/v1/sig"), unsigned[:len(unsigned)-ed25519.SignatureSize]...)
				signature, err := vault.Sign("dottie/v1/sig-snapshot", preimage, fixtureSigningKey(77))
				require.NoError(t, err)
				copy(envelope.Signature[:], signature)
				encoded, err := vault.EncodeEnvelope(envelope)
				require.NoError(t, err)
				snapshot := snapshotRecordForEnvelope(t, envelope, encoded, fixtureSigningKey(12))
				head := signFixtureHead(t, *fixture, encoded, 1, fixtureHeadObject(t, *fixture).PrevHeadCID, publisherSigner(), fixtureSigningKey(12))
				installSnapshot(t, fixture, encoded, snapshot, head)
			},
			want: ErrReadEnvelopeSignature, wantCalls: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReadFixture(t)
			tracker := &transitionObservationTracker{store: fixture.observationStore}
			adapter := transitionReadIO(&fixture, tracker, [][]byte{bytes.Clone(fixture.request.PreviousControl)})
			test.prepare(t, &fixture)
			adapter.Reader.VerificationMethods = fixture.request.VerificationMethods
			_, predecessor, err := adapter.ReadCurrent(context.Background())
			require.ErrorIs(t, err, test.want)
			assert.Equal(t, vault.Predecessor{}, predecessor)
			assert.Equal(t, test.wantCalls, fixture.transport.blobCalls)
			assertNoTransitionReadPersistence(t, tracker)
		})
	}
}

func TestReadCurrentAuthenticatesEnvelopeParentAgainstHeadPredecessor(t *testing.T) {
	fixture := newReadFixture(t)
	previousHeadCID := fixtureSnapshotCID(t, fixture)
	envelopeBytes, snapshot := sealFixtureSnapshot(t, fixture, nil, 0xC4, []byte("hostile parent join"))
	snapshotCID := readRawCID(t, envelopeBytes)
	head := signFixtureHead(t, fixture, envelopeBytes, 2, previousHeadCID, publisherSigner(), fixtureSigningKey(12))
	setTransitionReadControlHead(t, &fixture, snapshotCID)
	installSnapshot(t, &fixture, envelopeBytes, snapshot, head)

	tracker := &transitionObservationTracker{store: fixture.observationStore}
	adapter := transitionReadIO(&fixture, tracker, [][]byte{bytes.Clone(fixture.request.PreviousControl)})
	_, predecessor, err := adapter.ReadCurrent(context.Background())
	require.ErrorIs(t, err, ErrReadHeadEnvelopeLinkage)
	assert.Equal(t, vault.Predecessor{}, predecessor)
	assertNoTransitionReadPersistence(t, tracker)

	positive := newBuilderReadHistory(t).fixture
	positiveTracker := &transitionObservationTracker{store: positive.observationStore}
	positiveAdapter := transitionReadIO(&positive, positiveTracker, [][]byte{bytes.Clone(positive.request.PreviousControl)})
	_, genuine, err := positiveAdapter.ReadCurrent(context.Background())
	require.NoError(t, err, "the PrepareTransition/PreparePublication-built history is accepted")
	genuineHead, err := vault.DecodeHead(genuine.Head)
	require.NoError(t, err)
	genuineEnvelope, err := vault.DecodeEnvelope(positive.transport.blob)
	require.NoError(t, err)
	assert.Equal(t, genuineHead.PrevHeadCID, genuineEnvelope.Parent)
	assert.Equal(t, 1, positiveTracker.calls)
}

func TestReadCurrentAuthenticatesHeadAndEnvelopeSignerJoin(t *testing.T) {
	fixture := newReadFixture(t)
	head := fixtureHeadObject(t, fixture)
	head.Signer = vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")}
	headBytes := signReadHead(t, head, fixtureSigningKey(11))
	signedHead, err := vault.DecodeHead(headBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultHeadNSID, RKey: "self"}, headRecordFromObject(signedHead))
	replaceReadCAR(t, &fixture, fixture.records)

	tracker := &transitionObservationTracker{store: fixture.observationStore}
	adapter := transitionReadIO(&fixture, tracker, [][]byte{bytes.Clone(fixture.request.PreviousControl)})
	_, predecessor, err := adapter.ReadCurrent(context.Background())
	require.ErrorIs(t, err, ErrReadSignerMismatch)
	assert.Equal(t, vault.Predecessor{}, predecessor)
	assertNoTransitionReadPersistence(t, tracker)

	positive := newBuilderReadHistory(t).fixture
	positiveTracker := &transitionObservationTracker{store: positive.observationStore}
	positiveAdapter := transitionReadIO(&positive, positiveTracker, [][]byte{bytes.Clone(positive.request.PreviousControl)})
	_, genuine, err := positiveAdapter.ReadCurrent(context.Background())
	require.NoError(t, err, "the PreparePublication-built head and envelope signer pair reads")
	genuineHead, err := vault.DecodeHead(genuine.Head)
	require.NoError(t, err)
	genuineEnvelope, err := vault.DecodeEnvelope(positive.transport.blob)
	require.NoError(t, err)
	assert.Equal(t, "publisher", genuineHead.Signer.DeviceID)
	assert.Equal(t, genuineEnvelope.DeviceID, genuineHead.Signer.DeviceID)
	assert.Equal(t, genuineEnvelope.KeyID, genuineHead.Signer.KeyID)
	assert.Equal(t, 1, positiveTracker.calls)
}

func TestReadCurrentAuthenticatesControlPredecessorEpoch(t *testing.T) {
	fixture, genuinePreviousControl, wrongPreviousControl := readCurrentEpochTwoBuilderFixture(t)
	currentControlRecord, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	currentControl := controlFromRecord(currentControlRecord.(ControlRecord))
	wrongPreviousRecord, err := DecodeRecord(wrongPreviousControl)
	require.NoError(t, err)
	wrongPreviousBytes, err := vault.EncodeControl(controlFromRecord(wrongPreviousRecord.(ControlRecord)))
	require.NoError(t, err)
	currentControl.PrevControlCID = readRawCID(t, wrongPreviousBytes)
	currentControlBytes := signReadControl(t, currentControl, fixtureSigningKey(11))
	currentControl, err = vault.DecodeControl(currentControlBytes)
	require.NoError(t, err)
	installControl(t, &fixture, controlRecordFromObject(currentControl))
	tracker := &transitionObservationTracker{store: fixture.observationStore}
	adapter := transitionReadIO(&fixture, tracker, [][]byte{wrongPreviousControl})
	_, predecessor, err := adapter.ReadCurrent(context.Background())
	require.ErrorIs(t, err, ErrReadControlEpoch)
	assert.Equal(t, vault.Predecessor{}, predecessor)
	assertNoTransitionReadPersistence(t, tracker)

	positive, genuinePreviousControl, _ := readCurrentEpochTwoBuilderFixture(t)
	positiveTracker := &transitionObservationTracker{store: positive.observationStore}
	positiveAdapter := transitionReadIO(&positive, positiveTracker, [][]byte{genuinePreviousControl})
	_, genuine, err := positiveAdapter.ReadCurrent(context.Background())
	require.NoError(t, err, "the PrepareTransition/PreparePublication-built epoch predecessor control reads")
	assert.Equal(t, uint64(2), genuine.EpochSeq)
	assert.Equal(t, 1, positiveTracker.calls)
}

func setTransitionReadControlHead(t *testing.T, fixture *readFixture, snapshotCID []byte) {
	t.Helper()
	key := RecordKey{Collection: VaultControlNSID, RKey: "self"}
	decoded, err := DecodeRecord(fixture.records[key])
	require.NoError(t, err)
	control := controlFromRecord(decoded.(ControlRecord))
	control.HeadSnapshotCID = bytes.Clone(snapshotCID)
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	control, err = vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	installControl(t, fixture, controlRecordFromObject(control))
}
