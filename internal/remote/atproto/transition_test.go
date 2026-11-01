package atproto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type transitionApplyTransport struct {
	calls int
	body  []byte
}

func (transport *transitionApplyTransport) Do(_ context.Context, method, endpoint string, _ url.Values, body []byte, _ string) (int, []byte, error) {
	transport.calls++
	if method != "POST" || endpoint != "com.atproto.repo.applyWrites" {
		return 0, nil, fmt.Errorf("unexpected request %s %s", method, endpoint)
	}
	transport.body = bytes.Clone(body)
	return 200, []byte(`{"commit":{"cid":"bafybeigdyrzt5sfp7udm7hu76uhy26nfjpy2ytma2if42f2qht6lmtkq3u"}}`), nil
}

func (*transitionApplyTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("unexpected stream request")
}

type transitionTestFixture struct {
	root        vault.DeviceMaterial
	predecessor vault.Predecessor
}

type transitionTestStore struct {
	attempts map[string]state.TransitionAttempt
}

func newTransitionTestStore() *transitionTestStore {
	return &transitionTestStore{attempts: make(map[string]state.TransitionAttempt)}
}

func (s *transitionTestStore) BeginTransitionAttempt(_ context.Context, attempt state.TransitionAttempt) error {
	if _, exists := s.attempts[attempt.ID]; exists {
		return errors.New("duplicate transition attempt")
	}
	s.attempts[attempt.ID] = attempt
	return nil
}

func (s *transitionTestStore) UpdateTransitionAttempt(_ context.Context, id, outcome, evidence string) error {
	attempt, exists := s.attempts[id]
	if !exists {
		return errors.New("transition attempt is absent")
	}
	attempt.Outcome = outcome
	attempt.Evidence = evidence
	s.attempts[id] = attempt
	return nil
}

func (s *transitionTestStore) TransitionAttempt(_ context.Context, id string) (state.TransitionAttempt, error) {
	attempt, exists := s.attempts[id]
	if !exists {
		return state.TransitionAttempt{}, errors.New("transition attempt is absent")
	}
	return attempt, nil
}

func (s *transitionTestStore) TransitionAttempts(_ context.Context) ([]state.TransitionAttempt, error) {
	attempts := make([]state.TransitionAttempt, 0, len(s.attempts))
	for _, attempt := range s.attempts {
		attempts = append(attempts, attempt)
	}
	return attempts, nil
}

type transitionTestIO struct {
	predecessors      []vault.Predecessor
	readErrors        map[int]error
	readCount         int
	stageCount        int
	applyCount        int
	applyErrors       []error
	resolution        string
	publicationWrites [][]RecordWrite
	latestRevision    *Revision
}

func (io *transitionTestIO) ReadCurrent(_ context.Context) (*Revision, vault.Predecessor, error) {
	io.readCount++
	if err := io.readErrors[io.readCount]; err != nil {
		return nil, vault.Predecessor{}, err
	}
	index := io.readCount - 1
	if index >= len(io.predecessors) {
		index = len(io.predecessors) - 1
	}
	if index < 0 {
		return nil, vault.Predecessor{}, errors.New("no predecessor configured")
	}
	revision := cloneTransitionTestRevision(io.latestRevision)
	if revision == nil {
		revision = transitionTestRevision()
	}
	return revision, io.predecessors[index], nil
}

func (io *transitionTestIO) StageCandidate(_ context.Context, data []byte) (json.RawMessage, string, error) {
	io.stageCount++
	blobCID := cid.NewCidV1(cid.Raw, mustTransitionMultihash(data))
	reference, err := json.Marshal(map[string]any{
		"$type": "blob", "ref": map[string]string{"$link": blobCID.String()},
		"mimeType": "application/octet-stream", "size": len(data),
	})
	return reference, blobCID.String(), err
}

func (io *transitionTestIO) ApplyTransition(_ context.Context, revision *Revision, publication FencedPublication) error {
	io.applyCount++
	writes := []RecordWrite{publication.FirstBlobReference, publication.VaultHead, publication.VaultControl}
	writes = append(writes, publication.Additional...)
	io.publicationWrites = append(io.publicationWrites, writes)
	if io.applyCount <= len(io.applyErrors) && io.applyErrors[io.applyCount-1] != nil {
		io.latestRevision = transitionResolutionRevision(publication, io.resolution)
		return io.applyErrors[io.applyCount-1]
	}
	io.latestRevision = transitionResolutionRevision(publication, "committed")
	return nil
}

func transitionResolutionRevision(publication FencedPublication, resolution string) *Revision {
	revision := transitionTestRevision()
	if resolution == "unavailable" {
		return revision
	}
	if resolution == "committed" || resolution == "superseded" {
		markerCID, _ := recordCIDText(publication.FirstBlobReference.Record)
		revision.membership[RecordKey{Collection: VaultSnapshotNSID, RKey: publication.FirstBlobReference.RKey}] = markerCID
	}
	if resolution == "committed" {
		revision.membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}], _ = recordCIDText(publication.VaultHead.Record)
		revision.membership[RecordKey{Collection: VaultControlNSID, RKey: "self"}], _ = recordCIDText(publication.VaultControl.Record)
	}
	if resolution == "superseded" {
		revision.membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}] = "superseding-head"
		revision.membership[RecordKey{Collection: VaultControlNSID, RKey: "self"}] = "superseding-control"
	}
	return revision
}

func newTransitionTestFixture(t *testing.T) transitionTestFixture {
	t.Helper()
	kit := bytes.Repeat([]byte{41}, 32)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	root := vault.DeviceMaterial{DeviceID: "root-device", KeyID: []byte("root-key"), Signing: signing, Recipient: recipient}
	bootstrap, err := vault.Bootstrap(kit, "transition-test", root)
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(bootstrap.Policy)
	require.NoError(t, err)
	controlCID := cid.NewCidV1(cid.Raw, mustTransitionMultihash(bootstrap.Control)).Bytes()
	return transitionTestFixture{
		root: root,
		predecessor: vault.Predecessor{
			ControlCID: controlCID, PolicyDigest: policyDigest, EpochSeq: 0,
			Control: bootstrap.Control, Policy: bootstrap.Policy,
			Certificates: [][]byte{bootstrap.Certificate}, TrustAnchor: bootstrap.Anchor,
		},
	}
}

func prepareTransitionTestBundle(t *testing.T, fixture transitionTestFixture, id byte) vault.Transition {
	t.Helper()
	newSigning, newRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	newDevice := vault.DeviceMaterial{DeviceID: fmt.Sprintf("publisher-%d", id), KeyID: []byte(fmt.Sprintf("publisher-key-%d", id)), Signing: newSigning, Recipient: newRecipient}
	rootEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	newEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var contentKey [32]byte
	_, err = rand.Read(contentKey[:])
	require.NoError(t, err)
	var publicationID [16]byte
	publicationID[0] = id
	var nonce [24]byte
	nonce[0] = id + 1
	transition, err := vault.PrepareTransition(fixture.predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: mustTestVault(t, fixture.predecessor), Signer: fixture.root,
		NewDevice: &newDevice, RequestedRole: vault.RolePublisher, ContentKey: contentKey[:],
		Recipients: [][]byte{fixture.predecessor.Certificates[0]},
		Wraps: []vault.RecipientWrapInput{
			{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(rootEphemeral.Bytes())},
			{KeyID: bytes.Clone(newDevice.KeyID), EphemeralPrivate: [32]byte(newEphemeral.Bytes())},
		},
		Plaintext: []byte("synthetic transition payload"), PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	return transition
}

func mustTestVault(t *testing.T, predecessor vault.Predecessor) [32]byte {
	t.Helper()
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	return policy.Vault
}

func transitionTestRevision() *Revision {
	commit := cid.NewCidV1(cid.Raw, mustTransitionMultihash([]byte("verified test commit"))).String()
	return &Revision{did: proofTestDID, commitCID: commit, membership: make(map[RecordKey]string), records: make(map[RecordKey]ProvenRecord)}
}

func cloneTransitionTestRevision(revision *Revision) *Revision {
	if revision == nil {
		return nil
	}
	return &Revision{did: revision.did, commitCID: revision.commitCID, membership: revision.Membership(), records: revision.Records()}
}

func newTransitionTestIO(predecessors ...vault.Predecessor) *transitionTestIO {
	return &transitionTestIO{predecessors: predecessors, readErrors: make(map[int]error), resolution: "committed"}
}

func transitionPredecessorAfter(t *testing.T, predecessor vault.Predecessor, transition vault.Transition) vault.Predecessor {
	t.Helper()
	policyDigest, err := vault.ComputePolicyDigest(transition.Policy)
	require.NoError(t, err)
	head, err := vault.DecodeHead(transition.Head)
	require.NoError(t, err)
	return vault.Predecessor{
		ControlCID: rawTransitionCID(transition.Control), PolicyDigest: policyDigest, EpochSeq: head.EpochSeq,
		HeadCID: bytes.Clone(head.SnapshotCID), Head: bytes.Clone(transition.Head), Control: bytes.Clone(transition.Control),
		Policy: bytes.Clone(transition.Policy), Certificates: cloneTransitionCertificates(transition.Recipients), TrustAnchor: predecessor.TrustAnchor,
	}
}

func cloneTransitionCertificates(certificates [][]byte) [][]byte {
	result := make([][]byte, len(certificates))
	for index := range certificates {
		result[index] = bytes.Clone(certificates[index])
	}
	return result
}

func prepareRevocationTestBundle(t *testing.T, fixture transitionTestFixture, id byte) (vault.Predecessor, vault.Transition) {
	t.Helper()
	enrollment := prepareTransitionTestBundle(t, fixture, id)
	predecessor := transitionPredecessorAfter(t, fixture.predecessor, enrollment)
	var rootCertificate []byte
	var revokedDevice string
	for _, encoded := range enrollment.Recipients {
		certificate, err := vault.DecodeCertificate(encoded)
		require.NoError(t, err)
		if certificate.DeviceID == fixture.root.DeviceID {
			rootCertificate = bytes.Clone(encoded)
		} else {
			revokedDevice = certificate.DeviceID
		}
	}
	require.NotEmpty(t, rootCertificate)
	require.NotEmpty(t, revokedDevice)
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var ephemeralPrivate [32]byte
	copy(ephemeralPrivate[:], ephemeral.Bytes())
	var wrapNonce [24]byte
	_, err = rand.Read(wrapNonce[:])
	require.NoError(t, err)
	var contentKey [32]byte
	_, err = rand.Read(contentKey[:])
	require.NoError(t, err)
	var publicationID [16]byte
	_, err = rand.Read(publicationID[:])
	require.NoError(t, err)
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionRevoke, Vault: mustTestVault(t, predecessor), Signer: fixture.root, RevokeDeviceID: revokedDevice,
		ContentKey: contentKey[:], Recipients: [][]byte{rootCertificate},
		Wraps:     []vault.RecipientWrapInput{{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: ephemeralPrivate, WrapNonce: wrapNonce}},
		Plaintext: []byte("complete current snapshot for revocation"), PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	return predecessor, transition
}

func TestCommitTransitionRejectsBundleStaleAtFinalRevalidation(t *testing.T) {
	fixture := newTransitionTestFixture(t)
	bundle := prepareTransitionTestBundle(t, fixture, 1)
	competingBundle := prepareTransitionTestBundle(t, fixture, 2)
	stale := transitionPredecessorAfter(t, fixture.predecessor, competingBundle)
	io := newTransitionTestIO(fixture.predecessor, stale)
	store := newTransitionTestStore()
	result, err := CommitTransition(context.Background(), io, store, bundle, fixture.root.Signing, time.Unix(100, 0))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.ErrorIs(t, err, ErrPreparedPolicyMismatch)
	assert.NotEqual(t, TransitionOutcome(TransitionOutcomeCommitted), result.Outcome)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 0, io.applyCount)
	attempt, lookupErr := store.TransitionAttempt(context.Background(), result.AttemptID)
	require.NoError(t, lookupErr)
	assert.Equal(t, TransitionOutcomeNotLanded, attempt.Outcome)
}

func TestCommitTransitionLostFenceRequiresDiscardAndFreshPreparation(t *testing.T) {
	fixture := newTransitionTestFixture(t)
	first := prepareTransitionTestBundle(t, fixture, 1)
	io := newTransitionTestIO(fixture.predecessor)
	io.applyErrors = []error{ErrFenceLost, nil}
	io.resolution = "not-landed"
	store := newTransitionTestStore()
	firstResult, firstErr := CommitTransition(context.Background(), io, store, first, fixture.root.Signing, time.Unix(100, 0))
	require.ErrorIs(t, firstErr, ErrFenceLost)
	assert.ErrorIs(t, firstErr, ErrTransitionDiscarded)
	assert.NotErrorIs(t, firstErr, ErrCandidateMayBeDisclosed)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeFenceLost), firstResult.Outcome)
	var fenceError *TransitionFenceLostError
	require.ErrorAs(t, firstErr, &fenceError)
	assert.Equal(t, firstResult, fenceError.Result)
	require.NotNil(t, firstResult.Predecessor)
	assert.Equal(t, 3, io.readCount, "fence loss must be followed by one fresh verified read")
	fixture.predecessor = *firstResult.Predecessor
	second := prepareTransitionTestBundle(t, fixture, 2)
	require.NotEqual(t, first.Digest, second.Digest)
	secondResult, secondErr := CommitTransition(context.Background(), io, store, second, fixture.root.Signing, time.Unix(101, 0))
	require.NoError(t, secondErr)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), secondResult.Outcome)
	assert.Equal(t, 2, io.applyCount)
	assert.Equal(t, 2, io.stageCount)
	assert.NotEqual(t, firstResult.Marker, secondResult.Marker)
}

func TestCommitTransitionFiveHundredDoesNotResendAndSignalsDisclosure(t *testing.T) {
	fixture := newTransitionTestFixture(t)
	bundle := prepareTransitionTestBundle(t, fixture, 3)
	io := newTransitionTestIO(fixture.predecessor)
	io.applyErrors = []error{fmt.Errorf("HTTP 503: %w", ErrAmbiguousTransport)}
	io.resolution = "not-landed"
	store := newTransitionTestStore()
	result, err := CommitTransition(context.Background(), io, store, bundle, fixture.root.Signing, time.Unix(102, 0))
	require.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.ErrorIs(t, err, ErrTransitionNotLanded)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeNotLanded), result.Outcome)
	assert.Equal(t, 1, io.applyCount)
	assert.Equal(t, 1, io.stageCount)
}

func TestCommitTransitionResolvesUnknownOutcome(t *testing.T) {
	for _, test := range []struct {
		name       string
		resolution string
		readError  error
		want       TransitionOutcome
		wantError  error
	}{
		{name: "committed", resolution: "committed", want: TransitionOutcomeCommitted},
		{name: "committed but superseded", resolution: "superseded", want: TransitionOutcomeSuperseded, wantError: ErrTransitionSuperseded},
		{name: "not landed", resolution: "not-landed", want: TransitionOutcomeNotLanded, wantError: ErrTransitionNotLanded},
		{name: "unavailable", resolution: "unavailable", readError: errors.New("verified read unavailable"), want: TransitionOutcomeUnavailable, wantError: ErrTransitionUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTransitionTestFixture(t)
			bundle := prepareTransitionTestBundle(t, fixture, byte(len(test.name)))
			io := newTransitionTestIO(fixture.predecessor)
			io.applyErrors = []error{ErrAmbiguousTransport}
			io.resolution = test.resolution
			if test.readError != nil {
				io.readErrors[3] = test.readError
			}
			store := newTransitionTestStore()
			result, err := CommitTransition(context.Background(), io, store, bundle, fixture.root.Signing, time.Unix(103, 0))
			assert.Equal(t, test.want, result.Outcome)
			if test.wantError == nil {
				assert.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.wantError)
				assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
			}
			assert.Equal(t, 1, io.applyCount)
		})
	}
}

func TestResolveTransitionAttemptAfterUploadCrashDoesNotResend(t *testing.T) {
	fixture := newTransitionTestFixture(t)
	bundle := prepareTransitionTestBundle(t, fixture, 4)
	io := newTransitionTestIO(fixture.predecessor)
	io.readErrors[2] = errors.New("simulated process loss after blob upload")
	store := newTransitionTestStore()
	failed, err := CommitTransition(context.Background(), io, store, bundle, fixture.root.Signing, time.Unix(104, 0))
	require.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.Equal(t, 0, io.applyCount)
	reopened := newTransitionTestStore()
	reopened.attempts = make(map[string]state.TransitionAttempt, len(store.attempts))
	for id, attempt := range store.attempts {
		reopened.attempts[id] = attempt
	}
	io.readErrors = make(map[int]error)
	io.latestRevision = transitionTestRevision()
	resolved, resolveErr := ResolveTransitionAttempt(context.Background(), io, reopened, failed.AttemptID)
	require.ErrorIs(t, resolveErr, ErrTransitionNotLanded)
	assert.ErrorIs(t, resolveErr, ErrCandidateMayBeDisclosed)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeNotLanded), resolved.Outcome)
	assert.Equal(t, 0, io.applyCount)
}

func TestCommitRevocationWritesSnapshotHeadControlAndPolicyWithoutCertificate(t *testing.T) {
	fixture := newTransitionTestFixture(t)
	predecessor, revocation := prepareRevocationTestBundle(t, fixture, 61)
	policy, err := vault.DecodePolicy(revocation.Policy)
	require.NoError(t, err)
	io := newTransitionTestIO(predecessor)
	store := newTransitionTestStore()
	result, commitErr := CommitTransition(context.Background(), io, store, revocation, fixture.root.Signing, time.Unix(160, 0))
	require.NoError(t, commitErr)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), result.Outcome)
	require.Len(t, io.publicationWrites, 1)
	require.Len(t, io.publicationWrites[0], 4)
	collections := make(map[string]bool)
	for _, write := range io.publicationWrites[0] {
		collections[write.Collection] = true
	}
	for _, collection := range []string{VaultSnapshotNSID, VaultHeadNSID, VaultControlNSID, VaultPolicyNSID} {
		assert.True(t, collections[collection], "revocation omitted %s", collection)
	}
	assert.False(t, collections[VaultCertificateNSID])
	assert.Len(t, policy.Recipients, 1)
}

func TestCommitTransitionSubmitsCompleteWriteSetOnce(t *testing.T) {
	fixture := newTransitionTestFixture(t)
	bundle := prepareTransitionTestBundle(t, fixture, 5)
	io := newTransitionTestIO(fixture.predecessor)
	store := newTransitionTestStore()
	result, err := CommitTransition(context.Background(), io, store, bundle, fixture.root.Signing, time.Unix(105, 0))
	require.NoError(t, err)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), result.Outcome)
	assert.Equal(t, 1, io.applyCount)
	require.Len(t, io.publicationWrites, 1)
	require.Len(t, io.publicationWrites[0], 5)
	collections := make(map[string]bool)
	for _, write := range io.publicationWrites[0] {
		collections[write.Collection] = true
		var record map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(write.Record, &record))
		require.Contains(t, record, "$type")
		var typeID string
		require.NoError(t, json.Unmarshal(record["$type"], &typeID))
		assert.Equal(t, write.Collection, typeID, "write record lexicon type must match its collection")
	}
	for _, collection := range []string{VaultSnapshotNSID, VaultHeadNSID, VaultControlNSID, VaultPolicyNSID, VaultCertificateNSID} {
		assert.True(t, collections[collection], "write set omitted %s", collection)
	}
	assert.Equal(t, 1, io.stageCount)

	verifiedRevision := transitionTestRevision()
	blobReference := blobJSONFromCID(bundle.SnapshotCID, len(bundle.Snapshot))
	publication, err := transitionPublication(bundle, fixture.root.Signing, blobReference, verifiedRevision)
	require.NoError(t, err)
	transport := &transitionApplyTransport{}
	writer := ATProtoTransitionIO{Transport: transport}
	require.NoError(t, writer.ApplyTransition(context.Background(), verifiedRevision, publication))
	assert.Equal(t, 1, transport.calls)
	var input applyWritesInput
	require.NoError(t, json.Unmarshal(transport.body, &input))
	assert.Equal(t, verifiedRevision.CommitCID(), input.SwapCommit)
	assert.Len(t, input.Writes, 5)
}
