package atproto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

type publicationTestIO struct {
	predecessors []vault.Predecessor
	readCount    int
	stageCount   int
	applyCount   int
	publication  []FencedSnapshotPublication
	latest       *Revision
	applyError   error
}

func (io *publicationTestIO) ReadCurrent(context.Context) (*Revision, vault.Predecessor, error) {
	index := io.readCount
	io.readCount++
	if index >= len(io.predecessors) {
		index = len(io.predecessors) - 1
	}
	if index < 0 {
		return nil, vault.Predecessor{}, errors.New("no publication predecessor configured")
	}
	revision := cloneTransitionTestRevision(io.latest)
	if revision == nil {
		revision = publicationTestRevision()
	}
	return revision, io.predecessors[index], nil
}

func (io *publicationTestIO) StageCandidate(_ context.Context, data []byte) (json.RawMessage, string, error) {
	io.stageCount++
	cidText := cid.NewCidV1(cid.Raw, mustTransitionMultihash(data)).String()
	blob, err := json.Marshal(atdata.Blob{Ref: atdata.CIDLink(cid.NewCidV1(cid.Raw, mustTransitionMultihash(data))), MimeType: "application/octet-stream", Size: int64(len(data))})
	return blob, cidText, err
}

func (io *publicationTestIO) ApplyPublication(_ context.Context, _ *Revision, publication FencedSnapshotPublication) error {
	io.applyCount++
	io.publication = append(io.publication, publication)
	if io.applyError != nil {
		return io.applyError
	}
	io.latest = publicationResolutionRevision(publication)
	return nil
}

func publicationResolutionRevision(publication FencedSnapshotPublication) *Revision {
	revision := publicationTestRevision()
	markerCID, _ := recordCIDText(publication.SnapshotReference.Record)
	headCID, _ := recordCIDText(publication.VaultHead.Record)
	revision.membership[RecordKey{Collection: VaultSnapshotNSID, RKey: publication.SnapshotReference.RKey}] = markerCID
	revision.membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}] = headCID
	return revision
}

func publicationTestRevision() *Revision {
	revision := transitionTestRevision()
	revision.membership[RecordKey{Collection: VaultHeadNSID, RKey: "self"}] = "prior-head-record"
	return revision
}

func newAtprotoPublicationFixture(t *testing.T) (vault.DeviceMaterial, vault.DeviceMaterial, vault.Predecessor, vault.Publication) {
	t.Helper()
	fixture := newTransitionTestFixture(t)
	publisherSigning, publisherRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	publisher := vault.DeviceMaterial{DeviceID: "publication-device", KeyID: []byte("publication-key"), Signing: publisherSigning, Recipient: publisherRecipient}
	enrollment, err := vault.PrepareTransition(fixture.predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: mustTestVault(t, fixture.predecessor), Signer: fixture.root,
		NewDevice: &publisher, RequestedRole: vault.RolePublisher, ContentKey: publicationTestBytes(t, 32),
		Recipients: fixture.predecessor.Certificates, Wraps: publicationTestWrapsForKeyIDs(t, [][]byte{fixture.root.KeyID, publisher.KeyID}),
		Plaintext: []byte("publication baseline"), PublicationID: [16]byte(publicationTestBytes(t, 16)), Nonce: [24]byte(publicationTestBytes(t, 24)),
	})
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(enrollment.Policy)
	require.NoError(t, err)
	controlCID := rawTransitionCID(enrollment.Control)
	head, err := vault.DecodeHead(enrollment.Head)
	require.NoError(t, err)
	predecessor := vault.Predecessor{
		ControlCID: controlCID, PolicyDigest: policyDigest, EpochSeq: head.EpochSeq,
		HeadCID: bytes.Clone(head.SnapshotCID), Head: bytes.Clone(enrollment.Head), Control: bytes.Clone(enrollment.Control),
		Policy: bytes.Clone(enrollment.Policy), Certificates: clonePublicationByteSlices(enrollment.Recipients), TrustAnchor: fixture.predecessor.TrustAnchor,
	}
	publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
		Vault: mustTestVault(t, predecessor), Signer: publisher, ContentKey: publicationTestBytes(t, 32),
		Wraps: publicationTestWraps(t, predecessor.Certificates), Plaintext: []byte("published pack"),
		PublicationID: [16]byte(publicationTestBytes(t, 16)), Nonce: [24]byte(publicationTestBytes(t, 24)),
	})
	require.NoError(t, err)
	return fixture.root, publisher, predecessor, publication
}

func prepareAtprotoRevocation(t *testing.T, root, target vault.DeviceMaterial, predecessor vault.Predecessor) vault.Transition {
	t.Helper()
	activeRecipients := make([][]byte, 0, len(predecessor.Certificates)-1)
	for _, encoded := range predecessor.Certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		require.NoError(t, err)
		if certificate.DeviceID != target.DeviceID {
			activeRecipients = append(activeRecipients, bytes.Clone(encoded))
		}
	}
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionRevoke, Vault: mustTestVault(t, predecessor), Signer: root, RevokeDeviceID: target.DeviceID,
		ContentKey: publicationTestBytes(t, 32), Recipients: activeRecipients, Wraps: publicationTestWraps(t, activeRecipients),
		Plaintext: []byte("complete current state"), PublicationID: [16]byte(publicationTestBytes(t, 16)), Nonce: [24]byte(publicationTestBytes(t, 24)),
	})
	require.NoError(t, err)
	return transition
}

func publicationTestWraps(t *testing.T, certificates [][]byte) []vault.RecipientWrapInput {
	t.Helper()
	keyIDs := make([][]byte, 0, len(certificates))
	for _, encoded := range certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		require.NoError(t, err)
		keyIDs = append(keyIDs, certificate.KeyID)
	}
	return publicationTestWrapsForKeyIDs(t, keyIDs)
}

func publicationTestWrapsForKeyIDs(t *testing.T, keyIDs [][]byte) []vault.RecipientWrapInput {
	t.Helper()
	wraps := make([]vault.RecipientWrapInput, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		var privateBytes [32]byte
		copy(privateBytes[:], private.Bytes())
		var nonce [24]byte
		_, err = rand.Read(nonce[:])
		require.NoError(t, err)
		wraps = append(wraps, vault.RecipientWrapInput{KeyID: bytes.Clone(keyID), EphemeralPrivate: privateBytes, WrapNonce: nonce})
	}
	return wraps
}

func clonePublicationByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func publicationTestBytes(t *testing.T, size int) []byte {
	t.Helper()
	result := make([]byte, size)
	_, err := rand.Read(result)
	require.NoError(t, err)
	return result
}

func validPublication(blobCID string) FencedPublication {
	snapshot := json.RawMessage(fmt.Sprintf(`{"$type":"systems.lamb.dottie.vaultSnapshot","probe":"one","blob":{"$type":"blob","ref":{"$link":%q},"mimeType":"application/octet-stream","size":7}}`, blobCID))
	return FencedPublication{
		FirstBlobReference: RecordWrite{Action: RecordCreate, Collection: "systems.lamb.dottie.vaultSnapshot", RKey: "probe-one", Record: snapshot},
		VaultHead:          RecordWrite{Action: RecordUpdate, Collection: "systems.lamb.dottie.vaultHead", RKey: "self", Record: json.RawMessage(`{"$type":"systems.lamb.dottie.vaultHead","snapshotRkey":"probe-one"}`)},
		VaultControl:       RecordWrite{Action: RecordUpdate, Collection: "systems.lamb.dottie.vaultControl", RKey: "self", Record: json.RawMessage(`{"$type":"systems.lamb.dottie.vaultControl","devices":[],"policyEpoch":1}`)},
	}
}

func TestCommitPublicationUsesPublisherAndWritesSnapshotAndHeadOnly(t *testing.T) {
	_, publisher, predecessor, publication := newAtprotoPublicationFixture(t)
	io := &publicationTestIO{predecessors: []vault.Predecessor{predecessor}}
	store := newTransitionTestStore()
	result, err := CommitPublication(context.Background(), io, store, publication, publisher.Signing, time.Unix(200, 0))
	require.NoError(t, err)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), result.Outcome)
	assert.Equal(t, 1, io.stageCount)
	assert.Equal(t, 1, io.applyCount)
	require.Len(t, io.publication, 1)
	assert.NotEmpty(t, result.Marker.RKey)
	require.Equal(t, 2, len([]RecordWrite{io.publication[0].SnapshotReference, io.publication[0].VaultHead}))
	assert.Equal(t, VaultSnapshotNSID, io.publication[0].SnapshotReference.Collection)
	assert.Equal(t, VaultHeadNSID, io.publication[0].VaultHead.Collection)
	assert.NotEqual(t, VaultControlNSID, io.publication[0].SnapshotReference.Collection)
	assert.NotEqual(t, VaultControlNSID, io.publication[0].VaultHead.Collection)
}

func TestCommitPublicationRejectsSigningKeyOutsideCandidateCertificate(t *testing.T) {
	root, _, predecessor, publication := newAtprotoPublicationFixture(t)
	io := &publicationTestIO{predecessors: []vault.Predecessor{predecessor}}
	_, err := CommitPublication(context.Background(), io, newTransitionTestStore(), publication, root.Signing, time.Unix(202, 0))
	require.ErrorIs(t, err, ErrBatchRejected)
	assert.Zero(t, io.stageCount)
}

func TestCommitPublicationRejectsCandidateAfterPolicyChange(t *testing.T) {
	root, publisher, predecessor, publication := newAtprotoPublicationFixture(t)
	competingTransition := prepareAtprotoRevocation(t, root, publisher, predecessor)
	changed := transitionPredecessorAfter(t, predecessor, competingTransition)
	io := &publicationTestIO{predecessors: []vault.Predecessor{predecessor, changed}}
	store := newTransitionTestStore()
	result, err := CommitPublication(context.Background(), io, store, publication, publisher.Signing, time.Unix(201, 0))
	require.ErrorIs(t, err, ErrPreparedPolicyMismatch)
	assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeNotLanded), result.Outcome)
	assert.Equal(t, 1, io.stageCount)
	assert.Zero(t, io.applyCount)
}

func TestResolvePublicationAttemptUsesMarkerAndHeadWithoutControl(t *testing.T) {
	_, publisher, predecessor, publication := newAtprotoPublicationFixture(t)
	revision := publicationTestRevision()
	fenced, err := snapshotPublication(publication, publisher.Signing, blobJSONFromCID(publication.SnapshotCID, len(publication.Snapshot)), revision, predecessor)
	require.NoError(t, err)
	markerCID, err := recordCIDText(fenced.SnapshotReference.Record)
	require.NoError(t, err)
	headCID, err := recordCIDText(fenced.VaultHead.Record)
	require.NoError(t, err)
	evidence, err := json.Marshal(publicationAttemptEvidence{Version: 1, Kind: "publication", HeadRecordCID: headCID, PreparedRevision: revision.CommitCID()})
	require.NoError(t, err)
	attempt := state.TransitionAttempt{
		ID: "publication-attempt", MarkerCollection: VaultSnapshotNSID, MarkerRKey: fenced.SnapshotReference.RKey,
		ExpectedRecordCID: markerCID, CandidateBlobCID: cid.NewCidV1(cid.Raw, mustTransitionMultihash(publication.Snapshot)).String(),
		EpochSeq: publication.Predecessor.EpochSeq, PolicyDigest: hex.EncodeToString(publication.PolicyDigest[:]),
		Outcome: TransitionOutcomePrepared, Evidence: string(evidence), CreatedAt: 100,
	}
	store := newTransitionTestStore()
	require.NoError(t, store.BeginTransitionAttempt(context.Background(), attempt))
	require.NoError(t, store.UpdateTransitionAttempt(context.Background(), attempt.ID, TransitionOutcomeStaged, string(evidence)))
	require.NoError(t, store.UpdateTransitionAttempt(context.Background(), attempt.ID, TransitionOutcomeSubmitted, string(evidence)))
	io := &publicationTestIO{predecessors: []vault.Predecessor{predecessor}, latest: publicationResolutionRevision(fenced)}
	result, err := ResolvePublicationAttempt(context.Background(), io, store, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), result.Outcome)
	assert.Zero(t, io.applyCount)
}

func TestPublishSnapshotFencedKeepsAllPackReferencesInsideOneBatch(t *testing.T) {
	_, publisher, predecessor, publication := newAtprotoPublicationFixture(t)
	revision := publicationTestRevision()
	fenced, err := snapshotPublication(publication, publisher.Signing, blobJSONFromCID(publication.SnapshotCID, len(publication.Snapshot)), revision, predecessor)
	require.NoError(t, err)
	transport := &transitionApplyTransport{}
	_, err = PublishSnapshotFenced(context.Background(), transport, revision, fenced)
	require.NoError(t, err)
	var input struct {
		SwapCommit string `json:"swapCommit"`
		Writes     []struct {
			Collection string          `json:"collection"`
			RKey       string          `json:"rkey"`
			Value      json.RawMessage `json:"value"`
		} `json:"writes"`
	}
	require.NoError(t, json.Unmarshal(transport.body, &input))
	assert.Equal(t, revision.CommitCID(), input.SwapCommit)
	require.Len(t, input.Writes, 2)
	collections := []string{input.Writes[0].Collection, input.Writes[1].Collection}
	assert.Contains(t, collections, VaultSnapshotNSID)
	assert.Contains(t, collections, VaultHeadNSID)
	assert.NotContains(t, collections, VaultControlNSID)
	var snapshot SnapshotRecord
	var head HeadRecord
	for _, write := range input.Writes {
		if write.Collection == VaultSnapshotNSID {
			require.NoError(t, json.Unmarshal(write.Value, &snapshot))
		}
		if write.Collection == VaultHeadNSID {
			require.NoError(t, json.Unmarshal(write.Value, &head))
		}
	}
	assert.Equal(t, cid.Cid(snapshot.Blob.Ref).Bytes(), head.SnapshotCID)
	assert.Equal(t, cid.Cid(snapshot.Blob.Ref).Bytes(), head.BlobCID)
	assert.Equal(t, predecessor.PolicyDigest[:], head.PolicyDigest)
}

func TestPublishSnapshotFencedRejectsHeadReferenceOutsideSnapshot(t *testing.T) {
	_, publisher, predecessor, publication := newAtprotoPublicationFixture(t)
	revision := publicationTestRevision()
	fenced, err := snapshotPublication(publication, publisher.Signing, blobJSONFromCID(publication.SnapshotCID, len(publication.Snapshot)), revision, predecessor)
	require.NoError(t, err)
	var head HeadRecord
	require.NoError(t, json.Unmarshal(fenced.VaultHead.Record, &head))
	head.SnapshotCID = []byte("different snapshot")
	fenced.VaultHead.Record, err = json.Marshal(head)
	require.NoError(t, err)
	transport := &transitionApplyTransport{}
	_, err = PublishSnapshotFenced(context.Background(), transport, revision, fenced)
	require.ErrorIs(t, err, ErrBatchRejected)
	assert.Zero(t, transport.calls)
}

func TestPublishFencedAlwaysEncodesSwapCommit(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	transport := &proofTransport{doStatus: 200, doBody: []byte(`{"commit":{"cid":"bafybeigdyrzt5sfp7udm7hu76uhy26nfjpy2ytma2if42f2qht6lmtkq3u"}}`)}
	_, err := PublishFenced(context.Background(), transport, &Revision{did: proofTestDID, commitCID: fixture.root.String()}, validPublication(fixture.root.String()))
	if err != nil {
		require.NoError(t, err)
	}
	if transport.requestMethod != "POST" || transport.requestPath != "com.atproto.repo.applyWrites" {
		require.False(t, transport.requestMethod != "POST" || transport.requestPath != "com.atproto.repo.applyWrites", "applyWrites request=%s %s", transport.requestMethod, transport.requestPath)
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(transport.requestBody, &input); err != nil {
		require.NoError(t, err)
	}
	var swapCommit string
	raw, ok := input["swapCommit"]
	require.True(t, ok, "encoded applyWrites input omitted or changed swapCommit: %s", transport.requestBody)
	require.NoError(t, json.Unmarshal(raw, &swapCommit), "encoded applyWrites input omitted or changed swapCommit: %s", transport.requestBody)
	require.Equal(t, fixture.root.String(), swapCommit, "encoded applyWrites input omitted or changed swapCommit: %s", transport.requestBody)
	var writes []json.RawMessage
	if err := json.Unmarshal(input["writes"], &writes); err != nil || len(writes) != 3 {
		require.False(t, err != nil || len(writes) != 3, "encoded batch writes=%d error=%v", len(writes), err)
	}
}

func TestPublishFencedClassifiesOnlyStructuredInvalidSwap(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "structured name", status: 400, body: `{"error":"InvalidSwap","message":"revision no longer current"}`, want: ErrFenceLost},
		{name: "message text only", status: 400, body: `{"error":"InvalidRecord","message":"InvalidSwap"}`, want: ErrBatchRejected},
		{name: "malformed structured error", status: 400, body: `not json InvalidSwap`, want: ErrBatchRejected},
		{name: "server error stays ambiguous", status: 500, body: `{"error":"InvalidSwap"}`, want: ErrAmbiguousTransport},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &proofTransport{doStatus: test.status, doBody: []byte(test.body)}
			_, err := PublishFenced(context.Background(), transport, &Revision{did: proofTestDID, commitCID: fixture.root.String()}, validPublication(fixture.root.String()))
			if !errors.Is(err, test.want) {
				require.ErrorIs(t, err, test.want, "publish error=%v want %v", err, test.want)
			}
		})
	}
}

func TestPublishFencedDoesNotRetryAmbiguousTransport(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	transport := &proofTransport{doError: errors.New("timeout")}
	_, err := PublishFenced(context.Background(), transport, &Revision{did: proofTestDID, commitCID: fixture.root.String()}, validPublication(fixture.root.String()))
	require.ErrorIs(t, err, ErrAmbiguousTransport, "publish transport error=%v path=%q", err, transport.requestPath)
	require.Equal(t, "com.atproto.repo.applyWrites", transport.requestPath, "publish transport error=%v path=%q", err, transport.requestPath)
}

func TestPublishFencedRejectsInvalidBatchBeforeTransport(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	publication := validPublication(fixture.root.String())
	publication.VaultHead.Record = json.RawMessage(`not json`)
	transport := &proofTransport{}
	_, err := PublishFenced(context.Background(), transport, &Revision{did: proofTestDID, commitCID: fixture.root.String()}, publication)
	require.ErrorIs(t, err, ErrBatchRejected, "invalid batch error=%v request=%q", err, transport.requestPath)
	require.Equal(t, "", transport.requestPath, "invalid batch error=%v request=%q", err, transport.requestPath)
}

func TestPostSubmissionFailuresSignalCandidateDisclosureRisk(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		response string
		want     error
	}{
		{name: "rejected batch", status: 400, response: `{"error":"InvalidRequest","message":"bad"}`, want: ErrBatchRejected},
		{name: "server error", status: 503, response: `nope`, want: ErrAmbiguousTransport},
		{name: "unexpected status", status: 300, response: ``, want: ErrAmbiguousTransport},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := makeProofFixture(t, 1)
			transport := &proofTransport{doStatus: testCase.status, doBody: []byte(testCase.response)}
			revision := &Revision{did: proofTestDID, commitCID: fixture.root.String()}
			_, err := PublishFenced(context.Background(), transport, revision, validPublication(fixture.root.String()))
			if !errors.Is(err, testCase.want) {
				require.ErrorIs(t, err, testCase.want, "error = %v, want %v", err, testCase.want)
			}
			if !errors.Is(err, ErrCandidateMayBeDisclosed) {
				require.ErrorIs(t, err, ErrCandidateMayBeDisclosed, "post-submission failure must signal possible candidate disclosure: %v", err)
			}
		})
	}
}

func TestLostFenceDoesNotSignalCandidateDisclosureRisk(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	transport := &proofTransport{doStatus: 400, doBody: []byte(`{"error":"InvalidSwap"}`)}
	revision := &Revision{did: proofTestDID, commitCID: fixture.root.String()}
	_, err := PublishFenced(context.Background(), transport, revision, validPublication(fixture.root.String()))
	if !errors.Is(err, ErrFenceLost) {
		require.ErrorIs(t, err, ErrFenceLost, "error = %v, want ErrFenceLost", err)
	}
	if errors.Is(err, ErrCandidateMayBeDisclosed) {
		require.False(t, errors.Is(err, ErrCandidateMayBeDisclosed), "a lost fence is checked before blob processing and must not be reported as disclosure risk: %v", err)
	}
}
