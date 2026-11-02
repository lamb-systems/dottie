package atproto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
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

type candidateStageTransport struct {
	calls   int
	status  int
	body    []byte
	err     error
	request []byte
}

type signedCARFlowTransport struct {
	*readTransport
	t           *testing.T
	records     map[RecordKey][]byte
	commitKey   *atcrypto.PrivateKeyP256
	staged      map[string][]byte
	applyWrites int
}

func (transport *signedCARFlowTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	if endpoint == "com.atproto.sync.getBlob" {
		if staged, exists := transport.staged[query.Get("cid")]; exists {
			return 200, io.NopCloser(bytes.NewReader(staged)), nil
		}
	}
	return transport.readTransport.OpenStream(ctx, endpoint, query)
}

func (transport *signedCARFlowTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.sync.getLatestCommit" {
		return transport.readTransport.Do(ctx, method, endpoint, query, body, contentType)
	}
	switch endpoint {
	case "com.atproto.repo.uploadBlob":
		rawCID, err := rawBlobCID(body)
		if err != nil {
			return 0, nil, err
		}
		parsed, err := cid.Cast(rawCID)
		if err != nil {
			return 0, nil, err
		}
		transport.staged[parsed.String()] = bytes.Clone(body)
		response, err := json.Marshal(struct {
			Blob json.RawMessage `json:"blob"`
		}{Blob: blobJSONFromCID(rawCID, len(body))})
		return 200, response, err
	case "com.atproto.repo.applyWrites":
		var input applyWritesInput
		if err := json.Unmarshal(body, &input); err != nil {
			return 400, nil, err
		}
		for _, encoded := range input.Writes {
			var write struct {
				Collection string          `json:"collection"`
				RKey       string          `json:"rkey"`
				Value      json.RawMessage `json:"value"`
			}
			if err := json.Unmarshal(encoded, &write); err != nil {
				return 400, nil, err
			}
			object, err := atdata.UnmarshalJSON(write.Value)
			if err != nil {
				return 400, nil, err
			}
			encodedRecord, err := atdata.MarshalCBOR(normalizeRecordMap(object))
			if err != nil {
				return 400, nil, err
			}
			transport.records[RecordKey{Collection: write.Collection, RKey: write.RKey}] = encodedRecord
		}
		transport.applyWrites++
		transport.refreshCAR()
		response, err := json.Marshal(applyWritesOutput{Commit: struct {
			CID string `json:"cid"`
		}{CID: transport.proofTransport.latestCIDs[0]}})
		return 200, response, err
	default:
		return 0, nil, fmt.Errorf("unexpected endpoint %s", endpoint)
	}
}

func (transport *signedCARFlowTransport) refreshCAR() {
	transport.t.Helper()
	car, _, root, _ := buildReadCARWithPrivateKey(transport.t, transport.records, transport.commitKey)
	transport.carBytes = car
	transport.latestCIDs = repeatedCIDs(root.String(), 20)
	transport.latestCalls = 0
	transport.streamCalls = 0
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

func (transport *candidateStageTransport) Do(_ context.Context, method, endpoint string, _ url.Values, body []byte, _ string) (int, []byte, error) {
	transport.calls++
	if method != "POST" || endpoint != "com.atproto.repo.uploadBlob" {
		return 0, nil, fmt.Errorf("unexpected request %s %s", method, endpoint)
	}
	transport.request = bytes.Clone(body)
	return transport.status, bytes.Clone(transport.body), transport.err
}

func (*candidateStageTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("unexpected stream request")
}

func candidateUploadResponse(t *testing.T, data []byte) []byte {
	t.Helper()
	blob := blobJSONFromCID(rawTransitionCID(data), len(data))
	response, err := json.Marshal(struct {
		Blob json.RawMessage `json:"blob"`
	}{Blob: blob})
	require.NoError(t, err)
	return response
}

func TestATProtoTransitionStageCandidateRequiresEnvelopeContextBeforeNetwork(t *testing.T) {
	_, _, predecessor, publication := newAtprotoPublicationFixture(t)
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	transport := &candidateStageTransport{status: 200, body: candidateUploadResponse(t, publication.Snapshot)}
	io := ATProtoTransitionIO{Transport: transport, BlobUploadLimit: int64(len(publication.Snapshot))}
	ctx := context.Background()

	_, _, err = io.StageCandidate(ctx, []byte("synthetic plaintext"), policy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrCandidateEnvelopeInvalid)
	assert.Zero(t, transport.calls, "a non-envelope candidate must be refused before uploadBlob")

	wrongVault := policy.Vault
	wrongVault[0] ^= 1
	wrongVaultPolicy := policy
	wrongVaultPolicy.Vault = wrongVault
	_, _, err = io.StageCandidate(ctx, publication.Snapshot, wrongVaultPolicy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrCandidateContextMismatch)
	assert.Zero(t, transport.calls, "a candidate for another vault must be refused before uploadBlob")

	wrongEpochPolicy := policy
	wrongEpochPolicy.EpochSeq++
	_, _, err = io.StageCandidate(ctx, publication.Snapshot, wrongEpochPolicy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrCandidateContextMismatch)
	assert.Zero(t, transport.calls, "a candidate for another epoch must be refused before uploadBlob")

	wrongDigestPolicy := policy
	wrongDigestPolicy.MaxPublications++
	_, _, err = io.StageCandidate(ctx, publication.Snapshot, wrongDigestPolicy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrCandidateContextMismatch)
	assert.Zero(t, transport.calls, "a candidate for another policy must be refused before uploadBlob")

	blobReference, blobCID, err := io.StageCandidate(ctx, publication.Snapshot, policy, predecessor.Certificates)
	require.NoError(t, err)
	assert.NotEmpty(t, blobReference)
	assert.Equal(t, cid.NewCidV1(cid.Raw, mustTransitionMultihash(publication.Snapshot)).String(), blobCID)
	assert.Equal(t, 1, transport.calls, "the authenticated envelope positive control reaches uploadBlob")
	assert.Equal(t, publication.Snapshot, transport.request)
}

func TestATProtoTransitionStageCandidateEnforcesAdvertisedBlobUploadLimitBeforeNetwork(t *testing.T) {
	_, _, predecessor, publication := newAtprotoPublicationFixture(t)
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	candidateLength := int64(len(publication.Snapshot))

	for _, test := range []struct {
		name           string
		limit          int64
		wantErr        error
		otherAdmission error
	}{
		{name: "unadvertised", limit: 0, wantErr: ErrBlobUploadLimitUnadvertised, otherAdmission: ErrCandidateExceedsBlobUploadLimit},
		{name: "over ceiling", limit: candidateLength - 1, wantErr: ErrCandidateExceedsBlobUploadLimit, otherAdmission: ErrBlobUploadLimitUnadvertised},
		{name: "under ceiling", limit: candidateLength + 1},
		{name: "exact ceiling", limit: candidateLength},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &candidateStageTransport{status: 200, body: candidateUploadResponse(t, publication.Snapshot)}
			writer := ATProtoTransitionIO{Transport: transport, BlobUploadLimit: test.limit}
			_, _, err := writer.StageCandidate(context.Background(), publication.Snapshot, policy, predecessor.Certificates)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				assert.NotErrorIs(t, err, test.otherAdmission)
				assert.NotErrorIs(t, err, ErrCandidateEnvelopeInvalid)
				assert.Zero(t, transport.calls, "a refused candidate must not reach uploadBlob")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 1, transport.calls, "an admitted candidate reaches uploadBlob")
			assert.Equal(t, publication.Snapshot, transport.request)
		})
	}

	transport := &candidateStageTransport{status: 200, body: candidateUploadResponse(t, []byte("synthetic plaintext"))}
	_, _, err = (ATProtoTransitionIO{Transport: transport}).StageCandidate(context.Background(), []byte("synthetic plaintext"), policy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrCandidateEnvelopeInvalid)
	assert.NotErrorIs(t, err, ErrBlobUploadLimitUnadvertised)
	assert.NotErrorIs(t, err, ErrCandidateExceedsBlobUploadLimit)
	assert.Zero(t, transport.calls, "envelope preflight errors remain distinct and happen before uploadBlob")
}

func TestATProtoPublicationIOThreadsBlobUploadLimitToCandidateSink(t *testing.T) {
	_, _, predecessor, publication := newAtprotoPublicationFixture(t)
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	transport := &candidateStageTransport{status: 200, body: candidateUploadResponse(t, publication.Snapshot)}
	writer := ATProtoPublicationIO{Transport: transport, BlobUploadLimit: int64(len(publication.Snapshot) - 1)}

	_, _, err = writer.StageCandidate(context.Background(), publication.Snapshot, policy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrCandidateExceedsBlobUploadLimit)
	assert.Zero(t, transport.calls, "the publication adapter must pass its discovered ceiling to the sink")
}

func TestATProtoTransitionStageCandidateRejectsPlaintextEnvelope(t *testing.T) {
	currentPolicy, certificates, oldEnvelope, currentDigest := newStageCandidateAuthenticationFixture(t)
	plaintextCandidate := oldEnvelope
	plaintextCandidate.Vault = currentPolicy.Vault
	plaintextCandidate.EpochSeq = currentPolicy.EpochSeq
	plaintextCandidate.PolicyDigest = currentDigest
	plaintextCandidate.Ciphertext = []byte("synthetic plaintext")
	plaintextCandidate.Commit = [32]byte{}
	plaintextCandidate.Nonce = [24]byte{}
	plaintextCandidate.Tag = [16]byte{}
	plaintextCandidate.Signature = [64]byte{}
	plaintextBytes, err := vault.EncodeEnvelope(plaintextCandidate)
	require.NoError(t, err)
	transport := &candidateStageTransport{status: 200, body: candidateUploadResponse(t, plaintextBytes)}
	_, _, err = (ATProtoTransitionIO{Transport: transport}).StageCandidate(context.Background(), plaintextBytes, currentPolicy, certificates)
	require.ErrorIs(t, err, ErrCandidateUnauthenticated)
	assert.Zero(t, transport.calls, "a structurally valid plaintext envelope with zero authentication fields must be refused before uploadBlob")
}

func TestATProtoTransitionStageCandidateRejectsRelabelledOldEpochEnvelope(t *testing.T) {
	currentPolicy, certificates, oldEnvelope, currentDigest := newStageCandidateAuthenticationFixture(t)
	relabelledOldEnvelope := oldEnvelope
	relabelledOldEnvelope.EpochSeq = currentPolicy.EpochSeq
	relabelledOldEnvelope.PolicyDigest = currentDigest
	relabelledBytes, err := vault.EncodeEnvelope(relabelledOldEnvelope)
	require.NoError(t, err)
	transport := &candidateStageTransport{status: 200, body: candidateUploadResponse(t, relabelledBytes)}
	_, _, err = (ATProtoTransitionIO{Transport: transport}).StageCandidate(context.Background(), relabelledBytes, currentPolicy, certificates)
	require.ErrorIs(t, err, ErrCandidateUnauthenticated)
	assert.Zero(t, transport.calls, "rewriting an old-epoch envelope header must not make its old signature valid")
}

func newStageCandidateAuthenticationFixture(t *testing.T) (vault.Policy, [][]byte, vault.Envelope, [32]byte) {
	t.Helper()
	fixture := newTransitionTestFixture(t)
	newSigning, newRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	newDevice := vault.DeviceMaterial{DeviceID: "candidate-device", KeyID: []byte("candidate-key"), Signing: newSigning, Recipient: newRecipient}
	enrollment, err := vault.PrepareTransition(fixture.predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: mustTestVault(t, fixture.predecessor), Signer: fixture.root,
		NewDevice: &newDevice, RequestedRole: vault.RolePublisher, ContentKey: publicationTestBytes(t, 32),
		Recipients: fixture.predecessor.Certificates,
		Wraps:      publicationTestWrapsForKeyIDs(t, [][]byte{fixture.root.KeyID, newDevice.KeyID}),
		Plaintext:  []byte("synthetic enrollment snapshot"), PublicationID: [16]byte(publicationTestBytes(t, 16)),
		Nonce: [24]byte(publicationTestBytes(t, 24)),
	})
	require.NoError(t, err)
	currentPolicy, err := vault.DecodePolicy(enrollment.Policy)
	require.NoError(t, err)
	currentDigest, err := vault.ComputePolicyDigest(enrollment.Policy)
	require.NoError(t, err)

	oldPolicy, err := vault.DecodePolicy(fixture.predecessor.Policy)
	require.NoError(t, err)
	oldDigest, err := vault.ComputePolicyDigest(fixture.predecessor.Policy)
	require.NoError(t, err)
	rootCertificate, err := vault.DecodeCertificate(fixture.predecessor.Certificates[0])
	require.NoError(t, err)
	oldRecipients := make([]vault.RecipientPublicKey, 0, len(oldPolicy.Recipients))
	for _, recipient := range oldPolicy.Recipients {
		oldRecipients = append(oldRecipients, vault.RecipientPublicKey{KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:])})
	}
	oldEnvelope, err := vault.SealAuthorized(vault.SealRequest{
		Purpose: vault.PurposeSnapshot, Vault: oldPolicy.Vault, PublicationID: [16]byte(publicationTestBytes(t, 16)),
		EpochSeq: oldPolicy.EpochSeq, PolicyDigest: oldDigest, DeviceID: fixture.root.DeviceID, KeyID: bytes.Clone(fixture.root.KeyID),
		Plaintext: []byte("old-epoch snapshot"), SigningKey: fixture.root.Signing, Recipients: oldRecipients, Policy: oldPolicy,
	}, rootCertificate, oldPolicy)
	require.NoError(t, err)
	return currentPolicy, enrollment.Recipients, oldEnvelope, currentDigest
}

func TestATProtoTransitionStageCandidateSignalsPostTransmissionDisclosure(t *testing.T) {
	_, _, predecessor, publication := newAtprotoPublicationFixture(t)
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	ctx := context.Background()

	transportFailure := &candidateStageTransport{err: errors.New("response lost after dispatch")}
	_, _, err = (ATProtoTransitionIO{Transport: transportFailure, BlobUploadLimit: int64(len(publication.Snapshot))}).StageCandidate(ctx, publication.Snapshot, policy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrAmbiguousTransport)
	assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed)
	assert.Equal(t, 1, transportFailure.calls)

	acceptedBody := candidateUploadResponse(t, publication.Snapshot)
	acceptedResponse := &candidateStageTransport{status: 400, body: acceptedBody}
	_, _, err = (ATProtoTransitionIO{Transport: acceptedResponse, BlobUploadLimit: int64(len(publication.Snapshot))}).StageCandidate(ctx, publication.Snapshot, policy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrBatchRejected)
	assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed,
		"a non-2xx response carrying a valid blob reference suggests upload acceptance")
	assert.Equal(t, 1, acceptedResponse.calls)

	rejectedResponse := &candidateStageTransport{status: 400, body: []byte(`{"error":"InvalidRequest"}`)}
	_, _, err = (ATProtoTransitionIO{Transport: rejectedResponse, BlobUploadLimit: int64(len(publication.Snapshot))}).StageCandidate(ctx, publication.Snapshot, policy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrBatchRejected)
	assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed,
		"every post-transmission failure must signal possible candidate disclosure")

	redirectResponse := &candidateStageTransport{status: 302, body: []byte(`{"error":"Redirect"}`)}
	_, _, err = (ATProtoTransitionIO{Transport: redirectResponse, BlobUploadLimit: int64(len(publication.Snapshot))}).StageCandidate(ctx, publication.Snapshot, policy, predecessor.Certificates)
	require.ErrorIs(t, err, ErrBatchRejected)
	assert.ErrorIs(t, err, ErrCandidateMayBeDisclosed,
		"a post-transmission redirect response must signal possible candidate disclosure")
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

func (io *transitionTestIO) StageCandidate(_ context.Context, data []byte, _ vault.Policy, _ [][]byte) (json.RawMessage, string, error) {
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

func policyRecordBytesForObject(t *testing.T, encoded []byte) []byte {
	t.Helper()
	policy, err := vault.DecodePolicy(encoded)
	require.NoError(t, err)
	record, err := EncodeRecord(policyRecordFromObject(policy))
	require.NoError(t, err)
	return record
}

func TestATProtoAdaptersEnrollPublishAndRevokeAgainstSignedCAR(t *testing.T) {
	fixture := newReadFixture(t)
	records := make(map[RecordKey][]byte, len(fixture.records))
	for key, data := range fixture.records {
		records[key] = bytes.Clone(data)
	}
	commitKey, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	car, _, rootCID, method := buildReadCARWithPrivateKey(t, records, commitKey)
	fixture.transport.carBytes = car
	fixture.transport.latestCIDs = repeatedCIDs(rootCID.String(), 20)
	fixture.transport.latestCalls = 0
	flow := &signedCARFlowTransport{
		readTransport: fixture.transport, t: t, records: records, commitKey: commitKey,
		staged: make(map[string][]byte),
	}
	observedAt := time.Unix(200, 0)
	adapter := ATProtoTransitionIO{
		Reader: RevisionReader{
			Transport: flow, DIDDocumentID: fixture.request.DIDDocumentID,
			VerificationMethods: []VerificationMethod{{
				ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: method,
			}},
		},
		Transport: flow, BlobUploadLimit: 1 << 30, DID: fixture.request.DID, TrustAnchor: fixture.request.TrustAnchor,
		PreviousPolicies: [][]byte{bytes.Clone(fixture.request.PreviousPolicy)}, PreviousControls: [][]byte{bytes.Clone(fixture.request.PreviousControl)}, ObservationStore: fixture.observationStore,
		Clock: func() time.Time { return observedAt },
	}
	ctx := context.Background()
	_, predecessor, err := adapter.ReadCurrent(ctx)
	require.NoError(t, err)
	firstEpoch := predecessor.EpochSeq
	adapter.PreviousPolicies = append(adapter.PreviousPolicies, policyRecordBytesForObject(t, predecessor.Policy))
	adapter.PreviousControls = append(adapter.PreviousControls, encodeReadControlRecord(t, predecessor.Control))

	root := vault.DeviceMaterial{
		DeviceID: "root", KeyID: []byte("root-sign"), Signing: fixtureSigningKey(11), Recipient: readX25519Key(t, 21),
	}
	newSigning, newRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	newDevice := vault.DeviceMaterial{DeviceID: "adapter-enrolled", KeyID: []byte("adapter-enrolled-key"), Signing: newSigning, Recipient: newRecipient}
	enrollmentKeyIDs := make([][]byte, 0, len(predecessor.Certificates)+1)
	for _, encoded := range predecessor.Certificates {
		certificate, decodeErr := vault.DecodeCertificate(encoded)
		require.NoError(t, decodeErr)
		enrollmentKeyIDs = append(enrollmentKeyIDs, bytes.Clone(certificate.KeyID))
	}
	enrollmentKeyIDs = append(enrollmentKeyIDs, bytes.Clone(newDevice.KeyID))
	enrollment, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: mustTestVault(t, predecessor), Signer: root,
		NewDevice: &newDevice, RequestedRole: vault.RolePublisher, ContentKey: publicationTestBytes(t, 32),
		Recipients: cloneTransitionCertificates(predecessor.Certificates), Wraps: publicationTestWrapsForKeyIDs(t, enrollmentKeyIDs),
		Plaintext: []byte("adapter enrollment snapshot"), PublicationID: [16]byte(publicationTestBytes(t, 16)),
		Nonce: [24]byte(publicationTestBytes(t, 24)),
	})
	require.NoError(t, err)
	adapter.PreviousPolicies = append(adapter.PreviousPolicies, policyRecordBytesForObject(t, enrollment.Policy))
	adapter.PreviousControls = append(adapter.PreviousControls, encodeReadControlRecord(t, enrollment.Control))
	observedAt = time.Unix(201, 0)
	enrollmentResult, err := CommitTransition(ctx, adapter, fixture.observationStore, enrollment, root.Signing, time.Unix(200, 0))
	require.NoError(t, err, enrollmentResult.Evidence)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), enrollmentResult.Outcome)

	_, predecessor, err = adapter.ReadCurrent(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, firstEpoch, predecessor.EpochSeq)
	firstEpochAt, firstEpochFound, err := fixture.observationStore.VaultEpochFirstSeen(ctx, mustTestVault(t, predecessor), firstEpoch)
	require.NoError(t, err)
	newEpochAt, newEpochFound, err := fixture.observationStore.VaultEpochFirstSeen(ctx, mustTestVault(t, predecessor), predecessor.EpochSeq)
	require.NoError(t, err)
	require.True(t, firstEpochFound)
	require.True(t, newEpochFound)
	assert.Equal(t, int64(200), firstEpochAt)
	assert.Equal(t, int64(201), newEpochAt)
	publisher := vault.DeviceMaterial{
		DeviceID: "publisher", KeyID: []byte("publisher-sign"), Signing: fixtureSigningKey(12), Recipient: readX25519Key(t, 22),
	}
	publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
		Vault: mustTestVault(t, predecessor), Signer: publisher, ContentKey: publicationTestBytes(t, 32),
		Wraps: publicationTestWraps(t, predecessor.Certificates), Plaintext: []byte("adapter publication snapshot"),
		PublicationID: [16]byte(publicationTestBytes(t, 16)), Nonce: [24]byte(publicationTestBytes(t, 24)),
		EpochFirstSeen: fixture.observationStore, Clock: func() time.Time { return time.Unix(201, 0) },
	})
	require.NoError(t, err)
	publicationAdapter := ATProtoPublicationIO{
		Reader: adapter.Reader, Transport: flow, DID: adapter.DID, TrustAnchor: adapter.TrustAnchor,
		BlobUploadLimit:  adapter.BlobUploadLimit,
		PreviousPolicies: adapter.PreviousPolicies, PreviousControls: adapter.PreviousControls, ObservationStore: fixture.observationStore,
	}
	publicationResult, err := CommitPublication(ctx, publicationAdapter, fixture.observationStore, publication, publisher.Signing, time.Unix(201, 0))
	require.NoError(t, err)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), publicationResult.Outcome)

	_, predecessor, err = adapter.ReadCurrent(ctx)
	require.NoError(t, err)
	activeRecipients := make([][]byte, 0, len(predecessor.Certificates)-1)
	for _, encoded := range predecessor.Certificates {
		certificate, decodeErr := vault.DecodeCertificate(encoded)
		require.NoError(t, decodeErr)
		if certificate.DeviceID != newDevice.DeviceID {
			activeRecipients = append(activeRecipients, bytes.Clone(encoded))
		}
	}
	revocation, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionRevoke, Vault: mustTestVault(t, predecessor), Signer: root, RevokeDeviceID: newDevice.DeviceID,
		ContentKey: publicationTestBytes(t, 32), Recipients: activeRecipients, Wraps: publicationTestWraps(t, activeRecipients),
		Plaintext: []byte("adapter revocation snapshot"), PublicationID: [16]byte(publicationTestBytes(t, 16)),
		Nonce: [24]byte(publicationTestBytes(t, 24)),
	})
	require.NoError(t, err)
	revocationResult, err := CommitTransition(ctx, adapter, fixture.observationStore, revocation, root.Signing, time.Unix(202, 0))
	require.NoError(t, err)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), revocationResult.Outcome)
	_, predecessor, err = adapter.ReadCurrent(ctx)
	require.NoError(t, err)
	control, err := vault.DecodeControl(predecessor.Control)
	require.NoError(t, err)
	require.Len(t, control.Revoked, 1)
	assert.Equal(t, newDevice.DeviceID, control.Revoked[0].DeviceID)
	assert.Equal(t, 3, flow.applyWrites)
	assert.Len(t, flow.staged, 3)
}

func TestATProtoTransitionIORejectsPublicationCountGapOnPredecessorRead(t *testing.T) {
	fixture := newReadFixture(t)
	first, err := fixture.reader().Read(context.Background(), fixture.request)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.PublicationCount)

	headKey := RecordKey{Collection: VaultHeadNSID, RKey: "self"}
	decoded, err := DecodeRecord(fixture.records[headKey])
	require.NoError(t, err)
	head := headFromRecord(decoded.(HeadRecord))
	head.PublicationCount = 3
	encodedHead := signReadHead(t, head, fixtureSigningKey(12))
	headObject, err := vault.DecodeHead(encodedHead)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, headKey, headRecordFromObject(headObject))
	replaceReadCAR(t, &fixture, fixture.records)

	adapter := ATProtoTransitionIO{
		Reader: RevisionReader{
			Transport: fixture.transport, DIDDocumentID: fixture.request.DIDDocumentID,
			VerificationMethods: fixture.request.VerificationMethods,
		},
		Transport: fixture.transport, DID: fixture.request.DID, TrustAnchor: fixture.request.TrustAnchor,
		PreviousPolicies: [][]byte{fixture.request.PreviousPolicy}, PreviousControls: [][]byte{fixture.request.PreviousControl}, ObservationStore: fixture.observationStore,
	}
	_, _, err = adapter.ReadCurrent(context.Background())
	require.ErrorIs(t, err, ErrPublicationCountGap)
}

type publicationEpochAgeStore struct {
	firstSeenAt int64
	found       bool
}

func (store publicationEpochAgeStore) VaultEpochFirstSeen(context.Context, [32]byte, uint64) (int64, bool, error) {
	return store.firstSeenAt, store.found, nil
}

type transitionObservationTracker struct {
	store          PublicationObservationStore
	calls          int
	firstSeenCalls int
}

func (tracker *transitionObservationTracker) RecordVaultPublicationObservation(ctx context.Context, observation state.VaultPublicationObservation) error {
	tracker.calls++
	return tracker.store.RecordVaultPublicationObservation(ctx, observation)
}

func (tracker *transitionObservationTracker) VaultPublicationEpoch(ctx context.Context, vaultID [32]byte) (uint64, bool, error) {
	return tracker.store.VaultPublicationEpoch(ctx, vaultID)
}

func (tracker *transitionObservationTracker) RecordVaultEpochFirstSeen(ctx context.Context, vaultID [32]byte, epoch uint64, firstSeenAt int64) error {
	tracker.firstSeenCalls++
	return tracker.store.RecordVaultEpochFirstSeen(ctx, vaultID, epoch, firstSeenAt)
}

func TestReadCurrentRequiresPublicationAuthorityForHeadSigner(t *testing.T) {
	fixture := newReadFixture(t)
	policy, _, oldPolicyDigest := fixturePolicyParts(t, fixture)
	previousPolicyRecord := bytes.Clone(fixture.records[RecordKey{Collection: VaultPolicyNSID, RKey: "self"}])
	controlRecordDecoded, err := DecodeRecord(fixture.records[RecordKey{Collection: VaultControlNSID, RKey: "self"}])
	require.NoError(t, err)
	oldControlBytes, err := vault.EncodeControl(controlFromRecord(controlRecordDecoded.(ControlRecord)))
	require.NoError(t, err)

	policy.EpochSeq++
	policy.PrevPolicyDigest = oldPolicyDigest
	restoreSigning := fixtureSigningKey(77)
	restoreRecipient := readX25519Key(t, 78)
	restoreCertificate := vault.Certificate{
		Vault: policy.Vault, DeviceID: "restore-only", KeyID: []byte("restore-only-sign"),
		Role: vault.RoleRestoreOnly, CertEpoch: policy.EpochSeq, Issuer: "root",
		Signer: vault.Signer{DeviceID: "root", KeyID: []byte("root-sign")},
	}
	copy(restoreCertificate.SigningPublicKey[:], restoreSigning[32:])
	copy(restoreCertificate.EncryptionPublicKey[:], restoreRecipient.PublicKey().Bytes())
	restoreCertificateBytes := signReadCertificate(t, restoreCertificate, fixtureSigningKey(11))
	restoreCertificate, err = vault.DecodeCertificate(restoreCertificateBytes)
	require.NoError(t, err)
	policy.Roles = append(policy.Roles, vault.RoleBinding{DeviceID: restoreCertificate.DeviceID, Role: vault.RoleRestoreOnly})
	policy.Recipients = append(policy.Recipients, vault.PolicyRecipient{
		DeviceID: restoreCertificate.DeviceID, KeyID: bytes.Clone(restoreCertificate.KeyID), PublicKey: restoreCertificate.EncryptionPublicKey,
	})
	policyBytes := signReadPolicy(t, policy, fixtureSigningKey(11))
	policy, err = vault.DecodePolicy(policyBytes)
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultPolicyNSID, RKey: "self"}, policyRecordFromObject(policy))
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultCertificateNSID, RKey: "restore-only"}, certificateRecordFromObject(restoreCertificate))

	control, err := vault.DecodeControl(oldControlBytes)
	require.NoError(t, err)
	control.EpochSeq = policy.EpochSeq
	control.PolicyDigest = policyDigest
	control.PrevControlCID = readRawCID(t, oldControlBytes)
	tracker := &transitionObservationTracker{store: fixture.observationStore}
	adapter := ATProtoTransitionIO{
		Reader: RevisionReader{
			Transport: fixture.transport, DIDDocumentID: fixture.request.DIDDocumentID,
			VerificationMethods: fixture.request.VerificationMethods,
		},
		Transport: fixture.transport, DID: fixture.request.DID, TrustAnchor: fixture.request.TrustAnchor,
		PreviousPolicies: [][]byte{bytes.Clone(fixture.request.PreviousPolicy), previousPolicyRecord}, PreviousControls: [][]byte{encodeReadControlRecord(t, oldControlBytes)}, ObservationStore: tracker,
	}

	installReadPublicationForRoleJoin(t, &fixture, policy, control,
		vault.Signer{DeviceID: restoreCertificate.DeviceID, KeyID: restoreCertificate.KeyID}, restoreSigning, 1, 0xD1)
	adapter.Reader.VerificationMethods = fixture.request.VerificationMethods
	_, _, err = adapter.ReadCurrent(context.Background())
	require.ErrorIs(t, err, vault.ErrPublicationAuthority)
	assert.Equal(t, 0, tracker.calls, "a refused restore-only head does not persist an observation")

	installReadPublicationForRoleJoin(t, &fixture, policy, control, publisherSigner(), fixtureSigningKey(12), 1, 0xD2)
	adapter.Reader.VerificationMethods = fixture.request.VerificationMethods
	_, predecessor, err := adapter.ReadCurrent(context.Background())
	require.NoError(t, err, "a publisher-signed head remains readable after the refused restore-only read")
	assert.Equal(t, 1, tracker.calls)
	assert.Equal(t, publisherSigner().DeviceID, vaultHeadSignerDeviceID(t, predecessor.Head))
}

func installReadPublicationForRoleJoin(t *testing.T, fixture *readFixture, policy vault.Policy, control vault.Control, signer vault.Signer, signingKey ed25519.PrivateKey, count uint64, publicationSeed byte) {
	t.Helper()
	policyBytes, err := vault.EncodePolicy(policy)
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	certificate := fixturePublisherCertificate(t, *fixture)
	envelope, err := vault.SealAuthorized(vault.SealRequest{
		Purpose: vault.PurposeSnapshot, Vault: policy.Vault, PublicationID: [16]byte(bytes.Repeat([]byte{publicationSeed}, 16)),
		EpochSeq: policy.EpochSeq, PolicyDigest: policyDigest, DeviceID: certificate.DeviceID, KeyID: bytes.Clone(certificate.KeyID),
		Plaintext: []byte("synthetic publisher snapshot"), SigningKey: fixtureSigningKey(12), Recipients: fixtureRecipientPublicKeys(policy),
	}, certificate, policy)
	require.NoError(t, err)
	envelopeBytes, err := vault.EncodeEnvelope(envelope)
	require.NoError(t, err)
	snapshot := snapshotRecordForEnvelope(t, envelope, envelopeBytes, fixtureSigningKey(12))
	envelopeCID := readRawCID(t, envelopeBytes)
	control.EpochSeq = policy.EpochSeq
	control.PolicyDigest = policyDigest
	control.HeadSnapshotCID = bytes.Clone(envelopeCID)
	controlBytes := signReadControl(t, control, fixtureSigningKey(11))
	control, err = vault.DecodeControl(controlBytes)
	require.NoError(t, err)
	putReadRecord(t, fixture.records, RecordKey{Collection: VaultControlNSID, RKey: "self"}, controlRecordFromObject(control))
	head := fixtureHeadObject(t, *fixture)
	head.EpochSeq = policy.EpochSeq
	head.PolicyDigest = policyDigest
	head.SnapshotCID = bytes.Clone(envelopeCID)
	head.BlobCID = bytes.Clone(envelopeCID)
	head.PublicationCount = count
	head.Signer = vault.Signer{DeviceID: signer.DeviceID, KeyID: bytes.Clone(signer.KeyID)}
	headBytes := signReadHead(t, head, signingKey)
	head, err = vault.DecodeHead(headBytes)
	require.NoError(t, err)
	installSnapshot(t, fixture, envelopeBytes, snapshot, headRecordFromObject(head))
}

func vaultHeadSignerDeviceID(t *testing.T, encoded []byte) string {
	t.Helper()
	head, err := vault.DecodeHead(encoded)
	require.NoError(t, err)
	return head.Signer.DeviceID
}

func TestReadCurrentObservesConsecutivePublicationCounts(t *testing.T) {
	fixture := newReadFixture(t)
	adapter := ATProtoTransitionIO{
		Reader: RevisionReader{
			Transport: fixture.transport, DIDDocumentID: fixture.request.DIDDocumentID,
			VerificationMethods: fixture.request.VerificationMethods,
		},
		Transport: fixture.transport, DID: fixture.request.DID, TrustAnchor: fixture.request.TrustAnchor,
		PreviousPolicies: [][]byte{fixture.request.PreviousPolicy}, PreviousControls: [][]byte{fixture.request.PreviousControl}, ObservationStore: fixture.observationStore,
	}

	_, first, err := adapter.ReadCurrent(context.Background())
	require.NoError(t, err)
	firstHeadCID := bytes.Clone(first.HeadCID)

	envelope, snapshot := sealFixtureSnapshot(t, fixture, firstHeadCID, 0xD2, []byte("second consecutive publication"))
	secondHeadCID := readRawCID(t, envelope)
	head := signFixtureHead(t, fixture, envelope, 2, firstHeadCID, publisherSigner(), fixtureSigningKey(12))
	installSnapshot(t, &fixture, envelope, snapshot, head)
	adapter.Reader.VerificationMethods = fixture.request.VerificationMethods

	_, second, err := adapter.ReadCurrent(context.Background())
	require.NoError(t, err, "ReadCurrent accepts a legitimate count n+1 whose signed PrevHeadCID is the observed count n head")
	assert.Equal(t, secondHeadCID, second.HeadCID)
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
