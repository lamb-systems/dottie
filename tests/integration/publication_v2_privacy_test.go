package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const (
	publicationPrivacyDID         = "did:plc:abcdefghijklmnopqrstuvwx"
	publicationPrivacyTargetID    = "publication-privacy-files"
	publicationPrivacyTrackedFile = "prefs.ini"
	publicationPrivacyBlobLimit   = int64(1 << 20)
	publicationPrivacyLeakField   = "publicationPrivacyLeak"
	publicationPrivacyApplyURL    = "com.atproto.repo.applyWrites"
	publicationPrivacyListURL     = "com.atproto.repo.listRecords"
)

type publicationPrivacyCanary struct {
	name  string
	value []byte
}

type publicationPrivacyCanaries struct {
	plaintext        []byte
	credential       []byte
	revisionTwo      []byte
	allCanaries      []publicationPrivacyCanary
	materialCanaries []publicationPrivacyCanary
}

func publicationPrivacyNonce(t *testing.T) string {
	t.Helper()
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	return hex.EncodeToString(nonce)
}

func publicationPrivacyPlaintext(nonce string) []byte {
	return []byte("dottie-privacy-plaintext-" + nonce)
}

func publicationPrivacyCredential(nonce string) []byte {
	return []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ" + nonce + "In0.c2lnbmF0dXJlL" + nonce)
}

func publicationPrivacyRevisionTwo(nonce string) []byte {
	return []byte("dottie-privacy-revision-two-" + nonce)
}

func publicationPrivacyReviewAnchor(nonce string) []byte {
	value := make([]byte, 32)
	copy(value, "anchor-"+nonce)
	return value
}

func publicationPrivacyFileContent(nonce string) []byte {
	return []byte(
		string(publicationPrivacyPlaintext(nonce)) + "\n" + string(publicationPrivacyCredential(nonce)) + "\n",
	)
}

func publicationPrivacyRevisionTwoContent(nonce string) []byte {
	return []byte(string(publicationPrivacyRevisionTwo(nonce)) + "\n")
}

func newPublicationPrivacyCanaries(nonce, absolutePath string) publicationPrivacyCanaries {
	canaries := publicationPrivacyCanaries{
		plaintext:   publicationPrivacyPlaintext(nonce),
		credential:  publicationPrivacyCredential(nonce),
		revisionTwo: publicationPrivacyRevisionTwo(nonce),
	}
	canaries.materialCanaries = []publicationPrivacyCanary{
		{name: "target-file-plaintext", value: canaries.plaintext},
		{name: "credential-shaped-string", value: canaries.credential},
		{name: "second-target-file-plaintext", value: canaries.revisionTwo},
		{name: "absolute-local-path", value: []byte(absolutePath)},
		{name: "local-review-anchor", value: publicationPrivacyReviewAnchor(nonce)},
	}
	canaries.allCanaries = append(append([]publicationPrivacyCanary{}, canaries.materialCanaries...),
		publicationPrivacyCanary{name: "account-did", value: []byte(publicationPrivacyDID)})
	return canaries
}

type publicationPrivacyFinding struct {
	canary     string
	collection string
	rkey       string
	surface    string
}

func (finding publicationPrivacyFinding) String() string {
	return finding.canary + "@" + finding.collection + "/" + finding.rkey + "(" + finding.surface + ")"
}

type publicationPrivacyServedRecord struct {
	collection string
	rkey       string
	value      []byte
}

type publicationPrivacyScanControl struct {
	collection string
	field      string
	value      string
}

type publicationPrivacyFixture struct {
	pds           *atprototest.MemoryPDS
	binding       publicationstate.Binding
	adapter       *service.ATProtoMaterialTransport
	reader        *service.PublicationReader
	blobs         atproto.VaultReader
	coordinator   *service.Coordinator
	store         *publicationstate.Store
	records       *publicationPrivacyProposalStore
	reviews       publicationPrivacyReviews
	configuration config.Config
	selected      string
	publicationN  uint64
}

func newPublicationPrivacyFixture(
	t *testing.T,
	reviewAnchor []byte,
	control *publicationPrivacyScanControl,
) *publicationPrivacyFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationPrivacyDID, repositoryKey)
	require.NoError(t, err)
	var transport atproto.Transport = pds
	if control != nil {
		transport = publicationPrivacyLeakingTransport{base: pds, control: *control}
	}
	method := pds.VerificationMethod()
	revisionReader := atproto.RevisionReader{
		Transport: pds, DIDDocumentID: publicationPrivacyDID,
		VerificationMethods: []atproto.VerificationMethod{
			{
				ID:                 method.ID,
				Type:               method.Type,
				Controller:         method.Controller,
				PublicKeyMultibase: method.PublicKeyMultibase,
			},
		},
	}
	binding := publicationstate.Binding{
		AccountDID: publicationPrivacyDID, Backend: publicationstate.BackendPublicRepo,
		Repository: "at://" + publicationPrivacyDID, Vault: [32]byte{0x70, 0x72, 0x69},
	}
	adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
		Binding:         binding,
		DID:             publicationPrivacyDID,
		Reader:          revisionReader,
		Transport:       transport,
		BlobUploadLimit: publicationPrivacyBlobLimit,
	})
	require.NoError(t, err)
	blobs := atproto.VaultReader{Transport: pds, Budgets: atproto.DefaultBudgets()}
	session := &atproto.Session{DID: publicationPrivacyDID, Scopes: atproto.VaultScopes()}
	publicationReader, err := service.NewPublicationReader(service.PublicationReaderConfig{
		Binding: binding, DID: publicationPrivacyDID, Session: session, Adapter: adapter, Blobs: blobs,
	})
	require.NoError(t, err)

	machineRoot := filepath.Join(root, "machine")
	paths := platform.Paths{
		Home: filepath.Join(machineRoot, "home"), ConfigHome: filepath.Join(machineRoot, "config"),
		StateHome: filepath.Join(machineRoot, "state"), CacheHome: filepath.Join(machineRoot, "cache"),
		DataHome: filepath.Join(machineRoot, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	selected := filepath.Join(paths.Home, "synthetic")
	require.NoError(t, os.MkdirAll(selected, 0o700))
	empty := filepath.Join(paths.Home, "synthetic-empty")
	require.NoError(t, os.MkdirAll(empty, 0o700))
	configuration := config.Default()
	configuration.Targets = []config.Target{{
		ID: publicationPrivacyTargetID, Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory},
	}, {
		ID: publicationPrivacyTargetID + "-empty", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic-empty", Kind: model.SelectionDirectory},
	}}
	require.NoError(t, configuration.Validate())

	stateHome := filepath.Join(root, "state-home")
	require.NoError(t, os.MkdirAll(stateHome, 0o700))
	stateStore, err := state.Open(platform.Paths{Home: stateHome, StateHome: stateHome})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, stateStore.Close()) })
	storeDir := paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(storeDir, 0o700))
	require.NoError(t, os.Chmod(storeDir, 0o700))
	store, err := publicationstate.Open(storeDir, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	coordinator, err := service.NewCoordinator(service.Dependencies{
		State: stateStore, Paths: paths, Clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
	})
	require.NoError(t, err)
	review := publicationstate.LocalReviewContext{
		SelectionDigest: [32]byte{0x53, 0x45, 0x4c}, SelectionRevision: 1,
		ApprovalRevision: 1,
	}
	copy(review.ApprovalDigest[:], reviewAnchor)
	return &publicationPrivacyFixture{
		pds: pds, binding: binding, adapter: adapter, reader: publicationReader, blobs: blobs,
		coordinator: coordinator, store: store, records: newPublicationPrivacyProposalStore(),
		reviews: publicationPrivacyReviews{review: review}, configuration: configuration, selected: selected,
	}
}

func (fixture *publicationPrivacyFixture) writeTrackedFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(fixture.selected, publicationPrivacyTrackedFile)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func (fixture *publicationPrivacyFixture) request() service.PublicationPushRequest {
	fixture.publicationN++
	var publicationID [16]byte
	publicationID[0] = 0x70
	publicationID[15] = byte(fixture.publicationN)
	return service.PublicationPushRequest{
		Store: fixture.store, Transport: fixture.adapter, Reader: fixture.reader, Records: fixture.records,
		Binding: fixture.binding, Configuration: fixture.configuration, Reviews: fixture.reviews,
		PublicationID: publicationID,
	}
}

func (fixture *publicationPrivacyFixture) publish(
	t *testing.T,
) (service.MaterialPublishResult, service.PublicationPushPreparation, error) {
	t.Helper()
	ctx := context.Background()
	request := fixture.request()
	preparation, err := fixture.coordinator.PreparePublicationPush(ctx, request)
	require.NoError(t, err)
	require.False(t, preparation.NoOp)
	result, err := fixture.coordinator.ConfirmPublicationPush(
		ctx,
		request,
		preparation,
		preparation.Proposal.Confirmation,
	)
	return result, preparation, err
}

func (fixture *publicationPrivacyFixture) prepareOnly(
	t *testing.T,
) (service.PublicationPushRequest, service.PublicationPushPreparation, error) {
	t.Helper()
	request := fixture.request()
	preparation, err := fixture.coordinator.PreparePublicationPush(context.Background(), request)
	if err != nil {
		return request, preparation, err
	}
	require.False(t, preparation.NoOp)
	return request, preparation, nil
}

func (fixture *publicationPrivacyFixture) publishRejected(
	t *testing.T,
) (service.MaterialPublishResult, publicationstate.CandidateInput, error) {
	t.Helper()
	ctx := context.Background()
	request, preparation, err := fixture.prepareOnly(t)
	require.NoError(t, err)
	result, err := fixture.coordinator.ConfirmPublicationPush(
		ctx,
		request,
		preparation,
		preparation.Proposal.Confirmation,
	)
	return result, preparation.Proposal.Candidate, err
}

func (fixture *publicationPrivacyFixture) record(t *testing.T, collection, rkey string) []byte {
	t.Helper()
	record, exists := fixture.pds.Record(collection, rkey)
	require.True(t, exists, "provider is missing record %s/%s", collection, rkey)
	return record.Data
}

func (fixture *publicationPrivacyFixture) fetchBlob(t *testing.T, blobCID []byte, size int64) []byte {
	t.Helper()
	payload, err := fixture.blobs.FetchBlob(context.Background(), publicationPrivacyDID, blobCID, size)
	require.NoError(t, err)
	return payload
}

func (fixture *publicationPrivacyFixture) terminalSnapshot(t *testing.T) publication.SnapshotRecord {
	t.Helper()
	view, err := fixture.adapter.ReadView(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, view.Snapshots)
	record, err := publication.DecodeSnapshot(view.Snapshots[len(view.Snapshots)-1].Raw)
	require.NoError(t, err)
	return record
}

func (fixture *publicationPrivacyFixture) terminalRaw(t *testing.T) []byte {
	t.Helper()
	view, err := fixture.adapter.ReadView(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, view.Snapshots)
	return bytes.Clone(view.Snapshots[len(view.Snapshots)-1].Raw)
}

func (fixture *publicationPrivacyFixture) floorPresent(t *testing.T) bool {
	t.Helper()
	_, present, err := fixture.store.Load(context.Background())
	require.NoError(t, err)
	return present
}

func (fixture *publicationPrivacyFixture) attempt(t *testing.T, id [16]byte) publicationstate.Attempt {
	t.Helper()
	attempt, err := fixture.store.LoadAttempt(context.Background(), id)
	require.NoError(t, err)
	return attempt
}

func TestPublicationV2PrivacyGate(t *testing.T) {
	t.Run("published repository", func(t *testing.T) {
		nonce := publicationPrivacyNonce(t)
		fixture := newPublicationPrivacyFixture(t, publicationPrivacyReviewAnchor(nonce), nil)
		trackedPath := fixture.writeTrackedFile(t, publicationPrivacyFileContent(nonce))
		canaries := newPublicationPrivacyCanaries(nonce, trackedPath)

		result, preparation, err := fixture.publish(t)
		require.NoError(t, err)
		assert.Equal(t, publicationstate.AttemptRetiredSuccess, result.Attempt.Lifecycle)
		assert.Equal(t, uint64(0), result.Floor.Sequence)

		assert.Equal(t, []string{
			publication.HeadNSID + "/self",
			publication.SnapshotNSID + "/0000000000000000",
		}, publicationPrivacyRecordKeys(t, fixture.pds))
		assert.Equal(
			t,
			[]string{publication.HeadNSID, publication.SnapshotNSID},
			publicationPrivacyCollections(t, fixture.pds),
		)
		for _, legacy := range publicationPrivacyLegacyCollections() {
			assert.NotContains(t, publicationPrivacyCollections(t, fixture.pds), legacy)
		}
		require.Len(t, fixture.pds.CurrentRevision().Records, 2)
		publicationPrivacyAssertRecordSchema(t, fixture)

		require.Empty(
			t,
			publicationPrivacyScan(t, fixture, canaries.allCanaries),
			"candidate bytes surfaced in published repository records",
		)

		terminal := fixture.terminalSnapshot(t)
		terminalKey, err := publication.SequenceKey(terminal.PublicationSeq)
		require.NoError(t, err)
		assert.Equal(t, "0000000000000000", terminalKey)
		firstPublished := make([]string, 0)
		for _, blob := range recordBlobs(t, terminal) {
			firstPublished = append(firstPublished, publicationPrivacyBlobIdentifier(t, blob.CID))
		}
		assert.ElementsMatch(t, firstPublished, fixture.pds.StoredBlobCIDs())
		publicationPrivacyAssertBlobReferences(t, fixture)
		publicationPrivacyAssertBlobPacking(
			t,
			fixture,
			terminal,
			[][]byte{canaries.plaintext, canaries.credential},
		)
		publicationPrivacyAssertRetainedReviewHasNoCandidateBytes(t, preparation, canaries)

		fixture.writeTrackedFile(t, publicationPrivacyRevisionTwoContent(nonce))
		second, _, err := fixture.publish(t)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), second.Floor.Sequence)
		assert.Equal(t, []string{
			publication.HeadNSID + "/self",
			publication.SnapshotNSID + "/0000000000000000",
			publication.SnapshotNSID + "/0000000000000001",
		}, publicationPrivacyRecordKeys(t, fixture.pds))
		assert.Equal(
			t,
			[]string{publication.HeadNSID, publication.SnapshotNSID},
			publicationPrivacyCollections(t, fixture.pds),
		)
		for _, legacy := range publicationPrivacyLegacyCollections() {
			assert.NotContains(t, publicationPrivacyCollections(t, fixture.pds), legacy)
		}
		publicationPrivacyAssertRecordSchema(t, fixture)
		require.Empty(
			t,
			publicationPrivacyScan(t, fixture, canaries.allCanaries),
			"candidate bytes surfaced in published repository records",
		)
		terminal = fixture.terminalSnapshot(t)
		published := make(map[string]struct{}, len(firstPublished))
		for _, identifier := range firstPublished {
			published[identifier] = struct{}{}
		}
		for _, blob := range recordBlobs(t, terminal) {
			published[publicationPrivacyBlobIdentifier(t, blob.CID)] = struct{}{}
		}
		expected := make([]string, 0, len(published))
		for identifier := range published {
			expected = append(expected, identifier)
		}
		assert.ElementsMatch(t, expected, fixture.pds.StoredBlobCIDs())
		publicationPrivacyAssertBlobReferences(t, fixture)
		assert.Equal(t, uint64(1), terminal.PublicationSeq)
		publicationPrivacyAssertBlobPacking(t, fixture, terminal, [][]byte{canaries.revisionTwo})
	})

	t.Run("scan control", func(t *testing.T) {
		nonce := publicationPrivacyNonce(t)
		control := publicationPrivacyScanControl{
			collection: publication.HeadNSID, field: publicationPrivacyLeakField,
			value: "publication-privacy-scan-control-" + nonce,
		}
		fixture := newPublicationPrivacyFixture(t, publicationPrivacyReviewAnchor(nonce), &control)
		trackedPath := fixture.writeTrackedFile(t, publicationPrivacyFileContent(nonce))
		canaries := newPublicationPrivacyCanaries(nonce, trackedPath)

		_, _, err := fixture.publish(t)
		require.Error(
			t,
			err,
			"a head record carrying an unrecognized field must not resolve as a verified repository view",
		)
		require.Equal(t, []string{
			publication.HeadNSID + "/self",
			publication.SnapshotNSID + "/0000000000000000",
		}, publicationPrivacyRecordKeys(t, fixture.pds))

		scanned := append(
			append([]publicationPrivacyCanary{}, canaries.allCanaries...),
			publicationPrivacyCanary{name: "injected-record-canary", value: []byte(control.value)},
		)
		findings := publicationPrivacyScan(t, fixture, scanned)
		require.NotEmpty(t, findings, "the canary scan reported nothing for a record that carries an injected canary")
		for _, finding := range findings {
			assert.Equal(
				t,
				"injected-record-canary",
				finding.canary,
				"unexpected canary reported in records: %s",
				finding,
			)
		}
		assert.Contains(
			t,
			publicationPrivacyFindingNames(findings),
			"injected-record-canary@"+publication.HeadNSID+"/self",
		)
	})

	t.Run("blob upload rejected", func(t *testing.T) {
		nonce := publicationPrivacyNonce(t)
		fixture := newPublicationPrivacyFixture(t, publicationPrivacyReviewAnchor(nonce), nil)
		trackedPath := fixture.writeTrackedFile(t, publicationPrivacyFileContent(nonce))
		canaries := newPublicationPrivacyCanaries(nonce, trackedPath)
		fixture.pds.SetHooks(
			atprototest.MemoryPDSHooks{
				RejectNextUploadBlobStatus: 413,
				RejectNextUploadBlobCode:   "BlobTooLarge",
			},
		)

		result, _, err := fixture.publish(t)
		require.Error(t, err, "a rejected blob upload must refuse the publication")
		publicationPrivacyAssertTypedFailure(t, err, "upload", "upload_failed")
		require.ErrorIs(t, err, atproto.ErrCandidateExceedsBlobUploadLimit)
		publicationPrivacyAssertNoCanaryText(t, canaries, err.Error())
		assert.Empty(t, fixture.pds.StoredBlobCIDs())
		assert.Empty(t, fixture.pds.CurrentRevision().Records)
		require.Empty(t, publicationPrivacyScan(t, fixture, canaries.allCanaries))
		assert.False(t, fixture.floorPresent(t), "a rejected upload must not advance the accepted floor")
		attempt := fixture.attempt(t, result.Attempt.ID)
		assert.Equal(t, publicationstate.AttemptRetiredAbandoned, attempt.Lifecycle)
		_, retained := fixture.records.retained(result.Attempt.ID)
		assert.False(t, retained, "a pre-submission failure must retire the retained proposal record")
	})

	t.Run("record batch rejected", func(t *testing.T) {
		nonce := publicationPrivacyNonce(t)
		fixture := newPublicationPrivacyFixture(t, publicationPrivacyReviewAnchor(nonce), nil)
		trackedPath := fixture.writeTrackedFile(t, publicationPrivacyFileContent(nonce))
		canaries := newPublicationPrivacyCanaries(nonce, trackedPath)
		fixture.pds.SetHooks(
			atprototest.MemoryPDSHooks{
				RejectNextApplyWritesStatus: 400,
				RejectNextApplyWritesCode:   "InvalidRecord",
			},
		)

		result, candidate, err := fixture.publishRejected(t)
		require.Error(t, err, "a rejected record batch must refuse the publication")
		publicationPrivacyAssertTypedFailure(t, err, "submission", "submission_rejected")
		require.ErrorIs(t, err, service.ErrMaterialSubmissionRejected)
		require.ErrorIs(t, err, atproto.ErrCandidateMayBeDisclosed)
		require.NotErrorIs(t, err, atproto.ErrAmbiguousTransport)
		publicationPrivacyAssertNoCanaryText(t, canaries, err.Error())

		blobs := candidateBlobs(t, candidate)
		stored := fixture.pds.StoredBlobCIDs()
		require.Len(t, stored, len(blobs))
		identifiers := make([]string, 0, len(blobs))
		for _, blob := range blobs {
			identifiers = append(identifiers, publicationPrivacyBlobIdentifier(t, blob.CID))
		}
		assert.ElementsMatch(t, identifiers, stored)
		for index, blob := range blobs {
			assert.False(t, fixture.pds.BlobIsLive(stored[index]), "the retained plaintext blob must be unattached")
			assert.False(
				t,
				fixture.pds.PubliclyRetrievable(stored[index]),
				"the synthetic provider serves only referenced blobs",
			)
			_, fetchErr := fixture.blobs.FetchBlob(
				context.Background(),
				publicationPrivacyDID,
				blob.CID,
				int64(blob.Size),
			)
			require.ErrorIs(t, fetchErr, atproto.ErrReadBlobMissing)
		}

		assert.Empty(t, fixture.pds.CurrentRevision().Records, "a rejected batch must leave no record behind")
		require.Empty(t, publicationPrivacyScan(t, fixture, canaries.allCanaries))
		assert.False(t, fixture.floorPresent(t), "a rejected batch must not advance the accepted floor")
		attempt := fixture.attempt(t, result.Attempt.ID)
		assert.Equal(t, publicationstate.AttemptRetiredAbandoned, attempt.Lifecycle)
		assert.Equal(t, publicationstate.OutcomeRejected, attempt.Outcome)
		_, active, activeErr := fixture.store.ActiveAttempt(context.Background())
		require.NoError(t, activeErr)
		assert.False(t, active, "a definite provider refusal left the attempt blocking")
		_, custodyErr := fixture.store.ReadCandidate(context.Background(), result.Attempt.ID)
		var custodyState *publicationstate.Error
		require.ErrorAs(t, custodyErr, &custodyState)
		assert.Equal(t, publicationstate.ReasonCandidateMissing, custodyState.Reason())
	})

	t.Run("record batch rejected after blob processing", func(t *testing.T) {
		nonce := publicationPrivacyNonce(t)
		fixture := newPublicationPrivacyFixture(t, publicationPrivacyReviewAnchor(nonce), nil)
		trackedPath := fixture.writeTrackedFile(t, publicationPrivacyFileContent(nonce))
		canaries := newPublicationPrivacyCanaries(nonce, trackedPath)
		fixture.pds.SetHooks(
			atprototest.MemoryPDSHooks{RejectNextApplyWritesAfterBlobProcessing: true},
		)

		result, candidate, err := fixture.publishRejected(t)
		require.Error(t, err, "a rejected record batch must refuse the publication")
		publicationPrivacyAssertTypedFailure(t, err, "submission", "submission_rejected")
		require.ErrorIs(t, err, atproto.ErrPublicationQuota)
		require.ErrorIs(t, err, service.ErrMaterialSubmissionRejected)
		require.ErrorIs(t, err, atproto.ErrCandidateMayBeDisclosed)
		publicationPrivacyAssertNoCanaryText(t, canaries, err.Error())

		blobs := candidateBlobs(t, candidate)
		stored := fixture.pds.StoredBlobCIDs()
		require.Len(t, stored, len(blobs))
		identifiers := make([]string, 0, len(blobs))
		for _, blob := range blobs {
			identifiers = append(identifiers, publicationPrivacyBlobIdentifier(t, blob.CID))
		}
		assert.ElementsMatch(t, identifiers, stored)
		for index, blob := range blobs {
			assert.False(t, fixture.pds.BlobIsLive(stored[index]))
			assert.True(
				t,
				fixture.pds.PubliclyRetrievable(stored[index]),
				"the modeled post-processing window must expose the unattached plaintext blob",
			)
			retrieved, fetchErr := fixture.blobs.FetchBlob(
				context.Background(),
				publicationPrivacyDID,
				blob.CID,
				int64(blob.Size),
			)
			require.NoError(t, fetchErr)
			assert.Equal(t, blob.Size, uint64(len(retrieved)))
		}
		assert.Empty(t, fixture.pds.CurrentRevision().Records, "a rejected batch must leave no record behind")
		assert.False(t, fixture.floorPresent(t), "a rejected batch must not advance the accepted floor")
		attempt := fixture.attempt(t, result.Attempt.ID)
		assert.Equal(t, publicationstate.AttemptRetiredAbandoned, attempt.Lifecycle)
		assert.Equal(t, publicationstate.OutcomeRejected, attempt.Outcome)
	})

	t.Run("ambiguous commit response", func(t *testing.T) {
		nonce := publicationPrivacyNonce(t)
		fixture := newPublicationPrivacyFixture(t, publicationPrivacyReviewAnchor(nonce), nil)
		trackedPath := fixture.writeTrackedFile(t, publicationPrivacyFileContent(nonce))
		canaries := newPublicationPrivacyCanaries(nonce, trackedPath)
		fixture.pds.SetHooks(
			atprototest.MemoryPDSHooks{LoseNextApplyWritesResponse: true},
		)

		result, _, err := fixture.publish(t)
		require.Error(t, err, "a lost commit response must not be reported as a success")
		publicationPrivacyAssertTypedFailure(t, err, "submission", "submission_unresolved")
		require.ErrorIs(t, err, atproto.ErrAmbiguousTransport)
		require.ErrorIs(t, err, atproto.ErrCandidateMayBeDisclosed)
		publicationPrivacyAssertNoCanaryText(t, canaries, err.Error())

		assert.Equal(t, []string{
			publication.HeadNSID + "/self",
			publication.SnapshotNSID + "/0000000000000000",
		}, publicationPrivacyRecordKeys(t, fixture.pds))
		require.Empty(
			t,
			publicationPrivacyScan(t, fixture, canaries.allCanaries),
			"candidate bytes surfaced in published repository records",
		)
		publicationPrivacyAssertRecordSchema(t, fixture)
		publicationPrivacyAssertBlobReferences(t, fixture)
		terminal := fixture.terminalSnapshot(t)
		publicationPrivacyAssertBlobPacking(
			t,
			fixture,
			terminal,
			[][]byte{canaries.plaintext, canaries.credential},
		)
		assert.False(t, fixture.floorPresent(t), "an ambiguous commit must not advance the accepted floor")
		attempt := fixture.attempt(t, result.Attempt.ID)
		assert.Equal(t, publicationstate.AttemptMayHaveSubmitted, attempt.Lifecycle)
		assert.Equal(t, publicationstate.OutcomeUnresolved, attempt.Outcome)
	})
}

func publicationPrivacyLegacyCollections() []string {
	return []string{
		atproto.VaultSnapshotNSID, atproto.VaultHeadNSID, atproto.VaultControlNSID,
		atproto.VaultPolicyNSID, atproto.VaultCertificateNSID, atproto.VaultCheckpointNSID,
		atproto.VaultAttestationNSID,
	}
}

func publicationPrivacySnapshotRecordKeys() []string {
	return []string{
		"$type",
		"base",
		"blob",
		"entries",
		"form",
		"id",
		"key",
		"kind",
		"mimeType",
		"mode",
		"parent",
		"path",
		"publicationId",
		"publicationSeq",
		"ref",
		"root",
		"schemaId",
		"schemaVersion",
		"segments",
		"settings",
		"size",
		"source",
		"source_version",
		"state",
		"target",
		"text",
		"type",
		"value",
		"vault",
	}
}

func publicationPrivacyHeadRecordKeys() []string {
	return []string{"$type", "publicationSeq", "schemaVersion", "snapshotCid", "vault"}
}

func publicationPrivacyRecordKeys(t *testing.T, pds *atprototest.MemoryPDS) []string {
	t.Helper()
	keys := make([]string, 0)
	for _, record := range pds.CurrentRevision().Records {
		keys = append(keys, record.Collection+"/"+record.RKey)
	}
	sort.Strings(keys)
	return keys
}

func publicationPrivacyCollections(t *testing.T, pds *atprototest.MemoryPDS) []string {
	t.Helper()
	seen := make(map[string]struct{})
	for _, record := range pds.CurrentRevision().Records {
		seen[record.Collection] = struct{}{}
	}
	collections := make([]string, 0, len(seen))
	for collection := range seen {
		collections = append(collections, collection)
	}
	sort.Strings(collections)
	return collections
}

func publicationPrivacyRecursiveKeys(t *testing.T, data []byte) []string {
	t.Helper()
	object, err := atdata.UnmarshalCBOR(data)
	require.NoError(t, err)
	seen := make(map[string]struct{})
	publicationPrivacyCollectKeys(object, seen)
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func publicationPrivacyCollectKeys(atom any, seen map[string]struct{}) {
	switch value := atom.(type) {
	case map[string]any:
		for key, nested := range value {
			seen[key] = struct{}{}
			publicationPrivacyCollectKeys(nested, seen)
		}
	case []any:
		for _, nested := range value {
			publicationPrivacyCollectKeys(nested, seen)
		}
	case atdata.Blob:
		for _, key := range []string{"$type", "ref", "mimeType", "size"} {
			seen[key] = struct{}{}
		}
	}
}

func publicationPrivacyBlobIdentifier(t *testing.T, blobCID []byte) string {
	t.Helper()
	identifier, err := cid.Cast(blobCID)
	require.NoError(t, err)
	return identifier.String()
}

func publicationPrivacyScan(
	t *testing.T,
	fixture *publicationPrivacyFixture,
	canaries []publicationPrivacyCanary,
) []publicationPrivacyFinding {
	t.Helper()
	findings := make([]publicationPrivacyFinding, 0)
	for _, record := range fixture.pds.CurrentRevision().Records {
		for _, canary := range canaries {
			if bytes.Contains(record.Data, canary.value) {
				findings = append(findings, publicationPrivacyFinding{
					canary:     canary.name,
					collection: record.Collection,
					rkey:       record.RKey,
					surface:    "stored-record-cbor",
				})
			}
		}
	}
	for _, served := range publicationPrivacyServedRecords(t, fixture.pds) {
		for _, canary := range canaries {
			if bytes.Contains(served.value, canary.value) {
				findings = append(findings, publicationPrivacyFinding{
					canary:     canary.name,
					collection: served.collection,
					rkey:       served.rkey,
					surface:    "served-record-json",
				})
			}
		}
	}
	return findings
}

func publicationPrivacyFindingNames(findings []publicationPrivacyFinding) []string {
	names := make([]string, 0, len(findings))
	for _, finding := range findings {
		names = append(names, finding.canary+"@"+finding.collection+"/"+finding.rkey)
	}
	sort.Strings(names)
	return names
}

func publicationPrivacyServedRecords(t *testing.T, pds *atprototest.MemoryPDS) []publicationPrivacyServedRecord {
	t.Helper()
	served := make([]publicationPrivacyServedRecord, 0)
	for _, collection := range publicationPrivacyCollections(t, pds) {
		status, body, err := pds.Do(context.Background(), "GET", publicationPrivacyListURL, url.Values{
			"repo": {publicationPrivacyDID}, "collection": {collection}, "limit": {"100"},
		}, nil, "")
		require.NoError(t, err)
		require.Equal(t, 200, status, "listRecords for collection %s returned %d", collection, status)
		var listing struct {
			Records []struct {
				URI   string          `json:"uri"`
				Value json.RawMessage `json:"value"`
			} `json:"records"`
		}
		require.NoError(t, json.Unmarshal(body, &listing))
		for _, record := range listing.Records {
			index := strings.LastIndex(record.URI, "/")
			require.NotEqual(t, -1, index, "listRecords returned a record without a record key: %s", record.URI)
			served = append(served, publicationPrivacyServedRecord{
				collection: collection, rkey: record.URI[index+1:], value: record.Value,
			})
		}
	}
	return served
}

func publicationPrivacyAssertRecordSchema(t *testing.T, fixture *publicationPrivacyFixture) {
	t.Helper()
	records := fixture.pds.CurrentRevision().Records
	require.NotEmpty(t, records)
	for _, record := range records {
		switch record.Collection {
		case publication.SnapshotNSID:
			keys := publicationPrivacyRecursiveKeys(t, record.Data)
			assert.Subset(
				t,
				publicationPrivacySnapshotRecordKeys(),
				keys,
				"recursive key inventory of %s/%s",
				record.Collection,
				record.RKey,
			)
			assert.NotContains(t, keys, "content", "a snapshot record carried a plaintext field")
		case publication.HeadNSID:
			assert.Equal(
				t,
				publicationPrivacyHeadRecordKeys(),
				publicationPrivacyRecursiveKeys(t, record.Data),
				"recursive key inventory of %s/%s",
				record.Collection,
				record.RKey,
			)
		default:
			assert.Fail(t, "unexpected publication collection", record.Collection)
		}
	}
}

func publicationPrivacyAssertBlobReferences(t *testing.T, fixture *publicationPrivacyFixture) {
	t.Helper()
	stored := fixture.pds.StoredBlobCIDs()
	referenced := make([]string, 0)
	seen := make(map[string]struct{})
	for _, record := range fixture.pds.CurrentRevision().Records {
		object, err := atdata.UnmarshalCBOR(record.Data)
		require.NoError(t, err)
		for _, blob := range atdata.ExtractBlobs(object) {
			identifier := blob.Ref.String()
			if _, exists := seen[identifier]; !exists {
				seen[identifier] = struct{}{}
				referenced = append(referenced, identifier)
			}
			assert.Contains(
				t,
				stored,
				identifier,
				"record %s/%s references a blob the publish never uploaded",
				record.Collection,
				record.RKey,
			)
			assert.True(
				t,
				fixture.pds.BlobIsLive(identifier),
				"record %s/%s references a blob the provider does not serve as live",
				record.Collection,
				record.RKey,
			)
			payload := fixture.fetchBlob(t, blob.Ref.CID().Bytes(), blob.Size)
			assert.Len(t, payload, int(blob.Size))
			payloadIdentifier, err := publication.RawPayloadCID(payload)
			require.NoError(t, err)
			assert.True(
				t,
				bytes.Equal(blob.Ref.CID().Bytes(), payloadIdentifier),
				"record %s/%s references a blob whose bytes hash to a different CID",
				record.Collection,
				record.RKey,
			)
		}
	}
	require.NotEmpty(t, referenced)
	sort.Strings(referenced)
	assert.Equal(t, referenced, stored, "the provider stores blobs that no published record references")

	terminal := fixture.terminalSnapshot(t)
	terminalKey, err := publication.SequenceKey(terminal.PublicationSeq)
	require.NoError(t, err)
	headRaw := fixture.record(t, publication.HeadNSID, "self")
	snapshotRaw := fixture.record(t, publication.SnapshotNSID, terminalKey)
	head, err := publication.DecodeHead(headRaw)
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotRaw)
	require.NoError(t, err)
	assert.Equal(t, snapshotCID, head.SnapshotCID)
	require.NoError(t, publication.VerifyHeadBinding(headRaw, snapshotRaw, terminalKey))
}

func publicationPrivacyAssertBlobPacking(
	t *testing.T,
	fixture *publicationPrivacyFixture,
	record publication.SnapshotRecord,
	contained [][]byte,
) {
	t.Helper()
	fetched := make([][]byte, 0)
	for _, segment := range record.Segments {
		switch segment.Form {
		case publication.SegmentFormPacked:
			payload := fixture.fetchBlob(t, segment.Blob.CID, int64(segment.Blob.Size))
			assert.Len(
				t,
				payload, int(segment.Blob.Size),
				"the provider blob size disagrees with the published blob reference",
			)
			require.NoError(t, publication.VerifyPayload(payload, segment.Blob))
			decoded, err := publication.DecodePayload(payload, segment.Blob)
			require.NoError(t, err)
			repacked, err := vault.Pack(decoded)
			require.NoError(t, err)
			assert.True(
				t,
				bytes.Equal(payload, repacked.Payload),
				"the provider blob is not the canonical packed payload for the published snapshot",
			)
			assert.Equal(t, len(decoded.Entries), repacked.EntryCount)
			fetched = append(fetched, payload)
		case publication.SegmentFormEntries:
			for _, entry := range segment.Entries {
				payload := fixture.fetchBlob(t, entry.Blob.CID, int64(entry.Size))
				require.NoError(t, publication.VerifyPayload(payload, entry.Blob))
				fetched = append(fetched, payload)
			}
		}
	}
	for _, canary := range contained {
		matched := false
		for _, payload := range fetched {
			if bytes.Contains(payload, canary) {
				matched = true
				break
			}
		}
		assert.True(t, matched, "the provider blobs do not hold the published plaintext")
	}
}

func publicationPrivacyAssertRetainedReviewHasNoCandidateBytes(
	t *testing.T,
	preparation service.PublicationPushPreparation,
	canaries publicationPrivacyCanaries,
) {
	t.Helper()
	encoded, err := json.Marshal(preparation.Record)
	require.NoError(t, err)
	publicationPrivacyAssertNoCanaryText(t, canaries, string(encoded))
}

func publicationPrivacyAssertTypedFailure(t *testing.T, err error, stage, reason string) {
	t.Helper()
	require.ErrorIs(t, err, service.ErrPublishMaterial)
	var failure interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &failure)
	assert.Equal(t, stage, failure.Stage())
	assert.Equal(t, reason, failure.Reason())
}

func publicationPrivacyAssertNoCanaryText(t *testing.T, canaries publicationPrivacyCanaries, text string) {
	t.Helper()
	for _, canary := range canaries.materialCanaries {
		assert.NotContains(
			t,
			text, string(canary.value),
			"the %s canary surfaced through a Dottie surface",
			canary.name,
		)
	}
}

type publicationPrivacyLeakingTransport struct {
	base    atproto.Transport
	control publicationPrivacyScanControl
}

func (transport publicationPrivacyLeakingTransport) Do(
	ctx context.Context,
	method, endpoint string,
	query url.Values,
	body []byte,
	contentType string,
) (int, []byte, error) {
	if endpoint == publicationPrivacyApplyURL {
		body = publicationPrivacyInjectCanary(body, transport.control)
	}
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport publicationPrivacyLeakingTransport) OpenStream(
	ctx context.Context,
	endpoint string,
	query url.Values,
) (int, io.ReadCloser, error) {
	return transport.base.OpenStream(ctx, endpoint, query)
}

func publicationPrivacyInjectCanary(body []byte, control publicationPrivacyScanControl) []byte {
	var request struct {
		Repo       string `json:"repo"`
		SwapCommit string `json:"swapCommit"`
		Writes     []struct {
			Type       string          `json:"$type"`
			Collection string          `json:"collection"`
			RKey       string          `json:"rkey"`
			Value      json.RawMessage `json:"value"`
		} `json:"writes"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return body
	}
	injected := false
	for index, write := range request.Writes {
		if write.Collection != control.collection {
			continue
		}
		value := make(map[string]any)
		if err := json.Unmarshal(write.Value, &value); err != nil {
			continue
		}
		value[control.field] = control.value
		encoded, err := json.Marshal(value)
		if err != nil {
			continue
		}
		request.Writes[index].Value = encoded
		injected = true
	}
	if !injected {
		return body
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return body
	}
	return encoded
}

type publicationPrivacyProposalStore struct {
	mu      sync.Mutex
	entries map[[16]byte]service.PublicationProposalRecord
}

func newPublicationPrivacyProposalStore() *publicationPrivacyProposalStore {
	return &publicationPrivacyProposalStore{entries: make(map[[16]byte]service.PublicationProposalRecord)}
}

func (store *publicationPrivacyProposalStore) List(context.Context) ([]service.PublicationProposalRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]service.PublicationProposalRecord, 0, len(store.entries))
	for _, record := range store.entries {
		records = append(records, record)
	}
	return records, nil
}

func (store *publicationPrivacyProposalStore) Issue(_ context.Context, record service.PublicationProposalRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.entries[record.PublicationID] = record
	return nil
}

func (store *publicationPrivacyProposalStore) Consume(_ context.Context, publicationID [16]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.entries[publicationID]
	if !found {
		return service.ErrPublicationProposalAbsent
	}
	record.Consumed = true
	store.entries[publicationID] = record
	return nil
}

func (store *publicationPrivacyProposalStore) Delete(_ context.Context, publicationID [16]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.entries, publicationID)
	return nil
}

func (store *publicationPrivacyProposalStore) retained(
	publicationID [16]byte,
) (service.PublicationProposalRecord, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.entries[publicationID]
	return record, found
}

type publicationPrivacyReviews struct {
	review publicationstate.LocalReviewContext
}

func (reviews publicationPrivacyReviews) Acquire(
	context.Context,
) (publicationstate.LocalReviewContext, config.Token, service.ConfigGuard, error) {
	return reviews.review, config.Token{}, publicationPrivacyGuard{}, nil
}

type publicationPrivacyGuard struct{}

func (publicationPrivacyGuard) Release() {}

func TestPublicationV2FileSetPrivacyGate(t *testing.T) {
	nonce := publicationPrivacyNonce(t)
	fixture := newPublicationPrivacyFixture(t, publicationPrivacyReviewAnchor(nonce), nil)
	fixture.configuration.Targets = fixture.configuration.Targets[:1]
	content := publicationPrivacyFileContent(nonce)
	trackedPath := fixture.writeTrackedFile(t, content)
	canaries := newPublicationPrivacyCanaries(nonce, trackedPath)

	result, preparation, err := fixture.publish(t)
	require.NoError(t, err)
	require.NotEmpty(t, floorFileSet(result.Floor))
	record := fixture.terminalSnapshot(t)
	assert.Equal(t, publication.PayloadFormFileSet, record.PayloadForm())
	require.Len(t, recordFileSetEntries(record), 1)
	assert.Equal(t, publicationPrivacyTrackedFile, recordFileSetEntries(record)[0].Path)
	assert.Equal(t, uint32(0o600), recordFileSetEntries(record)[0].Mode)
	assert.Equal(t, uint64(len(content)), recordFileSetEntries(record)[0].Size)
	assert.NotEqual(t, [32]byte{}, preparation.Record.PayloadsDigest)

	head, err := publication.DecodeHead(result.Floor.Head)
	require.NoError(t, err)
	assert.Equal(t, result.Floor.RecordCID, head.SnapshotCID)
	assert.Empty(t, floorPackedBlob(result.Floor).CID)
	assert.Zero(t, floorPackedBlob(result.Floor).Size)

	for _, stored := range fixture.pds.CurrentRevision().Records {
		for _, canary := range canaries.allCanaries {
			assert.NotContains(t, string(stored.Data), string(canary.value), "file-set record exposed candidate bytes")
		}
	}
	encoded, err := publication.RecordToJSON(fixture.terminalRaw(t))
	require.NoError(t, err)
	for _, canary := range canaries.allCanaries {
		assert.NotContains(t, string(encoded), string(canary.value), "file-set record JSON exposed candidate bytes")
	}
	assert.Contains(t, string(encoded), `"path":"`+publicationPrivacyTrackedFile+`"`)
	assert.Contains(t, string(encoded), `"mode":384`)
	assert.Equal(
		t,
		[]string{publicationPrivacyBlobIdentifier(t, recordFileSetEntries(record)[0].Blob.CID)},
		fixture.pds.StoredBlobCIDs(),
	)
}
