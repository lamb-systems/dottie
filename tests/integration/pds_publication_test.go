package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

func TestCleanupPublicationLiveRecordsAcceptsRecordNotFound(t *testing.T) {
	t.Run("record was never created", func(t *testing.T) {
		transport := &publicationCleanupTransport{
			getStatuses: []int{http.StatusBadRequest},
			getBodies:   [][]byte{[]byte(`{"error":"RecordNotFound"}`)},
		}
		cleanupPublicationLiveRecords(
			t,
			transport,
			"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
			[]string{"systems.lamb.dottie.vaultHead/self"},
		)
		assert.Equal(t, []string{"GET com.atproto.repo.getRecord"}, transport.calls)
	})

	t.Run("deletion is verified with RecordNotFound", func(t *testing.T) {
		transport := &publicationCleanupTransport{
			getStatuses: []int{http.StatusOK, http.StatusBadRequest},
			getBodies:   [][]byte{[]byte(`{"value":{}}`), []byte(`{"error":"RecordNotFound"}`)},
		}
		cleanupPublicationLiveRecords(
			t,
			transport,
			"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
			[]string{"systems.lamb.dottie.vaultHead/self"},
		)
		assert.Equal(t, []string{
			"GET com.atproto.repo.getRecord",
			"POST com.atproto.repo.deleteRecord",
			"GET com.atproto.repo.getRecord",
		}, transport.calls)
	})
}

type publicationCleanupTransport struct {
	getStatuses []int
	getBodies   [][]byte
	getCalls    int
	calls       []string
}

func (transport *publicationCleanupTransport) Do(
	_ context.Context,
	method, endpoint string,
	_ url.Values,
	_ []byte,
	_ string,
) (int, []byte, error) {
	transport.calls = append(transport.calls, method+" "+endpoint)
	if endpoint == "com.atproto.repo.getRecord" {
		index := transport.getCalls
		transport.getCalls++
		return transport.getStatuses[index], bytes.Clone(transport.getBodies[index]), nil
	}
	if endpoint == "com.atproto.repo.deleteRecord" {
		return http.StatusOK, nil, nil
	}
	return 0, nil, errors.New("unexpected endpoint")
}

func (transport *publicationCleanupTransport) OpenStream(
	context.Context,
	string,
	url.Values,
) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("synthetic stream unavailable")
}

func TestLivePublicationRepositoryPrecondition(t *testing.T) {
	did := "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	transport := &liveRepositoryDescriptionTransport{
		status: http.StatusOK,
		body: []byte(
			`{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","collections":["app.bsky.graph.follow","app.bsky.actor.profile"]}`,
		),
	}
	skipReason, err := livePublicationRepositoryPrecondition(context.Background(), transport, did)
	require.NoError(t, err)
	assert.Equal(
		t,
		"repository is not empty; collections: app.bsky.actor.profile, app.bsky.graph.follow; genesis requires an empty repository; a skipped gate is not provider evidence",
		skipReason,
	)
	assert.Equal(t, http.MethodGet, transport.method)
	assert.Equal(t, "com.atproto.repo.describeRepo", transport.endpoint)
	assert.Equal(t, did, transport.query.Get("repo"))

	transport = &liveRepositoryDescriptionTransport{
		status: http.StatusOK,
		body:   []byte(`{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","collections":[]}`),
	}
	skipReason, err = livePublicationRepositoryPrecondition(context.Background(), transport, did)
	require.NoError(t, err)
	assert.Empty(t, skipReason)
}

type liveRepositoryDescriptionTransport struct {
	status   int
	body     []byte
	method   string
	endpoint string
	query    url.Values
}

func (transport *liveRepositoryDescriptionTransport) Do(
	_ context.Context,
	method, endpoint string,
	query url.Values,
	_ []byte,
	_ string,
) (int, []byte, error) {
	transport.method = method
	transport.endpoint = endpoint
	transport.query = query
	return transport.status, bytes.Clone(transport.body), nil
}

func (transport *liveRepositoryDescriptionTransport) OpenStream(
	context.Context,
	string,
	url.Values,
) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("synthetic stream unavailable")
}

type livePublicationRunManifest struct {
	RunID            string   `json:"run_id"`
	Provider         string   `json:"provider"`
	Handle           string   `json:"handle"`
	Collections      []string `json:"collections"`
	RecordTargets    []string `json:"record_targets,omitempty"`
	UploadedBlobCIDs []string `json:"uploaded_blob_cids"`
}

type livePublicationArtifact struct {
	RunID                  string   `json:"run_id"`
	Provider               string   `json:"provider"`
	Criterion              string   `json:"criterion"`
	Outcome                string   `json:"outcome"`
	RecordCount            int      `json:"record_count"`
	EnumeratedLiveCIDCount int      `json:"enumerated_live_cid_count"`
	UploadedCIDCount       int      `json:"uploaded_cid_count"`
	RetainedSetEvidence    string   `json:"retained_set_evidence"`
	StandingLimits         []string `json:"standing_limits"`
	BlobRetentionNote      string   `json:"blob_retention_note"`
}

func newLivePublicationArtifact(runID, provider string) livePublicationArtifact {
	return livePublicationArtifact{
		RunID:               runID,
		Provider:            provider,
		Criterion:           "live publication privacy audited",
		RetainedSetEvidence: "retained_set=unobservable",
		StandingLimits: []string{
			"record reads are public", "blob fetches are public", "blob enumeration is authenticated",
			"hosted logs and server storage are unobservable", "provider blobs cannot be deleted",
		},
		BlobRetentionNote: "A successful live privacy run leaves its uploaded ciphertext blobs on the provider permanently because the provider exposes no blob delete; this is expected and recorded rather than cleaned.",
	}
}

func writeLivePublicationArtifact(directory string, artifact livePublicationArtifact) (string, error) {
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, "publication-privacy.json")
	if err := writeAtomicLiveFile(path, encoded); err != nil {
		return "", err
	}
	return path, nil
}

func writeLivePublicationManifest(path string, manifest livePublicationRunManifest) error {
	if manifest.UploadedBlobCIDs == nil {
		manifest.UploadedBlobCIDs = []string{}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeAtomicLiveFile(path, encoded)
}

func persistLivePublicationUpload(path string, manifest *livePublicationRunManifest, cid string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("uploaded blob CID cannot be recorded because the run manifest does not exist: %w", err)
	}
	if !containsString(manifest.UploadedBlobCIDs, cid) {
		manifest.UploadedBlobCIDs = append(manifest.UploadedBlobCIDs, cid)
	}
	return writeLivePublicationManifest(path, *manifest)
}

func writeAtomicLiveFile(path string, contents []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".dottie-live-write-")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func cleanupPublicationLiveRecords(t *testing.T, transport atproto.Transport, did string, targets []string) {
	t.Helper()
	for _, target := range targets {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) != 2 {
			assert.Fail(t, "live run manifest contains an invalid record target")
			continue
		}
		collection, rkey := parts[0], parts[1]
		query := url.Values{"repo": {did}, "collection": {collection}, "rkey": {rkey}}
		status, responseBody, err := transport.Do(
			context.Background(),
			"GET",
			"com.atproto.repo.getRecord",
			query,
			nil,
			"",
		)
		if err != nil {
			assert.Fail(t, "live record cleanup lookup failed")
			continue
		}
		if isPDSRecordAbsent(status, responseBody) {
			continue
		}
		if status != 200 {
			assert.Fail(t, "live record cleanup lookup returned an unexpected status")
			continue
		}
		body, err := json.Marshal(map[string]string{"repo": did, "collection": collection, "rkey": rkey})
		if err != nil {
			assert.Fail(t, "live record cleanup request could not be encoded")
			continue
		}
		status, _, err = transport.Do(
			context.Background(),
			"POST",
			"com.atproto.repo.deleteRecord",
			nil,
			body,
			"application/json",
		)
		assert.True(t, err == nil && status >= 200 && status < 300, "live record cleanup request did not commit")
		status, responseBody, err = transport.Do(
			context.Background(),
			"GET",
			"com.atproto.repo.getRecord",
			query,
			nil,
			"",
		)
		assert.True(t, err == nil && isPDSRecordAbsent(status, responseBody), "live record cleanup was not verified")
	}
}

func livePublicationRepositoryPrecondition(
	ctx context.Context,
	transport atproto.Transport,
	did string,
) (string, error) {
	status, body, err := transport.Do(ctx, "GET", "com.atproto.repo.describeRepo", url.Values{"repo": {did}}, nil, "")
	if err != nil {
		return "", errors.New("live repository description failed")
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("live repository description returned status %d", status)
	}
	var description struct {
		Collections *[]string `json:"collections"`
	}
	if err := json.Unmarshal(body, &description); err != nil {
		return "", errors.New("live repository description was invalid")
	}
	if description.Collections == nil {
		return "", errors.New("live repository description omitted collections")
	}
	if len(*description.Collections) == 0 {
		return "", nil
	}
	collections := append([]string(nil), (*description.Collections)...)
	sort.Strings(collections)
	return "repository is not empty; collections: " + strings.Join(
		collections,
		", ",
	) + "; genesis requires an empty repository; a skipped gate is not provider evidence", nil
}

type publicationCIDTracker struct {
	base         atproto.Transport
	uploaded     []string
	beforeWrite  func([]byte) error
	manifestPath string
	onUpload     func(string) error
}

func (tracker *publicationCIDTracker) Do(
	ctx context.Context,
	method, endpoint string,
	query url.Values,
	body []byte,
	contentType string,
) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" && tracker.beforeWrite != nil {
		if err := tracker.beforeWrite(body); err != nil {
			return 0, nil, err
		}
	}
	if endpoint == "com.atproto.repo.uploadBlob" && tracker.manifestPath != "" {
		if tracker.onUpload == nil {
			return 0, nil, errors.New("publication blob upload has no run-manifest persistence callback")
		}
		if _, err := os.Stat(tracker.manifestPath); err != nil {
			return 0, nil, fmt.Errorf("publication blob upload attempted before run manifest exists: %w", err)
		}
	}
	status, response, err := tracker.base.Do(ctx, method, endpoint, query, body, contentType)
	if endpoint == "com.atproto.repo.uploadBlob" && err == nil && status >= 200 && status < 300 {
		blobCID := uploadedCID(response)
		if blobCID == "" {
			return status, response, errors.New("successful publication blob upload omitted its CID")
		}
		if !containsString(tracker.uploaded, blobCID) {
			tracker.uploaded = append(tracker.uploaded, blobCID)
			if tracker.onUpload != nil {
				if err := tracker.onUpload(blobCID); err != nil {
					return status, response, fmt.Errorf("persist uploaded publication blob CID: %w", err)
				}
			}
		}
	}
	return status, response, err
}

func (tracker *publicationCIDTracker) OpenStream(
	ctx context.Context,
	endpoint string,
	query url.Values,
) (int, io.ReadCloser, error) {
	return tracker.base.OpenStream(ctx, endpoint, query)
}

type publicationUploadTestTransport struct {
	response []byte
	calls    int
}

func (transport *publicationUploadTestTransport) Do(
	context.Context,
	string,
	string,
	url.Values,
	[]byte,
	string,
) (int, []byte, error) {
	transport.calls++
	return http.StatusOK, bytes.Clone(transport.response), nil
}

func (*publicationUploadTestTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("synthetic stream unavailable")
}

func TestLivePublicationEvidencePersistsUploadedCIDsAndSuccessArtifact(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "run-manifest.json")
	manifest := livePublicationRunManifest{
		RunID: "offline-run-id", Provider: "Bluesky-hosted", Collections: []string{},
		RecordTargets: []string{}, UploadedBlobCIDs: []string{},
	}
	require.NoError(t, writeLivePublicationManifest(manifestPath, manifest))
	transport := &publicationUploadTestTransport{response: []byte(`{"blob":{"ref":{"$link":"bafycid-one"}}}`)}
	tracker := &publicationCIDTracker{base: transport, manifestPath: manifestPath}
	tracker.onUpload = func(cid string) error {
		return persistLivePublicationUpload(manifestPath, &manifest, cid)
	}
	for _, cid := range []string{"bafycid-one", "bafycid-two", "bafycid-one"} {
		transport.response = []byte(fmt.Sprintf(`{"blob":{"ref":{"$link":%q}}}`, cid))
		status, _, err := tracker.Do(
			context.Background(),
			"POST",
			"com.atproto.repo.uploadBlob",
			nil,
			nil,
			"application/octet-stream",
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	var persisted livePublicationRunManifest
	require.NoError(t, json.Unmarshal(manifestBytes, &persisted))
	require.Equal(t, []string{"bafycid-one", "bafycid-two"}, persisted.UploadedBlobCIDs)
	manifestInfo, err := os.Stat(manifestPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), manifestInfo.Mode().Perm())

	artifact := newLivePublicationArtifact("offline-run-id", "Bluesky-hosted")
	artifact.Outcome = "passed"
	artifact.RecordCount = 7
	artifact.EnumeratedLiveCIDCount = 2
	artifact.UploadedCIDCount = len(tracker.uploaded)
	artifactPath, err := writeLivePublicationArtifact(directory, artifact)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(directory, "publication-privacy.json"), artifactPath)
	require.FileExists(t, artifactPath)
	artifactBytes, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	var persistedArtifact livePublicationArtifact
	require.NoError(t, json.Unmarshal(artifactBytes, &persistedArtifact))
	require.Equal(t, "offline-run-id", persistedArtifact.RunID)
	require.Equal(t, "Bluesky-hosted", persistedArtifact.Provider)
	require.Equal(t, "live publication privacy audited", persistedArtifact.Criterion)
	require.Equal(t, "passed", persistedArtifact.Outcome)
	require.Equal(t, 7, persistedArtifact.RecordCount)
	require.Equal(t, 2, persistedArtifact.EnumeratedLiveCIDCount)
	require.Equal(t, 2, persistedArtifact.UploadedCIDCount)
	require.Equal(t, "retained_set=unobservable", persistedArtifact.RetainedSetEvidence)
	limits := strings.Join(persistedArtifact.StandingLimits, "; ")
	for _, limit := range []string{"record reads are public", "blob fetches are public", "blob enumeration is authenticated", "hosted logs and server storage are unobservable", "provider blobs cannot be deleted"} {
		require.Contains(t, limits, limit)
	}
	require.Contains(t, persistedArtifact.BlobRetentionNote, "permanently")
	require.Contains(t, persistedArtifact.BlobRetentionNote, "expected and recorded rather than cleaned")
	require.NotContains(t, string(artifactBytes), "bafycid-one")
	require.NotContains(t, string(artifactBytes), directory)
	artifactInfo, err := os.Stat(artifactPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), artifactInfo.Mode().Perm())

	missingTransport := &publicationUploadTestTransport{response: transport.response}
	missingTracker := &publicationCIDTracker{
		base: missingTransport, manifestPath: filepath.Join(directory, "missing-manifest.json"),
		onUpload: func(_ string) error { return nil },
	}
	_, _, err = missingTracker.Do(
		context.Background(),
		"POST",
		"com.atproto.repo.uploadBlob",
		nil,
		nil,
		"application/octet-stream",
	)
	require.ErrorContains(t, err, "attempted before run manifest exists")
	require.Zero(t, missingTransport.calls)
}

func containsString(values []string, value string) bool {
	return slices.Contains(values, value)
}
