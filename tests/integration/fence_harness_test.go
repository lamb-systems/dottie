package integration

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fenceSnapshotCollection = "systems.lamb.dottie.vaultSnapshot"
	fenceHeadCollection     = "systems.lamb.dottie.vaultHead"
	fenceControlCollection  = "systems.lamb.dottie.vaultControl"
)

type fenceCreatedRecord struct {
	collection string
	rkey       string
}

type fenceSnapshotFixture struct {
	Type      string          `json:"$type"`
	Probe     string          `json:"probe"`
	Blob      json.RawMessage `json:"blob"`
	CreatedAt string          `json:"createdAt"`
}

type fenceHeadFixture struct {
	Type         string `json:"$type"`
	SnapshotRKey string `json:"snapshotRkey"`
	SnapshotCID  string `json:"snapshotCid"`
	UpdatedAt    string `json:"updatedAt"`
}

type fenceControlDevice struct {
	DID  string `json:"did"`
	Role string `json:"role"`
}

type fenceControlFixture struct {
	Type        string               `json:"$type"`
	Devices     []fenceControlDevice `json:"devices"`
	PolicyEpoch int                  `json:"policyEpoch"`
	UpdatedAt   string               `json:"updatedAt"`
}

type fenceDeleteInput struct {
	Repo       string `json:"repo"`
	SwapCommit string `json:"swapCommit"`
	Writes     []struct {
		Type       string `json:"$type"`
		Collection string `json:"collection"`
		RKey       string `json:"rkey"`
	} `json:"writes"`
}

type fenceInterleavingTransport struct {
	base  atproto.Transport
	hook  func() error
	calls int
}

func (t *fenceInterleavingTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	return t.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (t *fenceInterleavingTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	t.calls++
	if t.hook != nil {
		if err := t.hook(); err != nil {
			return 0, nil, err
		}
	}
	return t.base.OpenStream(ctx, endpoint, query)
}

func TestLiveFence(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_FENCE") != "1" {
		t.Skip("set DOTTIE_LIVE_FENCE=1 with explicit disposable-account authorization to run the publication-fence matrix")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if !allowedPDSHandle(handle) {
		require.True(t, allowedPDSHandle(handle), "DOTTIE_HANDLE %q is not in the live PDS disposable-identity allowlist", handle)
	}
	provider := pdsProviderName(handle)
	keyring, err := platform.NewKeyring()
	if err != nil {
		require.NoError(t, err, "open Secret Service keyring: %v", err)
	}
	defer keyring.Close()
	client, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	if err != nil {
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	identity, err := client.Discover(ctx, handle)
	if err != nil {
		pdsRecordFailure(t, provider, "unknown", "F04-discovery", redactText(err.Error()))
		require.NoError(t, err, "discover %s: %v", handle, err)
	}
	session, err := client.LoadSession(ctx, identity.DID)
	if err != nil {
		require.NoError(t, err, "load existing scoped OAuth session for %s: %v", handle, err)
	}
	for _, required := range []string{"atproto", "repo:" + fenceSnapshotCollection, "repo:" + fenceHeadCollection, "repo:" + fenceControlCollection, "blob:application/octet-stream"} {
		if !hasPDScope(session.Scopes, required) {
			require.True(t, hasPDScope(session.Scopes, required), "loaded session does not include required scope %q", required)
		}
	}
	auth, err := atproto.NewAuthMethod(client, identity, handle, session)
	if err != nil {
		require.NoError(t, err, "construct PDS auth method: %v", err)
	}
	authenticated, err := newPDSAPIClient(identity.PDS, auth, nil)
	if err != nil {
		require.NoError(t, err)
	}
	anonymous, err := newPDSAPIClient(identity.PDS, nil, nil)
	if err != nil {
		require.NoError(t, err)
	}
	runLiveFence(t, ctx, pdsProviderName(handle), identity, atproto.NewATClientTransport(authenticated), atproto.NewATClientTransport(anonymous))
}

func runLiveFence(t *testing.T, ctx context.Context, provider string, identity atproto.Identity, authenticated, anonymous atproto.Transport) {
	t.Helper()
	reader := atproto.RevisionReader{Transport: authenticated, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID, VerificationMethods: identity.VerificationMethods}
	initial, err := reader.Read(ctx, identity.DID)
	if err != nil {
		require.NoError(t, err, "read initial verified revision: %v", err)
	}
	for _, key := range []atproto.RecordKey{{Collection: fenceHeadCollection, RKey: "self"}, {Collection: fenceControlCollection, RKey: "self"}} {
		if initial.HasRecord(key) {
			require.False(t, initial.HasRecord(key), "refusing to alter pre-existing provisional fixture %s/%s", key.Collection, key.RKey)
		}
	}

	created := make([]fenceCreatedRecord, 0)
	createdSet := make(map[fenceCreatedRecord]struct{})
	track := func(publication atproto.FencedPublication) {
		writes := []atproto.RecordWrite{publication.FirstBlobReference, publication.VaultHead, publication.VaultControl}
		writes = append(writes, publication.Additional...)
		for _, write := range writes {
			key := fenceCreatedRecord{collection: write.Collection, rkey: write.RKey}
			if _, exists := createdSet[key]; !exists {
				createdSet[key] = struct{}{}
				created = append(created, key)
			}
		}
	}
	defer func() {
		cleanupFenceRecords(t, provider, identity, authenticated, reader, created)
	}()

	initialBlob, initialBlobCID := stageFenceBlob(t, ctx, provider, identity.PDS, authenticated, "f04 initial blob")
	if status, _, err := fetchFenceBlob(ctx, anonymous, identity.DID, initialBlobCID); err != nil || status >= 200 && status < 300 {
		pdsRecordFailure(t, provider, identity.PDS, "F04-initial-blob-unreachable-before-reference", fmt.Sprintf("status=%d error=%s", status, redactText(errorText(err))))
		require.NoError(t, err, "initial staged blob unexpectedly reachable before publication: status=%d error=%v", status, err)
		require.False(t, status >= 200 && status < 300, "initial staged blob unexpectedly reachable before publication: status=%d error=%v", status, err)
	}
	probe := newFenceProbeKey(t)
	initialPublication := makeFencePublication(t, identity.DID, probe, initialBlob, true, true, nil)
	track(initialPublication)
	if _, err := atproto.PublishFenced(ctx, authenticated, initial, initialPublication); err != nil {
		pdsRecordFailure(t, provider, identity.PDS, "F04-initial-atomic-publish", redactText(err.Error()))
		require.NoError(t, err, "initial fenced publish: %v", err)
	}
	afterInitial, err := reader.Read(ctx, identity.DID)
	if err != nil {
		require.NoError(t, err, "read revision after initial publish: %v", err)
	}
	for _, key := range []atproto.RecordKey{{Collection: fenceSnapshotCollection, RKey: probe}, {Collection: fenceHeadCollection, RKey: "self"}, {Collection: fenceControlCollection, RKey: "self"}} {
		if !afterInitial.HasRecord(key) {
			require.True(t, afterInitial.HasRecord(key), "initial atomic batch omitted %s/%s from the verified revision", key.Collection, key.RKey)
		}
	}
	status, _, err := fetchFenceBlob(ctx, anonymous, identity.DID, initialBlobCID)
	if err != nil || status != http.StatusOK {
		pdsRecordFailure(t, provider, identity.PDS, "F04-initial-blob-reachable-after-commit", fmt.Sprintf("status=%d error=%s", status, redactText(errorText(err))))
		require.NoError(t, err, "initial blob not retrievable after commit: status=%d error=%v", status, err)
		require.Equal(t, http.StatusOK, status, "initial blob not retrievable after commit: status=%d error=%v", status, err)
	}
	printFenceMatrix(provider, "1-initial-creation-fence", "passed", initial.CommitCID(), afterInitial.CommitCID(), initialBlobCID, "", "snapshot/head/control membership verified and blob retrievable only after commit")

	for _, experiment := range []string{"2-stale-writer-loses", "3-simulated-control-transition-fence"} {
		captured, err := reader.Read(ctx, identity.DID)
		if err != nil {
			require.NoError(t, err, "capture %s revision: %v", experiment, err)
		}
		candidateBlob, candidateCID := stageFenceBlob(t, ctx, provider, identity.PDS, authenticated, experiment+" candidate")
		competitor, err := publishFenceCompetitor(ctx, t, identity, authenticated, reader, initialBlob, experiment+" competitor", experiment == "3-simulated-control-transition-fence", track)
		if err != nil {
			require.NoError(t, err, "competing %s write: %v", experiment, err)
		}
		current, err := reader.Read(ctx, identity.DID)
		if err != nil {
			require.NoError(t, err, "read advanced commit for %s: %v", experiment, err)
		}
		fmt.Printf("FENCE_MATRIX provider=%q experiment=%q captured_swapCommit=%q competing_commit=%q current_commit=%q\n", provider, experiment, captured.CommitCID(), competitor, current.CommitCID())
		if current.CommitCID() == captured.CommitCID() || current.CommitCID() != competitor {
			pdsRecordFailure(t, provider, identity.PDS, "F04-"+experiment+"-competing-commit-advanced", fmt.Sprintf("captured_swapCommit=%s competing_commit=%s current_commit=%s scenario=INVALID", captured.CommitCID(), competitor, current.CommitCID()))
			require.NotEqual(t, captured.CommitCID(), current.CommitCID(), "%s scenario invalid: commit did not advance from captured swapCommit", experiment)
			require.Equal(t, competitor, current.CommitCID(), "%s scenario invalid: commit did not advance from captured swapCommit", experiment)
		}
		candidateRKey := newFenceProbeKey(t)
		stalePublication := makeFencePublication(t, identity.DID, candidateRKey, candidateBlob, false, false, nil)
		track(stalePublication)
		_, publishErr := atproto.PublishFenced(ctx, authenticated, captured, stalePublication)
		if !errors.Is(publishErr, atproto.ErrFenceLost) {
			pdsRecordFailure(t, provider, identity.PDS, "F04-"+experiment+"-InvalidSwap", fmt.Sprintf("captured_swapCommit=%s competing_commit=%s classified=%v", captured.CommitCID(), competitor, publishErr))
			require.ErrorIs(t, publishErr, atproto.ErrFenceLost, "%s was not classified from structured InvalidSwap: %v", experiment, publishErr)
		}
		postFailure, err := reader.Read(ctx, identity.DID)
		if err != nil {
			require.NoError(t, err, "read after lost %s fence: %v", experiment, err)
		}
		referenced, err := revisionReferencesBlob(postFailure, candidateCID)
		if err != nil || referenced {
			pdsRecordFailure(t, provider, identity.PDS, "F04-"+experiment+"-candidate-unreferenced", fmt.Sprintf("referenced=%t error=%s", referenced, redactText(errorText(err))))
			require.NoError(t, err, "candidate blob was referenced after lost fence: referenced=%t error=%v", referenced, err)
			require.False(t, referenced, "candidate blob was referenced after lost fence: referenced=%t error=%v", referenced, err)
		}
		status, _, fetchErr := fetchFenceBlob(ctx, anonymous, identity.DID, candidateCID)
		if fetchErr != nil || status >= 200 && status < 300 {
			pdsRecordFailure(t, provider, identity.PDS, "F04-"+experiment+"-candidate-blob-unreachable", fmt.Sprintf("status=%d error=%s", status, redactText(errorText(fetchErr))))
			require.NoError(t, fetchErr, "candidate blob reachable after lost fence: status=%d error=%v", status, fetchErr)
			require.False(t, status >= 200 && status < 300, "candidate blob reachable after lost fence: status=%d error=%v", status, fetchErr)
		}
		printFenceMatrix(provider, experiment, "passed (InvalidSwap)", captured.CommitCID(), competitor, candidateCID, postFailure.CommitCID(), "no record references staged CID and anonymous fetch fails")
	}

	cached, err := reader.Read(ctx, identity.DID)
	if err != nil {
		require.NoError(t, err, "capture stale-cache experiment revision: %v", err)
	}
	cacheCompetitor, err := publishFenceCompetitor(ctx, t, identity, authenticated, reader, initialBlob, "stale cache competitor", false, track)
	if err != nil {
		require.NoError(t, err, "advance stale-cache revision: %v", err)
	}
	isCurrent, err := reader.IsCurrent(ctx, identity.DID, cached)
	if err != nil || isCurrent || cacheCompetitor == cached.CommitCID() {
		pdsRecordFailure(t, provider, identity.PDS, "F04-stale-cache-rejected", fmt.Sprintf("captured=%s competing=%s current=%t error=%s", cached.CommitCID(), cacheCompetitor, isCurrent, redactText(errorText(err))))
		require.NoError(t, err, "stale cached revision was not rejected: current=%t error=%v", isCurrent, err)
		require.False(t, isCurrent, "stale cached revision was not rejected: current=%t error=%v", isCurrent, err)
		require.NotEqual(t, cached.CommitCID(), cacheCompetitor, "stale cached revision was not rejected: current=%t error=%v", isCurrent, err)
	}
	printFenceMatrix(provider, "4-stale-cache-rejected", "passed", cached.CommitCID(), cacheCompetitor, "", "", "current verified commit differs from cached revision")

	interleaveCount := 0
	interleaving := &fenceInterleavingTransport{base: authenticated}
	interleavedReader := atproto.RevisionReader{Transport: interleaving, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID, VerificationMethods: identity.VerificationMethods}
	interleaving.hook = func() error {
		interleaveCount++
		_, err := publishFenceCompetitor(ctx, t, identity, authenticated, reader, initialBlob, fmt.Sprintf("mixed view competitor %d", interleaveCount), false, track)
		return err
	}
	_, mixedErr := interleavedReader.Read(ctx, identity.DID)
	if !errors.Is(mixedErr, atproto.ErrRevisionMoving) || interleaveCount != 3 || interleaving.calls != 3 {
		pdsRecordFailure(t, provider, identity.PDS, "F04-mixed-view-bounded-retries", fmt.Sprintf("interleaves=%d repo_reads=%d error=%s", interleaveCount, interleaving.calls, redactText(errorText(mixedErr))))
		require.ErrorIs(t, mixedErr, atproto.ErrRevisionMoving, "mixed-view read did not exhaust exactly three bounded attempts: interleaves=%d streams=%d error=%v", interleaveCount, interleaving.calls, mixedErr)
		require.Equal(t, 3, interleaveCount, "mixed-view read did not exhaust exactly three bounded attempts: interleaves=%d streams=%d error=%v", interleaveCount, interleaving.calls, mixedErr)
		require.Equal(t, 3, interleaving.calls, "mixed-view read did not exhaust exactly three bounded attempts: interleaves=%d streams=%d error=%v", interleaveCount, interleaving.calls, mixedErr)
	}
	printFenceMatrix(provider, "5-mixed-view-read", "passed (ErrRevisionMoving)", "", "", "", "", fmt.Sprintf("three interleaved writes, retries=%d", interleaving.calls))

	validBlob, validCID := stageFenceBlob(t, ctx, provider, identity.PDS, authenticated, "experiment 6 valid staged blob")
	controlBlob, controlCID := stageFenceBlob(t, ctx, provider, identity.PDS, authenticated, "experiment 6 unreferenced control blob")
	_ = controlBlob
	controlStatus, _, controlErr := fetchFenceBlob(ctx, anonymous, identity.DID, controlCID)
	if controlErr != nil || controlStatus >= 200 && controlStatus < 300 {
		pdsRecordFailure(t, provider, identity.PDS, "F04-blob-processing-rollback-control-unreachable", fmt.Sprintf("control_cid=%s status=%d error=%s", controlCID, controlStatus, redactText(errorText(controlErr))))
		require.NoError(t, controlErr, "uploaded-but-unreferenced control blob was already reachable before the batch: status=%d error=%v", controlStatus, controlErr)
		require.False(t, controlStatus >= 200 && controlStatus < 300, "uploaded-but-unreferenced control blob was already reachable before the batch: status=%d error=%v", controlStatus, controlErr)
	}
	missingCID := createNeverUploadedCID(t)
	validProbe := newFenceProbeKey(t)
	missingProbe := newFenceProbeKey(t)
	missingBlob := json.RawMessage(fmt.Sprintf(`{"$type":"blob","ref":{"$link":%q},"mimeType":"application/octet-stream","size":%d}`, missingCID, 23))
	missingRecord, err := json.Marshal(fenceSnapshotFixture{Type: fenceSnapshotCollection, Probe: missingProbe, Blob: missingBlob, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		require.NoError(t, err)
	}
	additional := atproto.RecordWrite{Action: atproto.RecordCreate, Collection: fenceSnapshotCollection, RKey: missingProbe, Record: missingRecord}
	finalRevision, err := reader.Read(ctx, identity.DID)
	if err != nil {
		require.NoError(t, err, "capture experiment 6 revision: %v", err)
	}
	rollbackPublication := makeFencePublication(t, identity.DID, validProbe, validBlob, false, false, []atproto.RecordWrite{additional})
	track(rollbackPublication)
	_, rollbackErr := atproto.PublishFenced(ctx, authenticated, finalRevision, rollbackPublication)
	if !errors.Is(rollbackErr, atproto.ErrBatchRejected) {
		pdsRecordFailure(t, provider, identity.PDS, "F04-blob-processing-rollback-classified-rejection", fmt.Sprintf("valid_cid=%s missing_cid=%s error=%s", validCID, missingCID, redactText(errorText(rollbackErr))))
		require.ErrorIs(t, rollbackErr, atproto.ErrBatchRejected, "well-formed missing-blob batch did not produce a definitive rejection: %v", rollbackErr)
	}
	postRollback, err := reader.Read(ctx, identity.DID)
	if err != nil {
		require.NoError(t, err, "read after experiment 6 rejection: %v", err)
	}
	referenced, err := revisionReferencesBlob(postRollback, validCID)
	if err != nil || referenced {
		pdsRecordFailure(t, provider, identity.PDS, "F04-blob-processing-rollback-valid-blob-unreferenced", fmt.Sprintf("valid_cid=%s referenced=%t error=%s", validCID, referenced, redactText(errorText(err))))
		require.NoError(t, err, "valid staged blob referenced after rejected batch: referenced=%t error=%v", referenced, err)
		require.False(t, referenced, "valid staged blob referenced after rejected batch: referenced=%t error=%v", referenced, err)
	}
	controlAfter, _, controlAfterErr := fetchFenceBlob(ctx, anonymous, identity.DID, controlCID)
	printFenceMatrix(provider, "6-control-unreferenced-blob", fmt.Sprintf("status=%d", controlAfter), finalRevision.CommitCID(), "", controlCID, "", fmt.Sprintf("never referenced by any batch; error=%s", redactText(errorText(controlAfterErr))))
	status, _, fetchErr := fetchFenceBlob(ctx, anonymous, identity.DID, validCID)
	if fetchErr != nil || status >= 200 && status < 300 {
		pdsRecordFailure(t, provider, identity.PDS, "F04-blob-processing-rollback-blob-unreachable", fmt.Sprintf("valid_cid=%s status=%d error=%s", validCID, status, redactText(errorText(fetchErr))))
		require.NoError(t, fetchErr, "valid blob reachable after rejected experiment 6 batch: status=%d error=%v", status, fetchErr)
		require.False(t, status >= 200 && status < 300, "valid blob reachable after rejected experiment 6 batch: status=%d error=%v", status, fetchErr)
	}
	printFenceMatrix(provider, "6-blob-processing-rollback", "passed (batch rejected)", finalRevision.CommitCID(), "", validCID, postRollback.CommitCID(), "additional valid-shaped record referenced a never-uploaded CID; staged valid CID remains unreferenced and unreachable")
}

func makeFencePublication(t *testing.T, did, snapshotRKey string, blobRef json.RawMessage, headCreate, controlCreate bool, additional []atproto.RecordWrite) atproto.FencedPublication {
	t.Helper()
	snapshot := fenceSnapshotFixture{Type: fenceSnapshotCollection, Probe: snapshotRKey, Blob: blobRef, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		require.NoError(t, err)
	}
	snapshotCID, err := fenceRecordCID(snapshotBytes)
	if err != nil {
		require.NoError(t, err)
	}
	head := fenceHeadFixture{Type: fenceHeadCollection, SnapshotRKey: snapshotRKey, SnapshotCID: snapshotCID, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	headBytes, err := json.Marshal(head)
	if err != nil {
		require.NoError(t, err)
	}
	control := fenceControlFixture{Type: fenceControlCollection, Devices: []fenceControlDevice{{DID: did, Role: "owner"}}, PolicyEpoch: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	controlBytes, err := json.Marshal(control)
	if err != nil {
		require.NoError(t, err)
	}
	headAction := atproto.RecordUpdate
	if headCreate {
		headAction = atproto.RecordCreate
	}
	controlAction := atproto.RecordUpdate
	if controlCreate {
		controlAction = atproto.RecordCreate
	}
	return atproto.FencedPublication{
		FirstBlobReference: atproto.RecordWrite{Action: atproto.RecordCreate, Collection: fenceSnapshotCollection, RKey: snapshotRKey, Record: snapshotBytes},
		VaultHead:          atproto.RecordWrite{Action: headAction, Collection: fenceHeadCollection, RKey: "self", Record: headBytes},
		VaultControl:       atproto.RecordWrite{Action: controlAction, Collection: fenceControlCollection, RKey: "self", Record: controlBytes},
		Additional:         additional,
	}
}

func publishFenceCompetitor(ctx context.Context, t *testing.T, identity atproto.Identity, transport atproto.Transport, reader atproto.RevisionReader, blobRef json.RawMessage, suffix string, controlTransition bool, track func(atproto.FencedPublication)) (string, error) {
	t.Helper()
	revision, err := reader.Read(ctx, identity.DID)
	if err != nil {
		return "", err
	}
	rkey := newFenceProbeKey(t)
	publication := makeFencePublication(t, identity.DID, rkey, blobRef, false, false, nil)
	track(publication)
	if controlTransition {
		var record fenceControlFixture
		if err := json.Unmarshal(publication.VaultControl.Record, &record); err != nil {
			return "", err
		}
		record.PolicyEpoch++
		record.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		publication.VaultControl.Record, err = json.Marshal(record)
		if err != nil {
			return "", err
		}
	}
	result, err := atproto.PublishFenced(ctx, transport, revision, publication)
	if err != nil {
		return "", fmt.Errorf("%s: %w", suffix, err)
	}
	updated, err := reader.Read(ctx, identity.DID)
	if err != nil {
		return "", err
	}
	if result.CommitCID != "" && result.CommitCID != updated.CommitCID() {
		return updated.CommitCID(), fmt.Errorf("applyWrites result commit %s differs from verified commit %s", result.CommitCID, updated.CommitCID())
	}
	return updated.CommitCID(), nil
}

func stageFenceBlob(t *testing.T, ctx context.Context, provider, pds string, transport atproto.Transport, content string) (json.RawMessage, string) {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		require.NoError(t, err, "generate staged blob nonce: %v", err)
	}
	staged := append([]byte(content), nonce...)
	status, body, err := transport.Do(ctx, http.MethodPost, "com.atproto.repo.uploadBlob", nil, staged, "application/octet-stream")
	if err != nil || status < 200 || status >= 300 {
		pdsRecordFailure(t, provider, pds, "F04-stage-blob", pdsEvidence(status, classifyPDSResult(status, body, err), body, err))
		require.NoError(t, err, "stage blob: status=%d error=%v", status, err)
		require.GreaterOrEqual(t, status, 200, "stage blob: status=%d error=%v", status, err)
		require.Less(t, status, 300, "stage blob: status=%d error=%v", status, err)
	}
	var result struct {
		Blob json.RawMessage `json:"blob"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		require.NoError(t, err, "decode staged blob response: %v", err)
	}
	var blob struct {
		Ref struct {
			Link string `json:"$link"`
		} `json:"ref"`
	}
	if len(result.Blob) == 0 || json.Unmarshal(result.Blob, &blob) != nil || blob.Ref.Link == "" {
		require.NotEmpty(t, result.Blob, "staged blob response did not contain a blob CID: %s", redactBodyPrefix(body))
		require.NoError(t, json.Unmarshal(result.Blob, &blob), "staged blob response did not contain a blob CID: %s", redactBodyPrefix(body))
		require.NotEqual(t, "", blob.Ref.Link, "staged blob response did not contain a blob CID: %s", redactBodyPrefix(body))
	}
	return result.Blob, blob.Ref.Link
}

func fetchFenceBlob(ctx context.Context, anonymous atproto.Transport, did, cidValue string) (int, []byte, error) {
	status, stream, err := anonymous.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {did}, "cid": {cidValue}})
	if err != nil {
		return 0, nil, err
	}
	if stream == nil {
		return status, nil, errors.New("anonymous blob request returned no response body")
	}
	defer stream.Close()
	body, err := io.ReadAll(io.LimitReader(stream, 2<<20+1))
	if err != nil {
		return status, nil, err
	}
	if len(body) > 2<<20 {
		return status, nil, errors.New("anonymous blob response exceeded harness limit")
	}
	return status, body, nil
}

func revisionReferencesBlob(revision *atproto.Revision, target string) (bool, error) {
	if revision == nil {
		return false, errors.New("verified revision is nil")
	}
	for key, record := range revision.Records() {
		decoded, err := atdata.UnmarshalCBOR(record.Data)
		if err != nil {
			return false, fmt.Errorf("decode verified record %s/%s: %w", key.Collection, key.RKey, err)
		}
		for _, blob := range atdata.ExtractBlobs(decoded) {
			if blob.Ref.CID().String() == target {
				return true, nil
			}
		}
	}
	return false, nil
}

func fenceRecordCID(record []byte) (string, error) {
	decoded, err := atdata.UnmarshalJSON(record)
	if err != nil {
		return "", err
	}
	encoded, err := atdata.MarshalCBOR(decoded)
	if err != nil {
		return "", err
	}
	prefix := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	computed, err := prefix.Sum(encoded)
	if err != nil {
		return "", err
	}
	return computed.String(), nil
}

func createNeverUploadedCID(t *testing.T) string {
	t.Helper()
	prefix := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256)
	computed, err := prefix.Sum([]byte("never-uploaded DOT-F04 fixture"))
	if err != nil {
		require.NoError(t, err)
	}
	return computed.String()
}

func newFenceProbeKey(t *testing.T) string {
	t.Helper()
	key, err := newPDSProbeKey()
	if err != nil {
		require.NoError(t, err)
	}
	return "probe-" + key
}

func cleanupFenceRecords(t *testing.T, provider string, identity atproto.Identity, transport atproto.Transport, reader atproto.RevisionReader, records []fenceCreatedRecord) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		verified := false
		for attempt := 0; attempt < 3; attempt++ {
			revision, err := reader.Read(ctx, identity.DID)
			if err != nil {
				assert.NoError(t, err, "F04 cleanup read %s/%s: %v", record.collection, record.rkey, err)
				break
			}
			key := atproto.RecordKey{Collection: record.collection, RKey: record.rkey}
			if !revision.HasRecord(key) {
				if err := verifyFenceRecordDeleted(ctx, transport, reader, identity.DID, record.collection, record.rkey); err != nil {
					assert.NoError(t, err, "F04 cleanup verification %s/%s: %v", record.collection, record.rkey, err)
				} else {
					verified = true
				}
				break
			}
			input := fenceDeleteInput{Repo: identity.DID, SwapCommit: revision.CommitCID(), Writes: []struct {
				Type       string `json:"$type"`
				Collection string `json:"collection"`
				RKey       string `json:"rkey"`
			}{{Type: "com.atproto.repo.applyWrites#delete", Collection: record.collection, RKey: record.rkey}}}
			body, err := json.Marshal(input)
			if err != nil {
				assert.NoError(t, err, "F04 cleanup encode %s/%s: %v", record.collection, record.rkey, err)
				break
			}
			status, response, requestErr := transport.Do(ctx, http.MethodPost, "com.atproto.repo.applyWrites", nil, body, "application/json")
			verifyErr := verifyFenceRecordDeleted(ctx, transport, reader, identity.DID, record.collection, record.rkey)
			if verifyErr == nil {
				verified = true
				break
			}
			if status == http.StatusBadRequest && atproto.ParseInvalidSwapError(response) {
				continue
			}
			if requestErr != nil || status >= 500 {
				assert.NoError(t, requestErr, "F04 cleanup delete %s/%s status=%d error=%v verification=%v", record.collection, record.rkey, status, requestErr, verifyErr)
				assert.Less(t, status, 500, "F04 cleanup delete %s/%s status=%d error=%v verification=%v", record.collection, record.rkey, status, requestErr, verifyErr)
				break
			}
			if status < 200 || status >= 300 {
				assert.GreaterOrEqual(t, status, 200, "F04 cleanup delete %s/%s rejected status=%d body=%s verification=%v", record.collection, record.rkey, status, redactBodyPrefix(response), verifyErr)
				assert.Less(t, status, 300, "F04 cleanup delete %s/%s rejected status=%d body=%s verification=%v", record.collection, record.rkey, status, redactBodyPrefix(response), verifyErr)
				break
			}
			assert.True(t, false, "F04 cleanup verification %s/%s: %v", record.collection, record.rkey, verifyErr)
			break
		}
		if !verified {
			if err := verifyFenceRecordDeleted(ctx, transport, reader, identity.DID, record.collection, record.rkey); err != nil {
				assert.NoError(t, err, "F04 final cleanup verification %s/%s: %v", record.collection, record.rkey, err)
			}
		}
	}
}

func verifyFenceRecordDeleted(ctx context.Context, transport atproto.Transport, reader atproto.RevisionReader, did, collection, rkey string) error {
	revision, err := reader.Read(ctx, did)
	if err != nil {
		return err
	}
	if revision.HasRecord(atproto.RecordKey{Collection: collection, RKey: rkey}) {
		return errors.New("record remains in the current verified revision")
	}
	status, body, err := transport.Do(ctx, http.MethodGet, "com.atproto.repo.getRecord", url.Values{"repo": {did}, "collection": {collection}, "rkey": {rkey}}, nil, "")
	if err != nil {
		return err
	}
	if status == http.StatusNotFound || status == http.StatusBadRequest && isPDSRecordAbsent(status, body) {
		return nil
	}
	return fmt.Errorf("record still present or absence unproven: status=%d body=%s", status, redactBodyPrefix(body))
}

func printFenceMatrix(provider, experiment, status, capturedSwap, competing, blob, postCID, evidence string) {
	fmt.Printf("FENCE_MATRIX provider=%q experiment=%q status=%q captured_swapCommit=%q competing_commit=%q staged_blob_cid=%q post_failure_commit=%q evidence=%q\n", provider, experiment, status, capturedSwap, competing, blob, postCID, redactText(evidence))
}

func errorText(err error) string {
	if err == nil {
		return "none"
	}
	return err.Error()
}
