package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pdsProbeCollection = "systems.lamb.dottie.vaultSnapshot"

type pdsServerDescription struct {
	BlobUploadLimit *int64 `json:"blobUploadLimit,omitempty"`
}

type pdsListBlobsOutput struct {
	Cids   []string `json:"cids"`
	Cursor *string  `json:"cursor,omitempty"`
}

type pdsDeleteRecordInput struct {
	Repo       string `json:"repo"`
	Collection string `json:"collection"`
	Rkey       string `json:"rkey"`
}

var pdsCredentialPattern = regexp.MustCompile(`(?i)(accessjwt|refreshjwt|access_token|refresh_token|authorization|password|token|email|text)("?\s*:\s*"?)[^",\s}]+`)
var pdsEmailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
var pdsJWTPattern = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b`)

func TestLivePDSMatrix(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_PDS") != "1" {
		t.Skip("set DOTTIE_LIVE_PDS=1 with an owner-authorized disposable identity to run the live PDS matrix")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if !allowedPDSHandle(handle) {
		require.True(t, allowedPDSHandle(handle), "DOTTIE_HANDLE %q is not in the live PDS disposable-identity allowlist", handle)
	}
	byteProbe, ceiling, err := livePDSByteProbeConfig(os.Getenv("DOTTIE_LIVE_PDS_BYTES"), os.Getenv("DOTTIE_LIVE_PDS_BYTE_CEILING"))
	if err != nil {
		require.NoError(t, err)
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
		pdsRecordFailure(t, provider, "unknown", "D13-discovery", redactText(err.Error()))
		require.NoError(t, err, "discover %s: %v", handle, err)
	}
	session, err := client.LoadSession(ctx, identity.DID)
	if err != nil {
		require.NoError(t, err, "load existing scoped OAuth session for %s: %v", handle, err)
	}
	for _, required := range []string{"atproto", "repo:" + pdsProbeCollection, "blob:application/octet-stream"} {
		if !hasPDScope(session.Scopes, required) {
			require.True(t, hasPDScope(session.Scopes, required), "loaded session does not include required scope %q", required)
		}
	}
	if hasPDScope(session.Scopes, "account:email") {
		require.False(t, hasPDScope(session.Scopes, "account:email"), "loaded session includes account:email; the D6 data-minimisation observation requires that scope to be absent")
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
	runLivePDSMatrix(t, ctx, provider, identity, session, authenticated, anonymous, byteProbe, ceiling)
}

func runLivePDSMatrix(t *testing.T, ctx context.Context, provider string, identity atproto.Identity, session *atproto.Session, authenticated, anonymous *atclient.APIClient, byteProbe bool, ceiling int64) {
	var knownCIDs []string
	finalFetchDone := make(map[string]bool)
	defer func() {
		for _, observedCID := range knownCIDs {
			if finalFetchDone[observedCID] {
				continue
			}
			status, body, duration, fetchErr := fetchPDSBlob(ctxOrBackground(ctx), anonymous, identity.DID, observedCID)
			printPDSMatrix(provider, "d7-post-run-blob-reachability-"+observedCID, classifyPDSResult(status, body, fetchErr), redactedBlobResponse(status, body), duration)
			finalFetchDone[observedCID] = true
		}
	}()
	uploadLimit, limitKnown, describeOK := describePDS(t, ctx, provider, identity.PDS, anonymous)
	textStatus, textBody, textDuration, textErr := uploadPDSBlob(ctx, authenticated, []byte("dottie F03 MIME fixture"), "text/plain")
	textClass := classifyPDSResult(textStatus, textBody, textErr)
	printPDSMatrix(provider, "d4-upload-text-plain", textClass, redactBodyPrefix(textBody), textDuration)
	if textErr == nil && textStatus >= 200 && textStatus < 300 {
		if cid := uploadedCID(textBody); cid != "" {
			knownCIDs = append(knownCIDs, cid)
		}
		pdsRecordFailure(t, provider, identity.PDS, "D4-text-plain-rejected", pdsEvidence(textStatus, textClass, textBody, textErr))
	}
	if textErr != nil || textStatus < 400 || textStatus >= 500 {
		pdsRecordFailure(t, provider, identity.PDS, "D4-text-plain-classified-rejection", pdsEvidence(textStatus, textClass, textBody, textErr))
	}

	blobBytes := []byte("dottie F03 controlled blob fixture")
	blobStatus, blobBody, blobDuration, blobErr := uploadPDSBlob(ctx, authenticated, blobBytes, "application/octet-stream")
	printPDSMatrix(provider, "d4-upload-application-octet-stream", classifyPDSResult(blobStatus, blobBody, blobErr), redactBodyPrefix(blobBody), blobDuration)
	if blobErr != nil || blobStatus < 200 || blobStatus >= 300 {
		pdsRecordFailure(t, provider, identity.PDS, "D4-octet-stream-upload-accepted", pdsEvidence(blobStatus, classifyPDSResult(blobStatus, blobBody, blobErr), blobBody, blobErr))
		return
	}
	blobRef, cid, err := uploadedBlobRef(blobBody)
	if err != nil {
		pdsRecordFailure(t, provider, identity.PDS, "D4-upload-response-contains-blob-reference", redactText(err.Error()))
		return
	}
	knownCIDs = append(knownCIDs, cid)

	recordCreated := false
	probeRecordWasCreated := false
	probe := ""
	postDeleteListDone := false
	defer func() {
		if recordCreated && !probeRecordWasCreated {
			absent, status, body, duration, checkErr := verifyPDSRecordDeleted(context.Background(), authenticated, identity.DID, probe)
			printPDSMatrix(provider, "d7-check-record-absent-after-create-response", classifyPDSResult(status, body, checkErr), redactBodyPrefix(body), duration)
			if absent {
				recordCreated = false
			}
		}
		if recordCreated {
			deleteStatus, deleteBody, deleteDuration, deleteErr := deletePDSProbeRecord(context.Background(), authenticated, identity.DID, probe)
			printPDSMatrix(provider, "d7-deferred-delete-probe-record", classifyPDSResult(deleteStatus, deleteBody, deleteErr), redactBodyPrefix(deleteBody), deleteDuration)
			verified, verifyStatus, verifyBody, verifyDuration, verifyErr := verifyPDSRecordDeleted(context.Background(), authenticated, identity.DID, probe)
			printPDSMatrix(provider, "d7-deferred-verify-delete", classifyPDSResult(verifyStatus, verifyBody, verifyErr), redactBodyPrefix(verifyBody), verifyDuration)
			if verified {
				recordCreated = false
			} else {
				evidence := pdsEvidence(verifyStatus, classifyPDSResult(verifyStatus, verifyBody, verifyErr), verifyBody, verifyErr)
				if deleteErr != nil || deleteStatus < 200 || deleteStatus >= 300 {
					evidence += " delete=" + pdsEvidence(deleteStatus, classifyPDSResult(deleteStatus, deleteBody, deleteErr), deleteBody, deleteErr)
				}
				pdsRecordFailure(t, provider, identity.PDS, "D7-probe-record-cleanup", evidence)
			}
		}
		if probeRecordWasCreated && !recordCreated {
			if !finalFetchDone[cid] {
				status, body, _, duration, fetchErr := fetchPDSBlobData(ctxOrBackground(ctx), anonymous, identity.DID, cid)
				printPDSMatrix(provider, "d2-post-delete-reachability-after-deferred-cleanup", classifyPDSResult(status, body, fetchErr), redactedBlobResponse(status, body), duration)
				finalFetchDone[cid] = true
			}
			if !postDeleteListDone {
				listedAfterDelete, status, body, duration, listErr := isPDSBlobListed(ctxOrBackground(ctx), authenticated, identity.DID, cid)
				summary := string(body)
				if listErr == nil {
					summary = fmt.Sprintf("cid-listed=%t after-record-deletion", listedAfterDelete)
				}
				printPDSMatrix(provider, "d2-post-delete-listBlobs-enumeration", classifyPDSResult(status, body, listErr), redactText(summary), duration)
				if listErr != nil {
					pdsRecordFailure(t, provider, identity.PDS, "D2-post-delete-listBlobs-enumeration-completed", pdsEvidence(status, classifyPDSResult(status, body, listErr), body, listErr))
				}
				postDeleteListDone = true
			}
		} else if probeRecordWasCreated && !postDeleteListDone {
			printPDSMatrix(provider, "d2-post-delete-reachability", "not measured (record deletion unverified)", "[blob reachability not comparable until record deletion is verified]", 0)
			printPDSMatrix(provider, "d2-post-delete-listBlobs-enumeration", "not measured (record deletion unverified)", "[listBlobs queried only after verified deletion]", 0)
			postDeleteListDone = true
		}
		for _, observedCID := range knownCIDs {
			if finalFetchDone[observedCID] {
				continue
			}
			status, body, duration, fetchErr := fetchPDSBlob(ctxOrBackground(ctx), anonymous, identity.DID, observedCID)
			printPDSMatrix(provider, "d7-post-run-blob-reachability-"+observedCID, classifyPDSResult(status, body, fetchErr), redactedBlobResponse(status, body), duration)
			finalFetchDone[observedCID] = true
		}
	}()

	beforeStatus, beforeBody, _, beforeDuration, beforeErr := fetchPDSBlobData(ctx, anonymous, identity.DID, cid)
	printPDSMatrix(provider, "d2-unreferenced-anonymous-fetch", classifyPDSResult(beforeStatus, beforeBody, beforeErr), redactedBlobResponse(beforeStatus, beforeBody), beforeDuration)
	if beforeErr != nil || beforeStatus == http.StatusOK {
		pdsRecordFailure(t, provider, identity.PDS, "D2-unreferenced-blob-not-public", pdsBlobEvidence(beforeStatus, classifyPDSResult(beforeStatus, beforeBody, beforeErr), beforeBody, beforeErr))
	}

	baselineListed, baselineListStatus, baselineListBody, baselineListDuration, baselineListErr := isPDSBlobListed(ctx, authenticated, identity.DID, cid)
	baselineSummary := string(baselineListBody)
	if baselineListErr == nil {
		baselineSummary = fmt.Sprintf("cid-listed=%t before-record-creation", baselineListed)
	}
	printPDSMatrix(provider, "d2-unreferenced-listBlobs-enumeration", classifyPDSResult(baselineListStatus, baselineListBody, baselineListErr), redactText(baselineSummary), baselineListDuration)
	if baselineListErr != nil {
		pdsRecordFailure(t, provider, identity.PDS, "D2-unreferenced-listBlobs-enumeration-completed", pdsEvidence(baselineListStatus, classifyPDSResult(baselineListStatus, baselineListBody, baselineListErr), baselineListBody, baselineListErr))
	} else if baselineListed {
		pdsRecordFailure(t, provider, identity.PDS, "D2-unreferenced-blob-enumerated", fmt.Sprintf("listBlobs enumerated the unreferenced CID %s before any record referenced it", cid))
	}

	probe, err = newPDSProbeKey()
	if err != nil {
		pdsRecordFailure(t, provider, identity.PDS, "D3-probe-key-generated", redactText(err.Error()))
		return
	}
	recordCreated = true
	createStatus, createBody, createDuration, createErr := createPDSProbeRecord(ctx, authenticated, identity.DID, probe, blobRef)
	printPDSMatrix(provider, "d3-create-probe-record", classifyPDSResult(createStatus, createBody, createErr), redactBodyPrefix(createBody), createDuration)
	if createErr != nil || createStatus < 200 || createStatus >= 300 {
		pdsRecordFailure(t, provider, identity.PDS, "D3-probe-record-shape-accepted", pdsEvidence(createStatus, classifyPDSResult(createStatus, createBody, createErr), createBody, createErr))
		return
	}
	probeRecordWasCreated = true

	afterStatus, afterBody, afterData, afterDuration, afterErr := fetchPDSBlobData(ctx, anonymous, identity.DID, cid)
	printPDSMatrix(provider, "d2-referenced-anonymous-positive-control", classifyPDSResult(afterStatus, afterBody, afterErr), redactedBlobResponse(afterStatus, afterBody), afterDuration)
	if afterErr != nil || afterStatus != http.StatusOK || !bytes.Equal(blobBytes, afterData) {
		pdsRecordFailure(t, provider, identity.PDS, "D2-referenced-positive-control-byte-equality", pdsBlobEvidence(afterStatus, classifyPDSResult(afterStatus, afterBody, afterErr), afterBody, afterErr))
	}

	listed, listStatus, listBody, listDuration, listErr := isPDSBlobListed(ctx, authenticated, identity.DID, cid)
	listSummary := string(listBody)
	if listErr == nil {
		listSummary = fmt.Sprintf("cid-listed=%t", listed)
	}
	listMatrixStatus := classifyPDSResult(listStatus, listBody, listErr)
	if listed {
		listMatrixStatus = "success (CID enumerated while referenced; expected)"
	}
	printPDSMatrix(provider, "d2-authenticated-listBlobs-enumeration", listMatrixStatus, redactText(listSummary), listDuration)
	if listErr != nil {
		pdsRecordFailure(t, provider, identity.PDS, "D2-listBlobs-enumeration-completed", pdsEvidence(listStatus, classifyPDSResult(listStatus, listBody, listErr), listBody, listErr))
	}
	printPDSMatrix(provider, "d2-other-advertised-blob-hosts", "not-advertised", "protocol fact: PDS describeServer has no blob-host field; no separate host is advertised", 0)

	deleteStatus, deleteBody, deleteDuration, deleteErr := deletePDSProbeRecord(ctx, authenticated, identity.DID, probe)
	printPDSMatrix(provider, "d7-delete-probe-record", classifyPDSResult(deleteStatus, deleteBody, deleteErr), redactBodyPrefix(deleteBody), deleteDuration)
	if deleteErr != nil || deleteStatus < 200 || deleteStatus >= 300 {
		pdsRecordFailure(t, provider, identity.PDS, "D7-probe-record-delete-request", pdsEvidence(deleteStatus, classifyPDSResult(deleteStatus, deleteBody, deleteErr), deleteBody, deleteErr))
		return
	}
	verified, verifyStatus, verifyBody, verifyDuration, verifyErr := verifyPDSRecordDeleted(ctx, authenticated, identity.DID, probe)
	printPDSMatrix(provider, "d7-verify-probe-record-deleted", classifyPDSResult(verifyStatus, verifyBody, verifyErr), redactBodyPrefix(verifyBody), verifyDuration)
	if !verified {
		pdsRecordFailure(t, provider, identity.PDS, "D7-probe-record-deletion-verified", pdsEvidence(verifyStatus, classifyPDSResult(verifyStatus, verifyBody, verifyErr), verifyBody, verifyErr))
		return
	}
	recordCreated = false
	postStatus, postBody, _, postDuration, postErr := fetchPDSBlobData(ctx, anonymous, identity.DID, cid)
	printPDSMatrix(provider, "d2-post-delete-reachability", classifyPDSResult(postStatus, postBody, postErr), redactedBlobResponse(postStatus, postBody), postDuration)
	finalFetchDone[cid] = true
	postListed, postListStatus, postListBody, postListDuration, postListErr := isPDSBlobListed(ctx, authenticated, identity.DID, cid)
	postListSummary := string(postListBody)
	if postListErr == nil {
		postListSummary = fmt.Sprintf("cid-listed=%t after-record-deletion", postListed)
	}
	printPDSMatrix(provider, "d2-post-delete-listBlobs-enumeration", classifyPDSResult(postListStatus, postListBody, postListErr), redactText(postListSummary), postListDuration)
	postDeleteListDone = true
	if postListErr != nil {
		pdsRecordFailure(t, provider, identity.PDS, "D2-post-delete-listBlobs-enumeration-completed", pdsEvidence(postListStatus, classifyPDSResult(postListStatus, postListBody, postListErr), postListBody, postListErr))
	}

	runPDSSizeProbe(t, ctx, provider, identity, authenticated, uploadLimit, limitKnown, describeOK, byteProbe, ceiling, &knownCIDs)
	runPDSScopeWidening(t, ctx, provider, identity, session, authenticated, anonymous)
}

func describePDS(t *testing.T, ctx context.Context, provider, intendedPDS string, anonymous *atclient.APIClient) (int64, bool, bool) {
	t.Helper()
	response, body, duration, err := pdsDo(ctx, anonymous, http.MethodGet, "com.atproto.server.describeServer", nil, nil, "")
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	var description pdsServerDescription
	describeOK := err == nil && response != nil && status >= 200 && status < 300
	if describeOK {
		err = json.Unmarshal(body, &description)
		describeOK = err == nil
	}
	if !describeOK {
		pdsRecordFailure(t, provider, intendedPDS, "D4-describeServer-blobUploadLimit-observed", pdsEvidence(status, classifyPDSResult(status, body, err), body, err))
	}
	limit := "unadvertised"
	if description.BlobUploadLimit != nil {
		limit = strconv.FormatInt(*description.BlobUploadLimit, 10)
	}
	printPDSMatrix(provider, "d4-describeServer-blobUploadLimit", classifyPDSResult(status, body, err), "blobUploadLimit="+limit+" body="+redactBodyPrefix(body), duration)
	return valueOrZero(description.BlobUploadLimit), description.BlobUploadLimit != nil, describeOK
}

func uploadPDSBlob(ctx context.Context, authenticated *atclient.APIClient, data []byte, contentType string) (int, []byte, time.Duration, error) {
	response, body, duration, err := pdsDo(ctx, authenticated, http.MethodPost, "com.atproto.repo.uploadBlob", nil, data, contentType)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	return status, body, duration, err
}

func uploadPDSBlobStream(ctx context.Context, authenticated *atclient.APIClient, body io.Reader, getBody func() (io.ReadCloser, error), contentType string) (int, []byte, time.Duration, error) {
	response, output, duration, err := pdsDoStream(ctx, authenticated, http.MethodPost, "com.atproto.repo.uploadBlob", nil, body, getBody, contentType)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	return status, output, duration, err
}

type pdsRepeatReader struct {
	remaining int64
	pattern   []byte
	position  int
}

func newPDSRepeatReader(size int64) *pdsRepeatReader {
	return &pdsRepeatReader{remaining: size, pattern: []byte("dottie-f03-boundary-")}
}

func (r *pdsRepeatReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	count := len(buffer)
	if int64(count) > r.remaining {
		count = int(r.remaining)
	}
	for index := 0; index < count; index++ {
		buffer[index] = r.pattern[r.position]
		r.position = (r.position + 1) % len(r.pattern)
	}
	r.remaining -= int64(count)
	return count, nil
}

func uploadedBlobRef(body []byte) (json.RawMessage, string, error) {
	var result struct {
		Blob json.RawMessage `json:"blob"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("decode uploadBlob response: %w", err)
	}
	if len(result.Blob) == 0 || !json.Valid(result.Blob) {
		return nil, "", errors.New("uploadBlob response omitted a valid blob reference")
	}
	var blob struct {
		Ref struct {
			Link string `json:"$link"`
		} `json:"ref"`
	}
	if err := json.Unmarshal(result.Blob, &blob); err != nil || blob.Ref.Link == "" {
		return nil, "", errors.New("uploadBlob response omitted a CID")
	}
	return result.Blob, blob.Ref.Link, nil
}

func uploadedCID(body []byte) string {
	_, cid, _ := uploadedBlobRef(body)
	return cid
}

func fetchPDSBlob(ctx context.Context, anonymous *atclient.APIClient, did, cid string) (int, []byte, time.Duration, error) {
	status, body, _, duration, err := fetchPDSBlobData(ctx, anonymous, did, cid)
	return status, body, duration, err
}

func fetchPDSBlobData(ctx context.Context, anonymous *atclient.APIClient, did, cid string) (int, []byte, []byte, time.Duration, error) {
	query := url.Values{"did": {did}, "cid": {cid}}
	response, body, duration, err := pdsDo(ctx, anonymous, http.MethodGet, "com.atproto.sync.getBlob", query, nil, "")
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	return status, body, body, duration, err
}

func createPDSProbeRecord(ctx context.Context, authenticated *atclient.APIClient, did, probe string, blobRef json.RawMessage) (int, []byte, time.Duration, error) {
	record := struct {
		Type      string          `json:"$type"`
		Probe     string          `json:"probe"`
		Blob      json.RawMessage `json:"blob"`
		CreatedAt string          `json:"createdAt"`
	}{Type: pdsProbeCollection, Probe: probe, Blob: blobRef, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return 0, nil, 0, err
	}
	input := struct {
		Repo       string          `json:"repo"`
		Collection string          `json:"collection"`
		Rkey       string          `json:"rkey"`
		Record     json.RawMessage `json:"record"`
	}{Repo: did, Collection: pdsProbeCollection, Rkey: probe, Record: recordBytes}
	body, err := json.Marshal(input)
	if err != nil {
		return 0, nil, 0, err
	}
	response, output, duration, err := pdsDo(ctx, authenticated, http.MethodPost, "com.atproto.repo.createRecord", nil, body, "application/json")
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	return status, output, duration, err
}

func deletePDSProbeRecord(ctx context.Context, authenticated *atclient.APIClient, did, rkey string) (int, []byte, time.Duration, error) {
	input := pdsDeleteRecordInput{Repo: did, Collection: pdsProbeCollection, Rkey: rkey}
	body, err := json.Marshal(input)
	if err != nil {
		return 0, nil, 0, err
	}
	response, output, duration, err := pdsDo(ctx, authenticated, http.MethodPost, "com.atproto.repo.deleteRecord", nil, body, "application/json")
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	return status, output, duration, err
}

func verifyPDSRecordDeleted(ctx context.Context, authenticated *atclient.APIClient, did, rkey string) (bool, int, []byte, time.Duration, error) {
	query := url.Values{"repo": {did}, "collection": {pdsProbeCollection}, "rkey": {rkey}}
	response, body, duration, err := pdsDo(ctx, authenticated, http.MethodGet, "com.atproto.repo.getRecord", query, nil, "")
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	if err != nil {
		return false, status, body, duration, err
	}
	return isPDSRecordAbsent(status, body), status, body, duration, nil
}

func isPDSRecordAbsent(status int, body []byte) bool {
	if status == http.StatusNotFound {
		return true
	}
	if status != http.StatusBadRequest {
		return false
	}
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "recordnotfound") || strings.Contains(lower, "record not found")
}

func isPDSBlobListed(ctx context.Context, authenticated *atclient.APIClient, did, cid string) (bool, int, []byte, time.Duration, error) {
	cursor := ""
	pages := 0
	var lastBody []byte
	var lastStatus int
	var total time.Duration
	for pages < 1000 {
		query := url.Values{"did": {did}, "limit": {"1000"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		response, body, duration, err := pdsDo(ctx, authenticated, http.MethodGet, "com.atproto.sync.listBlobs", query, nil, "")
		total += duration
		if response != nil {
			lastStatus = response.StatusCode
		}
		lastBody = body
		if err != nil {
			return false, lastStatus, lastBody, total, err
		}
		if lastStatus < 200 || lastStatus >= 300 {
			return false, lastStatus, lastBody, total, nil
		}
		var output pdsListBlobsOutput
		if err := json.Unmarshal(body, &output); err != nil {
			return false, lastStatus, body, total, err
		}
		for _, listed := range output.Cids {
			if listed == cid {
				return true, lastStatus, []byte(fmt.Sprintf("cid-listed=true pages=%d", pages+1)), total, nil
			}
		}
		pages++
		if output.Cursor == nil || *output.Cursor == "" {
			return false, lastStatus, []byte(fmt.Sprintf("cid-listed=false pages=%d", pages)), total, nil
		}
		cursor = *output.Cursor
	}
	return false, lastStatus, []byte("listBlobs page limit exceeded"), total, errors.New("listBlobs enumeration exceeded 1000 pages")
}

func runPDSSizeProbe(t *testing.T, ctx context.Context, provider string, identity atproto.Identity, authenticated *atclient.APIClient, advertised int64, limitKnown, describeOK, enabled bool, ceiling int64, knownCIDs *[]string) {
	t.Helper()
	advertisedText := "unadvertised"
	attemptedText := "none"
	if limitKnown {
		advertisedText = strconv.FormatInt(advertised, 10)
	}
	if !enabled {
		printPDSMatrix(provider, "d4-size-boundary", "unmeasured (size probe disabled)", fmt.Sprintf("advertised=%s ceiling=not-approved attempted=none", advertisedText), 0)
		return
	}
	if !describeOK {
		printPDSMatrix(provider, "d4-size-boundary", "not measured (blobUploadLimit retrieval failed)", fmt.Sprintf("advertised=unknown ceiling=%d attempted=none", ceiling), 0)
		return
	}
	attempted, sizeErr := pdsBoundaryAttemptSize(advertised, limitKnown, ceiling)
	if sizeErr != nil {
		pdsRecordFailure(t, provider, identity.PDS, "D4-advertised-blob-limit-positive", redactText(sizeErr.Error()))
		printPDSMatrix(provider, "d4-size-boundary", "not-attempted-invalid-advertisement", fmt.Sprintf("advertised=%s ceiling=%d attempted=none", advertisedText, ceiling), 0)
		return
	}
	attemptedText = strconv.FormatInt(attempted, 10)
	status, body, duration, err := uploadPDSBlobStream(ctx, authenticated, newPDSRepeatReader(attempted), func() (io.ReadCloser, error) {
		return io.NopCloser(newPDSRepeatReader(attempted)), nil
	}, "application/octet-stream")
	class := classifyPDSResult(status, body, err)
	result := fmt.Sprintf("size: advertised=%s ceiling=%d attempted=%s result=%s latency=%s", advertisedText, ceiling, attemptedText, class, duration)
	printPDSMatrix(provider, "d4-size-boundary", class, result+" body="+redactBodyPrefix(body), duration)
	if err == nil && status >= 200 && status < 300 {
		if cid := uploadedCID(body); cid != "" {
			*knownCIDs = append(*knownCIDs, cid)
		}
		if attempted == ceiling {
			printPDSMatrix(provider, "d4-size-boundary-above-ceiling", "unmeasured", fmt.Sprintf("boundary above ceiling %d, unmeasured", ceiling), 0)
		}
	}
}

func runPDSScopeWidening(t *testing.T, ctx context.Context, provider string, identity atproto.Identity, session *atproto.Session, authenticated, anonymous *atclient.APIClient) {
	t.Helper()
	scope := "repo:app.bsky.feed.post"
	for _, granted := range session.Scopes {
		if granted == scope {
			pdsRecordFailure(t, provider, identity.PDS, "D6-fixture-outside-granted-scopes", "loaded session unexpectedly contains "+scope)
			return
		}
	}
	probe, err := newPDSProbeKey()
	if err != nil {
		pdsRecordFailure(t, provider, identity.PDS, "D6-fixture-key-generated", redactText(err.Error()))
		return
	}
	post := struct {
		Type      string `json:"$type"`
		Text      string `json:"text"`
		CreatedAt string `json:"createdAt"`
	}{Type: "app.bsky.feed.post", Text: "Dottie DOT-F03 disposable authorization-scope probe", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	recordBytes, _ := json.Marshal(post)
	input := struct {
		Repo       string          `json:"repo"`
		Collection string          `json:"collection"`
		Rkey       string          `json:"rkey"`
		Record     json.RawMessage `json:"record"`
	}{Repo: identity.DID, Collection: "app.bsky.feed.post", Rkey: probe, Record: recordBytes}
	body, _ := json.Marshal(input)
	response, resultBody, duration, err := pdsDo(ctx, authenticated, http.MethodPost, "com.atproto.repo.createRecord", nil, body, "application/json")
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	class := classifyPDSResult(status, resultBody, err)
	printPDSMatrix(provider, "d6-out-of-scope-write-known-valid-app-bsky-feed-post", class, redactBodyPrefix(resultBody), duration)
	writeCreated := err == nil && status >= 200 && status < 300
	defer func() {
		if !writeCreated {
			return
		}
		deleteBody, _ := json.Marshal(pdsDeleteRecordInput{Repo: identity.DID, Collection: "app.bsky.feed.post", Rkey: probe})
		deleteResponse, deleteResult, deleteDuration, deleteErr := pdsDo(context.Background(), authenticated, http.MethodPost, "com.atproto.repo.deleteRecord", nil, deleteBody, "application/json")
		deleteStatus := 0
		if deleteResponse != nil {
			deleteStatus = deleteResponse.StatusCode
		}
		printPDSMatrix(provider, "d6-cleanup-out-of-scope-record", classifyPDSResult(deleteStatus, deleteResult, deleteErr), redactBodyPrefix(deleteResult), deleteDuration)
		verified, verifyStatus, verifyBody, verifyDuration, verifyErr := verifyRecordDeletedFromCollection(context.Background(), authenticated, identity.DID, "app.bsky.feed.post", probe)
		printPDSMatrix(provider, "d6-verify-out-of-scope-record-cleanup", classifyPDSResult(verifyStatus, verifyBody, verifyErr), redactBodyPrefix(verifyBody), verifyDuration)
		if !verified {
			pdsRecordFailure(t, provider, identity.PDS, "D6-out-of-scope-write-cleanup", pdsEvidence(verifyStatus, classifyPDSResult(verifyStatus, verifyBody, verifyErr), verifyBody, verifyErr))
		}
	}()
	classifyExpectedScopeDenial(t, provider, identity.PDS, "D6-out-of-scope-write-authorization-classification", class, status, resultBody, err)

	query := url.Values{"repo": {identity.DID}, "collection": {"app.bsky.feed.post"}, "limit": {"1"}}
	readResponse, readBody, readDuration, readErr := pdsDo(ctx, authenticated, http.MethodGet, "com.atproto.repo.listRecords", query, nil, "")
	readStatus := 0
	if readResponse != nil {
		readStatus = readResponse.StatusCode
	}
	readClass := classifyPDSResult(readStatus, readBody, readErr)
	printPDSMatrix(provider, "d6-out-of-scope-read-known-valid-listRecords", readClass, redactBodyPrefix(readBody), readDuration)
	anonResponse, anonBody, anonDuration, anonErr := pdsDo(ctx, anonymous, http.MethodGet, "com.atproto.repo.listRecords", query, nil, "")
	anonStatus := 0
	if anonResponse != nil {
		anonStatus = anonResponse.StatusCode
	}
	anonClass := classifyPDSResult(anonStatus, anonBody, anonErr)
	printPDSMatrix(provider, "d6-out-of-scope-read-anonymous-control", anonClass, redactBodyPrefix(anonBody), anonDuration)
	switch {
	case readClass == "authorization":
	case readClass == "success" && anonClass == "success":
		printPDSMatrix(provider, "d6-out-of-scope-read-classification", "public-data", "repo content is readable without credentials, so authenticated success is not a widening signal", 0)
	case readClass == "success":
		pdsRecordFailure(t, provider, identity.PDS, "D6-out-of-scope-read-scope-widening-succeeded", pdsEvidence(readStatus, readClass, readBody, readErr))
	default:
		pdsRecordFailure(t, provider, identity.PDS, "D6-out-of-scope-read-observation", pdsEvidence(readStatus, readClass, readBody, readErr))
	}

	identityResponse, identityBody, identityDuration, identityErr := pdsDo(ctx, authenticated, http.MethodGet, "com.atproto.server.getSession", nil, nil, "")
	identityStatus := 0
	if identityResponse != nil {
		identityStatus = identityResponse.StatusCode
	}
	identityClass := classifyPDSResult(identityStatus, identityBody, identityErr)
	unrequestedFields := unrequestedPDSIdentityFields(identityBody)
	fieldSummary := "unrequested_identity_fields=none"
	if len(unrequestedFields) > 0 {
		fieldSummary = "unrequested_identity_fields=" + strings.Join(unrequestedFields, ",")
	}
	printPDSMatrix(provider, "d6-identity-data-minimisation-getSession", identityClass, fieldSummary, identityDuration)
	if identityClass == "success" && len(unrequestedFields) > 0 {
		pdsRecordFailure(t, provider, identity.PDS, "D6-unrequested-account-identity-fields", fieldSummary)
	} else if identityErr != nil || identityClass != "success" && identityClass != "authorization" {
		pdsRecordFailure(t, provider, identity.PDS, "D6-identity-data-minimisation-observation", pdsEvidence(identityStatus, identityClass, identityBody, identityErr))
	}
	printPDSMatrix(provider, "d6-identity-write", "not attempted", "identity write: not attempted (destructive on a disposable identity)", 0)
}

func verifyRecordDeletedFromCollection(ctx context.Context, authenticated *atclient.APIClient, did, collection, rkey string) (bool, int, []byte, time.Duration, error) {
	query := url.Values{"repo": {did}, "collection": {collection}, "rkey": {rkey}}
	response, body, duration, err := pdsDo(ctx, authenticated, http.MethodGet, "com.atproto.repo.getRecord", query, nil, "")
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	if err != nil {
		return false, status, body, duration, err
	}
	return isPDSRecordAbsent(status, body), status, body, duration, nil
}

func classifyExpectedScopeDenial(t *testing.T, provider, pds, criterion, class string, status int, body []byte, err error) {
	t.Helper()
	if class == "authorization" {
		return
	}
	if class == "success" {
		pdsRecordFailure(t, provider, pds, criterion+"-scope-widening-succeeded", pdsEvidence(status, class, body, err))
		return
	}
	pdsRecordFailure(t, provider, pds, criterion+"-inconclusive-not-authorization", pdsEvidence(status, class, body, err))
}

func unrequestedPDSIdentityFields(body []byte) []string {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil
	}
	fields := make(map[string]struct{})
	var walk func(any)
	walk = func(current any) {
		switch item := current.(type) {
		case map[string]any:
			for name, nested := range item {
				lower := strings.ToLower(name)
				for _, marker := range []string{"email", "phone", "birthdate", "dateofbirth", "address", "mobile", "contact"} {
					if strings.Contains(lower, marker) {
						fields[name] = struct{}{}
						break
					}
				}
				walk(nested)
			}
		case []any:
			for _, nested := range item {
				walk(nested)
			}
		}
	}
	walk(value)
	result := make([]string, 0, len(fields))
	for name := range fields {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func classifyPDSResult(status int, body []byte, err error) string {
	if err != nil {
		if errors.Is(err, atproto.ErrAuthMethodToken) || errors.Is(err, atproto.ErrAuthMethodHost) {
			return "authorization"
		}
		return "transport"
	}
	if status >= 200 && status < 300 {
		return "success"
	}
	lower := strings.ToLower(string(body))
	if status == http.StatusUnauthorized || status == http.StatusForbidden || strings.Contains(lower, "authrequired") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "insufficient_scope") || strings.Contains(lower, "invalid_token") || strings.Contains(lower, "scope") {
		return "authorization"
	}
	if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity || strings.Contains(lower, "validation") || strings.Contains(lower, "lexicon") {
		return "validation"
	}
	return fmt.Sprintf("http-%d", status)
}

func pdsBoundaryAttemptSize(advertised int64, limitKnown bool, ceiling int64) (int64, error) {
	if ceiling <= 0 {
		return 0, errors.New("owner-approved byte ceiling must be positive")
	}
	if !limitKnown {
		return ceiling, nil
	}
	if advertised <= 0 {
		return 0, errors.New("advertised blobUploadLimit must be positive")
	}
	if advertised < ceiling {
		return advertised, nil
	}
	return ceiling, nil
}

func livePDSByteProbeConfig(enabledValue, ceilingValue string) (bool, int64, error) {
	if enabledValue != "1" {
		return false, 0, nil
	}
	validDigits := ceilingValue != ""
	for _, digit := range ceilingValue {
		if digit < '0' || digit > '9' {
			validDigits = false
			break
		}
	}
	ceiling, err := strconv.ParseInt(ceilingValue, 10, 64)
	if !validDigits || err != nil || ceiling <= 0 {
		return false, 0, errors.New("DOTTIE_LIVE_PDS_BYTES=1 requires DOTTIE_LIVE_PDS_BYTE_CEILING to be a positive plain-decimal byte count; both variables are required for the size probe")
	}
	return true, ceiling, nil
}

func allowedPDSHandle(handle string) bool {
	return handle == "dottiethrowaway.bsky.social" || handle == "dottie.wallera.computer"
}

func pdsProviderName(handle string) string {
	if handle == "dottiethrowaway.bsky.social" {
		return "Bluesky-hosted"
	}
	return "independently-hosted"
}

func hasPDScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func newPDSProbeKey() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value)), nil
}

func printPDSMatrix(provider, experiment, status, body string, duration time.Duration) {
	fmt.Printf("PDS_MATRIX provider=%q experiment=%q status=%q body_prefix=%q timing_ms=%.3f\n", provider, experiment, status, body, float64(duration.Microseconds())/1000)
}

func redactedBlobResponse(_ int, body []byte) string {
	if len(body) == 0 {
		return "(empty body)"
	}
	return fmt.Sprintf("(blob body redacted, %d bytes)", len(body))
}

func redactBodyPrefix(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if !json.Valid(body) {
		text := strings.ToValidUTF8(string(body), "�")
		if strings.ContainsRune(text, '\u0000') {
			return fmt.Sprintf("[binary %d bytes redacted]", len(body))
		}
		return redactText(text)
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(body, &value) == nil {
		if raw, ok := value["error"]; ok {
			var code string
			if json.Unmarshal(raw, &code) == nil {
				return "error=" + redactText(code) + " message=[REDACTED]"
			}
		}
	}
	return "[JSON body redacted]"
}

func redactText(value string) string {
	value = pdsJWTPattern.ReplaceAllString(value, "[REDACTED]")
	value = pdsEmailPattern.ReplaceAllString(value, "[REDACTED]")
	value = pdsCredentialPattern.ReplaceAllString(value, "$1$2[REDACTED]")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 160 {
		value = value[:160]
	}
	return value
}

func pdsBlobEvidence(status int, class string, body []byte, err error) string {
	if err != nil {
		return fmt.Sprintf("status=%d class=%s error=%s body_prefix=%q", status, class, redactText(err.Error()), redactedBlobResponse(status, body))
	}
	return fmt.Sprintf("status=%d class=%s body_prefix=%q", status, class, redactedBlobResponse(status, body))
}

func pdsEvidence(status int, class string, body []byte, err error) string {
	if err != nil {
		return fmt.Sprintf("status=%d class=%s error=%s body_prefix=%q", status, class, redactText(err.Error()), redactBodyPrefix(body))
	}
	return fmt.Sprintf("status=%d class=%s body_prefix=%q", status, class, redactBodyPrefix(body))
}

type pdsFailureArtifact struct {
	Provider         string `json:"provider"`
	IntendedPDS      string `json:"intended_pds"`
	Criterion        string `json:"criterion"`
	RedactedEvidence string `json:"redacted_evidence"`
	DecisionDOTF07   string `json:"decision_required_at_DOT_F07"`
	CloudReleaseHold bool   `json:"cloud_release_hold"`
}

func writePDSFailureArtifact(parent string, artifact pdsFailureArtifact) (string, error) {
	artifact.RedactedEvidence = redactText(artifact.RedactedEvidence)
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return "", err
	}
	root, err := os.MkdirTemp(parent, "dottie-f03-pds-failure-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "failure.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func pdsRecordFailure(t *testing.T, provider, intendedPDS, criterion, evidence string) {
	t.Helper()
	artifact := pdsFailureArtifact{
		Provider:         provider,
		IntendedPDS:      intendedPDS,
		Criterion:        criterion,
		RedactedEvidence: evidence,
		DecisionDOTF07:   "Owner must decide provider-specific handling before DOT-F07; local-only fallback is not implemented.",
		CloudReleaseHold: true,
	}
	path, err := writePDSFailureArtifact("", artifact)
	if err != nil {
		assert.NoError(t, err, "failure artifact write for %s: %v", criterion, err)
		return
	}
	assert.True(t, false, "PDS criterion %s failed for %s; cloud release is held; failure artifact: %s", criterion, provider, path)
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil || ctx.Err() != nil {
		return context.Background()
	}
	return ctx
}

func TestPDSHandleAllowlist(t *testing.T) {
	for _, handle := range []string{"dottiethrowaway.bsky.social", "dottie.wallera.computer"} {
		if !allowedPDSHandle(handle) {
			assert.True(t, allowedPDSHandle(handle), "allowlist rejected %q", handle)
		}
	}
	for _, handle := range []string{"", "alice.example", "DOTTIEthrowaway.bsky.social", "dottiethrowaway.bsky.social.evil"} {
		if allowedPDSHandle(handle) {
			assert.False(t, allowedPDSHandle(handle), "allowlist accepted %q", handle)
		}
	}
}

func TestPDSFailureArtifactIsRedactedAndHoldsCloudRelease(t *testing.T) {
	path, err := writePDSFailureArtifact(t.TempDir(), pdsFailureArtifact{
		Provider:         "Bluesky-hosted",
		IntendedPDS:      "https://pds.example",
		Criterion:        "D2-positive-control",
		RedactedEvidence: `email=private@example.invalid eyJhbGciOiJub25lIn0.eyJ0b2tlbiI6InNpdGUtcmVhbGx5LXNlY3JldCJ9.signature12345678`,
		DecisionDOTF07:   "owner review required",
		CloudReleaseHold: true,
	})
	if err != nil {
		require.NoError(t, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		require.NoError(t, err)
	}
	if info.Mode().Perm() != 0o600 {
		require.Equal(t, 0o600, info.Mode().Perm(), "failure artifact mode=%o", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		require.NoError(t, err)
	}
	if bytes.Contains(body, []byte("private@example.invalid")) || bytes.Contains(body, []byte("signature12345678")) {
		require.NotContains(t, string(body), "private@example.invalid", "failure artifact leaked evidence: %s", body)
		require.NotContains(t, string(body), "signature12345678", "failure artifact leaked evidence: %s", body)
	}
	var artifact pdsFailureArtifact
	if err := json.Unmarshal(body, &artifact); err != nil {
		require.NoError(t, err)
	}
	if !artifact.CloudReleaseHold || artifact.Provider != "Bluesky-hosted" || artifact.Criterion != "D2-positive-control" || artifact.IntendedPDS != "https://pds.example" {
		require.True(t, artifact.CloudReleaseHold, "failure artifact fields=%+v", artifact)
		require.Equal(t, "Bluesky-hosted", artifact.Provider, "failure artifact fields=%+v", artifact)
		require.Equal(t, "D2-positive-control", artifact.Criterion, "failure artifact fields=%+v", artifact)
		require.Equal(t, "https://pds.example", artifact.IntendedPDS, "failure artifact fields=%+v", artifact)
	}
}

func TestPDSIdentityDataMinimisationReportsFieldNamesOnly(t *testing.T) {
	fields := unrequestedPDSIdentityFields([]byte(`{"did":"did:plc:abc","email":"private@example.invalid","emailConfirmed":true,"profile":{"phone":"+15555550123"}}`))
	if got := strings.Join(fields, ","); got != "email,emailConfirmed,phone" {
		require.Equal(t, "email,emailConfirmed,phone", got, "unrequested identity fields=%q", got)
	}
	if fields := unrequestedPDSIdentityFields([]byte(`{"did":"did:plc:abc","handle":"dottie.example"}`)); len(fields) != 0 {
		require.Len(t, fields, 0, "unexpected identity fields=%v", fields)
	}
}

func TestPDSBoundaryAttemptSizeNeverExceedsCeiling(t *testing.T) {
	for _, test := range []struct {
		name       string
		advertised int64
		known      bool
		ceiling    int64
		want       int64
	}{
		{name: "advertised above ceiling", advertised: 1000, known: true, ceiling: 500, want: 500},
		{name: "advertised below ceiling", advertised: 300, known: true, ceiling: 500, want: 300},
		{name: "unadvertised uses ceiling", ceiling: 500, want: 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := pdsBoundaryAttemptSize(test.advertised, test.known, test.ceiling)
			if err != nil || got != test.want || got > test.ceiling {
				require.NoError(t, err, "attempt size=%d error=%v want=%d ceiling=%d", got, err, test.want, test.ceiling)
				require.Equal(t, test.want, got, "attempt size=%d error=%v want=%d ceiling=%d", got, err, test.want, test.ceiling)
				require.LessOrEqual(t, got, test.ceiling, "attempt size=%d error=%v want=%d ceiling=%d", got, err, test.want, test.ceiling)
			}
		})
	}
	for _, test := range []struct {
		advertised int64
		known      bool
		ceiling    int64
	}{
		{advertised: 0, known: true, ceiling: 10},
		{advertised: 10, known: true, ceiling: 0},
	} {
		if _, err := pdsBoundaryAttemptSize(test.advertised, test.known, test.ceiling); err == nil {
			assert.Error(t, err, "invalid size inputs accepted: %+v", test)
		}
	}
}

func TestPDSRepeatReaderYieldsExactlyRequestedSize(t *testing.T) {
	reader := newPDSRepeatReader(47)
	data, err := io.ReadAll(reader)
	if err != nil || len(data) != 47 {
		require.NoError(t, err, "repeat reader returned %d bytes, error=%v", len(data), err)
		require.Len(t, data, 47, "repeat reader returned %d bytes, error=%v", len(data), err)
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		require.ErrorIs(t, err, io.EOF, "repeat reader after boundary error=%v", err)
	}
}

func TestPDSUploadRequestSetsExplicitOctetStreamContentType(t *testing.T) {
	request, err := pdsRequest(http.MethodPost, "com.atproto.repo.uploadBlob", nil, []byte("fixture"), "application/octet-stream")
	if err != nil {
		require.NoError(t, err)
	}
	if request.Headers.Get("Content-Type") != "application/octet-stream" {
		require.Equal(t, "application/octet-stream", request.Headers.Get("Content-Type"), "upload Content-Type=%q", request.Headers.Get("Content-Type"))
	}
}

func TestPDSResponseClassificationDistinguishesAuthorizationAndValidation(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		want   string
	}{
		{status: http.StatusForbidden, body: `{"error":"Forbidden"}`, want: "authorization"},
		{status: http.StatusBadRequest, body: `{"error":"AuthRequired"}`, want: "authorization"},
		{status: http.StatusBadRequest, body: `{"error":"InvalidRecord","message":"Lexicon validation failed"}`, want: "validation"},
		{status: http.StatusOK, want: "success"},
	} {
		if got := classifyPDSResult(test.status, []byte(test.body), nil); got != test.want {
			assert.Equal(t, test.want, got, "status=%d body=%s class=%q want=%q", test.status, test.body, got, test.want)
		}
	}
}

func TestLivePDSByteProbeConfigRequiresExplicitCeiling(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "+1", "1.5", "1e6", " 12", "9223372036854775808"} {
		if _, _, err := livePDSByteProbeConfig("1", value); err == nil || !strings.Contains(err.Error(), "DOTTIE_LIVE_PDS_BYTES") || !strings.Contains(err.Error(), "DOTTIE_LIVE_PDS_BYTE_CEILING") {
			assert.Error(t, err, "ceiling %q error = %v", value, err)
			if err != nil {
				assert.Contains(t, err.Error(), "DOTTIE_LIVE_PDS_BYTES", "ceiling %q error = %v", value, err)
				assert.Contains(t, err.Error(), "DOTTIE_LIVE_PDS_BYTE_CEILING", "ceiling %q error = %v", value, err)
			}
		}
	}
	enabled, ceiling, err := livePDSByteProbeConfig("1", "123")
	if err != nil || !enabled || ceiling != 123 {
		require.NoError(t, err, "valid size-probe config = %t %d %v", enabled, ceiling, err)
		require.True(t, enabled, "valid size-probe config = %t %d %v", enabled, ceiling, err)
		require.Equal(t, 123, ceiling, "valid size-probe config = %t %d %v", enabled, ceiling, err)
	}
	enabled, ceiling, err = livePDSByteProbeConfig("", "not-a-number")
	if err != nil || enabled || ceiling != 0 {
		require.NoError(t, err, "disabled size-probe config = %t %d %v", enabled, ceiling, err)
		require.False(t, enabled, "disabled size-probe config = %t %d %v", enabled, ceiling, err)
		require.Equal(t, 0, ceiling, "disabled size-probe config = %t %d %v", enabled, ceiling, err)
	}
}
