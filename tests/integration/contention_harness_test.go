package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const contentionDuplicateEffectUnproven = "unproven: final membership and returned commit CIDs cannot establish historical duplicate effects"

const (
	contentionHeadCollection    = "systems.lamb.dottie.vaultHead"
	contentionControlCollection = "systems.lamb.dottie.vaultControl"
	contentionExpiryHTTPBudget  = 34
	contentionShortHTTPBudget   = 600
	contentionRevisionBudget    = 160
	contentionApplyBudget       = 120
	contentionPublicationBudget = 12
	contentionCleanupBudget     = 12
	contentionLatencyMax        = 100
	contentionLatencyMinimum    = 200
)

var errContentionBudget = errors.New("contention harness budget exhausted")

type contentionBudgetError struct {
	Resource string
	Limit    int
	Observed int
}

func (e *contentionBudgetError) Error() string {
	return fmt.Sprintf("%s: %s budget limit=%d observed=%d", errContentionBudget, e.Resource, e.Limit, e.Observed)
}

func (e *contentionBudgetError) Is(target error) bool {
	return target == errContentionBudget
}

type contentionBudget struct {
	mu                        sync.Mutex
	httpLimit                 int
	applyLimit                int
	applyWireLimit            int
	revisionLimit             int
	publicationLimit          int
	cleanupLimit              int
	cleanupHTTPReserve        int
	latencyLimit              int
	expiryHTTP                bool
	cleaned                   bool
	httpRequests              int
	applyWrites               int
	applyWireRequests         int
	publicationWrites         int
	cleanupDeletes            int
	publicationCleanupDeletes int
	latencyCleanupDeletes     int
	expiryCleanupDeletes      int
	latencyUpdates            int
	revisionReads             int
	exceeded                  error
}

func newContentionBudget(expiry bool, latencyN int) *contentionBudget {
	budget := &contentionBudget{
		httpLimit:          contentionShortHTTPBudget,
		applyLimit:         contentionApplyBudget,
		applyWireLimit:     contentionApplyBudget,
		revisionLimit:      contentionRevisionBudget,
		publicationLimit:   contentionPublicationBudget,
		cleanupLimit:       4,
		cleanupHTTPReserve: 8,
		latencyLimit:       latencyN,
	}
	if expiry {
		budget.httpLimit = contentionExpiryHTTPBudget
		budget.applyLimit = contentionExpiryHTTPBudget
		budget.applyWireLimit = contentionExpiryHTTPBudget
		budget.revisionLimit = 8
		budget.publicationLimit = 0
		budget.cleanupLimit = 4
		budget.cleanupHTTPReserve = 8
		budget.latencyLimit = 0
		budget.expiryHTTP = true
	}
	return budget
}

func (b *contentionBudget) reserveHTTP(cleanup bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.httpLimit
	if !cleanup {
		limit -= b.cleanupHTTPReserve
	}
	if b.httpRequests+1 > limit {
		return b.failLocked("HTTP requests", limit, b.httpRequests+1)
	}
	b.httpRequests++
	return nil
}

func (b *contentionBudget) reserveApplyWire(cleanup bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.applyWireLimit
	if !cleanup {
		limit -= 2
	}
	if b.applyWireRequests+1 > limit {
		return b.failLocked("applyWrites wire requests", limit, b.applyWireRequests+1)
	}
	b.applyWireRequests++
	return nil
}

func (b *contentionBudget) remainingRevisionMeasurements() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.revisionLimit - 2 - b.revisionReads
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (b *contentionBudget) reserveRevision(cleanup bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.revisionLimit
	if !cleanup {
		limit -= 2
	}
	if b.revisionReads+1 > limit {
		return b.failLocked("verified revision reads", limit, b.revisionReads+1)
	}
	b.revisionReads++
	return nil
}

func (b *contentionBudget) reserveApply(kind string, writeCount int, deleteKinds map[string]int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if writeCount < 1 {
		writeCount = 1
	}
	if b.applyWrites+1 > b.applyLimit {
		return b.failLocked("applyWrites requests", b.applyLimit, b.applyWrites+1)
	}
	if kind != "cleanup" && b.applyWrites+1 > b.applyLimit-1 {
		return b.failLocked("applyWrites requests (cleanup reserve)", b.applyLimit-1, b.applyWrites+1)
	}
	if kind == "publication" && b.publicationWrites+1 > b.publicationLimit {
		return b.failLocked("contention/ambiguity publication attempts", b.publicationLimit, b.publicationWrites+1)
	}
	if kind == "latency" && b.latencyUpdates+1 > b.latencyLimit {
		return b.failLocked("latency update attempts", b.latencyLimit, b.latencyUpdates+1)
	}
	if kind == "cleanup" {
		for category, count := range deleteKinds {
			if count > 0 && category != "publication" && category != "latency" && category != "expiry" {
				return b.failLocked("unknown cleanup category", 0, count)
			}
		}
		contentionDeletes := deleteKinds["publication"]
		latencyDeletes := deleteKinds["latency"]
		expiryDeletes := deleteKinds["expiry"]
		if b.publicationCleanupDeletes+contentionDeletes > contentionCleanupBudget {
			return b.failLocked("contention/ambiguity cleanup deletes", contentionCleanupBudget, b.publicationCleanupDeletes+contentionDeletes)
		}
		if b.latencyCleanupDeletes+latencyDeletes > 1 {
			return b.failLocked("latency cleanup deletes", 1, b.latencyCleanupDeletes+latencyDeletes)
		}
		if b.expiryCleanupDeletes+expiryDeletes > b.cleanupLimit {
			return b.failLocked("expiry cleanup deletes", b.cleanupLimit, b.expiryCleanupDeletes+expiryDeletes)
		}
	}
	b.applyWrites++
	if kind == "publication" {
		b.publicationWrites++
	}
	if kind == "latency" {
		b.latencyUpdates++
	}
	if kind == "cleanup" {
		b.publicationCleanupDeletes += deleteKinds["publication"]
		b.latencyCleanupDeletes += deleteKinds["latency"]
		b.expiryCleanupDeletes += deleteKinds["expiry"]
		b.cleanupDeletes += deleteKinds["publication"] + deleteKinds["latency"] + deleteKinds["expiry"]
	}
	return nil
}

func (b *contentionBudget) failLocked(resource string, limit, observed int) error {
	if b.exceeded == nil {
		b.exceeded = &contentionBudgetError{Resource: resource, Limit: limit, Observed: observed}
	}
	return b.exceeded
}

func (b *contentionBudget) snapshot() (httpRequests, applyWrites, applyWireRequests, revisions, publications, cleanupDeletes, latencyUpdates int, exceeded error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.httpRequests, b.applyWrites, b.applyWireRequests, b.revisionReads, b.publicationWrites, b.cleanupDeletes, b.latencyUpdates, b.exceeded
}

func (b *contentionBudget) failure() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

func (b *contentionBudget) cleanupBreakdown() (publication, latency, expiry int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.publicationCleanupDeletes, b.latencyCleanupDeletes, b.expiryCleanupDeletes
}

type contentionRecordKey struct {
	Collection string
	RKey       string
}

type contentionRecordTracker struct {
	mu    sync.Mutex
	runID string
	kinds map[contentionRecordKey]string
}

func newContentionRecordTracker(runID string) *contentionRecordTracker {
	return &contentionRecordTracker{runID: runID, kinds: make(map[contentionRecordKey]string)}
}

func (r *contentionRecordTracker) track(keys []contentionRecordKey, category string) []contentionRecordKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	var newlyTracked []contentionRecordKey
	for _, key := range keys {
		if _, exists := r.kinds[key]; !exists {
			r.kinds[key] = category
			newlyTracked = append(newlyTracked, key)
		}
	}
	return newlyTracked
}

func (r *contentionRecordTracker) snapshot() map[contentionRecordKey]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[contentionRecordKey]string, len(r.kinds))
	for key, kind := range r.kinds {
		result[key] = kind
	}
	return result
}

type contentionWriteMonitor struct {
	mu         sync.Mutex
	dispatched bool
	wrote      bool
}

func (m *contentionWriteMonitor) markDispatched() {
	m.mu.Lock()
	m.dispatched = true
	m.mu.Unlock()
}

func (m *contentionWriteMonitor) markWritten() {
	m.mu.Lock()
	m.wrote = true
	m.mu.Unlock()
}

func (m *contentionWriteMonitor) state() (dispatched, wrote bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dispatched, m.wrote
}

type contentionAttemptEvidenceKey struct{}

type contentionAttemptEvidence struct {
	mu         sync.Mutex
	resolution contentionResolution
}

func (e *contentionAttemptEvidence) record(resolution contentionResolution) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.resolution = resolution
	e.mu.Unlock()
}

func (e *contentionAttemptEvidence) get() contentionResolution {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.resolution
}

type contentionWriteKindKey struct{}
type contentionWriteMonitorKey struct{}
type contentionWriterIDKey struct{}

type contentionHTTPRoundTripper struct {
	base   http.RoundTripper
	budget *contentionBudget
}

type contentionCleanupKey struct{}

func (t *contentionHTTPRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	cleanup, _ := request.Context().Value(contentionCleanupKey{}).(bool)
	if err := t.budget.reserveHTTP(cleanup); err != nil {
		return nil, err
	}
	if request.URL != nil && strings.Contains(request.URL.Path, "applyWrites") {
		if err := t.budget.reserveApplyWire(cleanup); err != nil {
			return nil, err
		}
	}
	if monitor, ok := request.Context().Value(contentionWriteMonitorKey{}).(*contentionWriteMonitor); ok {
		trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				monitor.markWritten()
			}
		}}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
		monitor.markDispatched()
	}
	return t.base.RoundTrip(request)
}

type contentionTransport struct {
	base    atproto.Transport
	budget  *contentionBudget
	tracker *contentionRecordTracker
}

func (t *contentionTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" {
		keys, deleteKinds, writeCount, err := contentionWriteKeys(body, t.tracker)
		if err != nil {
			return 0, nil, err
		}
		kind, _ := ctx.Value(contentionWriteKindKey{}).(string)
		if kind == "" {
			kind = "publication"
		}
		category, err := contentionCleanupCategory(kind)
		if err != nil {
			return 0, nil, err
		}
		if err := t.budget.reserveApply(kind, writeCount, deleteKinds); err != nil {
			return 0, nil, err
		}
		if t.tracker != nil {
			for _, key := range t.tracker.track(keys, category) {
				fmt.Printf("CONTENTION_TRACK run_id=%q collection=%q rkey=%q cleanup_category=%q before_first_send=true\n", t.tracker.runID, key.Collection, key.RKey, category)
			}
		}
	}
	status, response, err := t.base.Do(ctx, method, endpoint, query, body, contentType)
	if err != nil {
		if budgetErr := t.budget.failure(); budgetErr != nil {
			return status, response, budgetErr
		}
	}
	return status, response, err
}

func (t *contentionTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	status, body, err := t.base.OpenStream(ctx, endpoint, query)
	if err != nil {
		if budgetErr := t.budget.failure(); budgetErr != nil {
			return status, body, budgetErr
		}
	}
	return status, body, err
}

type contentionApplyInput struct {
	Repo       string            `json:"repo"`
	SwapCommit string            `json:"swapCommit"`
	Writes     []json.RawMessage `json:"writes"`
}

type contentionApplyWrite struct {
	Type       string          `json:"$type"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	Value      json.RawMessage `json:"value,omitempty"`
}

func contentionWriteKeys(body []byte, tracker *contentionRecordTracker) ([]contentionRecordKey, map[string]int, int, error) {
	var input struct {
		Writes []json.RawMessage `json:"writes"`
	}
	if err := json.Unmarshal(body, &input); err != nil || len(input.Writes) == 0 {
		return nil, nil, 0, errors.New("applyWrites request could not be inspected before send")
	}
	keys := make([]contentionRecordKey, 0, len(input.Writes))
	deleteKinds := make(map[string]int)
	for _, encoded := range input.Writes {
		var item struct {
			Type       string `json:"$type"`
			Collection string `json:"collection"`
			RKey       string `json:"rkey"`
		}
		if err := json.Unmarshal(encoded, &item); err != nil || item.Collection == "" || item.RKey == "" {
			return nil, nil, 0, errors.New("applyWrites record key could not be inspected before send")
		}
		key := contentionRecordKey{Collection: item.Collection, RKey: item.RKey}
		keys = append(keys, key)
		if strings.HasSuffix(item.Type, "#delete") {
			deleteKinds[trackerKind(tracker, key)]++
		}
	}
	return keys, deleteKinds, len(input.Writes), nil
}

func contentionCleanupCategory(operation string) (string, error) {
	switch operation {
	case "publication":
		return "publication", nil
	case "latency-init", "latency":
		return "latency", nil
	case "expiry":
		return "expiry", nil
	case "cleanup":
		return "cleanup", nil
	default:
		return "", fmt.Errorf("unknown contention cleanup category %q", operation)
	}
}

func trackerKind(tracker *contentionRecordTracker, key contentionRecordKey) string {
	if tracker == nil {
		return "publication"
	}
	if kind, exists := tracker.snapshot()[key]; exists {
		return kind
	}
	return "publication"
}

func newContentionHTTP1Transport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	return transport
}

func newContentionSetupHTTPClient(budget *contentionBudget) *http.Client {
	base := newContentionHTTP1Transport()
	return &http.Client{Transport: &contentionHTTPRoundTripper{base: base, budget: budget}, Timeout: 15 * time.Second}
}

func newContentionAPIClient(pds string, auth atclient.AuthMethod, budget *contentionBudget, layer func(http.RoundTripper) http.RoundTripper) (*atclient.APIClient, error) {
	base := newContentionHTTP1Transport()
	var transport http.RoundTripper = &contentionHTTPRoundTripper{base: base, budget: budget}
	if layer != nil {
		transport = layer(transport)
	}
	return newPDSAPIClient(pds, auth, transport)
}

type contentionReader struct {
	reader atproto.RevisionReader
	budget *contentionBudget
	did    string
}

func (r contentionReader) Read(ctx context.Context) (*atproto.Revision, error) {
	cleanup, _ := ctx.Value(contentionCleanupKey{}).(bool)
	if err := r.budget.reserveRevision(cleanup); err != nil {
		return nil, err
	}
	revision, err := r.reader.Read(ctx, r.did)
	if err != nil {
		if budgetErr := r.budget.failure(); budgetErr != nil {
			return nil, budgetErr
		}
	}
	return revision, err
}

type contentionMarker struct {
	Key        atproto.RecordKey
	RecordCID  string
	HeadCID    string
	ControlCID string
}

type contentionRevisionEvidence struct {
	Verified   bool
	Membership map[atproto.RecordKey]string
}

type contentionResolution string

const (
	contentionCommitted   contentionResolution = "committed"
	contentionSuperseded  contentionResolution = "committed-but-superseded"
	contentionNotLanded   contentionResolution = "not-landed"
	contentionUnavailable contentionResolution = "unavailable"
)

func contentionFinalMarkerMembership(marker contentionMarker, revision contentionRevisionEvidence) (available, present bool) {
	if !revision.Verified {
		return false, false
	}
	cidValue, ok := revision.Membership[marker.Key]
	return true, ok && cidValue == marker.RecordCID
}

func contentionCommitCIDsDistinct(attempts ...contentionAttempt) bool {
	if len(attempts) < 2 {
		return false
	}
	for _, attempt := range attempts {
		if attempt.Err != nil || attempt.Status < 200 || attempt.Status >= 300 {
			return false
		}
	}
	first := attempts[0].ReturnedCommit
	if !validContentionCID(first) {
		return false
	}
	for _, attempt := range attempts[1:] {
		if !validContentionCID(attempt.ReturnedCommit) || attempt.ReturnedCommit == first {
			return false
		}
	}
	return true
}

func resolveContentionMarker(marker contentionMarker, revision contentionRevisionEvidence) contentionResolution {
	if !revision.Verified {
		return contentionUnavailable
	}
	if cidValue, exists := revision.Membership[marker.Key]; !exists || cidValue != marker.RecordCID {
		return contentionNotLanded
	}
	if revision.Membership[atproto.RecordKey{Collection: contentionHeadCollection, RKey: "self"}] == marker.HeadCID && revision.Membership[atproto.RecordKey{Collection: contentionControlCollection, RKey: "self"}] == marker.ControlCID {
		return contentionCommitted
	}
	return contentionSuperseded
}

type contentionD1 string

const (
	contentionRejectedLocal   contentionD1 = "rejected-local"
	contentionNotSent         contentionD1 = "not-sent"
	contentionUnknown         contentionD1 = "unknown"
	contentionRejectedPreBlob contentionD1 = "rejected-pre-blob"
	contentionRejectedOther   contentionD1 = "rejected-other"
	contentionD1Committed     contentionD1 = "committed"
)

type contentionD1Input struct {
	LocalRejected bool
	NotSent       bool
	TransportErr  error
	Status        int
	Body          []byte
	CommitCID     string
	MarkerProven  bool
}

func classifyContentionD1(input contentionD1Input) contentionD1 {
	if input.LocalRejected {
		return contentionRejectedLocal
	}
	if input.NotSent {
		return contentionNotSent
	}
	if input.TransportErr != nil || input.Status >= 500 || !json.Valid(input.Body) {
		return contentionUnknown
	}
	if input.Status >= 400 && input.Status < 500 {
		var remoteError struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(input.Body, &remoteError) == nil && remoteError.Error == "InvalidSwap" {
			return contentionRejectedPreBlob
		}
		return contentionRejectedOther
	}
	if input.Status >= 200 && input.Status < 300 {
		if !validContentionCID(input.CommitCID) || !input.MarkerProven {
			return contentionUnknown
		}
		return contentionD1Committed
	}
	return contentionUnknown
}

func validContentionCID(value string) bool {
	parsed, err := cid.Parse(value)
	return err == nil && parsed.String() == value
}

func classifyContentionAttempt(requestErr error, dispatched, written bool, status int, body []byte, returnedCID string, resolution contentionResolution) contentionD1 {
	preDispatchFailure := !dispatched && !written
	localRejected := preDispatchFailure && (errors.Is(requestErr, errContentionBudget) || errors.Is(requestErr, atproto.ErrAuthMethodConfiguration) || errors.Is(requestErr, atproto.ErrAuthMethodHost) || errors.Is(requestErr, atproto.ErrAuthMethodSession) || errors.Is(requestErr, atproto.ErrAuthMethodNonReplayable))
	notSent := requestErr != nil && preDispatchFailure && !localRejected
	return classifyContentionD1(contentionD1Input{LocalRejected: localRejected, NotSent: notSent, TransportErr: requestErr, Status: status, Body: body, CommitCID: returnedCID, MarkerProven: resolution == contentionCommitted || resolution == contentionSuperseded})
}

func contentionRetryEvidenceEligible(outcome contentionD1, resolution contentionResolution) bool {
	return outcome == contentionNotSent || outcome == contentionUnknown && resolution == contentionNotLanded
}

func contentionCancellationDecision(attempt contentionAttempt) contentionAttempt {
	attempt.Inconclusive = true
	attempt.RetryEligible = contentionRetryEvidenceEligible(attempt.D1, attempt.Resolution)
	return attempt
}

type contentionAttempt struct {
	Experiment     string
	Status         int
	Body           []byte
	Err            error
	ReturnedCommit string
	Duration       time.Duration
	Written        bool
	Dispatched     bool
	D1             contentionD1
	Resolution     contentionResolution
	RetryEligible  bool
	Inconclusive   bool
}

const contentionAbsentOrInvalidCID = "absent-or-invalid"

func safeContentionCID(value string) string {
	if !validContentionCID(value) {
		return contentionAbsentOrInvalidCID
	}
	return value
}

func contentionReturnedCommit(body []byte) string {
	var response struct {
		Commit struct {
			CID string `json:"cid"`
		} `json:"commit"`
	}
	if json.Unmarshal(body, &response) != nil {
		return contentionAbsentOrInvalidCID
	}
	return safeContentionCID(response.Commit.CID)
}

func contentionResponseSummary(status int, body []byte) string {
	bodyClass := "json"
	if len(body) == 0 {
		bodyClass = "empty"
	} else if !json.Valid(body) {
		bodyClass = "malformed"
	}
	return fmt.Sprintf("status=%d body_bytes=%d body_class=%s", status, len(body), bodyClass)
}

func safeContentionError(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, errContentionBudget):
		return "budget-exhausted"
	case errors.Is(err, atproto.ErrAuthMethodSession):
		return "auth-session-error"
	case errors.Is(err, atproto.ErrAuthMethodNonce):
		return "auth-nonce-error"
	case errors.Is(err, atproto.ErrAuthMethodToken):
		return "auth-token-error"
	default:
		return "transport-error"
	}
}

type contentionLive struct {
	t         *testing.T
	ctx       context.Context
	provider  string
	identity  atproto.Identity
	budget    *contentionBudget
	tracker   *contentionRecordTracker
	transport *contentionTransport
	anonymous *contentionTransport
	reader    contentionReader
}

func newContentionLive(t *testing.T, ctx context.Context, provider string, identity atproto.Identity, session *atproto.Session, client *atproto.Client, budget *contentionBudget, authLayer func(http.RoundTripper) http.RoundTripper, runID string) (*contentionLive, error) {
	t.Helper()
	tracker := newContentionRecordTracker(runID)
	auth, err := atproto.NewAuthMethod(client, identity, identity.Handle, session)
	if err != nil {
		return nil, err
	}
	authAPI, err := newContentionAPIClient(identity.PDS, auth, budget, authLayer)
	if err != nil {
		return nil, err
	}
	anonymousAPI, err := newContentionAPIClient(identity.PDS, nil, budget, nil)
	if err != nil {
		return nil, err
	}
	authTransport := &contentionTransport{base: atproto.NewATClientTransport(authAPI), budget: budget, tracker: tracker}
	anonymous := &contentionTransport{base: atproto.NewATClientTransport(anonymousAPI), budget: budget, tracker: tracker}
	reader := atproto.RevisionReader{Transport: authTransport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID, VerificationMethods: identity.VerificationMethods}
	return &contentionLive{t: t, ctx: ctx, provider: provider, identity: identity, budget: budget, tracker: tracker, transport: authTransport, anonymous: anonymous, reader: contentionReader{reader: reader, budget: budget, did: identity.DID}}, nil
}

func newContentionRunID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func contentionDeadlineMinimum(long bool) time.Duration {
	if long {
		return 110 * time.Minute
	}
	return 30 * time.Minute
}

func contentionDeadlineError(deadline time.Time, hasDeadline, long bool) error {
	minimum := contentionDeadlineMinimum(long)
	if !hasDeadline || time.Until(deadline) < minimum {
		return fmt.Errorf("remaining go test runner deadline must be at least %s for the selected %s schedule, including setup and cleanup; invoke go test with an adequate -timeout", minimum, map[bool]string{true: "short plus long-expiry", false: "short"}[long])
	}
	return nil
}

func (l *contentionLive) fresh(ctx context.Context) (*atproto.Revision, error) {
	return l.reader.Read(ctx)
}

func (l *contentionLive) resolve(ctx context.Context, marker contentionMarker) contentionResolution {
	revision, err := l.fresh(ctx)
	if err != nil {
		return contentionUnavailable
	}
	return resolveContentionMarker(marker, contentionRevisionEvidence{Verified: true, Membership: revision.Membership()})
}

func (l *contentionLive) attempt(ctx context.Context, experiment string, transport atproto.Transport, revision *atproto.Revision, writes []contentionApplyWrite, marker contentionMarker, kind string) contentionAttempt {
	body, err := encodeContentionApply(l.identity.DID, revision.CommitCID(), writes)
	if err != nil {
		return contentionAttempt{Experiment: experiment, D1: contentionRejectedLocal, Err: err}
	}
	return l.attemptBody(ctx, experiment, transport, body, marker, kind)
}

func (l *contentionLive) attemptBody(ctx context.Context, experiment string, transport atproto.Transport, body []byte, marker contentionMarker, kind string) contentionAttempt {
	monitor := &contentionWriteMonitor{}
	evidence := &contentionAttemptEvidence{}
	ctx = context.WithValue(ctx, contentionWriteKindKey{}, kind)
	ctx = context.WithValue(ctx, contentionWriteMonitorKey{}, monitor)
	ctx = context.WithValue(ctx, contentionAttemptEvidenceKey{}, evidence)
	started := time.Now()
	status, response, requestErr := transport.Do(ctx, http.MethodPost, "com.atproto.repo.applyWrites", nil, body, "application/json")
	dispatched, written := monitor.state()
	attempt := contentionAttempt{Experiment: experiment, Status: status, Body: response, Err: requestErr, ReturnedCommit: contentionReturnedCommit(response), Duration: time.Since(started), Written: written, Dispatched: dispatched}
	resolution := evidence.get()
	if status >= 200 && status < 300 && requestErr == nil && validContentionCID(attempt.ReturnedCommit) && resolution == "" {
		resolution = l.resolve(ctx, marker)
	}
	attempt.D1 = classifyContentionAttempt(requestErr, attempt.Dispatched, attempt.Written, status, response, attempt.ReturnedCommit, resolution)
	if attempt.D1 == contentionUnknown && resolution == "" {
		resolveCtx := ctx
		if ctx.Err() != nil {
			resolveCtx = l.ctx
		}
		resolution = l.resolve(resolveCtx, marker)
	}
	attempt.Resolution = resolution
	attempt.RetryEligible = contentionRetryEvidenceEligible(attempt.D1, resolution)
	return attempt
}

func encodeContentionApply(did, swapCommit string, writes []contentionApplyWrite) ([]byte, error) {
	encoded := make([]json.RawMessage, 0, len(writes))
	for _, write := range writes {
		item, err := json.Marshal(write)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, item)
	}
	return json.Marshal(contentionApplyInput{Repo: did, SwapCommit: swapCommit, Writes: encoded})
}

func (l *contentionLive) markerFor(revision *atproto.Revision, rkey string, blobRef json.RawMessage) ([]contentionApplyWrite, contentionMarker, error) {
	snapshot := fenceSnapshotFixture{Type: fenceSnapshotCollection, Probe: rkey, Blob: blobRef, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		return nil, contentionMarker{}, err
	}
	snapshotCID, err := fenceRecordCID(snapshotBytes)
	if err != nil {
		return nil, contentionMarker{}, err
	}
	head := fenceHeadFixture{Type: contentionHeadCollection, SnapshotRKey: rkey, SnapshotCID: snapshotCID, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	headBytes, err := json.Marshal(head)
	if err != nil {
		return nil, contentionMarker{}, err
	}
	control := fenceControlFixture{Type: contentionControlCollection, Devices: []fenceControlDevice{{DID: l.identity.DID, Role: "owner"}}, PolicyEpoch: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	controlBytes, err := json.Marshal(control)
	if err != nil {
		return nil, contentionMarker{}, err
	}
	headCID, err := fenceRecordCID(headBytes)
	if err != nil {
		return nil, contentionMarker{}, err
	}
	controlCID, err := fenceRecordCID(controlBytes)
	if err != nil {
		return nil, contentionMarker{}, err
	}
	headAction := "create"
	if revision.HasRecord(atproto.RecordKey{Collection: contentionHeadCollection, RKey: "self"}) {
		headAction = "update"
	}
	controlAction := "create"
	if revision.HasRecord(atproto.RecordKey{Collection: contentionControlCollection, RKey: "self"}) {
		controlAction = "update"
	}
	writes := []contentionApplyWrite{
		{Type: "com.atproto.repo.applyWrites#create", Collection: fenceSnapshotCollection, RKey: rkey, Value: snapshotBytes},
		{Type: "com.atproto.repo.applyWrites#" + headAction, Collection: contentionHeadCollection, RKey: "self", Value: headBytes},
		{Type: "com.atproto.repo.applyWrites#" + controlAction, Collection: contentionControlCollection, RKey: "self", Value: controlBytes},
	}
	return writes, contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: rkey}, RecordCID: snapshotCID, HeadCID: headCID, ControlCID: controlCID}, nil
}

func (l *contentionLive) stageBlob(ctx context.Context, label string) (json.RawMessage, string, []byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", nil, err
	}
	data := append([]byte("DOT-F05 "+label+" "), nonce...)
	status, response, err := l.transport.Do(ctx, http.MethodPost, "com.atproto.repo.uploadBlob", nil, data, "application/octet-stream")
	if err != nil {
		return nil, "", data, fmt.Errorf("stage blob failed: %s: %w", contentionResponseSummary(status, response), err)
	}
	if status < 200 || status >= 300 {
		return nil, "", data, fmt.Errorf("stage blob failed: %s", contentionResponseSummary(status, response))
	}
	blobRef, cidValue, err := uploadedBlobRef(response)
	if err != nil {
		return nil, "", data, errors.New("uploaded blob response was invalid")
	}
	if !validContentionCID(cidValue) {
		return nil, "", data, errors.New("uploaded blob response contained an absent or invalid CID")
	}
	return blobRef, cidValue, data, nil
}

func (l *contentionLive) probeBlobBytes(ctx context.Context, experiment, cidValue string) (int, []byte, time.Duration, error) {
	started := time.Now()
	status, stream, err := l.anonymous.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {l.identity.DID}, "cid": {safeContentionCID(cidValue)}})
	if err != nil {
		elapsed := time.Since(started)
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q observation=%q staged_blob_cid=%q anonymous_status=%d timing_ms=%.3f probe_error=%q\n", l.provider, experiment, "anonymous-reachability", safeContentionCID(cidValue), status, float64(elapsed.Microseconds())/1000, safeContentionError(err))
		return status, nil, elapsed, err
	}
	if stream == nil {
		elapsed := time.Since(started)
		err = errors.New("anonymous blob request returned no body")
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q observation=%q staged_blob_cid=%q anonymous_status=%d timing_ms=%.3f probe_error=%q\n", l.provider, experiment, "anonymous-reachability", safeContentionCID(cidValue), status, float64(elapsed.Microseconds())/1000, safeContentionError(err))
		return status, nil, elapsed, err
	}
	body, readErr := io.ReadAll(io.LimitReader(stream, 2<<20+1))
	closeErr := stream.Close()
	if len(body) > 2<<20 {
		readErr = errors.New("anonymous blob response exceeded harness limit")
	}
	if readErr != nil {
		err = readErr
	} else if closeErr != nil {
		err = closeErr
	}
	elapsed := time.Since(started)
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q observation=%q staged_blob_cid=%q anonymous_status=%d timing_ms=%.3f probe_error=%q response_bytes=%d\n", l.provider, experiment, "anonymous-reachability", safeContentionCID(cidValue), status, float64(elapsed.Microseconds())/1000, safeContentionError(err), len(body))
	return status, body, elapsed, err
}

func (l *contentionLive) probeBlob(ctx context.Context, experiment, cidValue string) (int, time.Duration, error) {
	status, _, elapsed, err := l.probeBlobBytes(ctx, experiment, cidValue)
	return status, elapsed, err
}

func (l *contentionLive) probeBlobExact(ctx context.Context, experiment, cidValue string, expected []byte) (int, bool, time.Duration, error) {
	status, body, elapsed, err := l.probeBlobBytes(ctx, experiment, cidValue)
	exact := err == nil && status >= 200 && status < 300 && bytes.Equal(body, expected)
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q exact_staged_bytes_reachable=%t\n", l.provider, experiment, exact)
	return status, exact, elapsed, err
}

func printContentionAttempt(provider, experiment string, attempt contentionAttempt) {
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q d1=%q resolution=%q retry_evidence_eligible=%t http_status=%d returned_commit_cid=%q request_written=%t timing_ms=%.3f response=%q error_class=%q\n", provider, experiment, attempt.D1, attempt.Resolution, attempt.RetryEligible, attempt.Status, safeContentionCID(attempt.ReturnedCommit), attempt.Written, float64(attempt.Duration.Microseconds())/1000, contentionResponseSummary(attempt.Status, attempt.Body), safeContentionError(attempt.Err))
}

type contentionRequestInterval struct {
	writer string
	start  time.Time
	end    time.Time
}

type contentionBarrier struct {
	mu              sync.Mutex
	arrivals        int
	release         chan struct{}
	once            sync.Once
	intervals       []contentionRequestInterval
	nonceChallenges int
}

func newContentionBarrier() *contentionBarrier {
	return &contentionBarrier{release: make(chan struct{})}
}

func (b *contentionBarrier) layer(base http.RoundTripper) http.RoundTripper {
	return &contentionBarrierRoundTripper{base: base, barrier: b}
}

type contentionBarrierRoundTripper struct {
	base    http.RoundTripper
	barrier *contentionBarrier
}

func (t *contentionBarrierRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	isApply := request.URL != nil && strings.HasSuffix(request.URL.Path, "/xrpc/com.atproto.repo.applyWrites")
	if isApply {
		b := t.barrier
		b.mu.Lock()
		if b.arrivals < 2 {
			b.arrivals++
			if b.arrivals == 2 {
				b.once.Do(func() { close(b.release) })
			}
			b.mu.Unlock()
			timer := time.NewTimer(30 * time.Second)
			defer timer.Stop()
			select {
			case <-b.release:
			case <-timer.C:
				return nil, errors.New("contention send barrier timed out")
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
		} else {
			b.mu.Unlock()
		}
	}
	writer, _ := request.Context().Value(contentionWriterIDKey{}).(string)
	if isApply {
		var stateMu sync.Mutex
		var writeStart, responseStart time.Time
		appended := false
		appendInterval := func() {
			stateMu.Lock()
			complete := !appended && !writeStart.IsZero() && !responseStart.IsZero() && !responseStart.Before(writeStart)
			interval := contentionRequestInterval{writer: writer, start: writeStart, end: responseStart}
			if complete {
				appended = true
			}
			stateMu.Unlock()
			if complete {
				t.barrier.mu.Lock()
				t.barrier.intervals = append(t.barrier.intervals, interval)
				t.barrier.mu.Unlock()
			}
		}
		trace := &httptrace.ClientTrace{
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				observed := time.Now()
				if info.Err != nil {
					return
				}
				stateMu.Lock()
				if writeStart.IsZero() {
					writeStart = observed
				}
				stateMu.Unlock()
				appendInterval()
			},
			GotFirstResponseByte: func() {
				observed := time.Now()
				stateMu.Lock()
				if responseStart.IsZero() {
					responseStart = observed
				}
				stateMu.Unlock()
				appendInterval()
			},
		}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	}
	response, err := t.base.RoundTrip(request)
	if response != nil && (response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized) && response.Header.Get("DPoP-Nonce") != "" {
		t.barrier.mu.Lock()
		t.barrier.nonceChallenges++
		t.barrier.mu.Unlock()
	}
	return response, err
}

func contentionMaximumOverlap(intervals []contentionRequestInterval) int {
	type event struct {
		at     time.Time
		delta  int
		writer string
	}
	events := make([]event, 0, len(intervals)*2)
	for _, interval := range intervals {
		if interval.writer == "" || interval.start.IsZero() || interval.end.IsZero() || interval.end.Before(interval.start) {
			continue
		}
		events = append(events, event{at: interval.start, delta: 1, writer: interval.writer}, event{at: interval.end, delta: -1, writer: interval.writer})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at.Equal(events[j].at) {
			return events[i].delta < events[j].delta
		}
		return events[i].at.Before(events[j].at)
	})
	active := make(map[string]int)
	activeWriters, maximum := 0, 0
	for _, item := range events {
		if item.delta < 0 {
			active[item.writer]--
			if active[item.writer] == 0 {
				delete(active, item.writer)
				activeWriters--
			}
			continue
		}
		if active[item.writer] == 0 {
			activeWriters++
		}
		active[item.writer]++
		if activeWriters > maximum {
			maximum = activeWriters
		}
	}
	return maximum
}

func (b *contentionBarrier) snapshot() (arrivals, overlap, nonceChallenges, intervals int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.arrivals, contentionMaximumOverlap(b.intervals), b.nonceChallenges, len(b.intervals)
}

type contentionCommitThenError struct {
	base               atproto.Transport
	reader             contentionReader
	verify             func(context.Context, contentionMarker) (contentionResolution, error)
	marker             contentionMarker
	forwardedStatus    int
	forwardedBody      []byte
	forwardedCID       string
	verifiedCommit     bool
	responseSuppressed bool
}

func (t *contentionCommitThenError) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	status, response, err := t.base.Do(ctx, method, endpoint, query, body, contentType)
	if endpoint == "com.atproto.repo.applyWrites" {
		t.forwardedStatus = status
		t.forwardedBody = append([]byte(nil), response...)
		t.forwardedCID = contentionReturnedCommit(response)
	}
	if endpoint != "com.atproto.repo.applyWrites" || err != nil || status < 200 || status >= 300 {
		return status, response, err
	}
	resolution, verifyErr := t.verifyMarker(ctx)
	if verifyErr != nil {
		contentionRecordAttemptResolution(ctx, contentionUnavailable)
		return status, response, fmt.Errorf("forwarded response suppression verification unavailable: %w", verifyErr)
	}
	contentionRecordAttemptResolution(ctx, resolution)
	if resolution != contentionCommitted && resolution != contentionSuperseded {
		return status, response, fmt.Errorf("forwarded response suppression could not prove committed marker: resolution=%s", resolution)
	}
	t.verifiedCommit = true
	t.responseSuppressed = true
	return 0, nil, errors.New("synthetic response loss after independently verified commit")
}

func (t *contentionCommitThenError) verifyMarker(ctx context.Context) (contentionResolution, error) {
	if t.verify != nil {
		return t.verify(ctx, t.marker)
	}
	revision, err := t.reader.Read(ctx)
	if err != nil {
		return contentionUnavailable, err
	}
	return resolveContentionMarker(t.marker, contentionRevisionEvidence{Verified: true, Membership: revision.Membership()}), nil
}

func (t *contentionCommitThenError) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return t.base.OpenStream(ctx, endpoint, query)
}

type contentionAbsentThenError struct {
	base             atproto.Transport
	reader           contentionReader
	verify           func(context.Context, contentionMarker) (*atproto.Revision, contentionResolution, error)
	marker           contentionMarker
	forwardedStatus  int
	forwardedBody    []byte
	forwardedErr     error
	forwardedAt      time.Time
	verifiedRevision *atproto.Revision
	verifiedAbsent   bool
}

func (t *contentionAbsentThenError) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	status, response, err := t.base.Do(ctx, method, endpoint, query, body, contentType)
	if endpoint != "com.atproto.repo.applyWrites" {
		return status, response, err
	}
	t.forwardedStatus = status
	t.forwardedBody = append([]byte(nil), response...)
	t.forwardedErr = err
	t.forwardedAt = time.Now()
	monitor, _ := ctx.Value(contentionWriteMonitorKey{}).(*contentionWriteMonitor)
	if monitor == nil {
		return status, response, err
	}
	_, written := monitor.state()
	if !written {
		return status, response, err
	}
	var revision *atproto.Revision
	var resolution contentionResolution
	var readErr error
	if t.verify != nil {
		revision, resolution, readErr = t.verify(ctx, t.marker)
	} else {
		revision, readErr = t.reader.Read(ctx)
		if readErr == nil {
			resolution = resolveContentionMarker(t.marker, contentionRevisionEvidence{Verified: true, Membership: revision.Membership()})
		}
	}
	if readErr != nil {
		contentionRecordAttemptResolution(ctx, contentionUnavailable)
		return status, response, fmt.Errorf("response suppression verification unavailable: %w", readErr)
	}
	t.verifiedRevision = revision
	contentionRecordAttemptResolution(ctx, resolution)
	if resolution == contentionNotLanded {
		t.verifiedAbsent = true
		return 0, nil, errors.New("synthetic response suppression after independently verified absence")
	}
	return status, response, err
}

func contentionRecordAttemptResolution(ctx context.Context, resolution contentionResolution) {
	evidence, _ := ctx.Value(contentionAttemptEvidenceKey{}).(*contentionAttemptEvidence)
	evidence.record(resolution)
}

func (t *contentionAbsentThenError) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return t.base.OpenStream(ctx, endpoint, query)
}

type contentionCancelRoundTripper struct {
	base   http.RoundTripper
	cancel context.CancelFunc
	once   sync.Once
	mu     sync.Mutex
	fired  bool
}

func (t *contentionCancelRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL != nil && strings.HasSuffix(request.URL.Path, "/xrpc/com.atproto.repo.applyWrites") {
		trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) {
			t.once.Do(func() {
				t.mu.Lock()
				t.fired = true
				t.mu.Unlock()
				t.cancel()
			})
		}}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	}
	return t.base.RoundTrip(request)
}

func (t *contentionCancelRoundTripper) wasCanceled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fired
}

func TestLiveContention(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_CONTENTION") != "1" {
		t.Skip("set DOTTIE_LIVE_CONTENTION=1 with explicit disposable-account authorization to run the contention and ambiguous-failure harness")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if !allowedPDSHandle(handle) {
		require.True(t, allowedPDSHandle(handle), "DOTTIE_HANDLE %q is not in the live PDS disposable-identity allowlist", handle)
	}
	latencyN, err := contentionLatencyCount(os.Getenv("DOTTIE_LIVE_LATENCY_N"))
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	longExpiry := os.Getenv("DOTTIE_LIVE_EXPIRY") == "1"
	deadline, hasDeadline := t.Deadline()
	if err := contentionDeadlineError(deadline, hasDeadline, longExpiry); err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	runID, err := newContentionRunID()
	if err != nil {
		require.NoError(t, err, "create F05 run identifier: %s", safeContentionError(err))
	}
	provider := pdsProviderName(handle)
	fmt.Printf("CONTENTION_RUN run_id=%q provider=%q schedule=%q\n", runID, provider, map[bool]string{true: "short-plus-long-expiry", false: "short"}[longExpiry])
	keyring, err := platform.NewKeyring()
	if err != nil {
		require.NoError(t, err, "open Secret Service keyring: %s", safeContentionError(err))
	}
	defer keyring.Close()
	shortBudget := newContentionBudget(false, latencyN)
	client, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring, atproto.WithHTTPClient(newContentionSetupHTTPClient(shortBudget)))
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer setupCancel()
	identity, err := client.Discover(setupCtx, handle)
	if err != nil {
		pdsRecordFailure(t, provider, "unknown", "F05-discovery", safeContentionError(err))
		require.NoError(t, err, "discover %s: %s", handle, safeContentionError(err))
	}
	session, err := client.LoadSession(setupCtx, identity.DID)
	if err != nil {
		require.NoError(t, err, "load existing scoped OAuth session for %s: %s", handle, safeContentionError(err))
	}
	for _, required := range []string{"atproto", "repo:" + fenceSnapshotCollection, "repo:" + contentionHeadCollection, "repo:" + contentionControlCollection, "blob:application/octet-stream"} {
		if !hasPDScope(session.Scopes, required) {
			require.True(t, hasPDScope(session.Scopes, required), "loaded session does not include required scope %q", required)
		}
	}
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer shortCancel()
	short, err := newContentionLive(t, shortCtx, provider, identity, session, client, shortBudget, nil, runID)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	initial, err := short.fresh(shortCtx)
	if err != nil {
		require.NoError(t, err, "read initial fully verified revision: %s", safeContentionError(err))
	}
	for _, key := range []atproto.RecordKey{{Collection: contentionHeadCollection, RKey: "self"}, {Collection: contentionControlCollection, RKey: "self"}} {
		if initial.HasRecord(key) {
			require.False(t, initial.HasRecord(key), "refusing F05 run because provisional head/control self already exists: %s/%s; reconcile the prior run manually", key.Collection, key.RKey)
		}
	}
	defer short.cleanup()
	runContentionExperiments(t, short, client, session, handle, latencyN)
	short.cleanup()
	if os.Getenv("DOTTIE_LIVE_EXPIRY") == "1" {
		t.Run("expiry-long", func(t *testing.T) {
			longCtx, longCancel := context.WithTimeout(context.Background(), 75*time.Minute)
			defer longCancel()
			longBudget := newContentionBudget(true, 0)
			longClient, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring, atproto.WithHTTPClient(newContentionSetupHTTPClient(longBudget)))
			if err != nil {
				require.NoError(t, err, safeContentionError(err))
			}
			long, err := newContentionLive(t, longCtx, provider, identity, session, longClient, longBudget, nil, runID)
			if err != nil {
				require.NoError(t, err, safeContentionError(err))
			}
			longInitial, err := long.fresh(longCtx)
			if err != nil {
				require.NoError(t, err, "long-expiry initial verified revision: %s", safeContentionError(err))
			}
			for _, key := range []atproto.RecordKey{{Collection: contentionHeadCollection, RKey: "self"}, {Collection: contentionControlCollection, RKey: "self"}} {
				if longInitial.HasRecord(key) {
					require.False(t, longInitial.HasRecord(key), "long-expiry refusing pre-existing provisional self record %s/%s; reconcile the prior run manually", key.Collection, key.RKey)
				}
			}
			defer long.cleanup()
			runExpiryAges(t, long, []time.Duration{15 * time.Minute, 60 * time.Minute}, "long")
		})
	} else {
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q status=%q detail=%q\n", provider, "long-expiry", "unmeasured", "set DOTTIE_LIVE_EXPIRY=1 for the separately budgeted +15m/+60m referenceability run")
	}
}

func runContentionExperiments(t *testing.T, live *contentionLive, client *atproto.Client, session *atproto.Session, handle string, latencyN int) {
	t.Helper()
	ctx := live.ctx
	initial, err := live.fresh(ctx)
	if err != nil {
		require.NoError(t, err, "contention initial revision: %s", safeContentionError(err))
	}
	barrier := newContentionBarrier()
	apiOne, transportOne, err := newContentionWriter(live, client, session, handle, barrier.layer)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	apiTwo, transportTwo, err := newContentionWriter(live, client, session, handle, barrier.layer)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	_ = apiOne
	_ = apiTwo
	blobA, cidA, _, err := live.stageBlob(ctx, "experiment-1-writer-a")
	if err != nil {
		require.NoError(t, err, "stage contention candidate A: %s", safeContentionError(err))
	}
	blobB, cidB, _, err := live.stageBlob(ctx, "experiment-1-writer-b")
	if err != nil {
		require.NoError(t, err, "stage contention candidate B: %s", safeContentionError(err))
	}
	keyA := newFenceProbeKey(t)
	keyB := newFenceProbeKey(t)
	writesA, markerA, err := live.markerFor(initial, keyA, blobA)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	writesB, markerB, err := live.markerFor(initial, keyB, blobB)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	attempts := runBarrierPair(ctx, live, barrier, transportOne, transportTwo, initial, writesA, markerA, writesB, markerB, "experiment-1-two-writer-contention")
	for _, attempt := range attempts {
		printContentionAttempt(live.provider, attempt.Experiment, attempt)
	}
	committed := 0
	fenceLost := 0
	for _, attempt := range attempts {
		if contentionSettledCommitted(attempt) {
			committed++
		}
		if attempt.D1 == contentionRejectedPreBlob {
			fenceLost++
		}
	}
	deterministicLoss := committed == 1 && fenceLost == 1
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q stale_writer_deterministic_loss=%t committed=%d structured_fence_losses=%d\n", live.provider, "experiment-1-two-writer-contention", deterministicLoss, committed, fenceLost)
	if !deterministicLoss {
		pdsRecordFailure(t, live.provider, live.identity.PDS, "F05-stale-writer-deterministic-loss", fmt.Sprintf("committed=%d structured_fence_losses=%d", committed, fenceLost))
	}
	arrivals, overlap, nonceChallenges, intervalCount := barrier.snapshot()
	overlapStatus := "inconclusive: no overlapping request-write intervals observed"
	if overlap >= 2 {
		overlapStatus = "overlap observed"
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q label=%q barrier_arrivals=%d recorded_writer_request_intervals=%d maximum_in_flight_writers=%d overlap_status=%q dpop_nonce_challenges=%d staged_blob_cids=%q\n", live.provider, "experiment-1-two-writer-contention", "simulated two-device, shared session", arrivals, intervalCount, overlap, overlapStatus, nonceChallenges, []string{safeContentionCID(cidA), safeContentionCID(cidB)})
	for _, item := range []struct{ cidValue, label string }{{cidA, "experiment-1-writer-a"}, {cidB, "experiment-1-writer-b"}} {
		if _, _, err := live.probeBlob(ctx, item.label, item.cidValue); err != nil {
			assert.NoError(t, err, "anonymous candidate probe %s: %s", item.label, safeContentionError(err))
		}
	}

	runReplayAndIdenticalRace(t, live, client, session, handle)
	arrivals, overlap, nonceChallenges, intervalCount = barrier.snapshot()
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q stratum=%q source_experiment=%q barrier_arrivals=%d recorded_writer_request_intervals=%d maximum_in_flight_writers=%d overlap_observed=%t nonce_challenges=%d\n", live.provider, "experiment-1-dpop-nonce-contention-stratum", "DPoP-nonce contention", "experiment-1-two-writer-contention", arrivals, intervalCount, overlap, overlap >= 2, nonceChallenges)
	runAmbiguousFailureExperiments(t, live, client, session, handle)
	runRejectionRows(t, live, session)
	runExpiryAges(t, live, []time.Duration{0, time.Minute, 5 * time.Minute}, "short")
	runLatencyProfile(t, live, latencyN)
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q status=%q rule=%q\n", live.provider, "D8-viability", "unmeasured until live runs on both providers", "fail any stale/duplicate deterministic-loss, exactly-one-D1-state, or post-blob disclosure-duration criterion => not viable as designed; expiry is separate")
}

func newContentionWriter(live *contentionLive, client *atproto.Client, session *atproto.Session, handle string, layer func(http.RoundTripper) http.RoundTripper) (*atclient.APIClient, *contentionTransport, error) {
	writerClient, err := atproto.NewClient(client.ClientID, client.Store, atproto.WithHTTPClient(newContentionSetupHTTPClient(live.budget)))
	if err != nil {
		return nil, nil, err
	}
	writerSession := cloneContentionSession(session)
	auth, err := atproto.NewAuthMethod(writerClient, live.identity, handle, writerSession)
	if err != nil {
		return nil, nil, err
	}
	api, err := newContentionAPIClient(live.identity.PDS, auth, live.budget, layer)
	if err != nil {
		return nil, nil, err
	}
	transport := &contentionTransport{base: atproto.NewATClientTransport(api), budget: live.budget, tracker: live.tracker}
	return api, transport, nil
}

func cloneContentionSession(session *atproto.Session) *atproto.Session {
	if session == nil {
		return nil
	}
	return &atproto.Session{
		DID:            session.DID,
		Issuer:         session.Issuer,
		TokenEndpoint:  session.TokenEndpoint,
		Scopes:         append([]string(nil), session.Scopes...),
		AccessToken:    atproto.NewSecret(session.AccessToken.Reveal()),
		RefreshToken:   atproto.NewSecret(session.RefreshToken.Reveal()),
		DPoPPrivateKey: atproto.NewSecret(session.DPoPPrivateKey.Reveal()),
	}
}

func runBarrierPair(ctx context.Context, live *contentionLive, barrier *contentionBarrier, first, second atproto.Transport, revision *atproto.Revision, firstWrites []contentionApplyWrite, firstMarker contentionMarker, secondWrites []contentionApplyWrite, secondMarker contentionMarker, experiment string) []contentionAttempt {
	start := make(chan struct{})
	results := make(chan contentionAttempt, 2)
	for _, input := range []struct {
		transport atproto.Transport
		writes    []contentionApplyWrite
		marker    contentionMarker
		name      string
	}{{first, firstWrites, firstMarker, experiment + "/writer-a"}, {second, secondWrites, secondMarker, experiment + "/writer-b"}} {
		input := input
		go func() {
			<-start
			writerCtx := context.WithValue(ctx, contentionWriterIDKey{}, input.name)
			results <- live.attempt(writerCtx, input.name, input.transport, revision, input.writes, input.marker, "publication")
		}()
	}
	close(start)
	attempts := []contentionAttempt{<-results, <-results}
	if errors.Is(live.budgetError(), errContentionBudget) {
		require.NotErrorIs(live.t, live.budgetError(), errContentionBudget, "contention experiment budget exhausted: %s", safeContentionError(live.budgetError()))
	}
	_ = barrier
	return attempts
}

func runReplayAndIdenticalRace(t *testing.T, live *contentionLive, client *atproto.Client, session *atproto.Session, handle string) {
	t.Helper()
	ctx := live.ctx
	captured, err := live.fresh(ctx)
	if err != nil {
		require.NoError(t, err, "capture replay revision: %s", safeContentionError(err))
	}
	blobRef, _, _, err := live.stageBlob(ctx, "experiment-2-replay-and-race")
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	rkey := newFenceProbeKey(t)
	writes, marker, err := live.markerFor(captured, rkey, blobRef)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	success := live.attempt(ctx, "experiment-2-replay-after-success/first", live.transport, captured, writes, marker, "publication")
	printContentionAttempt(live.provider, success.Experiment, success)
	if contentionSettledCommitted(success) {
		replay := live.attempt(ctx, "experiment-2-replay-after-success/replay-same-body", live.transport, captured, writes, marker, "publication")
		printContentionAttempt(live.provider, replay.Experiment, replay)
		finalRevision, readErr := live.fresh(ctx)
		markerAvailable, markerPresent := false, false
		if readErr == nil {
			markerAvailable, markerPresent = contentionFinalMarkerMembership(marker, contentionRevisionEvidence{Verified: true, Membership: finalRevision.Membership()})
		}
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q first_http_status=%d first_d1=%q first_resolution=%q first_commit_cid=%q replay_http_status=%d replay_d1=%q replay_resolution=%q replay_commit_cid=%q returned_commit_cids_distinct=%t marker_cid=%q final_exact_marker_membership=%t marker_evidence_available=%t duplicate_effect_invariant=%q verification_error_class=%q\n", live.provider, "experiment-2-replay-after-success", success.Status, success.D1, success.Resolution, safeContentionCID(success.ReturnedCommit), replay.Status, replay.D1, replay.Resolution, safeContentionCID(replay.ReturnedCommit), contentionCommitCIDsDistinct(success, replay), safeContentionCID(marker.RecordCID), markerPresent, markerAvailable, contentionDuplicateEffectUnproven, safeContentionError(readErr))
		if readErr != nil {
			assert.NoError(t, readErr, "replay logical-effect verification unavailable: %s", safeContentionError(readErr))
		}
	} else {
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q first_http_status=%d first_d1=%q first_resolution=%q first_commit_cid=%q replay_result=%q marker_cid=%q final_exact_marker_membership=%q duplicate_effect_invariant=%q\n", live.provider, "experiment-2-replay-after-success", success.Status, success.D1, success.Resolution, safeContentionCID(success.ReturnedCommit), "not attempted: initial marker was not proven committed", safeContentionCID(marker.RecordCID), "unavailable", "unproven")
	}

	raceRevision, err := live.fresh(ctx)
	if err != nil {
		require.NoError(t, err, "capture identical-race revision: %s", safeContentionError(err))
	}
	raceBlob, _, _, err := live.stageBlob(ctx, "experiment-3-racing-identical-batch")
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	raceKey := newFenceProbeKey(t)
	raceWrites, raceMarker, err := live.markerFor(raceRevision, raceKey, raceBlob)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	barrier := newContentionBarrier()
	_, transportA, err := newContentionWriter(live, client, session, handle, barrier.layer)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	_, transportB, err := newContentionWriter(live, client, session, handle, barrier.layer)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	attempts := runBarrierPair(ctx, live, barrier, transportA, transportB, raceRevision, raceWrites, raceMarker, raceWrites, raceMarker, "experiment-3-racing-identical-batch")
	for _, attempt := range attempts {
		printContentionAttempt(live.provider, attempt.Experiment, attempt)
	}
	outcomeA := attempts[0]
	outcomeB := attempts[1]
	twoOK := outcomeA.Status >= 200 && outcomeA.Status < 300 && outcomeB.Status >= 200 && outcomeB.Status < 300
	arrivals, overlap, nonceChallenges, intervalCount := barrier.snapshot()
	postRace, readErr := live.fresh(ctx)
	markerAvailable, markerPresent := false, false
	if readErr == nil {
		markerAvailable, markerPresent = contentionFinalMarkerMembership(raceMarker, contentionRevisionEvidence{Verified: true, Membership: postRace.Membership()})
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q required_row=%q observed=%t outcomes=%q/%q returned_commit_cids=%q/%q returned_commit_cids_distinct=%t marker_cid=%q final_exact_marker_membership=%t marker_evidence_available=%t duplicate_effect_invariant=%q recorded_writer_request_intervals=%d maximum_in_flight_writers=%d overlap_observed=%t nonce_challenges=%d\n", live.provider, "experiment-3-racing-identical-batch", "2xx/2xx", twoOK, httpOutcome(outcomeA), httpOutcome(outcomeB), safeContentionCID(outcomeA.ReturnedCommit), safeContentionCID(outcomeB.ReturnedCommit), contentionCommitCIDsDistinct(outcomeA, outcomeB), safeContentionCID(raceMarker.RecordCID), markerPresent, markerAvailable, contentionDuplicateEffectUnproven, intervalCount, overlap, overlap >= 2, nonceChallenges)
	if arrivals != 2 || overlap < 2 {
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q overlap_status=%q\n", live.provider, "experiment-3-racing-identical-batch", "inconclusive: no overlapping request-write intervals observed")
	}
	if readErr != nil {
		assert.NoError(t, readErr, "identical race final marker verification unavailable: %s", safeContentionError(readErr))
	}
}

func httpOutcome(attempt contentionAttempt) string {
	if attempt.Err != nil {
		return "transport-error"
	}
	return fmt.Sprintf("http-%d", attempt.Status)
}

func contentionSettledCommitted(attempt contentionAttempt) bool {
	return attempt.D1 == contentionD1Committed || attempt.Resolution == contentionCommitted || attempt.Resolution == contentionSuperseded
}

func contentionDisclosureDurationMeasured(status int, markerAbsent, noCandidateReferences, reachableBefore, exactBytesAfter bool) bool {
	return status >= 400 && status < 500 && markerAbsent && noCandidateReferences && !reachableBefore && exactBytesAfter
}

func contentionExperiment4aRow(provider string, attempt contentionAttempt, blobCID string, forwardedStatus int, forwardedCID string, markerVerified, responseSuppressed bool) string {
	if markerVerified && responseSuppressed {
		return fmt.Sprintf("CONTENTION_MATRIX provider=%q experiment=%q status=%q outcome=%q staged_blob_cid=%q forwarded_http_status=%d forwarded_commit_cid=%q marker_verified=true response_suppressed=true assertion=%q", provider, "experiment-4a-committed-but-response-lost", "measured", attempt.D1, safeContentionCID(blobCID), forwardedStatus, safeContentionCID(forwardedCID), "forwarded request verified committed before synthetic transport error")
	}
	return fmt.Sprintf("CONTENTION_MATRIX provider=%q experiment=%q status=%q construction=%q outcome=%q staged_blob_cid=%q forwarded_http_status=%d forwarded_commit_cid=%q marker_verified=%t response_suppressed=%t", provider, "experiment-4a-response-loss-construction", "unmeasured/inconclusive", "construction-failed", attempt.D1, safeContentionCID(blobCID), forwardedStatus, safeContentionCID(forwardedCID), markerVerified, responseSuppressed)
}

func runAmbiguousFailureExperiments(t *testing.T, live *contentionLive, client *atproto.Client, session *atproto.Session, handle string) {
	t.Helper()
	ctx := live.ctx
	captured, err := live.fresh(ctx)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	blobRef, cidValue, _, err := live.stageBlob(ctx, "experiment-4a-response-lost")
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	before, _, err := live.probeBlob(ctx, "experiment-4a-before", cidValue)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	key := newFenceProbeKey(t)
	writes, marker, err := live.markerFor(captured, key, blobRef)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	lost := &contentionCommitThenError{base: live.transport, reader: live.reader, marker: marker}
	first := live.attempt(ctx, "experiment-4a-forward-verified-then-response-lost", lost, captured, writes, marker, "publication")
	printContentionAttempt(live.provider, first.Experiment, first)
	after, _, err := live.probeBlob(ctx, "experiment-4a-after", cidValue)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q anonymous_before=%d anonymous_after=%d\n", live.provider, "experiment-4a-blob-reachability", before, after)
	fmt.Println(contentionExperiment4aRow(live.provider, first, cidValue, lost.forwardedStatus, lost.forwardedCID, lost.verifiedCommit, lost.responseSuppressed))

	captured, err = live.fresh(ctx)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	absentBlob, absentCID, absentData, err := live.stageBlob(ctx, "experiment-4b-forward-verified-absent")
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	before, beforeExact, _, err := live.probeBlobExact(ctx, "experiment-4b-before", absentCID, absentData)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	absentKey := newFenceProbeKey(t)
	absentWrites, absentMarker, err := live.markerFor(captured, absentKey, absentBlob)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	missingCID := createNeverUploadedCID(t)
	missingRKey := newFenceProbeKey(t)
	missingBlobRef := json.RawMessage(fmt.Sprintf(`{"$type":"blob","ref":{"$link":%q},"mimeType":"application/octet-stream","size":23}`, missingCID))
	missingRecord, err := json.Marshal(fenceSnapshotFixture{Type: fenceSnapshotCollection, Probe: missingRKey, Blob: missingBlobRef, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	absentWrites = append(absentWrites, contentionApplyWrite{Type: "com.atproto.repo.applyWrites#create", Collection: fenceSnapshotCollection, RKey: missingRKey, Value: missingRecord})
	absent := &contentionAbsentThenError{base: live.transport, reader: live.reader, marker: absentMarker}
	second := live.attempt(ctx, "experiment-4b-forward-verified-absent-response-suppressed", absent, captured, absentWrites, absentMarker, "publication")
	printContentionAttempt(live.provider, second.Experiment, second)
	after, exactReachable, _, err := live.probeBlobExact(ctx, "experiment-4b-after-immediate", absentCID, absentData)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q outcome=%q staged_blob_cid=%q anonymously_reachable_before=%t anonymous_status_before=%d exact_staged_bytes_reachable_before=%t anonymous_status_after=%d exact_staged_bytes_reachable_after_rejection=%t missing_reference_cid=%q retry_evidence_eligible=%t forwarded_response=%q forwarded_error_class=%q marker_absent_verified=%t assertion=%q\n", live.provider, "experiment-4b-f04-post-blob-rejection", second.D1, safeContentionCID(absentCID), before >= 200 && before < 300, before, beforeExact, after, exactReachable, safeContentionCID(missingCID), second.RetryEligible, contentionResponseSummary(absent.forwardedStatus, absent.forwardedBody), safeContentionError(absent.forwardedErr), absent.verifiedAbsent, "valid staged blob plus valid-shaped reference to a never-uploaded blob")
	noCandidateReferences := false
	referenceCheck := "unmeasured"
	if absent.verifiedRevision != nil {
		referenced, referenceErr := revisionReferencesBlob(absent.verifiedRevision, absentCID)
		if referenceErr == nil && !referenced {
			noCandidateReferences = true
			referenceCheck = "verified-unreferenced"
		} else if referenceErr != nil {
			referenceCheck = "unavailable"
		} else {
			referenceCheck = "candidate-referenced-or-ambiguous"
		}
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q rejected_at=%q marker_absent_verified=%t candidate_reference_check=%q candidate_unreferenced=%t exact_staged_bytes_reachable_before=%t exact_staged_bytes_reachable_after_rejection=%t\n", live.provider, "experiment-5-post-rejection-disclosure-duration-prerequisites", absent.forwardedAt.UTC().Format(time.RFC3339Nano), absent.verifiedAbsent, referenceCheck, noCandidateReferences, beforeExact, exactReachable)
	if contentionDisclosureDurationMeasured(absent.forwardedStatus, absent.verifiedAbsent, noCandidateReferences, beforeExact, exactReachable) {
		probeContentionAges(t, live, ctx, "experiment-5-post-rejection-disclosure-duration", absentCID, absentData, absent.forwardedAt, []time.Duration{time.Minute, 5 * time.Minute})
	} else {
		reason := "post-rejection exact staged bytes were not anonymously reachable"
		if absent.forwardedStatus < 400 || absent.forwardedStatus >= 500 || !absent.verifiedAbsent {
			reason = "post-blob 4xx rejection and verified marker absence were not both observed"
		} else if !noCandidateReferences {
			reason = "verified revision did not establish that no record references the candidate CID"
		}
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q status=%q reason=%q reference_check=%q forwarded_http_status=%d rejected_at=%q exact_staged_bytes_reachable_before=%t exact_staged_bytes_reachable_after=%t\n", live.provider, "experiment-5-post-rejection-disclosure-duration", "unmeasured", reason, referenceCheck, absent.forwardedStatus, absent.forwardedAt.UTC().Format(time.RFC3339Nano), beforeExact, exactReachable)
	}

	cancelRevision, err := live.fresh(ctx)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	cancelBlob, cancelCID, _, err := live.stageBlob(ctx, "experiment-4c-cancel-after-write")
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	cancelBefore, _, err := live.probeBlob(ctx, "experiment-4c-before", cancelCID)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	cancelKey := newFenceProbeKey(t)
	cancelWrites, cancelMarker, err := live.markerFor(cancelRevision, cancelKey, cancelBlob)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var cancelTransport *contentionCancelRoundTripper
	cancelLayer := func(base http.RoundTripper) http.RoundTripper {
		cancelTransport = &contentionCancelRoundTripper{base: base, cancel: cancel}
		return cancelTransport
	}
	_, cancelWriter, err := newContentionWriter(live, client, session, handle, cancelLayer)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	cancelAttempt := live.attempt(cancelCtx, "experiment-4c-live-cancellation", cancelWriter, cancelRevision, cancelWrites, cancelMarker, "publication")
	cancel()
	cancelAttempt = contentionCancellationDecision(cancelAttempt)
	printContentionAttempt(live.provider, cancelAttempt.Experiment, cancelAttempt)
	cancelAfter, _, err := live.probeBlob(ctx, "experiment-4c-after", cancelCID)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q status=%q cancellation_triggered_after_write=%t d1=%q resolution=%q retry_evidence_eligible=%t staged_blob_cid=%q anonymous_before=%d anonymous_after=%d interpretation=%q\n", live.provider, "experiment-4c-live-cancellation", "INCONCLUSIVE", cancelTransport != nil && cancelTransport.wasCanceled(), cancelAttempt.D1, cancelAttempt.Resolution, cancelAttempt.RetryEligible, safeContentionCID(cancelCID), cancelBefore, cancelAfter, "processing point unknown; never label this timeout-after-commit")
	_ = client
	_ = session
	_ = handle
}

func runRejectionRows(t *testing.T, live *contentionLive, session *atproto.Session) {
	t.Helper()
	ctx := live.ctx
	if hasPDScope(session.Scopes, "repo:app.bsky.feed.post") {
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q capability=%q status=%q\n", live.provider, "experiment-7-rejection-scope", "repo:app.bsky.feed.post already granted", "not applicable: no out-of-scope operation")
	} else {
		revision, err := live.fresh(ctx)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		blobRef, stagedCID, _, err := live.stageBlob(ctx, "experiment-7-scope-rejection")
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		before, _, err := live.probeBlob(ctx, "experiment-7-scope-before", stagedCID)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		rkey := syntax.NewTIDNow(0).String()
		writes, marker, err := live.markerFor(revision, rkey, blobRef)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		postBytes, err := json.Marshal(struct {
			Type      string `json:"$type"`
			Text      string `json:"text"`
			CreatedAt string `json:"createdAt"`
		}{Type: "app.bsky.feed.post", Text: "Dottie DOT-F05 disposable scope probe", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		writes = []contentionApplyWrite{
			writes[0],
			{Type: "com.atproto.repo.applyWrites#create", Collection: "app.bsky.feed.post", RKey: rkey, Value: postBytes},
		}
		attempt := live.attempt(ctx, "experiment-7-rejection-scope", live.transport, revision, writes, marker, "publication")
		printContentionAttempt(live.provider, attempt.Experiment, attempt)
		after, _, err := live.probeBlob(ctx, "experiment-7-scope-after", stagedCID)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q capability=%q result=%q staged_blob_cid=%q anonymous_before=%d anonymous_after=%d\n", live.provider, "experiment-7-rejection-scope", "repo:app.bsky.feed.post absent from grant", attempt.D1, safeContentionCID(stagedCID), before, after)
		if attempt.D1 == contentionD1Committed || attempt.Resolution == contentionSuperseded {
			pdsRecordFailure(t, live.provider, live.identity.PDS, "F05-scope-write-rejected", fmt.Sprintf("unexpected out-of-scope write outcome=%s resolution=%s", attempt.D1, attempt.Resolution))
		}
	}
	mimeStatus, mimeBody, mimeErr := live.transport.Do(ctx, http.MethodPost, "com.atproto.repo.uploadBlob", nil, []byte("DOT-F05 MIME policy probe"), "text/plain")
	mimeMeasurement := "measured"
	if mimeErr != nil && mimeStatus == 0 {
		mimeMeasurement = "unmeasured: client grant prevented a provider MIME-policy request"
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q capability=%q measurement=%q http_status=%d result=%q response=%q error_class=%q\n", live.provider, "experiment-7-rejection-mime-policy", "text/plain upload", mimeMeasurement, mimeStatus, classifyPDSResult(mimeStatus, mimeBody, mimeErr), contentionResponseSummary(mimeStatus, mimeBody), safeContentionError(mimeErr))
	if mimeErr == nil && mimeStatus >= 200 && mimeStatus < 300 {
		if cidValue := uploadedCID(mimeBody); validContentionCID(cidValue) {
			status, _, probeErr := live.probeBlob(ctx, "experiment-7-mime-policy-accepted", cidValue)
			fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q staged_blob_cid=%q anonymous_status=%d probe_error_class=%q\n", live.provider, "experiment-7-mime-policy-accepted-unexpectedly", safeContentionCID(cidValue), status, safeContentionError(probeErr))
			pdsRecordFailure(t, live.provider, live.identity.PDS, "F05-text-plain-upload-rejected", fmt.Sprintf("status=%d class=success response=%s", mimeStatus, contentionResponseSummary(mimeStatus, mimeBody)))
		} else {
			fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q uploaded_blob_cid=%q\n", live.provider, "experiment-7-mime-policy", contentionAbsentOrInvalidCID)
		}
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q capability=%q status=%q\n", live.provider, "experiment-7-rejection-per-blob-size", "no owner-approved byte ceiling", "unmeasured")
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q capability=%q status=%q\n", live.provider, "experiment-7-rejection-account-quota", "provider quota reservation/limit is not exposed", "unmeasured")
	if err := live.budgetError(); err != nil {
		require.NoError(t, err, "rejection experiment stopped at enforced budget cap: %s", safeContentionError(err))
	}
}

func probeContentionAges(t *testing.T, live *contentionLive, ctx context.Context, experiment, cidValue string, expected []byte, rejectedAt time.Time, ages []time.Duration) {
	t.Helper()
	for _, age := range ages {
		if delay := time.Until(rejectedAt.Add(age)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				require.NoError(t, ctx.Err(), "candidate disclosure-age wait %s: %s", age, safeContentionError(ctx.Err()))
			}
		}
		probeAt := time.Now()
		status, exactBytes, duration, err := live.probeBlobExact(ctx, experiment+"-age-"+age.String(), cidValue, expected)
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q requested_age=%q rejected_at=%q probe_at=%q actual_age_ms=%.3f staged_blob_cid=%q anonymous_status=%d exact_staged_bytes_reachable=%t timing_ms=%.3f probe_error_class=%q\n", live.provider, experiment, age, rejectedAt.UTC().Format(time.RFC3339Nano), probeAt.UTC().Format(time.RFC3339Nano), float64(probeAt.Sub(rejectedAt).Microseconds())/1000, safeContentionCID(cidValue), status, exactBytes, float64(duration.Microseconds())/1000, safeContentionError(err))
		if err != nil {
			require.NoError(t, err, "candidate anonymous reachability at age %s: %s", age, safeContentionError(err))
		}
	}
}

func contentionExpiryBudgetRows(provider string, ages []time.Duration, run string, first int) []string {
	rows := make([]string, 0, len(ages)-first)
	for _, age := range ages[first:] {
		rows = append(rows, fmt.Sprintf("CONTENTION_MATRIX provider=%q experiment=%q age=%q referenceability=unmeasured: budget exhausted", provider, "expiry-"+run+"-reference-attempt", age))
	}
	return rows
}

func printExpiryBudgetRemaining(live *contentionLive, ages []time.Duration, run string, first int) {
	for _, row := range contentionExpiryBudgetRows(live.provider, ages, run, first) {
		fmt.Println(row)
	}
}

func runExpiryAges(t *testing.T, live *contentionLive, ages []time.Duration, run string) {
	t.Helper()
	type specimen struct {
		age       time.Duration
		blobRef   json.RawMessage
		cid       string
		createdAt time.Time
	}
	specimens := make([]specimen, 0, len(ages))
	for index, age := range ages {
		blobRef, cidValue, _, err := live.stageBlob(live.ctx, fmt.Sprintf("experiment-6-%s-expiry-age-%s-%d", run, age, index))
		if err != nil {
			if errors.Is(err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
				printExpiryBudgetRemaining(live, ages, run, 0)
				return
			}
			require.NoError(t, err, "stage fresh expiry specimen age=%s: %s", age, safeContentionError(err))
		}
		specimens = append(specimens, specimen{age: age, blobRef: blobRef, cid: cidValue, createdAt: time.Now()})
	}
	for index, sample := range specimens {
		if delay := time.Until(sample.createdAt.Add(sample.age)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-live.ctx.Done():
				timer.Stop()
				require.NoError(t, live.ctx.Err(), "expiry wait age=%s: %s", sample.age, safeContentionError(live.ctx.Err()))
			}
		}
		status, _, err := live.probeBlob(live.ctx, "expiry-"+run+"-unreferenced-age-"+sample.age.String(), sample.cid)
		if err != nil {
			if errors.Is(err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
				printExpiryBudgetRemaining(live, ages, run, index)
				return
			}
			require.NoError(t, err, "unreferenced age reachability probe age=%s: %s", sample.age, safeContentionError(err))
		}
		revision, err := live.fresh(live.ctx)
		if err != nil {
			if errors.Is(err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
				printExpiryBudgetRemaining(live, ages, run, index)
				return
			}
			require.NoError(t, err, "expiry reference attempt revision age=%s: %s", sample.age, safeContentionError(err))
		}
		rkey := newFenceProbeKey(t)
		writes, marker, err := live.markerFor(revision, rkey, sample.blobRef)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		attempt := live.attempt(live.ctx, "expiry-"+run+"-reference-attempt-"+sample.age.String(), live.transport, revision, writes, marker, "expiry")
		if errors.Is(attempt.Err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
			printExpiryBudgetRemaining(live, ages, run, index)
			return
		}
		printContentionAttempt(live.provider, attempt.Experiment, attempt)
		fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q age=%q actual_age_ms=%.3f referenceability=%q resolution=%q unreferenced_anonymous_status=%d staged_blob_cid=%q attempts=1 retry_evidence_eligible=%t\n", live.provider, attempt.Experiment, sample.age, float64(time.Since(sample.createdAt).Microseconds())/1000, attempt.D1, attempt.Resolution, status, safeContentionCID(sample.cid), attempt.RetryEligible)
	}
}

func effectiveContentionLatencyN(registered, remainingRevisionReads int) int {
	if remainingRevisionReads < 0 {
		remainingRevisionReads = 0
	}
	effective := remainingRevisionReads / 2
	if effective > registered {
		effective = registered
	}
	return effective
}

func contentionLatencyEvidence(attempt contentionAttempt, budgetExhausted bool) (counted bool, result string, successful bool) {
	if !attempt.Dispatched {
		return false, "not-dispatched", false
	}
	if budgetExhausted && attempt.Resolution == contentionUnavailable {
		return true, "unresolved-budget-exhausted", false
	}
	return true, string(attempt.D1), attempt.D1 == contentionD1Committed
}

func printContentionLatencyProfile(live *contentionLive, repetitions, effectiveN, updatesAttempted int, successLatencies, errorLatencies []time.Duration, budgetStopped bool) {
	status := "measured-with-caveat"
	if budgetStopped {
		status = "budget-exhausted-partial-profile"
	}
	fmt.Printf("CONTENTION_MATRIX provider=%q experiment=%q repetitions_registered=%d effective_n_used=%d updates_attempted=%d minimum_decision_grade=%d percentile_convention=%q success_n=%d success_percentiles=%q error_n=%d error_percentiles=%q repository_growth=%q status=%q caveat=%q\n", live.provider, "experiment-8-applyWrites-latency", repetitions, effectiveN, updatesAttempted, contentionLatencyMinimum, "nearest-rank: sorted ascending; rank=ceil(p*n), one-indexed", len(successLatencies), contentionPercentileSummary(successLatencies), len(errorLatencies), contentionPercentileSummary(errorLatencies), "one dedicated rkey updated in place; one cleanup delete", status, map[bool]string{true: "typed budget stop; profile is partial", false: "effective N is bounded by two verified revision reads per sample"}[budgetStopped])
}

func runLatencyProfile(t *testing.T, live *contentionLive, repetitions int) {
	t.Helper()
	ctx := live.ctx
	successLatencies := make([]time.Duration, 0, repetitions)
	errorLatencies := make([]time.Duration, 0, repetitions)
	blobRef, _, _, err := live.stageBlob(ctx, "experiment-8-latency-profile")
	if err != nil {
		if errors.Is(err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
			printContentionLatencyProfile(live, repetitions, 0, 0, successLatencies, errorLatencies, true)
			return
		}
		require.NoError(t, err, "stage latency fixture: %s", safeContentionError(err))
	}
	rkey := newFenceProbeKey(t)
	initial, err := live.fresh(ctx)
	if err != nil {
		if errors.Is(err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
			printContentionLatencyProfile(live, repetitions, 0, 0, successLatencies, errorLatencies, true)
			return
		}
		require.NoError(t, err, safeContentionError(err))
	}
	writes, marker, err := live.markerFor(initial, rkey, blobRef)
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	create := live.attempt(ctx, "experiment-8-latency-fixture-create", live.transport, initial, writes, marker, "latency-init")
	if errors.Is(create.Err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
		printContentionLatencyProfile(live, repetitions, 0, 0, successLatencies, errorLatencies, true)
		return
	}
	printContentionAttempt(live.provider, create.Experiment, create)
	if !contentionSettledCommitted(create) {
		printContentionLatencyProfile(live, repetitions, 0, 0, successLatencies, errorLatencies, false)
		assert.True(t, contentionSettledCommitted(create), "latency fixture creation was not committed: D1=%s resolution=%s", create.D1, create.Resolution)
		return
	}
	effectiveN := effectiveContentionLatencyN(repetitions, live.budget.remainingRevisionMeasurements())
	updatesAttempted := 0
	budgetStopped := false
	for index := 0; index < effectiveN; index++ {
		revision, readErr := live.fresh(ctx)
		if readErr != nil {
			if errors.Is(readErr, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget) {
				budgetStopped = true
				break
			}
			require.NoError(t, readErr, "latency sample %d fresh verified revision: %s", index+1, safeContentionError(readErr))
		}
		record := fenceSnapshotFixture{Type: fenceSnapshotCollection, Probe: rkey, Blob: blobRef, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		recordBytes, err := json.Marshal(record)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		cidValue, err := fenceRecordCID(recordBytes)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		update := []contentionApplyWrite{{Type: "com.atproto.repo.applyWrites#update", Collection: fenceSnapshotCollection, RKey: rkey, Value: recordBytes}}
		head := fenceHeadFixture{Type: contentionHeadCollection, SnapshotRKey: rkey, SnapshotCID: cidValue, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		headBytes, err := json.Marshal(head)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		control := fenceControlFixture{Type: contentionControlCollection, Devices: []fenceControlDevice{{DID: live.identity.DID, Role: "owner"}}, PolicyEpoch: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		controlBytes, err := json.Marshal(control)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		update = append(update,
			contentionApplyWrite{Type: "com.atproto.repo.applyWrites#update", Collection: contentionHeadCollection, RKey: "self", Value: headBytes},
			contentionApplyWrite{Type: "com.atproto.repo.applyWrites#update", Collection: contentionControlCollection, RKey: "self", Value: controlBytes},
		)
		headCID, err := fenceRecordCID(headBytes)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		controlCID, err := fenceRecordCID(controlBytes)
		if err != nil {
			require.NoError(t, err, safeContentionError(err))
		}
		attempt := live.attempt(ctx, fmt.Sprintf("experiment-8-latency-update-%03d", index+1), live.transport, revision, update, contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: rkey}, RecordCID: cidValue, HeadCID: headCID, ControlCID: controlCID}, "latency")
		budgetExhausted := errors.Is(attempt.Err, errContentionBudget) || errors.Is(live.budgetError(), errContentionBudget)
		counted, result, successful := contentionLatencyEvidence(attempt, budgetExhausted)
		if counted {
			updatesAttempted++
			if successful {
				successLatencies = append(successLatencies, attempt.Duration)
			} else {
				errorLatencies = append(errorLatencies, attempt.Duration)
			}
			fmt.Printf("CONTENTION_LATENCY provider=%q sample=%d result=%q d1=%q resolution=%q request_dispatched=%t http_status=%d error_class=%q duration_ms=%.3f commit_cid=%q\n", live.provider, index+1, result, attempt.D1, attempt.Resolution, attempt.Dispatched, attempt.Status, safeContentionError(attempt.Err), float64(attempt.Duration.Microseconds())/1000, safeContentionCID(attempt.ReturnedCommit))
		}
		if budgetExhausted {
			budgetStopped = true
			break
		}
	}
	printContentionLatencyProfile(live, repetitions, effectiveN, updatesAttempted, successLatencies, errorLatencies, budgetStopped)
}

func contentionPercentileSummary(values []time.Duration) string {
	if len(values) == 0 {
		return "p50=unavailable p95=unavailable p99=unavailable; insufficient sample - not decision-grade"
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	percentile := func(p int) time.Duration {
		rank := (p*len(sorted) + 99) / 100
		if rank < 1 {
			rank = 1
		}
		return sorted[rank-1]
	}
	valuesText := fmt.Sprintf("p50=%.3fms p95=%.3fms p99=%.3fms", float64(percentile(50).Microseconds())/1000, float64(percentile(95).Microseconds())/1000, float64(percentile(99).Microseconds())/1000)
	if len(sorted) < contentionLatencyMinimum {
		return valuesText + "; insufficient sample - not decision-grade"
	}
	return valuesText
}

func contentionLatencyCount(value string) (int, error) {
	if value == "" {
		return 50, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 || parsed > contentionLatencyMax {
		return 0, fmt.Errorf("DOTTIE_LIVE_LATENCY_N must be a positive integer no greater than %d", contentionLatencyMax)
	}
	return parsed, nil
}

func contentionTrackedSet(tracked map[contentionRecordKey]string) string {
	keys := make([]contentionRecordKey, 0, len(tracked))
	for key := range tracked {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Collection == keys[j].Collection {
			return keys[i].RKey < keys[j].RKey
		}
		return keys[i].Collection < keys[j].Collection
	})
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key.Collection+"/"+key.RKey)
	}
	return strings.Join(pairs, ",")
}

func printContentionReconciliation(runID, provider, reason string, tracked map[contentionRecordKey]string) {
	fmt.Printf("CONTENTION_RECONCILIATION run_id=%q provider=%q reason=%q tracked_pairs=%q instruction=%q\n", runID, provider, reason, contentionTrackedSet(tracked), "use only this complete set; inspect a fresh verified revision and do not delete unrelated records")
}

func (l *contentionLive) cleanup() {
	l.t.Helper()
	if l.budget.cleaned {
		return
	}
	l.budget.cleaned = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, contentionCleanupKey{}, true)
	tracked := l.tracker.snapshot()
	keys := make([]contentionRecordKey, 0, len(tracked))
	for key := range tracked {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Collection == keys[j].Collection {
			return keys[i].RKey < keys[j].RKey
		}
		return keys[i].Collection < keys[j].Collection
	})
	if len(keys) > 0 {
		revision, err := l.fresh(ctx)
		if err != nil {
			printContentionReconciliation(l.tracker.runID, l.provider, "cleanup revision could not be verified", tracked)
			assert.NoError(l.t, err, "F05 cleanup could not obtain a verified revision: %s", safeContentionError(err))
		} else {
			var deletes []contentionApplyWrite
			for _, key := range keys {
				if revision.HasRecord(atproto.RecordKey{Collection: key.Collection, RKey: key.RKey}) {
					deletes = append(deletes, contentionApplyWrite{Type: "com.atproto.repo.applyWrites#delete", Collection: key.Collection, RKey: key.RKey})
				}
			}
			if len(deletes) > 0 {
				body, encodeErr := encodeContentionApply(l.identity.DID, revision.CommitCID(), deletes)
				if encodeErr != nil {
					printContentionReconciliation(l.tracker.runID, l.provider, "tracked delete set could not be encoded", tracked)
					assert.NoError(l.t, encodeErr, "F05 cleanup encode tracked delete set: %s", safeContentionError(encodeErr))
				} else {
					cleanupCtx := context.WithValue(ctx, contentionWriteKindKey{}, "cleanup")
					status, response, requestErr := l.transport.Do(cleanupCtx, http.MethodPost, "com.atproto.repo.applyWrites", nil, body, "application/json")
					verified, verifyErr := l.fresh(ctx)
					if verifyErr != nil {
						printContentionReconciliation(l.tracker.runID, l.provider, "cleanup verification read failed", tracked)
						assert.NoError(l.t, verifyErr, "F05 cleanup verification read failed: %s", safeContentionError(verifyErr))
					} else {
						leftover := false
						for _, key := range keys {
							if verified.HasRecord(atproto.RecordKey{Collection: key.Collection, RKey: key.RKey}) {
								leftover = true
								assert.False(l.t, verified.HasRecord(atproto.RecordKey{Collection: key.Collection, RKey: key.RKey}), "F05 cleanup left tracked record %s/%s; status=%d response=%s error_class=%s", key.Collection, key.RKey, status, contentionResponseSummary(status, response), safeContentionError(requestErr))
							}
						}
						if leftover {
							printContentionReconciliation(l.tracker.runID, l.provider, "tracked records remain after cleanup", tracked)
						}
					}
				}
			}
		}
	}
	httpRequests, logicalApplyCalls, applyWireRequests, reads, publications, deletes, latencyUpdates, exceeded := l.budget.snapshot()
	publicationDeletes, latencyDeletes, expiryDeletes := l.budget.cleanupBreakdown()
	fmt.Printf("CONTENTION_BUDGET run_id=%q provider=%q run=%q logical_applyWrites_calls=%d logical_applyWrites_limit=%d applyWrites_wire_requests=%d applyWrites_wire_limit=%d publication_attempts=%d publication_limit=%d cleanup_deletes=%d cleanup_delete_limit=%d publication_cleanup_deletes=%d publication_cleanup_limit=%d latency_cleanup_deletes=%d expiry_cleanup_deletes=%d latency_updates=%d revision_reads=%d revision_read_limit=%d http_dispatches=%d http_request_limit=%d exceeded_class=%q manual_reconciliation=%q self_hazard=%q\n", l.tracker.runID, l.provider, map[bool]string{true: "long-expiry", false: "short"}[l.budget.expiryHTTP], logicalApplyCalls, l.budget.applyLimit, applyWireRequests, l.budget.applyWireLimit, publications, l.budget.publicationLimit, deletes, contentionCleanupBudget+1+l.budget.cleanupLimit, publicationDeletes, contentionCleanupBudget, latencyDeletes, expiryDeletes, latencyUpdates, reads, l.budget.revisionLimit, httpRequests, l.budget.httpLimit, safeContentionError(exceeded), "if run aborts before cleanup, reconcile only the complete run-id tracked_pairs emitted before first send; do not overwrite pre-existing head/control self", "restart refuses pre-existing head/control self because they may belong to a prior aborted run")
}

func (l *contentionLive) budgetError() error {
	_, _, _, _, _, _, _, err := l.budget.snapshot()
	return err
}

func TestContentionD1Classifier(t *testing.T) {
	cidValue := createNeverUploadedCID(t)
	for _, test := range []struct {
		name  string
		input contentionD1Input
		want  contentionD1
	}{
		{name: "local preflight wins", input: contentionD1Input{LocalRejected: true, Status: 500, Body: []byte(`{"error":"InvalidSwap"}`)}, want: contentionRejectedLocal},
		{name: "transport not written", input: contentionD1Input{NotSent: true, TransportErr: errors.New("dial failed")}, want: contentionNotSent},
		{name: "transport error after send", input: contentionD1Input{TransportErr: errors.New("connection reset")}, want: contentionUnknown},
		{name: "timeout after send", input: contentionD1Input{TransportErr: context.DeadlineExceeded}, want: contentionUnknown},
		{name: "500 InvalidSwap text is unknown", input: contentionD1Input{Status: 500, Body: []byte(`{"error":"InvalidSwap"}`)}, want: contentionUnknown},
		{name: "unparseable body", input: contentionD1Input{Status: 400, Body: []byte("not json")}, want: contentionUnknown},
		{name: "2xx without commit cid", input: contentionD1Input{Status: 200, Body: []byte(`{"commit":{}}`), MarkerProven: true}, want: contentionUnknown},
		{name: "structured InvalidSwap 4xx", input: contentionD1Input{Status: 400, Body: []byte(`{"error":"InvalidSwap"}`)}, want: contentionRejectedPreBlob},
		{name: "other 4xx may disclose", input: contentionD1Input{Status: 403, Body: []byte(`{"error":"Forbidden"}`)}, want: contentionRejectedOther},
		{name: "2xx exact marker proven", input: contentionD1Input{Status: 200, Body: []byte(`{"commit":{"cid":"` + cidValue + `"}}`), CommitCID: cidValue, MarkerProven: true}, want: contentionD1Committed},
		{name: "2xx marker absent remains unknown", input: contentionD1Input{Status: 200, Body: []byte(`{"commit":{"cid":"` + cidValue + `"}}`), CommitCID: cidValue}, want: contentionUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyContentionD1(test.input); got != test.want {
				require.Equal(t, test.want, got, "classifyContentionD1()=%q want=%q", got, test.want)
			}
		})
	}
}

func TestContentionRetryEvidenceEligibility(t *testing.T) {
	for _, test := range []struct {
		outcome    contentionD1
		resolution contentionResolution
		want       bool
	}{
		{outcome: contentionNotSent, want: true},
		{outcome: contentionUnknown, resolution: contentionNotLanded, want: true},
		{outcome: contentionUnknown, resolution: contentionUnavailable},
		{outcome: contentionRejectedOther, resolution: contentionNotLanded},
		{outcome: contentionD1Committed, resolution: contentionCommitted},
	} {
		if got := contentionRetryEvidenceEligible(test.outcome, test.resolution); got != test.want {
			assert.Equal(t, test.want, got, "contentionRetryEvidenceEligible(%s,%s)=%t want=%t", test.outcome, test.resolution, got, test.want)
		}
	}
}

func TestContentionMarkerThreeWayResolution(t *testing.T) {
	marker := contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: "probe-one"}, RecordCID: "snapshot-cid", HeadCID: "head-cid", ControlCID: "control-cid"}
	for _, test := range []struct {
		name     string
		evidence contentionRevisionEvidence
		want     contentionResolution
	}{
		{name: "unavailable", evidence: contentionRevisionEvidence{}, want: contentionUnavailable},
		{name: "verified absent", evidence: contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{}}, want: contentionNotLanded},
		{name: "present and bound", evidence: contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{marker.Key: marker.RecordCID, {Collection: contentionHeadCollection, RKey: "self"}: marker.HeadCID, {Collection: contentionControlCollection, RKey: "self"}: marker.ControlCID}}, want: contentionCommitted},
		{name: "present but superseded", evidence: contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{marker.Key: marker.RecordCID, {Collection: contentionHeadCollection, RKey: "self"}: "new-head", {Collection: contentionControlCollection, RKey: "self"}: "new-control"}}, want: contentionSuperseded},
		{name: "same key wrong cid is absent marker", evidence: contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{marker.Key: "other-cid"}}, want: contentionNotLanded},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveContentionMarker(marker, test.evidence); got != test.want {
				require.Equal(t, test.want, got, "resolveContentionMarker()=%q want=%q", got, test.want)
			}
		})
	}
}

func TestContentionNearestRankAndLatencyGate(t *testing.T) {
	values := []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond}
	got := contentionPercentileSummary(values)
	require.Contains(t, got, "p50=3.000ms", "nearest-rank exploratory summary=%q", got)
	require.Contains(t, got, "p95=5.000ms", "nearest-rank exploratory summary=%q", got)
	require.Contains(t, got, "insufficient sample - not decision-grade", "nearest-rank exploratory summary=%q", got)
	for _, input := range []struct {
		value string
		want  int
		bad   bool
	}{{value: "", want: 50}, {value: "1", want: 1}, {value: "100", want: 100}, {value: "101", bad: true}, {value: "0", bad: true}, {value: "1.5", bad: true}} {
		got, err := contentionLatencyCount(input.value)
		if input.bad && err == nil || !input.bad && (err != nil || got != input.want) {
			assert.False(t, input.bad && err == nil || !input.bad && (err != nil || got != input.want), "contentionLatencyCount(%q)=(%d,%v), want=%d bad=%t", input.value, got, err, input.want, input.bad)
		}
	}
}

func TestContentionBudgetCapsAndTypedErrors(t *testing.T) {
	budget := newContentionBudget(true, 0)
	for index := 0; index < contentionExpiryHTTPBudget; index++ {
		if err := budget.reserveHTTP(true); err != nil {
			require.NoError(t, err, "request %d unexpectedly rejected: %s", index+1, safeContentionError(err))
		}
	}
	if err := budget.reserveHTTP(true); !errors.Is(err, errContentionBudget) {
		require.ErrorIs(t, err, errContentionBudget, "HTTP over-budget error=%s", safeContentionError(err))
	}
	if _, _, _, _, _, _, _, exceeded := budget.snapshot(); exceeded == nil {
		require.NotNil(t, exceeded, "budget exhaustion did not retain a typed error")
	} else if _, ok := exceeded.(*contentionBudgetError); !ok {
		require.IsType(t, &contentionBudgetError{}, exceeded, "budget exhaustion is not typed: %T", exceeded)
	}
}

func TestContentionBudgetEnforcesWriteAndCleanupCaps(t *testing.T) {
	publications := newContentionBudget(false, 1)
	for index := 0; index < contentionPublicationBudget; index++ {
		if err := publications.reserveApply("publication", 3, nil); err != nil {
			require.NoError(t, err, "publication %d unexpectedly rejected: %s", index+1, safeContentionError(err))
		}
	}
	if err := publications.reserveApply("publication", 3, nil); !errors.Is(err, errContentionBudget) {
		require.ErrorIs(t, err, errContentionBudget, "publication over-budget error=%s", safeContentionError(err))
	}

	latency := newContentionBudget(false, 1)
	if err := latency.reserveApply("latency", 3, nil); err != nil {
		require.NoError(t, err, "first latency update rejected: %s", safeContentionError(err))
	}
	if err := latency.reserveApply("latency", 3, nil); !errors.Is(err, errContentionBudget) {
		require.ErrorIs(t, err, errContentionBudget, "latency over-budget error=%s", safeContentionError(err))
	}

	cleanup := newContentionBudget(false, 1)
	if err := cleanup.reserveApply("cleanup", 13, map[string]int{"publication": contentionCleanupBudget + 1}); !errors.Is(err, errContentionBudget) {
		require.ErrorIs(t, err, errContentionBudget, "cleanup delete over-budget error=%s", safeContentionError(err))
	}
}

type contentionNonceChallengeFake struct {
	mu        sync.Mutex
	forwarded int
	perWrite  map[string]int
}

func (f *contentionNonceChallengeFake) RoundTrip(request *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.forwarded++
	if f.perWrite == nil {
		f.perWrite = make(map[string]int)
	}
	id := request.Header.Get("X-Write-ID")
	f.perWrite[id]++
	count := f.perWrite[id]
	f.mu.Unlock()
	response := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}
	if count == 1 {
		response.StatusCode = http.StatusBadRequest
		response.Header.Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		response.Header.Set("DPoP-Nonce", "test-nonce")
		return response, nil
	}
	response.StatusCode = http.StatusOK
	return response, nil
}

type contentionNonceReplayFake struct {
	base http.RoundTripper
}

func (t contentionNonceReplayFake) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || response == nil || response.StatusCode != http.StatusBadRequest || response.Header.Get("DPoP-Nonce") == "" {
		return response, err
	}
	_ = response.Body.Close()
	if request.GetBody == nil {
		return nil, errors.New("test request is not replayable")
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, err
	}
	replay := request.Clone(request.Context())
	replay.Body = body
	return t.base.RoundTrip(replay)
}

func newContentionFakeWriteRequest(t *testing.T, id string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://pds.example/xrpc/com.atproto.repo.applyWrites", strings.NewReader("{}"))
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	request.Header.Set("X-Write-ID", id)
	return request
}

func TestContentionHTTP1TransportPreservesExplicitAuthReplay(t *testing.T) {
	var mu sync.Mutex
	protocols := make([]string, 0, 2)
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		protocols = append(protocols, request.Proto)
		requests++
		count := requests
		mu.Unlock()
		if count == 1 {
			writer.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			writer.Header().Set("DPoP-Nonce", "test-nonce")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "{}")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport := newContentionHTTP1Transport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	budget := newContentionBudget(false, 0)
	dispatch := &contentionHTTPRoundTripper{base: transport, budget: budget}
	client := contentionNonceReplayFake{base: dispatch}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/xrpc/com.atproto.repo.applyWrites", strings.NewReader("payload"))
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	response, err := client.RoundTrip(request)
	require.NoError(t, err, "explicit authentication replay response status=%v error=%s", responseStatus(response), safeContentionError(err))
	require.NotNil(t, response, "explicit authentication replay response status=%v error=%s", responseStatus(response), safeContentionError(err))
	require.Equal(t, http.StatusOK, response.StatusCode, "explicit authentication replay response status=%v error=%s", responseStatus(response), safeContentionError(err))
	_ = response.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 2, requests, "TLS protocol/replay observations requests=%d protocols=%q", requests, protocols)
	require.Len(t, protocols, 2, "TLS protocol/replay observations requests=%d protocols=%q", requests, protocols)
	require.Equal(t, "HTTP/1.1", protocols[0], "TLS protocol/replay observations requests=%d protocols=%q", requests, protocols)
	require.Equal(t, "HTTP/1.1", protocols[1], "TLS protocol/replay observations requests=%d protocols=%q", requests, protocols)
	require.Equal(t, 2, budget.applyWireRequests, "explicit auth replay wire count=%d, want 2", budget.applyWireRequests)
}

func responseStatus(response *http.Response) string {
	if response == nil {
		return "none"
	}
	return response.Status
}

func TestContentionApplyWritesWireCapCountsAuthenticationReplays(t *testing.T) {
	t.Run("challenge replay counts as a wire request", func(t *testing.T) {
		budget := newContentionBudget(false, 0)
		budget.applyWireLimit = 4
		fake := &contentionNonceChallengeFake{}
		dispatch := &contentionHTTPRoundTripper{base: fake, budget: budget}
		client := contentionNonceReplayFake{base: dispatch}
		response, err := client.RoundTrip(newContentionFakeWriteRequest(t, "write-one"))
		require.NoError(t, err, "nonce challenge replay response=%s error=%s", responseStatus(response), safeContentionError(err))
		require.NotNil(t, response, "nonce challenge replay response=%s error=%s", responseStatus(response), safeContentionError(err))
		require.Equal(t, http.StatusOK, response.StatusCode, "nonce challenge replay response=%s error=%s", responseStatus(response), safeContentionError(err))
		_ = response.Body.Close()
		require.Equal(t, 2, fake.forwarded, "replay accounting forwarded=%d per-write=%d wire-count=%d", fake.forwarded, fake.perWrite["write-one"], budget.applyWireRequests)
		require.Equal(t, 2, fake.perWrite["write-one"], "replay accounting forwarded=%d per-write=%d wire-count=%d", fake.forwarded, fake.perWrite["write-one"], budget.applyWireRequests)
		require.Equal(t, 2, budget.applyWireRequests, "replay accounting forwarded=%d per-write=%d wire-count=%d", fake.forwarded, fake.perWrite["write-one"], budget.applyWireRequests)
		_, logical, wire, _, _, _, _, _ := budget.snapshot()
		require.Equal(t, 0, logical, "HTTP replay counters logical=%d wire=%d, want logical=0 wire=2", logical, wire)
		require.Equal(t, 2, wire, "HTTP replay counters logical=%d wire=%d, want logical=0 wire=2", logical, wire)
	})

	t.Run("cleanup authentication replay is capped and counted", func(t *testing.T) {
		budget := newContentionBudget(false, 0)
		budget.applyWireLimit = 2
		fake := &contentionNonceChallengeFake{}
		dispatch := &contentionHTTPRoundTripper{base: fake, budget: budget}
		client := contentionNonceReplayFake{base: dispatch}
		request := newContentionFakeWriteRequest(t, "cleanup-write")
		request = request.WithContext(context.WithValue(request.Context(), contentionCleanupKey{}, true))
		response, err := client.RoundTrip(request)
		require.NoError(t, err, "cleanup replay response=%s error=%s", responseStatus(response), safeContentionError(err))
		require.NotNil(t, response, "cleanup replay response=%s error=%s", responseStatus(response), safeContentionError(err))
		require.Equal(t, http.StatusOK, response.StatusCode, "cleanup replay response=%s error=%s", responseStatus(response), safeContentionError(err))
		_ = response.Body.Close()
		require.Equal(t, 2, fake.forwarded, "cleanup replay accounting forwarded=%d wire-count=%d", fake.forwarded, budget.applyWireRequests)
		require.Equal(t, 2, budget.applyWireRequests, "cleanup replay accounting forwarded=%d wire-count=%d", fake.forwarded, budget.applyWireRequests)
	})

	t.Run("wire cap aborts replay before forwarding", func(t *testing.T) {
		budget := newContentionBudget(false, 0)
		budget.applyWireLimit = 3
		fake := &contentionNonceChallengeFake{}
		dispatch := &contentionHTTPRoundTripper{base: fake, budget: budget}
		client := contentionNonceReplayFake{base: dispatch}
		response, err := client.RoundTrip(newContentionFakeWriteRequest(t, "write-one"))
		if response != nil {
			_ = response.Body.Close()
		}
		require.ErrorIs(t, err, errContentionBudget, "replay cap error=%s, want typed budget error", safeContentionError(err))
		require.Equal(t, 1, fake.forwarded, "capped replay was forwarded: forwarded=%d per-write=%d wire-count=%d", fake.forwarded, fake.perWrite["write-one"], budget.applyWireRequests)
		require.Equal(t, 1, fake.perWrite["write-one"], "capped replay was forwarded: forwarded=%d per-write=%d wire-count=%d", fake.forwarded, fake.perWrite["write-one"], budget.applyWireRequests)
		require.Equal(t, 1, budget.applyWireRequests, "capped replay was forwarded: forwarded=%d per-write=%d wire-count=%d", fake.forwarded, fake.perWrite["write-one"], budget.applyWireRequests)
	})
}

type contentionSerializedFakeRoundTripper struct {
	mu             sync.Mutex
	calls          int
	secondObserved chan struct{}
}

func (f *contentionSerializedFakeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	f.mu.Lock()
	trace := httptrace.ContextClientTrace(request.Context())
	if trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	f.calls++
	call := f.calls
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}
	if trace != nil && trace.GotFirstResponseByte != nil {
		trace.GotFirstResponseByte()
	}
	f.mu.Unlock()
	if call == 1 {
		<-f.secondObserved
	} else {
		close(f.secondObserved)
	}
	return response, nil
}

func TestContentionBarrierForcedInterleavingDoesNotInferOverlap(t *testing.T) {
	base := &contentionSerializedFakeRoundTripper{secondObserved: make(chan struct{})}
	barrier := newContentionBarrier()
	transport := barrier.layer(base)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			request, err := http.NewRequest(http.MethodPost, "https://pds.example/xrpc/com.atproto.repo.applyWrites", strings.NewReader("{}"))
			if !assert.NoError(t, err, safeContentionError(err)) {
				return
			}
			request.Header.Set("X-Write-ID", fmt.Sprintf("serialized-%d", index))
			request = request.WithContext(context.WithValue(request.Context(), contentionWriterIDKey{}, fmt.Sprintf("writer-%d", index)))
			response, err := transport.RoundTrip(request)
			if err != nil {
				assert.NoError(t, err, "serialized fake request: %s", safeContentionError(err))
				return
			}
			_ = response.Body.Close()
		}(i)
	}
	close(start)
	wait.Wait()
	arrivals, overlap, _, intervals := barrier.snapshot()
	require.Equal(t, 2, arrivals, "serialized transport falsely reported overlap: arrivals=%d intervals=%d maximum=%d", arrivals, intervals, overlap)
	require.Equal(t, 2, intervals, "serialized transport falsely reported overlap: arrivals=%d intervals=%d maximum=%d", arrivals, intervals, overlap)
	require.Less(t, overlap, 2, "serialized transport falsely reported overlap: arrivals=%d intervals=%d maximum=%d", arrivals, intervals, overlap)
}

type contentionAsyncCancellationRoundTripper struct {
	callbackDone chan struct{}
	dataSent     chan struct{}
}

func (f *contentionAsyncCancellationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if _, err := io.ReadAll(request.Body); err != nil {
		return nil, err
	}
	close(f.dataSent)
	trace := httptrace.ContextClientTrace(request.Context())
	go func() {
		time.Sleep(10 * time.Millisecond)
		if trace != nil && trace.WroteRequest != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
		close(f.callbackDone)
	}()
	return nil, context.Canceled
}

func TestContentionMissingWriteCallbackAfterDispatchIsUnknown(t *testing.T) {
	budget := newContentionBudget(false, 0)
	fake := &contentionAsyncCancellationRoundTripper{callbackDone: make(chan struct{}), dataSent: make(chan struct{})}
	monitor := &contentionWriteMonitor{}
	request := newContentionFakeWriteRequest(t, "async-cancel")
	request = request.WithContext(context.WithValue(request.Context(), contentionWriteMonitorKey{}, monitor))
	_, err := (&contentionHTTPRoundTripper{base: fake, budget: budget}).RoundTrip(request)
	<-fake.dataSent
	dispatched, written := monitor.state()
	require.True(t, dispatched, "state before callback dispatched=%t written=%t", dispatched, written)
	require.False(t, written, "state before callback dispatched=%t written=%t", dispatched, written)
	d1 := classifyContentionAttempt(err, dispatched, written, 0, nil, contentionAbsentOrInvalidCID, "")
	marker := contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: "async-cancel"}, RecordCID: "expected-cid"}
	d2 := resolveContentionMarker(marker, contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{}})
	require.Equal(t, contentionUnknown, d1, "async partial-send evidence d1=%q d2=%q retry=%t", d1, d2, contentionRetryEvidenceEligible(d1, d2))
	require.Equal(t, contentionNotLanded, d2, "async partial-send evidence d1=%q d2=%q retry=%t", d1, d2, contentionRetryEvidenceEligible(d1, d2))
	require.True(t, contentionRetryEvidenceEligible(d1, d2), "async partial-send evidence d1=%q d2=%q retry=%t", d1, d2, contentionRetryEvidenceEligible(d1, d2))
	<-fake.callbackDone
	dispatched, written = monitor.state()
	require.True(t, written, "late WroteRequest callback was not observed")
}

func TestContentionPreDispatchFailureRemainsNotSent(t *testing.T) {
	err := errors.New("synthetic pre-dispatch failure")
	if got := classifyContentionAttempt(err, false, false, 0, nil, contentionAbsentOrInvalidCID, ""); got != contentionNotSent {
		require.Equal(t, contentionNotSent, got, "pre-dispatch outcome=%q, want %q", got, contentionNotSent)
	}
}

func TestContentionSentAuthenticationErrorsRemainUnknown(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "sent 401 refresh failure", err: atproto.ErrAuthMethodSession},
		{name: "sent nonce replay budget exhaustion", err: &contentionBudgetError{Resource: "applyWrites wire requests", Limit: 1, Observed: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := classifyContentionAttempt(test.err, true, true, http.StatusUnauthorized, []byte(`{"error":"invalid_token"}`), contentionAbsentOrInvalidCID, contentionUnavailable)
			require.Equal(t, contentionUnknown, got, "sent authentication failure classified as %q", got)
			require.NotEqual(t, contentionRejectedLocal, got, "sent authentication failure classified as %q", got)
			require.False(t, contentionRetryEvidenceEligible(got, contentionUnavailable), "unavailable D2 resolution must not become retry eligible")
			marker := contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: "sent-auth-error"}, RecordCID: "expected-cid"}
			absent := resolveContentionMarker(marker, contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{}})
			require.Equal(t, contentionNotLanded, absent, "sent unknown outcome did not use verified D2 absence: resolution=%s retry=%t", absent, contentionRetryEvidenceEligible(got, absent))
			require.True(t, contentionRetryEvidenceEligible(got, absent), "sent unknown outcome did not use verified D2 absence: resolution=%s retry=%t", absent, contentionRetryEvidenceEligible(got, absent))
		})
	}
}

type contentionFakeTransport struct {
	applyResponse []byte
	applyStatus   int
	applyCalls    int
	readCalls     int
}

func (f *contentionFakeTransport) Do(ctx context.Context, _ string, endpoint string, _ url.Values, _ []byte, _ string) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" {
		if monitor, ok := ctx.Value(contentionWriteMonitorKey{}).(*contentionWriteMonitor); ok {
			monitor.markDispatched()
			monitor.markWritten()
		}
		f.applyCalls++
		return f.applyStatus, append([]byte(nil), f.applyResponse...), nil
	}
	f.readCalls++
	return http.StatusInternalServerError, nil, errors.New("synthetic read unavailable")
}

func (f *contentionFakeTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, errors.New("synthetic stream unavailable")
}

func TestContentionDecoratorUnavailableIsTerminalInAttempt(t *testing.T) {
	commitCID := createNeverUploadedCID(t)
	base := &contentionFakeTransport{applyStatus: http.StatusOK, applyResponse: []byte(`{"commit":{"cid":"` + commitCID + `"}}`)}
	marker := contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: "decorator-unavailable"}, RecordCID: "expected-cid"}
	decorator := &contentionCommitThenError{
		base:   base,
		marker: marker,
		verify: func(context.Context, contentionMarker) (contentionResolution, error) {
			return contentionUnavailable, atproto.ErrSignature
		},
	}
	budget := newContentionBudget(false, 0)
	live := &contentionLive{ctx: context.Background(), budget: budget, reader: contentionReader{reader: atproto.RevisionReader{Transport: base, Budgets: atproto.DefaultBudgets()}, budget: budget, did: "did:example:test"}}
	attempt := live.attemptBody(context.Background(), "offline-decorator-unavailable", decorator, []byte("{}"), marker, "publication")
	require.Equal(t, contentionUnavailable, attempt.Resolution, "decorator verification result was lost: d1=%q resolution=%q retry=%t", attempt.D1, attempt.Resolution, attempt.RetryEligible)
	require.Equal(t, contentionUnknown, attempt.D1, "decorator verification result was lost: d1=%q resolution=%q retry=%t", attempt.D1, attempt.Resolution, attempt.RetryEligible)
	require.False(t, attempt.RetryEligible, "decorator verification result was lost: d1=%q resolution=%q retry=%t", attempt.D1, attempt.Resolution, attempt.RetryEligible)
	require.Equal(t, 1, base.applyCalls, "decorator/attempt used apply=%d follow-up reads=%d; unavailable must prevent a second read", base.applyCalls, base.readCalls)
	require.Equal(t, 0, base.readCalls, "decorator/attempt used apply=%d follow-up reads=%d; unavailable must prevent a second read", base.applyCalls, base.readCalls)
	row := contentionExperiment4aRow("provider", attempt, "", decorator.forwardedStatus, decorator.forwardedCID, decorator.verifiedCommit, decorator.responseSuppressed)
	require.NotContains(t, row, "committed-but-response-lost", "unavailable decorator verification produced affirmative experiment row: %s", row)
	require.NotContains(t, row, "verified committed before", "unavailable decorator verification produced affirmative experiment row: %s", row)
}

func TestContentionCancellationUnavailableIsTerminal(t *testing.T) {
	sequence := []contentionResolution{contentionUnavailable, contentionNotLanded}
	readIndex := 0
	read := func() contentionResolution {
		result := sequence[readIndex]
		readIndex++
		return result
	}
	firstVerification := read()
	decision := contentionCancellationDecision(contentionAttempt{D1: contentionUnknown, Resolution: firstVerification})
	laterVerification := read()
	require.Equal(t, contentionNotLanded, laterVerification, "second sequence read did not model a later successful verification")
	require.True(t, contentionRetryEvidenceEligible(contentionUnknown, laterVerification), "second sequence read did not model a later successful verification")
	require.Equal(t, contentionUnavailable, decision.Resolution, "later successful read replaced terminal unavailable decision: %+v", decision)
	require.False(t, decision.RetryEligible, "later successful read replaced terminal unavailable decision: %+v", decision)
}

type contentionDelayedTraceRoundTripper struct {
	callbacks chan struct{}
	started   chan struct{}
}

func (f *contentionDelayedTraceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(request.Context())
	go func() {
		<-f.callbacks
		if trace != nil && trace.WroteRequest != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
		if trace != nil && trace.GotFirstResponseByte != nil {
			trace.GotFirstResponseByte()
		}
		f.started <- struct{}{}
	}()
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}, nil
}

func TestContentionOverlapAsyncCallbacksRemainInconclusiveUntilComplete(t *testing.T) {
	base := &contentionDelayedTraceRoundTripper{callbacks: make(chan struct{}), started: make(chan struct{}, 2)}
	barrier := newContentionBarrier()
	transport := barrier.layer(base)
	responses := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func(index int) {
			request, err := http.NewRequest(http.MethodPost, "https://pds.example/xrpc/com.atproto.repo.applyWrites", strings.NewReader("{}"))
			if !assert.NoError(t, err, safeContentionError(err)) {
				responses <- err
				return
			}
			request.Header.Set("X-Write-ID", fmt.Sprintf("async-trace-%d", index))
			request = request.WithContext(context.WithValue(request.Context(), contentionWriterIDKey{}, fmt.Sprintf("async-writer-%d", index)))
			response, err := transport.RoundTrip(request)
			if err == nil {
				_ = response.Body.Close()
			}
			responses <- err
		}(index)
	}
	for index := 0; index < 2; index++ {
		if err := <-responses; err != nil {
			require.NoError(t, err, "async trace request: %s", safeContentionError(err))
		}
	}
	arrivals, overlap, _, intervals := barrier.snapshot()
	require.Equal(t, 2, arrivals, "incomplete trace claimed arrivals=%d intervals=%d overlap=%d", arrivals, intervals, overlap)
	require.Equal(t, 0, overlap, "incomplete trace claimed arrivals=%d intervals=%d overlap=%d", arrivals, intervals, overlap)
	require.Equal(t, 0, intervals, "incomplete trace claimed arrivals=%d intervals=%d overlap=%d", arrivals, intervals, overlap)
	close(base.callbacks)
	<-base.started
	<-base.started
	if _, _, _, intervals := barrier.snapshot(); intervals != 2 {
		require.Equal(t, 2, intervals, "completed async trace intervals=%d, want 2", intervals)
	}
}

func TestContentionOverlapEvidenceRequiresObservedIntervals(t *testing.T) {
	start := time.Now()
	if got := contentionMaximumOverlap([]contentionRequestInterval{{writer: "a", start: start, end: start.Add(time.Second)}, {writer: "b", start: start.Add(time.Second), end: start.Add(2 * time.Second)}}); got != 1 {
		require.Equal(t, 1, got, "adjacent intervals overlap count=%d, want 1", got)
	}
	if got := contentionMaximumOverlap([]contentionRequestInterval{{writer: "a", start: start, end: start.Add(time.Second)}, {writer: "b", start: start.Add(500 * time.Millisecond), end: start.Add(2 * time.Second)}}); got != 2 {
		require.Equal(t, 2, got, "overlapping intervals count=%d, want 2", got)
	}
}

func TestContentionFinalMarkerEvidenceDoesNotProveDuplicateInvariant(t *testing.T) {
	firstCID := createNeverUploadedCID(t)
	secondCID, err := fenceRecordCID([]byte(`{"different":"commit"}`))
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	attempts := []contentionAttempt{{Status: http.StatusOK, ReturnedCommit: firstCID}, {Status: http.StatusOK, ReturnedCommit: secondCID}}
	require.True(t, contentionCommitCIDsDistinct(attempts...), "2xx/2xx distinct commit CIDs were not retained as distinct evidence")
	marker := contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: "probe-final-marker"}, RecordCID: firstCID}
	available, present := contentionFinalMarkerMembership(marker, contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{}})
	require.True(t, available, "missing marker evidence available=%t present=%t", available, present)
	require.False(t, present, "missing marker evidence available=%t present=%t", available, present)
	require.True(t, strings.HasPrefix(contentionDuplicateEffectUnproven, "unproven:"), "duplicate effect conclusion overstates evidence: %q", contentionDuplicateEffectUnproven)
}

func TestContentionRemoteRefreshFailureOutputIsSafe(t *testing.T) {
	bodySecret := "refresh-body-secret-opaque"
	headerSecret := "malformed-header-secret"
	err := &atproto.AuthMethodError{Kind: atproto.ErrAuthMethodToken, Err: fmt.Errorf("refresh response body=%s malformed header=%s", bodySecret, headerSecret)}
	require.ErrorIs(t, err, atproto.ErrAuthMethodToken, "typed auth failure did not preserve errors.Is classification")
	output := fmt.Sprintf("refresh failure: %s", safeContentionError(err))
	require.NotContains(t, output, bodySecret, "safe fatal-output path leaked remote refresh text: %q", output)
	require.NotContains(t, output, headerSecret, "safe fatal-output path leaked remote refresh text: %q", output)
	require.Equal(t, "refresh failure: auth-token-error", output, "safe fatal-output classification=%q", output)
}

func TestContentionOutputSanitizesUntrustedCIDAndBody(t *testing.T) {
	secret := "password=opaque-secret"
	body := []byte(`{"commit":{"cid":"` + secret + `"}}`)
	if got := contentionReturnedCommit(body); got != contentionAbsentOrInvalidCID {
		require.Equal(t, contentionAbsentOrInvalidCID, got, "invalid returned CID was emitted: %q", got)
	}
	if got := safeContentionCID(secret); got != contentionAbsentOrInvalidCID {
		require.Equal(t, contentionAbsentOrInvalidCID, got, "unsafe CID field was emitted: %q", got)
	}
	summary := contentionResponseSummary(http.StatusBadRequest, []byte("non-JSON "+secret))
	require.NotContains(t, summary, secret, "response summary leaked opaque body: %q", summary)
	require.NotContains(t, summary, "non-JSON", "response summary leaked opaque body: %q", summary)
	require.Contains(t, summary, "body_bytes=", "response summary leaked opaque body: %q", summary)
	require.Contains(t, summary, "body_class=malformed", "response summary leaked opaque body: %q", summary)
}

func TestContentionLatencyEffectiveNUsesTwoRevisionReads(t *testing.T) {
	for _, test := range []struct {
		registered int
		remaining  int
		want       int
	}{{registered: 100, remaining: 158, want: 79}, {registered: 50, remaining: 80, want: 40}, {registered: 10, remaining: 8, want: 4}, {registered: 10, remaining: 1, want: 0}} {
		if got := effectiveContentionLatencyN(test.registered, test.remaining); got != test.want {
			assert.Equal(t, test.want, got, "effectiveContentionLatencyN(%d,%d)=%d want=%d", test.registered, test.remaining, got, test.want)
		}
	}
}

func TestContentionExpiryBudgetStopReportsEveryRemainingAge(t *testing.T) {
	ages := []time.Duration{15 * time.Minute, 60 * time.Minute}
	rows := contentionExpiryBudgetRows("provider", ages, "long", 0)
	require.Len(t, rows, len(ages), "unmeasured rows=%d want=%d", len(rows), len(ages))
	for i, row := range rows {
		assert.False(t, !strings.Contains(row, "referenceability=unmeasured: budget exhausted") || !strings.Contains(row, ages[i].String()), "remaining age row %d=%q", i, row)
	}
}

func TestContentionExpiryBudgetCoversBothSuccessfulAges(t *testing.T) {
	measurement := 3 + 2 + 2*(1+3+1) + 6
	cleanup := 3 + 1 + 1 + 3
	total := measurement + cleanup
	headroom := contentionExpiryHTTPBudget - total
	require.Equal(t, 21, measurement, "expiry budget arithmetic measurement=%d cleanup=%d total=%d headroom=%d cap=%d", measurement, cleanup, total, headroom, contentionExpiryHTTPBudget)
	require.Equal(t, 8, cleanup, "expiry budget arithmetic measurement=%d cleanup=%d total=%d headroom=%d cap=%d", measurement, cleanup, total, headroom, contentionExpiryHTTPBudget)
	require.Equal(t, 29, total, "expiry budget arithmetic measurement=%d cleanup=%d total=%d headroom=%d cap=%d", measurement, cleanup, total, headroom, contentionExpiryHTTPBudget)
	require.LessOrEqual(t, total, contentionExpiryHTTPBudget, "expiry budget arithmetic measurement=%d cleanup=%d total=%d headroom=%d cap=%d", measurement, cleanup, total, headroom, contentionExpiryHTTPBudget)
	require.Equal(t, 34, contentionExpiryHTTPBudget, "expiry budget arithmetic measurement=%d cleanup=%d total=%d headroom=%d cap=%d", measurement, cleanup, total, headroom, contentionExpiryHTTPBudget)
	require.Equal(t, 5, headroom, "expiry budget arithmetic measurement=%d cleanup=%d total=%d headroom=%d cap=%d", measurement, cleanup, total, headroom, contentionExpiryHTTPBudget)
}

func TestContentionSaturatedCleanupHTTPBudgetAllowsFinalVerification(t *testing.T) {
	budget := newContentionBudget(true, 0)
	measurementLimit := budget.httpLimit - budget.cleanupHTTPReserve
	for request := 0; request < measurementLimit; request++ {
		if err := budget.reserveHTTP(false); err != nil {
			require.NoError(t, err, "measurement request %d of %d rejected: %s", request+1, measurementLimit, safeContentionError(err))
		}
	}
	reserve := func(label string, count int) {
		t.Helper()
		for index := 0; index < count; index++ {
			if err := budget.reserveHTTP(true); err != nil {
				require.NoError(t, err, "cleanup %s request %d blocked: %s", label, index+1, safeContentionError(err))
			}
		}
	}
	reserve("initial verified read", 3)
	if err := budget.reserveApply("cleanup", 1, nil); err != nil {
		require.NoError(t, err, "challenged cleanup delete logical request blocked: %s", safeContentionError(err))
	}
	for replay := 0; replay < 2; replay++ {
		reserve("delete and authentication replay", 1)
		if err := budget.reserveApplyWire(true); err != nil {
			require.NoError(t, err, "cleanup applyWrites wire request %d blocked: %s", replay+1, safeContentionError(err))
		}
	}
	reserve("final verified read", 3)
	requests, _, wire, _, _, _, _, _ := budget.snapshot()
	require.Equal(t, contentionExpiryHTTPBudget, requests, "cleanup ledger total HTTP=%d/%d applyWrites wire=%d/2", requests, contentionExpiryHTTPBudget, wire)
	require.Equal(t, 2, wire, "cleanup ledger total HTTP=%d/%d applyWrites wire=%d/2", requests, contentionExpiryHTTPBudget, wire)
}

func TestContentionTrackBeforeSendEmitsCompleteStableSet(t *testing.T) {
	tracker := newContentionRecordTracker("run-test")
	keys := []contentionRecordKey{{Collection: fenceSnapshotCollection, RKey: "second"}, {Collection: contentionHeadCollection, RKey: "self"}}
	first := tracker.track(keys, "publication")
	require.Len(t, first, 2, "track-before-send first set=%v run=%q", first, tracker.runID)
	require.Equal(t, "run-test", tracker.runID, "track-before-send first set=%v run=%q", first, tracker.runID)
	if later := tracker.track(keys, "publication"); len(later) != 0 {
		require.Len(t, later, 0, "already tracked keys were emitted again: %v", later)
	}
	set := contentionTrackedSet(tracker.snapshot())
	require.Equal(t, contentionHeadCollection+"/self,"+fenceSnapshotCollection+"/second", set, "complete tracked set=%q", set)
}

func TestContentionLatencyCreateUpdateCleanupCategories(t *testing.T) {
	tracker := newContentionRecordTracker("run-test")
	key := contentionRecordKey{Collection: fenceSnapshotCollection, RKey: "latency-fixture"}
	latencyCategory, err := contentionCleanupCategory("latency-init")
	if err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	require.Equal(t, "latency", latencyCategory, "latency initialization category=%q", latencyCategory)
	tracker.track([]contentionRecordKey{key}, latencyCategory)
	if _, err := contentionCleanupCategory("latency"); err != nil {
		require.NoError(t, err, safeContentionError(err))
	}
	tracker.track([]contentionRecordKey{key}, "latency")
	budget := newContentionBudget(false, 1)
	if err := budget.reserveApply("latency-init", 3, nil); err != nil {
		require.NoError(t, err, "create operation reserve: %s", safeContentionError(err))
	}
	if err := budget.reserveApply("latency", 3, nil); err != nil {
		require.NoError(t, err, "update operation reserve: %s", safeContentionError(err))
	}
	deleteKinds := map[string]int{trackerKind(tracker, key): 1}
	if err := budget.reserveApply("cleanup", 1, deleteKinds); err != nil {
		require.NoError(t, err, "cleanup reserve: %s", safeContentionError(err))
	}
	httpRequests, logical, wire, _, _, cleanupDeletes, latencyUpdates, _ := budget.snapshot()
	_, latencyDeletes, _ := budget.cleanupBreakdown()
	require.Equal(t, 0, httpRequests, "lifecycle accounting http=%d logical=%d wire=%d cleanup=%d latency-cleanup=%d updates=%d", httpRequests, logical, wire, cleanupDeletes, latencyDeletes, latencyUpdates)
	require.Equal(t, 3, logical, "lifecycle accounting http=%d logical=%d wire=%d cleanup=%d latency-cleanup=%d updates=%d", httpRequests, logical, wire, cleanupDeletes, latencyDeletes, latencyUpdates)
	require.Equal(t, 0, wire, "lifecycle accounting http=%d logical=%d wire=%d cleanup=%d latency-cleanup=%d updates=%d", httpRequests, logical, wire, cleanupDeletes, latencyDeletes, latencyUpdates)
	require.Equal(t, 1, cleanupDeletes, "lifecycle accounting http=%d logical=%d wire=%d cleanup=%d latency-cleanup=%d updates=%d", httpRequests, logical, wire, cleanupDeletes, latencyDeletes, latencyUpdates)
	require.Equal(t, 1, latencyDeletes, "lifecycle accounting http=%d logical=%d wire=%d cleanup=%d latency-cleanup=%d updates=%d", httpRequests, logical, wire, cleanupDeletes, latencyDeletes, latencyUpdates)
	require.Equal(t, 1, latencyUpdates, "lifecycle accounting http=%d logical=%d wire=%d cleanup=%d latency-cleanup=%d updates=%d", httpRequests, logical, wire, cleanupDeletes, latencyDeletes, latencyUpdates)
	if _, err := contentionCleanupCategory("unknown"); err == nil {
		require.Error(t, err, "unknown cleanup category was accepted")
	}
	if err := budget.reserveApply("cleanup", 1, map[string]int{"unknown": 1}); !errors.Is(err, errContentionBudget) {
		require.ErrorIs(t, err, errContentionBudget, "unknown delete category error=%s", safeContentionError(err))
	}
}

func TestContentionDisclosureDurationRequiresObservedExactBytes(t *testing.T) {
	require.False(t, contentionDisclosureDurationMeasured(http.StatusBadRequest, true, true, false, false), "never-reachable candidate was reported as a measured disclosure window")
	require.True(t, contentionDisclosureDurationMeasured(http.StatusBadRequest, true, true, false, true), "exact bytes newly reachable after rejection and no-reference verification were not measurable")
	require.False(t, contentionDisclosureDurationMeasured(http.StatusBadRequest, true, false, false, true), "candidate with ambiguous or existing record references was measured")
	require.False(t, contentionDisclosureDurationMeasured(http.StatusBadRequest, true, true, true, true), "pre-existing reachability was attributed to rejection")
}

func TestContentionExperiment4aRowRequiresVerifiedSuppression(t *testing.T) {
	attempt := contentionAttempt{D1: contentionUnknown}
	for _, input := range []struct {
		name       string
		status     int
		verified   bool
		suppressed bool
	}{{name: "non-2xx forward", status: http.StatusBadGateway}, {name: "unavailable verification", status: http.StatusOK}} {
		t.Run(input.name, func(t *testing.T) {
			row := contentionExperiment4aRow("provider", attempt, createNeverUploadedCID(t), input.status, "", input.verified, input.suppressed)
			require.NotContains(t, row, "experiment-4a-committed-but-response-lost", "failed construction emitted affirmative claim: %s", row)
			require.NotContains(t, row, "verified committed before", "failed construction emitted affirmative claim: %s", row)
			require.Contains(t, row, "unmeasured/inconclusive", "failed construction emitted affirmative claim: %s", row)
			require.Contains(t, row, "construction-failed", "failed construction emitted affirmative claim: %s", row)
		})
	}
	positive := contentionExperiment4aRow("provider", attempt, createNeverUploadedCID(t), http.StatusOK, createNeverUploadedCID(t), true, true)
	require.Contains(t, positive, "experiment-4a-committed-but-response-lost", "verified and suppressed construction omitted affirmative label: %s", positive)
	require.Contains(t, positive, "verified committed before", "verified and suppressed construction omitted affirmative label: %s", positive)
}

func TestContentionLatencyBudgetExhaustionKeepsSentAttempt(t *testing.T) {
	attempt := contentionAttempt{D1: contentionUnknown, Resolution: contentionUnavailable, Dispatched: true, Status: http.StatusOK, Duration: time.Millisecond}
	counted, result, successful := contentionLatencyEvidence(attempt, true)
	require.True(t, counted, "sent write lost its unresolved latency evidence: counted=%t result=%q successful=%t", counted, result, successful)
	require.Equal(t, "unresolved-budget-exhausted", result, "sent write lost its unresolved latency evidence: counted=%t result=%q successful=%t", counted, result, successful)
	require.False(t, successful, "sent write lost its unresolved latency evidence: counted=%t result=%q successful=%t", counted, result, successful)
}

func TestContentionOfflineQuotaAndBlobSizeRejectionFixtures(t *testing.T) {
	fixtures := []struct {
		name       string
		status     int
		body       []byte
		precedence []byte
	}{
		{name: "account quota", status: http.StatusTooManyRequests, body: []byte(`{"error":"QuotaExceeded"}`), precedence: []byte(`{"error":"QuotaExceeded"}`)},
		{name: "per-blob size", status: http.StatusRequestEntityTooLarge, body: []byte(`{"error":"BlobTooLarge"}`), precedence: []byte(`{"error":"BlobTooLarge"}`)},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			outcome := classifyContentionD1(contentionD1Input{Status: fixture.status, Body: fixture.body})
			require.Equal(t, contentionRejectedOther, outcome, "synthetic 4xx classified %q", outcome)
			possibleDisclosure := outcome == contentionRejectedOther
			require.True(t, possibleDisclosure, "other 4xx was not treated as possible disclosure")
			marker := contentionMarker{Key: atproto.RecordKey{Collection: fenceSnapshotCollection, RKey: "synthetic-rejection"}, RecordCID: "expected-cid"}
			verifiedAbsent := resolveContentionMarker(marker, contentionRevisionEvidence{Verified: true, Membership: map[atproto.RecordKey]string{}})
			require.Equal(t, contentionNotLanded, verifiedAbsent, "possible-disclosure rejection recovery=%s retry=%t", verifiedAbsent, contentionRetryEvidenceEligible(outcome, verifiedAbsent))
			require.False(t, contentionRetryEvidenceEligible(outcome, verifiedAbsent), "possible-disclosure rejection recovery=%s retry=%t", verifiedAbsent, contentionRetryEvidenceEligible(outcome, verifiedAbsent))
			unknown := classifyContentionD1(contentionD1Input{Status: http.StatusInternalServerError, Body: fixture.precedence})
			require.Equal(t, contentionUnknown, unknown, "5xx containing provider rejection text did not take D1 precedence: %q", unknown)
			unavailable := resolveContentionMarker(marker, contentionRevisionEvidence{})
			require.Equal(t, contentionUnavailable, unavailable, "unavailable recovery=%s retry=%t", unavailable, contentionRetryEvidenceEligible(unknown, unavailable))
			require.False(t, contentionRetryEvidenceEligible(unknown, unavailable), "unavailable recovery=%s retry=%t", unavailable, contentionRetryEvidenceEligible(unknown, unavailable))
			require.True(t, contentionRetryEvidenceEligible(unknown, verifiedAbsent), "unknown outcome plus verified absence did not produce D2 retry evidence eligibility")
		})
	}
}

func TestContentionRunnerDeadlineFailsClosed(t *testing.T) {
	if err := contentionDeadlineError(time.Now().Add(29*time.Minute), true, false); err == nil {
		require.Error(t, err, "short run accepted an insufficient deadline")
	}
	if err := contentionDeadlineError(time.Now().Add(31*time.Minute), true, false); err != nil {
		require.NoError(t, err, "short run rejected adequate deadline: %s", safeContentionError(err))
	}
	if err := contentionDeadlineError(time.Now().Add(109*time.Minute), true, true); err == nil {
		require.Error(t, err, "long schedule accepted an insufficient deadline")
	}
	if err := contentionDeadlineError(time.Now().Add(111*time.Minute), true, true); err != nil {
		require.NoError(t, err, "long schedule rejected adequate deadline: %s", safeContentionError(err))
	}
	if err := contentionDeadlineError(time.Time{}, false, false); err == nil {
		require.Error(t, err, "run accepted missing runner deadline")
	}
}
