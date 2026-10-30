package atproto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func validPublication(blobCID string) FencedPublication {
	snapshot := json.RawMessage(fmt.Sprintf(`{"$type":"systems.lamb.dottie.vaultSnapshot","probe":"one","blob":{"$type":"blob","ref":{"$link":%q},"mimeType":"application/octet-stream","size":7}}`, blobCID))
	return FencedPublication{
		FirstBlobReference: RecordWrite{Action: RecordCreate, Collection: "systems.lamb.dottie.vaultSnapshot", RKey: "probe-one", Record: snapshot},
		VaultHead:          RecordWrite{Action: RecordUpdate, Collection: "systems.lamb.dottie.vaultHead", RKey: "self", Record: json.RawMessage(`{"$type":"systems.lamb.dottie.vaultHead","snapshotRkey":"probe-one"}`)},
		VaultControl:       RecordWrite{Action: RecordUpdate, Collection: "systems.lamb.dottie.vaultControl", RKey: "self", Record: json.RawMessage(`{"$type":"systems.lamb.dottie.vaultControl","devices":[],"policyEpoch":1}`)},
	}
}

func TestPublishFencedAlwaysEncodesSwapCommit(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	transport := &proofTransport{doStatus: 200, doBody: []byte(`{"commit":{"cid":"bafybeigdyrzt5sfp7udm7hu76uhy26nfjpy2ytma2if42f2qht6lmtkq3u"}}`)}
	_, err := PublishFenced(context.Background(), transport, &Revision{did: proofTestDID, commitCID: fixture.root.String()}, validPublication(fixture.root.String()))
	if err != nil {
		t.Fatal(err)
	}
	if transport.requestMethod != "POST" || transport.requestPath != "com.atproto.repo.applyWrites" {
		t.Fatalf("applyWrites request=%s %s", transport.requestMethod, transport.requestPath)
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(transport.requestBody, &input); err != nil {
		t.Fatal(err)
	}
	var swapCommit string
	if raw, ok := input["swapCommit"]; !ok || json.Unmarshal(raw, &swapCommit) != nil || swapCommit != fixture.root.String() {
		t.Fatalf("encoded applyWrites input omitted or changed swapCommit: %s", transport.requestBody)
	}
	var writes []json.RawMessage
	if err := json.Unmarshal(input["writes"], &writes); err != nil || len(writes) != 3 {
		t.Fatalf("encoded batch writes=%d error=%v", len(writes), err)
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
				t.Fatalf("publish error=%v want %v", err, test.want)
			}
		})
	}
}

func TestPublishFencedDoesNotRetryAmbiguousTransport(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	transport := &proofTransport{doError: errors.New("timeout")}
	_, err := PublishFenced(context.Background(), transport, &Revision{did: proofTestDID, commitCID: fixture.root.String()}, validPublication(fixture.root.String()))
	if !errors.Is(err, ErrAmbiguousTransport) || transport.requestPath != "com.atproto.repo.applyWrites" {
		t.Fatalf("publish transport error=%v path=%q", err, transport.requestPath)
	}
}

func TestPublishFencedRejectsInvalidBatchBeforeTransport(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	publication := validPublication(fixture.root.String())
	publication.VaultHead.Record = json.RawMessage(`not json`)
	transport := &proofTransport{}
	_, err := PublishFenced(context.Background(), transport, &Revision{did: proofTestDID, commitCID: fixture.root.String()}, publication)
	if !errors.Is(err, ErrBatchRejected) || transport.requestPath != "" {
		t.Fatalf("invalid batch error=%v request=%q", err, transport.requestPath)
	}
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
				t.Fatalf("error = %v, want %v", err, testCase.want)
			}
			if !errors.Is(err, ErrCandidateMayBeDisclosed) {
				t.Fatalf("post-submission failure must signal possible candidate disclosure: %v", err)
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
		t.Fatalf("error = %v, want ErrFenceLost", err)
	}
	if errors.Is(err, ErrCandidateMayBeDisclosed) {
		t.Fatalf("a lost fence is checked before blob processing and must not be reported as disclosure risk: %v", err)
	}
}
