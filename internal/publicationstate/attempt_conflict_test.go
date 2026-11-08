package publicationstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirstConflictResolveRefreshReopenRepinRetireAndPayloadLoss(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	store, directory := newStore(t, f)
	floorObservation := f.observation(1)
	first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 1)
	preflight := attemptView(f, floorObservation, false)
	review := attemptReview()
	attempt := createAndSubmitSuccessor(t, store, f, candidate, preflight, review)

	h1 := competingSuccessorView(t, f, preflight, candidate, 0x41, []byte{0x51, 0x52, 0x53})
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, h1)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, resolution.Outcome)
	h1Conflict, present, err := store.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	require.NotEmpty(t, h1Conflict.Evidence)
	assert.Equal(t, h1.Head, h1Conflict.Head)
	assert.Equal(t, h1.Snapshots[len(h1.Snapshots)-1].Raw, h1Conflict.HeadRecord)
	assert.Equal(t, uint64(4), h1Conflict.HeadSequence)
	assert.Equal(t, "0000000000000004", h1Conflict.HeadKey)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	beforeRefresh, present, err := reopened.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, h1Conflict.ID, beforeRefresh.ID)
	assert.Equal(t, h1Conflict.Evidence, beforeRefresh.Evidence)
	samePosition, err := reopened.ResolveAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, h1)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, samePosition.Outcome)

	rewind := competingSuccessorView(t, f, preflight, candidate, 0x41, []byte{0x51, 0x52})
	rewritten := competingSuccessorView(t, f, preflight, candidate, 0x41, []byte{0x61, 0x62, 0x63})
	substituted := competingSuccessorView(t, f, preflight, candidate, 0x71, []byte{0x72, 0x73, 0x74})
	for name, view := range map[string]SuppliedRepositoryView{"rewind": rewind, "rewritten-descendant": rewritten, "substituted-occupant": substituted} {
		t.Run(name, func(t *testing.T) {
			before := readAttemptLogicalRows(t, reopened)
			_, err := reopened.ResolveAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, view)
			requireErrorMetadata(t, err, ErrContinuity, StageResolve, ReasonCorrupt)
			assert.Equal(t, before, readAttemptLogicalRows(t, reopened))
		})
	}

	h2 := competingSuccessorView(t, f, preflight, candidate, 0x41, []byte{0x51, 0x52, 0x53, 0x54})
	refreshed, err := reopened.ResolveAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, h2)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, refreshed.Outcome)
	latest, present, err := reopened.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, h1Conflict.ID, latest.ID)
	assert.Equal(t, h1Conflict.Evidence, latest.Evidence)
	var latestOutcome []byte
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT body FROM attempt_evidence WHERE attempt_id=? AND role='outcome'", attempt.ID[:]).Scan(&latestOutcome))
	var latestWire attemptEvidenceWire
	require.NoError(t, strictJSON(latestOutcome, &latestWire))
	assert.Len(t, latestWire.Suffix, 5)

	fork := forkGenesisObservation(t, f)
	repin, err := reopened.Prepare(ctx, ModeReplaceFloor, fork, f.payload)
	require.NoError(t, err)
	_, err = reopened.Accept(ctx, ModeReplaceFloor, repin.StateToken, fork, f.payload, repin.Confirmation)
	require.NoError(t, err)
	afterRepin, present, err := reopened.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, h1Conflict.ID, afterRepin.ID)
	abandon, err := reopened.PrepareAbandon(ctx, attempt.ID, &h2)
	require.NoError(t, err)
	retired, err := reopened.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &h2, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	var refs, reservations int
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attempt.ID[:]).Scan(&refs))
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?", attempt.ID[:]).Scan(&reservations))
	assert.Zero(t, refs)
	assert.Zero(t, reservations)
	payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
	require.NoError(t, os.Remove(payloadPath))
	require.NoError(t, reopened.Close())

	final, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer final.Close()
	withoutPayload, present, err := final.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, h1Conflict.ID, withoutPayload.ID)
	assert.Equal(t, h1Conflict.Evidence, withoutPayload.Evidence)
	assert.Equal(t, h1.Head, withoutPayload.Head)
}

func TestFirstConflictDirectAbandonAndThreeRoleAdmission(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	positionLimits := DefaultLimits()
	positionLimits.SuppliedContextBytes = 512
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	slot := uint64(4096)
	reserve := 3*slot + 3*32

	underLimits := DefaultAttemptLimits()
	underLimits.EvidenceSlotBytes = slot
	underLimits.EvidenceBytes = reserve - 1
	under, underDirectory := openAttemptStoreWithAttemptLimits(t, f, positionLimits, underLimits)
	_, present, err := under.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	_, err = under.PrepareAttempt(ctx, candidate, empty, review)
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	result, err := under.CreateAttempt(ctx, [32]byte{}, candidate, empty, review, [32]byte{})
	requireErrorMetadata(t, err, ErrLimit, StageAttempt, ReasonCapacity)
	assert.Equal(t, Attempt{}, result)
	assertNoAttemptCustodyMutation(t, under, underDirectory)
	require.NoError(t, under.Close())

	exactLimits := DefaultAttemptLimits()
	exactLimits.EvidenceSlotBytes = slot
	exactLimits.EvidenceBytes = reserve
	exact, directory := openAttemptStoreWithAttemptLimits(t, f, positionLimits, exactLimits)
	attempt := createAndSubmitGenesis(t, exact, f, empty, candidate, review)
	absent, present, err := exact.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, FirstConflictEvidence{}, absent)
	conflict := competingGenesisView(t, f)
	proposal, err := exact.PrepareAbandon(ctx, attempt.ID, &conflict)
	require.NoError(t, err)
	retired, err := exact.AbandonAttempt(ctx, attempt.ID, proposal.StateToken, &conflict, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, retired.Outcome)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	var roles int
	require.NoError(t, exact.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_evidence WHERE attempt_id=?", attempt.ID[:]).Scan(&roles))
	assert.Equal(t, 3, roles)
	first, present, err := exact.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, conflict.Head, first.Head)
	require.NoError(t, exact.Close())
	reopened, err := OpenWithOptions(directory, f.binding, attemptOpenOptions(positionLimits, exactLimits))
	require.NoError(t, err)
	defer reopened.Close()
	loaded, present, err := reopened.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, first.ID, loaded.ID)
	assert.Equal(t, first.Evidence, loaded.Evidence)
}

func TestFirstConflictInsertionAndEventFailuresRollbackTogether(t *testing.T) {
	for _, fault := range []struct {
		name string
		ddl  string
	}{
		{"first-conflict-insert", "CREATE TEMP TRIGGER fail_first_conflict BEFORE INSERT ON main.attempt_evidence WHEN NEW.role='first-conflict' BEGIN SELECT RAISE(ABORT,'first-conflict-canary'); END"},
		{"lost-event-insert", "CREATE TEMP TRIGGER fail_lost_event BEFORE INSERT ON main.attempt_events WHEN NEW.kind='outcome-lost-fence' BEGIN SELECT RAISE(ABORT,'lost-event-canary'); END"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			f.appendRecord(t, 1)
			store, directory := newStore(t, f)
			floorObservation := f.observation(1)
			first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
			require.NoError(t, err)
			_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
			require.NoError(t, err)
			candidate := attemptCandidate(f, 1)
			preflight := attemptView(f, floorObservation, false)
			review := attemptReview()
			attempt := createAndSubmitSuccessor(t, store, f, candidate, preflight, review)
			conflict := competingSuccessorView(t, f, preflight, candidate, 0x31, []byte{0x32})
			before := readAttemptLogicalRows(t, store)
			payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
			beforePayload, err := os.ReadFile(payloadPath)
			require.NoError(t, err)
			_, err = store.conn.ExecContext(ctx, fault.ddl)
			require.NoError(t, err)
			result, err := store.ResolveAttempt(ctx, attempt.ID, stateDigestForAttempt(t, store, attempt.ID), conflict)
			requireErrorMetadata(t, err, ErrStorage, StageResolve, ReasonIO)
			assert.Equal(t, AttemptResolution{}, result)
			assert.NotContains(t, err.Error(), "-canary")
			assert.Equal(t, before, readAttemptLogicalRows(t, store))
			afterPayload, err := os.ReadFile(payloadPath)
			require.NoError(t, err)
			assert.Equal(t, beforePayload, afterPayload)
			loaded, err := store.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, OutcomeUnresolved, loaded.Outcome)
			_, err = store.conn.ExecContext(ctx, "DROP TRIGGER "+map[string]string{"first-conflict-insert": "fail_first_conflict", "lost-event-insert": "fail_lost_event"}[fault.name])
			require.NoError(t, err)
			require.NoError(t, store.Close())
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			absent, found, err := reopened.ReadFirstConflict(ctx, attempt.ID)
			require.NoError(t, err)
			assert.False(t, found)
			assert.Equal(t, FirstConflictEvidence{}, absent)
			resolution, err := reopened.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, conflict)
			require.NoError(t, err)
			assert.Equal(t, OutcomeLostFence, resolution.Outcome)
			_, found, err = reopened.ReadFirstConflict(ctx, attempt.ID)
			require.NoError(t, err)
			assert.True(t, found)
		})
	}
}

func TestFirstConflictDirectAbandonRetirementFailureRollsBackAllRecords(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	conflict := competingGenesisView(t, f)
	proposal, err := store.PrepareAbandon(ctx, attempt.ID, &conflict)
	require.NoError(t, err)
	before := readAttemptLogicalRows(t, store)
	payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
	beforePayload, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "CREATE TEMP TRIGGER fail_first_conflict_retirement BEFORE INSERT ON main.attempt_evidence WHEN NEW.role='retirement' BEGIN SELECT RAISE(ABORT,'first-conflict-retirement-canary'); END")
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, proposal.StateToken, &conflict, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageAbandon, ReasonIO)
	assert.Equal(t, Attempt{}, retired)
	assert.NotContains(t, err.Error(), "-canary")
	assert.Equal(t, before, readAttemptLogicalRows(t, store))
	afterPayload, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	assert.Equal(t, beforePayload, afterPayload)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, OutcomeUnresolved, loaded.Outcome)
	_, found, err := store.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	assert.False(t, found)
	_, err = store.conn.ExecContext(ctx, "DROP TRIGGER fail_first_conflict_retirement")
	require.NoError(t, err)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	proposal, err = reopened.PrepareAbandon(ctx, attempt.ID, &conflict)
	require.NoError(t, err)
	retired, err = reopened.AbandonAttempt(ctx, attempt.ID, proposal.StateToken, &conflict, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, retired.Outcome)
	_, found, err = reopened.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	assert.True(t, found)
}

func TestFirstConflictReadbackRejectsMissingAndMisjoinedRows(t *testing.T) {
	for _, damage := range []string{"missing-role", "wrong-core", "wrong-event-id", "wrong-proof"} {
		t.Run(damage, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, _ := newStore(t, f)
			candidate := attemptCandidate(f, 0)
			empty := attemptView(f, f.observation(1), true)
			review := attemptReview()
			attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
			conflict := competingGenesisView(t, f)
			loaded, err := store.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			_, err = store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, conflict)
			require.NoError(t, err)
			var report, event []byte
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body FROM attempt_evidence WHERE attempt_id=? AND role='first-conflict'", attempt.ID[:]).Scan(&report))
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body FROM attempt_events WHERE attempt_id=? AND kind='outcome-lost-fence'", attempt.ID[:]).Scan(&event))
			switch damage {
			case "missing-role":
				_, err = store.conn.ExecContext(ctx, "DELETE FROM attempt_evidence WHERE attempt_id=? AND role='first-conflict'", attempt.ID[:])
				require.NoError(t, err)
			case "wrong-core":
				var wire firstConflictWire
				require.NoError(t, strictJSON(report, &wire))
				wire.CoreDigest[0] ^= 0x80
				report, err = canonicalJSON(wire)
				require.NoError(t, err)
				digest := domainHash("systems.lamb.dottie.publication-attempt-evidence.v1", report)
				_, err = store.conn.ExecContext(ctx, "UPDATE attempt_evidence SET body=?,digest=? WHERE attempt_id=? AND role='first-conflict'", report, digest[:], attempt.ID[:])
				require.NoError(t, err)
			case "wrong-event-id":
				var wire attemptEventWire
				require.NoError(t, strictJSON(event, &wire))
				wire.Evidence[0] ^= 0xff
				event, err = encodeAttemptEvent(wire)
				require.NoError(t, err)
				digest := domainHash("systems.lamb.dottie.publication-attempt-event.v1", event)
				_, err = store.conn.ExecContext(ctx, "UPDATE attempt_events SET body=?,digest=? WHERE attempt_id=? AND kind='outcome-lost-fence'", event, digest[:], attempt.ID[:])
				require.NoError(t, err)
			case "wrong-proof":
				var envelope firstConflictWire
				require.NoError(t, strictJSON(report, &envelope))
				envelope.Proof.Suffix[0].Raw[0] ^= 0x80
				report, err = canonicalJSON(envelope)
				require.NoError(t, err)
				reportDigest := domainHash("systems.lamb.dottie.publication-attempt-evidence.v1", report)
				reportID := domainHash("systems.lamb.dottie.publication-attempt-first-conflict.v1", report)
				_, err = store.conn.ExecContext(ctx, "UPDATE attempt_evidence SET body=?,digest=? WHERE attempt_id=? AND role='first-conflict'", report, reportDigest[:], attempt.ID[:])
				require.NoError(t, err)
				var eventWire attemptEventWire
				require.NoError(t, strictJSON(event, &eventWire))
				eventWire.Evidence = bytes.Clone(reportID[:])
				event, err = encodeAttemptEvent(eventWire)
				require.NoError(t, err)
				eventDigest := domainHash("systems.lamb.dottie.publication-attempt-event.v1", event)
				_, err = store.conn.ExecContext(ctx, "UPDATE attempt_events SET body=?,digest=? WHERE attempt_id=? AND kind='outcome-lost-fence'", event, eventDigest[:], attempt.ID[:])
				require.NoError(t, err)
			}
			_, _, err = store.ReadFirstConflict(ctx, attempt.ID)
			requireErrorMetadata(t, err, ErrSchema, StageHistory, ReasonCorrupt)
			require.NoError(t, store.Close())
		})
	}
}

func TestFirstConflictCannotBeCopiedToAnotherAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	first := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	conflict := competingGenesisView(t, f)
	proposal, err := store.PrepareAbandon(ctx, first.ID, &conflict)
	require.NoError(t, err)
	_, err = store.AbandonAttempt(ctx, first.ID, proposal.StateToken, &conflict, proposal.Confirmation)
	require.NoError(t, err)
	var body, digest []byte
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body,digest FROM attempt_evidence WHERE attempt_id=? AND role='first-conflict'", first.ID[:]).Scan(&body, &digest))

	secondCandidate := candidateWithPublicationID(t, candidate, [16]byte{0x73})
	secondProposal, err := store.PrepareAttempt(ctx, secondCandidate, empty, review)
	require.NoError(t, err)
	second, err := store.CreateAttempt(ctx, secondProposal.StateToken, secondCandidate, empty, review, secondProposal.Confirmation)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "INSERT INTO attempt_evidence(attempt_id,role,body,digest) VALUES(?,'first-conflict',?,?)", second.ID[:], body, digest)
	require.NoError(t, err)
	_, _, err = store.ReadFirstConflict(ctx, second.ID)
	requireErrorMetadata(t, err, ErrSchema, StageHistory, ReasonCorrupt)
}

func TestTerminalEvidenceRefreshRequiresExactSuffixPrefix(t *testing.T) {
	for _, transition := range []struct {
		name string
		from AttemptOutcome
		to   AttemptOutcome
	}{
		{"current-to-superseded", OutcomeCurrent, OutcomeSuperseded},
		{"superseded-extension", OutcomeSuperseded, OutcomeSuperseded},
		{"lost-fence-extension", OutcomeLostFence, OutcomeLostFence},
	} {
		t.Run(transition.name, func(t *testing.T) {
			old := attemptEvidenceWire{Version: 1, Role: "outcome", AttemptedKey: "0000000000000001", AttemptedRecord: []byte("candidate"), PredecessorRecord: []byte("predecessor"), Suffix: []SnapshotBlock{{Key: "0000000000000001", Raw: []byte("first")}, {Key: "0000000000000002", Raw: []byte("second")}}, Outcome: string(transition.from)}
			if transition.from == OutcomeLostFence {
				old.AttemptedRecord = []byte("occupant")
				old.Suffix[0].Raw = []byte("occupant")
			}
			newer := old
			newer.Outcome = string(transition.to)
			newer.Suffix = append(cloneSnapshotBlocks(old.Suffix), SnapshotBlock{Key: "0000000000000003", Raw: []byte("third")})
			oldBytes, err := encodeAttemptEvidence(old)
			require.NoError(t, err)
			newBytes, err := encodeAttemptEvidence(newer)
			require.NoError(t, err)
			assert.True(t, terminalEvidenceExtends(oldBytes, newBytes))
			short := old
			short.Suffix = short.Suffix[:1]
			shortBytes, err := encodeAttemptEvidence(short)
			require.NoError(t, err)
			assert.False(t, terminalEvidenceExtends(oldBytes, shortBytes))
			rewritten := newer
			rewritten.Suffix[1].Raw = []byte("rewritten")
			rewrittenBytes, err := encodeAttemptEvidence(rewritten)
			require.NoError(t, err)
			assert.False(t, terminalEvidenceExtends(oldBytes, rewrittenBytes))
		})
	}
}

func createAndSubmitSuccessor(t *testing.T, store *Store, f fixture, candidate CandidateInput, preflight SuppliedRepositoryView, review LocalReviewContext) Attempt {
	t.Helper()
	ctx := context.Background()
	proposal, err := store.PrepareAttempt(ctx, candidate, preflight, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, preflight, review, proposal.Confirmation)
	require.NoError(t, err)
	upload, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, upload.StateToken, preflight, review, upload.Confirmation)
	require.NoError(t, err)
	submission, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, preflight, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submission.StateToken, preflight, review, submission.Confirmation)
	require.NoError(t, err)
	return attempt
}

func competingSuccessorView(t *testing.T, f fixture, preflight SuppliedRepositoryView, candidate CandidateInput, occupantID byte, descendantIDs []byte) SuppliedRepositoryView {
	t.Helper()
	occupant, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	occupant.PublicationID = [16]byte{}
	occupant.PublicationID[15] = occupantID
	occupantRaw, err := publication.EncodeSnapshot(occupant)
	require.NoError(t, err)
	last := SnapshotBlock{Key: candidate.SnapshotKey, Raw: occupantRaw}
	blocks := []SnapshotBlock{cloneSnapshotBlocks(f.blocks[:1])[0], last}
	for _, id := range descendantIDs {
		record, err := publication.DecodeSnapshot(last.Raw)
		require.NoError(t, err)
		lastCID, err := publication.RecordCID(last.Raw)
		require.NoError(t, err)
		record.PublicationSeq++
		record.Parent = lastCID
		record.PublicationID = [16]byte{}
		record.PublicationID[15] = id
		raw, err := publication.EncodeSnapshot(record)
		require.NoError(t, err)
		key, err := publication.SequenceKey(record.PublicationSeq)
		require.NoError(t, err)
		last = SnapshotBlock{Key: key, Raw: raw}
		blocks = append(blocks, last)
	}
	lastRecord, err := publication.DecodeSnapshot(last.Raw)
	require.NoError(t, err)
	lastCID, err := publication.RecordCID(last.Raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: lastRecord.Vault, PublicationSeq: lastRecord.PublicationSeq, SnapshotCID: lastCID, BlobCID: lastRecord.Blob.CID})
	require.NoError(t, err)
	return SuppliedRepositoryView{Origin: f.binding, Scope: preflight.Scope, SuppliedContext: cloneContext(preflight.SuppliedContext), Head: head, Snapshots: blocks}
}
