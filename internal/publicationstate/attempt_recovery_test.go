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

func TestNeverSubmittedAttemptCanBeAbandonedWithoutRepositoryView(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, retired.Outcome)
	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Attempt{}, active)
	var refs int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&refs))
	assert.Equal(t, 0, refs)
}

func TestSubmittedAbsenceViewCannotAuthorizeAbandonment(t *testing.T) {
	for _, caseValue := range []struct {
		name           string
		observedAbsent bool
		genesis        bool
	}{
		{name: "submitted-unresolved-empty-view", genesis: true},
		{name: "observed-absent-old-predecessor-view", observedAbsent: true},
	} {
		t.Run(caseValue.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			if !caseValue.genesis {
				f.appendRecord(t, 1)
			}
			store, directory := newStore(t, f)
			t.Cleanup(func() { _ = store.Close() })
			var candidate CandidateInput
			var absenceView SuppliedRepositoryView
			var currentView SuppliedRepositoryView
			review := attemptReview()
			var attempt Attempt
			if caseValue.genesis {
				candidate = attemptCandidate(f, 0)
				absenceView = attemptView(f, f.observation(1), true)
				attempt = createAndSubmitGenesis(t, store, f, absenceView, candidate, review)
				currentView = attemptView(f, f.observation(1), false)
			} else {
				floorObservation := f.observation(1)
				first, err := store.Prepare(ctx, ModeFirstUse, floorObservation, f.payload)
				require.NoError(t, err)
				_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, floorObservation, f.payload, first.Confirmation)
				require.NoError(t, err)
				candidate = attemptCandidate(f, 1)
				absenceView = attemptView(f, floorObservation, false)
				attempt = createAndSubmitSuccessor(t, store, f, candidate, absenceView, review)
				currentView = attemptView(f, f.observation(2), false)
			}
			loaded, err := store.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, OutcomeUnresolved, loaded.Outcome)
			if caseValue.observedAbsent {
				resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, absenceView)
				require.NoError(t, err)
				assert.Equal(t, OutcomeAbsentUnresolved, resolution.Outcome)
				loaded = resolution.Attempt
			}
			before := readAttemptLogicalRows(t, store)
			payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
			beforePayload, err := os.ReadFile(payloadPath)
			require.NoError(t, err)

			proposal, err := store.PrepareAbandon(ctx, attempt.ID, &absenceView)
			requireErrorMetadata(t, err, ErrContinuity, StageAbandon, ReasonSubmittedUnknown)
			assert.Equal(t, AbandonProposal{}, proposal)
			assert.Equal(t, before, readAttemptLogicalRows(t, store))
			currentProposal, err := store.PrepareAbandon(ctx, attempt.ID, &currentView)
			require.NoError(t, err)
			retired, err := store.AbandonAttempt(ctx, attempt.ID, currentProposal.StateToken, &absenceView, currentProposal.Confirmation)
			requireErrorMetadata(t, err, ErrContinuity, StageAbandon, ReasonSubmittedUnknown)
			assert.Equal(t, Attempt{}, retired)
			assert.Equal(t, before, readAttemptLogicalRows(t, store))
			afterPayload, err := os.ReadFile(payloadPath)
			require.NoError(t, err)
			assert.Equal(t, beforePayload, afterPayload)

			retired, err = store.AbandonAttempt(ctx, attempt.ID, currentProposal.StateToken, &currentView, currentProposal.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
			assert.Equal(t, OutcomeCurrent, retired.Outcome)
			assertOutcomeRetirementProofs(t, store, attempt.ID, OutcomeCurrent)
			require.NoError(t, store.Close())
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, AttemptRetiredAbandoned, loaded.Lifecycle)
			assert.Equal(t, OutcomeCurrent, loaded.Outcome)
			assertOutcomeRetirementProofs(t, reopened, attempt.ID, OutcomeCurrent)
		})
	}
}

func TestPublicationAttemptAbsentAfterSubmissionCannotRetryOrAbandon(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	mayHaveSubmitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	_, err = store.RecordObservation(ctx, f.observation(1))
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, mayHaveSubmitted.StateDigest, empty)
	require.NoError(t, err)
	assert.Equal(t, OutcomeAbsentUnresolved, resolution.Outcome)
	_, err = store.PrepareAbandon(ctx, attempt.ID, nil)
	requireErrorMetadata(t, err, ErrContinuity, StageAbandon, ReasonSubmittedUnknown)
	_, err = store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonTransition)

	current := attemptView(f, f.observation(1), false)
	unresolved, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err = store.ResolveAttempt(ctx, attempt.ID, unresolved.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, resolution.Outcome)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, &current)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &current, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	assert.Equal(t, OutcomeCurrent, retired.Outcome)
}

func TestMissingCorruptAndUnsafeCandidateDoNotBlockOutcomeInspection(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			candidate := attemptCandidate(f, 0)
			empty := attemptView(f, f.observation(1), true)
			review := attemptReview()
			attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
			require.NoError(t, store.Close())
			path := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
			switch damage {
			case "missing":
				require.NoError(t, os.Remove(path))
			case "corrupt":
				corrupt := bytes.Clone(candidate.Payload)
				corrupt[len(corrupt)/2] ^= 0x01
				require.NoError(t, os.WriteFile(path, corrupt, 0o600))
			case "symlink":
				sentinel := filepath.Join(directory, "sentinel")
				require.NoError(t, os.WriteFile(sentinel, []byte("unchanged sentinel"), 0o600))
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(sentinel, path))
			}
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			loaded, err := reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
			_, err = reopened.ReadCandidate(ctx, attempt.ID)
			switch damage {
			case "missing":
				requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateMissing)
			case "corrupt":
				requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateCorrupt)
			case "symlink":
				requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateUnsafe)
				sentinelBytes, readErr := os.ReadFile(filepath.Join(directory, "sentinel"))
				require.NoError(t, readErr)
				assert.Equal(t, []byte("unchanged sentinel"), sentinelBytes)
			}
			current := attemptView(f, f.observation(1), false)
			resolution, err := reopened.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
			require.NoError(t, err)
			assert.Equal(t, OutcomeCurrent, resolution.Outcome)
			_, err = reopened.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
			require.Error(t, err)
			abandon, err := reopened.PrepareAbandon(ctx, attempt.ID, &current)
			require.NoError(t, err)
			retired, err := reopened.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &current, abandon.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
			floor, present, err := reopened.Load(ctx)
			require.NoError(t, err)
			assert.False(t, present)
			assert.Equal(t, Floor{}, floor)
		})
	}
}

func TestTerminalAttemptEvidenceSurvivesReopenAndRejectsContradiction(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, resolution.Outcome)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, loaded.Outcome)
	supersededView := attemptView(f, f.observation(2), false)
	resolution, err = reopened.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, supersededView)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSuperseded, resolution.Outcome)
	require.NoError(t, reopened.Close())

	finalReopen, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer finalReopen.Close()
	loaded, err = finalReopen.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSuperseded, loaded.Outcome)
	beforeDigest := loaded.StateDigest
	_, err = finalReopen.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, empty)
	requireErrorMetadata(t, err, ErrContinuity, StageResolve, ReasonCorrupt)
	after, err := finalReopen.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSuperseded, after.Outcome)
	assert.Equal(t, beforeDigest, after.StateDigest)
}

func TestDirectTerminalAbandonmentPersistsOutcomeAndRetirementAcrossReopen(t *testing.T) {
	scenarios := []struct {
		name        string
		resolve     AttemptOutcome
		final       AttemptOutcome
		view        func(*testing.T, fixture) SuppliedRepositoryView
		resolveView func(*testing.T, fixture) SuppliedRepositoryView
	}{
		{"unresolved-to-current", "", OutcomeCurrent, func(_ *testing.T, f fixture) SuppliedRepositoryView { return attemptView(f, f.observation(1), false) }, nil},
		{"unresolved-to-lost-fence", "", OutcomeLostFence, competingGenesisView, nil},
		{"unresolved-to-superseded", "", OutcomeSuperseded, func(_ *testing.T, f fixture) SuppliedRepositoryView { return attemptView(f, f.observation(2), false) }, nil},
		{"absent-to-current", OutcomeAbsentUnresolved, OutcomeCurrent, func(_ *testing.T, f fixture) SuppliedRepositoryView { return attemptView(f, f.observation(1), false) }, func(_ *testing.T, f fixture) SuppliedRepositoryView { return attemptView(f, f.observation(1), true) }},
		{"absent-to-lost-fence", OutcomeAbsentUnresolved, OutcomeLostFence, competingGenesisView, func(_ *testing.T, f fixture) SuppliedRepositoryView { return attemptView(f, f.observation(1), true) }},
		{"current-to-superseded", OutcomeCurrent, OutcomeSuperseded, func(_ *testing.T, f fixture) SuppliedRepositoryView { return attemptView(f, f.observation(2), false) }, func(_ *testing.T, f fixture) SuppliedRepositoryView { return attemptView(f, f.observation(1), false) }},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			if scenario.final == OutcomeSuperseded {
				f.appendRecord(t, 1)
			}
			store, directory := newStore(t, f)
			candidate := attemptCandidate(f, 0)
			empty := attemptView(f, f.observation(1), true)
			review := attemptReview()
			attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
			if scenario.resolve != "" {
				initialView := scenario.resolveView(t, f)
				loaded, err := store.LoadAttempt(ctx, attempt.ID)
				require.NoError(t, err)
				resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, initialView)
				require.NoError(t, err)
				assert.Equal(t, scenario.resolve, resolution.Outcome)
			}
			view := scenario.view(t, f)
			abandon, err := store.PrepareAbandon(ctx, attempt.ID, &view)
			require.NoError(t, err)
			retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &view, abandon.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
			assert.Equal(t, scenario.final, retired.Outcome)
			assertOutcomeRetirementProofs(t, store, attempt.ID, scenario.final)
			var firstConflict FirstConflictEvidence
			if scenario.final == OutcomeLostFence {
				var conflictPresent bool
				firstConflict, conflictPresent, err = store.ReadFirstConflict(ctx, attempt.ID)
				require.NoError(t, err)
				require.True(t, conflictPresent)
				assert.Equal(t, view.Head, firstConflict.Head)
				assert.Equal(t, view.Snapshots[0].Raw, firstConflict.HeadRecord)
			}
			active, present, err := store.ActiveAttempt(ctx)
			require.NoError(t, err)
			assert.False(t, present)
			assert.Equal(t, Attempt{}, active)
			var attemptRefs, reservations int
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attempt.ID[:]).Scan(&attemptRefs))
			require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?", attempt.ID[:]).Scan(&reservations))
			assert.Equal(t, 0, attemptRefs)
			assert.Equal(t, 0, reservations)
			payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
			beforePayload, err := os.ReadFile(payloadPath)
			require.NoError(t, err)
			assert.Equal(t, candidate.Payload, beforePayload)
			require.NoError(t, store.Close())
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			loaded, err := reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, AttemptRetiredAbandoned, loaded.Lifecycle)
			assert.Equal(t, scenario.final, loaded.Outcome)
			assertOutcomeRetirementProofs(t, reopened, attempt.ID, scenario.final)
			if scenario.final == OutcomeLostFence {
				storedConflict, conflictPresent, err := reopened.ReadFirstConflict(ctx, attempt.ID)
				require.NoError(t, err)
				require.True(t, conflictPresent)
				assert.Equal(t, firstConflict.ID, storedConflict.ID)
				assert.Equal(t, firstConflict.Evidence, storedConflict.Evidence)
				assert.Equal(t, firstConflict.Head, storedConflict.Head)
				assert.Equal(t, firstConflict.HeadRecord, storedConflict.HeadRecord)
			}
			payloadPath = filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
			payloadBytes, readErr := os.ReadFile(payloadPath)
			require.NoError(t, readErr)
			assert.Equal(t, candidate.Payload, payloadBytes)
			page, err := reopened.AttemptHistory(ctx, [16]byte{}, 10)
			require.NoError(t, err)
			require.Len(t, page.Attempts, 1)
			assert.Equal(t, scenario.final, page.Attempts[0].Outcome)
		})
	}
}

func competingGenesisView(t *testing.T, f fixture) SuppliedRepositoryView {
	t.Helper()
	candidate := attemptCandidate(f, 0)
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	record.Vault[0] ^= 0x20
	record.PublicationID[0] = 0x42
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: record.Vault, PublicationSeq: 0, SnapshotCID: cid, BlobCID: record.Blob.CID})
	require.NoError(t, err)
	context := f.observation(1).SuppliedContext
	return SuppliedRepositoryView{Origin: f.binding, Scope: ViewScopeWholeRepository, SuppliedContext: context, Head: head, Snapshots: []SnapshotBlock{{Key: f.blocks[0].Key, Raw: raw}}}
}

func assertOutcomeRetirementProofs(t *testing.T, store *Store, id [16]byte, outcome AttemptOutcome) {
	t.Helper()
	rows, err := store.conn.QueryContext(context.Background(), "SELECT role,body FROM attempt_evidence WHERE attempt_id=? ORDER BY role", id[:])
	require.NoError(t, err)
	defer rows.Close()
	proofs := make(map[string]attemptEvidenceWire)
	for rows.Next() {
		var role string
		var body []byte
		require.NoError(t, rows.Scan(&role, &body))
		if role == "first-conflict" {
			continue
		}
		var wire attemptEvidenceWire
		require.NoError(t, strictJSON(body, &wire))
		proofs[role] = wire
	}
	require.NoError(t, rows.Err())
	require.Contains(t, proofs, "outcome")
	require.Contains(t, proofs, "retirement")
	assert.Equal(t, string(outcome), proofs["outcome"].Outcome)
	assert.Equal(t, string(outcome), proofs["retirement"].Outcome)
}

func createAndSubmitGenesis(t *testing.T, store *Store, f fixture, empty SuppliedRepositoryView, candidate CandidateInput, review LocalReviewContext) Attempt {
	t.Helper()
	ctx := context.Background()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, empty, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, empty, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	_, err = store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, empty, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	return attempt
}
