package local_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReconcilePublicHistoryAttemptAndJournalPreservation(t *testing.T) {
	fixture := newPublicationReconcileRollbackFixture(t)
	require.NoError(t, syncengine.Apply(fixture.ctx, fixture.store, publicationReconcileRollbackApplyRequest(fixture, nil)))
	assertPublicationReconcilePreservationFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)
	assertPublicationReconcilePreservationFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcilePreservationFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
	assertPublicationReconcilePreservationFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)

	journal, err := fixture.store.JournalEntriesAll(fixture.ctx)
	require.NoError(t, err)
	require.Len(t, journal, 1)
	applied := clonePublicationReconcilePreservationJournal(journal[0])
	assertPublicationReconcilePreservationJournal(t, fixture, applied)
	backup, err := fixture.store.Payload(applied.BackupRef)
	require.NoError(t, err)
	require.True(t, bytes.Equal(publicationReconcileInitial, backup), "the applied journal must retain the independently expected original bytes")

	candidateBytes := []byte("source A sequence-2 candidate settings\n")
	require.False(t, bytes.Equal(candidateBytes, publicationReconcileInitial), "candidate bytes must differ from the original backup")
	require.False(t, bytes.Equal(candidateBytes, publicationReconcileSuccessor), "candidate bytes must differ from current accepted material")
	require.Len(t, fixture.request.Configuration.Targets, 1)
	portable, err := fixture.request.Configuration.Targets[0].Model()
	require.NoError(t, err)
	candidateEntry := model.Entry{TargetID: publicationReconcileTargetID, File: &model.FileEntry{
		Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular,
		Content: bytes.Clone(candidateBytes), Mode: 0o600,
	}}
	candidateSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: []model.Entry{candidateEntry}}
	require.NoError(t, candidateSnapshot.Validate())
	candidateID := [16]byte{0x25, 0x93}
	candidateMaterial := encodePublicationReconcileMaterial(t, fixture.request.Binding, candidateSnapshot, 2, fixture.homeB.floor.RecordCID, candidateID)
	candidate := publicationstate.CandidateInput{
		SnapshotKey: candidateMaterial.key, SnapshotRecord: bytes.Clone(candidateMaterial.record),
		HeadRecord: bytes.Clone(candidateMaterial.head), Payload: bytes.Clone(candidateMaterial.payload),
	}
	require.False(t, bytes.Equal(candidate.Payload, fixture.request.Payload), "candidate payload must differ from current accepted payload")
	require.False(t, bytes.Equal(candidate.Payload, publicationReconcileInitial), "candidate payload must differ from original backup bytes")

	acceptedHistory := readPublicationReconcilePreservationHistory(t, fixture.homeB.pubStore, fixture.homeB.floor)
	view := publicationReconcilePreservationView(t, fixture.homeB.floor, acceptedHistory)
	review := publicationstate.LocalReviewContext{
		SelectionDigest: [32]byte{0x61}, SelectionRevision: 1,
		ApprovalDigest: [32]byte{0x62}, ApprovalRevision: 1,
	}
	proposal, err := fixture.homeB.pubStore.PrepareAttempt(fixture.ctx, candidate, view, review)
	require.NoError(t, err)
	assert.True(t, proposal.Kind == publicationstate.AttemptSuccessor, "the prepared candidate must be a successor")
	assert.True(t, proposal.CapturedGeneration == fixture.homeB.floor.Generation, "the candidate must capture the accepted generation")
	require.NotNil(t, proposal.CapturedFloor)
	require.True(t, reflect.DeepEqual(fixture.homeB.floor, *proposal.CapturedFloor), "the candidate must capture the exact accepted floor")
	attempt, err := fixture.homeB.pubStore.CreateAttempt(fixture.ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	require.True(t, attempt.ID == candidateID, "the created attempt must retain the independently selected candidate ID")
	assert.True(t, attempt.Kind == publicationstate.AttemptSuccessor, "the created attempt must be a successor")
	assert.True(t, attempt.Lifecycle == publicationstate.AttemptPrepared, "the candidate must remain prepared")
	assert.True(t, attempt.Outcome == publicationstate.OutcomeNotSubmitted, "the candidate must remain not submitted")
	assert.True(t, attempt.CapturedRevision == fixture.homeB.floor.Revision, "the attempt must capture the current revision")
	assert.True(t, attempt.CapturedGeneration == fixture.homeB.floor.Generation, "the attempt must capture the current generation")
	require.NotNil(t, attempt.CapturedFloor)
	require.True(t, reflect.DeepEqual(fixture.homeB.floor, *attempt.CapturedFloor), "the attempt must capture the exact current floor")
	assert.True(t, attempt.Availability == publicationstate.AvailabilityAvailable, "the newly created candidate must be locally available")
	assertPublicationReconcilePreservationCandidate(t, fixture.homeB.pubStore, attempt.ID, candidate)

	beforePreview := snapshotPublicationReconcilePreservationState(t, fixture, attempt.ID, candidate)
	preview, disposition, err := service.PreviewPublicationTarget(fixture.ctx, fixture.request, fixture.base)
	require.NoError(t, err)
	assert.True(t, disposition == service.PublicationPreviewBaseEstablished, "the valid base must remain established")
	require.True(t, preview.Complete, "the valid current preview must be complete")
	require.Len(t, preview.Targets, 1)
	assert.True(t, preview.Targets[0].ID == publicationReconcileTargetID, "the preview must contain only the selected target")
	require.Len(t, preview.Targets[0].Entries, 1)
	entry := preview.Targets[0].Entries[0]
	assert.True(t, entry.Key == (model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}), "the preview must contain only the selected file")
	assert.True(t, entry.DecisionAction == syncengine.ActionUnchanged, "the applied current file must preview unchanged")
	assert.True(t, entry.Reason == syncengine.PreviewReasonEqual, "the applied current file must compare equal")
	assertPublicationReconcilePreservationNoSentinelPreview(t, preview)
	afterPreview := snapshotPublicationReconcilePreservationState(t, fixture, attempt.ID, candidate)
	assert.True(t, reflect.DeepEqual(beforePreview, afterPreview), "a successful service preview must preserve all public logical state and current custody")
	assertPublicationReconcilePreservationFiles(t, fixture)

	beforeRefusal := snapshotPublicationReconcilePreservationState(t, fixture, attempt.ID, candidate)
	independent, err := service.NewPublicationLocalContext(fixture.homeB.paths, nil, nil)
	require.NoError(t, err)
	refusalRequest := fixture.request
	refusalRequest.Local = independent
	refusedPreview, refusedDisposition, refusalErr := service.PreviewPublicationTarget(fixture.ctx, refusalRequest, fixture.base)
	require.ErrorIs(t, refusalErr, service.ErrPublicationReconciliation)
	assert.True(t, reflect.DeepEqual(refusedPreview, syncengine.Preview{}), "an ineligible supplied base must return a zero preview")
	assert.True(t, refusedDisposition == "", "an ineligible supplied base must not return a disposition or fall back")
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, refusalErr, &classified)
	assert.True(t, classified.Stage() == "base-eligibility", "the refusal must occur at base eligibility")
	assert.True(t, classified.Reason() == "selection_mismatch", "the distinct context must refuse the supplied base for selection mismatch")
	afterRefusal := snapshotPublicationReconcilePreservationState(t, fixture, attempt.ID, candidate)
	assert.True(t, reflect.DeepEqual(beforeRefusal, afterRefusal), "a valid-material base refusal must preserve all public logical state and current custody")
	assertPublicationReconcilePreservationFiles(t, fixture)
}

type publicationReconcilePreservationState struct {
	Floor         publicationstate.Floor
	HistoryPages  []publicationstate.HistoryPage
	ActiveAttempt publicationstate.Attempt
	ActivePresent bool
	LoadedAttempt publicationstate.Attempt
	AttemptPages  []publicationstate.AttemptPage
	Candidate     publicationstate.CandidateMaterial
	Journal       []state.JournalEntry
	Backups       []publicationReconcilePreservationBackup
	AppliedBases  []state.BaseRecord
}

type publicationReconcilePreservationBackup struct {
	JournalID string
	Reference string
	Payload   []byte
}

func snapshotPublicationReconcilePreservationState(t *testing.T, fixture *publicationReconcileRollbackFixture, attemptID [16]byte, expected publicationstate.CandidateInput) publicationReconcilePreservationState {
	t.Helper()
	floor, present, err := fixture.homeB.pubStore.Load(fixture.ctx)
	require.NoError(t, err)
	require.True(t, present, "the accepted floor must remain present")
	require.True(t, reflect.DeepEqual(fixture.homeB.floor, floor), "the public floor must equal the independently expected fixture floor")
	historyPages := readPublicationReconcilePreservationHistory(t, fixture.homeB.pubStore, floor)

	active, activePresent, err := fixture.homeB.pubStore.ActiveAttempt(fixture.ctx)
	require.NoError(t, err)
	require.True(t, activePresent, "the prepared attempt must remain active")
	require.True(t, active.ID == attemptID, "the current active attempt ID must match")
	expectedSnapshot, err := publication.DecodeSnapshot(expected.SnapshotRecord)
	require.NoError(t, err)
	expectedSnapshotCID, err := publication.RecordCID(expected.SnapshotRecord)
	require.NoError(t, err)
	expectedHeadCID, err := publication.RecordCID(expected.HeadRecord)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.AttemptSuccessor, active.Kind)
	assert.Equal(t, uint64(2), active.Sequence)
	assert.Empty(t, active.Blocked)
	assert.Equal(t, expected.SnapshotKey, active.SnapshotKey)
	assert.True(t, bytes.Equal(expectedSnapshotCID, active.SnapshotRecordCID), "the active attempt must retain the expected snapshot-record CID")
	assert.True(t, bytes.Equal(expectedHeadCID, active.HeadRecordCID), "the active attempt must retain the expected head-record CID")
	assert.True(t, bytes.Equal(expectedSnapshot.Blob.CID, active.BlobCID), "the active attempt must retain the expected blob CID")
	assert.Equal(t, expectedSnapshot.Blob.Size, active.BlobSize)
	require.NotNil(t, active.CapturedFloor)
	assert.True(t, reflect.DeepEqual(fixture.homeB.floor, *active.CapturedFloor), "the active attempt must capture the exact fixture floor")
	assert.Equal(t, fixture.homeB.floor.Revision, active.CapturedRevision)
	assert.Equal(t, fixture.homeB.floor.Generation, active.CapturedGeneration)
	loaded, err := fixture.homeB.pubStore.LoadAttempt(fixture.ctx, active.ID)
	require.NoError(t, err)
	require.True(t, loaded.ID == attemptID, "the current by-ID attempt must match")
	require.True(t, loaded.Lifecycle == publicationstate.AttemptPrepared, "the attempt must remain prepared")
	require.True(t, loaded.Outcome == publicationstate.OutcomeNotSubmitted, "the attempt must remain not submitted")
	require.True(t, reflect.DeepEqual(active, loaded), "active and by-ID attempt reads must preserve the same complete attempt")
	attemptPages := readPublicationReconcilePreservationAttemptHistory(t, fixture, attemptID)
	require.Len(t, attemptPages, 1)
	require.Len(t, attemptPages[0].Attempts, 1)
	require.True(t, reflect.DeepEqual(active, attemptPages[0].Attempts[0]), "AttemptHistory must preserve the independently checked active attempt")
	require.Empty(t, attemptPages[0].Evidence, "a prepared not-submitted attempt must have no transition evidence")
	candidate := readPublicationReconcilePreservationCandidate(t, fixture.homeB.pubStore, active.ID, expected)

	journal, err := fixture.store.JournalEntriesAll(fixture.ctx)
	require.NoError(t, err)
	require.Len(t, journal, 1)
	assertPublicationReconcilePreservationJournal(t, fixture, journal[0])
	backups := make([]publicationReconcilePreservationBackup, 0, len(journal))
	for _, current := range journal {
		if current.BackupRef == "" {
			continue
		}
		payload, err := fixture.store.Payload(current.BackupRef)
		require.NoError(t, err)
		backups = append(backups, publicationReconcilePreservationBackup{
			JournalID: current.ID, Reference: current.BackupRef, Payload: bytes.Clone(payload),
		})
	}
	require.Len(t, backups, 1)
	bases, err := fixture.store.AppliedBase(fixture.ctx, publicationReconcileTargetID)
	require.NoError(t, err)
	require.Empty(t, bases, "the test journal must not create or adopt a v1 applied base")

	return publicationReconcilePreservationState{
		Floor: clonePublicationReconcilePreservationFloor(floor), HistoryPages: clonePublicationReconcilePreservationHistoryPages(historyPages),
		ActiveAttempt: clonePublicationReconcilePreservationAttempt(active), ActivePresent: activePresent,
		LoadedAttempt: clonePublicationReconcilePreservationAttempt(loaded), AttemptPages: clonePublicationReconcilePreservationAttemptPages(attemptPages),
		Candidate: clonePublicationReconcilePreservationCandidate(candidate), Journal: clonePublicationReconcilePreservationJournalEntries(journal),
		Backups: clonePublicationReconcilePreservationBackups(backups), AppliedBases: append([]state.BaseRecord(nil), bases...),
	}
}

func readPublicationReconcilePreservationHistory(t *testing.T, store *publicationstate.Store, expectedFloor publicationstate.Floor) []publicationstate.HistoryPage {
	t.Helper()
	const expectedEvents = 2
	require.True(t, expectedFloor.Revision == expectedEvents, "the bounded fixture must have exactly two accepted events")
	pages := make([]publicationstate.HistoryPage, 0, expectedEvents)
	afterRevision := uint64(0)
	for len(pages) < expectedEvents {
		beforeRevision := afterRevision
		page, err := store.History(context.Background(), afterRevision, 1)
		require.NoError(t, err)
		require.Len(t, page.Events, 1, "each bounded history page must contain the next event")
		event := page.Events[0]
		require.True(t, event.Revision == beforeRevision+1, "accepted history revisions must be contiguous")
		require.True(t, page.NextRevision == event.Revision && page.NextRevision > beforeRevision, "history pagination must advance by the returned revision")
		require.True(t, page.HasMore == (len(pages)+1 < expectedEvents), "history pagination must report the exact remaining page")
		pages = append(pages, clonePublicationReconcilePreservationHistoryPage(page))
		afterRevision = page.NextRevision
	}
	require.True(t, afterRevision == expectedFloor.Revision, "history must end exactly at the accepted floor revision")
	assertPublicationReconcilePreservationHistoryEvidence(t, pages, expectedFloor)
	return pages
}

func assertPublicationReconcilePreservationHistoryEvidence(t *testing.T, pages []publicationstate.HistoryPage, expectedFloor publicationstate.Floor) {
	t.Helper()
	require.Len(t, pages, 2)
	require.Len(t, pages[0].Events, 1)
	require.Len(t, pages[1].Events, 1)
	require.Nil(t, pages[0].Events[0].OldFloor)
	require.NotNil(t, pages[1].Events[0].OldFloor)
	require.True(t, reflect.DeepEqual(pages[0].Events[0].NewFloor, *pages[1].Events[0].OldFloor), "the successor event must join the complete prior floor")
	distinct := make(map[string]publicationstate.RecordEvidence)
	for pageIndex, page := range pages {
		require.Len(t, page.Events, 1)
		for _, event := range page.Events {
			for _, reference := range event.Trace {
				found := false
				for _, evidence := range page.Records {
					if evidence.Reference.Key == reference.Key && evidence.Reference.Sequence == reference.Sequence && bytes.Equal(evidence.Reference.CID, reference.CID) {
						cid, err := publication.RecordCID(evidence.Raw)
						require.NoError(t, err)
						require.True(t, bytes.Equal(cid, reference.CID), "accepted raw record bytes must match their history reference")
						found = true
					}
				}
				require.True(t, found, "each event reference must have its raw record in the same public history page")
			}
			for _, evidence := range page.Records {
				key := string(evidence.Reference.CID)
				if prior, ok := distinct[key]; ok {
					require.True(t, prior.Reference.Key == evidence.Reference.Key && prior.Reference.Sequence == evidence.Reference.Sequence, "repeated history evidence must retain the same key and sequence")
					require.True(t, bytes.Equal(prior.Raw, evidence.Raw), "repeated history evidence must retain identical raw record bytes")
					continue
				}
				distinct[key] = publicationstate.RecordEvidence{
					Reference: publicationstate.RecordReference{Key: evidence.Reference.Key, CID: bytes.Clone(evidence.Reference.CID), Sequence: evidence.Reference.Sequence},
					Raw:       bytes.Clone(evidence.Raw),
				}
			}
		}
		if pageIndex == 1 {
			require.True(t, reflect.DeepEqual(page.Events[0].NewFloor, expectedFloor), "the final accepted event must join the complete current floor")
		}
	}
	require.Len(t, distinct, 2, "the accepted history must retain exactly the two fixture snapshot records")
	sequences := make([]uint64, 0, len(distinct))
	for _, evidence := range distinct {
		sequence, err := publication.ParseSequenceKey(evidence.Reference.Key)
		require.NoError(t, err)
		require.True(t, sequence == evidence.Reference.Sequence, "accepted history keys must match their sequence")
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
	require.True(t, reflect.DeepEqual(sequences, []uint64{0, 1}), "accepted history must retain the exact genesis and successor records")
}

func publicationReconcilePreservationView(t *testing.T, floor publicationstate.Floor, pages []publicationstate.HistoryPage) publicationstate.SuppliedRepositoryView {
	t.Helper()
	require.True(t, floor.Revision == 2, "the supplied view must be built from the two-event accepted history")
	byCID := make(map[string]publicationstate.RecordEvidence)
	for _, page := range pages {
		for _, evidence := range page.Records {
			key := string(evidence.Reference.CID)
			if prior, ok := byCID[key]; ok {
				require.True(t, prior.Reference.Key == evidence.Reference.Key && prior.Reference.Sequence == evidence.Reference.Sequence, "deduplicated evidence must have matching public references")
				require.True(t, bytes.Equal(prior.Raw, evidence.Raw), "deduplicated evidence must have identical raw records")
				continue
			}
			byCID[key] = publicationstate.RecordEvidence{
				Reference: publicationstate.RecordReference{Key: evidence.Reference.Key, CID: bytes.Clone(evidence.Reference.CID), Sequence: evidence.Reference.Sequence},
				Raw:       bytes.Clone(evidence.Raw),
			}
		}
	}
	records := make([]publicationstate.RecordEvidence, 0, len(byCID))
	for _, evidence := range byCID {
		records = append(records, evidence)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Reference.Sequence < records[j].Reference.Sequence })
	require.Len(t, records, 2)
	snapshots := make([]publicationstate.SnapshotBlock, 0, len(records))
	for index, evidence := range records {
		require.True(t, evidence.Reference.Sequence == uint64(index), "the supplied view must be ordered by actual accepted sequence")
		key, err := publication.SequenceKey(uint64(index))
		require.NoError(t, err)
		require.True(t, evidence.Reference.Key == key, "the supplied view key must match its accepted sequence")
		snapshots = append(snapshots, publicationstate.SnapshotBlock{Key: key, Raw: bytes.Clone(evidence.Raw)})
	}
	last := records[len(records)-1]
	require.True(t, last.Reference.Key == floor.SnapshotKey && bytes.Equal(last.Reference.CID, floor.RecordCID), "the supplied view must end at the exact accepted predecessor")
	view := publicationstate.SuppliedRepositoryView{
		Origin: floor.Binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: clonePublicationReconcilePreservationContext(floor.SuppliedContext),
		Head:            bytes.Clone(floor.Head), Snapshots: snapshots,
	}
	require.True(t, view.Origin == floor.Binding, "the supplied view binding must match the accepted floor")
	require.True(t, reflect.DeepEqual(view.SuppliedContext, floor.SuppliedContext), "the supplied view context must match the accepted floor")
	require.True(t, bytes.Equal(view.Head, floor.Head), "the supplied view head must match the accepted floor")
	return view
}

func readPublicationReconcilePreservationAttemptHistory(t *testing.T, fixture *publicationReconcileRollbackFixture, attemptID [16]byte) []publicationstate.AttemptPage {
	t.Helper()
	pages := make([]publicationstate.AttemptPage, 0, 1)
	var cursor [16]byte
	page, err := fixture.homeB.pubStore.AttemptHistory(fixture.ctx, cursor, 1)
	require.NoError(t, err)
	require.Len(t, page.Attempts, 1, "the fixture must retain exactly one attempt")
	require.True(t, page.Attempts[0].ID == attemptID, "the complete attempt page must contain the active attempt")
	require.True(t, page.NextID == attemptID, "attempt pagination must identify its returned cursor")
	require.False(t, page.HasMore, "the single attempt must terminate bounded pagination")
	pages = append(pages, clonePublicationReconcilePreservationAttemptPage(page))
	return pages
}

func assertPublicationReconcilePreservationCandidate(t *testing.T, store *publicationstate.Store, attemptID [16]byte, expected publicationstate.CandidateInput) {
	t.Helper()
	material, err := store.ReadCandidate(context.Background(), attemptID)
	require.NoError(t, err)
	assert.True(t, material.AttemptID == attemptID, "candidate custody must belong to the current attempt ID")
	assert.True(t, material.SnapshotKey == expected.SnapshotKey, "candidate custody must retain the exact key")
	assert.True(t, bytes.Equal(material.SnapshotRecord, expected.SnapshotRecord), "candidate custody must retain the exact snapshot record")
	assert.True(t, bytes.Equal(material.HeadRecord, expected.HeadRecord), "candidate custody must retain the exact head record")
	assert.True(t, bytes.Equal(material.Payload, expected.Payload), "candidate custody must retain the exact distinct payload")
	record, err := publication.DecodeSnapshot(expected.SnapshotRecord)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(material.Blob.CID, record.Blob.CID), "candidate custody must retain the exact blob CID")
	assert.True(t, material.Blob.Size == record.Blob.Size, "candidate custody must retain the exact blob size")
}

func readPublicationReconcilePreservationCandidate(t *testing.T, store *publicationstate.Store, attemptID [16]byte, expected publicationstate.CandidateInput) publicationstate.CandidateMaterial {
	t.Helper()
	material, err := store.ReadCandidate(context.Background(), attemptID)
	require.NoError(t, err)
	assert.True(t, material.AttemptID == attemptID, "the fresh candidate read must use the current attempt ID")
	assert.True(t, material.SnapshotKey == expected.SnapshotKey, "the fresh candidate read must retain the expected key")
	assert.True(t, bytes.Equal(material.SnapshotRecord, expected.SnapshotRecord), "the fresh candidate read must retain the exact snapshot record")
	assert.True(t, bytes.Equal(material.HeadRecord, expected.HeadRecord), "the fresh candidate read must retain the exact head record")
	assert.True(t, bytes.Equal(material.Payload, expected.Payload), "the fresh candidate read must retain the exact candidate payload")
	record, err := publication.DecodeSnapshot(expected.SnapshotRecord)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(material.Blob.CID, record.Blob.CID), "the fresh candidate read must retain the expected blob CID")
	assert.True(t, material.Blob.Size == record.Blob.Size, "the fresh candidate read must retain the expected blob size")
	return clonePublicationReconcilePreservationCandidate(material)
}

func assertPublicationReconcilePreservationJournal(t *testing.T, fixture *publicationReconcileRollbackFixture, entry state.JournalEntry) {
	t.Helper()
	expectedIdentity := model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}
	expectedPreimage := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", publicationReconcileInitial)
	expectedPostimage := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", publicationReconcileSuccessor)
	assert.True(t, entry.ID != "", "the real Apply must create a journal ID")
	assert.True(t, entry.Operation == "replace", "the journal must describe a file replacement")
	assert.True(t, entry.State == "applied" && entry.Stage == state.JournalStageVerified, "the journal must record a verified Apply")
	assert.True(t, entry.Identity == expectedIdentity, "the journal must identify the expected synthetic file")
	assert.True(t, entry.RootPath == filepath.Clean(fixture.homeB.root), "the journal must bind the expected private B root")
	assert.True(t, entry.DestinationPath == "settings.ini", "the journal must bind the expected destination")
	assert.True(t, reflect.DeepEqual(entry.Preimage, expectedPreimage), "the journal must retain the independently expected original preimage")
	assert.True(t, reflect.DeepEqual(entry.Postimage, expectedPostimage), "the journal must retain the independently expected successor postimage")
	assert.Nil(t, entry.Retention, "the test journal must not carry a fabricated retention binding")
	assert.True(t, entry.BackupRef != "", "the verified journal must retain its current backup reference")
	backup, err := fixture.store.Payload(entry.BackupRef)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(backup, publicationReconcileInitial), "the current backup reference must read the exact original bytes")
	assert.True(t, int64(len(backup)) == entry.Preimage.Size, "the original backup size must match its preimage")
}

func assertPublicationReconcilePreservationNoSentinelPreview(t *testing.T, preview syncengine.Preview) {
	t.Helper()
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			assert.True(t, entry.Key.FilePath != "machine-only", "the preview must not contain the synthetic excluded sentinel")
		}
	}
}

func assertPublicationReconcilePreservationFiles(t *testing.T, fixture *publicationReconcileRollbackFixture) {
	t.Helper()
	assertPublicationReconcilePreservationFile(t, fixture.destination, publicationReconcileSuccessor, 0o600)
	assertPublicationReconcilePreservationFile(t, filepath.Join(fixture.homeA.selected, "settings.ini"), publicationReconcileSuccessor, 0o600)
	assertPublicationReconcilePreservationFile(t, fixture.homeA.sentinel, publicationReconcileSentinelA, 0o640)
	assertPublicationReconcilePreservationFile(t, fixture.homeB.sentinel, publicationReconcileSentinelB, 0o640)
}

func assertPublicationReconcilePreservationFile(t *testing.T, path string, expected []byte, mode os.FileMode) {
	t.Helper()
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(actual, expected), "the private synthetic file must retain independently expected bytes")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, info.Mode().Perm() == mode.Perm(), "the private synthetic file must retain its expected mode")
}

func clonePublicationReconcilePreservationFloor(floor publicationstate.Floor) publicationstate.Floor {
	floor.AnchorCID = bytes.Clone(floor.AnchorCID)
	floor.SuppliedContext = clonePublicationReconcilePreservationContext(floor.SuppliedContext)
	floor.Head = bytes.Clone(floor.Head)
	floor.RecordCID = bytes.Clone(floor.RecordCID)
	floor.BlobCID = bytes.Clone(floor.BlobCID)
	return floor
}

func clonePublicationReconcilePreservationContext(supplied publicationstate.SuppliedContext) publicationstate.SuppliedContext {
	supplied.RepositoryDigest = bytes.Clone(supplied.RepositoryDigest)
	if supplied.Policy != nil {
		policy := *supplied.Policy
		policy.Identity = bytes.Clone(policy.Identity)
		supplied.Policy = &policy
	}
	return supplied
}

func clonePublicationReconcilePreservationHistoryPages(pages []publicationstate.HistoryPage) []publicationstate.HistoryPage {
	result := make([]publicationstate.HistoryPage, len(pages))
	for index, page := range pages {
		result[index] = clonePublicationReconcilePreservationHistoryPage(page)
	}
	return result
}

func clonePublicationReconcilePreservationHistoryPage(page publicationstate.HistoryPage) publicationstate.HistoryPage {
	result := page
	result.Events = make([]publicationstate.HistoryEvent, len(page.Events))
	for index, event := range page.Events {
		cloned := event
		cloned.OldFloor = nil
		if event.OldFloor != nil {
			oldFloor := clonePublicationReconcilePreservationFloor(*event.OldFloor)
			cloned.OldFloor = &oldFloor
		}
		cloned.NewFloor = clonePublicationReconcilePreservationFloor(event.NewFloor)
		cloned.Trace = clonePublicationReconcilePreservationReferences(event.Trace)
		result.Events[index] = cloned
	}
	result.Records = make([]publicationstate.RecordEvidence, len(page.Records))
	for index, evidence := range page.Records {
		result.Records[index] = publicationstate.RecordEvidence{
			Reference: clonePublicationReconcilePreservationReference(evidence.Reference), Raw: bytes.Clone(evidence.Raw),
		}
	}
	return result
}

func clonePublicationReconcilePreservationReferences(references []publicationstate.RecordReference) []publicationstate.RecordReference {
	result := make([]publicationstate.RecordReference, len(references))
	for index, reference := range references {
		result[index] = clonePublicationReconcilePreservationReference(reference)
	}
	return result
}

func clonePublicationReconcilePreservationReference(reference publicationstate.RecordReference) publicationstate.RecordReference {
	reference.CID = bytes.Clone(reference.CID)
	return reference
}

func clonePublicationReconcilePreservationAttempt(attempt publicationstate.Attempt) publicationstate.Attempt {
	attempt.SnapshotRecordCID = bytes.Clone(attempt.SnapshotRecordCID)
	attempt.HeadRecordCID = bytes.Clone(attempt.HeadRecordCID)
	attempt.BlobCID = bytes.Clone(attempt.BlobCID)
	if attempt.CapturedFloor != nil {
		floor := clonePublicationReconcilePreservationFloor(*attempt.CapturedFloor)
		attempt.CapturedFloor = &floor
	}
	return attempt
}

func clonePublicationReconcilePreservationAttemptPage(page publicationstate.AttemptPage) publicationstate.AttemptPage {
	result := page
	result.Attempts = make([]publicationstate.Attempt, len(page.Attempts))
	for index, attempt := range page.Attempts {
		result.Attempts[index] = clonePublicationReconcilePreservationAttempt(attempt)
	}
	result.Evidence = make([]publicationstate.AttemptEvidence, len(page.Evidence))
	for index, evidence := range page.Evidence {
		result.Evidence[index] = publicationstate.AttemptEvidence{AttemptID: evidence.AttemptID, Role: evidence.Role, Evidence: bytes.Clone(evidence.Evidence)}
	}
	return result
}

func clonePublicationReconcilePreservationAttemptPages(pages []publicationstate.AttemptPage) []publicationstate.AttemptPage {
	result := make([]publicationstate.AttemptPage, len(pages))
	for index, page := range pages {
		result[index] = clonePublicationReconcilePreservationAttemptPage(page)
	}
	return result
}

func clonePublicationReconcilePreservationCandidate(candidate publicationstate.CandidateMaterial) publicationstate.CandidateMaterial {
	candidate.SnapshotRecord = bytes.Clone(candidate.SnapshotRecord)
	candidate.HeadRecord = bytes.Clone(candidate.HeadRecord)
	candidate.Payload = bytes.Clone(candidate.Payload)
	candidate.Blob.CID = bytes.Clone(candidate.Blob.CID)
	return candidate
}

func clonePublicationReconcilePreservationJournal(entry state.JournalEntry) state.JournalEntry {
	if entry.Retention != nil {
		retention := *entry.Retention
		retention.SnapshotCID = bytes.Clone(retention.SnapshotCID)
		retention.ControlCID = bytes.Clone(retention.ControlCID)
		entry.Retention = &retention
	}
	return entry
}

func clonePublicationReconcilePreservationJournalEntries(entries []state.JournalEntry) []state.JournalEntry {
	result := make([]state.JournalEntry, len(entries))
	for index, entry := range entries {
		result[index] = clonePublicationReconcilePreservationJournal(entry)
	}
	return result
}

func clonePublicationReconcilePreservationBackups(backups []publicationReconcilePreservationBackup) []publicationReconcilePreservationBackup {
	result := make([]publicationReconcilePreservationBackup, len(backups))
	for index, backup := range backups {
		result[index] = publicationReconcilePreservationBackup{JournalID: backup.JournalID, Reference: backup.Reference, Payload: bytes.Clone(backup.Payload)}
	}
	return result
}
