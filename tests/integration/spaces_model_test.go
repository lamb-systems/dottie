package integration

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	spacesResolutionKeepLocal  = "keep-local-overwrite"
	spacesResolutionTakeRemote = "take-remote"
	spacesResolutionUnresolved = "unresolved"
)

type spacesModelAssumption struct {
	name        string
	description string
}

var spacesModelAssumptions = []spacesModelAssumption{
	{name: "occupied-sequence-create-rejects-whole-batch", description: "an occupied immutable sequence key rejects the snapshot-and-head batch, including identical replays"},
	{name: "rejected-batch-is-atomic", description: "a rejected batch cannot leave a newly-created snapshot or advance the head"},
	{name: "head-binds-record-and-blob", description: "head snapshot record CID, record blob CID, and payload bytes identify one exact candidate"},
	{name: "mutable-policy-revision-is-checked-at-commit", description: "a mutable owner-only policy revision must still match at commit"},
	{name: "immutable-owner-policy-refuses-broadening", description: "an immutable owner-only policy refuses a broadening transition"},
	{name: "conflict-is-reported-and-candidate-retained", description: "a losing local candidate remains recoverable and its conflict is reportable"},
	{name: "resolution-is-one-of-three-recorded-outcomes", description: "conflicts are recorded as keep-local-overwrite, take-remote, or unresolved"},
}

type spacesCandidate struct {
	id                       string
	vault                    string
	sequence                 uint64
	parentCID                string
	blobCID                  string
	recordCID                string
	payload                  []byte
	policyRevision           uint64
	committedPolicyRevision  uint64
	committedPolicyOwnerOnly bool
}

type spacesHead struct {
	vault     string
	sequence  uint64
	snapshot  string
	blob      string
	candidate string
}

type spacesConflictPosition struct {
	vault    string
	sequence int64
	record   string
}

type spacesConflictReport struct {
	local  spacesConflictPosition
	remote spacesConflictPosition
}

type spacesPolicyMode string

const (
	spacesMutablePolicy   spacesPolicyMode = "mutable-revision"
	spacesImmutablePolicy spacesPolicyMode = "immutable-owner-only"
)

type spacesModel struct {
	rejectOccupiedKey      bool
	atomicRejectedBatch    bool
	bindHeadRecord         bool
	checkPolicyRevision    bool
	forbidPolicyBroadening bool
	reportConflict         bool
	retainConflict         bool
	recordResolution       bool

	records              map[uint64]spacesCandidate
	blobs                map[string][]byte
	pending              map[string]spacesCandidate
	committed            map[string]spacesCandidate
	conflicts            map[string]bool
	reported             map[string]bool
	reports              map[string]spacesConflictReport
	resolutions          map[string]string
	conflictGeneration   map[string]int
	policyBlocked        map[string]bool
	resolutionRemoteHead map[string]string
	resolutionOverwrite  map[string]string

	head                *spacesHead
	highestCommitted    uint64
	hasCommitted        bool
	policyMode          spacesPolicyMode
	policyRevision      uint64
	policyOwnerOnly     bool
	publicationOutcomes map[string]string
}

func newSpacesModel() *spacesModel {
	return &spacesModel{
		rejectOccupiedKey:      true,
		atomicRejectedBatch:    true,
		bindHeadRecord:         true,
		checkPolicyRevision:    true,
		forbidPolicyBroadening: true,
		reportConflict:         true,
		retainConflict:         true,
		recordResolution:       true,
		records:                make(map[uint64]spacesCandidate),
		blobs:                  make(map[string][]byte),
		pending:                make(map[string]spacesCandidate),
		committed:              make(map[string]spacesCandidate),
		conflicts:              make(map[string]bool),
		reported:               make(map[string]bool),
		reports:                make(map[string]spacesConflictReport),
		resolutions:            make(map[string]string),
		conflictGeneration:     make(map[string]int),
		policyBlocked:          make(map[string]bool),
		resolutionRemoteHead:   make(map[string]string),
		resolutionOverwrite:    make(map[string]string),
		policyRevision:         1,
		policyOwnerOnly:        true,
		publicationOutcomes:    make(map[string]string),
	}
}

func spacesBlobCID(payload []byte) string {
	digest := sha256.Sum256(payload)
	return fmt.Sprintf("blob-sha256:%x", digest[:])
}

func spacesSnapshotRecordCID(vault string, sequence uint64, parentCID, blobCID string, publicationID string) string {
	encoded := fmt.Sprintf("snapshot-v2\x00%s\x00%d\x00%s\x00%s\x00%s", vault, sequence, parentCID, blobCID, publicationID)
	digest := sha256.Sum256([]byte(encoded))
	return fmt.Sprintf("record-sha256:%x", digest[:])
}

func spacesPrepareCandidate(model *spacesModel, id, vault string, payload []byte) spacesCandidate {
	candidate := spacesCandidate{
		id:             id,
		vault:          vault,
		blobCID:        spacesBlobCID(payload),
		payload:        append([]byte(nil), payload...),
		policyRevision: model.policyRevision,
	}
	if model.head != nil {
		candidate.sequence = model.head.sequence + 1
		candidate.parentCID = model.head.snapshot
	}
	candidate.recordCID = spacesSnapshotRecordCID(candidate.vault, candidate.sequence, candidate.parentCID, candidate.blobCID, candidate.id)
	model.pending[candidate.id] = candidate
	return candidate
}

func (model *spacesModel) recordFailure(candidate spacesCandidate, conflict bool) {
	if !conflict {
		return
	}
	model.conflicts[candidate.id] = true
	model.conflictGeneration[candidate.id]++
	if model.reportConflict {
		remote := spacesConflictPosition{vault: "none", sequence: -1, record: "no-head"}
		if model.head != nil {
			remote = spacesConflictPosition{vault: model.head.vault, sequence: int64(model.head.sequence), record: model.head.snapshot}
		}
		model.reported[candidate.id] = true
		model.reports[candidate.id] = spacesConflictReport{
			local:  spacesConflictPosition{vault: candidate.vault, sequence: int64(candidate.sequence), record: candidate.recordCID},
			remote: remote,
		}
	}
	if !model.retainConflict {
		delete(model.pending, candidate.id)
	}
	if model.recordResolution {
		model.resolutions[candidate.id] = spacesResolutionUnresolved
	}
}

func (model *spacesModel) commit(candidate spacesCandidate, failBetweenSnapshotAndHead bool) string {
	policyValid := model.policyOwnerOnly && candidate.policyRevision == model.policyRevision
	if !policyValid && model.checkPolicyRevision {
		model.policyBlocked[candidate.id] = true
		model.publicationOutcomes[candidate.id] = "policy-blocked"
		return "policy-blocked"
	}
	if existing, occupied := model.records[candidate.sequence]; occupied && model.rejectOccupiedKey {
		if existing.recordCID == candidate.recordCID {
			model.publicationOutcomes[candidate.id] = "committed-but-superseded"
			delete(model.pending, candidate.id)
			return "superseded"
		}
		model.recordFailure(candidate, true)
		return "conflict"
	}
	if failBetweenSnapshotAndHead {
		if model.atomicRejectedBatch {
			model.recordFailure(candidate, false)
			return "rejected-atomic"
		}
		model.records[candidate.sequence] = candidate
		model.blobs[candidate.blobCID] = append([]byte(nil), candidate.payload...)
		model.recordFailure(candidate, false)
		return "rejected-partial"
	}
	candidate.committedPolicyRevision = model.policyRevision
	candidate.committedPolicyOwnerOnly = model.policyOwnerOnly
	model.records[candidate.sequence] = candidate
	model.blobs[candidate.blobCID] = append([]byte(nil), candidate.payload...)
	snapshotCID := candidate.recordCID
	if !model.bindHeadRecord {
		snapshotCID = candidate.blobCID
	}
	model.head = &spacesHead{
		vault:     candidate.vault,
		sequence:  candidate.sequence,
		snapshot:  snapshotCID,
		blob:      candidate.blobCID,
		candidate: candidate.id,
	}
	model.committed[candidate.id] = candidate
	model.publicationOutcomes[candidate.id] = "committed"
	if !model.hasCommitted || candidate.sequence > model.highestCommitted {
		model.highestCommitted = candidate.sequence
		model.hasCommitted = true
	}
	delete(model.pending, candidate.id)
	return "committed"
}

func (model *spacesModel) broadenPolicy() bool {
	if model.policyMode == spacesImmutablePolicy && model.forbidPolicyBroadening {
		return false
	}
	if model.policyMode == spacesImmutablePolicy {
	}
	model.policyRevision++
	model.policyOwnerOnly = false
	return true
}

func (model *spacesModel) currentConflictPosition() spacesConflictPosition {
	if model.head == nil {
		return spacesConflictPosition{vault: "none", sequence: -1, record: "no-head"}
	}
	return spacesConflictPosition{vault: model.head.vault, sequence: int64(model.head.sequence), record: model.head.snapshot}
}

func (model *spacesModel) refreshConflictIfHeadMoved(candidateID string) bool {
	report, ok := model.reports[candidateID]
	if !ok {
		return true
	}
	current := model.currentConflictPosition()
	if report.remote == current {
		return false
	}
	report.remote = current
	model.reports[candidateID] = report
	model.reported[candidateID] = true
	model.conflictGeneration[candidateID]++
	if model.recordResolution {
		model.resolutions[candidateID] = spacesResolutionUnresolved
	}
	return true
}

func (model *spacesModel) resolve(candidateID, outcome string) bool {
	candidate, ok := model.pending[candidateID]
	if !ok || !model.conflicts[candidateID] || model.policyBlocked[candidateID] {
		return false
	}
	if outcome != spacesResolutionKeepLocal && outcome != spacesResolutionTakeRemote && outcome != spacesResolutionUnresolved {
		return false
	}
	if outcome == spacesResolutionUnresolved {
		if model.recordResolution {
			model.resolutions[candidateID] = outcome
		}
		return true
	}
	if model.refreshConflictIfHeadMoved(candidateID) {
		return false
	}
	report := model.reports[candidateID]
	if report.remote.sequence < 0 {
		return false
	}
	model.resolutionRemoteHead[candidateID] = report.remote.record
	if outcome == spacesResolutionTakeRemote {
		if model.recordResolution {
			model.resolutions[candidateID] = outcome
		}
		delete(model.pending, candidateID)
		return true
	}
	overwrite := spacesCandidate{
		id:             candidateID + "-keep-local-overwrite",
		vault:          candidate.vault,
		sequence:       uint64(report.remote.sequence + 1),
		parentCID:      report.remote.record,
		blobCID:        candidate.blobCID,
		payload:        append([]byte(nil), candidate.payload...),
		policyRevision: model.policyRevision,
	}
	overwrite.recordCID = spacesSnapshotRecordCID(overwrite.vault, overwrite.sequence, overwrite.parentCID, overwrite.blobCID, overwrite.id)
	model.pending[overwrite.id] = overwrite
	if model.refreshConflictIfHeadMoved(candidateID) || model.commit(overwrite, false) != "committed" {
		delete(model.pending, overwrite.id)
		return false
	}
	if model.recordResolution {
		model.resolutions[candidateID] = outcome
	}
	model.resolutionOverwrite[candidateID] = overwrite.id
	delete(model.pending, candidateID)
	return true
}

func spacesInvariantViolations(model *spacesModel) []string {
	violations := make(map[string]bool)
	committed := make([]spacesCandidate, 0, len(model.committed))
	for _, candidate := range model.committed {
		committed = append(committed, candidate)
	}
	for left := 0; left < len(committed); left++ {
		for right := left + 1; right < len(committed); right++ {
			if committed[left].sequence == committed[right].sequence && committed[left].parentCID == committed[right].parentCID && committed[left].id != committed[right].id {
				violations["I1 distinct-candidate exclusion"] = true
			}
		}
	}
	if model.head != nil {
		record, ok := model.records[model.head.sequence]
		if !ok {
			violations["I2 exact binding"] = true
			violations["I4 no partial publication"] = true
		} else {
			payload, blobExists := model.blobs[record.blobCID]
			if model.head.snapshot != record.recordCID || model.head.blob != record.blobCID || model.head.vault != record.vault || model.head.sequence != record.sequence || !blobExists || spacesBlobCID(payload) != record.blobCID {
				violations["I2 exact binding"] = true
			}
			if model.head.candidate != record.id {
				violations["I2 exact binding"] = true
			}
		}
		if model.hasCommitted && model.head.sequence < model.highestCommitted {
			violations["I3 no rewind"] = true
		}
	}
	for _, candidate := range model.records {
		if _, committed := model.committed[candidate.id]; !committed {
			violations["I4 no partial publication"] = true
		}
	}
	if model.head != nil {
		if record, ok := model.records[model.head.sequence]; !ok || record.recordCID != model.head.snapshot {
			violations["I4 no partial publication"] = true
		}
	}
	for candidateID := range model.conflicts {
		report, hasReport := model.reports[candidateID]
		if !model.reported[candidateID] || !hasReport || report.local.record == "" || report.remote.record == "" {
			violations["I5 no silent loss"] = true
		}
		if _, retained := model.pending[candidateID]; !retained {
			if model.resolutions[candidateID] != spacesResolutionTakeRemote && model.resolutions[candidateID] != spacesResolutionKeepLocal {
				violations["I5 no silent loss"] = true
			}
		}
		outcome := model.resolutions[candidateID]
		switch outcome {
		case spacesResolutionUnresolved:
			if _, retained := model.pending[candidateID]; !retained || !model.reported[candidateID] {
				violations["I6 explicit resolution"] = true
			}
		case spacesResolutionTakeRemote:
			report, hasReport := model.reports[candidateID]
			if !hasReport || model.resolutionRemoteHead[candidateID] == "" || model.resolutionRemoteHead[candidateID] != report.remote.record {
				violations["I6 explicit resolution"] = true
			}
		case spacesResolutionKeepLocal:
			report, hasReport := model.reports[candidateID]
			overwriteID := model.resolutionOverwrite[candidateID]
			overwrite, committed := model.committed[overwriteID]
			if !hasReport || !committed || model.resolutionRemoteHead[candidateID] != report.remote.record || overwrite.parentCID != report.remote.record || overwrite.sequence != uint64(report.remote.sequence+1) || overwrite.payload == nil {
				violations["I6 explicit resolution"] = true
			}
		default:
			violations["I6 explicit resolution"] = true
		}
	}
	for _, candidate := range model.committed {
		if !candidate.committedPolicyOwnerOnly || candidate.committedPolicyRevision != candidate.policyRevision {
			violations["I7 policy revision binding"] = true
		}
	}
	if model.policyMode == spacesImmutablePolicy && !model.policyOwnerOnly {
		violations["I7 policy revision binding"] = true
	}
	result := make([]string, 0, len(violations))
	for violation := range violations {
		result = append(result, violation)
	}
	sort.Strings(result)
	return result
}

func TestSpacesModelDeclaredAssumptionsAreNamed(t *testing.T) {
	expected := []string{
		"occupied-sequence-create-rejects-whole-batch",
		"rejected-batch-is-atomic",
		"head-binds-record-and-blob",
		"mutable-policy-revision-is-checked-at-commit",
		"immutable-owner-policy-refuses-broadening",
		"conflict-is-reported-and-candidate-retained",
		"resolution-is-one-of-three-recorded-outcomes",
	}
	actual := make([]string, 0, len(spacesModelAssumptions))
	for _, assumption := range spacesModelAssumptions {
		actual = append(actual, assumption.name)
		t.Logf("model assumption %s: %s", assumption.name, assumption.description)
	}
	assert.Equal(t, expected, actual)
}

func TestSpacesModelDifferentCandidateRaceAndGenesisRace(t *testing.T) {
	t.Run("successors", func(t *testing.T) {
		model := newSpacesModel()
		genesis := spacesPrepareCandidate(model, "genesis", "vault-a", []byte("base"))
		require.Equal(t, "committed", model.commit(genesis, false))
		left := spacesPrepareCandidate(model, "left", "vault-a", []byte("left"))
		right := spacesPrepareCandidate(model, "right", "vault-a", []byte("right"))
		require.Equal(t, left.sequence, right.sequence)
		require.Equal(t, left.parentCID, right.parentCID)
		require.Equal(t, "committed", model.commit(left, false))
		winnerHead := model.head.snapshot
		assert.Equal(t, "conflict", model.commit(right, false))
		assert.Equal(t, winnerHead, model.head.snapshot)
		assert.Equal(t, []string{}, spacesInvariantViolations(model))
		assert.True(t, model.conflicts[right.id])
		assert.Equal(t, right, model.pending[right.id])
	})
	t.Run("genesis", func(t *testing.T) {
		model := newSpacesModel()
		left := spacesPrepareCandidate(model, "genesis-left", "vault-left", []byte("left-vault"))
		right := spacesPrepareCandidate(model, "genesis-right", "vault-right", []byte("right-vault"))
		require.Equal(t, uint64(0), left.sequence)
		require.Equal(t, left.sequence, right.sequence)
		assert.Equal(t, "committed", model.commit(left, false))
		winnerHead := model.head.snapshot
		assert.Equal(t, "conflict", model.commit(right, false))
		assert.Equal(t, winnerHead, model.head.snapshot)
		assert.Equal(t, []string{}, spacesInvariantViolations(model))
	})
}

func TestSpacesModelOccupiedKeyInversionViolatesCandidateExclusion(t *testing.T) {
	model := newSpacesModel()
	left := spacesPrepareCandidate(model, "race-left", "vault-a", []byte("left"))
	right := spacesPrepareCandidate(model, "race-right", "vault-a", []byte("right"))
	model.rejectOccupiedKey = false
	require.Equal(t, "committed", model.commit(left, false))
	assert.Equal(t, "committed", model.commit(right, false))
	assert.Contains(t, spacesInvariantViolations(model), "I1 distinct-candidate exclusion")
}

func TestSpacesModelDelayedIdenticalReplayCannotRewind(t *testing.T) {
	model := newSpacesModel()
	first := spacesPrepareCandidate(model, "publish-zero", "vault-a", []byte("same-bytes"))
	require.Equal(t, "committed", model.commit(first, false))
	successor := spacesPrepareCandidate(model, "publish-one", "vault-a", []byte("new-bytes"))
	require.Equal(t, "committed", model.commit(successor, false))
	delayedReplay := first
	assert.Equal(t, "superseded", model.commit(delayedReplay, false))
	assert.Equal(t, "committed-but-superseded", model.publicationOutcomes[first.id])
	assert.Equal(t, []string{}, spacesInvariantViolations(model))
	assert.Equal(t, successor.recordCID, model.head.snapshot)
}

func TestSpacesModelIdenticalReplayInversionViolatesNoRewind(t *testing.T) {
	model := newSpacesModel()
	first := spacesPrepareCandidate(model, "identical-zero", "vault-a", []byte("same-bytes"))
	require.Equal(t, "committed", model.commit(first, false))
	successor := spacesPrepareCandidate(model, "successor-one", "vault-a", []byte("later-bytes"))
	require.Equal(t, "committed", model.commit(successor, false))
	model.rejectOccupiedKey = false
	assert.Equal(t, "committed", model.commit(first, false))
	assert.Contains(t, spacesInvariantViolations(model), "I3 no rewind")
}

func TestSpacesModelHeadAndBlobBinding(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*spacesModel, spacesCandidate)
	}{
		{
			name: "head-does-not-name-record-cid",
			mutate: func(model *spacesModel, candidate spacesCandidate) {
				model.head.snapshot = model.head.blob
			},
		},
		{
			name: "head-does-not-name-record-blob-cid",
			mutate: func(model *spacesModel, candidate spacesCandidate) {
				model.head.blob = "blob-sha256:wrong"
			},
		},
		{
			name: "record-does-not-name-blob-cid",
			mutate: func(model *spacesModel, candidate spacesCandidate) {
				record := model.records[candidate.sequence]
				record.blobCID = "blob-sha256:wrong"
				model.records[candidate.sequence] = record
			},
		},
		{
			name: "blob-bytes-do-not-hash-to-cid",
			mutate: func(model *spacesModel, candidate spacesCandidate) {
				model.blobs[candidate.blobCID] = []byte("altered payload")
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			model := newSpacesModel()
			candidate := spacesPrepareCandidate(model, "bound", "vault-a", []byte("payload"))
			require.Equal(t, "committed", model.commit(candidate, false))
			assert.Equal(t, []string{}, spacesInvariantViolations(model))
			testCase.mutate(model, candidate)
			assert.Contains(t, spacesInvariantViolations(model), "I2 exact binding")
		})
	}
}

func TestSpacesModelHeadBindingAssumptionInversionViolatesExactBinding(t *testing.T) {
	model := newSpacesModel()
	model.bindHeadRecord = false
	candidate := spacesPrepareCandidate(model, "unbound-head", "vault-a", []byte("payload"))
	require.Equal(t, "committed", model.commit(candidate, false))
	assert.Contains(t, spacesInvariantViolations(model), "I2 exact binding")
}

func TestSpacesModelRejectedBatchIsAtomic(t *testing.T) {
	model := newSpacesModel()
	candidate := spacesPrepareCandidate(model, "interrupted", "vault-a", []byte("payload"))
	assert.Equal(t, "rejected-atomic", model.commit(candidate, true))
	assert.Equal(t, []string{}, spacesInvariantViolations(model))
}

func TestSpacesModelPartialBatchInversionViolatesAtomicPublication(t *testing.T) {
	model := newSpacesModel()
	candidate := spacesPrepareCandidate(model, "partial", "vault-a", []byte("payload"))
	model.atomicRejectedBatch = false
	assert.Equal(t, "rejected-partial", model.commit(candidate, true))
	assert.Contains(t, spacesInvariantViolations(model), "I4 no partial publication")
}

func TestSpacesModelHeadWithoutRecordViolatesAtomicPublication(t *testing.T) {
	model := newSpacesModel()
	candidate := spacesPrepareCandidate(model, "head-only", "vault-a", []byte("payload"))
	model.head = &spacesHead{
		vault:     candidate.vault,
		sequence:  candidate.sequence,
		snapshot:  candidate.recordCID,
		blob:      candidate.blobCID,
		candidate: candidate.id,
	}
	assert.Contains(t, spacesInvariantViolations(model), "I4 no partial publication")
}

func TestSpacesModelConflictIsReportedAndRetained(t *testing.T) {
	model := newSpacesModel()
	first := spacesPrepareCandidate(model, "winner", "vault-a", []byte("winner"))
	loser := spacesPrepareCandidate(model, "loser", "vault-a", []byte("loser"))
	require.Equal(t, "committed", model.commit(first, false))
	assert.Equal(t, "conflict", model.commit(loser, false))
	assert.True(t, model.reported[loser.id])
	assert.Equal(t, spacesConflictReport{
		local:  spacesConflictPosition{vault: loser.vault, sequence: int64(loser.sequence), record: loser.recordCID},
		remote: spacesConflictPosition{vault: first.vault, sequence: int64(first.sequence), record: first.recordCID},
	}, model.reports[loser.id])
	assert.Equal(t, loser, model.pending[loser.id])
	assert.Equal(t, []string{}, spacesInvariantViolations(model))
}

func TestSpacesModelConflictReportingAndRetentionInversionsViolateNoSilentLoss(t *testing.T) {
	t.Run("discard", func(t *testing.T) {
		model := newSpacesModel()
		first := spacesPrepareCandidate(model, "winner", "vault-a", []byte("winner"))
		loser := spacesPrepareCandidate(model, "loser", "vault-a", []byte("loser"))
		require.Equal(t, "committed", model.commit(first, false))
		model.retainConflict = false
		assert.Equal(t, "conflict", model.commit(loser, false))
		assert.Contains(t, spacesInvariantViolations(model), "I5 no silent loss")
	})
	t.Run("hide-report", func(t *testing.T) {
		model := newSpacesModel()
		first := spacesPrepareCandidate(model, "winner", "vault-a", []byte("winner"))
		loser := spacesPrepareCandidate(model, "loser", "vault-a", []byte("loser"))
		require.Equal(t, "committed", model.commit(first, false))
		model.reportConflict = false
		assert.Equal(t, "conflict", model.commit(loser, false))
		assert.Contains(t, spacesInvariantViolations(model), "I5 no silent loss")
	})
}

func TestSpacesModelResolutionOutcomesAreExplicit(t *testing.T) {
	t.Run("unresolved", func(t *testing.T) {
		model := newSpacesModel()
		winner := spacesPrepareCandidate(model, "remote", "vault-a", []byte("remote"))
		local := spacesPrepareCandidate(model, "local", "vault-a", []byte("local"))
		require.Equal(t, "committed", model.commit(winner, false))
		assert.Equal(t, "conflict", model.commit(local, false))
		require.True(t, model.resolve(local.id, spacesResolutionUnresolved))
		assert.Equal(t, spacesResolutionUnresolved, model.resolutions[local.id])
		assert.Equal(t, local, model.pending[local.id])
		assert.True(t, model.reported[local.id])
		assert.Equal(t, []string{}, spacesInvariantViolations(model))
	})
	t.Run("keep-local-overwrite", func(t *testing.T) {
		model := newSpacesModel()
		winner := spacesPrepareCandidate(model, "remote", "vault-a", []byte("remote"))
		local := spacesPrepareCandidate(model, "local", "vault-a", []byte("local"))
		require.Equal(t, "committed", model.commit(winner, false))
		assert.Equal(t, "conflict", model.commit(local, false))
		require.True(t, model.resolve(local.id, spacesResolutionKeepLocal))
		overwrite := model.committed[model.resolutionOverwrite[local.id]]
		assert.Equal(t, spacesResolutionKeepLocal, model.resolutions[local.id])
		assert.Equal(t, winner.recordCID, overwrite.parentCID)
		assert.Equal(t, uint64(1), overwrite.sequence)
		assert.Equal(t, local.blobCID, model.head.blob)
		assert.Equal(t, []string{}, spacesInvariantViolations(model))
	})
	t.Run("take-remote", func(t *testing.T) {
		model := newSpacesModel()
		winner := spacesPrepareCandidate(model, "remote", "vault-a", []byte("remote"))
		local := spacesPrepareCandidate(model, "local", "vault-a", []byte("local"))
		require.Equal(t, "committed", model.commit(winner, false))
		assert.Equal(t, "conflict", model.commit(local, false))
		require.True(t, model.resolve(local.id, spacesResolutionTakeRemote))
		assert.Equal(t, spacesResolutionTakeRemote, model.resolutions[local.id])
		assert.NotContains(t, model.pending, local.id)
		assert.Equal(t, winner.recordCID, model.head.snapshot)
		assert.Equal(t, []string{}, spacesInvariantViolations(model))
	})
}

func TestSpacesModelKeepLocalRejectsUnseenHead(t *testing.T) {
	model := newSpacesModel()
	genesis := spacesPrepareCandidate(model, "genesis", "vault-a", []byte("base"))
	require.Equal(t, "committed", model.commit(genesis, false))
	local := spacesPrepareCandidate(model, "local", "vault-a", []byte("local-copy"))
	writerOne := spacesPrepareCandidate(model, "writer-one", "vault-a", []byte("remote-one"))
	require.Equal(t, "committed", model.commit(writerOne, false))
	assert.Equal(t, "conflict", model.commit(local, false))
	assert.Equal(t, writerOne.recordCID, model.reports[local.id].remote.record)

	writerTwo := spacesPrepareCandidate(model, "writer-two", "vault-a", []byte("remote-two"))
	require.Equal(t, "committed", model.commit(writerTwo, false))
	observedHead := model.head.snapshot
	assert.False(t, model.resolve(local.id, spacesResolutionKeepLocal))
	assert.Equal(t, observedHead, model.head.snapshot)
	assert.Equal(t, local, model.pending[local.id])
	assert.True(t, model.reported[local.id])
	assert.Equal(t, writerTwo.recordCID, model.reports[local.id].remote.record)
	assert.Equal(t, 2, model.conflictGeneration[local.id])
	assert.Equal(t, spacesResolutionUnresolved, model.resolutions[local.id])
	assert.Equal(t, []string{}, spacesInvariantViolations(model))

	require.True(t, model.resolve(local.id, spacesResolutionKeepLocal))
	overwrite := model.committed[model.resolutionOverwrite[local.id]]
	assert.Equal(t, writerTwo.recordCID, model.resolutionRemoteHead[local.id])
	assert.Equal(t, writerTwo.recordCID, overwrite.parentCID)
	assert.Equal(t, writerTwo.sequence+1, overwrite.sequence)
	assert.Equal(t, []string{}, spacesInvariantViolations(model))
}

func TestSpacesModelUnrecordedResolutionInversionViolatesExplicitResolution(t *testing.T) {
	model := newSpacesModel()
	winner := spacesPrepareCandidate(model, "remote", "vault-a", []byte("remote"))
	loser := spacesPrepareCandidate(model, "local", "vault-a", []byte("local"))
	require.Equal(t, "committed", model.commit(winner, false))
	assert.Equal(t, "conflict", model.commit(loser, false))
	model.recordResolution = false
	delete(model.resolutions, loser.id)
	assert.Contains(t, spacesInvariantViolations(model), "I6 explicit resolution")
}

func TestSpacesModelMutablePolicyRaceRequiresCommitRevision(t *testing.T) {
	model := newSpacesModel()
	model.policyMode = spacesMutablePolicy
	genesis := spacesPrepareCandidate(model, "policy-race-genesis", "vault-a", []byte("base"))
	require.Equal(t, "committed", model.commit(genesis, false))
	oldHead := model.head.snapshot
	candidate := spacesPrepareCandidate(model, "policy-race", "vault-a", []byte("payload"))
	assert.True(t, model.broadenPolicy())
	assert.Equal(t, "policy-blocked", model.commit(candidate, false))
	assert.Equal(t, oldHead, model.head.snapshot)
	assert.NotContains(t, model.records, candidate.sequence)
	assert.True(t, model.policyBlocked[candidate.id])
	assert.NotContains(t, model.conflicts, candidate.id)
	assert.Equal(t, []string{}, spacesInvariantViolations(model))
}

func TestSpacesModelPolicyBlockCannotBeResolvedAsConflict(t *testing.T) {
	model := newSpacesModel()
	model.policyMode = spacesMutablePolicy
	genesis := spacesPrepareCandidate(model, "policy-block-genesis", "vault-a", []byte("base"))
	require.Equal(t, "committed", model.commit(genesis, false))
	candidate := spacesPrepareCandidate(model, "policy-blocked", "vault-a", []byte("payload"))
	assert.True(t, model.broadenPolicy())
	headBefore := model.head.snapshot
	assert.Equal(t, "policy-blocked", model.commit(candidate, false))
	for _, outcome := range []string{spacesResolutionKeepLocal, spacesResolutionTakeRemote, spacesResolutionUnresolved} {
		assert.False(t, model.resolve(candidate.id, outcome))
	}
	assert.Equal(t, headBefore, model.head.snapshot)
	assert.Equal(t, candidate, model.pending[candidate.id])
	assert.True(t, model.policyBlocked[candidate.id])
	assert.NotContains(t, model.conflicts, candidate.id)
	assert.NotContains(t, model.reports, candidate.id)
}

func TestSpacesModelMutablePolicyRevisionInversionViolatesPolicyBinding(t *testing.T) {
	model := newSpacesModel()
	model.policyMode = spacesMutablePolicy
	genesis := spacesPrepareCandidate(model, "policy-race-inverted-genesis", "vault-a", []byte("base"))
	require.Equal(t, "committed", model.commit(genesis, false))
	candidate := spacesPrepareCandidate(model, "policy-race-inverted", "vault-a", []byte("payload"))
	assert.True(t, model.broadenPolicy())
	model.checkPolicyRevision = false
	assert.Equal(t, "committed", model.commit(candidate, false))
	committed := model.committed[candidate.id]
	assert.Equal(t, candidate.policyRevision, committed.policyRevision)
	assert.Equal(t, model.policyRevision, committed.committedPolicyRevision)
	assert.False(t, committed.committedPolicyOwnerOnly)
	assert.Contains(t, spacesInvariantViolations(model), "I7 policy revision binding")
}

func TestSpacesModelImmutablePolicyRefusesBroadening(t *testing.T) {
	model := newSpacesModel()
	model.policyMode = spacesImmutablePolicy
	candidate := spacesPrepareCandidate(model, "immutable-policy", "vault-a", []byte("payload"))
	assert.False(t, model.broadenPolicy())
	assert.Equal(t, "committed", model.commit(candidate, false))
	assert.Equal(t, []string{}, spacesInvariantViolations(model))
}

func TestSpacesModelImmutablePolicyBroadeningInversionViolatesPolicyBinding(t *testing.T) {
	model := newSpacesModel()
	model.policyMode = spacesImmutablePolicy
	model.forbidPolicyBroadening = false
	assert.True(t, model.broadenPolicy())
	assert.Contains(t, spacesInvariantViolations(model), "I7 policy revision binding")
}
