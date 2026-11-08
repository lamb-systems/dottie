package publicationstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type wireOracleBinding struct {
	AccountDID string `json:"accountDid"`
	Backend    string `json:"backend"`
	Repository string `json:"repository"`
	Vault      []byte `json:"vault"`
	Profile    string `json:"profile"`
}

type wireOraclePolicy struct {
	Revision  string `json:"revision"`
	Identity  []byte `json:"identity"`
	OwnerOnly bool   `json:"ownerOnly"`
}

type wireOracleContext struct {
	RepositoryRevision string            `json:"repositoryRevision"`
	RepositoryDigest   []byte            `json:"repositoryDigest"`
	Policy             *wireOraclePolicy `json:"policy"`
}

type wireOracleSnapshot struct {
	Key string
	Raw []byte
}

type wireOracleReview struct {
	SelectionDigest   []byte `json:"selectionDigest"`
	SelectionRevision uint64 `json:"selectionRevision"`
	ApprovalDigest    []byte `json:"approvalDigest"`
	ApprovalRevision  uint64 `json:"approvalRevision"`
}

type wireOracleFloor struct {
	Version             uint32            `json:"version"`
	DatabaseID          []byte            `json:"databaseId"`
	Revision            uint64            `json:"revision"`
	Generation          uint64            `json:"generation"`
	Provenance          string            `json:"provenance"`
	AnchorCID           []byte            `json:"anchorCid"`
	Binding             wireOracleBinding `json:"binding"`
	SuppliedContext     wireOracleContext `json:"suppliedContext"`
	Head                []byte            `json:"head"`
	SnapshotKey         string            `json:"snapshotKey"`
	Sequence            uint64            `json:"sequence"`
	PublicationID       []byte            `json:"publicationId"`
	RecordCID           []byte            `json:"recordCid"`
	BlobCID             []byte            `json:"blobCid"`
	BlobSize            uint64            `json:"blobSize"`
	ObservationDigest   []byte            `json:"observationDigest"`
	AcceptedEventDigest []byte            `json:"acceptedEventDigest"`
}

type wireOracleLimits struct {
	SuppliedSnapshotCount uint32 `json:"suppliedSnapshotCount"`
	SuppliedTotalBytes    uint64 `json:"suppliedTotalBytes"`
	SuppliedContextBytes  uint32 `json:"suppliedContextBytes"`
	MaxLineageLinks       uint32 `json:"maxLineageLinks"`
	CacheRecordCount      uint32 `json:"cacheRecordCount"`
	CacheObservationCount uint32 `json:"cacheObservationCount"`
	CacheLogicalBytes     uint64 `json:"cacheLogicalBytes"`
	AcceptedRecordCount   uint32 `json:"acceptedRecordCount"`
	AcceptedEventCount    uint32 `json:"acceptedEventCount"`
	AcceptedLogicalBytes  uint64 `json:"acceptedLogicalBytes"`
	HistoryPageEvents     uint32 `json:"historyPageEvents"`
	HistoryEvidenceBytes  uint64 `json:"historyEvidenceBytes"`
}

type wireOracleAttemptLimits struct {
	ActiveAttempts       uint32 `json:"activeAttempts"`
	HistoricalAttempts   uint32 `json:"historicalAttempts"`
	RetainedPublications uint32 `json:"retainedPublications"`
	ManagedObjects       uint32 `json:"managedObjects"`
	CustodyBytes         uint64 `json:"custodyBytes"`
	MetadataBytes        uint64 `json:"metadataBytes"`
	EvidenceBytes        uint64 `json:"evidenceBytes"`
	EvidenceSlotBytes    uint64 `json:"evidenceSlotBytes"`
	LifecycleEvents      uint32 `json:"lifecycleEvents"`
	EventBytes           uint64 `json:"eventBytes"`
	CoreBytes            uint64 `json:"coreBytes"`
	HistoryPageEntries   uint32 `json:"historyPageEntries"`
	HistoryPageBytes     uint64 `json:"historyPageBytes"`
}

type wireOracleView struct {
	Version   uint32               `json:"version"`
	Origin    wireOracleBinding    `json:"origin"`
	Scope     string               `json:"scope"`
	Context   wireOracleContext    `json:"context"`
	Head      []byte               `json:"head"`
	Snapshots []wireOracleSnapshot `json:"snapshots"`
}

type wireOracleAttemptToken struct {
	Version             uint32                  `json:"version"`
	DatabaseID          []byte                  `json:"databaseId"`
	FloorRevision       uint64                  `json:"floorRevision"`
	Generation          uint64                  `json:"generation"`
	Floor               *wireOracleFloor        `json:"floor"`
	MutationRevision    uint64                  `json:"mutationRevision"`
	ActiveAttemptID     []byte                  `json:"activeAttemptId"`
	ActiveAttemptDigest []byte                  `json:"activeAttemptDigest"`
	PositionLimits      wireOracleLimits        `json:"positionLimits"`
	AttemptLimits       wireOracleAttemptLimits `json:"attemptLimits"`
}

type wireOracleAttemptState struct {
	Version            uint32 `json:"version"`
	AttemptID          []byte `json:"attemptId"`
	CoreDigest         []byte `json:"coreDigest"`
	Lifecycle          string `json:"lifecycle"`
	Outcome            string `json:"outcome"`
	Blocked            string `json:"blocked"`
	MutationRevision   uint64 `json:"mutationRevision"`
	TerminalEvidence   []byte `json:"terminalEvidence"`
	RetirementEvidence []byte `json:"retirementEvidence"`
}

type wireOracleCandidateConfirmation struct {
	Version         uint32           `json:"version"`
	DatabaseID      []byte           `json:"databaseId"`
	StateToken      []byte           `json:"stateToken"`
	AttemptID       []byte           `json:"attemptId"`
	CandidateDigest []byte           `json:"candidateDigest"`
	ViewDigest      []byte           `json:"viewDigest"`
	Review          wireOracleReview `json:"review"`
}

type wireOracleDispatchConfirmation struct {
	Version    uint32           `json:"version"`
	DatabaseID []byte           `json:"databaseId"`
	StateToken []byte           `json:"stateToken"`
	AttemptID  []byte           `json:"attemptId"`
	Kind       string           `json:"kind"`
	ViewDigest []byte           `json:"viewDigest"`
	Review     wireOracleReview `json:"review"`
}

type wireOracleAbandonConfirmation struct {
	Version           uint32           `json:"version"`
	DatabaseID        []byte           `json:"databaseId"`
	MutationToken     []byte           `json:"mutationToken"`
	AttemptID         []byte           `json:"attemptId"`
	CandidateDigest   []byte           `json:"candidateDigest"`
	Floor             *wireOracleFloor `json:"floor"`
	Lifecycle         string           `json:"lifecycle"`
	Outcome           string           `json:"outcome"`
	Blocked           string           `json:"blocked"`
	Evidence          []byte           `json:"evidence"`
	ReferenceReleased bool             `json:"referenceReleased"`
	Warning           string           `json:"warning"`
}

type wireOracleEvidence struct {
	Version           uint32               `json:"version"`
	Role              string               `json:"role"`
	Scope             string               `json:"scope"`
	ViewDigest        []byte               `json:"viewDigest"`
	Origin            wireOracleBinding    `json:"origin"`
	Context           wireOracleContext    `json:"context"`
	Head              []byte               `json:"head"`
	AttemptedKey      string               `json:"attemptedKey"`
	AttemptedRecord   []byte               `json:"attemptedRecord"`
	PredecessorRecord []byte               `json:"predecessorRecord"`
	Suffix            []wireOracleSnapshot `json:"suffix"`
	Outcome           string               `json:"outcome"`
}

type wireOracleFirstConflict struct {
	Version          uint32             `json:"version"`
	AttemptID        []byte             `json:"attemptId"`
	CoreDigest       []byte             `json:"coreDigest"`
	EventOrdinal     uint32             `json:"eventOrdinal"`
	MutationRevision uint64             `json:"mutationRevision"`
	EventStateDigest []byte             `json:"eventStateDigest"`
	Blocked          string             `json:"blocked"`
	Proof            wireOracleEvidence `json:"proof"`
}

func oracleCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	require.NoError(t, encoder.Encode(value))
	return bytes.TrimSuffix(bytes.Clone(output.Bytes()), []byte{'\n'})
}

func oracleDomainHash(domain string, body []byte) [32]byte {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	hash.Write(body)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func oracleCandidateDigest(t *testing.T, candidate validatedCandidate, state stateSnapshot, review LocalReviewContext, databaseID [32]byte, floorBytes []byte) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("systems.lamb.dottie.publication-candidate.v1\x00"))
	var length [8]byte
	writePart := func(part []byte) {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		hash.Write(length[:])
		hash.Write(part)
	}
	writePart(databaseID[:])
	var counters [16]byte
	binary.BigEndian.PutUint64(counters[:8], state.revision)
	binary.BigEndian.PutUint64(counters[8:], state.generation)
	writePart(counters[:])
	writePart(floorBytes)
	writePart([]byte(candidate.key))
	writePart(candidate.snapshotRaw)
	writePart(candidate.headRaw)
	writePart(candidate.payload)
	writePart(candidate.view.digest[:])
	reviewBody := oracleCanonicalJSON(t, wireOracleReview{SelectionDigest: bytes.Clone(review.SelectionDigest[:]), SelectionRevision: review.SelectionRevision, ApprovalDigest: bytes.Clone(review.ApprovalDigest[:]), ApprovalRevision: review.ApprovalRevision})
	writePart(reviewBody)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func wireVectorBinding(binding Binding) wireOracleBinding {
	return wireOracleBinding{AccountDID: binding.AccountDID, Backend: string(binding.Backend), Repository: binding.Repository, Vault: bytes.Clone(binding.Vault[:]), Profile: "systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"}
}

func wireVectorContext(context SuppliedContext) wireOracleContext {
	wire := wireOracleContext{RepositoryRevision: context.RepositoryRevision, RepositoryDigest: bytes.Clone(context.RepositoryDigest)}
	if context.Policy != nil {
		wire.Policy = &wireOraclePolicy{Revision: context.Policy.Revision, Identity: bytes.Clone(context.Policy.Identity), OwnerOnly: context.Policy.OwnerOnly}
	}
	return wire
}

func wireVectorFloor(floor Floor) wireOracleFloor {
	return wireOracleFloor{Version: 1, DatabaseID: bytes.Clone(floor.DatabaseID[:]), Revision: floor.Revision, Generation: floor.Generation, Provenance: string(floor.Provenance), AnchorCID: bytes.Clone(floor.AnchorCID), Binding: wireVectorBinding(floor.Binding), SuppliedContext: wireVectorContext(floor.SuppliedContext), Head: bytes.Clone(floor.Head), SnapshotKey: floor.SnapshotKey, Sequence: floor.Sequence, PublicationID: bytes.Clone(floor.PublicationID[:]), RecordCID: bytes.Clone(floor.RecordCID), BlobCID: bytes.Clone(floor.BlobCID), BlobSize: floor.BlobSize, ObservationDigest: bytes.Clone(floor.ObservationDigest[:]), AcceptedEventDigest: bytes.Clone(floor.AcceptedEventDigest[:])}
}

func oraclePositionLimits() wireOracleLimits {
	return wireOracleLimits{SuppliedSnapshotCount: 4095, SuppliedTotalBytes: 8 << 20, SuppliedContextBytes: 16 << 10, MaxLineageLinks: 4094, CacheRecordCount: 4096, CacheObservationCount: 1024, CacheLogicalBytes: 16 << 20, AcceptedRecordCount: 16384, AcceptedEventCount: 8192, AcceptedLogicalBytes: 128 << 20, HistoryPageEvents: 100, HistoryEvidenceBytes: 16 << 20}
}

func oracleAttemptLimits() wireOracleAttemptLimits {
	return wireOracleAttemptLimits{ActiveAttempts: 1, HistoricalAttempts: 1024, RetainedPublications: 64, ManagedObjects: 64, CustodyBytes: 4 * (384 << 20), MetadataBytes: 128 << 20, EvidenceBytes: 128 << 20, EvidenceSlotBytes: 16 << 20, LifecycleEvents: 16, EventBytes: 64 << 10, CoreBytes: 256 << 10, HistoryPageEntries: 100, HistoryPageBytes: 16 << 20}
}

func oracleBytes(seed byte, length int) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}

func TestLocalAttemptWireGoldenVectors(t *testing.T) {
	binding := Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: BackendPublicRepo, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx"}
	for index := range binding.Vault {
		binding.Vault[index] = byte(index + 1)
	}
	contextValue := SuppliedContext{RepositoryRevision: "<>&\x01", RepositoryDigest: []byte{0, 1, 0xfe}}
	view := SuppliedRepositoryView{Origin: binding, Scope: ViewScopeWholeRepository, SuppliedContext: contextValue, Head: []byte{0, 0xff, '<'}, Snapshots: []SnapshotBlock{{Key: "0000000000000007", Raw: []byte{0, 1, 0xff, '<', '&', '>'}}}}
	viewDigest, err := makeViewDigest(view, view.Snapshots)
	require.NoError(t, err)
	oracleViewBody := oracleCanonicalJSON(t, wireOracleView{Version: 1, Origin: wireVectorBinding(binding), Scope: string(view.Scope), Context: wireVectorContext(contextValue), Head: bytes.Clone(view.Head), Snapshots: []wireOracleSnapshot{{Key: view.Snapshots[0].Key, Raw: bytes.Clone(view.Snapshots[0].Raw)}}})
	oracleViewDigest := oracleDomainHash("systems.lamb.dottie.supplied-repository-view.v1", oracleViewBody)
	expectedViewBody := []byte(`{"version":1,"origin":{"accountDid":"did:plc:abcdefghijklmnopqrstuvwx","backend":"public-repo","repository":"at://did:plc:abcdefghijklmnopqrstuvwx","vault":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","profile":"systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"},"scope":"whole-repository","context":{"repositoryRevision":"<>&\u0001","repositoryDigest":"AAH+","policy":null},"head":"AP88","snapshots":[{"Key":"0000000000000007","Raw":"AAH/PCY+"}]}`)
	assert.Equal(t, expectedViewBody, oracleViewBody)
	assert.Equal(t, "a160b691117604cf04a4bbc0937cadf60a25e46c0ba7bc01ad626c40c4715782", hex.EncodeToString(oracleViewDigest[:]))
	assert.Equal(t, oracleViewDigest, viewDigest)
	nilHead := view
	nilHead.Head = nil
	emptyHead := view
	emptyHead.Head = []byte{}
	nilHeadDigest, err := makeViewDigest(nilHead, nilHead.Snapshots)
	require.NoError(t, err)
	emptyHeadDigest, err := makeViewDigest(emptyHead, emptyHead.Snapshots)
	require.NoError(t, err)
	assert.Equal(t, "a70e302069c9c1ce043d0254ae37c409ec2fe50204fdbeacf5a4f58a08e82f7e", hex.EncodeToString(nilHeadDigest[:]))
	assert.Equal(t, "f4dae5ed178920d6c22663ac5b6ff15b628efe663d09b97b2cba08ff0b2b4d03", hex.EncodeToString(emptyHeadDigest[:]))
	assert.NotEqual(t, nilHeadDigest, emptyHeadDigest)
	nilSnapshots := view
	nilSnapshots.Snapshots = nil
	emptySnapshots := view
	emptySnapshots.Snapshots = []SnapshotBlock{}
	nilSnapshotsDigest, err := makeViewDigest(nilSnapshots, nilSnapshots.Snapshots)
	require.NoError(t, err)
	emptySnapshotsDigest, err := makeViewDigest(emptySnapshots, emptySnapshots.Snapshots)
	require.NoError(t, err)
	assert.Equal(t, nilSnapshotsDigest, emptySnapshotsDigest)
	changedView := view
	changedContext := contextValue
	changedContext.RepositoryRevision = "<>&\x02"
	changedView.SuppliedContext = changedContext
	changedViewDigest, err := makeViewDigest(changedView, changedView.Snapshots)
	require.NoError(t, err)
	assert.NotEqual(t, viewDigest, changedViewDigest)

	var databaseID [32]byte
	copy(databaseID[:], oracleBytes(0xa0, 32))
	var attemptID [16]byte
	copy(attemptID[:], oracleBytes(0x10, 16))
	var review LocalReviewContext
	copy(review.SelectionDigest[:], oracleBytes(0x20, 32))
	copy(review.ApprovalDigest[:], oracleBytes(0x40, 32))
	review.SelectionRevision = 11
	review.ApprovalRevision = 13
	candidate := validatedCandidate{id: attemptID, key: "0000000000000007", snapshotRaw: []byte{0x31, 0, 0xff}, headRaw: []byte{0x41, '<', '&', '>'}, payload: []byte{0x51, 0, 0xfe}}
	candidate.view.digest = oracleViewDigest
	state := stateSnapshot{revision: 23, generation: 7}
	candidateHash, err := candidateDigest(candidate, state, review, databaseID)
	require.NoError(t, err)
	oracleCandidateHash := oracleCandidateDigest(t, candidate, state, review, databaseID, nil)
	assert.Equal(t, "5de4657ce5b2cdf6616957ad1e5c1853fc99625ee803f3d9a86e4f1a4725e979", hex.EncodeToString(oracleCandidateHash[:]))
	assert.Equal(t, oracleCandidateHash, candidateHash)
	nilPayload := candidate
	nilPayload.payload = nil
	emptyPayload := candidate
	emptyPayload.payload = []byte{}
	nilPayloadHash, err := candidateDigest(nilPayload, state, review, databaseID)
	require.NoError(t, err)
	emptyPayloadHash, err := candidateDigest(emptyPayload, state, review, databaseID)
	require.NoError(t, err)
	assert.Equal(t, nilPayloadHash, emptyPayloadHash)
	changedDatabaseID := databaseID
	changedDatabaseID[0] ^= 1
	changedCandidateHash, err := candidateDigest(candidate, state, review, changedDatabaseID)
	require.NoError(t, err)
	assert.NotEqual(t, candidateHash, changedCandidateHash)
	changedCandidateState := state
	changedCandidateState.generation++
	changedGenerationHash, err := candidateDigest(candidate, changedCandidateState, review, databaseID)
	require.NoError(t, err)
	assert.NotEqual(t, candidateHash, changedGenerationHash)
	changedReview := review
	changedReview.ApprovalDigest[0] ^= 1
	changedReviewHash, err := candidateDigest(candidate, state, changedReview, databaseID)
	require.NoError(t, err)
	assert.NotEqual(t, candidateHash, changedReviewHash)

	floor := Floor{DatabaseID: databaseID, Revision: 5, Generation: 4, Provenance: ProvenanceFirst, AnchorCID: []byte{0x61, 0x62}, Binding: binding, SuppliedContext: contextValue, Head: []byte{0x71, 0xff}, SnapshotKey: "0000000000000006", Sequence: 6, PublicationID: attemptID, RecordCID: []byte{0x81}, BlobCID: []byte{0x91, 0x92}, BlobSize: 93}
	copy(floor.ObservationDigest[:], oracleBytes(0x50, 32))
	copy(floor.AcceptedEventDigest[:], oracleBytes(0x70, 32))
	floorState := stateSnapshot{floor: &floor, revision: floor.Revision, generation: floor.Generation}
	floorBytes := oracleCanonicalJSON(t, wireVectorFloor(floor))
	floorCandidateHash := oracleCandidateDigest(t, candidate, floorState, review, databaseID, floorBytes)
	actualFloorCandidateHash, err := candidateDigest(candidate, floorState, review, databaseID)
	require.NoError(t, err)
	assert.Equal(t, "53ff2587c5261f5f95259cb9d28fa892ef341e9a371fdb5bd6e04665fd116c01", hex.EncodeToString(floorCandidateHash[:]))
	assert.Equal(t, floorCandidateHash, actualFloorCandidateHash)

	positionLimits := Limits{SuppliedSnapshotCount: 4095, SuppliedTotalBytes: 8388608, SuppliedContextBytes: 16384, MaxLineageLinks: 4094, CacheRecordCount: 4096, CacheObservationCount: 1024, CacheLogicalBytes: 16777216, AcceptedRecordCount: 16384, AcceptedEventCount: 8192, AcceptedLogicalBytes: 134217728, HistoryPageEvents: 100, HistoryEvidenceBytes: 16777216}
	attemptLimits := AttemptLimits{ActiveAttempts: 1, HistoricalAttempts: 1024, RetainedPublications: 64, ManagedObjects: 64, CustodyBytes: 1610612736, MetadataBytes: 134217728, EvidenceBytes: 134217728, EvidenceSlotBytes: 16777216, LifecycleEvents: 16, EventBytes: 65536, CoreBytes: 262144, HistoryPageEntries: 100, HistoryPageBytes: 16777216}
	var tokenActiveDigest [32]byte
	copy(tokenActiveDigest[:], oracleBytes(0x80, 32))
	activeID := [16]byte(attemptID)
	tokenState := stateSnapshot{floor: &floor, revision: 5, generation: 4}
	token, err := makeAttemptToken(databaseID, tokenState, 17, activeID[:], tokenActiveDigest[:], positionLimits, attemptLimits)
	require.NoError(t, err)
	tokenBody := oracleCanonicalJSON(t, wireOracleAttemptToken{Version: 2, DatabaseID: bytes.Clone(databaseID[:]), FloorRevision: 5, Generation: 4, Floor: ptrWireVectorFloor(floor), MutationRevision: 17, ActiveAttemptID: bytes.Clone(activeID[:]), ActiveAttemptDigest: bytes.Clone(tokenActiveDigest[:]), PositionLimits: oraclePositionLimits(), AttemptLimits: oracleAttemptLimits()})
	tokenHash := oracleDomainHash("systems.lamb.dottie.local-attempt-state.v1", tokenBody)
	assert.Equal(t, "6e2148c146ce5634b042a985b4ca3ed532ff4f24f3b05ce378119d8352dba0b3", hex.EncodeToString(tokenHash[:]))
	assert.Equal(t, tokenHash, token)
	changedDatabaseToken, err := makeAttemptToken(changedDatabaseID, tokenState, 17, activeID[:], tokenActiveDigest[:], positionLimits, attemptLimits)
	require.NoError(t, err)
	changedGenerationState := tokenState
	changedGenerationState.generation++
	changedGenerationToken, err := makeAttemptToken(databaseID, changedGenerationState, 17, activeID[:], tokenActiveDigest[:], positionLimits, attemptLimits)
	require.NoError(t, err)
	changedContextFloor := floor
	changedContextFloor.SuppliedContext.RepositoryRevision = "<>&\x02"
	changedContextState := tokenState
	changedContextState.floor = &changedContextFloor
	changedContextToken, err := makeAttemptToken(databaseID, changedContextState, 17, activeID[:], tokenActiveDigest[:], positionLimits, attemptLimits)
	require.NoError(t, err)
	assert.NotEqual(t, token, changedDatabaseToken)
	assert.NotEqual(t, token, changedGenerationToken)
	assert.NotEqual(t, token, changedContextToken)

	var confirmationCandidateHash, viewHash [32]byte
	copy(confirmationCandidateHash[:], oracleBytes(0x90, 32))
	copy(viewHash[:], oracleBytes(0xb0, 32))
	candidateConfirmation, err := makeCandidateConfirmation(databaseID, token, attemptID, confirmationCandidateHash, viewHash, review)
	require.NoError(t, err)
	candidateConfirmationBody := oracleCanonicalJSON(t, wireOracleCandidateConfirmation{Version: 1, DatabaseID: bytes.Clone(databaseID[:]), StateToken: bytes.Clone(token[:]), AttemptID: bytes.Clone(attemptID[:]), CandidateDigest: bytes.Clone(confirmationCandidateHash[:]), ViewDigest: bytes.Clone(viewHash[:]), Review: oracleReview(review)})
	candidateConfirmationHash := oracleDomainHash("systems.lamb.dottie.local-attempt-consent.v1", candidateConfirmationBody)
	assert.Equal(t, []byte(`{"version":1,"databaseId":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=","stateToken":"biFIwUbOVjSwQqmFtMo+1TL/TyTzsFzjeBGdg1LboLM=","attemptId":"EBESExQVFhcYGRobHB0eHw==","candidateDigest":"kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq8=","viewDigest":"sLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs8=","review":{"selectionDigest":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=","selectionRevision":11,"approvalDigest":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=","approvalRevision":13}}`), candidateConfirmationBody)
	assert.Equal(t, "c3505b82ca75aa6ebbe9c6a0311951320d5b030c93db93e206d372678974a28e", hex.EncodeToString(candidateConfirmationHash[:]))
	assert.Equal(t, candidateConfirmationHash, candidateConfirmation)
	changedCandidateConfirmation, err := makeCandidateConfirmation(databaseID, token, attemptID, confirmationCandidateHash, viewHash, changedReview)
	require.NoError(t, err)
	assert.NotEqual(t, candidateConfirmation, changedCandidateConfirmation)

	dispatchConfirmation, err := makeDispatchConfirmation(databaseID, token, attemptID, DispatchSubmission, viewHash, review)
	require.NoError(t, err)
	dispatchConfirmationBody := oracleCanonicalJSON(t, wireOracleDispatchConfirmation{Version: 1, DatabaseID: bytes.Clone(databaseID[:]), StateToken: bytes.Clone(token[:]), AttemptID: bytes.Clone(attemptID[:]), Kind: string(DispatchSubmission), ViewDigest: bytes.Clone(viewHash[:]), Review: oracleReview(review)})
	dispatchConfirmationHash := oracleDomainHash("systems.lamb.dottie.local-attempt-dispatch.v1", dispatchConfirmationBody)
	assert.Equal(t, []byte(`{"version":1,"databaseId":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=","stateToken":"biFIwUbOVjSwQqmFtMo+1TL/TyTzsFzjeBGdg1LboLM=","attemptId":"EBESExQVFhcYGRobHB0eHw==","kind":"submission","viewDigest":"sLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs8=","review":{"selectionDigest":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=","selectionRevision":11,"approvalDigest":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=","approvalRevision":13}}`), dispatchConfirmationBody)
	assert.Equal(t, "1f4542de5c7c1c6e3dc85ea4ea917a8feaa391798e89f70f1875e5827e7054c6", hex.EncodeToString(dispatchConfirmationHash[:]))
	assert.Equal(t, dispatchConfirmationHash, dispatchConfirmation)
	changedDispatchConfirmation, err := makeDispatchConfirmation(databaseID, token, attemptID, DispatchSubmission, viewHash, changedReview)
	require.NoError(t, err)
	assert.NotEqual(t, dispatchConfirmation, changedDispatchConfirmation)

	coreBytes := []byte{0x01, '<', '&', '>', 0xff}
	terminalEvidence := []byte{0x00, 0xff, '<', '&', 0x01}
	stateDigestActual, err := makeAttemptStateDigest(coreBytes, AttemptMayHaveSubmitted, OutcomeLostFence, "blocked-floor-replaced", 19, terminalEvidence, nil)
	require.NoError(t, err)
	stateCoreDigest := oracleDomainHash("systems.lamb.dottie.publication-attempt-core.v1", coreBytes)
	stateBody := oracleCanonicalJSON(t, wireOracleAttemptState{Version: 1, AttemptID: nil, CoreDigest: bytes.Clone(stateCoreDigest[:]), Lifecycle: string(AttemptMayHaveSubmitted), Outcome: string(OutcomeLostFence), Blocked: "blocked-floor-replaced", MutationRevision: 19, TerminalEvidence: bytes.Clone(terminalEvidence), RetirementEvidence: nil})
	stateDigestExpected := oracleDomainHash("systems.lamb.dottie.publication-attempt-state.v1", stateBody)
	assert.Equal(t, []byte(`{"version":1,"attemptId":null,"coreDigest":"sl/0abm1Rx3gNkqUXpKRfwYj9hpy9nbHjWdTdX938SQ=","lifecycle":"may-have-submitted","outcome":"lost-fence","blocked":"blocked-floor-replaced","mutationRevision":19,"terminalEvidence":"AP88JgE=","retirementEvidence":null}`), stateBody)
	assert.Equal(t, "b619885fb4454f32e32c1689bc47072373a99f2345802a3082cfacbac2164e79", hex.EncodeToString(stateDigestExpected[:]))
	assert.Equal(t, stateDigestExpected, stateDigestActual)
	nilStateDigest, err := makeAttemptStateDigest(coreBytes, AttemptMayHaveSubmitted, OutcomeLostFence, "blocked-floor-replaced", 19, nil, nil)
	require.NoError(t, err)
	emptyStateDigest, err := makeAttemptStateDigest(coreBytes, AttemptMayHaveSubmitted, OutcomeLostFence, "blocked-floor-replaced", 19, []byte{}, nil)
	require.NoError(t, err)
	assert.NotEqual(t, nilStateDigest, emptyStateDigest)

	stored := storedAttempt{core: attemptCoreWire{AttemptID: bytes.Clone(attemptID[:])}, coreBytes: coreBytes, lifecycle: AttemptMayHaveSubmitted, outcome: OutcomeLostFence, blocked: "blocked-floor-replaced"}
	abandonStore := Store{databaseID: databaseID}
	abandonToken := token
	evidence := []byte{0x00, 0xff, '<', '>', '&', 0x01}
	abandon, err := abandonStore.makeAbandonConfirmation(stored, stateSnapshot{}, abandonToken, OutcomeLostFence, evidence)
	require.NoError(t, err)
	coreDigest := oracleDomainHash("systems.lamb.dottie.publication-attempt-core.v1", coreBytes)
	abandonBody := oracleCanonicalJSON(t, wireOracleAbandonConfirmation{Version: 1, DatabaseID: bytes.Clone(databaseID[:]), MutationToken: bytes.Clone(abandonToken[:]), AttemptID: bytes.Clone(attemptID[:]), CandidateDigest: bytes.Clone(coreDigest[:]), Floor: nil, Lifecycle: string(AttemptMayHaveSubmitted), Outcome: string(OutcomeLostFence), Blocked: "blocked-floor-replaced", Evidence: bytes.Clone(evidence), ReferenceReleased: true, Warning: AbandonWarning})
	abandonHash := oracleDomainHash("systems.lamb.dottie.local-attempt-abandon.v1", abandonBody)
	assert.Equal(t, []byte(`{"version":1,"databaseId":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=","mutationToken":"biFIwUbOVjSwQqmFtMo+1TL/TyTzsFzjeBGdg1LboLM=","attemptId":"EBESExQVFhcYGRobHB0eHw==","candidateDigest":"sl/0abm1Rx3gNkqUXpKRfwYj9hpy9nbHjWdTdX938SQ=","floor":null,"lifecycle":"may-have-submitted","outcome":"lost-fence","blocked":"blocked-floor-replaced","evidence":"AP88PiYB","referenceReleased":true,"warning":"local retirement does not retract provider bytes or securely erase local plaintext"}`), abandonBody)
	assert.Equal(t, "368a2755ef070c4a476ce1db0ccb3743ccdb9fe46e543fbfe9285db58adf58eb", hex.EncodeToString(abandonHash[:]))
	assert.Equal(t, abandonHash, abandon)

	proof := wireOracleEvidence{Version: 1, Role: "outcome", Scope: string(ViewScopeWholeRepository), ViewDigest: bytes.Clone(viewHash[:]), Origin: wireVectorBinding(binding), Context: wireVectorContext(contextValue), Head: []byte{1, 2, 0xff}, AttemptedKey: "0000000000000007", AttemptedRecord: []byte{3, 4}, PredecessorRecord: []byte{5}, Suffix: []wireOracleSnapshot{{Key: "0000000000000007", Raw: []byte{6, 7}}}, Outcome: string(OutcomeLostFence)}
	var firstConflictStateDigest [32]byte
	copy(firstConflictStateDigest[:], oracleBytes(0xc0, 32))
	conflictBody := oracleCanonicalJSON(t, wireOracleFirstConflict{Version: 1, AttemptID: bytes.Clone(attemptID[:]), CoreDigest: bytes.Clone(coreDigest[:]), EventOrdinal: 5, MutationRevision: 19, EventStateDigest: bytes.Clone(firstConflictStateDigest[:]), Blocked: "blocked-floor-replaced", Proof: proof})
	conflictID := oracleDomainHash("systems.lamb.dottie.publication-attempt-first-conflict.v1", conflictBody)
	conflictDigest := oracleDomainHash("systems.lamb.dottie.publication-attempt-evidence.v1", conflictBody)
	actualConflict, err := makeFirstConflictRecord(stored, encodeOracleProof(t, proof), 5, 19, firstConflictStateDigest, "blocked-floor-replaced")
	require.NoError(t, err)
	assert.Equal(t, conflictBody, actualConflict.Body)
	assert.Equal(t, "e6b62bce5b16ff57787149b273bfee588ef3edd4f6c0845ca6dfdc23d276ff92", hex.EncodeToString(conflictID[:]))
	assert.Equal(t, conflictID, actualConflict.ID)
	assert.Equal(t, conflictDigest[:], actualConflict.Digest)
}

func TestAttemptWireDecodersRejectMalformedVectors(t *testing.T) {
	valid := attemptCoreWire{Version: 1, AttemptID: bytes.Repeat([]byte{1}, 16), DatabaseID: bytes.Repeat([]byte{2}, 32), SnapshotCID: []byte{3}, HeadCID: []byte{4}, BlobCID: []byte{5}, CandidateConfirmation: bytes.Repeat([]byte{6}, 32), InitialViewDigest: bytes.Repeat([]byte{7}, 32)}
	encoded, err := encodeAttemptCore(valid)
	require.NoError(t, err)
	decoded, err := decodeAttemptCore(encoded)
	require.NoError(t, err)
	assert.Equal(t, valid, decoded)

	wrongVersion := valid
	wrongVersion.Version = 2
	wrongVersionBytes, err := encodeAttemptCore(wrongVersion)
	require.NoError(t, err)
	_, err = decodeAttemptCore(wrongVersionBytes)
	require.Error(t, err)
	wrongDatabaseID := valid
	wrongDatabaseID.DatabaseID = wrongDatabaseID.DatabaseID[:31]
	wrongDatabaseIDBytes, err := encodeAttemptCore(wrongDatabaseID)
	require.NoError(t, err)
	_, err = decodeAttemptCore(wrongDatabaseIDBytes)
	require.Error(t, err)
	wrongConfirmationLength := valid
	wrongConfirmationLength.CandidateConfirmation = wrongConfirmationLength.CandidateConfirmation[:31]
	wrongConfirmationBytes, err := encodeAttemptCore(wrongConfirmationLength)
	require.NoError(t, err)
	_, err = decodeAttemptCore(wrongConfirmationBytes)
	require.Error(t, err)

	var event attemptEventWire
	assert.Error(t, strictJSON([]byte(`{"version":1,"ordinal":1,"ordinal":2,"kind":"created","previousDigest":null,"evidence":null,"stateDigest":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`), &event))
	assert.Error(t, strictJSON([]byte{0xff}, &event))
	assert.Error(t, strictJSON([]byte(`{"version":1,"ordinal":4294967296,"kind":"created","previousDigest":null,"evidence":null,"stateDigest":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`), &event))
}

func ptrWireVectorFloor(floor Floor) *wireOracleFloor {
	wire := wireVectorFloor(floor)
	return &wire
}

func oracleReview(review LocalReviewContext) wireOracleReview {
	return wireOracleReview{SelectionDigest: bytes.Clone(review.SelectionDigest[:]), SelectionRevision: review.SelectionRevision, ApprovalDigest: bytes.Clone(review.ApprovalDigest[:]), ApprovalRevision: review.ApprovalRevision}
}

func encodeOracleProof(t *testing.T, proof wireOracleEvidence) []byte {
	t.Helper()
	return oracleCanonicalJSON(t, proof)
}
