package state

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetentionDeclarationBelowPolicyFloorIsPersisted(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	declaration := RetentionDeclaration{
		Vault: [32]byte{40}, DeviceID: "device-a", PolicyDigest: [32]byte{9}, RetentionFloor: 1,
		RecoveryPoints: []RetentionRecoveryPoint{{Epoch: 1, SnapshotCID: []byte("snapshot-one")}}, DeclaredAt: 100,
	}
	stored, err := store.PutRetentionDeclaration(context.Background(), declaration)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), stored.RetentionFloor)
	persisted, err := store.RetentionDeclaration(context.Background(), declaration.Vault, declaration.DeviceID)
	require.NoError(t, err)
	assert.Equal(t, stored, persisted)
}

func TestRetentionDeclarationReplacesCurrentAndKeepsHistory(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	vaultID := [32]byte{41}
	first := RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{1}, RetentionFloor: 2,
		RecoveryPoints: []RetentionRecoveryPoint{{Epoch: 2, SnapshotCID: []byte("snapshot-two")}}, DeclaredAt: 100,
	}
	storedFirst, err := store.PutRetentionDeclaration(context.Background(), first)
	require.NoError(t, err)
	assert.Zero(t, storedFirst.PreviousDeclarationDigest)
	assert.Equal(t, int64(-1), storedFirst.PreviousDeclaredAt)

	second := RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{2}, RetentionFloor: 3,
		RecoveryPoints: []RetentionRecoveryPoint{{Epoch: 3, SnapshotCID: []byte("snapshot-three")}}, DeclaredAt: 200,
	}
	storedSecond, err := store.PutRetentionDeclaration(context.Background(), second)
	require.NoError(t, err)
	assert.NotEqual(t, storedFirst.DeclarationDigest, storedSecond.DeclarationDigest)
	assert.Equal(t, storedFirst.DeclarationDigest, storedSecond.PreviousDeclarationDigest)
	assert.Equal(t, storedFirst.DeclaredAt, storedSecond.PreviousDeclaredAt)

	current, err := store.RetentionDeclaration(context.Background(), vaultID, "device-a")
	require.NoError(t, err)
	assert.Equal(t, storedSecond, current)
	assert.Equal(t, []RetentionRecoveryPoint{{Epoch: 3, SnapshotCID: []byte("snapshot-three")}}, current.RecoveryPoints)
	history, err := store.RetentionDeclarationHistory(context.Background(), vaultID, "device-a")
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, int64(1), history[0].Revision)
	assert.Equal(t, storedFirst.DeclarationDigest, history[0].DeclarationDigest)
	assert.Equal(t, storedFirst.RecoveryPoints, history[0].RecoveryPoints)
}

func TestRetentionPruneDryRunAndApplyOnlyDeletesUnreferencedAndExpiredMaterial(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	ctx := context.Background()
	vaultID := [32]byte{42}
	boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("boundary-snapshot")}
	olderPoint := RetentionRecoveryPoint{Epoch: 1, SnapshotCID: []byte("older-snapshot")}
	declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{olderPoint, boundary}
	storedDeclaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	declaration = storedDeclaration
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
	}))

	basePayload := []byte("base payload")
	baseRecord, err := store.PutAppliedBase(ctx, BaseRecord{
		Identity: fileIdentity("base.toml"), Fingerprint: NewFingerprint("present", model.FileRegular, 0o600, "", "", "", basePayload), RecordedAt: 1,
	}, basePayload)
	require.NoError(t, err)
	intentPayload := []byte("intent payload")
	intent, err := store.AppendIntent(ctx, Intent{ID: "intent", Identity: fileIdentity("intent.toml"), State: "pending", CreatedAt: 1}, intentPayload)
	require.NoError(t, err)
	localConflict := []byte("conflict local")
	remoteConflict := []byte("conflict remote")
	conflict, err := store.RecordConflict(ctx, Conflict{ID: "conflict", Identity: fileIdentity("conflict.toml"), State: "open", CreatedAt: 1}, localConflict, remoteConflict)
	require.NoError(t, err)

	aged, live := appendRetentionJournal(t, store, "aged-backup", 10), appendRetentionJournal(t, store, "live-backup", time.Now().Unix())
	now := time.Unix(10, 0).Add(JournalBackupRetention)
	planRequest := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: now}
	unreferencedPayload := []byte("unreferenced")
	unreferencedRef := storeUnreferencedPayload(t, store, unreferencedPayload)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, olderPoint, []string{unreferencedRef}, []string{aged.BackupRef}))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, nil, nil))
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	declaration, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	planRequest.DeviceID = declaration.DeviceID
	expectedPayloads := []string{unreferencedRef, aged.BackupRef}
	sort.Strings(expectedPayloads)

	plan, err := store.PlanRetentionPrune(ctx, planRequest)
	require.NoError(t, err)
	assert.Equal(t, expectedPayloads, plan.PayloadReferences)
	assert.Equal(t, []string{"aged-backup"}, plan.ExpiredBackupIDs)
	assert.Equal(t, RetentionPruneScope, plan.EpochScope)
	var eligiblePayload, eligibleBackup *RetentionPruneCandidate
	for index := range plan.Candidates {
		candidate := &plan.Candidates[index]
		if candidate.Kind == RetentionPruneCandidatePayload && candidate.Reference == unreferencedRef {
			eligiblePayload = candidate
		}
		if candidate.Kind == RetentionPruneCandidateBackup && candidate.JournalID == aged.ID {
			eligibleBackup = candidate
		}
	}
	require.NotNil(t, eligiblePayload)
	assert.True(t, eligiblePayload.Eligible)
	assert.Equal(t, []uint64{olderPoint.Epoch}, eligiblePayload.RecoveryPointEpochs)
	assert.Contains(t, eligiblePayload.Reasons, "unreferenced by applied base")
	assert.Contains(t, eligiblePayload.Reasons, "unreferenced by outbound intent")
	assert.Contains(t, eligiblePayload.Reasons, "unreferenced by conflict")
	assert.Contains(t, eligiblePayload.Reasons, "not tied to a retained recovery point")
	assert.Contains(t, eligiblePayload.Reasons, "all associated recovery-point epochs are below the boundary")
	require.NotNil(t, eligibleBackup)
	assert.True(t, eligibleBackup.Eligible)
	assert.Equal(t, []uint64{olderPoint.Epoch}, eligibleBackup.RecoveryPointEpochs)
	assert.Contains(t, eligibleBackup.Reasons, "journal backup age bound elapsed")
	assert.Contains(t, eligibleBackup.Reasons, "not tied to a retained recovery point")
	for _, reference := range plan.PayloadReferences {
		_, err := store.Payload(reference)
		require.NoError(t, err, "dry run deleted %s", reference)
	}
	journalBefore, err := store.JournalEntries(ctx, "target")
	require.NoError(t, err)
	for _, entry := range journalBefore {
		if entry.ID == aged.ID {
			assert.Equal(t, aged.BackupRef, entry.BackupRef, "dry run detached an expired backup")
		}
	}
	assert.ErrorIs(t, func() error { _, err := store.ApplyRetentionPrune(ctx, planRequest, false); return err }(), ErrRetentionConfirmationRequired)

	report, err := store.ApplyRetentionPrune(ctx, planRequest, true)
	require.NoError(t, err)
	assert.Equal(t, expectedPayloads, report.DeletedPayloads)
	assert.Equal(t, []string{"aged-backup"}, report.PrunedBackupIDs)
	assert.Equal(t, RetentionPruneScope, report.EpochScope)
	for _, reference := range expectedPayloads {
		_, err := store.Payload(reference)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	for _, reference := range []string{baseRecord.PayloadRef, intent.PayloadRef, conflict.LocalPayloadRef, conflict.RemotePayloadRef, live.BackupRef} {
		payload, err := store.Payload(reference)
		require.NoError(t, err, "referenced payload %s was deleted", reference)
		assert.NotEmpty(t, payload)
	}
	journal, err := store.JournalEntries(ctx, "target")
	require.NoError(t, err)
	for _, entry := range journal {
		switch entry.ID {
		case "aged-backup":
			assert.Empty(t, entry.BackupRef)
		case "live-backup":
			assert.Equal(t, live.BackupRef, entry.BackupRef)
		}
	}
}

func TestRetentionPrunePreservesMaterialTiedToRetainedRecoveryPoint(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	ctx := context.Background()
	vaultID := [32]byte{49}
	boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("boundary-snapshot")}
	newerUnretainedPoint := RetentionRecoveryPoint{Epoch: 3, SnapshotCID: []byte("newer-unretained-snapshot")}
	retainedPoint := RetentionRecoveryPoint{Epoch: 4, SnapshotCID: []byte("retained-snapshot")}
	declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary, newerUnretainedPoint, retainedPoint}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
	}))

	oldPayloadRef := storeUnreferencedPayload(t, store, []byte("old retained snapshot payload"))
	newerPayloadRef := storeUnreferencedPayload(t, store, []byte("newer unretained snapshot payload"))
	aged := appendRetentionJournal(t, store, "aged-retained-backup", 10)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, nil, nil))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, newerUnretainedPoint, []string{newerPayloadRef}, nil))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, retainedPoint, []string{oldPayloadRef}, []string{aged.BackupRef}))
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary, retainedPoint}
	declaration.DeclaredAt++
	declaration, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	request := RetentionPruneRequest{
		Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary,
		Now: time.Unix(10, 0).Add(JournalBackupRetention),
	}
	plan, err := store.PlanRetentionPrune(ctx, request)
	require.NoError(t, err)
	assert.NotContains(t, plan.PayloadReferences, oldPayloadRef)
	assert.NotContains(t, plan.PayloadReferences, newerPayloadRef)
	assert.NotContains(t, plan.ExpiredBackupIDs, aged.ID)
	var payloadCandidate, newerCandidate, backupCandidate *RetentionPruneCandidate
	for index := range plan.Candidates {
		candidate := &plan.Candidates[index]
		if candidate.Kind == RetentionPruneCandidatePayload && candidate.Reference == oldPayloadRef {
			payloadCandidate = candidate
		}
		if candidate.Kind == RetentionPruneCandidatePayload && candidate.Reference == newerPayloadRef {
			newerCandidate = candidate
		}
		if candidate.Kind == RetentionPruneCandidateBackup && candidate.JournalID == aged.ID {
			backupCandidate = candidate
		}
	}
	require.NotNil(t, payloadCandidate)
	assert.False(t, payloadCandidate.Eligible)
	assert.Equal(t, []uint64{retainedPoint.Epoch}, payloadCandidate.RecoveryPointEpochs)
	assert.Contains(t, payloadCandidate.Reasons, "tied to a retained recovery point")
	require.NotNil(t, newerCandidate)
	assert.False(t, newerCandidate.Eligible)
	assert.Equal(t, []uint64{newerUnretainedPoint.Epoch}, newerCandidate.RecoveryPointEpochs)
	assert.Contains(t, newerCandidate.Reasons, "associated recovery-point epoch is at or above the boundary")
	require.NotNil(t, backupCandidate)
	assert.False(t, backupCandidate.Eligible)
	assert.Contains(t, backupCandidate.Reasons, "tied to a retained recovery point")

	report, err := store.ApplyRetentionPrune(ctx, request, true)
	require.NoError(t, err)
	assert.Empty(t, report.DeletedPayloads)
	assert.Empty(t, report.PrunedBackupIDs)
	_, err = store.Payload(oldPayloadRef)
	assert.NoError(t, err)
	_, err = store.Payload(newerPayloadRef)
	assert.NoError(t, err)
	journal, err := store.JournalEntries(ctx, "target")
	require.NoError(t, err)
	for _, entry := range journal {
		if entry.ID == aged.ID {
			assert.Equal(t, aged.BackupRef, entry.BackupRef)
		}
	}
}

func TestRetentionPruneRefusesWhenRecoveryPointMaterialInventoryIsUnknown(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{50}
	boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("boundary-snapshot")}
	declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
	}))
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.ErrorIs(t, err, ErrRetentionRecoveryPointInventoryUnknown)
	assert.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, nil, nil))
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.NoError(t, err)
}

func TestRetentionPruneRefusesWithoutExactVerifiedCheckpointBeforeDeleting(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{43}
	boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("boundary-snapshot")}
	declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
	_, err := store.PutRetentionDeclaration(context.Background(), declaration)
	require.NoError(t, err)
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("head"), ControlCID: []byte("control"),
	}))
	reference := storeUnreferencedPayload(t, store, []byte("keep on refusal"))
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}
	_, err = store.PlanRetentionPrune(context.Background(), request)
	assert.ErrorIs(t, err, ErrRetentionBoundaryNotVerified)
	_, err = store.ApplyRetentionPrune(context.Background(), request, true)
	assert.ErrorIs(t, err, ErrRetentionBoundaryNotVerified)
	_, err = store.Payload(reference)
	assert.NoError(t, err)
}

func TestRetentionPruneRefusesLiveHeadEpochBeforeDeleting(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{44}
	boundary := RetentionRecoveryPoint{Epoch: 3, SnapshotCID: []byte("head-snapshot")}
	declaration := testRetentionDeclaration(vaultID, boundary, 3, 1_700_000_000)
	_, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: boundary.Epoch, HeadCID: []byte("head"), ControlCID: []byte("control"),
	}))
	reference := storeUnreferencedPayload(t, store, []byte("keep live head"))
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.ErrorIs(t, err, ErrRetentionLiveHead)
	_, err = store.ApplyRetentionPrune(ctx, request, true)
	assert.ErrorIs(t, err, ErrRetentionLiveHead)
	_, err = store.Payload(reference)
	assert.NoError(t, err)
}

func TestRetentionPruneRefusesWhenLiveHeadIsUnobserved(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{45}
	boundary := RetentionRecoveryPoint{Epoch: 1, SnapshotCID: []byte("boundary")}
	declaration := testRetentionDeclaration(vaultID, boundary, 1, 1_700_000_000)
	_, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.ErrorIs(t, err, ErrRetentionLiveHead)
}

func TestRetentionPruneBoundaryRequiresMatchingPolicyDigest(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{46}
	boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("boundary")}
	declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
	_, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	wrongDigest := [32]byte{99}
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, wrongDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 4, HeadCID: []byte("head"), ControlCID: []byte("control"),
	}))
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.ErrorIs(t, err, ErrRetentionBoundaryNotVerified)
}

func TestRetentionPrunePreservesPayloadRetainedByAnotherVault(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	reference := storeUnreferencedPayload(t, store, []byte("shared retained payload"))
	request := configureRetentionPruneOwner(t, store, reference, false)
	registerRetainedMaterialForSubject(t, store, [32]byte{92}, "device-b", reference, false)

	plan, err := store.PlanRetentionPrune(ctx, request)
	require.NoError(t, err)
	assert.NotContains(t, plan.PayloadReferences, reference)
	for _, candidate := range plan.Candidates {
		if candidate.Kind == RetentionPruneCandidatePayload && candidate.Reference == reference {
			assert.False(t, candidate.Eligible)
			assert.Contains(t, candidate.Reasons, "tied to a retained recovery point")
		}
	}

	report, err := store.ApplyRetentionPrune(ctx, request, true)
	require.NoError(t, err)
	assert.NotContains(t, report.DeletedPayloads, reference)
	payload, err := store.Payload(reference)
	require.NoError(t, err)
	assert.Equal(t, []byte("shared retained payload"), payload)
}

func TestRetentionPrunePreservesJournalBackupRetainedByAnotherDevice(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	ctx := context.Background()
	entry := appendRetentionJournal(t, store, "shared-retained-backup", 10)
	request := configureRetentionPruneOwner(t, store, entry.BackupRef, true)
	registerRetainedMaterialForSubject(t, store, request.Vault, "device-b", entry.BackupRef, true)

	plan, err := store.PlanRetentionPrune(ctx, request)
	require.NoError(t, err)
	assert.NotContains(t, plan.ExpiredBackupIDs, entry.ID)
	for _, candidate := range plan.Candidates {
		if candidate.Kind == RetentionPruneCandidateBackup && candidate.JournalID == entry.ID {
			assert.False(t, candidate.Eligible)
			assert.Contains(t, candidate.Reasons, "tied to a retained recovery point")
		}
	}

	report, err := store.ApplyRetentionPrune(ctx, request, true)
	require.NoError(t, err)
	assert.NotContains(t, report.PrunedBackupIDs, entry.ID)
	assert.NotContains(t, report.DeletedPayloads, entry.BackupRef)
	payload, err := store.Payload(entry.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte(entry.ID+"-before"), payload)
	entries, err := store.JournalEntries(ctx, "target")
	require.NoError(t, err)
	for _, actual := range entries {
		if actual.ID == entry.ID {
			assert.Equal(t, entry.BackupRef, actual.BackupRef)
		}
	}
}

func TestRetentionMaterialRegistrationSerializesWithPruneUnlink(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	reference := storeUnreferencedPayload(t, store, []byte("payload pending prune"))
	request := configureRetentionPruneOwner(t, store, reference, false)
	otherVault := [32]byte{93}
	otherPoint := RetentionRecoveryPoint{Epoch: 9, SnapshotCID: []byte("other-retained-point")}
	_, err := store.PutRetentionDeclaration(ctx, RetentionDeclaration{
		Vault: otherVault, DeviceID: "device-b", PolicyDigest: [32]byte{7}, RetentionFloor: otherPoint.Epoch,
		RecoveryPoints: []RetentionRecoveryPoint{otherPoint}, DeclaredAt: 1_700_000_001,
	})
	require.NoError(t, err)

	store.mu.Lock()
	type pruneResult struct {
		report RetentionPruneReport
		err    error
	}
	pruned := make(chan pruneResult, 1)
	startedPruning := make(chan struct{})
	go func() {
		close(startedPruning)
		report, err := store.ApplyRetentionPrune(ctx, request, true)
		pruned <- pruneResult{report: report, err: err}
	}()
	<-startedPruning
	for store.payloadMu.TryLock() {
		store.payloadMu.Unlock()
		runtime.Gosched()
	}
	registered := make(chan error, 1)
	startedRegistration := make(chan struct{})
	go func() {
		close(startedRegistration)
		registered <- store.SetRetentionRecoveryPointMaterial(ctx, otherVault, "device-b", otherPoint, []string{reference}, nil)
	}()
	<-startedRegistration
	store.mu.Unlock()

	pruneOutcome := <-pruned
	require.NoError(t, pruneOutcome.err)
	assert.Equal(t, []string{reference}, pruneOutcome.report.DeletedPayloads)
	registrationErr := <-registered
	assert.ErrorIs(t, registrationErr, os.ErrNotExist)
	_, err = store.Payload(reference)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRetentionRegistrationWinsBeforePruneEligibility(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	reference := storeUnreferencedPayload(t, store, []byte("payload registered before prune"))
	request := configureRetentionPruneOwner(t, store, reference, false)
	otherVault := [32]byte{94}
	otherPoint := RetentionRecoveryPoint{Epoch: 9, SnapshotCID: []byte("other-retained-point")}
	_, err := store.PutRetentionDeclaration(ctx, RetentionDeclaration{
		Vault: otherVault, DeviceID: "device-b", PolicyDigest: [32]byte{7}, RetentionFloor: otherPoint.Epoch,
		RecoveryPoints: []RetentionRecoveryPoint{otherPoint}, DeclaredAt: 1_700_000_001,
	})
	require.NoError(t, err)

	store.mu.Lock()
	registered := make(chan error, 1)
	startedRegistration := make(chan struct{})
	go func() {
		close(startedRegistration)
		registered <- store.SetRetentionRecoveryPointMaterial(ctx, otherVault, "device-b", otherPoint, []string{reference}, nil)
	}()
	<-startedRegistration
	for store.payloadMu.TryLock() {
		store.payloadMu.Unlock()
		runtime.Gosched()
	}
	type pruneResult struct {
		report RetentionPruneReport
		err    error
	}
	pruned := make(chan pruneResult, 1)
	startedPruning := make(chan struct{})
	go func() {
		close(startedPruning)
		report, err := store.ApplyRetentionPrune(ctx, request, true)
		pruned <- pruneResult{report: report, err: err}
	}()
	<-startedPruning
	store.mu.Unlock()

	registrationErr := <-registered
	require.NoError(t, registrationErr)
	pruneOutcome := <-pruned
	require.NoError(t, pruneOutcome.err)
	assert.Empty(t, pruneOutcome.report.DeletedPayloads)
	payload, err := store.Payload(reference)
	require.NoError(t, err)
	assert.Equal(t, []byte("payload registered before prune"), payload)
}

func configureRetentionPruneOwner(t *testing.T, store *Store, reference string, asBackup bool) RetentionPruneRequest {
	t.Helper()
	ctx := context.Background()
	vaultID := [32]byte{91}
	boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("owner-boundary")}
	olderPoint := RetentionRecoveryPoint{Epoch: 1, SnapshotCID: []byte("owner-old-point")}
	declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{olderPoint, boundary}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("owner-live-head"), ControlCID: []byte("owner-live-control"),
	}))
	payloadReferences, backupReferences := []string{reference}, []string(nil)
	if asBackup {
		payloadReferences, backupReferences = nil, []string{reference}
	}
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, olderPoint, payloadReferences, backupReferences))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, nil, nil))
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	declaration, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	return RetentionPruneRequest{
		Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Unix(10, 0).Add(JournalBackupRetention),
	}
}

func registerRetainedMaterialForSubject(t *testing.T, store *Store, vault [32]byte, deviceID, reference string, asBackup bool) {
	t.Helper()
	ctx := context.Background()
	point := RetentionRecoveryPoint{Epoch: 9, SnapshotCID: []byte("other-retained-point")}
	_, err := store.PutRetentionDeclaration(ctx, RetentionDeclaration{
		Vault: vault, DeviceID: deviceID, PolicyDigest: [32]byte{7}, RetentionFloor: point.Epoch,
		RecoveryPoints: []RetentionRecoveryPoint{point}, DeclaredAt: 1_700_000_001,
	})
	require.NoError(t, err)
	payloadReferences, backupReferences := []string{reference}, []string(nil)
	if asBackup {
		payloadReferences, backupReferences = nil, []string{reference}
	}
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vault, deviceID, point, payloadReferences, backupReferences))
}

func appendRetentionJournal(t *testing.T, store *Store, id string, createdAt int64) JournalEntry {
	t.Helper()
	ctx := context.Background()
	preimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte(id+"-before"))
	postimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte(id+"-after"))
	entry, err := store.AppendJournal(ctx, JournalEntry{
		ID: id, Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity: fileIdentity(id + ".toml"), Preimage: preimage, Postimage: postimage, CreatedAt: createdAt,
	}, []byte(id+"-before"))
	require.NoError(t, err)
	require.NoError(t, store.TransitionJournalEntry(ctx, id, "pending", "applied", JournalStageVerified))
	return entry
}

func testRetentionDeclaration(vaultID [32]byte, boundary RetentionRecoveryPoint, floor uint64, declaredAt int64) RetentionDeclaration {
	return RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{7}, RetentionFloor: floor,
		RecoveryPoints: []RetentionRecoveryPoint{{Epoch: boundary.Epoch, SnapshotCID: bytes.Clone(boundary.SnapshotCID)}}, DeclaredAt: declaredAt,
	}
}

func testRetentionCheckpoint(t *testing.T, vaultID [32]byte, boundary RetentionRecoveryPoint, policyDigest [32]byte) VaultCheckpoint {
	t.Helper()
	checkpoint := VaultCheckpoint{
		Vault: vaultID, Anchor: [32]byte{8}, SnapshotCID: bytes.Clone(boundary.SnapshotCID), Epoch: boundary.Epoch,
		PolicyDigest: policyDigest, RecordedAt: 1_700_000_000,
	}
	checkpoint.ControlBytes = testVaultControlBytes(vaultID, boundary.Epoch, policyDigest, boundary.SnapshotCID)
	checkpoint.ControlCID = testRawCID(t, checkpoint.ControlBytes)
	return checkpoint
}

func storeUnreferencedPayload(t *testing.T, store *Store, payload []byte) string {
	t.Helper()
	reference, _ := payloadReference(payload)
	require.NoError(t, store.storePayload(reference, payload))
	return reference
}

func TestRetentionPrunePlanSortsPayloads(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{47}
	boundary := RetentionRecoveryPoint{Epoch: 2, SnapshotCID: []byte("boundary")}
	olderPoint := RetentionRecoveryPoint{Epoch: 1, SnapshotCID: []byte("older")}
	declaration := testRetentionDeclaration(vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{olderPoint, boundary}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 4, HeadCID: []byte("head"), ControlCID: []byte("control"),
	}))
	refs := []string{
		storeUnreferencedPayload(t, store, []byte("second")),
		storeUnreferencedPayload(t, store, []byte("first")),
	}
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, olderPoint, refs, nil))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, nil, nil))
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	declaration, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}
	plan, err := store.PlanRetentionPrune(ctx, request)
	require.NoError(t, err)
	sort.Strings(refs)
	assert.Equal(t, refs, plan.PayloadReferences)
}

func TestRetentionDeclarationInvalidInputDoesNotPersist(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	_, err := store.PutRetentionDeclaration(context.Background(), RetentionDeclaration{
		Vault: [32]byte{48}, DeviceID: "device-a", PolicyDigest: [32]byte{1}, DeclaredAt: 1,
		RecoveryPoints: []RetentionRecoveryPoint{{Epoch: 1, SnapshotCID: []byte("same")}, {Epoch: 1, SnapshotCID: []byte("same")}},
	})
	assert.Error(t, err)
	_, err = store.RetentionDeclaration(context.Background(), [32]byte{48}, "device-a")
	assert.ErrorIs(t, err, ErrRetentionDeclarationNotFound)
}
