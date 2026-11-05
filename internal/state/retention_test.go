package state

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
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
	vaultID := [32]byte{40}
	point := testRetentionPoint(t, vaultID, 1, []byte("snapshot-one"), [32]byte{9})
	declaration := RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{9}, RetentionFloor: 1,
		RecoveryPoints: []RetentionRecoveryPoint{point}, DeclaredAt: 100,
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
	firstPoint := testRetentionPoint(t, vaultID, 2, []byte("snapshot-two"), [32]byte{1})
	first := RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{1}, RetentionFloor: 2,
		RecoveryPoints: []RetentionRecoveryPoint{firstPoint}, DeclaredAt: 100,
	}
	storedFirst, err := store.PutRetentionDeclaration(context.Background(), first)
	require.NoError(t, err)
	assert.Zero(t, storedFirst.PreviousDeclarationDigest)
	assert.Equal(t, int64(-1), storedFirst.PreviousDeclaredAt)

	secondPoint := testRetentionPoint(t, vaultID, 3, []byte("snapshot-three"), [32]byte{2})
	second := RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{2}, RetentionFloor: 3,
		RecoveryPoints: []RetentionRecoveryPoint{secondPoint}, DeclaredAt: 200,
	}
	storedSecond, err := store.PutRetentionDeclaration(context.Background(), second)
	require.NoError(t, err)
	assert.NotEqual(t, storedFirst.DeclarationDigest, storedSecond.DeclarationDigest)
	assert.Equal(t, storedFirst.DeclarationDigest, storedSecond.PreviousDeclarationDigest)
	assert.Equal(t, storedFirst.DeclaredAt, storedSecond.PreviousDeclaredAt)

	current, err := store.RetentionDeclaration(context.Background(), vaultID, "device-a")
	require.NoError(t, err)
	assert.Equal(t, storedSecond, current)
	assert.Equal(t, []RetentionRecoveryPoint{secondPoint}, current.RecoveryPoints)
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
	unreferencedPayload := []byte("unreferenced")
	boundaryPayload := []byte("boundary snapshot body")
	boundary := testRetentionPoint(t, vaultID, 2, boundaryPayload, [32]byte{7})
	olderPoint := testRetentionPoint(t, vaultID, 1, unreferencedPayload, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
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
	unreferencedRef := storeUnreferencedPayload(t, store, unreferencedPayload)
	boundaryRef := storeUnreferencedPayload(t, store, boundaryPayload)
	unboundPreimage := []byte("aged-backup-before")
	unboundAssociationRef := storeUnreferencedPayload(t, store, unboundPreimage)
	assert.Equal(t, aged.BackupRef, unboundAssociationRef)
	require.NoError(t, store.PutVaultSelection(ctx, VaultSelection{Vault: vaultID, DeviceID: declaration.DeviceID, RecordedAt: 1}))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, olderPoint, []string{unreferencedRef}, nil))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, []string{boundaryRef}, nil))
	boundAged := appendBoundRetentionJournal(t, store, vaultID, declaration.DeviceID, olderPoint, "bound-aged-backup", 10)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, olderPoint, []string{unreferencedRef}, []string{unboundAssociationRef, boundAged.BackupRef}))
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	declaration, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	planRequest.DeviceID = declaration.DeviceID
	expectedPayloads := []string{unreferencedRef, boundAged.BackupRef}
	sort.Strings(expectedPayloads)

	plan, err := store.PlanRetentionPrune(ctx, planRequest)
	require.NoError(t, err)
	assert.Equal(t, expectedPayloads, plan.PayloadReferences)
	assert.Equal(t, []string{boundAged.ID}, plan.ExpiredBackupIDs)
	assert.Equal(t, RetentionPruneScope, plan.EpochScope)
	var eligiblePayload, eligibleBackup, unboundBackup *RetentionPruneCandidate
	for index := range plan.Candidates {
		candidate := &plan.Candidates[index]
		if candidate.Kind == RetentionPruneCandidatePayload && candidate.Reference == unreferencedRef {
			eligiblePayload = candidate
		}
		if candidate.Kind == RetentionPruneCandidateBackup && candidate.JournalID == boundAged.ID {
			eligibleBackup = candidate
		}
		if candidate.Kind == RetentionPruneCandidateBackup && candidate.JournalID == aged.ID {
			unboundBackup = candidate
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
	require.NotNil(t, unboundBackup)
	assert.False(t, unboundBackup.Eligible, "a digest-level old association cannot authorize a fresh version-1 unbound row")
	assert.Contains(t, unboundBackup.Reasons, "journal backup has no retention binding")
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
	assert.Equal(t, []string{boundAged.ID}, report.PrunedBackupIDs)
	assert.Equal(t, RetentionPruneScope, report.EpochScope)
	for _, reference := range expectedPayloads {
		_, err := store.Payload(reference)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	unboundPayload, err := store.Payload(aged.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, unboundPreimage, unboundPayload)
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
			assert.Equal(t, aged.BackupRef, entry.BackupRef)
		case boundAged.ID:
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
	boundaryPayload := []byte("boundary retained snapshot body")
	newerPayload := []byte("newer unretained snapshot payload")
	retainedPayload := []byte("old retained snapshot payload")
	boundary := testRetentionPoint(t, vaultID, 2, boundaryPayload, [32]byte{7})
	newerUnretainedPoint := testRetentionPoint(t, vaultID, 3, newerPayload, [32]byte{7})
	retainedPoint := testRetentionPoint(t, vaultID, 4, retainedPayload, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary, newerUnretainedPoint, retainedPoint}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
	}))

	oldPayloadRef := storeUnreferencedPayload(t, store, retainedPayload)
	newerPayloadRef := storeUnreferencedPayload(t, store, newerPayload)
	boundaryRef := storeUnreferencedPayload(t, store, boundaryPayload)
	aged := appendRetentionJournal(t, store, "aged-retained-backup", 10)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, []string{boundaryRef}, nil))
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
	boundaryBody := []byte("boundary snapshot")
	boundary := testRetentionPoint(t, vaultID, 2, boundaryBody, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("live-head"), ControlCID: []byte("live-control"),
	}))
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: declaration.DeviceID, Boundary: boundary, Now: time.Now()}
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.ErrorIs(t, err, ErrRetentionRecoveryPointInventoryUnknown)
	boundaryRef := storeUnreferencedPayload(t, store, boundaryBody)
	assert.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, []string{boundaryRef}, nil))
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.NoError(t, err)
}

func TestRetentionPruneRefusesWithoutExactVerifiedCheckpointBeforeDeleting(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{43}
	boundary := testRetentionPoint(t, vaultID, 2, []byte("boundary snapshot"), [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
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
	boundary := testRetentionPoint(t, vaultID, 3, []byte("head snapshot"), [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 3, 1_700_000_000)
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
	boundary := testRetentionPoint(t, vaultID, 1, []byte("boundary"), [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 1, 1_700_000_000)
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
	boundary := testRetentionPoint(t, vaultID, 2, []byte("boundary"), [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
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
	otherPayload, err := store.Payload(reference)
	require.NoError(t, err)
	otherPoint := testRetentionPoint(t, otherVault, 9, otherPayload, [32]byte{7})
	_, err = store.PutRetentionDeclaration(ctx, RetentionDeclaration{
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
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for store.payloadMu.TryLock() {
		store.payloadMu.Unlock()
		select {
		case outcome := <-pruned:
			store.mu.Unlock()
			require.NoError(t, outcome.err)
			t.Fatal("prune completed without acquiring the payload lock")
		case <-deadline.C:
			store.mu.Unlock()
			t.Fatal("prune did not acquire the payload lock")
		default:
			runtime.Gosched()
		}
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
	otherPayload := []byte("payload registered before prune")
	otherPoint := testRetentionPoint(t, otherVault, 9, otherPayload, [32]byte{7})
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
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for store.payloadMu.TryLock() {
		store.payloadMu.Unlock()
		select {
		case registrationErr := <-registered:
			store.mu.Unlock()
			require.NoError(t, registrationErr)
			t.Fatal("registration completed without acquiring the payload lock")
		case <-deadline.C:
			store.mu.Unlock()
			t.Fatal("registration did not acquire the payload lock")
		default:
			runtime.Gosched()
		}
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
	boundaryPayload := []byte("owner boundary body")
	boundary := testRetentionPoint(t, vaultID, 2, boundaryPayload, [32]byte{7})
	var olderBody []byte
	if asBackup {
		olderBody = []byte("owner older snapshot body")
	} else {
		var err error
		olderBody, err = store.Payload(reference)
		require.NoError(t, err)
	}
	olderPoint := testRetentionPoint(t, vaultID, 1, olderBody, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{olderPoint, boundary}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 5, HeadCID: []byte("owner-live-head"), ControlCID: []byte("owner-live-control"),
	}))
	payloadReferences, backupReferences := []string{reference}, []string(nil)
	if asBackup {
		payloadReferences = []string{storeUnreferencedPayload(t, store, olderBody)}
		backupReferences = []string{reference}
	}
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, olderPoint, payloadReferences, backupReferences))
	boundaryRef := storeUnreferencedPayload(t, store, boundaryPayload)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, []string{boundaryRef}, nil))
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
	payload, err := store.Payload(reference)
	require.NoError(t, err)
	body := payload
	if asBackup {
		body = []byte("retained snapshot body")
	}
	point := testRetentionPoint(t, vault, 9, body, [32]byte{7})
	_, err = store.PutRetentionDeclaration(ctx, RetentionDeclaration{
		Vault: vault, DeviceID: deviceID, PolicyDigest: [32]byte{7}, RetentionFloor: point.Epoch,
		RecoveryPoints: []RetentionRecoveryPoint{point}, DeclaredAt: 1_700_000_001,
	})
	require.NoError(t, err)
	payloadReferences, backupReferences := []string{reference}, []string(nil)
	if asBackup {
		payloadReferences = []string{storeUnreferencedPayload(t, store, body)}
		backupReferences = []string{reference}
	}
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vault, deviceID, point, payloadReferences, backupReferences))
}

func appendRetentionJournal(t *testing.T, store *Store, id string, createdAt int64) JournalEntry {
	t.Helper()
	return appendUnboundRetentionJournal(t, store, id, []byte(id+"-before"), createdAt)
}

func appendUnboundRetentionJournal(t *testing.T, store *Store, id string, preimage []byte, createdAt int64) JournalEntry {
	t.Helper()
	ctx := context.Background()
	preimageFingerprint := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", preimage)
	postimage := []byte(id + "-after")
	entry, err := store.AppendJournal(ctx, JournalEntry{
		ID: id, Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity: fileIdentity(id + ".toml"), Preimage: preimageFingerprint,
		Postimage: NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", postimage), CreatedAt: createdAt,
	}, preimage)
	require.NoError(t, err)
	require.NoError(t, store.TransitionJournalEntry(ctx, id, "pending", "applied", JournalStageVerified))
	return entry
}

func testRetentionPoint(t *testing.T, vaultID [32]byte, epoch uint64, body []byte, policyDigest [32]byte) RetentionRecoveryPoint {
	t.Helper()
	snapshotCID := testRawCID(t, body)
	controlCID := testRawCID(t, testVaultControlBytes(vaultID, epoch, policyDigest, snapshotCID))
	return RetentionRecoveryPoint{
		Epoch: epoch, SnapshotCID: snapshotCID, PolicyDigest: policyDigest, ControlCID: controlCID,
	}
}

func testRetentionDeclaration(t *testing.T, vaultID [32]byte, boundary RetentionRecoveryPoint, floor uint64, declaredAt int64) RetentionDeclaration {
	t.Helper()
	return RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{7}, RetentionFloor: floor,
		RecoveryPoints: []RetentionRecoveryPoint{{
			Epoch: boundary.Epoch, SnapshotCID: bytes.Clone(boundary.SnapshotCID),
			PolicyDigest: boundary.PolicyDigest, ControlCID: bytes.Clone(boundary.ControlCID),
		}}, DeclaredAt: declaredAt,
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

func TestRetentionPrunePreservesUnboundSettingAndRedactsBoundSettingBackup(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	require.NoError(t, store.PutTarget(ctx, TargetDescriptor{ID: "settings", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 1}))
	vaultID := [32]byte{0xA6}
	deviceID := "device-a"
	require.NoError(t, store.PutVaultSelection(ctx, VaultSelection{Vault: vaultID, DeviceID: deviceID, RecordedAt: 1}))
	oldBody := []byte("old settings recovery point")
	boundaryBody := []byte("boundary settings recovery point")
	oldPoint := testRetentionPoint(t, vaultID, 1, oldBody, [32]byte{7})
	boundary := testRetentionPoint(t, vaultID, 2, boundaryBody, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, boundary.Epoch, 1_700_000_000)
	declaration.DeviceID = deviceID
	declaration.RecoveryPoints = []RetentionRecoveryPoint{oldPoint, boundary}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{Vault: vaultID, Epoch: 5, HeadCID: []byte("settings-live-head"), ControlCID: []byte("settings-live-control")}))
	oldBodyReference := storeUnreferencedPayload(t, store, oldBody)
	boundaryBodyReference := storeUnreferencedPayload(t, store, boundaryBody)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, oldPoint, []string{oldBodyReference}, nil))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, boundary, []string{boundaryBodyReference}, nil))

	unboundKey := model.EntryKey{TargetID: "settings", Source: model.SourceGNOME, SchemaID: "org.example.Settings", SettingsPath: "/", SettingKey: "enabled"}
	unboundPreimage := []byte("s\x00before")
	unboundEntry, err := store.AppendJournal(ctx, JournalEntry{
		ID: "setting-unbound", Operation: "setting-set", State: "pending", Stage: JournalStagePending,
		Identity: unboundKey, Preimage: NewSettingFingerprint(model.SettingPresent, "s", "before"),
		Postimage: NewSettingFingerprint(model.SettingPresent, "s", "after"), CreatedAt: 10,
	}, unboundPreimage)
	require.NoError(t, err)
	require.NoError(t, store.TransitionJournalEntry(ctx, unboundEntry.ID, "pending", "applied", JournalStageVerified))

	boundKey := unboundKey
	boundKey.SettingKey = "theme"
	boundPreimage := []byte("s\x00eligible-before")
	binding := &RetentionBinding{Vault: vaultID, Epoch: oldPoint.Epoch, SnapshotCID: bytes.Clone(oldPoint.SnapshotCID), PolicyDigest: oldPoint.PolicyDigest, ControlCID: bytes.Clone(oldPoint.ControlCID)}
	boundEntry, err := store.AppendJournal(ctx, JournalEntry{
		ID: "setting-bound-aged", Operation: "setting-set", State: "pending", Stage: JournalStagePending,
		Identity: boundKey, Preimage: NewSettingFingerprint(model.SettingPresent, "s", "eligible-before"),
		Postimage: NewSettingFingerprint(model.SettingPresent, "s", "after"), Retention: binding, CreatedAt: 10,
	}, boundPreimage)
	require.NoError(t, err)
	require.NoError(t, store.TransitionJournalEntry(ctx, boundEntry.ID, "pending", "applied", JournalStageVerified))
	unboundReference, _ := payloadReference(unboundPreimage)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, oldPoint, []string{oldBodyReference}, []string{unboundReference, boundEntry.BackupRef}))
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	declaration, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: deviceID, Boundary: boundary, Now: time.Unix(10, 0).Add(JournalBackupRetention)}

	report, err := store.ApplyRetentionPrune(ctx, request, true)
	require.NoError(t, err)
	assert.Equal(t, []string{boundEntry.ID}, report.PrunedBackupIDs)
	rows, err := store.JournalEntries(ctx, "settings")
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, row := range rows {
		switch row.ID {
		case unboundEntry.ID:
			assert.Equal(t, unboundEntry.BackupRef, row.BackupRef)
			assert.Equal(t, "s", row.Preimage.ValueType)
			assert.Equal(t, "before", row.Preimage.ValueText)
			assert.Equal(t, "s", row.Postimage.ValueType)
			assert.Equal(t, "after", row.Postimage.ValueText)
			payload, payloadErr := store.Payload(row.BackupRef)
			require.NoError(t, payloadErr)
			assert.Equal(t, unboundPreimage, payload)
		case boundEntry.ID:
			assert.Empty(t, row.BackupRef)
			assert.Empty(t, row.Preimage.ValueType)
			assert.Empty(t, row.Preimage.ValueText)
			assert.Empty(t, row.Postimage.ValueType)
			assert.Empty(t, row.Postimage.ValueText)
			_, payloadErr := store.Payload(boundEntry.BackupRef)
			assert.ErrorIs(t, payloadErr, os.ErrNotExist)
		}
	}
}

func TestMigrationLegacyAndJournalPruneEligibility(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	require.NoError(t, store.PutTarget(ctx, testDescriptor()))
	vaultID := [32]byte{0xA1}
	deviceID := "device-a"
	require.NoError(t, store.PutVaultSelection(ctx, VaultSelection{Vault: vaultID, DeviceID: deviceID, RecordedAt: 1}))
	oldPoint := testRetentionPoint(t, vaultID, 0, []byte("evicted point body"), [32]byte{7})
	boundary := testRetentionPoint(t, vaultID, 1, []byte("current point body"), [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 1, 1_700_000_000)
	declaration.DeviceID = deviceID
	declaration.RecoveryPoints = []RetentionRecoveryPoint{oldPoint, boundary}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{Vault: vaultID, Epoch: 2, HeadCID: []byte("live-head"), ControlCID: []byte("live-control")}))
	oldBodyReference := storeUnreferencedPayload(t, store, []byte("evicted point body"))
	boundaryBodyReference := storeUnreferencedPayload(t, store, []byte("current point body"))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, oldPoint, []string{oldBodyReference}, nil))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, boundary, []string{boundaryBodyReference}, nil))
	oldBackup := appendBoundRetentionJournal(t, store, vaultID, deviceID, oldPoint, "eligible-evicted-bound-backup", 1)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, oldPoint, []string{oldBodyReference}, []string{oldBackup.BackupRef}))
	retainedBackup := appendBoundRetentionJournal(t, store, vaultID, deviceID, boundary, "retained-bound-backup", 1)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, boundary, []string{boundaryBodyReference}, []string{retainedBackup.BackupRef}))
	unassociatedBackup := appendBoundRetentionJournal(t, store, vaultID, deviceID, boundary, "unassociated-bound-backup", 1)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, boundary, []string{boundaryBodyReference}, []string{retainedBackup.BackupRef}))
	legacyBackup := appendRetentionJournal(t, store, "legacy-unbound-backup", 1)
	require.NoError(t, store.withTx(ctx, func(tx *sql.Tx) error {
		_, updateErr := tx.ExecContext(ctx, "UPDATE apply_journal SET retention_binding_version = 0 WHERE id = ?", legacyBackup.ID)
		return updateErr
	}))
	legacyBackup.State = "applied"
	legacyBackup.Stage = JournalStageVerified
	legacyBackup.RetentionBindingVersion = 0
	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	_, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	now := time.Unix(1, 0).Add(JournalBackupRetention)
	request := RetentionPruneRequest{Vault: vaultID, DeviceID: deviceID, Boundary: boundary, Now: now}
	plan, err := store.PlanRetentionPrune(ctx, request)
	require.NoError(t, err)
	candidateFor := func(kind RetentionPruneCandidateKind, id string) *RetentionPruneCandidate {
		for index := range plan.Candidates {
			candidate := &plan.Candidates[index]
			if candidate.Kind == kind && (candidate.JournalID == id || candidate.Reference == id) {
				return candidate
			}
		}
		return nil
	}
	eligibleBound := candidateFor(RetentionPruneCandidateBackup, oldBackup.ID)
	require.NotNil(t, eligibleBound)
	assert.True(t, eligibleBound.Eligible)
	legacyCandidate := candidateFor(RetentionPruneCandidateBackup, legacyBackup.ID)
	require.NotNil(t, legacyCandidate)
	assert.False(t, legacyCandidate.Eligible)
	assert.Contains(t, legacyCandidate.Reasons, "legacy journal row has no retention-binding version")
	unassociatedCandidate := candidateFor(RetentionPruneCandidateBackup, unassociatedBackup.ID)
	require.NotNil(t, unassociatedCandidate)
	assert.False(t, unassociatedCandidate.Eligible)
	assert.Contains(t, unassociatedCandidate.Reasons, "journal backup has an authenticated binding without a recovery-material association")
	retainedCandidate := candidateFor(RetentionPruneCandidateBackup, retainedBackup.ID)
	require.NotNil(t, retainedCandidate)
	assert.False(t, retainedCandidate.Eligible)
	assert.Contains(t, retainedCandidate.Reasons, "tied to a retained recovery point")
	_, err = store.Payload(oldBackup.BackupRef)
	require.NoError(t, err)
	retainedBytes, err := store.Payload(retainedBackup.BackupRef)
	require.NoError(t, err)
	unassociatedBytes, err := store.Payload(unassociatedBackup.BackupRef)
	require.NoError(t, err)
	legacyBytes, err := store.Payload(legacyBackup.BackupRef)
	require.NoError(t, err)

	pruned, err := store.PruneJournalBackupIfEligible(ctx, oldBackup.ID, now)
	require.NoError(t, err)
	assert.True(t, pruned, "an aged backup associated with an evicted point can be pruned")
	_, err = store.Payload(oldBackup.BackupRef)
	assert.Error(t, err)
	oldAfter := mustJournalEntryByID(t, store, oldBackup.ID)
	assert.Empty(t, oldAfter.BackupRef)
	for _, sentinel := range []struct {
		entry   JournalEntry
		payload []byte
	}{{retainedBackup, retainedBytes}, {unassociatedBackup, unassociatedBytes}, {legacyBackup, legacyBytes}} {
		pruned, err = store.PruneJournalBackupIfEligible(ctx, sentinel.entry.ID, now)
		require.NoError(t, err)
		assert.False(t, pruned)
		actual, err := store.Payload(sentinel.entry.BackupRef)
		require.NoError(t, err)
		assert.Equal(t, sentinel.payload, actual)
		assert.Equal(t, sentinel.entry, mustJournalEntryByID(t, store, sentinel.entry.ID))
	}
}

func TestAutomaticJournalPruneRequiresAnAssociatedPointBelowHeldBoundary(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{0xA4}
	deviceID := "device-a"
	require.NoError(t, store.PutTarget(ctx, testDescriptor()))
	require.NoError(t, store.PutVaultSelection(ctx, VaultSelection{Vault: vaultID, DeviceID: deviceID, RecordedAt: 1}))
	pointBodies := [][]byte{
		[]byte("automatic old point"), []byte("automatic boundary point"),
		[]byte("automatic live point"), []byte("automatic newer point"),
	}
	points := []RetentionRecoveryPoint{
		testRetentionPoint(t, vaultID, 0, pointBodies[0], [32]byte{7}),
		testRetentionPoint(t, vaultID, 1, pointBodies[1], [32]byte{7}),
		testRetentionPoint(t, vaultID, 2, pointBodies[2], [32]byte{7}),
		testRetentionPoint(t, vaultID, 3, pointBodies[3], [32]byte{7}),
	}
	boundary := points[1]
	declaration := testRetentionDeclaration(t, vaultID, boundary, boundary.Epoch, 1_700_000_000)
	declaration.DeviceID = deviceID
	declaration.RecoveryPoints = points
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{Vault: vaultID, Epoch: 3, HeadCID: []byte("automatic-live-head"), ControlCID: []byte("automatic-live-control")}))

	backups := make([]JournalEntry, 0, len(points))
	bodyReferences := make([]string, 0, len(points))
	for index, point := range points {
		bodyReference := storeUnreferencedPayload(t, store, pointBodies[index])
		bodyReferences = append(bodyReferences, bodyReference)
		require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, point, []string{bodyReference}, nil))
		backup := appendBoundRetentionJournal(t, store, vaultID, deviceID, point, fmt.Sprintf("automatic-bound-%d", point.Epoch), 1)
		require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, point, []string{bodyReference}, []string{backup.BackupRef}))
		backups = append(backups, backup)
	}
	unboundPreimage := []byte("automatic repeated checkpoint preimage")
	unboundAssociation := storeUnreferencedPayload(t, store, unboundPreimage)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, points[0], []string{bodyReferences[0]}, []string{backups[0].BackupRef, unboundAssociation}))
	unbound := appendUnboundRetentionJournal(t, store, "automatic-unbound-version-one", unboundPreimage, 1)
	assert.Equal(t, unboundAssociation, unbound.BackupRef)
	assert.Equal(t, uint8(1), unbound.RetentionBindingVersion)
	assert.Nil(t, unbound.Retention)

	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.DeclaredAt++
	_, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	now := time.Unix(1, 0).Add(JournalBackupRetention)
	for _, index := range []int{1, 2, 3} {
		backup := backups[index]
		pruned, pruneErr := store.PruneJournalBackupIfEligible(ctx, backup.ID, now)
		require.NoError(t, pruneErr)
		assert.False(t, pruned, "boundary-equal, live-epoch and newer backups are preserved")
		_, payloadErr := store.Payload(backup.BackupRef)
		require.NoError(t, payloadErr)
	}
	prunedIDs, err := store.PruneExpiredJournalBackups(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, []string{backups[0].ID}, prunedIDs, "the properly bound evicted point below the boundary is pruned")
	_, err = store.Payload(backups[0].BackupRef)
	assert.ErrorIs(t, err, os.ErrNotExist)
	unboundAfter := mustJournalEntryByID(t, store, unbound.ID)
	assert.Equal(t, unbound.BackupRef, unboundAfter.BackupRef)
	unboundPayload, err := store.Payload(unbound.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, unboundPreimage, unboundPayload, "a repeated-preimage version-1 unbound row stays attached and its bytes survive automatic pruning")
}

func TestBoundJournalAppendIsIdempotentUntilRefreshCompletesInventory(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{0xA5}
	deviceID := "device-a"
	require.NoError(t, store.PutTarget(ctx, testDescriptor()))
	require.NoError(t, store.PutVaultSelection(ctx, VaultSelection{Vault: vaultID, DeviceID: deviceID, RecordedAt: 1}))
	oldPoint := testRetentionPoint(t, vaultID, 0, []byte("append old point body"), [32]byte{7})
	boundary := testRetentionPoint(t, vaultID, 1, []byte("append boundary body"), [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, oldPoint, oldPoint.Epoch, 1_700_000_000)
	declaration.DeviceID = deviceID
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, oldPoint, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{Vault: vaultID, Epoch: 2, HeadCID: []byte("append-live-head"), ControlCID: []byte("append-live-control")}))
	oldBodyReference := storeUnreferencedPayload(t, store, []byte("append old point body"))
	boundaryBodyReference := storeUnreferencedPayload(t, store, []byte("append boundary body"))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, oldPoint, []string{oldBodyReference}, nil))

	before := []byte("identical preimage")
	binding := &RetentionBinding{Vault: vaultID, Epoch: oldPoint.Epoch, SnapshotCID: bytes.Clone(oldPoint.SnapshotCID), PolicyDigest: oldPoint.PolicyDigest, ControlCID: bytes.Clone(oldPoint.ControlCID)}
	for index, id := range []string{"repeated-preimage-a", "repeated-preimage-b"} {
		entry, appendErr := store.AppendJournal(ctx, JournalEntry{
			ID: id, Operation: "replace", State: "pending", Stage: JournalStagePending,
			Identity:  fileIdentity(fmt.Sprintf("repeated-%d.toml", index)),
			Preimage:  NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", before),
			Postimage: NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte(fmt.Sprintf("postimage-%d", index))),
			Retention: binding, CreatedAt: 1,
		}, before)
		require.NoError(t, appendErr, "the second same-binding append must be accepted while inventory is incomplete")
		require.NoError(t, store.TransitionJournalEntry(ctx, entry.ID, "pending", "applied", JournalStageVerified))
	}
	backupReference, _ := payloadReference(before)
	var associationCount int
	require.NoError(t, store.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND backup_ref = ?`, vaultID[:], deviceID, oldPoint.Epoch, oldPoint.SnapshotCID, backupReference).Scan(&associationCount)
	}))
	assert.Equal(t, 1, associationCount, "an identical backup digest has one association, not one row per journal entry")
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, oldPoint, []string{oldBodyReference}, []string{backupReference}))
	third, err := store.AppendJournal(ctx, JournalEntry{
		ID: "repeated-preimage-after-refresh", Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity:  fileIdentity("repeated-after-refresh.toml"),
		Preimage:  NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", before),
		Postimage: NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("postimage-after-refresh")),
		Retention: binding, CreatedAt: 1,
	}, before)
	require.NoError(t, err, "re-inserting an existing point/reference association after refresh is idempotent")
	require.NoError(t, store.TransitionJournalEntry(ctx, third.ID, "pending", "applied", JournalStageVerified))
	associationCount = 0
	require.NoError(t, store.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM retention_recovery_material
WHERE vault = ? AND device_id = ? AND epoch = ? AND snapshot_cid = ? AND backup_ref = ?`, vaultID[:], deviceID, oldPoint.Epoch, oldPoint.SnapshotCID, backupReference).Scan(&associationCount)
	}))
	assert.Equal(t, 1, associationCount)

	request := RetentionPruneRequest{Vault: vaultID, DeviceID: deviceID, Boundary: oldPoint, Now: time.Unix(1, 0).Add(JournalBackupRetention)}
	_, err = store.PlanRetentionPrune(ctx, request)
	assert.ErrorIs(t, err, ErrRetentionRecoveryPointInventoryUnknown, "pruning refuses while the point inventory remains incomplete")

	declaration.RecoveryPoints = []RetentionRecoveryPoint{boundary}
	declaration.RetentionFloor = boundary.Epoch
	declaration.DeclaredAt++
	_, err = store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, deviceID, boundary, []string{boundaryBodyReference}, nil))
	request.Boundary = boundary
	plan, err := store.PlanRetentionPrune(ctx, request)
	require.NoError(t, err, "pruning becomes available after refresh evicts the incomplete point and completes the retained inventory")
	eligibleIDs := make([]string, 0, 2)
	for _, candidate := range plan.Candidates {
		if candidate.Kind == RetentionPruneCandidateBackup && (candidate.JournalID == "repeated-preimage-a" || candidate.JournalID == "repeated-preimage-b" || candidate.JournalID == "repeated-preimage-after-refresh") {
			assert.True(t, candidate.Eligible)
			eligibleIDs = append(eligibleIDs, candidate.JournalID)
		}
	}
	assert.ElementsMatch(t, []string{"repeated-preimage-a", "repeated-preimage-b", "repeated-preimage-after-refresh"}, eligibleIDs)
	report, err := store.ApplyRetentionPrune(ctx, request, true)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"repeated-preimage-a", "repeated-preimage-b", "repeated-preimage-after-refresh"}, report.PrunedBackupIDs)
	_, err = store.Payload(backupReference)
	assert.Error(t, err)
}

func appendBoundRetentionJournal(t *testing.T, store *Store, vaultID [32]byte, deviceID string, point RetentionRecoveryPoint, id string, createdAt int64) JournalEntry {
	t.Helper()
	ctx := context.Background()
	before, after := []byte(id+" preimage"), []byte(id+" postimage")
	entry, err := store.AppendJournal(ctx, JournalEntry{
		ID: id, Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity:  fileIdentity(id + ".toml"),
		Preimage:  NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", before),
		Postimage: NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", after),
		Retention: &RetentionBinding{Vault: vaultID, Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID)},
		CreatedAt: createdAt,
	}, before)
	require.NoError(t, err)
	require.NoError(t, store.TransitionJournalEntry(ctx, entry.ID, "pending", "applied", JournalStageVerified))
	entry.State = "applied"
	entry.Stage = JournalStageVerified
	return entry
}

func mustJournalEntryByID(t *testing.T, store *Store, id string) JournalEntry {
	t.Helper()
	entries, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.ID == id {
			return entry
		}
	}
	t.Fatalf("journal row %q is missing", id)
	return JournalEntry{}
}

func TestRetentionPrunePlanSortsPayloads(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	ctx := context.Background()
	vaultID := [32]byte{47}
	firstPayload, secondPayload := []byte("first"), []byte("second")
	boundaryPayload := []byte("sort boundary body")
	boundary := testRetentionPoint(t, vaultID, 2, boundaryPayload, [32]byte{7})
	olderPoint := testRetentionPoint(t, vaultID, 1, secondPayload, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, boundary, 2, 1_700_000_000)
	declaration.RecoveryPoints = []RetentionRecoveryPoint{olderPoint, boundary}
	declaration, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(ctx, testRetentionCheckpoint(t, vaultID, boundary, declaration.PolicyDigest)))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, VaultPublicationObservation{
		Vault: vaultID, Epoch: 4, HeadCID: []byte("head"), ControlCID: []byte("control"),
	}))
	refs := []string{
		storeUnreferencedPayload(t, store, secondPayload),
		storeUnreferencedPayload(t, store, firstPayload),
	}
	boundaryRef := storeUnreferencedPayload(t, store, boundaryPayload)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, olderPoint, refs, nil))
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, boundary, []string{boundaryRef}, nil))
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
	vaultID := [32]byte{48}
	point := testRetentionPoint(t, vaultID, 1, []byte("same"), [32]byte{1})
	_, err := store.PutRetentionDeclaration(context.Background(), RetentionDeclaration{
		Vault: vaultID, DeviceID: "device-a", PolicyDigest: [32]byte{1}, DeclaredAt: 1,
		RecoveryPoints: []RetentionRecoveryPoint{point, point},
	})
	assert.Error(t, err)
	_, err = store.RetentionDeclaration(context.Background(), [32]byte{48}, "device-a")
	assert.ErrorIs(t, err, ErrRetentionDeclarationNotFound)
}
