package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	cid "github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
)

type RetentionAdmissionStatus string

const (
	RetentionAdmissionUpdated     RetentionAdmissionStatus = "updated"
	RetentionAdmissionAtCap       RetentionAdmissionStatus = "at-cap"
	RetentionAdmissionRefused     RetentionAdmissionStatus = "refused"
	RetentionAdmissionUnavailable RetentionAdmissionStatus = "unavailable"
)

type RetentionAdmissionReason string

const (
	RetentionReasonNone                 RetentionAdmissionReason = ""
	RetentionReasonPointCap             RetentionAdmissionReason = "point-cap-exceeded"
	RetentionReasonCheckpointPosition   RetentionAdmissionReason = "checkpoint-position-unavailable"
	RetentionReasonPointEvidence        RetentionAdmissionReason = "point-evidence-unavailable"
	RetentionReasonHistoricalBody       RetentionAdmissionReason = "historical-body-unavailable"
	RetentionReasonInvalidEvidence      RetentionAdmissionReason = "retention-evidence-refused"
	RetentionReasonUnexpectedMaterial   RetentionAdmissionReason = "unexpected-point-material"
	RetentionReasonMaterialReplacement  RetentionAdmissionReason = "material-replacement-failed"
	RetentionReasonCheckpointNotCurrent RetentionAdmissionReason = "checkpoint-not-current-or-descendant"
	RetentionReasonInventoryUnavailable RetentionAdmissionReason = "inventory-unavailable"
)

type RetentionFloorStatus string

const (
	RetentionFloorMeetsPolicy RetentionFloorStatus = "meets-policy"
	RetentionFloorBelowPolicy RetentionFloorStatus = "below-policy"
	RetentionFloorUnknown     RetentionFloorStatus = "unknown"
	RetentionFloorNoMaterial  RetentionFloorStatus = "no-known-material"
)

type RetentionFloorReport struct {
	RecoveryFloor                 uint64
	HasRecoveryFloor              bool
	ConfidentialityFloor          uint64
	HasConfidentialityFloor       bool
	PolicyFloor                   uint64
	Status                        RetentionFloorStatus
	BelowPolicy                   bool
	UnknownHoldingReasons         []string
	CompromisedForConfidentiality bool
}

type RetentionReport struct {
	Admission RetentionAdmissionStatus
	Reason    RetentionAdmissionReason
	Floors    RetentionFloorReport
}

type RetentionPruneStatus string

const (
	RetentionPrunePlanned              RetentionPruneStatus = "planned"
	RetentionPruneApplied              RetentionPruneStatus = "applied"
	RetentionPruneConfirmationRequired RetentionPruneStatus = "confirmation-required"
	RetentionPruneRefused              RetentionPruneStatus = "refused"
	RetentionPruneUnavailable          RetentionPruneStatus = "unavailable"
)

type RetentionPruneReason string

const (
	RetentionPruneReasonNone               RetentionPruneReason = ""
	RetentionPruneReasonDeclarationMissing RetentionPruneReason = "declaration-missing"
	RetentionPruneReasonBoundaryMismatch   RetentionPruneReason = "boundary-mismatch"
	RetentionPruneReasonBoundaryNotOldest  RetentionPruneReason = "checkpoint-not-oldest-point"
	RetentionPruneReasonLiveHead           RetentionPruneReason = "live-head-not-later"
	RetentionPruneReasonIncomplete         RetentionPruneReason = "inventory-incomplete"
	RetentionPruneReasonConfirmation       RetentionPruneReason = "confirmation-required"
	RetentionPruneReasonRefused            RetentionPruneReason = "prune-refused"
)

type RetentionPruneResult struct {
	Status RetentionPruneStatus
	Reason RetentionPruneReason
	Plan   state.RetentionPrunePlan
	Report state.RetentionPruneReport
	Floors RetentionFloorReport
}

type retentionBlobFetcher interface {
	FetchBlob(context.Context, string, []byte, int64) ([]byte, error)
}

type retentionPosition struct {
	evidence   state.AuthenticatedPositionEvidence
	head       vault.Head
	control    vault.Control
	controlCID []byte
}

func (coordinator *Coordinator) retentionInventory(ctx context.Context, selection VaultSelection, policyFloor uint64) (state.RetentionInventory, RetentionFloorReport, error) {
	inventory, err := coordinator.deps.State.RetentionInventory(ctx, selection.Vault, selection.DeviceID)
	if err != nil {
		return state.RetentionInventory{}, RetentionFloorReport{PolicyFloor: policyFloor, Status: RetentionFloorUnknown}, err
	}
	return inventory, retentionFloors(inventory, policyFloor), nil
}

func retentionFloors(inventory state.RetentionInventory, policyFloor uint64) RetentionFloorReport {
	report := RetentionFloorReport{PolicyFloor: policyFloor, UnknownHoldingReasons: append([]string(nil), inventory.UnknownHoldingReasons...)}
	for _, point := range inventory.Points {
		if !point.InventoryComplete {
			continue
		}
		if !report.HasRecoveryFloor || point.Epoch < report.RecoveryFloor {
			report.RecoveryFloor = point.Epoch
			report.HasRecoveryFloor = true
		}
	}
	for _, epoch := range inventory.KnownMaterialEpochs {
		if !report.HasConfidentialityFloor || epoch < report.ConfidentialityFloor {
			report.ConfidentialityFloor = epoch
			report.HasConfidentialityFloor = true
		}
	}
	switch {
	case len(report.UnknownHoldingReasons) != 0:
		report.Status = RetentionFloorUnknown
		report.CompromisedForConfidentiality = true
	case !report.HasConfidentialityFloor:
		report.Status = RetentionFloorNoMaterial
	case report.ConfidentialityFloor < policyFloor:
		report.Status = RetentionFloorBelowPolicy
		report.BelowPolicy = true
		report.CompromisedForConfidentiality = true
	default:
		report.Status = RetentionFloorMeetsPolicy
	}
	return report
}

func (coordinator *Coordinator) refreshRetention(ctx context.Context, selection VaultSelection, trust TrustMaterial, read atproto.ReadResult, currency vault.VerificationResult) RetentionReport {
	policyFloor := read.Policy.PolicyRetentionFloor
	inventory, floors, err := coordinator.retentionInventory(ctx, selection, policyFloor)
	if err != nil {
		return RetentionReport{Admission: RetentionAdmissionUnavailable, Reason: RetentionReasonInventoryUnavailable, Floors: floors}
	}
	if currency.Outcome != vault.CheckpointCurrent && currency.Outcome != vault.CheckpointDescendant {
		return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonCheckpointNotCurrent, Floors: floors}
	}
	positions, err := retentionPositions(ctx, coordinator.deps.State, selection.Vault)
	if err != nil {
		return RetentionReport{Admission: RetentionAdmissionUnavailable, Reason: RetentionReasonPointEvidence, Floors: floors}
	}
	checkpointPosition, ok := findCheckpointRetentionPosition(positions, trust.Checkpoint)
	if !ok {
		return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonCheckpointPosition, Floors: floors}
	}
	points, unambiguous := selectRetentionPositions(positions, checkpointPosition)
	if !unambiguous {
		return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonPointEvidence, Floors: floors}
	}
	if len(points) > int(read.Policy.RetainedRecoveryPoints) {
		return RetentionReport{Admission: RetentionAdmissionAtCap, Reason: RetentionReasonPointCap, Floors: floors}
	}
	materials := make([]state.RetentionRecoveryPointMaterials, 0, len(points))
	pointEvidence := make([]vault.RetentionRecoveryPointEvidence, 0, len(points))
	knownEpochs := append([]uint64(nil), inventory.KnownMaterialEpochs...)
	for _, selected := range points {
		point := state.RetentionRecoveryPoint{
			Epoch: selected.head.EpochSeq, SnapshotCID: bytes.Clone(selected.head.SnapshotCID),
			PolicyDigest: selected.head.PolicyDigest, ControlCID: bytes.Clone(selected.controlCID),
		}
		epochStart, exists := findEpochStartRetentionPosition(positions, selected)
		if !exists {
			return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonPointEvidence, Floors: floors}
		}
		startBody, err := coordinator.retentionBody(ctx, read, epochStart, epochStart.head.SnapshotCID)
		if err != nil {
			return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonHistoricalBody, Floors: floors}
		}
		startHeadBytes := bytes.Clone(epochStart.evidence.Head)
		evidence := vault.RetentionRecoveryPointEvidence{
			Point:          vault.RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID)},
			Position:       retentionControlEvidence(selected.evidence),
			Intermediates:  retentionControlIntermediates(positions, selected, checkpointPosition),
			EpochStartHead: startHeadBytes, EpochStartSnapshot: bytes.Clone(startBody),
		}
		if !retentionControlChainAvailable(positions, selected, checkpointPosition) {
			return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonPointEvidence, Floors: floors}
		}
		pointBody, err := coordinator.retentionBody(ctx, read, selected, point.SnapshotCID)
		if err != nil {
			return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonHistoricalBody, Floors: floors}
		}
		if selected.head.PublicationCount != 0 {
			evidence.Head = bytes.Clone(selected.evidence.Head)
			evidence.Ciphertext = bytes.Clone(pointBody)
		} else if !bytes.Equal(selected.head.SnapshotCID, selected.control.HeadSnapshotCID) {
			return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonInvalidEvidence, Floors: floors}
		}
		pointMaterial := state.RetentionRecoveryPointMaterials{Point: point, Payloads: [][]byte{bytes.Clone(pointBody)}}
		seenBackups := make(map[string]bool)
		for _, existing := range inventory.Materials {
			if existing.Epoch != point.Epoch || !bytes.Equal(existing.SnapshotCID, point.SnapshotCID) {
				continue
			}
			if existing.PayloadReference != "" && !payloadReferenceMatchesCID(existing.PayloadReference, point.SnapshotCID) {
				return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonUnexpectedMaterial, Floors: floors}
			}
			if existing.BackupReference != "" && !seenBackups[existing.BackupReference] {
				seenBackups[existing.BackupReference] = true
				pointMaterial.BackupReferences = append(pointMaterial.BackupReferences, existing.BackupReference)
			}
		}
		sort.Strings(pointMaterial.BackupReferences)
		materials = append(materials, pointMaterial)
		pointEvidence = append(pointEvidence, evidence)
		knownEpochs = append(knownEpochs, point.Epoch)
	}
	forecast := state.RetentionInventory{KnownMaterialEpochs: uniqueEpochs(knownEpochs), UnknownHoldingReasons: inventory.UnknownHoldingReasons}
	floors = retentionFloors(forecast, policyFloor)
	retentionFloor := uint64(0)
	if floors.Status != RetentionFloorUnknown && floors.HasConfidentialityFloor {
		retentionFloor = floors.ConfidentialityFloor
	}
	stateEvidence := retentionControlEvidence(checkpointPosition.evidence)
	judgement, err := vault.EvaluateRetentionDeclaration(vault.RetentionDeclarationRequest{
		VaultID: selection.Vault, TrustAnchor: trust.Anchor, State: stateEvidence,
		DeviceID: selection.DeviceID, RetentionFloor: retentionFloor,
		RecoveryPoints: retentionVaultPoints(materials), PointEvidence: pointEvidence,
		UnknownEpochMaterial: floors.Status == RetentionFloorUnknown,
	})
	if err != nil {
		return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonInvalidEvidence, Floors: floors}
	}
	declaration := state.RetentionDeclaration{
		Vault: selection.Vault, DeviceID: selection.DeviceID, PolicyDigest: judgement.Declaration.PolicyDigest,
		RetentionFloor: judgement.Declaration.RetentionFloor, DeclaredAt: coordinator.deps.Clock().Unix(),
	}
	for _, point := range judgement.Declaration.RecoveryPoints {
		declaration.RecoveryPoints = append(declaration.RecoveryPoints, state.RetentionRecoveryPoint{
			Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID), PolicyDigest: point.PolicyDigest, ControlCID: bytes.Clone(point.ControlCID),
		})
	}
	if _, err := coordinator.deps.State.ReplaceRetentionDeclarationWithMaterials(ctx, declaration, materials); err != nil {
		return RetentionReport{Admission: RetentionAdmissionRefused, Reason: RetentionReasonMaterialReplacement, Floors: floors}
	}
	_, floors, err = coordinator.retentionInventory(ctx, selection, policyFloor)
	if err != nil {
		return RetentionReport{Admission: RetentionAdmissionUpdated, Reason: RetentionReasonNone, Floors: RetentionFloorReport{PolicyFloor: policyFloor, Status: RetentionFloorUnknown}}
	}
	return RetentionReport{Admission: RetentionAdmissionUpdated, Floors: floors}
}

func retentionPositions(ctx context.Context, store *state.Store, vaultID [32]byte) ([]retentionPosition, error) {
	evidence, err := store.AuthenticatedPositionHistory(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	positions := make([]retentionPosition, 0, len(evidence))
	for _, item := range evidence {
		head, err := vault.DecodeHead(item.Head)
		if err != nil {
			return nil, err
		}
		control, err := vault.DecodeControl(item.Control)
		if err != nil {
			return nil, err
		}
		controlCID := rawVaultCID(item.Control)
		if len(controlCID) == 0 || item.Epoch != head.EpochSeq || item.Epoch != control.EpochSeq || item.PolicyDigest != head.PolicyDigest || control.PolicyDigest != item.PolicyDigest {
			return nil, errors.New("stored authenticated retention position is inconsistent")
		}
		positions = append(positions, retentionPosition{evidence: item, head: head, control: control, controlCID: controlCID})
	}
	return positions, nil
}

func findCheckpointRetentionPosition(positions []retentionPosition, checkpoint state.VaultCheckpoint) (retentionPosition, bool) {
	var match retentionPosition
	found := false
	for _, position := range positions {
		if position.head.EpochSeq != checkpoint.Epoch || position.head.PublicationCount != 0 ||
			position.evidence.PolicyDigest != checkpoint.PolicyDigest || !bytes.Equal(position.head.SnapshotCID, checkpoint.SnapshotCID) ||
			!bytes.Equal(position.evidence.Control, checkpoint.ControlBytes) || !bytes.Equal(position.controlCID, checkpoint.ControlCID) {
			continue
		}
		if found && (!bytes.Equal(match.evidence.Head, position.evidence.Head) || !bytes.Equal(match.evidence.Control, position.evidence.Control)) {
			return retentionPosition{}, false
		}
		match, found = position, true
	}
	return match, found
}

func selectRetentionPositions(positions []retentionPosition, checkpoint retentionPosition) ([]retentionPosition, bool) {
	latest := make(map[uint64]retentionPosition)
	for _, position := range positions {
		if position.head.EpochSeq <= checkpoint.head.EpochSeq {
			continue
		}
		current, exists := latest[position.head.EpochSeq]
		if !exists || position.head.PublicationCount > current.head.PublicationCount {
			latest[position.head.EpochSeq] = position
			continue
		}
		if position.head.PublicationCount == current.head.PublicationCount && !bytes.Equal(position.head.SnapshotCID, current.head.SnapshotCID) {
			return nil, false
		}
	}
	epochs := make([]uint64, 0, len(latest))
	for epoch := range latest {
		epochs = append(epochs, epoch)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	selected := make([]retentionPosition, 0, len(epochs)+1)
	selected = append(selected, checkpoint)
	for _, epoch := range epochs {
		selected = append(selected, latest[epoch])
	}
	return selected, true
}

func findEpochStartRetentionPosition(positions []retentionPosition, selected retentionPosition) (retentionPosition, bool) {
	var match retentionPosition
	found := false
	for _, position := range positions {
		if position.head.EpochSeq != selected.head.EpochSeq || position.head.PublicationCount != 0 ||
			position.evidence.PolicyDigest != selected.evidence.PolicyDigest ||
			!bytes.Equal(position.evidence.Control, selected.evidence.Control) ||
			!bytes.Equal(position.head.SnapshotCID, selected.control.HeadSnapshotCID) {
			continue
		}
		if found && !bytes.Equal(match.evidence.Head, position.evidence.Head) {
			return retentionPosition{}, false
		}
		match, found = position, true
	}
	return match, found
}

func retentionControlEvidence(position state.AuthenticatedPositionEvidence) vault.ControlEvidence {
	return vault.ControlEvidence{Policy: bytes.Clone(position.Policy), Control: bytes.Clone(position.Control), Certificates: cloneServiceByteSlices(position.Certificates)}
}

func retentionControlChainAvailable(positions []retentionPosition, selected, checkpoint retentionPosition) bool {
	_, ok := buildRetentionControlIntermediates(positions, selected, checkpoint)
	return ok
}

func retentionControlIntermediates(positions []retentionPosition, selected, checkpoint retentionPosition) []vault.ControlEvidence {
	intermediates, _ := buildRetentionControlIntermediates(positions, selected, checkpoint)
	return intermediates
}

func buildRetentionControlIntermediates(positions []retentionPosition, selected, checkpoint retentionPosition) ([]vault.ControlEvidence, bool) {
	if selected.control.EpochSeq == checkpoint.control.EpochSeq && bytes.Equal(selected.controlCID, checkpoint.controlCID) {
		return nil, true
	}
	byCID := make(map[string]vault.ControlEvidence)
	for _, position := range positions {
		byCID[string(position.controlCID)] = retentionControlEvidence(position.evidence)
	}
	current := selected.control
	intermediates := make([]vault.ControlEvidence, 0, vault.MaxCheckpointWalkDepth)
	for depth := 0; depth < vault.MaxCheckpointWalkDepth; depth++ {
		if len(current.PrevControlCID) == 0 {
			return nil, false
		}
		if bytes.Equal(current.PrevControlCID, checkpoint.controlCID) {
			return intermediates, true
		}
		intermediate, exists := byCID[string(current.PrevControlCID)]
		if !exists {
			return nil, false
		}
		decoded, err := vault.DecodeControl(intermediate.Control)
		if err != nil {
			return nil, false
		}
		intermediates = append(intermediates, intermediate)
		current = decoded
	}
	return nil, false
}

func (coordinator *Coordinator) retentionBody(ctx context.Context, read atproto.ReadResult, position retentionPosition, snapshotCID []byte) ([]byte, error) {
	var recordBytes []byte
	var record atproto.SnapshotRecord
	for key, proven := range read.Revision.Records() {
		if key.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, err := atproto.DecodeRecord(proven.Data)
		if err != nil {
			continue
		}
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		if !ok || !bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), snapshotCID) {
			continue
		}
		if len(recordBytes) != 0 {
			return nil, errors.New("verified revision has duplicate snapshot records for one CID")
		}
		recordBytes = bytes.Clone(proven.Data)
		record = snapshot
	}
	if len(recordBytes) == 0 || record.Blob.Size <= 0 || record.EpochSeq != position.head.EpochSeq ||
		!bytes.Equal(record.Vault, position.control.Vault[:]) || !bytes.Equal(record.PolicyDigest, position.evidence.PolicyDigest[:]) {
		return nil, errors.New("verified revision omits the point snapshot record")
	}
	var body []byte
	if bytes.Equal(snapshotCID, read.HeadCID) {
		body = bytes.Clone(read.Ciphertext)
	} else {
		fetcher, ok := coordinator.deps.Remote.(retentionBlobFetcher)
		if !ok {
			return nil, errors.New("remote reader does not expose verified CID blob retrieval")
		}
		var err error
		body, err = fetcher.FetchBlob(ctx, read.Revision.DID(), bytes.Clone(snapshotCID), record.Blob.Size)
		if err != nil {
			return nil, err
		}
	}
	if len(body) == 0 || int64(len(body)) != record.Blob.Size {
		return nil, errors.New("retention body size does not match the proven snapshot record")
	}
	if err := atproto.VerifyRecordBinding(recordBytes, body); err != nil {
		return nil, err
	}
	envelope, err := vault.DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	certificate, found := retentionEnvelopeCertificate(position.evidence.Certificates, envelope.DeviceID, envelope.KeyID)
	if !found || atproto.VerifySnapshotRecordSignature(record, certificate.SigningPublicKey[:]) != nil {
		return nil, errors.New("retention snapshot record signer is not authenticated by its position")
	}
	return body, nil
}

func retentionEnvelopeCertificate(certificates [][]byte, deviceID string, keyID []byte) (vault.Certificate, bool) {
	for _, encoded := range certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		if err != nil {
			continue
		}
		if certificate.DeviceID == deviceID && bytes.Equal(certificate.KeyID, keyID) {
			return certificate, true
		}
	}
	return vault.Certificate{}, false
}

func payloadReferenceMatchesCID(reference string, snapshotCID []byte) bool {
	return strings.HasPrefix(reference, "sha256:") && len(reference) == len("sha256:")+64 &&
		bytes.Equal([]byte(reference[len("sha256:"):]), []byte(fmt.Sprintf("%x", mustCIDHash(snapshotCID))))
}

func mustCIDHash(snapshotCID []byte) []byte {
	parsed, err := cid.Cast(snapshotCID)
	if err != nil || parsed.Prefix().Codec != cid.Raw {
		return nil
	}
	decoded, err := multihash.Decode(parsed.Hash())
	if err != nil || decoded.Code != multihash.SHA2_256 {
		return nil
	}
	return decoded.Digest
}

func retentionVaultPoints(materials []state.RetentionRecoveryPointMaterials) []vault.RetentionRecoveryPoint {
	points := make([]vault.RetentionRecoveryPoint, 0, len(materials))
	for _, material := range materials {
		points = append(points, vault.RetentionRecoveryPoint{
			Epoch: material.Point.Epoch, SnapshotCID: bytes.Clone(material.Point.SnapshotCID),
			PolicyDigest: material.Point.PolicyDigest, ControlCID: bytes.Clone(material.Point.ControlCID),
		})
	}
	return points
}

func uniqueEpochs(epochs []uint64) []uint64 {
	seen := make(map[uint64]bool, len(epochs))
	result := make([]uint64, 0, len(epochs))
	for _, epoch := range epochs {
		if seen[epoch] {
			continue
		}
		seen[epoch] = true
		result = append(result, epoch)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (coordinator *Coordinator) PlanPrune(ctx context.Context, selection VaultSelection) (RetentionPruneResult, error) {
	if err := coordinator.lock(ctx); err != nil {
		return RetentionPruneResult{}, err
	}
	defer coordinator.mu.Unlock()
	return coordinator.planPruneLocked(ctx, selection)
}

func (coordinator *Coordinator) planPruneLocked(ctx context.Context, requested VaultSelection) (RetentionPruneResult, error) {
	selected, err := coordinator.selectVault(ctx, requested)
	if err != nil {
		return RetentionPruneResult{}, err
	}
	trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
	if err != nil {
		return RetentionPruneResult{}, err
	}
	pulled, err := coordinator.pullLockedWithTrust(ctx, selected, &trust)
	if err != nil {
		return RetentionPruneResult{Status: RetentionPruneUnavailable, Reason: RetentionPruneReasonRefused}, err
	}
	return coordinator.planPruneAtHeldPosition(ctx, selected, trust, pulled.Read.Policy.PolicyRetentionFloor)
}

func (coordinator *Coordinator) planPruneAtHeldPosition(ctx context.Context, selected VaultSelection, trust TrustMaterial, policyFloor uint64) (RetentionPruneResult, error) {
	request := state.RetentionPruneRequest{
		Vault: selected.Vault, DeviceID: selected.DeviceID,
		Boundary: state.RetentionRecoveryPoint{Epoch: trust.Checkpoint.Epoch, SnapshotCID: bytes.Clone(trust.Checkpoint.SnapshotCID), PolicyDigest: trust.Checkpoint.PolicyDigest, ControlCID: bytes.Clone(trust.Checkpoint.ControlCID)},
		Now:      coordinator.deps.Clock(),
	}
	plan, err := coordinator.deps.State.PlanRetentionPrune(ctx, request)
	if err != nil {
		result := RetentionPruneResult{Status: RetentionPruneRefused, Reason: retentionPruneReason(err)}
		_, result.Floors, _ = coordinator.retentionInventory(ctx, selected, policyFloor)
		return result, nil
	}
	_, floors, err := coordinator.retentionInventory(ctx, selected, policyFloor)
	if err != nil {
		floors = RetentionFloorReport{PolicyFloor: policyFloor, Status: RetentionFloorUnknown}
	}
	return RetentionPruneResult{Status: RetentionPrunePlanned, Plan: plan, Floors: floors}, nil
}

func (coordinator *Coordinator) ApplyPrune(ctx context.Context, selection VaultSelection, confirmed bool) (RetentionPruneResult, error) {
	if !confirmed {
		result, err := coordinator.PlanPrune(ctx, selection)
		if err != nil {
			return result, err
		}
		result.Status = RetentionPruneConfirmationRequired
		result.Reason = RetentionPruneReasonConfirmation
		return result, nil
	}
	if err := coordinator.lock(ctx); err != nil {
		return RetentionPruneResult{}, err
	}
	defer coordinator.mu.Unlock()
	selected, err := coordinator.selectVault(ctx, selection)
	if err != nil {
		return RetentionPruneResult{}, err
	}
	trust, err := coordinator.deps.Trust.Resolve(ctx, selected)
	if err != nil {
		return RetentionPruneResult{}, err
	}
	pulled, err := coordinator.pullLockedWithTrust(ctx, selected, &trust)
	if err != nil {
		return RetentionPruneResult{Status: RetentionPruneUnavailable, Reason: RetentionPruneReasonRefused}, err
	}
	if pulled.Currency.Outcome != vault.CheckpointCurrent && pulled.Currency.Outcome != vault.CheckpointDescendant {
		return RetentionPruneResult{Status: RetentionPruneRefused, Reason: RetentionPruneReasonBoundaryMismatch, Floors: pulled.Retention.Floors}, nil
	}
	request := state.RetentionPruneRequest{
		Vault: selected.Vault, DeviceID: selected.DeviceID,
		Boundary: state.RetentionRecoveryPoint{Epoch: trust.Checkpoint.Epoch, SnapshotCID: bytes.Clone(trust.Checkpoint.SnapshotCID), PolicyDigest: trust.Checkpoint.PolicyDigest, ControlCID: bytes.Clone(trust.Checkpoint.ControlCID)},
		Now:      coordinator.deps.Clock(),
	}
	report, err := coordinator.deps.State.ApplyRetentionPrune(ctx, request, true)
	if err != nil {
		status := RetentionPruneRefused
		if len(report.DeletedPayloads) != 0 || len(report.PrunedBackupIDs) != 0 {
			status = RetentionPruneUnavailable
		}
		result := RetentionPruneResult{Status: status, Reason: retentionPruneReason(err), Plan: report.Plan, Report: report, Floors: pulled.Retention.Floors}
		return result, nil
	}
	_, floors, floorErr := coordinator.retentionInventory(ctx, selected, pulled.Read.Policy.PolicyRetentionFloor)
	if floorErr != nil {
		floors = RetentionFloorReport{PolicyFloor: pulled.Read.Policy.PolicyRetentionFloor, Status: RetentionFloorUnknown}
	}
	return RetentionPruneResult{Status: RetentionPruneApplied, Plan: report.Plan, Report: report, Floors: floors}, nil
}

func retentionPruneReason(err error) RetentionPruneReason {
	switch {
	case errors.Is(err, state.ErrRetentionDeclarationNotFound):
		return RetentionPruneReasonDeclarationMissing
	case errors.Is(err, state.ErrRetentionBoundaryNotVerified):
		return RetentionPruneReasonBoundaryMismatch
	case errors.Is(err, state.ErrRetentionBoundaryNewerThanFloor):
		return RetentionPruneReasonBoundaryNotOldest
	case errors.Is(err, state.ErrRetentionLiveHead):
		return RetentionPruneReasonLiveHead
	case errors.Is(err, state.ErrRetentionRecoveryPointInventoryUnknown):
		return RetentionPruneReasonIncomplete
	case errors.Is(err, state.ErrRetentionConfirmationRequired):
		return RetentionPruneReasonConfirmation
	default:
		return RetentionPruneReasonRefused
	}
}
