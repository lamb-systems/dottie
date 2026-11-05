package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

var (
	ErrExportRefused               = errors.New("vault export refused")
	ErrExportLineageUnavailable    = errors.New("required authenticated export lineage is unavailable")
	ErrExportUnenumerableRetention = errors.New("retained recovery points cannot be enumerated")
)

type ExportRefusalError struct {
	CID    string
	Reason string
	Err    error
}

func (e *ExportRefusalError) Error() string {
	if e.CID != "" {
		return fmt.Sprintf("%v: %s: %s", ErrExportRefused, e.CID, e.Reason)
	}
	return fmt.Sprintf("%v: %s", ErrExportRefused, e.Reason)
}

func (e *ExportRefusalError) Unwrap() error { return errors.Join(ErrExportRefused, e.Err) }

type ExportRequest struct {
	Selection      VaultSelection
	ExpectedVault  [32]byte
	ExpectedAnchor [32]byte
	Kit            []byte
	Path           string
}

type ImportExportRequest struct {
	Path           string
	ExpectedVault  [32]byte
	ExpectedAnchor [32]byte
	Kit            []byte
}

type ExportPositionReport struct {
	Epoch            uint64
	PolicyDigest     [32]byte
	SnapshotCID      string
	PublicationCount uint64
}

type ExportReport struct {
	VaultID        [32]byte
	Anchor         [32]byte
	CurrentEpoch   uint64
	Current        ExportPositionReport
	Lineage        []ExportPositionReport
	RecoveryPoints []ExportPositionReport
	Omissions      []vault.ExportOmissionCode
}

type exportBlobFetcher interface {
	FetchBlob(context.Context, string, []byte, int64) ([]byte, error)
}

func (coordinator *Coordinator) Export(ctx context.Context, request ExportRequest) (ExportReport, error) {
	if err := coordinator.lock(ctx); err != nil {
		return ExportReport{}, err
	}
	defer coordinator.mu.Unlock()
	if coordinator.deps.Config == nil || coordinator.deps.Session == nil || coordinator.deps.Remote == nil {
		return ExportReport{}, errors.New("export coordinator ports are unavailable")
	}
	if len(request.Kit) != 32 || request.ExpectedVault == ([32]byte{}) || request.ExpectedAnchor == ([32]byte{}) {
		return ExportReport{}, fmt.Errorf("%w: expected vault, anchor and 32-byte recovery kit are required", ErrExportRefused)
	}
	selected, err := coordinator.selectVault(ctx, request.Selection)
	if err != nil {
		return ExportReport{}, err
	}
	if selected.Vault != request.ExpectedVault {
		return ExportReport{}, vault.ErrForeignVault
	}
	checkpoint, err := coordinator.deps.State.VaultCheckpoint(ctx, selected.Vault)
	if err != nil {
		return ExportReport{}, err
	}
	if checkpoint.Vault != request.ExpectedVault {
		return ExportReport{}, vault.ErrForeignVault
	}
	if checkpoint.Anchor != request.ExpectedAnchor {
		return ExportReport{}, vault.ErrForeignAnchor
	}
	checkpointBytes, _, trust, err := coordinator.exportTrust(ctx, selected, checkpoint)
	if err != nil {
		return ExportReport{}, err
	}
	kitPublic, err := vault.RecoveryKitSigningPublicKey(request.Kit, selected.Vault)
	if err != nil {
		return ExportReport{}, ErrRecoveryKitMismatch
	}
	verifiedCheckpoint, err := vault.VerifyCheckpoint(checkpointBytes, kitPublic)
	if err != nil {
		return ExportReport{}, fmt.Errorf("%w: kit did not authenticate the persisted checkpoint", ErrRecoveryKitMismatch)
	}
	if verifiedCheckpoint.Vault != selected.Vault || verifiedCheckpoint.Anchor != request.ExpectedAnchor || verifiedCheckpoint.EpochSeq != checkpoint.Epoch || verifiedCheckpoint.PolicyDigest != checkpoint.PolicyDigest || !bytes.Equal(verifiedCheckpoint.ControlCID, checkpoint.ControlCID) || !bytes.Equal(verifiedCheckpoint.SnapshotCID, checkpoint.SnapshotCID) {
		return ExportReport{}, fmt.Errorf("%w: persisted signed checkpoint does not match local checkpoint", ErrExportRefused)
	}
	read, err := coordinator.readForExport(ctx, selected, trust)
	if err != nil {
		if errors.Is(err, atproto.ErrReadRecordMissing) || errors.Is(err, atproto.ErrReadBlobMissing) || errors.Is(err, atproto.ErrReadSnapshotAmbiguous) {
			if missingCID := latestLocalHeadCID(ctx, coordinator.deps.State, selected.Vault); len(missingCID) != 0 {
				return ExportReport{}, exportRefusalCID(missingCID, "required current snapshot record or blob is unavailable", err)
			}
		}
		return ExportReport{}, err
	}
	if read.Revision == nil || read.Revision.DID() == "" {
		return ExportReport{}, errors.New("verified export revision is unavailable")
	}
	current, err := coordinator.deps.State.AuthenticatedPositionEvidence(ctx, selected.Vault, read.EpochSeq, mustPolicyDigestBytes(read))
	if err != nil {
		return ExportReport{}, fmt.Errorf("%w: current position evidence: %v", ErrExportLineageUnavailable, err)
	}
	history, err := coordinator.deps.State.AuthenticatedPositionHistory(ctx, selected.Vault)
	if err != nil {
		return ExportReport{}, err
	}
	positions, err := verifiedExportPositions(selected.Vault, request.ExpectedAnchor, history)
	if err != nil {
		return ExportReport{}, err
	}
	currentCID := historyHeadCID(current)
	currentPosition, found := positions[string(currentCID)]
	if !found || !samePosition(current, currentPosition) {
		return ExportReport{}, exportRefusalCID(currentCID, "current position was not retained in authenticated history", ErrExportLineageUnavailable)
	}
	checkpointControlCID := bytes.Clone(verifiedCheckpoint.ControlCID)
	lineage, err := exportLineage(currentPosition, checkpointControlCID, positions)
	if err != nil {
		return ExportReport{}, err
	}
	recoveryPositions, err := coordinator.exportRecoveryPositions(read.Revision, selected.Vault, request.ExpectedAnchor, positions)
	if err != nil {
		return ExportReport{}, err
	}
	recoveryAncestors, err := recoveryHeadAncestors(recoveryPositions, positions)
	if err != nil {
		return ExportReport{}, err
	}
	lineage = appendUniquePositions(lineage, recoveryAncestors)
	blobs, err := coordinator.exportRequiredBlobs(ctx, read.Revision, currentPosition, lineage, recoveryPositions, request.ExpectedAnchor)
	if err != nil {
		return ExportReport{}, err
	}
	configuration, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return ExportReport{}, err
	}
	if err := configuration.Validate(); err != nil {
		return ExportReport{}, err
	}
	input := vault.ExportInput{
		VaultID: selected.Vault, AnchorFingerprint: request.ExpectedAnchor, Epoch: read.EpochSeq,
		PolicyDigest: mustPolicyDigestBytes(read), Current: exportPosition(currentPosition), Checkpoint: checkpointBytes,
		Lineage: exportPositions(lineage), RecoveryPoints: exportPositions(recoveryPositions), Blobs: blobs,
		RecoveryKit: bytes.Clone(request.Kit),
	}
	defer clear(input.RecoveryKit)
	captured, err := exportSelectionPredicate(configuration, coordinator.deps.Paths)
	if err != nil {
		return ExportReport{}, err
	}
	if err := vault.WriteExportArchive(request.Path, input, captured); err != nil {
		return ExportReport{}, err
	}
	return makeExportReport(input), nil
}

func (coordinator *Coordinator) ImportExportArchive(ctx context.Context, request ImportExportRequest) (ExportReport, error) {
	if err := coordinator.lock(ctx); err != nil {
		return ExportReport{}, err
	}
	defer coordinator.mu.Unlock()
	if request.ExpectedVault == ([32]byte{}) || request.ExpectedAnchor == ([32]byte{}) || len(request.Kit) != 32 {
		return ExportReport{}, fmt.Errorf("%w: expected vault, anchor and 32-byte recovery kit are required", ErrExportRefused)
	}
	file, err := os.Open(request.Path)
	if err != nil {
		return ExportReport{}, fmt.Errorf("open export archive: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ExportReport{}, fmt.Errorf("%w: export archive must be a regular file", vault.ErrIncompleteExport)
	}
	recoveryKit := bytes.Clone(request.Kit)
	defer clear(recoveryKit)
	archive, err := vault.ReadExportArchive(file, vault.ImportOptions{
		ExpectedVaultID: request.ExpectedVault, ExpectedAnchor: request.ExpectedAnchor, RecoveryKit: recoveryKit,
	})
	if err != nil {
		return ExportReport{}, err
	}
	return reportFromArchive(archive), nil
}

func (coordinator *Coordinator) exportTrust(ctx context.Context, selected VaultSelection, checkpoint state.VaultCheckpoint) ([]byte, state.AuthenticatedPositionEvidence, TrustMaterial, error) {
	history, err := coordinator.deps.State.AuthenticatedPositionHistory(ctx, selected.Vault)
	if err != nil {
		return nil, state.AuthenticatedPositionEvidence{}, TrustMaterial{}, err
	}
	var checkpointBytes []byte
	var checkpointEvidence state.AuthenticatedPositionEvidence
	for _, evidence := range history {
		if len(evidence.CheckpointPosition) == 0 {
			continue
		}
		decoded, decodeErr := vault.DecodeCheckpoint(evidence.CheckpointPosition)
		if decodeErr != nil || decoded.Vault != checkpoint.Vault || decoded.EpochSeq != checkpoint.Epoch || decoded.PolicyDigest != checkpoint.PolicyDigest || !bytes.Equal(decoded.ControlCID, checkpoint.ControlCID) || !bytes.Equal(decoded.SnapshotCID, checkpoint.SnapshotCID) {
			continue
		}
		if len(checkpointBytes) != 0 && !bytes.Equal(checkpointBytes, evidence.CheckpointPosition) {
			return nil, state.AuthenticatedPositionEvidence{}, TrustMaterial{}, fmt.Errorf("%w: conflicting signed checkpoint evidence", ErrExportRefused)
		}
		checkpointBytes = bytes.Clone(evidence.CheckpointPosition)
		checkpointEvidence = evidence
	}
	if len(checkpointBytes) == 0 {
		return nil, state.AuthenticatedPositionEvidence{}, TrustMaterial{}, fmt.Errorf("%w: signed checkpoint position is not locally retained", ErrExportLineageUnavailable)
	}
	checkpointPosition := checkpointEvidence
	if len(checkpointPosition.CheckpointPosition) == 0 || !bytes.Equal(checkpointPosition.CheckpointPosition, checkpointBytes) {
		return nil, state.AuthenticatedPositionEvidence{}, TrustMaterial{}, fmt.Errorf("%w: checkpoint signature is not attached to its authenticated position", ErrExportRefused)
	}
	trust := TrustMaterial{Selection: selected, Anchor: checkpoint.Anchor, Checkpoint: checkpoint}
	trust.Held = vault.ControlEvidence{Policy: checkpointPosition.Policy, Control: checkpointPosition.Control, Certificates: checkpointPosition.Certificates}
	if err := validateHeldEvidence(trust); err != nil {
		return nil, state.AuthenticatedPositionEvidence{}, TrustMaterial{}, fmt.Errorf("%w: held checkpoint evidence: %v", ErrExportRefused, err)
	}
	if checkpoint.Epoch > 0 {
		policy, decodeErr := vault.DecodePolicy(checkpointPosition.Policy)
		if decodeErr != nil || policy.PrevPolicyDigest == ([32]byte{}) {
			return nil, state.AuthenticatedPositionEvidence{}, TrustMaterial{}, fmt.Errorf("%w: checkpoint predecessor policy", ErrMissingPredecessorEvidence)
		}
		predecessor, predErr := coordinator.deps.State.AuthenticatedPositionEvidence(ctx, checkpoint.Vault, checkpoint.Epoch-1, policy.PrevPolicyDigest)
		if predErr != nil {
			return nil, state.AuthenticatedPositionEvidence{}, TrustMaterial{}, fmt.Errorf("%w: epoch %d", ErrMissingPredecessorEvidence, checkpoint.Epoch-1)
		}
		trust.PredecessorPolicy = bytes.Clone(predecessor.Policy)
		trust.PredecessorControl = bytes.Clone(predecessor.Control)
	}
	return checkpointBytes, checkpointPosition, trust, nil
}

func (coordinator *Coordinator) readForExport(ctx context.Context, selected VaultSelection, trust TrustMaterial) (atproto.ReadResult, error) {
	if coordinator.deps.Session == nil || coordinator.deps.Remote == nil {
		return atproto.ReadResult{}, errors.New("export read ports are unavailable")
	}
	var previousPolicy, previousControl []byte
	var err error
	if trust.ImportedCheckpoint {
		previousPolicy, previousControl, err = encodePositionRecords(trust.Held.Policy, trust.Held.Control)
	} else {
		previousPolicy, previousControl, err = encodePredecessorRecords(trust)
	}
	if err != nil {
		return atproto.ReadResult{}, fmt.Errorf("%w: read predecessor evidence: %v", ErrMissingPredecessorEvidence, err)
	}
	pairs := make([][2][]byte, 0)
	appendPair := func(policy, control []byte) {
		for _, prior := range pairs {
			if bytes.Equal(prior[0], policy) && bytes.Equal(prior[1], control) {
				return
			}
		}
		pairs = append(pairs, [2][]byte{bytes.Clone(policy), bytes.Clone(control)})
	}
	appendPair(previousPolicy, previousControl)
	if len(trust.Held.Policy) != 0 {
		heldPolicy, heldControl, encodeErr := encodePositionRecords(trust.Held.Policy, trust.Held.Control)
		if encodeErr != nil {
			return atproto.ReadResult{}, encodeErr
		}
		appendPair(heldPolicy, heldControl)
	} else if trust.Checkpoint.Epoch == 0 {
		appendPair(nil, nil)
	}
	history, historyErr := coordinator.deps.State.AuthenticatedPositionHistory(ctx, selected.Vault)
	if historyErr != nil {
		return atproto.ReadResult{}, historyErr
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].Epoch != history[j].Epoch {
			return history[i].Epoch > history[j].Epoch
		}
		left, _ := vault.DecodeHead(history[i].Head)
		right, _ := vault.DecodeHead(history[j].Head)
		return left.PublicationCount > right.PublicationCount
	})
	for _, evidence := range history {
		policy, control, encodeErr := encodePositionRecords(evidence.Policy, evidence.Control)
		if encodeErr != nil {
			return atproto.ReadResult{}, fmt.Errorf("%w: stored predecessor position: %v", ErrMissingPredecessorEvidence, encodeErr)
		}
		appendPair(policy, control)
	}
	var read atproto.ReadResult
	var readErr error
	for _, pair := range pairs {
		request, requestErr := coordinator.deps.Session.ReadRequest(ctx, selected, vault.DeviceMaterial{}, trust.Anchor, pair[0], pair[1])
		if requestErr != nil {
			return atproto.ReadResult{}, requestErr
		}
		request.Vault = selected.Vault
		request.TrustAnchor = trust.Anchor
		request.PreviousPolicy = bytes.Clone(pair[0])
		request.PreviousControl = bytes.Clone(pair[1])
		request.DeviceKeyID = nil
		request.DeviceKey = nil
		read, readErr = coordinator.deps.Remote.Read(ctx, request)
		if readErr == nil {
			break
		}
	}
	if readErr != nil {
		return atproto.ReadResult{}, readErr
	}
	if trust.ImportedCheckpoint {
		if err := verifyImportedCheckpointRead(trust, read); err != nil {
			return atproto.ReadResult{}, err
		}
	}
	if err := coordinator.recordPosition(ctx, selected.Vault, read); err != nil {
		return atproto.ReadResult{}, fmt.Errorf("record authenticated export position: %w", err)
	}
	return read, nil
}

func mustPolicyDigestBytes(read atproto.ReadResult) [32]byte {
	encoded, err := vault.EncodePolicy(policyObject(read.Policy))
	if err != nil {
		return [32]byte{}
	}
	digest, _ := vault.ComputePolicyDigest(encoded)
	return digest
}

func verifiedExportPositions(vaultID, anchor [32]byte, evidence []state.AuthenticatedPositionEvidence) (map[string]state.AuthenticatedPositionEvidence, error) {
	positions := make(map[string]state.AuthenticatedPositionEvidence, len(evidence))
	publicationCounts := make(map[string]map[uint64][]byte)
	trusted := vault.NewTrustedContext(vaultID, anchor)
	for _, position := range evidence {
		result, err := vault.VerifyControlState(trusted, vault.VerificationRequest{Supplied: vault.ControlEvidence{
			Policy: position.Policy, Control: position.Control, Certificates: position.Certificates,
		}})
		if err != nil || result.Outcome == vault.CheckpointConflicting {
			return nil, exportRefusalCID(controlRawCID(position.Control), "stored position signatures or context failed", errors.Join(err, vault.ErrAuthorization))
		}
		head, err := vault.DecodeHead(position.Head)
		if err != nil {
			return nil, exportRefusalCID(nil, "stored head is malformed", err)
		}
		controlCID := string(controlRawCID(position.Control))
		if publicationCounts[controlCID] == nil {
			publicationCounts[controlCID] = make(map[uint64][]byte)
		}
		if priorCID, exists := publicationCounts[controlCID][head.PublicationCount]; exists && !bytes.Equal(priorCID, head.SnapshotCID) {
			return nil, exportRefusalCID(head.SnapshotCID, "authenticated history contains competing heads at one publication count", ErrExportLineageUnavailable)
		}
		publicationCounts[controlCID][head.PublicationCount] = bytes.Clone(head.SnapshotCID)
		key := string(head.SnapshotCID)
		if prior, exists := positions[key]; exists && !samePosition(prior, position) {
			return nil, exportRefusalCID(head.SnapshotCID, "duplicate head CID has conflicting evidence", ErrExportLineageUnavailable)
		}
		positions[key] = position
	}
	return positions, nil
}

func exportLineage(current state.AuthenticatedPositionEvidence, checkpointControlCID []byte, positions map[string]state.AuthenticatedPositionEvidence) ([]state.AuthenticatedPositionEvidence, error) {
	currentControlCID := controlRawCID(current.Control)
	controlPositions := make(map[string]state.AuthenticatedPositionEvidence)
	for _, position := range positions {
		controlCID := controlRawCID(position.Control)
		if _, exists := controlPositions[string(controlCID)]; !exists {
			controlPositions[string(controlCID)] = position
		}
	}
	neededControls := make(map[string]bool)
	controlCID := bytes.Clone(currentControlCID)
	for step := 0; step < len(positions)+1; step++ {
		if bytes.Equal(controlCID, checkpointControlCID) {
			neededControls[string(controlCID)] = true
			break
		}
		key := string(controlCID)
		if neededControls[key] {
			return nil, exportRefusalCID(controlCID, "control lineage contains a cycle", ErrExportLineageUnavailable)
		}
		position, exists := controlPositions[key]
		if !exists {
			return nil, exportRefusalCID(controlCID, "required control position was not retained", ErrExportLineageUnavailable)
		}
		neededControls[key] = true
		control, err := vault.DecodeControl(position.Control)
		if err != nil || len(control.PrevControlCID) == 0 {
			return nil, exportRefusalCID(controlCID, "required control predecessor is unavailable", errors.Join(err, ErrExportLineageUnavailable))
		}
		controlCID = bytes.Clone(control.PrevControlCID)
	}
	if !neededControls[string(checkpointControlCID)] {
		return nil, exportRefusalCID(checkpointControlCID, "checkpoint control is not an ancestor of current control", ErrExportLineageUnavailable)
	}
	lineage := make([]state.AuthenticatedPositionEvidence, 0)
	for controlKey := range neededControls {
		var group []state.AuthenticatedPositionEvidence
		for _, position := range positions {
			if string(controlRawCID(position.Control)) == controlKey {
				group = append(group, position)
			}
		}
		if len(group) == 0 {
			return nil, exportRefusalCID([]byte(controlKey), "required control position has no authenticated heads", ErrExportLineageUnavailable)
		}
		maxCount := uint64(0)
		var latest state.AuthenticatedPositionEvidence
		for _, position := range group {
			head, _ := vault.DecodeHead(position.Head)
			if head.PublicationCount >= maxCount {
				maxCount = head.PublicationCount
				latest = position
			}
		}
		for {
			head, _ := vault.DecodeHead(latest.Head)
			lineage = appendUniquePosition(lineage, latest)
			if head.PublicationCount == 0 {
				break
			}
			predecessor, exists := positions[string(head.PrevHeadCID)]
			if !exists || !bytes.Equal(controlRawCID(predecessor.Control), controlRawCID(latest.Control)) {
				return nil, exportRefusalCID(head.PrevHeadCID, "required publication-head predecessor was not retained", ErrExportLineageUnavailable)
			}
			predecessorHead, decodeErr := vault.DecodeHead(predecessor.Head)
			if decodeErr != nil || predecessorHead.PublicationCount+1 != head.PublicationCount {
				return nil, exportRefusalCID(head.PrevHeadCID, "publication-head predecessor count or identity is invalid", errors.Join(decodeErr, ErrExportLineageUnavailable))
			}
			latest = predecessor
		}
	}
	currentHeadCID := historyHeadCID(current)
	lineage = removePosition(lineage, currentHeadCID)
	return lineage, nil
}

func recoveryHeadAncestors(recovery []state.AuthenticatedPositionEvidence, positions map[string]state.AuthenticatedPositionEvidence) ([]state.AuthenticatedPositionEvidence, error) {
	var result []state.AuthenticatedPositionEvidence
	for _, point := range recovery {
		latest := point
		for {
			head, err := vault.DecodeHead(latest.Head)
			if err != nil {
				return nil, exportRefusalCID(historyHeadCID(latest), "retained recovery head is malformed", err)
			}
			if head.PublicationCount == 0 {
				break
			}
			predecessor, exists := positions[string(head.PrevHeadCID)]
			if !exists || !bytes.Equal(controlRawCID(predecessor.Control), controlRawCID(latest.Control)) {
				return nil, exportRefusalCID(head.PrevHeadCID, "retained recovery publication-head predecessor was not retained", ErrExportLineageUnavailable)
			}
			predecessorHead, decodeErr := vault.DecodeHead(predecessor.Head)
			if decodeErr != nil || predecessorHead.PublicationCount+1 != head.PublicationCount {
				return nil, exportRefusalCID(head.PrevHeadCID, "retained recovery publication-head predecessor count is invalid", errors.Join(decodeErr, ErrExportLineageUnavailable))
			}
			result = appendUniquePosition(result, predecessor)
			latest = predecessor
		}
	}
	return result, nil
}

func (coordinator *Coordinator) exportRecoveryPositions(revision *atproto.Revision, vaultID, anchor [32]byte, positions map[string]state.AuthenticatedPositionEvidence) ([]state.AuthenticatedPositionEvidence, error) {
	records := revision.Records()
	keys := make([]atproto.RecordKey, 0)
	for key := range records {
		if key.Collection == atproto.VaultAttestationNSID {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].RKey < keys[j].RKey })
	unique := make(map[string]state.AuthenticatedPositionEvidence)
	for _, key := range keys {
		proven := records[key]
		recordCID := revision.Membership()[key]
		decoded, err := atproto.DecodeRecord(proven.Data)
		attestation, ok := decoded.(atproto.AttestationRecord)
		if err != nil || !ok {
			return nil, exportRefusalCIDString(recordCID, "attestation record is invalid", err)
		}
		if attestation.SchemaVersion == 1 && attestation.RetainedRecoveryPoints != 0 {
			return nil, &ExportRefusalError{CID: recordCID, Reason: "version-1 attestation has a nonzero count without enumerable points", Err: ErrExportUnenumerableRetention}
		}
		if attestation.SchemaVersion == 2 && len(attestation.RecoveryPoints) != int(attestation.RetainedRecoveryPoints) {
			return nil, &ExportRefusalError{CID: recordCID, Reason: "version-2 attestation count differs from enumerated points", Err: ErrExportUnenumerableRetention}
		}
		position, err := findPositionForAttestation(vaultID, positions, attestation)
		if err != nil {
			return nil, &ExportRefusalError{CID: recordCID, Reason: "attestation control position is unavailable", Err: err}
		}
		policyRecord, controlRecord, err := encodePositionRecords(position.Policy, position.Control)
		if err != nil {
			return nil, &ExportRefusalError{CID: recordCID, Reason: "attestation context is invalid", Err: err}
		}
		verification := vault.AttestationVerificationRequest{VaultID: vaultID, TrustAnchor: anchor, State: vault.ControlEvidence{
			Policy: position.Policy, Control: position.Control, Certificates: position.Certificates,
		}}
		object, err := attestationObjectFromRecord(attestation)
		if err != nil {
			return nil, &ExportRefusalError{CID: recordCID, Reason: "attestation object is invalid", Err: err}
		}
		objectBytes, err := vault.EncodeAttestation(object)
		if err != nil || atproto.VerifyRecordBinding(proven.Data, objectBytes) != nil || atproto.VerifyRecordContext(proven.Data, atproto.RecordContext{
			Policy: policyRecord, Control: controlRecord, TrustAnchor: anchor,
		}) != nil {
			return nil, &ExportRefusalError{CID: recordCID, Reason: "attestation record binding or context failed", Err: errors.Join(err, vault.ErrAuthorization)}
		}
		if _, err := atproto.VerifyAttestationRecord(proven.Data, verification); err != nil {
			return nil, &ExportRefusalError{CID: recordCID, Reason: "attestation signature failed", Err: err}
		}
		if attestation.SchemaVersion != 2 {
			continue
		}
		for _, recoveryPoint := range attestation.RecoveryPoints {
			position, found := positions[string(recoveryPoint.SnapshotCID)]
			if !found {
				return nil, exportRefusalCID(recoveryPoint.SnapshotCID, "retained recovery-point position was not retained", ErrExportLineageUnavailable)
			}
			head, decodeErr := vault.DecodeHead(position.Head)
			if decodeErr != nil || head.EpochSeq != recoveryPoint.Epoch || !bytes.Equal(head.SnapshotCID, recoveryPoint.SnapshotCID) {
				return nil, exportRefusalCID(recoveryPoint.SnapshotCID, "retained recovery-point position does not match its attestation", errors.Join(decodeErr, ErrExportUnenumerableRetention))
			}
			unique[string(recoveryPoint.SnapshotCID)] = position
		}
	}
	result := make([]state.AuthenticatedPositionEvidence, 0, len(unique))
	for _, position := range unique {
		result = append(result, position)
	}
	sort.Slice(result, func(i, j int) bool {
		left, _ := vault.DecodeHead(result[i].Head)
		right, _ := vault.DecodeHead(result[j].Head)
		if left.EpochSeq != right.EpochSeq {
			return left.EpochSeq < right.EpochSeq
		}
		return bytes.Compare(left.SnapshotCID, right.SnapshotCID) < 0
	})
	return result, nil
}

func findPositionForAttestation(vaultID [32]byte, positions map[string]state.AuthenticatedPositionEvidence, attestation atproto.AttestationRecord) (state.AuthenticatedPositionEvidence, error) {
	for _, position := range positions {
		if position.Vault != vaultID || !bytes.Equal(controlRawCID(position.Control), attestation.ControlCID) || !bytes.Equal(position.PolicyDigest[:], attestation.PolicyDigest) {
			continue
		}
		return position, nil
	}
	return state.AuthenticatedPositionEvidence{}, ErrExportLineageUnavailable
}

func attestationObjectFromRecord(record atproto.AttestationRecord) (vault.Attestation, error) {
	object := vault.Attestation{
		SchemaVersion: uint8(record.SchemaVersion), Vault: [32]byte(record.Vault), DeviceID: record.DeviceID,
		PolicyDigest: [32]byte(record.PolicyDigest), RetentionFloor: record.RetentionFloor,
		RetainedRecoveryPoints: record.RetainedRecoveryPoints, ControlCID: bytes.Clone(record.ControlCID),
		Signer: vault.Signer{DeviceID: record.SignerDeviceID, KeyID: bytes.Clone(record.SignerKeyID)},
	}
	if len(record.Signature) != len(object.Signature) {
		return vault.Attestation{}, errors.New("attestation signature size is invalid")
	}
	copy(object.Signature[:], record.Signature)
	for _, point := range record.RecoveryPoints {
		object.RecoveryPoints = append(object.RecoveryPoints, vault.RetentionRecoveryPoint{Epoch: point.Epoch, SnapshotCID: bytes.Clone(point.SnapshotCID)})
	}
	return object, nil
}

func (coordinator *Coordinator) fetchPositionEnvelope(ctx context.Context, read atproto.ReadResult, position state.AuthenticatedPositionEvidence, anchor [32]byte) ([]byte, error) {
	head, err := vault.DecodeHead(position.Head)
	if err != nil {
		return nil, err
	}
	if position.Vault == ([32]byte{}) || head.Vault != position.Vault || head.EpochSeq != position.Epoch || head.PolicyDigest != position.PolicyDigest || !bytes.Equal(head.SnapshotCID, head.BlobCID) {
		return nil, errors.New("position head does not bind a snapshot envelope")
	}
	recordBytes, snapshotRecord, err := findExportSnapshotRecord(read.Revision, head.SnapshotCID)
	if err != nil {
		return nil, exportRefusalCID(head.SnapshotCID, "position snapshot record is unavailable", err)
	}
	if snapshotRecord.EpochSeq != head.EpochSeq || !bytes.Equal(snapshotRecord.Vault, position.Vault[:]) || !bytes.Equal(snapshotRecord.PolicyDigest, position.PolicyDigest[:]) || !bytes.Equal(cid.Cid(snapshotRecord.Blob.Ref).Bytes(), head.BlobCID) {
		return nil, errors.New("position snapshot record does not match its head")
	}
	fetcher, ok := coordinator.deps.Remote.(exportBlobFetcher)
	if !ok {
		return nil, errors.New("remote reader does not expose verified CID blob retrieval")
	}
	blob, err := fetcher.FetchBlob(ctx, read.Revision.DID(), head.SnapshotCID, snapshotRecord.Blob.Size)
	if err != nil {
		return nil, exportRefusalCID(head.SnapshotCID, "position snapshot body could not be fetched and verified", err)
	}
	if err := verifyExportSnapshotRecord(recordBytes, snapshotRecord, blob, position, anchor); err != nil {
		return nil, exportRefusalCID(head.SnapshotCID, "position snapshot record failed authentication", err)
	}
	envelope, err := vault.DecodeEnvelope(blob)
	if err != nil || envelope.Vault != position.Vault || envelope.EpochSeq != position.Epoch || envelope.PolicyDigest != position.PolicyDigest || !bytes.Equal(envelope.Parent, head.PrevHeadCID) || !bytes.Equal(rawVaultCID(blob), head.SnapshotCID) {
		return nil, exportRefusalCID(head.SnapshotCID, "position snapshot envelope does not match its head", errors.Join(err, atproto.ErrReadHeadEnvelopeLinkage))
	}
	var snapshotSigner vault.Certificate
	foundSigner := false
	for _, certificateBytes := range position.Certificates {
		certificate, decodeErr := vault.DecodeCertificate(certificateBytes)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if certificate.DeviceID == envelope.DeviceID && bytes.Equal(certificate.KeyID, envelope.KeyID) {
			snapshotSigner = certificate
			foundSigner = true
			break
		}
	}
	if !foundSigner {
		return nil, errors.New("position snapshot signer is not in authenticated certificates")
	}
	if err := atproto.VerifySnapshotEnvelopeSignature(blob, snapshotSigner); err != nil {
		return nil, err
	}
	return blob, nil
}

func (coordinator *Coordinator) exportRequiredBlobs(ctx context.Context, revision *atproto.Revision, current state.AuthenticatedPositionEvidence, lineage, recovery []state.AuthenticatedPositionEvidence, anchor [32]byte) ([]vault.ExportBlob, error) {
	fetcher, ok := coordinator.deps.Remote.(exportBlobFetcher)
	if !ok {
		return nil, errors.New("remote reader does not expose verified CID blob retrieval")
	}
	all := []state.AuthenticatedPositionEvidence{current}
	all = append(all, lineage...)
	all = append(all, recovery...)
	needed := make(map[string]state.AuthenticatedPositionEvidence)
	for _, position := range all {
		head, err := vault.DecodeHead(position.Head)
		if err != nil {
			return nil, exportRefusalCID(nil, "required head is malformed", err)
		}
		needed[string(head.SnapshotCID)] = position
	}
	cids := make([]string, 0, len(needed))
	for raw := range needed {
		cids = append(cids, raw)
	}
	sort.Slice(cids, func(i, j int) bool { return bytes.Compare([]byte(cids[i]), []byte(cids[j])) < 0 })
	blobs := make([]vault.ExportBlob, 0, len(cids))
	for _, raw := range cids {
		cidBytes := []byte(raw)
		if _, err := cid.Cast(cidBytes); err != nil {
			return nil, exportRefusalCID(cidBytes, "required snapshot CID is invalid", err)
		}
		recordBytes, snapshotRecord, err := findExportSnapshotRecord(revision, cidBytes)
		if err != nil {
			return nil, exportRefusalCID(cidBytes, "required snapshot record is missing or ambiguous", err)
		}
		position := needed[raw]
		head, _ := vault.DecodeHead(position.Head)
		if snapshotRecord.EpochSeq != head.EpochSeq || !bytes.Equal(snapshotRecord.Vault, position.Vault[:]) || !bytes.Equal(snapshotRecord.PolicyDigest, position.PolicyDigest[:]) {
			return nil, exportRefusalCID(cidBytes, "required snapshot record context differs from authenticated position", atproto.ErrReadRecordContext)
		}
		blobData, err := fetcher.FetchBlob(ctx, revision.DID(), cidBytes, snapshotRecord.Blob.Size)
		if err != nil {
			return nil, exportRefusalCID(cidBytes, "required snapshot blob could not be fetched and verified", err)
		}
		if err := verifyExportSnapshotRecord(recordBytes, snapshotRecord, blobData, position, anchor); err != nil {
			return nil, exportRefusalCID(cidBytes, "required snapshot record binding, context or signature failed", err)
		}
		blobs = append(blobs, vault.ExportBlob{CID: bytes.Clone(cidBytes), Data: blobData})
	}
	return blobs, nil
}

func findExportSnapshotRecord(revision *atproto.Revision, expectedCID []byte) ([]byte, atproto.SnapshotRecord, error) {
	if revision == nil {
		return nil, atproto.SnapshotRecord{}, errors.New("verified revision is missing")
	}
	var selected []byte
	var result atproto.SnapshotRecord
	for key, proven := range revision.Records() {
		if key.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		record, err := atproto.DecodeRecord(proven.Data)
		if err != nil {
			return nil, atproto.SnapshotRecord{}, err
		}
		snapshot, ok := record.(atproto.SnapshotRecord)
		if !ok {
			return nil, atproto.SnapshotRecord{}, atproto.ErrReadRecordType
		}
		if bytes.Equal(cid.Cid(snapshot.Blob.Ref).Bytes(), expectedCID) {
			if selected != nil {
				return nil, atproto.SnapshotRecord{}, atproto.ErrReadSnapshotAmbiguous
			}
			selected = bytes.Clone(proven.Data)
			result = snapshot
		}
	}
	if selected == nil {
		return nil, atproto.SnapshotRecord{}, atproto.ErrReadRecordMissing
	}
	return selected, result, nil
}

func verifyExportSnapshotRecord(recordBytes []byte, snapshot atproto.SnapshotRecord, blob []byte, position state.AuthenticatedPositionEvidence, anchor [32]byte) error {
	if err := atproto.VerifyRecordBinding(recordBytes, blob); err != nil {
		return err
	}
	var signerCertificate []byte
	var signer vault.Certificate
	for _, encoded := range position.Certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		if err != nil {
			return err
		}
		if certificate.DeviceID == snapshot.SignerDeviceID && bytes.Equal(certificate.KeyID, snapshot.SignerKeyID) {
			signerCertificate = encoded
			signer = certificate
			break
		}
	}
	if signerCertificate == nil {
		return errors.New("snapshot signer certificate is absent from authenticated position")
	}
	certificateRecord, err := encodeCertificateRecord(signer)
	if err != nil {
		return err
	}
	policyRecord, _, err := encodePositionRecords(position.Policy, position.Control)
	if err != nil {
		return err
	}
	if err := atproto.VerifyRecordContext(recordBytes, atproto.RecordContext{Policy: policyRecord, Certificate: certificateRecord, TrustAnchor: anchor}); err != nil {
		return err
	}
	return atproto.VerifySnapshotRecordSignature(snapshot, signer.SigningPublicKey[:])
}

func encodeCertificateRecord(value vault.Certificate) ([]byte, error) {
	return atproto.EncodeRecord(atproto.CertificateRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), DeviceID: value.DeviceID, KeyID: bytes.Clone(value.KeyID),
		SigningPublicKey: bytes.Clone(value.SigningPublicKey[:]), EncryptionPublicKey: bytes.Clone(value.EncryptionPublicKey[:]),
		Role: uint8(value.Role), CertEpoch: value.CertEpoch, Issuer: value.Issuer, RevocationRef: bytes.Clone(value.RevocationRef),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	})
}

func exportSelectionPredicate(configuration config.Config, paths platform.Paths) (func(string) (bool, error), error) {
	roots := make([]struct {
		path string
		file bool
	}, 0)
	for _, target := range configuration.Targets {
		if target.Source != model.SourceFiles || target.Root == nil {
			continue
		}
		var base string
		switch target.Root.Base {
		case model.RootHome:
			base = paths.Home
		case model.RootXDGConfig:
			base = paths.ConfigHome
		default:
			return nil, fmt.Errorf("target %q has an unsupported selection base", target.ID)
		}
		if base == "" {
			return nil, fmt.Errorf("target %q selection base is unavailable", target.ID)
		}
		root := filepath.Clean(filepath.Join(base, filepath.FromSlash(target.Root.Path)))
		resolved, err := resolveSelectionPath(root)
		if err != nil {
			return nil, fmt.Errorf("resolve target %q selection: %w", target.ID, err)
		}
		roots = append(roots, struct {
			path string
			file bool
		}{path: resolved, file: target.Root.Kind == model.SelectionFile})
	}
	return func(destination string) (bool, error) {
		resolved, err := resolveSelectionPath(destination)
		if err != nil {
			return false, err
		}
		for _, root := range roots {
			if resolved == root.path || !root.file && pathWithin(root.path, resolved) {
				return true, nil
			}
		}
		return false, nil
	}, nil
}

func resolveSelectionPath(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	pending := make([]string, 0)
	current := absolute
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for index := len(pending) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, pending[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", resolveErr
		}
		pending = append(pending, filepath.Base(current))
		current = parent
	}
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func exportPosition(evidence state.AuthenticatedPositionEvidence) vault.ExportPosition {
	return vault.ExportPosition{
		Policy: bytes.Clone(evidence.Policy), Control: bytes.Clone(evidence.Control), Head: bytes.Clone(evidence.Head),
		Certificates: cloneServiceByteSlices(evidence.Certificates),
	}
}

func exportPositions(evidence []state.AuthenticatedPositionEvidence) []vault.ExportPosition {
	result := make([]vault.ExportPosition, len(evidence))
	for index := range evidence {
		result[index] = exportPosition(evidence[index])
	}
	sort.Slice(result, func(i, j int) bool {
		leftControl := controlRawCID(result[i].Control)
		rightControl := controlRawCID(result[j].Control)
		if order := bytes.Compare(leftControl, rightControl); order != 0 {
			return order < 0
		}
		left, _ := vault.DecodeHead(result[i].Head)
		right, _ := vault.DecodeHead(result[j].Head)
		if left.PublicationCount != right.PublicationCount {
			return left.PublicationCount < right.PublicationCount
		}
		return bytes.Compare(left.SnapshotCID, right.SnapshotCID) < 0
	})
	return result
}

func latestLocalHeadCID(ctx context.Context, store *state.Store, vaultID [32]byte) []byte {
	positions, err := store.AuthenticatedPositionHistory(ctx, vaultID)
	if err != nil {
		return nil
	}
	var selected state.AuthenticatedPositionEvidence
	var selectedCount uint64
	for _, position := range positions {
		head, decodeErr := vault.DecodeHead(position.Head)
		if decodeErr != nil {
			continue
		}
		if position.Epoch > selected.Epoch || position.Epoch == selected.Epoch && head.PublicationCount >= selectedCount {
			selected = position
			selectedCount = head.PublicationCount
		}
	}
	return historyHeadCID(selected)
}

func historyHeadCID(evidence state.AuthenticatedPositionEvidence) []byte {
	head, err := vault.DecodeHead(evidence.Head)
	if err != nil {
		return nil
	}
	return bytes.Clone(head.SnapshotCID)
}

func controlRawCID(encoded []byte) []byte { return rawVaultCID(encoded) }

func samePosition(left, right state.AuthenticatedPositionEvidence) bool {
	if left.Vault != right.Vault || left.Epoch != right.Epoch || left.PolicyDigest != right.PolicyDigest ||
		!bytes.Equal(left.Policy, right.Policy) || !bytes.Equal(left.Control, right.Control) || !bytes.Equal(left.Head, right.Head) || len(left.Certificates) != len(right.Certificates) {
		return false
	}
	for index := range left.Certificates {
		if !bytes.Equal(left.Certificates[index], right.Certificates[index]) {
			return false
		}
	}
	return true
}

func appendUniquePosition(positions []state.AuthenticatedPositionEvidence, position state.AuthenticatedPositionEvidence) []state.AuthenticatedPositionEvidence {
	cid := historyHeadCID(position)
	for _, existing := range positions {
		if bytes.Equal(historyHeadCID(existing), cid) {
			return positions
		}
	}
	return append(positions, position)
}

func appendUniquePositions(positions, more []state.AuthenticatedPositionEvidence) []state.AuthenticatedPositionEvidence {
	for _, position := range more {
		positions = appendUniquePosition(positions, position)
	}
	return positions
}

func removePosition(positions []state.AuthenticatedPositionEvidence, headCID []byte) []state.AuthenticatedPositionEvidence {
	result := make([]state.AuthenticatedPositionEvidence, 0, len(positions))
	for _, position := range positions {
		if !bytes.Equal(historyHeadCID(position), headCID) {
			result = append(result, position)
		}
	}
	return result
}

func exportRefusalCID(cidBytes []byte, reason string, err error) error {
	name := ""
	if len(cidBytes) != 0 {
		if parsed, parseErr := cid.Cast(cidBytes); parseErr == nil {
			name = parsed.String()
		} else {
			name = fmt.Sprintf("%x", cidBytes)
		}
	}
	return &ExportRefusalError{CID: name, Reason: reason, Err: err}
}

func exportRefusalCIDString(cidText, reason string, err error) error {
	return &ExportRefusalError{CID: cidText, Reason: reason, Err: err}
}

func makeExportReport(input vault.ExportInput) ExportReport {
	report := ExportReport{
		VaultID: input.VaultID, Anchor: input.AnchorFingerprint, CurrentEpoch: input.Epoch,
		Current: exportPositionReport(input.Current), Omissions: append([]vault.ExportOmissionCode(nil), input.Omissions...),
	}
	for _, position := range input.Lineage {
		report.Lineage = append(report.Lineage, exportPositionReport(position))
	}
	for _, position := range input.RecoveryPoints {
		report.RecoveryPoints = append(report.RecoveryPoints, exportPositionReport(position))
	}
	return report
}

func reportFromArchive(archive vault.ExportArchive) ExportReport {
	report := ExportReport{
		VaultID: archive.VaultID, Anchor: archive.Anchor, CurrentEpoch: archive.Epoch,
		Current: exportPositionReport(archive.Current), Omissions: append([]vault.ExportOmissionCode(nil), archive.Manifest.Omissions...),
	}
	for _, position := range archive.Lineage {
		report.Lineage = append(report.Lineage, exportPositionReport(position))
	}
	for _, position := range archive.RecoveryPoints {
		report.RecoveryPoints = append(report.RecoveryPoints, exportPositionReport(position))
	}
	return report
}

func exportPositionReport(position vault.ExportPosition) ExportPositionReport {
	report := ExportPositionReport{}
	if digest, err := vault.ComputePolicyDigest(position.Policy); err == nil {
		report.PolicyDigest = digest
	}
	policy, _ := vault.DecodePolicy(position.Policy)
	report.Epoch = policy.EpochSeq
	head, err := vault.DecodeHead(position.Head)
	if err == nil {
		report.SnapshotCID = cidName(head.SnapshotCID)
		report.PublicationCount = head.PublicationCount
	}
	return report
}

func cidName(encoded []byte) string {
	parsed, err := cid.Cast(encoded)
	if err != nil {
		return fmt.Sprintf("%x", encoded)
	}
	return parsed.String()
}
