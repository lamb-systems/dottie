package service

import (
	"bytes"
	"context"
	"os"
	"reflect"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

const (
	publicationBaseMaxUnionKeys  = 20000
	publicationBaseMaxFileBytes  = 8 << 20
	publicationBaseMaxTotalBytes = 256 << 20
)

type PublicationReconciliationRequest struct {
	Store          *publicationstate.Store
	Binding        publicationstate.Binding
	ExpectedFloor  publicationstate.Floor
	SnapshotRecord []byte
	Payload        []byte
	Configuration  config.Config
	TargetID       string
	Local          *PublicationLocalContext
}

type PublicationReconciliationBase struct {
	position  publicationBasePosition
	selection publicationBaseSelection
	entries   []model.Entry
}

type publicationBasePosition struct {
	floor          publicationstate.Floor
	snapshotRecord []byte
}

type publicationBaseAffinity struct {
	token    *publicationContextAffinity
	identity byte
}

type publicationBaseSelection struct {
	affinity     publicationBaseAffinity
	paths        platform.Paths
	target       config.Target
	portable     model.Target
	mode         config.Mode
	excludes     []string
	settingRefs  []SettingRef
	resolvedPath string
	anchorPath   string
	anchorName   string
	anchorInfo   os.FileInfo
}

type publicationBaseReason publicationReconciliationReason

const (
	publicationBaseStage            publicationReconciliationStage = "base"
	publicationBaseEligibilityStage publicationReconciliationStage = "base-eligibility"

	publicationBaseReasonInput          publicationBaseReason = "request_invalid"
	publicationBaseReasonTarget         publicationBaseReason = "target_missing"
	publicationBaseReasonUntracked      publicationBaseReason = "untracked_projection"
	publicationBaseReasonBounds         publicationBaseReason = "bounds_exceeded"
	publicationBaseReasonConvergence    publicationBaseReason = "not_converged"
	publicationBaseReasonPlan           publicationBaseReason = "plan_invalid"
	publicationBaseEligibilityInput     publicationBaseReason = "position_invalid"
	publicationBaseEligibilityBinding   publicationBaseReason = "binding_mismatch"
	publicationBaseEligibilityLineage   publicationBaseReason = "lineage_mismatch"
	publicationBaseEligibilitySelection publicationBaseReason = "selection_mismatch"
	publicationBaseEligibilityHistory   publicationBaseReason = "history_invalid"
)

func EstablishLocalReconciliationBase(ctx context.Context, request PublicationReconciliationRequest) (*PublicationReconciliationBase, error) {
	if ctx == nil || request.Store == nil || request.Local == nil || request.TargetID == "" {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonInput, nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonInput, err)
	}
	if len(request.SnapshotRecord) == 0 || len(request.SnapshotRecord) > publication.MaxRecordBytes {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonInput, nil)
	}
	record := bytes.Clone(request.SnapshotRecord)

	material, err := validateAcceptedPublication(ctx, acceptedPublicationRequest{
		store: request.Store, binding: request.Binding, expectedFloor: request.ExpectedFloor,
		snapshotRecord: record, payload: request.Payload,
	})
	if err != nil {
		return nil, err
	}
	var portable model.Target
	found := false
	for _, target := range material.snapshot.Targets {
		if target.ID == request.TargetID {
			portable = cloneSelectionTargetModel(target)
			found = true
			break
		}
	}
	if !found {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonTarget, nil)
	}

	local := snapshotPublicationLocalContext(request.Local)
	selection, err := selectPublicationTarget(ctx, local, request.Configuration, request.TargetID, portable)
	if err != nil {
		return nil, err
	}
	projected, err := projectPublicationSnapshot(selection, material.snapshot)
	if err != nil {
		return nil, err
	}
	if len(projected.untracked) != 0 {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonUntracked, nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonInput, err)
	}

	captured, err := capturePublicationTarget(ctx, selection)
	if err != nil {
		return nil, err
	}
	localEntries, unknown := publicationBaseLocalEntries(captured)
	coverage := []string(nil)
	if captured.complete {
		coverage = []string{selection.portable.ID}
	}
	localView := syncengine.LocalView{Entries: localEntries, Unknown: unknown, Coverage: coverage}
	if !publicationBaseWithinBounds(nil, localView, projected.entries, nil) {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonBounds, nil)
	}
	binding, err := syncengine.NewTargetBinding(selection.portable)
	if err != nil {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonPlan, err)
	}
	plan, err := syncengine.Reconcile(syncengine.BaseView{Status: syncengine.BaseMissing}, localView, projected.entries, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
	if err != nil {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonPlan, err)
	}
	preview, err := syncengine.BuildPreview(plan, []model.Target{selection.portable}, captured.observations)
	if err != nil {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonPlan, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonInput, err)
	}
	if !captured.complete || !preview.Complete || !publicationBasePlanUnchanged(plan) {
		return nil, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonConvergence, nil)
	}

	base := &PublicationReconciliationBase{
		position: publicationBasePosition{
			floor: clonePublicationFloor(material.floor), snapshotRecord: record,
		},
		selection: snapshotPublicationBaseSelection(selection),
		entries:   projected.entries,
	}
	if err := checkAcceptedPublicationFloor(ctx, request.Store, material.floor); err != nil {
		return nil, err
	}
	return base, nil
}

func checkBaseEligibility(ctx context.Context, store *publicationstate.Store, position publicationBasePosition, baseSelection publicationBaseSelection, currentFloor publicationstate.Floor, currentSelection publicationSelection) error {
	if ctx == nil || store == nil || !validPublicationBasePosition(position) || !validPublicationBaseSelection(baseSelection) || !validPublicationFloorInput(currentFloor) {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilityInput, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilityInput, err)
	}
	if position.floor.Binding != currentFloor.Binding {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilityBinding, nil)
	}
	if position.floor.DatabaseID == ([32]byte{}) || currentFloor.DatabaseID != position.floor.DatabaseID || position.floor.Generation == 0 || currentFloor.Generation != position.floor.Generation || position.floor.Revision > currentFloor.Revision {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilityLineage, nil)
	}
	currentSnapshot := snapshotPublicationBaseSelection(currentSelection)
	if !validPublicationBaseSelection(currentSnapshot) || !samePublicationBaseSelection(baseSelection, currentSnapshot) {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilitySelection, nil)
	}

	page, err := store.History(ctx, position.floor.Revision-1, 1)
	if err != nil {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilityHistory, err)
	}
	if len(page.Events) != 1 || page.NextRevision != position.floor.Revision {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilityHistory, nil)
	}
	event := page.Events[0]
	if event.Revision != position.floor.Revision || !reflect.DeepEqual(event.NewFloor, position.floor) || event.EventDigest != position.floor.AcceptedEventDigest || event.ObservationDigest != position.floor.ObservationDigest || !hasAcceptedRecordReference(event.Trace, position.floor) || !hasAcceptedRecordEvidence(page.Records, position.snapshotRecord, position.floor) {
		return publicationBaseFailure(ctx, publicationBaseEligibilityStage, publicationBaseEligibilityHistory, nil)
	}
	return nil
}

func validPublicationBasePosition(position publicationBasePosition) bool {
	floor := position.floor
	if !validPublicationFloorInput(floor) || floor.DatabaseID == ([32]byte{}) || floor.Generation == 0 || len(position.snapshotRecord) == 0 || len(position.snapshotRecord) > publication.MaxRecordBytes {
		return false
	}
	record, err := publication.DecodeSnapshot(position.snapshotRecord)
	if err != nil {
		return false
	}
	cid, err := publication.RecordCID(position.snapshotRecord)
	if err != nil || !bytes.Equal(cid, floor.RecordCID) || record.Vault != floor.Binding.Vault || record.PublicationID != floor.PublicationID || record.PublicationSeq != floor.Sequence || !bytes.Equal(record.Blob.CID, floor.BlobCID) || record.Blob.Size != floor.BlobSize {
		return false
	}
	sequence, err := publication.ParseSequenceKey(floor.SnapshotKey)
	if err != nil || sequence != floor.Sequence || publication.VerifyHeadBinding(floor.Head, position.snapshotRecord, floor.SnapshotKey) != nil {
		return false
	}
	head, err := publication.DecodeHead(floor.Head)
	return err == nil && head.Vault == floor.Binding.Vault && head.PublicationSeq == floor.Sequence && bytes.Equal(head.SnapshotCID, floor.RecordCID) && bytes.Equal(head.BlobCID, floor.BlobCID)
}

func validPublicationBaseSelection(selection publicationBaseSelection) bool {
	if selection.affinity.token == nil || selection.affinity.identity == 0 || selection.affinity.token.identity != selection.affinity.identity || !validPublicationContextPaths(selection.paths) {
		return false
	}
	portable, err := selection.target.Model()
	if err != nil || !reflect.DeepEqual(portable, selection.portable) || portable.Validate() != nil || !validPublicationBaseMode(selection.mode) {
		return false
	}
	if selection.target.Source == model.SourceFiles {
		context := &PublicationLocalContext{paths: selection.paths, files: LocalFilesCapture{}, affinity: selection.affinity.token}
		fileSelection := publicationSelection{
			context: context, target: cloneSelectionTarget(selection.target), portable: cloneSelectionTargetModel(selection.portable), mode: selection.mode,
			excludes: append([]string(nil), selection.excludes...), resolvedPath: selection.resolvedPath,
			anchorPath: selection.anchorPath, anchorName: selection.anchorName, anchorInfo: selection.anchorInfo,
		}
		return selection.target.Root != nil && len(selection.settingRefs) == 0 && validPublicationFileSelection(fileSelection)
	}
	if selection.target.Source != model.SourceGNOME || selection.target.Root != nil || selection.target.GNOMEPolicy == nil || len(selection.excludes) != 0 || selection.resolvedPath != "" || selection.anchorPath != "" || selection.anchorName != "" || selection.anchorInfo != nil {
		return false
	}
	refs, ok := publicationGNOMESelectedRefs(publicationSelection{target: selection.target, portable: selection.portable, settingRefs: selection.settingRefs})
	return ok && sameSettingRefs(refs, selection.settingRefs)
}

func validPublicationBaseMode(mode config.Mode) bool {
	return mode == config.AutoApply || mode == config.Review || mode == config.BackupOnly
}

func samePublicationBaseSelection(left, right publicationBaseSelection) bool {
	if !validPublicationBaseSelection(left) || !validPublicationBaseSelection(right) || left.affinity.token != right.affinity.token || left.affinity.identity != right.affinity.identity || left.paths != right.paths || !reflect.DeepEqual(left.target, right.target) || !reflect.DeepEqual(left.portable, right.portable) || left.mode != right.mode || !samePublicationStrings(left.excludes, right.excludes) || !sameSettingRefs(left.settingRefs, right.settingRefs) || left.resolvedPath != right.resolvedPath || left.anchorPath != right.anchorPath || left.anchorName != right.anchorName {
		return false
	}
	if left.anchorInfo == nil || right.anchorInfo == nil {
		return left.anchorInfo == nil && right.anchorInfo == nil
	}
	return os.SameFile(left.anchorInfo, right.anchorInfo)
}

func snapshotPublicationBaseSelection(selection publicationSelection) publicationBaseSelection {
	result := publicationBaseSelection{
		target: cloneSelectionTarget(selection.target), portable: cloneSelectionTargetModel(selection.portable),
		mode: selection.mode, excludes: append([]string(nil), selection.excludes...),
		settingRefs:  append([]SettingRef(nil), selection.settingRefs...),
		resolvedPath: selection.resolvedPath, anchorPath: selection.anchorPath, anchorName: selection.anchorName,
		anchorInfo: selection.anchorInfo,
	}
	if selection.context != nil {
		result.paths = selection.context.paths
		if selection.context.affinity != nil {
			result.affinity = publicationBaseAffinity{token: selection.context.affinity, identity: selection.context.affinity.identity}
		}
	}
	return result
}

func snapshotPublicationLocalContext(local *PublicationLocalContext) *PublicationLocalContext {
	if local == nil {
		return nil
	}
	return &PublicationLocalContext{
		paths: local.paths, files: local.files, settings: local.settings,
		affinity: local.affinity, pathBytes: local.pathBytes,
	}
}

func capturePublicationTarget(ctx context.Context, selection publicationSelection) (publicationCapture, error) {
	switch selection.portable.Source {
	case model.SourceFiles:
		return capturePublicationFiles(ctx, selection)
	case model.SourceGNOME:
		return capturePublicationGNOME(ctx, selection)
	default:
		return publicationCapture{}, publicationBaseFailure(ctx, publicationBaseStage, publicationBaseReasonInput, nil)
	}
}

func publicationBaseLocalEntries(captured publicationCapture) ([]model.Entry, []model.EntryKey) {
	entries := make([]model.Entry, 0, len(captured.observations))
	unknown := make([]model.EntryKey, 0)
	for _, observation := range captured.observations {
		switch observation.State {
		case model.ObservationPresent:
			if observation.Entry != nil {
				entries = append(entries, *observation.Entry)
			}
		case model.ObservationUnknown:
			unknown = append(unknown, observation.Identity)
		}
	}
	return entries, unknown
}

func publicationBasePlanUnchanged(plan syncengine.Plan) bool {
	for _, decision := range plan.Decisions {
		if decision.Action != syncengine.ActionUnchanged {
			return false
		}
	}
	return true
}

func publicationBaseWithinBounds(base []model.Entry, local syncengine.LocalView, remote []model.Entry, untracked []model.EntryKey) bool {
	views := [][]model.Entry{base, local.Entries, remote}
	occurrences := []int{len(base), len(local.Entries), len(remote), len(local.Unknown), len(local.Untracked), len(untracked)}
	totalOccurrences := 0
	for _, count := range occurrences {
		if count < 0 || count > publicationBaseMaxUnionKeys || totalOccurrences > int(^uint(0)>>1)-count {
			return false
		}
		totalOccurrences += count
	}

	capacity := totalOccurrences
	if capacity > publicationBaseMaxUnionKeys {
		capacity = publicationBaseMaxUnionKeys
	}
	keys := make(map[model.EntryKey]struct{}, capacity)
	addKey := func(key model.EntryKey) bool {
		keys[key] = struct{}{}
		return len(keys) <= publicationBaseMaxUnionKeys
	}
	for _, view := range views {
		for _, entry := range view {
			if !addKey(entry.Identity()) {
				return false
			}
		}
	}
	for _, key := range local.Unknown {
		if !addKey(key) {
			return false
		}
	}
	for _, key := range local.Untracked {
		if !addKey(key) {
			return false
		}
	}
	for _, key := range untracked {
		if !addKey(key) {
			return false
		}
	}

	var contentBytes uint64
	for _, view := range views {
		for _, entry := range view {
			if entry.File == nil || entry.File.Kind != model.FileRegular {
				continue
			}
			size := uint64(len(entry.File.Content))
			if size > publicationBaseMaxFileBytes || size > publicationBaseMaxTotalBytes-contentBytes {
				return false
			}
			contentBytes += size
		}
	}
	return true
}

func publicationBaseFailure(ctx context.Context, stage publicationReconciliationStage, reason publicationBaseReason, cause error) error {
	return publicationReconciliationFailure(ctx, stage, publicationReconciliationReason(reason), cause)
}
