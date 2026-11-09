package service

import (
	"bytes"
	"context"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

type PublicationPreviewBaseDisposition string

const (
	PublicationPreviewBaseUnestablished PublicationPreviewBaseDisposition = "unestablished"
	PublicationPreviewBaseEstablished   PublicationPreviewBaseDisposition = "established"

	publicationPreviewStage           publicationReconciliationStage  = "preview"
	publicationPreviewReasonInput     publicationReconciliationReason = "request_invalid"
	publicationPreviewReasonBounds    publicationReconciliationReason = "bounds_exceeded"
	publicationPreviewReasonTarget    publicationReconciliationReason = "target_missing"
	publicationPreviewReasonUntracked publicationReconciliationReason = "untracked_projection"
	publicationPreviewReasonPlan      publicationReconciliationReason = "plan_invalid"
)

func PreviewPublicationTarget(ctx context.Context, request PublicationReconciliationRequest, base *PublicationReconciliationBase) (syncengine.Preview, PublicationPreviewBaseDisposition, error) {
	owned, err := snapshotPublicationPreviewInputs(ctx, request, base)
	if err != nil {
		return syncengine.Preview{}, "", err
	}

	material, err := validateAcceptedPublication(ctx, acceptedPublicationRequest{
		store: owned.store, binding: owned.binding, expectedFloor: owned.expectedFloor,
		snapshotRecord: owned.snapshotRecord, payload: owned.payload,
	})
	if err != nil {
		return syncengine.Preview{}, "", err
	}
	portable, found := publicationPreviewTarget(material.snapshot, owned.targetID)
	if !found {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonTarget, nil)
	}
	selection, err := selectPublicationTarget(ctx, owned.local, owned.configuration, owned.targetID, portable)
	if err != nil {
		return syncengine.Preview{}, "", err
	}

	current, err := projectPublicationSnapshot(selection, material.snapshot)
	if err != nil {
		return syncengine.Preview{}, "", err
	}
	if len(current.untracked) != 0 {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonUntracked, nil)
	}

	baseView := syncengine.BaseView{Status: syncengine.BaseMissing}
	disposition := PublicationPreviewBaseUnestablished
	var baseEntries []model.Entry
	if owned.base != nil {
		if err := checkBaseEligibility(ctx, owned.store, owned.base.position, owned.base.selection, material.floor, selection); err != nil {
			return syncengine.Preview{}, "", err
		}
		projectedBase, err := projectPublicationSnapshot(selection, model.Snapshot{
			Version: model.SnapshotVersion, Targets: []model.Target{selection.portable}, Entries: owned.base.entries,
		})
		if err != nil {
			return syncengine.Preview{}, "", err
		}
		if len(projectedBase.untracked) != 0 {
			return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonUntracked, nil)
		}
		baseEntries = projectedBase.entries
		baseView = syncengine.BaseView{Status: syncengine.BaseKnown, Entries: baseEntries}
		disposition = PublicationPreviewBaseEstablished
	}
	if err := ctx.Err(); err != nil {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonInput, err)
	}

	captured, err := capturePublicationTarget(ctx, selection)
	if err != nil {
		return syncengine.Preview{}, "", err
	}
	localEntries, unknown := publicationBaseLocalEntries(captured)
	coverage := []string(nil)
	if captured.complete {
		coverage = []string{selection.portable.ID}
	}
	localView := syncengine.LocalView{Entries: localEntries, Unknown: unknown, Coverage: coverage}
	if !publicationBaseWithinBounds(baseEntries, localView, current.entries, nil) {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonBounds, nil)
	}
	if err := ctx.Err(); err != nil {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonInput, err)
	}
	binding, err := syncengine.NewTargetBinding(selection.portable)
	if err != nil {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonPlan, err)
	}
	plan, err := syncengine.Reconcile(baseView, localView, current.entries, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
	if err != nil {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonPlan, err)
	}
	if err := ctx.Err(); err != nil {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonInput, err)
	}
	preview, err := syncengine.BuildPreview(plan, []model.Target{selection.portable}, captured.observations)
	if err != nil {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonPlan, err)
	}
	if err := checkAcceptedPublicationFloor(ctx, owned.store, material.floor); err != nil {
		return syncengine.Preview{}, "", err
	}
	if err := ctx.Err(); err != nil {
		return syncengine.Preview{}, "", publicationPreviewFailure(ctx, publicationPreviewReasonInput, err)
	}
	return preview, disposition, nil
}

type publicationPreviewInputs struct {
	store          *publicationstate.Store
	binding        publicationstate.Binding
	expectedFloor  publicationstate.Floor
	snapshotRecord []byte
	payload        []byte
	configuration  config.Config
	targetID       string
	local          *PublicationLocalContext
	base           *PublicationReconciliationBase
}

func snapshotPublicationPreviewInputs(ctx context.Context, request PublicationReconciliationRequest, base *PublicationReconciliationBase) (publicationPreviewInputs, error) {
	if ctx == nil || request.Store == nil || request.Local == nil || request.TargetID == "" {
		return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonInput, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonInput, err)
	}
	if len(request.SnapshotRecord) == 0 || len(request.SnapshotRecord) > publication.MaxRecordBytes || len(request.Payload) == 0 || uint64(len(request.Payload)) > publication.MaxBlobBytes || !validPublicationFloorInput(request.ExpectedFloor) {
		return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonInput, nil)
	}
	if len(request.Configuration.Targets) > publicationSelectionMaxTargets {
		return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonBounds, nil)
	}
	for _, target := range request.Configuration.Targets {
		if target.Root != nil && len(target.Root.Exclude) > publicationSelectionMaxExcludes || target.GNOMEPolicy != nil && len(target.GNOMEPolicy.Categories) > matrix.MaxKeys {
			return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonBounds, nil)
		}
	}
	budget := publicationStringBudget{}
	if !addPublicationConfigStrings(&budget, request.Configuration) || !budget.add(request.TargetID) {
		return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonBounds, nil)
	}
	local := snapshotPublicationLocalContext(request.Local)
	if !validPublicationContextPaths(local.paths) {
		return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonInput, nil)
	}
	pathBytes := 0
	for _, path := range []string{local.paths.Home, local.paths.ConfigHome, local.paths.StateHome, local.paths.CacheHome, local.paths.DataHome} {
		if !budget.add(path) {
			return publicationPreviewInputs{}, publicationPreviewFailure(ctx, publicationPreviewReasonBounds, nil)
		}
		pathBytes += len(path)
	}
	local.pathBytes = pathBytes

	owned := publicationPreviewInputs{
		store: request.Store, binding: request.Binding,
		expectedFloor:  clonePublicationFloor(request.ExpectedFloor),
		snapshotRecord: bytes.Clone(request.SnapshotRecord), payload: bytes.Clone(request.Payload),
		configuration: clonePublicationPreviewConfig(request.Configuration), targetID: request.TargetID, local: local,
	}
	if base != nil {
		ownedBase, reason := snapshotPublicationPreviewBase(base)
		if reason != "" {
			return publicationPreviewInputs{}, publicationPreviewFailure(ctx, reason, nil)
		}
		owned.base = ownedBase
	}
	return owned, nil
}

func clonePublicationPreviewConfig(configuration config.Config) config.Config {
	out := configuration
	if configuration.Targets != nil {
		out.Targets = make([]config.Target, len(configuration.Targets))
		for index, target := range configuration.Targets {
			out.Targets[index] = cloneSelectionTarget(target)
		}
	}
	return out
}

func snapshotPublicationPreviewBase(base *PublicationReconciliationBase) (*PublicationReconciliationBase, publicationReconciliationReason) {
	if !validPublicationFloorInput(base.position.floor) || len(base.position.snapshotRecord) == 0 || len(base.position.snapshotRecord) > publication.MaxRecordBytes {
		return nil, publicationPreviewReasonInput
	}
	if !publicationPreviewBaseSelectionWithinBounds(base.selection) {
		return nil, publicationPreviewReasonBounds
	}
	retained := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{base.selection.portable}, Entries: base.entries}
	if !publicationProjectionWithinBounds(retained) {
		return nil, publicationPreviewReasonBounds
	}
	position := publicationBasePosition{floor: clonePublicationFloor(base.position.floor), snapshotRecord: bytes.Clone(base.position.snapshotRecord)}
	selection := clonePublicationPreviewBaseSelection(base.selection)
	entries := make([]model.Entry, len(base.entries))
	for index, entry := range base.entries {
		entries[index] = clonePublicationProjectionEntry(entry)
	}
	return &PublicationReconciliationBase{position: position, selection: selection, entries: entries}, ""
}

func publicationPreviewBaseSelectionWithinBounds(selection publicationBaseSelection) bool {
	if selection.target.Root != nil && len(selection.target.Root.Exclude) > publicationSelectionMaxExcludes {
		return false
	}
	if selection.target.GNOMEPolicy != nil && len(selection.target.GNOMEPolicy.Categories) > matrix.MaxKeys || len(selection.excludes) > publicationSelectionMaxExcludes || len(selection.settingRefs) > matrix.MaxKeys {
		return false
	}
	budget := publicationStringBudget{}
	values := []string{
		selection.paths.Home, selection.paths.ConfigHome, selection.paths.StateHome, selection.paths.CacheHome, selection.paths.DataHome,
		selection.target.ID, string(selection.target.Source), string(selection.mode), selection.portable.ID, string(selection.portable.Source),
		selection.resolvedPath, selection.anchorPath, selection.anchorName,
	}
	for _, value := range values {
		if !budget.add(value) {
			return false
		}
	}
	if selection.target.Root != nil {
		if !budget.add(string(selection.target.Root.Base)) || !budget.add(selection.target.Root.Path) || !budget.add(string(selection.target.Root.Kind)) {
			return false
		}
		for _, value := range selection.target.Root.Exclude {
			if !budget.add(value) {
				return false
			}
		}
	}
	if selection.target.GNOMEPolicy != nil {
		if !budget.add(string(selection.target.GNOMEPolicy.Approval)) || !budget.add(selection.target.GNOMEPolicy.KeyDigest) {
			return false
		}
		for _, value := range selection.target.GNOMEPolicy.Categories {
			if !budget.add(value) {
				return false
			}
		}
	}
	for _, value := range selection.excludes {
		if !budget.add(value) {
			return false
		}
	}
	for _, ref := range selection.settingRefs {
		if !budget.add(ref.SchemaID) || !budget.add(ref.Path) || !budget.add(ref.Key) {
			return false
		}
	}
	return true
}

func clonePublicationPreviewBaseSelection(selection publicationBaseSelection) publicationBaseSelection {
	out := selection
	out.target = cloneSelectionTarget(selection.target)
	out.portable = cloneSelectionTargetModel(selection.portable)
	out.excludes = append([]string(nil), selection.excludes...)
	out.settingRefs = append([]SettingRef(nil), selection.settingRefs...)
	return out
}

func publicationPreviewTarget(snapshot model.Snapshot, targetID string) (model.Target, bool) {
	for _, target := range snapshot.Targets {
		if target.ID == targetID {
			return cloneSelectionTargetModel(target), true
		}
	}
	return model.Target{}, false
}

func publicationPreviewFailure(ctx context.Context, reason publicationReconciliationReason, cause error) error {
	return publicationReconciliationFailure(ctx, publicationPreviewStage, reason, cause)
}
