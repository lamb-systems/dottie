package service

import (
	"context"
	"errors"
	"reflect"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
)

const publicationCaptureGNOMESettingsChanged publicationReconciliationReason = "settings_changed"

func capturePublicationGNOME(ctx context.Context, selection publicationSelection) (publicationCapture, error) {
	if ctx == nil || !validPublicationGNOMESelection(selection) {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonInput, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}

	selectedRefs, ok := publicationGNOMESelectedRefs(selection)
	if !ok {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonInput, nil)
	}
	expectedRefs := append([]SettingRef(nil), selectedRefs...)
	matched, cancellation := publicationGNOMERefsMatch(ctx, selection, expectedRefs)
	if !matched {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureGNOMESettingsChanged, cancellation)
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}

	callbackRefs := append([]SettingRef(nil), expectedRefs...)
	captured, err := selection.context.settings.Capture(ctx, selection.target.ID, callbackRefs)
	if err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonProvider, err)
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}
	matched, cancellation = publicationGNOMERefsMatch(ctx, selection, expectedRefs)
	if !matched {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureGNOMESettingsChanged, cancellation)
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}

	adapted, reason := adaptPublicationGNOMECapture(selection, expectedRefs, captured)
	if reason != "" {
		return publicationCapture{}, publicationCaptureFailure(ctx, reason, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}
	return adapted, nil
}

func validPublicationGNOMESelection(selection publicationSelection) bool {
	if selection.context == nil || selection.context.affinity == nil || selection.context.affinity.identity == 0 || nilPublicationDependency(selection.context.settings) || !validPublicationContextPaths(selection.context.paths) {
		return false
	}
	if selection.target.Source != model.SourceGNOME || selection.target.Root != nil || selection.target.GNOMEPolicy == nil || len(selection.target.GNOMEPolicy.Categories) > matrix.MaxKeys {
		return false
	}
	portable, err := selection.target.Model()
	if err != nil || !reflect.DeepEqual(portable, selection.portable) || portable.Validate() != nil || portable.Source != model.SourceGNOME || portable.Root != nil {
		return false
	}
	_, ok := publicationGNOMESelectedRefs(selection)
	return ok
}

func publicationGNOMESelectedRefs(selection publicationSelection) ([]SettingRef, bool) {
	if selection.target.GNOMEPolicy == nil || len(selection.target.GNOMEPolicy.Categories) > matrix.MaxKeys || len(selection.settingRefs) == 0 || len(selection.settingRefs) > matrix.MaxKeys {
		return nil, false
	}
	budget := publicationStringBudget{}
	if !budget.add(selection.target.ID) || !budget.add(string(selection.target.GNOMEPolicy.Approval)) || !budget.add(selection.target.GNOMEPolicy.KeyDigest) {
		return nil, false
	}
	for _, category := range selection.target.GNOMEPolicy.Categories {
		if !budget.add(category) {
			return nil, false
		}
	}
	for _, ref := range selection.settingRefs {
		if !budget.add(ref.SchemaID) || !budget.add(ref.Path) || !budget.add(ref.Key) {
			return nil, false
		}
	}
	refs, err := validatePublicationSettingRefs(selection.target.ID, selection.settingRefs)
	if err != nil || len(refs) == 0 || !sameSettingRefs(refs, selection.settingRefs) {
		return nil, false
	}
	return refs, true
}

type publicationGNOMEResolvePort struct {
	SettingsPort
	cancellation error
}

func (port *publicationGNOMEResolvePort) Resolve(ctx context.Context, targetID, schemaID, path string) (string, error) {
	resolved, err := port.SettingsPort.Resolve(ctx, targetID, schemaID, path)
	if errors.Is(err, context.Canceled) {
		port.cancellation = context.Canceled
	} else if errors.Is(err, context.DeadlineExceeded) {
		port.cancellation = context.DeadlineExceeded
	}
	return resolved, err
}

func publicationGNOMERefsMatch(ctx context.Context, selection publicationSelection, expected []SettingRef) (bool, error) {
	if ctx == nil || ctx.Err() != nil || !validPublicationGNOMESelectionWithoutRefs(selection) {
		return false, nil
	}
	port := &publicationGNOMEResolvePort{SettingsPort: selection.context.settings}
	resolved, err := approvedSettings(ctx, port, selection.target)
	if err != nil || ctx.Err() != nil || len(resolved) == 0 || len(resolved) > matrix.MaxKeys {
		return false, port.cancellation
	}
	validated, err := validatePublicationSettingRefs(selection.target.ID, resolved)
	return err == nil && len(validated) == len(expected) && sameSettingRefs(validated, expected), nil
}

func validPublicationGNOMESelectionWithoutRefs(selection publicationSelection) bool {
	if selection.context == nil || selection.context.affinity == nil || selection.context.affinity.identity == 0 || nilPublicationDependency(selection.context.settings) || selection.target.Source != model.SourceGNOME || selection.target.Root != nil || selection.target.GNOMEPolicy == nil {
		return false
	}
	portable, err := selection.target.Model()
	return err == nil && reflect.DeepEqual(portable, selection.portable) && portable.Validate() == nil && portable.Source == model.SourceGNOME && portable.Root == nil
}

func sameSettingRefs(left, right []SettingRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func adaptPublicationGNOMECapture(selection publicationSelection, refs []SettingRef, captured SettingsCapture) (publicationCapture, publicationReconciliationReason) {
	if len(captured.Entries) > len(refs) || len(captured.Unknown) > len(refs)-len(captured.Entries) {
		return publicationCapture{}, publicationCaptureReasonBounds
	}
	valueLimit := model.MaxVariantTypeBytes + model.MaxVariantTextBytes
	aggregateLimit := len(refs) * valueLimit
	var aggregateBytes int
	for _, entry := range captured.Entries {
		if entry.Setting == nil || entry.Setting.Value == nil {
			continue
		}
		typeBytes := len(entry.Setting.Value.Type)
		textBytes := len(entry.Setting.Value.Text)
		if typeBytes > model.MaxVariantTypeBytes || textBytes > model.MaxVariantTextBytes || typeBytes > aggregateLimit-aggregateBytes || textBytes > aggregateLimit-aggregateBytes-typeBytes {
			return publicationCapture{}, publicationCaptureReasonBounds
		}
		aggregateBytes += typeBytes + textBytes
	}

	selected := make(map[model.EntryKey]struct{}, len(refs))
	for _, ref := range refs {
		key := model.EntryKey{TargetID: selection.target.ID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}
		selected[key] = struct{}{}
	}
	seen := make(map[model.EntryKey]struct{}, len(captured.Entries)+len(captured.Unknown))
	for _, entry := range captured.Entries {
		if entry.TargetID != selection.target.ID || entry.File != nil || entry.Setting == nil || entry.Validate() != nil {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		key := entry.Identity()
		if key.Source != model.SourceGNOME || key.Validate() != nil {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		setting := entry.Setting
		if (matrix.KeyRef{SchemaID: setting.SchemaID, Path: setting.Path, Key: setting.Key}).Validate() != nil {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		if _, ok := selected[key]; !ok {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		if _, duplicate := seen[key]; duplicate {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		seen[key] = struct{}{}
	}
	for _, key := range captured.Unknown {
		if key.TargetID != selection.target.ID || key.Source != model.SourceGNOME || key.Validate() != nil || (matrix.KeyRef{SchemaID: key.SchemaID, Path: key.SettingsPath, Key: key.SettingKey}).Validate() != nil {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		if _, ok := selected[key]; !ok {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		if _, duplicate := seen[key]; duplicate {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		seen[key] = struct{}{}
	}

	entries := make(map[model.EntryKey]int, len(captured.Entries))
	for index, entry := range captured.Entries {
		entries[entry.Identity()] = index
	}
	observations := make([]model.Observation, 0, len(refs))
	complete := true
	for _, ref := range refs {
		key := model.EntryKey{TargetID: selection.target.ID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}
		if index, ok := entries[key]; ok {
			observations = append(observations, model.Observation{State: model.ObservationPresent, Identity: key, Entry: clonePublicationGNOMEEntry(captured.Entries[index])})
			continue
		}
		observations = append(observations, model.Observation{State: model.ObservationUnknown, Identity: key})
		complete = false
	}
	return publicationCapture{observations: observations, complete: complete}, publicationReconciliationReason("")
}

func clonePublicationGNOMEEntry(entry model.Entry) *model.Entry {
	out := entry
	if entry.Setting != nil {
		setting := *entry.Setting
		if entry.Setting.Value != nil {
			value := *entry.Setting.Value
			setting.Value = &value
		}
		out.Setting = &setting
	}
	return &out
}
