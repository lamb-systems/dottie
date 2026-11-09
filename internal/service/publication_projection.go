package service

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/ignore"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/vault"
)

type publicationProjection struct {
	entries   []model.Entry
	untracked []model.EntryKey
}

const publicationProjectionMaxTargets = 20000

const (
	publicationProjectionStage publicationReconciliationStage = "projection"

	publicationProjectionReasonInput     publicationReconciliationReason = "request_invalid"
	publicationProjectionReasonBounds    publicationReconciliationReason = "bounds_exceeded"
	publicationProjectionReasonSnapshot  publicationReconciliationReason = "snapshot_invalid"
	publicationProjectionReasonSelection publicationReconciliationReason = "selection_mismatch"
)

func projectPublicationSnapshot(selection publicationSelection, snapshot model.Snapshot) (publicationProjection, error) {
	if !publicationProjectionWithinBounds(snapshot) {
		return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonBounds)
	}
	if snapshot.Validate() != nil {
		return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonSnapshot)
	}

	var validSelection bool
	switch selection.portable.Source {
	case model.SourceFiles:
		validSelection = validPublicationFileSelection(selection)
	case model.SourceGNOME:
		validSelection = validPublicationProjectionGNOMESelection(selection)
	}
	if !validSelection {
		return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonInput)
	}

	var selected *model.Target
	for index := range snapshot.Targets {
		if snapshot.Targets[index].ID == selection.portable.ID {
			selected = &snapshot.Targets[index]
			break
		}
	}
	if selected == nil || !reflect.DeepEqual(*selected, selection.portable) {
		return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonSelection)
	}

	switch selection.portable.Source {
	case model.SourceFiles:
		return projectPublicationFileEntries(selection, snapshot)
	case model.SourceGNOME:
		return projectPublicationGNOMEEntries(selection, snapshot)
	default:
		return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonInput)
	}
}

func projectPublicationFileEntries(selection publicationSelection, snapshot model.Snapshot) (publicationProjection, error) {
	matcher, err := ignore.Compile(selection.excludes)
	if err != nil {
		return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonInput)
	}

	projection := publicationProjection{entries: make([]model.Entry, 0), untracked: make([]model.EntryKey, 0)}
	for _, entry := range snapshot.Entries {
		if entry.TargetID != selection.portable.ID {
			continue
		}
		file := entry.File
		path := file.Path
		kind := selection.portable.Root.Kind
		if kind == model.SelectionDirectory && path == "." {
			return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonSnapshot)
		}
		if kind == model.SelectionFile {
			if path != "." || file.State == model.FilePresent && file.Kind != model.FileRegular {
				return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonSnapshot)
			}
		}
		if publicationFilePathExcluded(kind, matcher, path) {
			continue
		}
		if file.State == model.FilePresent && file.Kind == model.FileSymlink {
			parent := publicationCaptureParent(path)
			if _, external := files.LexicalResolve(parent, file.LinkTarget); external {
				return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonSnapshot)
			}
		}
		projection.entries = append(projection.entries, clonePublicationProjectionEntry(entry))
	}
	sort.Slice(projection.entries, func(left, right int) bool {
		return publicationProjectionEntryLess(projection.entries[left], projection.entries[right])
	})
	return projection, nil
}

func validPublicationProjectionGNOMESelection(selection publicationSelection) bool {
	if !validPublicationGNOMESelection(selection) {
		return false
	}
	policy := selection.target.GNOMEPolicy
	if policy.Approval != config.GNOMEApprovalApproved || policy.MatrixVersion != matrix.Version {
		return false
	}
	keys, err := matrix.SelectCategories(policy.Categories)
	if err != nil || len(keys) == 0 || len(keys) > matrix.MaxKeys {
		return false
	}
	digest, err := matrix.KeySetDigest(keys)
	if err != nil || hex.EncodeToString(digest[:]) != policy.KeyDigest {
		return false
	}
	refs, ok := publicationGNOMESelectedRefs(selection)
	if !ok || len(refs) != len(keys) {
		return false
	}

	type schemaSetting struct {
		schema string
		key    string
	}
	multiplicity := make(map[schemaSetting]int, len(keys))
	for _, key := range keys {
		identity := schemaSetting{schema: key.SchemaID, key: key.Key}
		multiplicity[identity]++
	}
	for _, ref := range refs {
		identity := schemaSetting{schema: ref.SchemaID, key: ref.Key}
		if multiplicity[identity] == 0 {
			return false
		}
		multiplicity[identity]--
	}
	for _, count := range multiplicity {
		if count != 0 {
			return false
		}
	}
	return true
}

func projectPublicationGNOMEEntries(selection publicationSelection, snapshot model.Snapshot) (publicationProjection, error) {
	refs, ok := publicationGNOMESelectedRefs(selection)
	if !ok || len(refs) > matrix.MaxKeys {
		return publicationProjection{}, publicationProjectionFailure(publicationProjectionReasonInput)
	}
	approved := make(map[model.EntryKey]struct{}, len(refs))
	for _, ref := range refs {
		approved[model.EntryKey{TargetID: selection.portable.ID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}] = struct{}{}
	}

	projection := publicationProjection{entries: make([]model.Entry, 0), untracked: make([]model.EntryKey, 0)}
	for _, entry := range snapshot.Entries {
		if entry.TargetID != selection.portable.ID {
			continue
		}
		key := entry.Identity()
		if _, ok := approved[key]; !ok {
			projection.untracked = append(projection.untracked, clonePublicationProjectionKey(key))
			continue
		}
		projection.entries = append(projection.entries, clonePublicationProjectionEntry(entry))
	}
	sort.Slice(projection.entries, func(left, right int) bool {
		return publicationProjectionEntryLess(projection.entries[left], projection.entries[right])
	})
	sort.Slice(projection.untracked, func(left, right int) bool {
		return publicationProjectionKeyLess(projection.untracked[left], projection.untracked[right])
	})
	return projection, nil
}

func publicationProjectionWithinBounds(snapshot model.Snapshot) bool {
	limits := vault.DefaultLimits()
	fileBudget := files.DefaultBudget()
	if len(snapshot.Entries) > limits.MaxEntries || len(snapshot.Targets) > publicationProjectionMaxTargets {
		return false
	}

	var metadataBytes int64
	addMetadata := func(value string) bool {
		remaining := limits.MaxManifestBytes - metadataBytes
		if remaining < 0 || int64(len(value)) > remaining {
			return false
		}
		metadataBytes += int64(len(value))
		return true
	}
	for _, target := range snapshot.Targets {
		if len(target.ID) > model.MaxTargetIDBytes || len(target.Source) > len(string(model.SourceFiles)) || !addMetadata(target.ID) || !addMetadata(string(target.Source)) {
			return false
		}
		if target.Root == nil {
			continue
		}
		if len(target.Root.Base) > len(string(model.RootXDGConfig)) || len(target.Root.Path) > model.MaxRelativePathBytes || len(target.Root.Kind) > len(string(model.SelectionDirectory)) || !addMetadata(string(target.Root.Base)) || !addMetadata(target.Root.Path) || !addMetadata(string(target.Root.Kind)) {
			return false
		}
	}

	var fileBytes int64
	for _, entry := range snapshot.Entries {
		if len(entry.TargetID) > model.MaxTargetIDBytes || !addMetadata(entry.TargetID) {
			return false
		}
		if entry.File != nil {
			file := entry.File
			if len(file.Path) > model.MaxRelativePathBytes || !publicationProjectionDepthWithin(file.Path, limits.MaxDepth) || len(file.LinkTarget) > model.MaxSymlinkTargetBytes || len(file.State) > len(string(model.FileDeleted)) || len(file.Kind) > len(string(model.FileDirectory)) {
				return false
			}
			if !addMetadata(file.Path) || !addMetadata(string(file.State)) || !addMetadata(string(file.Kind)) || !addMetadata(file.LinkTarget) {
				return false
			}
			contentBytes := int64(len(file.Content))
			if contentBytes > int64(fileBudget.MaxFileBytes) || contentBytes > int64(fileBudget.MaxTotalBytes)-fileBytes {
				return false
			}
			fileBytes += contentBytes
		}
		if entry.Setting != nil {
			setting := entry.Setting
			if len(setting.SchemaID) > model.MaxSettingSchemaIDBytes || len(setting.Path) > model.MaxRelativePathBytes || !publicationProjectionSettingDepthWithin(setting.Path, limits.MaxDepth) || len(setting.Key) > model.MaxSettingKeyBytes || len(setting.State) > len(string(model.SettingPresent)) {
				return false
			}
			if !addMetadata(setting.SchemaID) || !addMetadata(setting.Path) || !addMetadata(setting.Key) || !addMetadata(string(setting.State)) {
				return false
			}
			if setting.Value != nil {
				if len(setting.Value.Type) > model.MaxVariantTypeBytes || len(setting.Value.Text) > model.MaxVariantTextBytes || !addMetadata(setting.Value.Type) || !addMetadata(setting.Value.Text) {
					return false
				}
			}
		}
	}
	return true
}

func publicationProjectionDepthWithin(path string, maximum int) bool {
	if path == "." {
		return true
	}
	return strings.Count(path, "/")+1 <= maximum
}

func publicationProjectionSettingDepthWithin(path string, maximum int) bool {
	components := strings.Trim(path, "/")
	if components == "" {
		return true
	}
	return strings.Count(components, "/")+1 <= maximum
}

func clonePublicationProjectionEntry(entry model.Entry) model.Entry {
	out := entry
	out.TargetID = strings.Clone(entry.TargetID)
	if entry.File != nil {
		file := *entry.File
		file.Path = strings.Clone(entry.File.Path)
		file.State = model.FileState(strings.Clone(string(entry.File.State)))
		file.Kind = model.FileKind(strings.Clone(string(entry.File.Kind)))
		file.Content = bytes.Clone(entry.File.Content)
		file.LinkTarget = strings.Clone(entry.File.LinkTarget)
		out.File = &file
	}
	if entry.Setting != nil {
		setting := *entry.Setting
		setting.SchemaID = strings.Clone(entry.Setting.SchemaID)
		setting.Path = strings.Clone(entry.Setting.Path)
		setting.Key = strings.Clone(entry.Setting.Key)
		setting.State = model.SettingState(strings.Clone(string(entry.Setting.State)))
		if entry.Setting.Value != nil {
			value := *entry.Setting.Value
			value.Type = strings.Clone(entry.Setting.Value.Type)
			value.Text = strings.Clone(entry.Setting.Value.Text)
			setting.Value = &value
		}
		out.Setting = &setting
	}
	return out
}

func clonePublicationProjectionKey(key model.EntryKey) model.EntryKey {
	return model.EntryKey{
		TargetID: strings.Clone(key.TargetID), Source: model.SourceKind(strings.Clone(string(key.Source))),
		FilePath: strings.Clone(key.FilePath), SchemaID: strings.Clone(key.SchemaID),
		SettingsPath: strings.Clone(key.SettingsPath), SettingKey: strings.Clone(key.SettingKey),
	}
}

func publicationProjectionEntryLess(left, right model.Entry) bool {
	return publicationProjectionKeyLess(left.Identity(), right.Identity())
}

func publicationProjectionKeyLess(left, right model.EntryKey) bool {
	if left.TargetID != right.TargetID {
		return left.TargetID < right.TargetID
	}
	if left.Source != right.Source {
		return left.Source < right.Source
	}
	if left.FilePath != right.FilePath {
		return left.FilePath < right.FilePath
	}
	if left.SchemaID != right.SchemaID {
		return left.SchemaID < right.SchemaID
	}
	if left.SettingsPath != right.SettingsPath {
		return left.SettingsPath < right.SettingsPath
	}
	return left.SettingKey < right.SettingKey
}

func publicationProjectionFailure(reason publicationReconciliationReason) error {
	return publicationReconciliationFailure(nil, publicationProjectionStage, reason, nil)
}
