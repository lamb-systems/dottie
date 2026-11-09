package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
)

const publicationSelectionMaxTargets = 256
const publicationSelectionMaxStringBytes = 1 << 20
const publicationSelectionMaxExcludes = 64
const publicationSelectionMaxExcludeBytes = 4096

type publicationSelectionStageCode string
type publicationSelectionReasonCode string

type publicationContextAffinity struct {
	identity byte
}

type PublicationLocalContext struct {
	paths     platform.Paths
	files     CapturePort
	settings  SettingsPort
	affinity  *publicationContextAffinity
	pathBytes int
}

type publicationSelection struct {
	context      *PublicationLocalContext
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

const (
	publicationSelectionStage = publicationSelectionStageCode("selection")

	publicationSelectionReasonInput    = publicationSelectionReasonCode("input_invalid")
	publicationSelectionReasonConfig   = publicationSelectionReasonCode("config_invalid")
	publicationSelectionReasonTarget   = publicationSelectionReasonCode("target_mismatch")
	publicationSelectionReasonBounds   = publicationSelectionReasonCode("bounds_exceeded")
	publicationSelectionReasonRoot     = publicationSelectionReasonCode("root_invalid")
	publicationSelectionReasonSettings = publicationSelectionReasonCode("settings_invalid")
	publicationSelectionReasonCanceled = publicationSelectionReasonCode("canceled")
)

func NewPublicationLocalContext(paths platform.Paths, capture CapturePort, settings SettingsPort) (*PublicationLocalContext, error) {
	budget := publicationStringBudget{}
	for _, value := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		if value == "" || len(value) > model.MaxRelativePathBytes || !filepath.IsAbs(value) || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || !budget.add(value) {
			return nil, publicationSelectionFailure(context.Background(), publicationSelectionReasonInput)
		}
	}
	if nilPublicationDependency(capture) {
		capture = LocalFilesCapture{}
	}
	if nilPublicationDependency(settings) {
		settings = nil
	}
	return &PublicationLocalContext{
		paths: paths, files: capture, settings: settings,
		affinity: &publicationContextAffinity{identity: 1}, pathBytes: budget.used,
	}, nil
}

func selectPublicationTarget(ctx context.Context, local *PublicationLocalContext, configuration config.Config, selectedID string, expected model.Target) (publicationSelection, error) {
	if ctx == nil || local == nil || local.affinity == nil || local.files == nil || !validPublicationContextPaths(local.paths) {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonInput)
	}
	if err := ctx.Err(); err != nil {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonCanceled)
	}
	if len(configuration.Targets) > publicationSelectionMaxTargets {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonBounds)
	}
	for _, target := range configuration.Targets {
		if target.Root != nil {
			if len(target.Root.Exclude) > publicationSelectionMaxExcludes {
				return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonBounds)
			}
			for _, pattern := range target.Root.Exclude {
				if len(pattern) > publicationSelectionMaxExcludeBytes {
					return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonBounds)
				}
			}
		}
		if target.GNOMEPolicy != nil && len(target.GNOMEPolicy.Categories) > matrix.MaxKeys {
			return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonBounds)
		}
	}
	budget := publicationStringBudget{used: local.pathBytes}
	if !addPublicationConfigStrings(&budget, configuration) || !budget.add(selectedID) || !addPortableTargetStrings(&budget, expected) {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonBounds)
	}
	if configuration.Version != config.Version || configuration.Validate() != nil {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonConfig)
	}
	if expected.Validate() != nil || selectedID == "" {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonTarget)
	}

	selectedIndex := -1
	var selected config.Target
	for index, target := range configuration.Targets {
		if target.ID != selectedID {
			continue
		}
		if selectedIndex != -1 {
			return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonTarget)
		}
		selectedIndex = index
		selected = target
	}
	if selectedIndex == -1 {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonTarget)
	}
	portable, err := selected.Model()
	if err != nil || !reflect.DeepEqual(portable, expected) {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonTarget)
	}
	others := configuration
	others.Targets = make([]config.Target, 0, len(configuration.Targets)-1)
	for index, target := range configuration.Targets {
		if index != selectedIndex {
			others.Targets = append(others.Targets, target)
		}
	}
	if config.CheckAddition(others, local.paths, selected) != nil {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonRoot)
	}

	selection := publicationSelection{context: local}
	if selected.Source == model.SourceFiles {
		var derivedPaths []string
		selection.resolvedPath, selection.anchorPath, selection.anchorName, selection.anchorInfo, derivedPaths, err = resolvePublicationFileAnchor(selected, local.paths)
		if err != nil {
			return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonRoot)
		}
		for _, path := range derivedPaths {
			if !budget.add(path) {
				return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonBounds)
			}
		}
	} else {
		if local.settings == nil || selected.GNOMEPolicy == nil || len(selected.GNOMEPolicy.Categories) > matrix.MaxKeys {
			return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonSettings)
		}
		refs, resolveErr := approvedSettings(ctx, local.settings, selected)
		if resolveErr != nil || len(refs) > matrix.MaxKeys {
			return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonSettings)
		}
		for _, ref := range refs {
			if !budget.add(ref.SchemaID) || !budget.add(ref.Path) || !budget.add(ref.Key) {
				return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonBounds)
			}
		}
		selection.settingRefs, resolveErr = validatePublicationSettingRefs(selected.ID, refs)
		if resolveErr != nil {
			return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonSettings)
		}
	}
	if err := ctx.Err(); err != nil {
		return publicationSelection{}, publicationSelectionFailure(ctx, publicationSelectionReasonCanceled)
	}
	selection.target = cloneSelectionTarget(selected)
	selection.portable = cloneSelectionTargetModel(portable)
	selection.mode = selected.ModeOrDefault(configuration.Defaults)
	if selected.Root != nil {
		selection.excludes = append([]string(nil), selected.Root.Exclude...)
	}
	return selection, nil
}

func samePublicationContext(left, right *PublicationLocalContext) bool {
	return left != nil && right != nil && left.affinity != nil && left.affinity == right.affinity
}

type publicationStringBudget struct {
	used int
}

func (budget *publicationStringBudget) add(value string) bool {
	remaining := publicationSelectionMaxStringBytes - budget.used
	if remaining < 0 || len(value) > remaining {
		return false
	}
	if !utf8.ValidString(value) {
		return false
	}
	budget.used += len(value)
	return true
}

func addPublicationConfigStrings(budget *publicationStringBudget, configuration config.Config) bool {
	if !budget.add(string(configuration.Defaults.Mode)) {
		return false
	}
	for _, target := range configuration.Targets {
		if !budget.add(target.ID) || !budget.add(string(target.Source)) || !budget.add(string(target.Mode)) {
			return false
		}
		if target.Root != nil {
			if !budget.add(string(target.Root.Base)) || !budget.add(target.Root.Path) || !budget.add(string(target.Root.Kind)) {
				return false
			}
			for _, pattern := range target.Root.Exclude {
				if !budget.add(pattern) {
					return false
				}
			}
		}
		if target.GNOMEPolicy != nil {
			if !budget.add(string(target.GNOMEPolicy.Approval)) || !budget.add(target.GNOMEPolicy.KeyDigest) {
				return false
			}
			for _, category := range target.GNOMEPolicy.Categories {
				if !budget.add(category) {
					return false
				}
			}
		}
	}
	return true
}

func addPortableTargetStrings(budget *publicationStringBudget, target model.Target) bool {
	if !budget.add(target.ID) || !budget.add(string(target.Source)) {
		return false
	}
	if target.Root != nil {
		return budget.add(string(target.Root.Base)) && budget.add(target.Root.Path) && budget.add(string(target.Root.Kind))
	}
	return true
}

func nilPublicationDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validPublicationContextPaths(paths platform.Paths) bool {
	for _, value := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		if value == "" || len(value) > model.MaxRelativePathBytes || !filepath.IsAbs(value) || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			return false
		}
	}
	return true
}

func resolvePublicationFileAnchor(target config.Target, paths platform.Paths) (string, string, string, os.FileInfo, []string, error) {
	if target.Source != model.SourceFiles || target.Root == nil {
		return "", "", "", nil, nil, os.ErrInvalid
	}
	logicalPath, err := target.ResolvedPath(paths)
	if err != nil {
		return "", "", "", nil, nil, err
	}
	resolvedPath, err := platform.RealPath(logicalPath)
	if err != nil {
		return "", "", "", nil, nil, err
	}
	var declaredBase string
	switch target.Root.Base {
	case model.RootHome:
		declaredBase, err = platform.RealPath(paths.Home)
	case model.RootXDGConfig:
		declaredBase, err = platform.RealPath(paths.ConfigHome)
	default:
		return "", "", "", nil, nil, os.ErrInvalid
	}
	if err != nil || !publicationPathWithin(declaredBase, resolvedPath) {
		return "", "", "", nil, nil, os.ErrPermission
	}
	homeBase, homeErr := platform.RealPath(paths.Home)
	configBase, configErr := platform.RealPath(paths.ConfigHome)
	if homeErr != nil || configErr != nil || resolvedPath == homeBase || resolvedPath == configBase {
		return "", "", "", nil, nil, os.ErrPermission
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return "", "", "", nil, nil, err
	}
	anchorPath := resolvedPath
	anchorName := ""
	switch target.Root.Kind {
	case model.SelectionDirectory:
		if !info.IsDir() {
			return "", "", "", nil, nil, os.ErrInvalid
		}
		for _, basePath := range []string{homeBase, configBase} {
			baseInfo, statErr := os.Stat(basePath)
			if statErr == nil && os.SameFile(info, baseInfo) {
				return "", "", "", nil, nil, os.ErrPermission
			}
		}
	case model.SelectionFile:
		lexicalInfo, lstatErr := os.Lstat(logicalPath)
		if lstatErr != nil || lexicalInfo.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", "", "", nil, nil, os.ErrInvalid
		}
		anchorName = filepath.Base(logicalPath)
		logicalParent, parentErr := platform.RealPath(filepath.Dir(logicalPath))
		if parentErr != nil || anchorName != filepath.Base(resolvedPath) || logicalParent != filepath.Dir(resolvedPath) {
			return "", "", "", nil, nil, os.ErrInvalid
		}
		anchorPath = logicalParent
		info, err = os.Stat(anchorPath)
		if err != nil || !info.IsDir() || anchorName == "." || anchorName == ".." {
			return "", "", "", nil, nil, os.ErrInvalid
		}
	default:
		return "", "", "", nil, nil, os.ErrInvalid
	}
	derivedPaths := []string{logicalPath, resolvedPath, declaredBase, homeBase, configBase, anchorPath, anchorName}
	return resolvedPath, anchorPath, anchorName, info, derivedPaths, nil
}

func publicationPathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	if relative == "." {
		return true
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == ".." {
			return false
		}
	}
	return true
}

func cloneSelectionTarget(target config.Target) config.Target {
	out := target
	if target.Root != nil {
		root := *target.Root
		root.Exclude = append([]string(nil), target.Root.Exclude...)
		out.Root = &root
	}
	if target.GNOMEPolicy != nil {
		policy := *target.GNOMEPolicy
		policy.Categories = append([]string(nil), target.GNOMEPolicy.Categories...)
		out.GNOMEPolicy = &policy
	}
	return out
}

func cloneSelectionTargetModel(target model.Target) model.Target {
	out := target
	if target.Root != nil {
		root := *target.Root
		out.Root = &root
	}
	return out
}

func validatePublicationSettingRefs(targetID string, refs []SettingRef) ([]SettingRef, error) {
	if len(refs) > matrix.MaxKeys {
		return nil, errors.New("invalid selected settings")
	}
	seen := make(map[model.EntryKey]struct{}, len(refs))
	validated := make([]SettingRef, 0, len(refs))
	for _, ref := range refs {
		key := model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key}
		locator := matrix.KeyRef{SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key}
		if key.Validate() != nil || locator.Validate() != nil {
			return nil, errors.New("invalid selected settings")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("invalid selected settings")
		}
		seen[key] = struct{}{}
		validated = append(validated, ref)
	}
	sortSettingRefs(validated)
	return validated, nil
}

func sortSettingRefs(refs []SettingRef) {
	for i := 1; i < len(refs); i++ {
		for j := i; j > 0 && settingRefLess(refs[j], refs[j-1]); j-- {
			refs[j], refs[j-1] = refs[j-1], refs[j]
		}
	}
}

func settingRefLess(left, right SettingRef) bool {
	if left.SchemaID != right.SchemaID {
		return left.SchemaID < right.SchemaID
	}
	if left.Path != right.Path {
		return left.Path < right.Path
	}
	return left.Key < right.Key
}

func publicationSelectionFailure(ctx context.Context, reason publicationSelectionReasonCode) error {
	if ctx != nil && ctx.Err() != nil {
		reason = publicationSelectionReasonCanceled
	}
	return publicationReconciliationFailure(ctx, publicationReconciliationStage(publicationSelectionStage), publicationReconciliationReason(reason), nil)
}
