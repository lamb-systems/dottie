package service

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/ignore"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
)

type publicationCapture struct {
	observations []model.Observation
	complete     bool
}

const (
	publicationCaptureStage publicationReconciliationStage = "capture"

	publicationCaptureReasonInput    publicationReconciliationReason = "request_invalid"
	publicationCaptureReasonBounds   publicationReconciliationReason = "bounds_exceeded"
	publicationCaptureReasonProvider publicationReconciliationReason = "provider_invalid"
	publicationCaptureReasonRoot     publicationReconciliationReason = "root_changed"
	publicationCaptureReasonCanceled publicationReconciliationReason = "canceled"
)

func capturePublicationFiles(ctx context.Context, selection publicationSelection) (publicationCapture, error) {
	if ctx == nil || !validPublicationFileSelection(selection) {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonInput, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}
	matcher, err := ignore.Compile(selection.excludes)
	if err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonInput, nil)
	}
	if !publicationCaptureAnchorMatches(selection) {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonRoot, nil)
	}

	var result files.Result
	callbackUsed := true
	singleFileDotExcluded := publicationFilePathExcluded(selection.target.Root.Kind, matcher, ".")
	if selection.target.Root.Kind == model.SelectionFile && singleFileDotExcluded {
		callbackUsed = false
	} else {
		target := cloneSelectionTarget(selection.target)
		result, err = selection.context.files.Capture(ctx, target, selection.resolvedPath)
		if err != nil {
			return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonProvider, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}
	if !publicationCaptureAnchorMatches(selection) {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonRoot, nil)
	}
	adapted, reason := adaptPublicationFileCapture(selection, matcher, result, callbackUsed)
	if reason != "" {
		return publicationCapture{}, publicationCaptureFailure(ctx, reason, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationCapture{}, publicationCaptureFailure(ctx, publicationCaptureReasonCanceled, err)
	}
	return adapted, nil
}

func validPublicationFileSelection(selection publicationSelection) bool {
	if selection.context == nil || selection.context.affinity == nil || selection.context.files == nil || !validPublicationContextPaths(selection.context.paths) || selection.target.Source != model.SourceFiles || selection.target.Root == nil || selection.anchorInfo == nil {
		return false
	}
	portable, err := selection.target.Model()
	if err != nil || !reflect.DeepEqual(portable, selection.portable) || portable.Validate() != nil {
		return false
	}
	if !samePublicationStrings(selection.target.Root.Exclude, selection.excludes) {
		return false
	}
	if !filepath.IsAbs(selection.resolvedPath) || !filepath.IsAbs(selection.anchorPath) {
		return false
	}
	switch selection.target.Root.Kind {
	case model.SelectionDirectory:
		return selection.anchorName == "" && selection.resolvedPath == selection.anchorPath
	case model.SelectionFile:
		return selection.anchorName != "" && selection.anchorName != "." && selection.anchorName != ".." && selection.anchorName == filepath.Base(selection.resolvedPath) && filepath.Dir(selection.resolvedPath) == selection.anchorPath
	default:
		return false
	}
}

func samePublicationStrings(left, right []string) bool {
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

func publicationCaptureAnchorMatches(selection publicationSelection) bool {
	anchorInfo, err := os.Lstat(selection.anchorPath)
	if err != nil || anchorInfo.Mode()&os.ModeSymlink != 0 || !anchorInfo.IsDir() || !os.SameFile(selection.anchorInfo, anchorInfo) {
		return false
	}
	if config.CheckAddition(config.Default(), selection.context.paths, selection.target) != nil {
		return false
	}
	resolvedPath, anchorPath, anchorName, currentInfo, _, err := resolvePublicationFileAnchor(selection.target, selection.context.paths)
	if err != nil || resolvedPath != selection.resolvedPath || anchorPath != selection.anchorPath || anchorName != selection.anchorName || !os.SameFile(selection.anchorInfo, currentInfo) {
		return false
	}
	finalInfo, err := os.Lstat(selection.anchorPath)
	return err == nil && finalInfo.Mode()&os.ModeSymlink == 0 && finalInfo.IsDir() && os.SameFile(selection.anchorInfo, finalInfo)
}

func adaptPublicationFileCapture(selection publicationSelection, matcher ignore.Matcher, result files.Result, callbackUsed bool) (publicationCapture, publicationReconciliationReason) {
	budget := files.DefaultBudget()
	if len(result.Observations) > budget.MaxEntries || len(result.Skipped) > budget.MaxEntries-len(result.Observations) {
		return publicationCapture{}, publicationCaptureReasonBounds
	}

	var totalBytes int64
	for _, observation := range result.Observations {
		path := observation.Identity.FilePath
		if observation.Identity.Source == model.SourceFiles && (len(path) > model.MaxRelativePathBytes || !publicationCapturePathDepthWithin(path, budget.MaxDepth)) {
			return publicationCapture{}, publicationCaptureReasonBounds
		}
		if observation.Entry != nil && observation.Entry.File != nil && observation.Entry.File.Kind == model.FileRegular {
			size := len(observation.Entry.File.Content)
			if size > budget.MaxFileBytes || int64(size) > int64(budget.MaxTotalBytes)-totalBytes {
				return publicationCapture{}, publicationCaptureReasonBounds
			}
			totalBytes += int64(size)
		}
	}
	for _, skip := range result.Skipped {
		if len(skip.Path) > model.MaxRelativePathBytes || !publicationCapturePathDepthWithin(skip.Path, budget.MaxDepth) {
			return publicationCapture{}, publicationCaptureReasonBounds
		}
	}

	seen := make(map[string]struct{}, len(result.Observations)+len(result.Skipped))
	nonDirectories := make(map[string]struct{}, len(result.Observations)+len(result.Skipped))
	paths := make([]string, 0, len(result.Observations)+len(result.Skipped))
	for _, observation := range result.Observations {
		if !validPublicationFileObservation(selection, observation) {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		path := observation.Identity.FilePath
		if _, duplicate := seen[path]; duplicate {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
		if observation.State == model.ObservationPresent && observation.Entry.File.Kind != model.FileDirectory {
			nonDirectories[path] = struct{}{}
		}
	}
	for _, skip := range result.Skipped {
		key := model.EntryKey{TargetID: selection.target.ID, Source: model.SourceFiles, FilePath: skip.Path}
		if key.Validate() != nil || !publicationCapturePathAllowed(selection, skip.Path) {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		if _, duplicate := seen[skip.Path]; duplicate {
			return publicationCapture{}, publicationCaptureReasonProvider
		}
		seen[skip.Path] = struct{}{}
		paths = append(paths, skip.Path)
		switch skip.Reason {
		case files.SkipExcluded:
			if selection.target.Root.Kind == model.SelectionDirectory && skip.Path == "." {
				return publicationCapture{}, publicationCaptureReasonProvider
			}
			if !publicationFilePathExcluded(selection.target.Root.Kind, matcher, skip.Path) {
				return publicationCapture{}, publicationCaptureReasonProvider
			}
		case files.SkipSpecialFile, files.SkipExternalLink, files.SkipSymlink:
			if skip.Path != "." {
				nonDirectories[skip.Path] = struct{}{}
			}
		default:
			return publicationCapture{}, publicationCaptureReasonProvider
		}
	}
	for _, path := range paths {
		for parent := publicationCaptureParent(path); parent != "."; parent = publicationCaptureParent(parent) {
			if _, exists := nonDirectories[parent]; exists {
				return publicationCapture{}, publicationCaptureReasonProvider
			}
		}
	}

	byPath := make(map[string]model.Observation, len(paths))
	complete := true
	for _, observation := range result.Observations {
		path := observation.Identity.FilePath
		if observation.State == model.ObservationUnknown && path == "." {
			byPath[path] = model.Observation{State: model.ObservationUnknown, Identity: observation.Identity}
			complete = false
			continue
		}
		if publicationFilePathExcluded(selection.target.Root.Kind, matcher, path) {
			continue
		}
		if observation.State == model.ObservationUnknown {
			byPath[path] = model.Observation{State: model.ObservationUnknown, Identity: observation.Identity}
			complete = false
			continue
		}
		file := observation.Entry.File
		if file.Kind == model.FileSymlink {
			parent := publicationCaptureParent(path)
			if _, external := files.LexicalResolve(parent, file.LinkTarget); external {
				byPath[path] = model.Observation{State: model.ObservationUnknown, Identity: observation.Identity}
				complete = false
				continue
			}
		}
		byPath[path] = clonePublicationCaptureObservation(observation)
	}
	for _, skip := range result.Skipped {
		if skip.Reason == files.SkipExcluded {
			continue
		}
		if skip.Path != "." && publicationFilePathExcluded(selection.target.Root.Kind, matcher, skip.Path) {
			continue
		}
		identity := model.EntryKey{TargetID: selection.target.ID, Source: model.SourceFiles, FilePath: skip.Path}
		byPath[skip.Path] = model.Observation{State: model.ObservationUnknown, Identity: identity}
		complete = false
	}
	if selection.target.Root.Kind == model.SelectionFile && callbackUsed && len(result.Observations) == 0 && len(result.Skipped) == 0 {
		identity := model.EntryKey{TargetID: selection.target.ID, Source: model.SourceFiles, FilePath: "."}
		byPath["."] = model.Observation{State: model.ObservationUnknown, Identity: identity}
		complete = false
	}

	observations := make([]model.Observation, 0, len(byPath))
	for _, observation := range byPath {
		observations = append(observations, observation)
	}
	sort.Slice(observations, func(left, right int) bool {
		return publicationCapturePathLess(observations[left].Identity.FilePath, observations[right].Identity.FilePath)
	})
	return publicationCapture{observations: observations, complete: complete}, publicationReconciliationReason("")
}

func validPublicationFileObservation(selection publicationSelection, observation model.Observation) bool {
	if observation.Identity.TargetID != selection.target.ID || observation.Identity.Source != model.SourceFiles || observation.Identity.Validate() != nil || observation.Validate() != nil {
		return false
	}
	if !publicationCapturePathAllowed(selection, observation.Identity.FilePath) {
		return false
	}
	switch observation.State {
	case model.ObservationUnknown:
		return observation.Entry == nil
	case model.ObservationPresent:
		if observation.Entry == nil || observation.Entry.File == nil || observation.Entry.Setting != nil {
			return false
		}
		file := observation.Entry.File
		if file.State != model.FilePresent {
			return false
		}
		if selection.target.Root.Kind == model.SelectionFile {
			return file.Path == "." && file.Kind == model.FileRegular
		}
		return file.Path != "."
	default:
		return false
	}
}

func publicationCapturePathAllowed(selection publicationSelection, path string) bool {
	key := model.EntryKey{TargetID: selection.target.ID, Source: model.SourceFiles, FilePath: path}
	if key.Validate() != nil {
		return false
	}
	if selection.target.Root.Kind == model.SelectionFile {
		return path == "."
	}
	return selection.target.Root.Kind == model.SelectionDirectory
}

func publicationCapturePathDepthWithin(path string, maximum int) bool {
	if path == "." || path == "" {
		return true
	}
	return strings.Count(path, "/")+1 <= maximum
}

func publicationCaptureParent(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return "."
	}
	return path[:index]
}

func publicationFilePathExcluded(kind model.SelectionKind, matcher ignore.Matcher, path string) bool {
	switch kind {
	case model.SelectionDirectory:
		if path == "." {
			return false
		}
	case model.SelectionFile:
		if path == "." {
			_, excluded := matcher.Exclude(path)
			return excluded
		}
	default:
		return true
	}
	for candidate := path; candidate != "."; candidate = publicationCaptureParent(candidate) {
		if _, excluded := matcher.Exclude(candidate); excluded {
			return true
		}
	}
	return false
}

func publicationCapturePathLess(left, right string) bool {
	leftDepth := publicationCapturePathDepth(left)
	rightDepth := publicationCapturePathDepth(right)
	if leftDepth != rightDepth {
		return leftDepth < rightDepth
	}
	return left < right
}

func publicationCapturePathDepth(path string) int {
	if path == "." {
		return 0
	}
	return strings.Count(path, "/") + 1
}

func clonePublicationCaptureObservation(observation model.Observation) model.Observation {
	out := observation
	if observation.Entry != nil {
		entry := *observation.Entry
		if observation.Entry.File != nil {
			file := *observation.Entry.File
			file.Content = bytes.Clone(observation.Entry.File.Content)
			entry.File = &file
		}
		out.Entry = &entry
	}
	return out
}

func publicationCaptureFailure(ctx context.Context, reason publicationReconciliationReason, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		reason = publicationCaptureReasonCanceled
	}
	return publicationReconciliationFailure(ctx, publicationCaptureStage, reason, cause)
}
