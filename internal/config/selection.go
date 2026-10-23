package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
)

func ResolveSelection(paths platform.Paths, absPath string) (Root, error) {
	if absPath == "" || !filepath.IsAbs(absPath) {
		return Root{}, errors.New("selection path must be absolute")
	}
	resolved, err := platform.RealPath(absPath)
	if err != nil {
		return Root{}, errors.New("selection path cannot be resolved")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return Root{}, errors.New("selection path is unavailable")
	}
	kind := model.SelectionKind("")
	switch {
	case info.IsDir():
		kind = model.SelectionDirectory
	case info.Mode().IsRegular():
		kind = model.SelectionFile
	default:
		return Root{}, errors.New("selection must be a regular file or directory")
	}

	configBase, err := platform.RealPath(paths.ConfigHome)
	if err != nil {
		return Root{}, errors.New("configuration base cannot be resolved")
	}
	homeBase, err := platform.RealPath(paths.Home)
	if err != nil {
		return Root{}, errors.New("home base cannot be resolved")
	}
	if pathWithin(configBase, resolved) {
		return makeRoot(model.RootXDGConfig, configBase, resolved, kind)
	}
	if pathWithin(homeBase, resolved) {
		return makeRoot(model.RootHome, homeBase, resolved, kind)
	}
	return Root{}, errors.New("selection must be inside HOME or XDG_CONFIG_HOME")
}

func makeRoot(base model.RootBase, basePath, selected string, kind model.SelectionKind) (Root, error) {
	relative, err := filepath.Rel(basePath, selected)
	if err != nil || filepath.IsAbs(relative) {
		return Root{}, errors.New("selection is outside its logical base")
	}
	path := filepath.ToSlash(relative)
	if path == "" {
		path = "."
	}
	root := Root{Base: base, Path: path, Kind: kind}
	if err := (model.FileRoot{Base: root.Base, Path: root.Path, Kind: root.Kind}).Validate(); err != nil {
		return Root{}, err
	}
	if root.Path == "." {
		return Root{}, errors.New("select a subdirectory or file, not the whole base")
	}
	return root, nil
}

func DeriveID(base model.RootBase, path string) string {
	var slug strings.Builder
	lastHyphen := false
	for i := 0; i < len(path); i++ {
		b := path[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')) {
			b = '-'
		}
		if b == '-' {
			if lastHyphen {
				continue
			}
			lastHyphen = true
		} else {
			lastHyphen = false
		}
		slug.WriteByte(b)
	}
	part := strings.Trim(slug.String(), "-")
	id := string(base)
	if part != "" {
		id += "-" + part
	}
	if len(id) > model.MaxTargetIDBytes {
		id = id[:model.MaxTargetIDBytes]
	}
	id = strings.TrimRight(id, "-")
	return id
}

func CheckAddition(c Config, paths platform.Paths, added Target) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("existing configuration is invalid: %w", err)
	}
	if err := validateTarget(added); err != nil {
		return err
	}
	if added.Root != nil && added.Root.Path == "." {
		return errors.New("select a subdirectory or file, not the whole base")
	}
	var candidatePath string
	if added.Root != nil {
		var err error
		candidatePath, err = realTargetPath(added, paths)
		if err != nil {
			return errors.New("new selection root cannot be resolved")
		}
		if err := rejectDottieOverlap(paths, candidatePath); err != nil {
			return err
		}
	}
	for _, existing := range c.Targets {
		if existing.ID == added.ID && !sameLogicalRoot(existing.Root, added.Root) {
			return fmt.Errorf("target id %q is already used by %q and cannot also identify %q", added.ID, targetSelector(existing), targetSelector(added))
		}
		if existing.Root == nil {
			continue
		}
		storedPath, err := realTargetPath(existing, paths)
		if err != nil {
			return fmt.Errorf("stored root for target %q cannot be resolved", existing.ID)
		}
		if err := rejectDottieOverlap(paths, storedPath); err != nil {
			return fmt.Errorf("stored root for target %q is unsafe: %w", existing.ID, err)
		}
		if candidatePath != "" && pathsOverlap(candidatePath, storedPath) {
			return fmt.Errorf("selection overlaps existing target %q; remove it first", existing.ID)
		}
	}
	return nil
}

func realTargetPath(target Target, paths platform.Paths) (string, error) {
	logical, err := target.ResolvedPath(paths)
	if err != nil {
		return "", err
	}
	return platform.RealPath(logical)
}

func rejectDottieOverlap(paths platform.Paths, candidate string) error {
	for _, protected := range []string{paths.AppConfigDir(), paths.AppStateDir(), paths.AppCacheDir(), paths.AppDataDir()} {
		resolved, err := platform.RealPath(protected)
		if err != nil {
			return errors.New("Dottie data location cannot be resolved safely")
		}
		if pathsOverlap(candidate, resolved) {
			return errors.New("selection overlaps Dottie's own configuration, state, cache or data")
		}
	}
	return nil
}

func pathsOverlap(a, b string) bool {
	return pathWithin(a, b) || pathWithin(b, a)
}

func pathWithin(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	relative, err := filepath.Rel(root, candidate)
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

func targetSelector(target Target) string {
	if target.Root == nil {
		return "gnome"
	}
	selector := string(target.Root.Base)
	if target.Root.Path != "." {
		selector += "/" + target.Root.Path
	}
	return selector
}

func sameLogicalRoot(a, b *Root) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Base == b.Base && a.Path == b.Path && a.Kind == b.Kind
}
