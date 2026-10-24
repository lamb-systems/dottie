package config

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/dottorblaster/dottie/internal/ignore"
	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
)

const Version uint32 = 1
const FileName = "config.toml"

type Mode string

const (
	AutoApply  Mode = "auto-apply"
	Review     Mode = "review"
	BackupOnly Mode = "backup-only"
)

type Defaults struct {
	Mode Mode `toml:"mode,omitempty"`
}

type Config struct {
	Version  uint32   `toml:"config_version"`
	Defaults Defaults `toml:"defaults,omitempty"`
	Targets  []Target `toml:"targets,omitempty"`
}

type Target struct {
	ID     string           `toml:"id"`
	Source model.SourceKind `toml:"source"`
	Mode   Mode             `toml:"mode,omitempty"`
	Root   *Root            `toml:"root,omitempty"`
}

type Root struct {
	Base    model.RootBase      `toml:"base"`
	Path    string              `toml:"path"`
	Kind    model.SelectionKind `toml:"kind"`
	Exclude []string            `toml:"exclude,omitempty"`
}

func Default() Config {
	return Config{Version: Version, Defaults: Defaults{Mode: Review}}
}

func (c Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("unsupported or missing config version %d", c.Version)
	}
	if !validModeOrEmpty(c.Defaults.Mode) {
		return errors.New("invalid default mode")
	}
	ids := make(map[string]struct{}, len(c.Targets))
	for _, target := range c.Targets {
		if _, exists := ids[target.ID]; exists {
			return fmt.Errorf("duplicate target id %q", target.ID)
		}
		ids[target.ID] = struct{}{}
		if err := validateTarget(target); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
	}
	return nil
}

func validateTarget(target Target) error {
	portable, err := target.Model()
	if err != nil {
		return err
	}
	if err := portable.Validate(); err != nil {
		return err
	}
	if !validModeOrEmpty(target.Mode) {
		return errors.New("invalid mode")
	}
	if target.Root != nil {
		if target.Root.Path == "." {
			return errors.New("selects a whole base, which is not allowed")
		}
		if _, err := ignore.Compile(target.Root.Exclude); err != nil {
			return fmt.Errorf("invalid exclude patterns: %w", err)
		}
	}
	return nil
}

func (c Config) Target(id string) (Target, bool) {
	for _, target := range c.Targets {
		if target.ID == id {
			return target, true
		}
	}
	return Target{}, false
}

func (t Target) Model() (model.Target, error) {
	portable := model.Target{ID: t.ID, Source: t.Source, SourceVersion: model.SourceVersion}
	if t.Root != nil {
		portable.Root = &model.FileRoot{Base: t.Root.Base, Path: t.Root.Path, Kind: t.Root.Kind}
	}
	if err := portable.Validate(); err != nil {
		return model.Target{}, err
	}
	return portable, nil
}

func (t Target) ModeOrDefault(d Defaults) Mode {
	if t.Mode != "" {
		return t.Mode
	}
	if d.Mode != "" {
		return d.Mode
	}
	return Review
}

func (t Target) ResolvedPath(paths platform.Paths) (string, error) {
	if err := validateTarget(t); err != nil {
		return "", err
	}
	if t.Source != model.SourceFiles || t.Root == nil {
		return "", errors.New("target has no filesystem root")
	}
	var base string
	switch t.Root.Base {
	case model.RootHome:
		base = paths.Home
	case model.RootXDGConfig:
		base = paths.ConfigHome
	default:
		return "", errors.New("unsupported filesystem root base")
	}
	if base == "" || !filepath.IsAbs(base) {
		return "", errors.New("filesystem base is not absolute")
	}
	return filepath.Clean(filepath.Join(base, filepath.FromSlash(t.Root.Path))), nil
}

func (c Config) ResolveTargets(paths platform.Paths) (map[string]string, error) {
	resolved := make(map[string]string)
	for _, target := range c.Targets {
		if target.Source != model.SourceFiles {
			continue
		}
		path, err := target.ResolvedPath(paths)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", target.ID, err)
		}
		path, err = platform.RealPath(path)
		if err != nil {
			return nil, fmt.Errorf("target %q root cannot be resolved", target.ID)
		}
		resolved[target.ID] = path
	}
	return resolved, nil
}

func validModeOrEmpty(mode Mode) bool {
	return mode == "" || mode == AutoApply || mode == Review || mode == BackupOnly
}

func normalizeExcludes(excludes []string) []string {
	seen := make(map[string]struct{}, len(excludes))
	result := make([]string, 0, len(excludes))
	for _, exclude := range excludes {
		if _, exists := seen[exclude]; exists {
			continue
		}
		seen[exclude] = struct{}{}
		result = append(result, exclude)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func normalizeConfig(c Config) Config {
	c.Targets = append([]Target(nil), c.Targets...)
	for i := range c.Targets {
		if c.Targets[i].Root != nil {
			root := *c.Targets[i].Root
			root.Exclude = normalizeExcludes(root.Exclude)
			c.Targets[i].Root = &root
		}
	}
	return c
}
