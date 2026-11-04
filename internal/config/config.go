package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/lamb-systems/dottie/internal/ignore"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
)

const Version uint32 = 2
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
	ID          string           `toml:"id"`
	Source      model.SourceKind `toml:"source"`
	Mode        Mode             `toml:"mode,omitempty"`
	Root        *Root            `toml:"root,omitempty"`
	GNOMEPolicy *GNOMEPolicy     `toml:"gnome_policy,omitempty"`
}

type GNOMEApproval string

const (
	GNOMEApprovalApproved GNOMEApproval = "approved"
	GNOMEApprovalPending  GNOMEApproval = "pending"
)

type GNOMEPolicy struct {
	Approval      GNOMEApproval `toml:"approval"`
	Categories    []string      `toml:"categories,omitempty"`
	MatrixVersion uint32        `toml:"matrix_version,omitempty"`
	KeyDigest     string        `toml:"key_digest,omitempty"`
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
	if c.Version != 1 && c.Version != Version {
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
		if err := validateTarget(target, c.Version); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
	}
	return nil
}

func validateTarget(target Target, version uint32) error {
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
	if err := validateGNOMEPolicy(target, version); err != nil {
		return err
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

func validateGNOMEPolicy(target Target, version uint32) error {
	if target.Source == model.SourceFiles {
		if target.GNOMEPolicy != nil {
			return errors.New("files target cannot carry a GNOME category policy")
		}
		return nil
	}
	if version == 1 {
		if target.GNOMEPolicy != nil {
			return errors.New("version 1 GNOME target cannot carry a category policy")
		}
		return nil
	}
	policy := target.GNOMEPolicy
	if policy == nil {
		return errors.New("GNOME target requires a category policy")
	}
	switch policy.Approval {
	case GNOMEApprovalPending:
		if len(policy.Categories) != 0 || policy.MatrixVersion != 0 || policy.KeyDigest != "" {
			return errors.New("pending GNOME category policy cannot carry approved categories, matrix version or key digest")
		}
	case GNOMEApprovalApproved:
		if len(policy.Categories) == 0 || policy.MatrixVersion == 0 {
			return errors.New("approved GNOME category policy requires categories and matrix version")
		}
		seen := make(map[string]struct{}, len(policy.Categories))
		for _, category := range policy.Categories {
			if !validGNOMECategoryID(category) {
				return errors.New("approved GNOME category policy has an invalid category id")
			}
			if _, duplicate := seen[category]; duplicate {
				return errors.New("approved GNOME category policy has a duplicate category id")
			}
			seen[category] = struct{}{}
		}
		digest, err := hex.DecodeString(policy.KeyDigest)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != policy.KeyDigest {
			return errors.New("approved GNOME category policy requires a lowercase SHA-256 key digest")
		}
	default:
		return errors.New("invalid GNOME category approval state")
	}
	return nil
}

func validGNOMECategoryID(id string) bool {
	if id == "" {
		return false
	}
	for index, character := range id {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && index > 0)) {
			return false
		}
	}
	return true
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
	if err := validateTarget(t, Version); err != nil {
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
		if c.Targets[i].GNOMEPolicy != nil {
			policy := *c.Targets[i].GNOMEPolicy
			policy.Categories = append([]string(nil), policy.Categories...)
			c.Targets[i].GNOMEPolicy = &policy
		}
		if c.Targets[i].Root != nil {
			root := *c.Targets[i].Root
			root.Exclude = normalizeExcludes(root.Exclude)
			c.Targets[i].Root = &root
		}
	}
	return c
}
