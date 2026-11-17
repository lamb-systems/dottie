package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
)

var (
	digestTestKey  = strings.Repeat("ab", 32)
	digestOtherKey = strings.Repeat("cd", 32)
)

func digestTestConfig() Config {
	gnome := Target{ID: "desktop", Source: model.SourceGNOME, GNOMEPolicy: &GNOMEPolicy{
		Approval:      GNOMEApprovalApproved,
		Categories:    []string{"appearance", "clock"},
		MatrixVersion: 1,
		KeyDigest:     digestTestKey,
	}}
	nvim := filesTarget("nvim", model.RootXDGConfig, "nvim", model.SelectionDirectory)
	nvim.Root.Exclude = []string{".git", ".git/**"}
	dots := filesTarget("dots", model.RootHome, "dotfiles", model.SelectionDirectory)
	return Config{Version: Version, Defaults: Defaults{Mode: Review}, Targets: []Target{nvim, gnome, dots}}
}

func TestSelectionDigestIgnoresOrderingCommentsAndImplicitDefaults(t *testing.T) {
	base := digestTestConfig()
	reordered := digestTestConfig()
	reordered.Targets = []Target{reordered.Targets[2], reordered.Targets[0], reordered.Targets[1]}
	assert.Equal(t, selectionDigest(base), selectionDigest(reordered), "target order moved the selection digest")

	sortedExcludes := digestTestConfig()
	sortedExcludes.Targets[0].Root.Exclude = []string{".git/**", ".git"}
	assert.Equal(t, selectionDigest(base), selectionDigest(sortedExcludes), "exclude order moved the selection digest")

	duplicated := digestTestConfig()
	duplicated.Targets[0].Root.Exclude = []string{".git/**", ".git", ".git"}
	assert.Equal(t, selectionDigest(base), selectionDigest(duplicated), "duplicate exclude moved the selection digest")

	sortedCategories := digestTestConfig()
	sortedCategories.Targets[1].GNOMEPolicy.Categories = []string{"clock", "appearance"}
	assert.Equal(
		t,
		selectionDigest(base),
		selectionDigest(sortedCategories),
		"category order moved the selection digest",
	)

	duplicatedCategory := digestTestConfig()
	duplicatedCategory.Targets[1].GNOMEPolicy.Categories = []string{"clock", "appearance", "appearance"}
	assert.Equal(
		t,
		selectionDigest(base),
		selectionDigest(duplicatedCategory),
		"duplicate category moved the selection digest",
	)
	assert.Equal(
		t,
		approvalDigest(base),
		approvalDigest(duplicatedCategory),
		"duplicate category moved the approval digest",
	)

	implicitDefault := digestTestConfig()
	implicitDefault.Defaults.Mode = ""
	assert.Equal(
		t,
		selectionDigest(base),
		selectionDigest(implicitDefault),
		"omitted default mode moved the selection digest",
	)

	implicitTargetMode := digestTestConfig()
	implicitTargetMode.Targets[2].Mode = Review
	assert.Equal(
		t,
		selectionDigest(base),
		selectionDigest(implicitTargetMode),
		"explicit default target mode moved the selection digest",
	)
}

func TestSelectionDigestIgnoresFileComments(t *testing.T) {
	paths := testPaths(t)
	writeRawConfig(t, paths, digestTestDocument(""))
	plain, err := OpenSnapshot(paths)
	require.NoError(t, err)

	commented := testPaths(t)
	writeRawConfig(t, commented, digestTestDocument("# a comment that changes the bytes only\n"))
	annotated, err := OpenSnapshot(commented)
	require.NoError(t, err)

	assert.Equal(t, plain.Selection, annotated.Selection, "a comment moved the selection digest")
	assert.Equal(t, plain.Approval, annotated.Approval, "a comment moved the approval digest")
	assert.NotEqual(t, plain.Token, annotated.Token, "a comment did not change the content token")
}

func digestTestDocument(header string) string {
	return header + `config_version = 2

[defaults]
mode = "review"

[[targets]]
id = "nvim"
source = "files"

[targets.root]
base = "xdg-config"
path = "nvim"
kind = "directory"
exclude = [".git", ".git/**"]

[[targets]]
id = "desktop"
source = "gnome"

[targets.gnome_policy]
approval = "approved"
categories = ["appearance", "clock"]
matrix_version = 1
key_digest = "` + digestTestKey + `"

[[targets]]
id = "dots"
source = "files"

[targets.root]
base = "home"
path = "dotfiles"
kind = "directory"
`
}

func TestSelectionDigestTracksSemanticChanges(t *testing.T) {
	base := digestTestConfig()
	changes := []struct {
		name   string
		change func(*Config)
	}{
		{"target mode", func(c *Config) { c.Targets[2].Mode = AutoApply }},
		{"default mode", func(c *Config) { c.Defaults.Mode = BackupOnly }},
		{"root base", func(c *Config) { c.Targets[0].Root.Base = model.RootHome }},
		{"root path", func(c *Config) { c.Targets[0].Root.Path = "other" }},
		{"root kind", func(c *Config) { c.Targets[0].Root.Kind = model.SelectionFile }},
		{"exclude entry", func(c *Config) { c.Targets[0].Root.Exclude = []string{".git"} }},
		{"approval", func(c *Config) {
			c.Targets[1].GNOMEPolicy = &GNOMEPolicy{Approval: GNOMEApprovalPending}
		}},
		{"categories", func(c *Config) { c.Targets[1].GNOMEPolicy.Categories = []string{"appearance"} }},
		{"matrix version", func(c *Config) { c.Targets[1].GNOMEPolicy.MatrixVersion = 2 }},
		{"key digest", func(c *Config) { c.Targets[1].GNOMEPolicy.KeyDigest = digestOtherKey }},
		{"target id", func(c *Config) { c.Targets[2].ID = "renamed" }},
		{"removed target", func(c *Config) { c.Targets = c.Targets[:2] }},
	}
	for _, testCase := range changes {
		t.Run(testCase.name, func(t *testing.T) {
			changed := digestTestConfig()
			testCase.change(&changed)
			assert.NotEqual(t, selectionDigest(base), selectionDigest(changed), "selection digest ignored the change")
		})
	}
}

func TestApprovalDigestCoversOnlyApprovalFields(t *testing.T) {
	base := digestTestConfig()
	approvalChanges := []struct {
		name   string
		change func(*Config)
	}{
		{"approval", func(c *Config) { c.Targets[1].GNOMEPolicy = &GNOMEPolicy{Approval: GNOMEApprovalPending} }},
		{"categories", func(c *Config) { c.Targets[1].GNOMEPolicy.Categories = []string{"appearance"} }},
		{"matrix version", func(c *Config) { c.Targets[1].GNOMEPolicy.MatrixVersion = 2 }},
		{"key digest", func(c *Config) { c.Targets[1].GNOMEPolicy.KeyDigest = digestOtherKey }},
		{"policy removed", func(c *Config) { c.Targets[1].GNOMEPolicy = nil }},
	}
	for _, testCase := range approvalChanges {
		t.Run(testCase.name, func(t *testing.T) {
			changed := digestTestConfig()
			testCase.change(&changed)
			assert.NotEqual(t, approvalDigest(base), approvalDigest(changed), "approval digest ignored the change")
		})
	}

	selectionOnly := digestTestConfig()
	selectionOnly.Targets[0].Mode = AutoApply
	selectionOnly.Targets[0].Root.Exclude = []string{".git"}
	selectionOnly.Targets[2].Root.Path = "moved"
	assert.NotEqual(
		t,
		selectionDigest(base),
		selectionDigest(selectionOnly),
		"selection digest ignored a selection-only change",
	)
	assert.Equal(
		t,
		approvalDigest(base),
		approvalDigest(selectionOnly),
		"approval digest moved for a selection-only change",
	)

	added := digestTestConfig()
	added.Targets = append(added.Targets, filesTarget("extra", model.RootHome, "extra", model.SelectionDirectory))
	assert.NotEqual(t, selectionDigest(base), selectionDigest(added), "selection digest ignored an added target")
	assert.Equal(t, approvalDigest(base), approvalDigest(added), "approval digest moved for a files target")
}

func TestApprovalDigestDistinguishesTargets(t *testing.T) {
	left := digestTestConfig()
	right := digestTestConfig()
	right.Targets[1].ID = "other-desktop"
	assert.NotEqual(t, approvalDigest(left), approvalDigest(right), "approval digest ignored the target id")

	withoutPolicies := Config{Version: Version, Defaults: Defaults{Mode: Review}}
	assert.Equal(
		t,
		approvalDigest(withoutPolicies),
		approvalDigest(Config{Version: Version}),
		"approval digest depends on non-approval fields",
	)
}

func TestRevisionOnlyEditChangesTokenAndStaleness(t *testing.T) {
	paths := testPaths(t)
	writeRawConfig(t, paths, digestTestDocument(""))
	before, err := OpenSnapshot(paths)
	require.NoError(t, err)
	require.Equal(t, uint64(0), before.Selection.Revision, "raw document revision")

	edited := strings.Replace(
		digestTestDocument(""),
		"config_version = 2",
		"config_version = 2\nselection_revision = 41",
		1,
	)
	require.NoError(t, os.WriteFile(filepath.Join(paths.AppConfigDir(), FileName), []byte(edited), 0o600))
	after, err := OpenSnapshot(paths)
	require.NoError(t, err)

	assert.Equal(t, before.Selection.Digest, after.Selection.Digest, "revision-only edit moved the selection digest")
	assert.Equal(t, uint64(41), after.Selection.Revision, "revision-only edit revision")
	assert.NotEqual(t, before.Token, after.Token, "revision-only edit did not change the content token")

	_, err = Update(paths, before.Token, func(c Config) (Config, error) {
		c.Defaults.Mode = AutoApply
		return c, nil
	})
	require.ErrorIs(t, err, ErrConfigStale, "update accepted a token from before the revision-only edit")
	got, err := os.ReadFile(filepath.Join(paths.AppConfigDir(), FileName))
	require.NoError(t, err)
	assert.Equal(t, edited, string(got), "refused update rewrote the file")
}
