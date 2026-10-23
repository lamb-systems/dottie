package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dottorblaster/dottie/internal/model"
)

func TestResolveSelectionNestingAndKinds(t *testing.T) {
	paths := testPaths(t)
	paths.ConfigHome = filepath.Join(paths.Home, ".config")
	if err := os.Mkdir(paths.ConfigHome, 0o700); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(paths.ConfigHome, "settings.ini")
	if err := os.WriteFile(configFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := ResolveSelection(paths, configFile)
	if err != nil {
		t.Fatal(err)
	}
	if root.Base != model.RootXDGConfig || root.Path != "settings.ini" || root.Kind != model.SelectionFile {
		t.Fatalf("config selection = %#v", root)
	}
	directory := filepath.Join(paths.Home, "documents")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err = ResolveSelection(paths, directory)
	if err != nil {
		t.Fatal(err)
	}
	if root.Base != model.RootHome || root.Path != "documents" || root.Kind != model.SelectionDirectory {
		t.Fatalf("home selection = %#v", root)
	}
}

func TestResolveSelectionRejectsWholeBases(t *testing.T) {
	paths := testPaths(t)
	paths.ConfigHome = filepath.Join(t.TempDir(), "relocated-config")
	paths.StateHome = filepath.Join(t.TempDir(), "relocated-state")
	paths.CacheHome = filepath.Join(t.TempDir(), "relocated-cache")
	paths.DataHome = filepath.Join(t.TempDir(), "relocated-data")
	if err := os.Mkdir(paths.ConfigHome, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Home, paths.ConfigHome} {
		if _, err := ResolveSelection(paths, path); err == nil || !strings.Contains(err.Error(), "whole base") {
			t.Errorf("ResolveSelection(%q) error = %v", path, err)
		}
	}
}

func TestResolveSelectionRejectsOutsideAndSymlinkEscape(t *testing.T) {
	paths := testPaths(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSelection(paths, outside); err == nil {
		t.Fatal("outside path accepted")
	}
	link := filepath.Join(paths.Home, "escaped")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSelection(paths, link); err == nil {
		t.Fatal("symlink escaping portable roots accepted")
	}
}

func TestDeriveIDGoldenVectors(t *testing.T) {
	longAtLimit := strings.Repeat("a", 123)
	longPastLimit := strings.Repeat("a", 124)
	trimAfterTruncate := strings.Repeat("a", 122) + "/more"
	tests := []struct {
		base model.RootBase
		path string
		want string
	}{
		{model.RootHome, "---", "home"},
		{model.RootHome, "caf\u00e9", "home-caf"},
		{model.RootHome, "A//B", "home-a-b"},
		{model.RootHome, longAtLimit, "home-" + longAtLimit},
		{model.RootHome, longPastLimit, "home-" + strings.Repeat("a", 123)},
		{model.RootHome, trimAfterTruncate, "home-" + strings.Repeat("a", 122)},
	}
	for _, tt := range tests {
		if got := DeriveID(tt.base, tt.path); got != tt.want {
			t.Errorf("DeriveID(%q, %q) = %q, want %q", tt.base, tt.path, got, tt.want)
		}
	}
}

func TestCheckAdditionIdCollisions(t *testing.T) {
	paths := testPaths(t)
	for _, pair := range [][2]string{{"A/B", "a--b"}, {strings.Repeat("a", 123) + "x", strings.Repeat("a", 123) + "y"}} {
		id := DeriveID(model.RootHome, pair[0])
		current := Default()
		current.Targets = []Target{filesTarget(id, model.RootHome, pair[0], model.SelectionDirectory)}
		added := filesTarget(DeriveID(model.RootHome, pair[1]), model.RootHome, pair[1], model.SelectionDirectory)
		if added.ID != id {
			t.Fatalf("fixture ids did not collide: %q vs %q", id, added.ID)
		}
		if err := CheckAddition(current, paths, added); err == nil || !strings.Contains(err.Error(), "id") || !strings.Contains(err.Error(), pair[0]) || !strings.Contains(err.Error(), pair[1]) {
			t.Errorf("CheckAddition collision error = %v", err)
		}
	}
}

func TestCheckAdditionOverlapUsesPathComponents(t *testing.T) {
	paths := testPaths(t)
	current := Default()
	current.Targets = []Target{
		filesTarget("parent-prefix", model.RootHome, "dottie", model.SelectionDirectory),
		filesTarget("short", model.RootHome, "b", model.SelectionDirectory),
	}
	for _, added := range []Target{
		filesTarget("sibling-prefix", model.RootHome, "dottie-notes", model.SelectionDirectory),
		filesTarget("longer-sibling", model.RootHome, "bc", model.SelectionDirectory),
	} {
		if err := CheckAddition(current, paths, added); err != nil {
			t.Errorf("sibling %q incorrectly overlaps: %v", added.Root.Path, err)
		}
	}
	if err := CheckAddition(current, paths, filesTarget("child", model.RootHome, "dottie/child", model.SelectionDirectory)); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("child overlap error = %v", err)
	}
}

func TestCheckAdditionRejectsContainingAndNestedDottieDirectories(t *testing.T) {
	paths := testPaths(t)
	selected := filepath.Join(paths.Home, "container")
	paths.ConfigHome = filepath.Join(selected, "config")
	paths.StateHome = filepath.Join(selected, "state")
	paths.CacheHome = filepath.Join(selected, "cache")
	paths.DataHome = filepath.Join(selected, "data")
	if err := os.MkdirAll(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ResolveSelection(paths, selected)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAddition(Default(), paths, Target{ID: "container", Source: model.SourceFiles, Root: &root}); err == nil || !strings.Contains(err.Error(), "Dottie") {
		t.Fatalf("containing self-capture error = %v", err)
	}

	inside := filepath.Join(paths.Home, "outside-config")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	paths.ConfigHome = inside
	child := filepath.Join(inside, "dottie", "nested")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err = ResolveSelection(paths, child)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAddition(Default(), paths, Target{ID: "nested", Source: model.SourceFiles, Root: &root}); err == nil || !strings.Contains(err.Error(), "Dottie") {
		t.Fatalf("nested self-capture error = %v", err)
	}
}

func TestCheckAdditionSelfCaptureThroughSymlinkedXDG(t *testing.T) {
	paths := testPaths(t)
	actualConfig := filepath.Join(t.TempDir(), "actual-config")
	if err := os.Mkdir(actualConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedConfig := filepath.Join(paths.Home, ".config-link")
	if err := os.Symlink(actualConfig, linkedConfig); err != nil {
		t.Fatal(err)
	}
	paths.ConfigHome = linkedConfig
	selected := filepath.Join(actualConfig, "dottie", "sync")
	if err := os.MkdirAll(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ResolveSelection(paths, selected)
	if err != nil {
		t.Fatal(err)
	}
	candidate := Target{ID: "self", Source: model.SourceFiles, Root: &root}
	if err := CheckAddition(Default(), paths, candidate); err == nil || !strings.Contains(err.Error(), "Dottie") {
		t.Fatalf("self-capture error = %v", err)
	}
}

func TestCheckAdditionFailsClosedForUnavailableStoredRoot(t *testing.T) {
	paths := testPaths(t)
	broken := filepath.Join(paths.Home, "broken")
	if err := os.Symlink(filepath.Join(paths.Home, "missing"), broken); err != nil {
		t.Fatal(err)
	}
	current := Default()
	current.Targets = []Target{filesTarget("offline", model.RootHome, "broken/selected", model.SelectionDirectory)}
	added := filesTarget("other", model.RootHome, "new", model.SelectionDirectory)
	if err := CheckAddition(current, paths, added); err == nil || !strings.Contains(err.Error(), "stored root") {
		t.Fatalf("unavailable existing root error = %v", err)
	}
}

func TestCheckAdditionRejectsLocalPolicyAndKinds(t *testing.T) {
	paths := testPaths(t)
	for _, target := range []Target{
		{ID: "whole", Source: model.SourceFiles, Root: &Root{Base: model.RootHome, Path: ".", Kind: model.SelectionDirectory}},
		{ID: "mode", Source: model.SourceFiles, Mode: "always", Root: &Root{Base: model.RootHome, Path: "x", Kind: model.SelectionDirectory}},
		{ID: "exclude", Source: model.SourceFiles, Root: &Root{Base: model.RootHome, Path: "x", Kind: model.SelectionDirectory, Exclude: []string{"/absolute"}}},
	} {
		if err := CheckAddition(Default(), paths, target); err == nil {
			t.Errorf("invalid target accepted: %#v", target)
		}
	}
}

func TestModelConversionDoesNotCarryLocalFields(t *testing.T) {
	root := &Root{Base: model.RootHome, Path: "dotfiles", Kind: model.SelectionDirectory, Exclude: []string{"secret"}}
	target := Target{ID: "same-id", Source: model.SourceFiles, Mode: AutoApply, Root: root}
	portable, err := target.Model()
	if err != nil {
		t.Fatal(err)
	}
	if portable.ID != target.ID || portable.Source != model.SourceFiles || portable.SourceVersion != 1 || portable.Root == nil || portable.Root.Base != root.Base || portable.Root.Path != root.Path || portable.Root.Kind != root.Kind {
		t.Fatalf("portable fields = %#v", portable)
	}
	gnome, err := (Target{ID: "gnome-id", Source: model.SourceGNOME, Mode: Review}).Model()
	if err != nil || gnome.ID != "gnome-id" || gnome.Source != model.SourceGNOME || gnome.Root != nil || gnome.SourceVersion != 1 {
		t.Fatalf("GNOME model = %#v, %v", gnome, err)
	}
}

func TestConcurrentSaveAndLoadSupplemental(t *testing.T) {
	paths := testPaths(t)
	if err := Save(paths, Default()); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for writer := 0; writer < 2; writer++ {
		group.Add(1)
		go func(writer int) {
			defer group.Done()
			for i := 0; i < 8; i++ {
				value := Default()
				value.Targets = []Target{{ID: fmt.Sprintf("writer-%d-%d", writer, i), Source: model.SourceGNOME}}
				if err := Save(paths, value); err != nil {
					t.Errorf("Save: %v", err)
					return
				}
			}
		}(writer)
	}
	for i := 0; i < 8; i++ {
		if _, err := Load(paths); err != nil {
			t.Errorf("Load: %v", err)
		}
	}
	group.Wait()
}
