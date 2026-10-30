package integration

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestAtprotoProductionPackageDoesNotImportPDSProbeHelpers(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test source")
	}
	productionDir := filepath.Join(filepath.Dir(sourceFile), "..", "..", "internal", "remote", "atproto")
	files, err := filepath.Glob(filepath.Join(productionDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(path, "tests/integration") {
				t.Errorf("production source %s imports test-only PDS helpers %q", filepath.Base(file), path)
			}
		}
	}
}
