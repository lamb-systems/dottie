package integration

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProductionPackagesDoNotImportIntegrationHarness(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		require.True(t, ok, "cannot locate integration test source")
	}
	repoRoot := filepath.Join(filepath.Dir(sourceFile), "..", "..")
	err := filepath.WalkDir(repoRoot, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if file != repoRoot && (entry.Name() == ".git" || entry.Name() == "vendor" || entry.Name() == "bin") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			return fmt.Errorf("parse production source %s: %w", file, err)
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if strings.Contains(path, "tests/integration") || strings.Contains(path, "contention_harness") {
				assert.False(t, strings.Contains(path, "tests/integration") || strings.Contains(path, "contention_harness"), "non-test source %s imports test-only integration harness %q", file, path)
			}
		}
		return nil
	})
	if err != nil {
		require.NoError(t, err)
	}
}
