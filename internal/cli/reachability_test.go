package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const v1ApplyEngineImport = "github.com/lamb-systems/dottie/internal/syncengine"

func TestRemovedV1ApplyEngineHasNoProductionReference(t *testing.T) {
	root := filepath.Join("..", "..")
	references := make([]string, 0)
	for _, directory := range []string{filepath.Join("cmd"), filepath.Join("internal", "cli"), filepath.Join("internal", "service")} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		require.NoError(t, err, "read production directory")
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(root, directory, entry.Name())
			found, err := fileReferencesApply(path)
			require.NoError(t, err, "parse production file")
			if found {
				references = append(references, path)
			}
		}
	}
	assert.Empty(t, references, "production code must not reach the retired v1 apply engine")
}

func fileReferencesApply(path string) (bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return false, err
	}
	local := ""
	for _, imported := range file.Imports {
		value, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return false, err
		}
		if value != v1ApplyEngineImport {
			continue
		}
		local = "syncengine"
		if imported.Name != nil {
			local = imported.Name.Name
		}
	}
	if local == "" || local == "_" || local == "." {
		return false, nil
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Apply" {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && identifier.Name == local {
			found = true
		}
		return true
	})
	return found, nil
}
