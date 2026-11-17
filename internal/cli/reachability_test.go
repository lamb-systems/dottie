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

var removedV1ApplySymbols = map[string]bool{
	"Apply":                       true,
	"ApplyRequest":                true,
	"ErrNotActionable":            true,
	"ErrPreconditionChanged":      true,
	"ErrRecoveryRequired":         true,
	"MaxRollbackMaterialBytes":    true,
	"ModePolicy":                  true,
	"NotActionableError":          true,
	"PartialApplyError":           true,
	"Postimage":                   true,
	"RollbackApplied":             true,
	"RollbackAppliedWithSettings": true,
	"RollbackMaterialLimitError":  true,
	"RollbackReport":              true,
	"SettingPostimage":            true,
	"UnsupportedApplyEntryError":  true,
}

var removedV1Commands = []string{
	"recover", "export", "import", "prune", "history", "devices", "recoverCommand", "finalize",
}

var removedV1ServiceSymbols = map[string]bool{
	"Enroll":             true,
	"Revoke":             true,
	"RevokeApproval":     true,
	"RecordCheckpoint":   true,
	"FinalizeVaultTrust": true,
	"PrepareArchive":     true,
	"ValidateArchive":    true,
}

func TestRetiredV1CommandsAreGone(t *testing.T) {
	root := filepath.Join("..", "..")
	files, err := filepath.Glob(filepath.Join(root, "internal", "cli", "*.go"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	present := make([]string, 0)
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		require.NoError(t, parseErr)
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				return true
			}
			for _, retired := range removedV1Commands {
				if value == retired {
					present = append(present, filepath.Base(file)+": "+retired)
				}
			}
			return true
		})
	}
	assert.Empty(t, present, "a retired command name is still registered")
}

func TestRetiredV1ServiceSymbolsHaveNoCaller(t *testing.T) {
	root := filepath.Join("..", "..")
	directories := []string{
		filepath.Join(root, "internal", "cli"),
		filepath.Join(root, "internal", "service"),
		filepath.Join(root, "cmd"),
	}

	references := make([]string, 0)
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		require.NoError(t, err)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			require.NoError(t, parseErr)
			ast.Inspect(parsed, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok || removedV1ServiceSymbols[selector.Sel.Name] {
					if ok {
						references = append(references, entry.Name()+": "+selector.Sel.Name)
					}
				}
				return true
			})
		}
	}
	assert.Empty(t, references, "a retired service entry point still has a production caller")
}

func TestRemovedV1ApplyEngineHasNoProductionReference(t *testing.T) {
	root := filepath.Join("..", "..")

	reintroduced := make([]string, 0)
	syncengineDir := filepath.Join(root, "internal", "syncengine")
	entries, err := os.ReadDir(syncengineDir)
	require.NoError(t, err, "read syncengine directory")
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(syncengineDir, entry.Name())
		found, err := fileDeclaresRemovedApplySymbol(path)
		require.NoError(t, err, "parse syncengine file")
		reintroduced = append(reintroduced, found...)
	}
	assert.Empty(t, reintroduced, "the retired v1 apply engine must stay deleted")

	references := make([]string, 0)
	for _, directory := range []string{"cmd", filepath.Join("internal", "cli"), filepath.Join("internal", "service")} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		require.NoError(t, err, "read production directory")
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(root, directory, entry.Name())
			found, err := fileReferencesRemovedApplySymbol(path)
			require.NoError(t, err, "parse production file")
			if found {
				references = append(references, path)
			}
		}
	}
	assert.Empty(t, references, "production code must not reach the retired v1 apply engine")
}

func fileDeclaresRemovedApplySymbol(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	found := make([]string, 0)
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if declaration.Recv == nil && removedV1ApplySymbols[declaration.Name.Name] {
				found = append(found, declaration.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					if removedV1ApplySymbols[spec.Name.Name] {
						found = append(found, spec.Name.Name)
					}
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						if removedV1ApplySymbols[name.Name] {
							found = append(found, name.Name)
						}
					}
				}
			}
		}
	}
	return found, nil
}

func fileReferencesRemovedApplySymbol(path string) (bool, error) {
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
		if !ok || !removedV1ApplySymbols[selector.Sel.Name] {
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
