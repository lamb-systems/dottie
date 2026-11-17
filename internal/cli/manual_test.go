package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	urfave "github.com/urfave/cli/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
)

func runManualCommandForTest(command *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	arguments := append([]string{"dottie"}, args...)
	if err := command.Run(ctx, arguments); err != nil && *exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return *exitCode
}

func TestManualStatusRefusalUsesDistinctExitCodeAndEscapesControls(t *testing.T) {
	factory := func() (*service.Coordinator, func(), error) {
		return nil, func() {}, errors.New("unsafe\nrefusal")
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "status")
	require.Equal(t, 3, code)
	assert.Empty(t, stdout.String())
	assert.NotContains(t, stderr.String(), "unsafe\nrefusal")
	assert.Contains(t, stderr.String(), "unsafe\\x0Arefusal")
}

func TestManualStatusReportsSelectedTargetsWithoutJournalRows(t *testing.T) {
	root := t.TempDir()
	paths := platform.Paths{Home: root + "/home", StateHome: root + "/state", CacheHome: root + "/cache"}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	configuration := config.Default()
	configuration.Targets = []config.Target{
		{
			ID:     "prefs",
			Source: model.SourceFiles,
			Mode:   config.Review,
			Root:   &config.Root{Base: model.RootHome, Path: "prefs", Kind: model.SelectionDirectory},
		},
	}
	factory := func() (*service.Coordinator, func(), error) {
		coordinator, err := service.NewCoordinator(
			service.Dependencies{Config: statusTestConfig{value: configuration}, State: store},
		)
		return coordinator, func() {}, err
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "status")
	require.Equal(t, 0, code)
	assert.Empty(t, stderr.String())
	assert.Contains(t, stdout.String(), "prefs\tfiles\treview\tunknown\titems=0")
}

func newManualStatusTestStore(t *testing.T) (*state.Store, platform.Paths) {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{Home: root + "/home", StateHome: root + "/state", CacheHome: root + "/cache"}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return store, paths
}

func TestManualStatusPrintsRecordedVaultSelection(t *testing.T) {
	store, paths := newManualStatusTestStore(t)
	selection := state.VaultSelection{Vault: [32]byte{0x09, 0x11, 0x23}, DeviceID: "synthetic-device", RecordedAt: 7}
	require.NoError(t, store.PutVaultSelection(context.Background(), selection))
	configuration := config.Default()
	factory := func() (*service.Coordinator, func(), error) {
		coordinator, err := service.NewCoordinator(
			service.Dependencies{Config: statusTestConfig{value: configuration}, State: store},
		)
		return coordinator, func() {}, err
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "status")
	require.Equal(t, 0, code, "exit code")
	assert.Empty(t, stderr.String(), "stderr")
	assert.Equal(
		t,
		"vault\t"+hex.EncodeToString(selection.Vault[:])+"\tdevice=synthetic-device\nno targets selected\n",
		stdout.String(),
		"stdout",
	)
	_, statErr := os.Lstat(paths.PublicationStateDir())
	assert.ErrorIs(t, statErr, os.ErrNotExist, "status opened the publication position store")
}

func TestManualStatusPrintsAbsentVaultSelection(t *testing.T) {
	store, _ := newManualStatusTestStore(t)
	factory := func() (*service.Coordinator, func(), error) {
		coordinator, err := service.NewCoordinator(
			service.Dependencies{Config: statusTestConfig{value: config.Default()}, State: store},
		)
		return coordinator, func() {}, err
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newManualCommand(&stdout, &stderr, &code, factory)
	code = runManualCommandForTest(command, &code, "status")
	require.Equal(t, 0, code, "exit code")
	assert.Empty(t, stderr.String(), "stderr")
	assert.Equal(t, "no vault selection recorded\nno targets selected\n", stdout.String(), "stdout")
}

func TestStatusDispatchPassesNoSessionFactory(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "root.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err)
	closures := make([]string, 0)
	cases := 0
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Run" || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expression := range clause.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING || literal.Value != `"status"` {
					continue
				}
				cases++
				for _, statement := range clause.Body {
					ast.Inspect(statement, func(inner ast.Node) bool {
						if _, closure := inner.(*ast.FuncLit); closure {
							closures = append(closures, "status dispatch passes a factory closure")
						}
						return true
					})
				}
			}
			return true
		})
	}
	assert.Equal(t, 1, cases, "status dispatch case")
	assert.Empty(t, closures, "status must be wired without a keyring or session factory")
}

type statusTestConfig struct {
	value config.Config
}

func (port statusTestConfig) Load(context.Context) (config.Config, error) { return port.value, nil }

func (statusTestConfig) Snapshot(context.Context) (config.Snapshot, error) {
	return config.Snapshot{}, errors.New("unexpected config snapshot")
}

func (statusTestConfig) Update(
	context.Context,
	config.Token,
	func(config.Config) (config.Config, error),
) (config.Snapshot, error) {
	return config.Snapshot{}, errors.New("unexpected config update")
}
