package cli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	configuration.Targets = []config.Target{{ID: "prefs", Source: model.SourceFiles, Mode: config.Review, Root: &config.Root{Base: model.RootHome, Path: "prefs", Kind: model.SelectionDirectory}}}
	factory := func() (*service.Coordinator, func(), error) {
		coordinator, err := service.NewCoordinator(service.Dependencies{Config: statusTestConfig{value: configuration}, State: store})
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

type statusTestConfig struct {
	value config.Config
}

func (port statusTestConfig) Load(context.Context) (config.Config, error) { return port.value, nil }

func (statusTestConfig) Snapshot(context.Context) (config.Snapshot, error) {
	return config.Snapshot{}, errors.New("unexpected config snapshot")
}

func (statusTestConfig) Update(context.Context, config.Token, func(config.Config) (config.Config, error)) (config.Snapshot, error) {
	return config.Snapshot{}, errors.New("unexpected config update")
}
