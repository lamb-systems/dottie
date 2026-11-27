package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
)

func dropTestCommand(t *testing.T, values ...string) *urfave.Command {
	t.Helper()
	exitCode := 0
	command := &urfave.Command{
		Name: "push",
		Flags: []urfave.Flag{
			&urfave.StringSliceFlag{Name: "drop-target"},
		},
		Writer:    &bytes.Buffer{},
		ErrWriter: &bytes.Buffer{},
		Action:    func(context.Context, *urfave.Command) error { return nil },
	}
	arguments := []string{"push"}
	for _, value := range values {
		arguments = append(arguments, "--drop-target", value)
	}
	require.NoError(t, command.Run(context.Background(), arguments))
	_ = exitCode
	return command
}

func TestPublicationDropTargetsSortsAndRefusesDuplicates(t *testing.T) {
	command := dropTestCommand(t, "second", "first")
	dropped, err := publicationDropTargets(command)
	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second"}, dropped)

	duplicated := dropTestCommand(t, "first", "first")
	_, err = publicationDropTargets(duplicated)
	var exitErr urfave.ExitCoder
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 2, exitErr.ExitCode())
	assert.Contains(t, err.Error(), "more than once")

	empty := dropTestCommand(t, "")
	_, err = publicationDropTargets(empty)
	require.ErrorAs(t, err, &exitErr)
	assert.Contains(t, err.Error(), "requires a target id")
}

func TestPublicationDropTargetsIsEmptyWithoutTheFlag(t *testing.T) {
	command := dropTestCommand(t)
	dropped, err := publicationDropTargets(command)
	require.NoError(t, err)
	assert.Empty(t, dropped)
}

func TestValidatePublicationDropRefusesAnUnpublishedTarget(t *testing.T) {
	binding := pullTestFileSetBinding()
	fileSet := newCLIFileSetPublication(t, binding)
	configuration := config.Config{Version: config.Version}

	require.NoError(t, serviceValidateDrop(t, nil, fileSet.block.Raw, configuration))
	err := serviceValidateDrop(t, []string{"absent"}, fileSet.block.Raw, configuration)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "carry")

	require.Error(t, serviceValidateDrop(t, []string{"files"}, fileSet.block.Raw, configuration),
		"dropping the only published target was accepted")
}

func serviceValidateDrop(
	t *testing.T,
	drop []string,
	record []byte,
	configuration config.Config,
) error {
	t.Helper()
	recorded, err := publication.DecodeSnapshot(record)
	require.NoError(t, err)
	assert.Equal(t, publication.SegmentFormEntries, recorded.Segments[0].Form)
	assert.Equal(t, model.SourceFiles, recorded.Segments[0].Target.Source)
	return service.ValidatePublicationDrop(drop, record, configuration)
}

func TestSyncDropSelectionBindsTheReviewedTerminalRecord(t *testing.T) {
	binding := pullTestFileSetBinding()
	fileSet := newCLIFileSetPublication(t, binding)
	configuration := config.Config{Version: config.Version, Targets: []config.Target{{
		ID: "files", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
	}}}
	require.Error(t, service.ValidatePublicationDrop([]string{"files"}, fileSet.block.Raw, configuration),
		"a drop that leaves no target was accepted beside a configured target")
	require.NoError(t, service.ValidatePublicationDrop(nil, fileSet.block.Raw, configuration))
}

var _ = publicationstate.Binding{}

func TestRenderSyncPullEffectsNamesWhatSurvivesARefusedPush(t *testing.T) {
	plan := service.PublicationApplyPlan{
		Changes: 2,
		Entries: []service.PublicationApplyPlanEntry{
			{TargetID: "files", Path: "init.lua", Operation: service.PublicationApplyWrite},
			{TargetID: "files", Path: "options.lua", Operation: service.PublicationApplyDelete},
			{TargetID: "files", Path: "kept.lua", Operation: service.PublicationApplyUnchanged},
		},
	}
	output := renderSyncPullEffects(plan, []string{"retired"})
	assert.Contains(t, output, "sync: pull effects: local-deletions=1 local-writes=1")
	assert.Contains(t, output, "these local deletions survive a refused push")
	assert.Contains(t, output, "the drop is published only if the push half completes")

	quiet := renderSyncPullEffects(service.PublicationApplyPlan{
		Entries: []service.PublicationApplyPlanEntry{
			{TargetID: "files", Path: "kept.lua", Operation: service.PublicationApplyUnchanged},
		},
	}, nil)
	assert.Empty(t, quiet, "a plan without deletions or a drop printed a partial-success note")

	dropOnly := renderSyncPullEffects(service.PublicationApplyPlan{}, []string{"retired"})
	assert.NotContains(t, dropOnly, "local deletions survive")
	assert.Contains(t, dropOnly, "the drop is published only if the push half completes")
}
