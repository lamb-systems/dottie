package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlanEscapesPathsAndNeverPrintsContents(t *testing.T) {
	target := model.Target{
		ID:            "files",
		Source:        model.SourceFiles,
		SourceVersion: model.SourceVersion,
		Root:          &model.FileRoot{Base: model.RootHome, Path: "prefs", Kind: model.SelectionDirectory},
	}
	baseEntry := model.Entry{TargetID: target.ID, File: &model.FileEntry{
		Path:    "name\n\x1b\u0085",
		State:   model.FilePresent,
		Kind:    model.FileRegular,
		Content: []byte("old-private-content"),
		Mode:    0o600,
	}}
	observedEntry := model.Entry{TargetID: target.ID, File: &model.FileEntry{
		Path:    "name\n\x1b\u0085",
		State:   model.FilePresent,
		Kind:    model.FileRegular,
		Content: []byte("ULTRA_PRIVATE_PLAN_CONTENT_7d2ca91e"),
		Mode:    0o640,
	}}
	bundle := map[string]any{
		"version":      1,
		"base_status":  "known",
		"targets":      []model.Target{target},
		"base":         []model.Entry{baseEntry},
		"observations": []model.Observation{{State: model.ObservationPresent, Identity: observedEntry.Identity(), Entry: &observedEntry}},
		"remote":       []model.Entry{baseEntry},
		"coverage":     []string{"files"},
	}
	input, err := json.Marshal(bundle)
	require.NoError(t, err)
	inputPath := filepath.Join(t.TempDir(), "views.json")
	require.NoError(t, os.WriteFile(inputPath, input, 0o600))
	before, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"plan", "--from", inputPath}, &stdout, &stderr)
	require.Equal(t, 0, code, "plan exit code")
	assert.Empty(t, stderr.String(), "plan error output")
	assert.Contains(t, stdout.String(), "change", "plan action")
	assert.Contains(t, stdout.String(), "name\\x0A\\x1B\\x85", "text output escapes controls in the path")
	assert.NotContains(t, stdout.String(), "\x1b", "text output contains a raw terminal escape")
	assert.NotContains(t, stdout.String(), "\u0085", "text output contains a raw Unicode line control")
	assert.NotContains(t, stdout.String(), "ULTRA_PRIVATE_PLAN_CONTENT_7d2ca91e", "text output contains file content")
	assert.NotContains(t, stdout.String(), "old-private-content", "text output contains base content")
	after, err := os.ReadFile(inputPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "plan command modified its input file")

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"plan", "--from", inputPath, "--json"}, &stdout, &stderr)
	require.Equal(t, 0, code, "JSON plan exit code")
	assert.Empty(t, stderr.String(), "JSON plan error output")
	assert.Contains(t, stdout.String(), `"name\n\u001b\u0085"`, "JSON output escapes controls in the path")
	assert.NotContains(t, stdout.String(), "\x1b", "JSON output contains a raw terminal escape")
	assert.NotContains(t, stdout.String(), "\u0085", "JSON output contains a raw Unicode line control")
	assert.NotContains(t, stdout.String(), "ULTRA_PRIVATE_PLAN_CONTENT_7d2ca91e", "JSON output contains file content")
	assert.NotContains(t, stdout.String(), "old-private-content", "JSON output contains base content")
	var preview syncengine.Preview
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &preview), "JSON output remains valid after escaping controls")
	require.Len(t, preview.Targets, 1)
	assert.Equal(t, "name\n\x1b\u0085", preview.Targets[0].Entries[0].Key.FilePath, "JSON path round-trips exactly")
}

func TestPlanTextLabelsIncompleteResultingSnapshotAsLowerBound(t *testing.T) {
	output := renderPreview(syncengine.Preview{
		TransferBytes:          5,
		ResultingSnapshotBytes: 12,
		Complete:               false,
		UnresolvedEntries:      2,
	})
	assert.Contains(t, output, "transfer bytes=5\n", "transfer amount is explicit")
	assert.Contains(t, output, "resulting snapshot at least 12 bytes, incomplete: 2 unresolved\n", "incomplete result is labeled as a lower bound")
}

func TestPlanRequiresFromFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"plan"}, &stdout, &stderr)
	require.Equal(t, 2, code, "missing --from exit code")
	assert.Empty(t, stdout.String(), "missing --from output")
	assert.Contains(t, stderr.String(), "--from", "usage error names the required flag")
}

func TestPlanInputRequiresFieldsWithTypedError(t *testing.T) {
	_, err := decodePlanInput([]byte(`{"base_status":"missing","targets":[],"base":[],"observations":[],"remote":[],"coverage":[]}`))
	require.Error(t, err, "version is required")
	var inputError *PlanInputError
	require.ErrorAs(t, err, &inputError, "missing required fields have a typed error")
	assert.Equal(t, "version", inputError.Field, "missing field")
	assert.Equal(t, "is missing required", inputError.Kind, "missing field error kind")
}

func TestPlanInputRejectsUnknownFields(t *testing.T) {
	_, err := decodePlanInput([]byte(`{"version":1,"base_status":"missing","targets":[],"base":[],"observations":[],"remote":[],"coverage":[],"hook":"run me"}`))
	require.Error(t, err, "unknown input fields must be rejected")
	var inputError *PlanInputError
	require.ErrorAs(t, err, &inputError, "invalid JSON has a typed error")
	assert.Equal(t, "is invalid JSON", inputError.Kind, "unknown field error kind")
}
