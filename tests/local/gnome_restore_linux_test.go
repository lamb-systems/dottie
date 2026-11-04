//go:build linux && cgo && gsettings

package local_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/source/gnome"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gateActorMarker = "DOTTIE_GNOME_RESTORE_GATE_ACTOR"

var gateCountKeys = []string{
	"captured_entries", "capture_unknowns", "captured_present", "captured_reset", "missing_key_unknowns", "missing_schema_unknowns",
	"file_entries", "file_unknowns", "preview_actions_files", "preview_actions_settings", "preview_actions_total", "directory_unchanged",
	"applied_file_rows", "applied_setting_rows", "applied_rows", "convergence_actions", "convergence_unknowns", "second_apply_rows_added",
	"verified_present_values", "verified_reset_absent", "sentinel_values", "verified_file_contents", "rollback_rows", "rollback_skipped_newer",
	"rollback_restored", "rollback_setting_reset", "rollback_file_restored", "locked_observations", "locked_writes", "receipt_written",
}

type gateLayout struct {
	Root       string            `json:"root"`
	Name       string            `json:"name"`
	Home       string            `json:"home"`
	Config     string            `json:"config"`
	Data       string            `json:"data"`
	DataHome   string            `json:"data_home"`
	State      string            `json:"state"`
	Cache      string            `json:"cache"`
	Runtime    string            `json:"runtime"`
	Temp       string            `json:"temp"`
	Schemas    string            `json:"schemas"`
	Profile    string            `json:"profile"`
	Backend    string            `json:"backend"`
	SchemaKind string            `json:"schema_kind"`
	Paths      map[string]string `json:"paths"`
}

type gateCapture struct {
	Settings []model.Entry        `json:"settings"`
	Unknown  []matrix.KeyRef      `json:"unknown"`
	Errors   []gnome.CaptureError `json:"errors"`
	File     []model.Observation  `json:"file"`
}

type gateReceipt struct {
	Version int               `json:"version"`
	Role    string            `json:"role"`
	Backend string            `json:"backend"`
	Paths   map[string]string `json:"paths"`
	Counts  map[string]int    `json:"counts"`
	Bus     string            `json:"bus,omitempty"`
}

type gateApplyInput struct {
	Snapshot model.Snapshot                `json:"snapshot"`
	Preview  syncengine.Preview            `json:"preview"`
	Roots    map[string]string             `json:"roots"`
	Content  []syncengine.Postimage        `json:"content"`
	Settings []syncengine.SettingPostimage `json:"settings"`
}

func TestGNOMERestoreGate(t *testing.T) {
	if os.Getenv(gateActorMarker) != "" {
		return
	}
	if testing.Short() {
		t.Log("GNOME restore gate is not run in short mode")
		return
	}
	requireGatePrerequisites(t)
	for _, backend := range []string{"keyfile", "dconf"} {
		t.Run(backend, func(t *testing.T) {
			runGNOMERestoreBackend(t, backend)
		})
	}
	t.Run("receipt-validator", testGateReceiptValidator)
}

func TestGNOMERestoreGateActor(t *testing.T) {
	if os.Getenv(gateActorMarker) != "1" {
		return
	}
	runGateActor(t)
}

func requireGatePrerequisites(t *testing.T) {
	t.Helper()
	for _, name := range []string{"glib-compile-schemas", "dbus-run-session", "env", "gsettings"} {
		_, err := exec.LookPath(name)
		require.NoError(t, err, "GNOME restore gate requires %s", name)
	}
	service := findDconfService()
	require.NotEmpty(t, service, "GNOME restore gate requires ca.desrt.dconf.service; install dconf-service")
}

func runGNOMERestoreBackend(t *testing.T, backend string) {
	t.Helper()
	root := t.TempDir()
	sharedState := filepath.Join(root, "state")
	artifacts := filepath.Join(root, "artifacts")
	require.NoError(t, os.MkdirAll(artifacts, 0o700))
	fixtureRoot := gateFixtureRoot(t)
	a := newGateLayout(t, root, "a", backend, "canonical", sharedState)
	b := newGateLayout(t, root, "b", backend, "vendor", sharedState)
	prepareGateSchemas(t, a, fixtureRoot, "canonical")
	prepareGateSchemas(t, b, fixtureRoot, "vendor")
	if backend == "dconf" {
		probeGateDconfModule(t, b)
	}
	prepareMainTrees(t, a, b)
	assertGateTreeSkeleton(t, filepath.Join(b.Config, "sync-root"))
	assert.Equal(t, map[string]string{"nested": "dir:710"}, readGateTree(t, filepath.Join(b.Config, "sync-root")), "destination files must be absent before restore")
	portableTarget := gateFileTarget(t, a)
	otherPortableTarget := gateFileTarget(t, b)
	assert.Equal(t, portableTarget.Root, otherPortableTarget.Root, "portable file selection must be identical across machines")
	assert.NotEqual(t, filepath.Join(a.Config, portableTarget.Root.Path), filepath.Join(b.Config, portableTarget.Root.Path), "machine roots must differ")
	targets := gateTargets(portableTarget.Root)
	beforeA := readGateTree(t, filepath.Join(a.Config, portableTarget.Root.Path))

	aActor := gateActorSpec{layout: a, role: "source-capture", artifacts: artifacts, selection: "all"}
	aReceipt := runGateActorParent(t, aActor, "source-capture", backend, map[string]int{
		"captured_entries": 14, "captured_present": 7, "captured_reset": 7, "file_entries": 3,
	})
	assertGateReceiptPaths(t, aReceipt, a)
	snapshotPath := filepath.Join(artifacts, "source-snapshot.json")
	snapshot := readGateSnapshot(t, snapshotPath)
	require.NoError(t, snapshot.Validate())
	assert.Equal(t, targets, snapshot.Targets, "source snapshot must contain portable file and GNOME targets")
	assert.Equal(t, 17, len(snapshot.Entries), "snapshot must contain 14 settings and three nested file/directory entries")
	snapshotBytes, err := os.ReadFile(snapshotPath)
	require.NoError(t, err)
	assert.NotContains(t, string(snapshotBytes), a.Home, "snapshot must not expose source home paths")
	assert.NotContains(t, string(snapshotBytes), a.Config, "snapshot must not expose source XDG paths")
	assertGateSourceInventory(t, snapshot)

	captureSpec := gateActorSpec{layout: b, role: "dest-capture", artifacts: artifacts, selection: "all", seedSentinels: true}
	bReceipt := runGateActorParent(t, captureSpec, "dest-capture", backend, map[string]int{
		"captured_entries": 14, "capture_unknowns": 0, "captured_reset": 14, "file_entries": 1, "sentinel_values": 3,
	})
	assertGateReceiptPaths(t, bReceipt, b)
	baselineReceipt := runGateActorParent(t, gateActorSpec{layout: b, role: "dest-baseline", artifacts: artifacts, selection: "all"}, "dest-baseline", backend, map[string]int{"sentinel_values": 3})
	assertGateReceiptPaths(t, baselineReceipt, b)
	capture := readGateCapture(t, filepath.Join(artifacts, "dest-capture.json"))
	assert.Equal(t, 14, len(capture.Settings))
	assert.Empty(t, capture.Unknown)
	assert.Equal(t, 1, len(capture.File), "destination has only the pre-created nested directory observation")
	local, observations := gateLocalView(t, targets, capture, "all")
	plan, preview, bindings := gateReconcile(t, targets, snapshot.Entries, local, observations, syncengine.BaseMissing)
	assertMainGatePreview(t, plan, preview)
	applyInput := gateBuildApplyInput(t, snapshot, preview, targets, b)
	applyPath := filepath.Join(artifacts, "apply-input.json")
	writeGateJSON(t, applyPath, applyInput)

	applyReceipt := runGateActorParent(t, gateActorSpec{layout: b, role: "dest-apply", artifacts: artifacts, input: applyPath, selection: "all"}, "dest-apply", backend, map[string]int{
		"captured_entries": 14, "captured_present": 7, "captured_reset": 7, "file_entries": 3,
		"preview_actions_files": 2, "preview_actions_settings": 7, "preview_actions_total": 9, "directory_unchanged": 1,
		"applied_file_rows": 2, "applied_setting_rows": 7, "applied_rows": 9, "convergence_actions": 0, "convergence_unknowns": 0, "second_apply_rows_added": 0,
	})
	assertGateReceiptPaths(t, applyReceipt, b)
	assertMainGateJournal(t, b, snapshot, "applied")
	assert.Equal(t, beforeA, readGateTree(t, filepath.Join(a.Config, portableTarget.Root.Path)), "restore must leave source tree unchanged")
	assertMainGateFiles(t, b, snapshot)
	assert.Equal(t, []byte("unrelated sentinel\n"), mustReadGateFile(t, filepath.Join(b.Home, "outside-selected-root.txt")))
	assert.Equal(t, []byte("unrelated config sentinel\n"), mustReadGateFile(t, filepath.Join(b.Config, "outside-selected-root-second.txt")))

	verifyReceipt := runGateActorParent(t, gateActorSpec{layout: b, role: "dest-verify", artifacts: artifacts, input: applyPath, selection: "all"}, "dest-verify", backend, map[string]int{
		"verified_present_values": 7, "verified_reset_absent": 7, "sentinel_values": 3, "verified_file_contents": 2,
	})
	assertGateReceiptPaths(t, verifyReceipt, b)

	editFile := filepath.Join(b.Config, portableTarget.Root.Path, "prefs.ini")
	newerFile := []byte("user-edited-after-restore\n")
	require.NoError(t, os.WriteFile(editFile, newerFile, 0o600))
	sentinelPath := filepath.Join(b.Home, "outside-selected-root.txt")
	sentinelEdit := []byte("unrelated user edit after restore\n")
	require.NoError(t, os.WriteFile(sentinelPath, sentinelEdit, 0o600))
	editReceipt := runGateActorParent(t, gateActorSpec{layout: b, role: "dest-edit-newer", artifacts: artifacts, input: applyPath, selection: "all"}, "dest-edit-newer", backend, map[string]int{
		"sentinel_values": 3,
	})
	assertGateReceiptPaths(t, editReceipt, b)
	rollbackReceipt := runGateActorParent(t, gateActorSpec{layout: b, role: "dest-rollback", artifacts: artifacts, input: applyPath, selection: "all"}, "dest-rollback", backend, map[string]int{
		"rollback_rows": 9, "rollback_skipped_newer": 2, "rollback_restored": 7, "rollback_setting_reset": 6, "rollback_file_restored": 1,
		"sentinel_values": 3,
	})
	assertGateReceiptPaths(t, rollbackReceipt, b)
	assert.Equal(t, newerFile, mustReadGateFile(t, editFile), "rollback must preserve newer file content")
	assert.Equal(t, sentinelEdit, mustReadGateFile(t, sentinelPath), "rollback must preserve newer out-of-root sentinel content")
	assert.Equal(t, []byte("unrelated config sentinel\n"), mustReadGateFile(t, filepath.Join(b.Config, "outside-selected-root-second.txt")), "rollback must retain the other out-of-root sentinel")
	assert.Equal(t, map[string]string{"nested": "dir:710", "prefs.ini": fmt.Sprintf("file:600:%x", newerFile)}, readGateTree(t, filepath.Join(b.Config, portableTarget.Root.Path)), "rollback must restore every other file to its pre-apply absence")
	assertMainGateJournal(t, b, snapshot, "rolled-back")
	assert.Equal(t, beforeA, readGateTree(t, filepath.Join(a.Config, portableTarget.Root.Path)), "rollback must not alter source tree")
	t.Logf("combined restore: real %s backend; dconf uses the real service on a private bus; synthetic canonical/vendor schemas, isolated homes, prepared selections, exact journal and rollback evidence", backend)

	if backend == "keyfile" {
		runGateRefusalScenarios(t, root, sharedState, artifacts, fixtureRoot, snapshot)
		runGateSubsetScenario(t, root, sharedState, artifacts, fixtureRoot, snapshot, portableTarget.Root)
		runGateLockedScenario(t, root, fixtureRoot, artifacts)
	}
	_ = bindings
}

type gateActorSpec struct {
	layout        gateLayout
	role          string
	artifacts     string
	input         string
	selection     string
	captureName   string
	seedSentinels bool
	invocation    int
}

func newGateLayout(t *testing.T, parent, name, backend, schemaKind, stateHome string) gateLayout {
	t.Helper()
	root := filepath.Join(parent, name)
	layout := gateLayout{
		Root: root, Name: name, Home: filepath.Join(root, "home"), Config: filepath.Join(root, "xdg-config"),
		Data: filepath.Join(root, "xdg-data"), DataHome: filepath.Join(root, "xdg-data-home"), State: stateHome,
		Cache: filepath.Join(root, "cache"), Runtime: filepath.Join(root, "runtime"), Temp: filepath.Join(root, "tmp"),
		Schemas: filepath.Join(root, "xdg-data", "glib-2.0", "schemas"), Profile: filepath.Join(root, "profile"), Backend: backend, SchemaKind: schemaKind,
	}
	if name == "b" {
		layout.Config = filepath.Join(root, "alt-config")
	}
	for _, directory := range []string{layout.Home, layout.Config, layout.Data, layout.DataHome, layout.State, layout.Cache, layout.Runtime, layout.Temp, filepath.Dir(layout.Schemas)} {
		require.NoError(t, os.MkdirAll(directory, 0o700), "isolated machine directory must be created: %s", directory)
	}
	require.NoError(t, os.Chmod(layout.Runtime, 0o700))
	if backend == "dconf" {
		require.NoError(t, os.MkdirAll(filepath.Join(layout.Config, "dconf"), 0o700))
		require.NoError(t, os.WriteFile(layout.Profile, []byte("user-db:user\n"), 0o600))
		services := filepath.Join(layout.DataHome, "dbus-1", "services")
		require.NoError(t, os.MkdirAll(services, 0o700))
		service := findDconfService()
		require.NotEmpty(t, service, "dconf service file missing; install dconf-service")
		data, err := os.ReadFile(service)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(services, "ca.desrt.dconf.service"), data, 0o600))
	}
	layout.Paths = map[string]string{
		"home": layout.Home, "config": layout.Config, "data": layout.Data, "data_home": layout.DataHome,
		"state": layout.State, "cache": layout.Cache, "runtime": layout.Runtime, "temp": layout.Temp,
		"schemas": layout.Schemas, "profile": layout.Profile,
	}
	return layout
}

func probeGateDconfModule(t *testing.T, layout gateLayout) {
	t.Helper()
	command := exec.Command("env", "-i", "PATH=/usr/bin:/bin", "HOME="+layout.Home, "XDG_CONFIG_HOME="+layout.Config, "XDG_DATA_HOME="+layout.DataHome, "XDG_DATA_DIRS="+layout.Data, "GSETTINGS_BACKEND=dconf", "gsettings", "list-schemas")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "dconf GIO module probe failed; install the dconf GIO backend: %s", output)
	require.NotContains(t, string(output), "Can't find module", "dconf GIO module is not loadable")
}

func prepareGateSchemas(t *testing.T, layout gateLayout, fixtures, kind string) {
	t.Helper()
	fixture := filepath.Join(fixtures, "gsettings")
	switch kind {
	case "canonical":
	case "vendor":
		fixture = filepath.Join(fixtures, "gsettings-vendor")
	case "older":
		fixture = filepath.Join(layout.Root, "schema-source-older")
		require.NoError(t, os.MkdirAll(fixture, 0o700))
		for _, source := range []string{filepath.Join(fixtures, "gsettings-older"), filepath.Join(fixtures, "gsettings")} {
			entries, err := os.ReadDir(source)
			require.NoError(t, err)
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, "org.dottie.Test") && source == filepath.Join(fixtures, "gsettings") {
					data, err := os.ReadFile(filepath.Join(source, name))
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(filepath.Join(fixture, name), data, 0o600))
				}
				if source == filepath.Join(fixtures, "gsettings-older") {
					data, err := os.ReadFile(filepath.Join(source, name))
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(filepath.Join(fixture, name), data, 0o600))
				}
			}
		}
	case "no-calendar":
		fixture = filepath.Join(layout.Root, "schema-source-no-calendar")
		require.NoError(t, os.MkdirAll(fixture, 0o700))
		entries, err := os.ReadDir(filepath.Join(fixtures, "gsettings"))
		require.NoError(t, err)
		for _, entry := range entries {
			if entry.Name() == "org.gnome.desktop.calendar.gschema.xml" || entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(fixtures, "gsettings", entry.Name()))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(fixture, entry.Name()), data, 0o600))
		}
	default:
		require.FailNow(t, "unknown synthetic schema fixture", "%s", kind)
	}
	compileGateSchemas(t, fixture, layout.Schemas)
}

func compileGateSchemas(t *testing.T, source, target string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(target, 0o700))
	command := exec.Command("glib-compile-schemas", "--strict", "--targetdir", target, source)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "strict schema compilation failed: %s", output)
}

func prepareMainTrees(t *testing.T, a, b gateLayout) {
	t.Helper()
	aRoot := filepath.Join(a.Config, "sync-root")
	bRoot := filepath.Join(b.Config, "sync-root")
	for path, mode := range map[string]os.FileMode{aRoot: 0o750, filepath.Join(aRoot, "nested"): 0o710, bRoot: 0o750, filepath.Join(bRoot, "nested"): 0o710} {
		require.NoError(t, os.MkdirAll(path, mode))
		require.NoError(t, os.Chmod(path, mode))
	}
	for path, data := range map[string][]byte{
		filepath.Join(aRoot, "prefs.ini"):              []byte("source preference\n"),
		filepath.Join(aRoot, "nested", "options.conf"): []byte("source nested option\n"),
	} {
		require.NoError(t, os.WriteFile(path, data, 0o600))
		require.NoError(t, os.Chmod(path, 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(b.Home, "outside-selected-root.txt"), []byte("unrelated sentinel\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(b.Config, "outside-selected-root-second.txt"), []byte("unrelated config sentinel\n"), 0o600))
}

func gateFileTarget(t *testing.T, layout gateLayout) model.Target {
	t.Helper()
	selection := filepath.Join(layout.Config, "sync-root")
	resolved, err := config.ResolveSelection(platform.Paths{Home: layout.Home, ConfigHome: layout.Config}, selection)
	require.NoError(t, err)
	return model.Target{ID: "selected-files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: resolved.Base, Path: resolved.Path, Kind: resolved.Kind}}
}

func gateTargets(root *model.FileRoot) []model.Target {
	return []model.Target{
		{ID: "gnome-desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion},
		{ID: "selected-files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: root},
	}
}

func gateFixtureRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(source), "../../tests/testdata"))
}

func runGateActorParent(t *testing.T, spec gateActorSpec, role, backend string, nonzero map[string]int) gateReceipt {
	t.Helper()
	spec.role = role
	spec.layout.Backend = backend
	spec.invocation = spec.invocation + 1
	filename := fmt.Sprintf("%s-%s-%d.json", role, spec.layout.Name, spec.invocation)
	receiptPath := filepath.Join(spec.artifacts, filename)
	_ = os.Remove(receiptPath)
	environment := gateEnvironment(spec)
	executable, err := os.Executable()
	require.NoError(t, err)
	var command *exec.Cmd
	if backend == "dconf" {
		args := []string{"-i"}
		args = append(args, environment...)
		args = append(args, "dbus-run-session", "--", "env", "G_DEBUG=fatal-warnings", executable, "-test.run=^TestGNOMERestoreGateActor$")
		command = exec.Command("env", args...)
	} else {
		environment = append(environment, "G_DEBUG=fatal-warnings")
		command = exec.Command(executable, "-test.run=^TestGNOMERestoreGateActor$")
		command.Env = environment
	}
	if backend == "dconf" {
		command.Env = nil
	}
	output, runErr := command.CombinedOutput()
	require.NoError(t, runErr, "GNOME actor %s/%s failed: %s", role, backend, output)
	data, err := os.ReadFile(receiptPath)
	require.NoError(t, err, "GNOME actor %s did not write its terminal receipt: %s", role, output)
	expected := gateExpectedCounts(nonzero)
	receipt, err := validateGateReceipt(data, role, backend, spec.layout.Paths, expected)
	require.NoError(t, err, "GNOME actor %s receipt rejected", role)
	return receipt
}

func gateEnvironment(spec gateActorSpec) []string {
	values := map[string]string{
		"PATH": "/usr/bin:/bin", "HOME": spec.layout.Home, "XDG_CONFIG_HOME": spec.layout.Config,
		"XDG_DATA_HOME": spec.layout.DataHome, "XDG_DATA_DIRS": spec.layout.Data,
		"XDG_STATE_HOME": spec.layout.State, "XDG_CACHE_HOME": spec.layout.Cache,
		"XDG_RUNTIME_DIR": spec.layout.Runtime, "TMPDIR": spec.layout.Temp, "LANG": "C.UTF-8",
		"GSETTINGS_BACKEND": spec.layout.Backend, gateActorMarker: "1", "DOTTIE_GATE_ROLE": spec.role,
		"DOTTIE_GATE_BACKEND": spec.layout.Backend, "DOTTIE_GATE_MACHINE": spec.layout.Name,
		"DOTTIE_GATE_MACHINE_ROOT": spec.layout.Root, "DOTTIE_GATE_SCHEMAS": spec.layout.Schemas,
		"DOTTIE_GATE_ARTIFACTS": spec.artifacts, "DOTTIE_GATE_SELECTION": spec.selection,
		"DOTTIE_GATE_CAPTURE_NAME":   spec.captureName,
		"DOTTIE_GATE_SEED_SENTINELS": fmt.Sprint(spec.seedSentinels),
		"DOTTIE_GATE_PROFILE":        spec.layout.Profile,
		"DOTTIE_GATE_RECEIPT":        filepath.Join(spec.artifacts, fmt.Sprintf("%s-%s-%d.json", spec.role, spec.layout.Name, spec.invocation)),
		"DOTTIE_GATE_INPUT":          spec.input,
	}
	if spec.layout.Backend == "dconf" {
		values["DCONF_PROFILE"] = spec.layout.Profile
	}
	result := make([]string, 0, len(values))
	for key, value := range values {
		if value == "" {
			continue
		}
		result = append(result, key+"="+value)
	}
	sort.Strings(result)
	return result
}

func gateExpectedCounts(nonzero map[string]int) map[string]int {
	result := make(map[string]int, len(gateCountKeys))
	for _, key := range gateCountKeys {
		result[key] = 0
	}
	result["receipt_written"] = 1
	for key, value := range nonzero {
		result[key] = value
	}
	return result
}

func validateGateReceipt(data []byte, role, backend string, paths map[string]string, counts map[string]int) (gateReceipt, error) {
	if len(data) == 0 {
		return gateReceipt{}, errors.New("receipt is missing")
	}
	var receipt gateReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return gateReceipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	if receipt.Version != 1 || receipt.Role != role || receipt.Backend != backend {
		return gateReceipt{}, errors.New("receipt version, role, or backend does not match")
	}
	if !reflect.DeepEqual(receipt.Paths, paths) {
		return gateReceipt{}, errors.New("receipt isolated paths do not match the expected machine")
	}
	if !reflect.DeepEqual(receipt.Counts, counts) {
		return gateReceipt{}, fmt.Errorf("receipt count map differs: got %v, want %v", receipt.Counts, counts)
	}
	return receipt, nil
}

func assertGateReceiptPaths(t *testing.T, receipt gateReceipt, layout gateLayout) {
	t.Helper()
	assert.Equal(t, layout.Home, receipt.Paths["home"])
	assert.Equal(t, layout.Config, receipt.Paths["config"])
	assert.Equal(t, layout.State, receipt.Paths["state"])
	assert.Equal(t, layout.Schemas, receipt.Paths["schemas"])
	if layout.Backend == "dconf" {
		assert.Contains(t, receipt.Bus, "unix:")
	}
}

func testGateReceiptValidator(t *testing.T) {
	wantCounts := gateExpectedCounts(map[string]int{"captured_entries": 1})
	wantPaths := map[string]string{"home": "/tmp/synthetic/home"}
	valid := gateReceipt{Version: 1, Role: "role", Backend: "keyfile", Paths: wantPaths, Counts: wantCounts}
	data, err := json.Marshal(valid)
	require.NoError(t, err)
	_, err = validateGateReceipt(data, "role", "keyfile", wantPaths, wantCounts)
	assert.NoError(t, err)
	_, err = validateGateReceipt(nil, "role", "keyfile", wantPaths, wantCounts)
	assert.Error(t, err)
	partial := valid
	partial.Counts = map[string]int{"captured_entries": 1}
	partialData, err := json.Marshal(partial)
	require.NoError(t, err)
	_, err = validateGateReceipt(partialData, "role", "keyfile", wantPaths, wantCounts)
	assert.Error(t, err)
	wrong := valid
	wrong.Counts = gateExpectedCounts(map[string]int{"captured_entries": 2})
	wrongData, err := json.Marshal(wrong)
	require.NoError(t, err)
	_, err = validateGateReceipt(wrongData, "role", "keyfile", wantPaths, wantCounts)
	assert.Error(t, err)
	invokeUnmarkedActor(t, filepath.Join(t.TempDir(), "unmarked-receipt.json"))
}

func readGateSnapshot(t *testing.T, path string) model.Snapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var snapshot model.Snapshot
	require.NoError(t, json.Unmarshal(data, &snapshot))
	return snapshot
}

func readGateCapture(t *testing.T, path string) gateCapture {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var capture gateCapture
	require.NoError(t, json.Unmarshal(data, &capture))
	return capture
}

func writeGateJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func gateSelection(mode string) []matrix.KeyRef {
	keys, _ := matrix.SelectCategories([]string{"appearance", "fonts", "clock"})
	for index := range keys {
		keys[index].Path = gateSchemaPath(keys[index].SchemaID)
	}
	if mode == "subset" {
		filtered := keys[:0]
		for _, key := range keys {
			if key.Key != "color-scheme" && key.Key != "accent-color" {
				filtered = append(filtered, key)
			}
		}
		keys = filtered
	}
	return keys
}

func gateSchemaPath(schemaID string) string {
	if schemaID == "org.gnome.desktop.calendar" {
		return "/org/gnome/desktop/calendar/"
	}
	return "/org/gnome/desktop/interface/"
}

func gateSourceValues() map[string]model.VariantValue {
	return map[string]model.VariantValue{
		"gtk-theme":           {Type: "s", Text: "'User-Gtk'"},
		"cursor-theme":        {Type: "s", Text: "'User-Cursors'"},
		"accent-color":        {Type: "s", Text: "'purple'"},
		"font-name":           {Type: "s", Text: "'User Sans 12'"},
		"text-scaling-factor": {Type: "d", Text: "1.25"},
		"clock-show-seconds":  {Type: "b", Text: "true"},
		"show-weekdate":       {Type: "b", Text: "true"},
	}
}

func gateResetKeys() map[string]struct{} {
	return map[string]struct{}{"icon-theme": {}, "document-font-name": {}, "monospace-font-name": {}, "color-scheme": {}, "clock-format": {}, "clock-show-date": {}, "clock-show-weekday": {}}
}

func gateCanonicalResetDefaults() map[string]string {
	return map[string]string{
		"icon-theme": "'Adwaita'", "document-font-name": "'Adwaita Sans 11'", "monospace-font-name": "'Adwaita Mono 11'",
		"color-scheme": "'default'", "clock-format": "'24h'", "clock-show-date": "true", "clock-show-weekday": "false",
	}
}

func gateVendorResetDefaults() map[string]string {
	return map[string]string{
		"icon-theme": "'Vendor Icons'", "document-font-name": "'Vendor Serif 13'", "monospace-font-name": "'Vendor Mono 13'",
		"color-scheme": "'prefer-light'", "clock-format": "'12h'", "clock-show-date": "false", "clock-show-weekday": "true",
	}
}

func assertGateDefaults(t *testing.T, expected map[string]string, absent bool) {
	t.Helper()
	for key, text := range expected {
		identity, ok := gateSettingKey(key)
		require.True(t, ok)
		settings, err := gnome.OpenDefault(identity.SchemaID, identity.SettingsPath)
		require.NoError(t, err)
		snapshot, readErr := settings.Read(identity.SettingKey)
		assert.NoError(t, readErr)
		if readErr == nil {
			assert.Equal(t, text, snapshot.Default.Text, "schema default for %s", key)
			assert.Equal(t, text, snapshot.Effective.Text, "effective reset value for %s", key)
			if absent {
				assert.Nil(t, snapshot.User, "user override for reset key %s", key)
			}
		}
		assert.NoError(t, settings.Close())
	}
}

func gateKeyName(key model.EntryKey) string {
	return key.SettingKey
}

func gateEntriesByIdentity(entries []model.Entry) map[model.EntryKey]model.Entry {
	result := make(map[model.EntryKey]model.Entry, len(entries))
	for _, entry := range entries {
		result[entry.Identity()] = entry
	}
	return result
}

func gateSettingsByName(entries []model.Entry) map[string]model.Entry {
	result := make(map[string]model.Entry, len(entries))
	for _, entry := range entries {
		if entry.Setting != nil {
			result[entry.Setting.Key] = entry
		}
	}
	return result
}

func gateLocalView(t *testing.T, targets []model.Target, capture gateCapture, selection string) (syncengine.LocalView, []model.Observation) {
	t.Helper()
	local := syncengine.LocalView{}
	observations := append([]model.Observation(nil), capture.File...)
	local.Coverage = []string{"selected-files"}
	for _, observation := range capture.File {
		switch observation.State {
		case model.ObservationPresent:
			require.NotNil(t, observation.Entry)
			local.Entries = append(local.Entries, *observation.Entry)
		case model.ObservationUnknown:
			local.Unknown = append(local.Unknown, observation.Identity)
		}
	}
	for _, entry := range capture.Settings {
		local.Entries = append(local.Entries, entry)
		observations = append(observations, model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry})
	}
	for _, key := range capture.Unknown {
		identity := model.EntryKey{TargetID: "gnome-desktop", Source: model.SourceGNOME, SchemaID: key.SchemaID, SettingsPath: key.Path, SettingKey: key.Key}
		local.Unknown = append(local.Unknown, identity)
		observations = append(observations, model.Observation{State: model.ObservationUnknown, Identity: identity})
	}
	if len(capture.Unknown) == 0 && len(capture.Settings) == len(gateSelection(selection)) {
		local.Coverage = append(local.Coverage, "gnome-desktop")
	}
	return local, observations
}

func gateReconcile(t *testing.T, targets []model.Target, remote []model.Entry, local syncengine.LocalView, observations []model.Observation, status syncengine.BaseStatus) (syncengine.Plan, syncengine.Preview, []syncengine.TargetBinding) {
	t.Helper()
	bindings := make([]syncengine.TargetBinding, 0, len(targets))
	for _, target := range targets {
		binding, err := syncengine.NewTargetBinding(target)
		require.NoError(t, err)
		bindings = append(bindings, binding)
	}
	plan, err := syncengine.Reconcile(syncengine.BaseView{Status: status, Entries: nil}, local, remote, syncengine.Options{Bindings: bindings})
	require.NoError(t, err)
	preview, err := syncengine.BuildPreview(plan, targets, observations)
	require.NoError(t, err)
	return plan, preview, bindings
}

func assertGateSourceInventory(t *testing.T, snapshot model.Snapshot) {
	t.Helper()
	settings := gateSettingsByName(snapshot.Entries)
	values := gateSourceValues()
	resets := gateResetKeys()
	require.Len(t, settings, 14)
	for key, value := range values {
		entry, ok := settings[key]
		require.True(t, ok, "source snapshot is missing %s", key)
		assert.Equal(t, model.SettingPresent, entry.Setting.State)
		assert.Equal(t, &value, entry.Setting.Value)
	}
	for key := range resets {
		entry, ok := settings[key]
		require.True(t, ok, "source snapshot is missing reset %s", key)
		assert.Equal(t, model.SettingReset, entry.Setting.State)
		assert.Nil(t, entry.Setting.Value)
	}
}

func assertMainGatePreview(t *testing.T, plan syncengine.Plan, preview syncengine.Preview) {
	t.Helper()
	actions := map[model.SourceKind]int{}
	unchangedDirs := 0
	for _, decision := range plan.Decisions {
		if decision.Action == syncengine.ActionDownload {
			actions[decision.Key.Source]++
			if decision.Key.Source == model.SourceGNOME {
				assert.Equal(t, model.SettingReset, decision.Local.Setting.State, "base-missing inbound setting reset is the D3 witness")
				assert.Equal(t, model.SettingPresent, decision.Remote.Setting.State)
			}
		}
		if decision.Key.Source == model.SourceFiles && decision.Action == syncengine.ActionUnchanged && decision.Local.File != nil && decision.Local.File.Kind == model.FileDirectory {
			unchangedDirs++
		}
	}
	assert.Equal(t, 2, actions[model.SourceFiles])
	assert.Equal(t, 7, actions[model.SourceGNOME])
	assert.Equal(t, 1, unchangedDirs)
	assert.True(t, preview.Complete)
	assert.Equal(t, 0, preview.UnresolvedEntries)
	assert.Equal(t, 9, countGatePreviewActions(preview))
}

func countGatePreviewActions(preview syncengine.Preview) int {
	count := 0
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Action != "" {
				count++
			}
		}
	}
	return count
}

func gateBuildApplyInput(t *testing.T, snapshot model.Snapshot, preview syncengine.Preview, targets []model.Target, layout gateLayout) gateApplyInput {
	t.Helper()
	input := gateApplyInput{Snapshot: snapshot, Preview: preview, Roots: map[string]string{"selected-files": filepath.Join(layout.Config, snapshot.Targets[1].Root.Path)}}
	remote := gateEntriesByIdentity(snapshot.Entries)
	for _, target := range preview.Targets {
		for _, item := range target.Entries {
			if item.Action != syncengine.PreviewCreate && item.Action != syncengine.PreviewChange {
				continue
			}
			entry, ok := remote[item.Key]
			require.True(t, ok, "preview postimage missing from portable snapshot")
			if entry.File != nil {
				digest := sha256.Sum256(entry.File.Content)
				input.Content = append(input.Content, syncengine.Postimage{TargetID: entry.TargetID, Key: entry.File.Path, Data: entry.File.Content, Digest: digest[:], Mode: os.FileMode(entry.File.Mode)})
			} else {
				setting := *entry.Setting
				input.Settings = append(input.Settings, syncengine.SettingPostimage{TargetID: entry.TargetID, SchemaID: setting.SchemaID, SettingsPath: setting.Path, SettingKey: setting.Key, State: setting.State, Value: setting.Value})
			}
		}
	}
	return input
}

func actorMain() (string, string, string, map[string]string) {
	return os.Getenv("DOTTIE_GATE_ROLE"), os.Getenv("DOTTIE_GATE_BACKEND"), os.Getenv("DOTTIE_GATE_MACHINE"), map[string]string{
		"home": os.Getenv("HOME"), "config": os.Getenv("XDG_CONFIG_HOME"), "data": os.Getenv("XDG_DATA_DIRS"),
		"data_home": os.Getenv("XDG_DATA_HOME"), "state": os.Getenv("XDG_STATE_HOME"), "cache": os.Getenv("XDG_CACHE_HOME"),
		"runtime": os.Getenv("XDG_RUNTIME_DIR"), "temp": os.Getenv("TMPDIR"), "schemas": os.Getenv("DOTTIE_GATE_SCHEMAS"),
		"profile": os.Getenv("DOTTIE_GATE_PROFILE"),
	}
}

func runGateActor(t *testing.T) {
	role, backend, machine, paths := actorMain()
	assert.Contains(t, []string{"keyfile", "dconf"}, backend)
	root := os.Getenv("DOTTIE_GATE_MACHINE_ROOT")
	configPath := filepath.Join(root, "xdg-config")
	if machine == "b" {
		configPath = filepath.Join(root, "alt-config")
	}
	assert.Equal(t, filepath.Join(root, "home"), paths["home"])
	assert.Equal(t, configPath, paths["config"])
	assert.Equal(t, filepath.Join(root, "xdg-data"), paths["data"])
	assert.Equal(t, filepath.Join(root, "xdg-data-home"), paths["data_home"])
	assert.Equal(t, filepath.Join(root, "cache"), paths["cache"])
	assert.Equal(t, filepath.Join(root, "runtime"), paths["runtime"])
	assert.Equal(t, filepath.Join(root, "tmp"), paths["temp"])
	assert.Equal(t, filepath.Join(root, "xdg-data", "glib-2.0", "schemas"), paths["schemas"])
	assert.Equal(t, root, filepath.Dir(paths["home"]))
	assert.Equal(t, "C.UTF-8", os.Getenv("LANG"))
	info, err := os.Stat(paths["runtime"])
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	if backend == "dconf" {
		assert.NotEmpty(t, os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
		assert.Contains(t, os.Getenv("DBUS_SESSION_BUS_ADDRESS"), "unix:")
		assert.Equal(t, "user-db:user\n", string(mustReadGateFile(t, os.Getenv("DCONF_PROFILE"))))
		serviceSource := findDconfService()
		require.NotEmpty(t, serviceSource, "GNOME restore gate requires ca.desrt.dconf.service; install dconf-service")
		copiedService := filepath.Join(paths["data_home"], "dbus-1", "services", "ca.desrt.dconf.service")
		serviceInfo, err := os.Stat(copiedService)
		require.NoError(t, err, "isolated dconf service file missing at %s; ensure the service was copied into XDG_DATA_HOME", copiedService)
		assert.False(t, serviceInfo.IsDir(), "isolated dconf service path must be a file: %s", copiedService)
		copiedServiceBytes, err := os.ReadFile(copiedService)
		require.NoError(t, err, "could not read isolated dconf service file at %s", copiedService)
		assert.NotEmpty(t, copiedServiceBytes, "isolated dconf service file is empty: %s", copiedService)
		systemServiceBytes, err := os.ReadFile(serviceSource)
		require.NoError(t, err, "could not read system dconf service file at %s", serviceSource)
		assert.Equal(t, systemServiceBytes, copiedServiceBytes, "isolated dconf service file at %s must match system service file at %s", copiedService, serviceSource)
		require.NoError(t, os.MkdirAll(filepath.Join(paths["config"], "dconf"), 0o700))
	}
	counts := gateExpectedCounts(nil)
	var backendForClose *gnome.SettingsBackend
	switch role {
	case "source-capture":
		snapshot := actorSourceCapture(t, backend, paths, counts)
		writeActorJSON(t, filepath.Join(os.Getenv("DOTTIE_GATE_ARTIFACTS"), "source-snapshot.json"), snapshot)
	case "dest-capture", "extra-capture", "subset-capture":
		capture := actorCapture(t, role, paths, counts)
		name := role
		if role != "dest-capture" {
			name = os.Getenv("DOTTIE_GATE_CAPTURE_NAME")
		}
		if name == "" {
			name = role
		}
		writeActorJSON(t, filepath.Join(os.Getenv("DOTTIE_GATE_ARTIFACTS"), name+".json"), capture)
	case "dest-apply", "subset-apply":
		actorApply(t, paths, counts)
	case "dest-verify", "subset-verify":
		actorVerify(t, paths, counts)
	case "dest-baseline":
		assertActorSentinels(t)
		counts["sentinel_values"] = 3
	case "dest-edit-newer":
		backendForClose = actorBackend(t)
		actorEditNewer(t, backendForClose, paths, counts)
		assert.NoError(t, backendForClose.Close())
	case "dest-rollback":
		backendForClose = actorBackend(t)
		actorRollback(t, backendForClose, paths, counts)
		assert.NoError(t, backendForClose.Close())
	case "refusal":
		backendForClose = actorBackend(t)
		actorRefusal(t, backendForClose, paths, counts)
		assert.NoError(t, backendForClose.Close())
	case "locked":
		backendForClose = actorBackend(t)
		actorLocked(t, backendForClose, paths, counts)
		assert.NoError(t, backendForClose.Close())
	case "locked-positive":
		backendForClose = actorBackend(t)
		actorLockedPositive(t, backendForClose, paths, counts)
		assert.NoError(t, backendForClose.Close())
	default:
		require.FailNow(t, "unknown GNOME gate actor role", "%s", role)
	}
	_ = backendForClose
	if backend == "dconf" {
		_, databaseErr := os.Stat(filepath.Join(paths["config"], "dconf", "user"))
		require.NoError(t, databaseErr, "isolated dconf user database must be created")
	}
	counts["receipt_written"] = 1
	receipt := gateReceipt{Version: 1, Role: role, Backend: backend, Paths: receiptActorPaths(paths), Counts: counts}
	if backend == "dconf" {
		receipt.Bus = os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	}
	writeActorJSON(t, os.Getenv("DOTTIE_GATE_RECEIPT"), receipt)
	_ = machine
}

func receiptActorPaths(paths map[string]string) map[string]string {
	result := make(map[string]string, len(paths))
	for key, value := range paths {
		if value != "" {
			result[key] = value
		}
	}
	return result
}

func writeActorJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func actorSourceCapture(t *testing.T, backend string, paths map[string]string, counts map[string]int) model.Snapshot {
	t.Helper()
	for key, value := range gateSourceValues() {
		entry, ok := gateSettingKey(key)
		require.True(t, ok)
		require.NoError(t, actorSetSetting(t, entry, value.Type, value.Text))
	}
	settingsCapture := actorCaptureSettings(t, paths, "all")
	assertGateDefaults(t, gateCanonicalResetDefaults(), true)
	counts["captured_entries"] = len(settingsCapture.Entries)
	counts["capture_unknowns"] = len(settingsCapture.Unknown)
	for _, entry := range settingsCapture.Entries {
		if entry.Setting.State == model.SettingPresent {
			counts["captured_present"]++
		} else {
			counts["captured_reset"]++
		}
	}
	fileCapture := actorCaptureFiles(t)
	counts["file_entries"] = countPresentObservations(fileCapture.Observations)
	entries := make([]model.Entry, 0, len(settingsCapture.Entries)+counts["file_entries"])
	entries = append(entries, settingsCapture.Entries...)
	for _, observation := range fileCapture.Observations {
		if observation.State == model.ObservationPresent {
			require.NotNil(t, observation.Entry)
			entries = append(entries, *observation.Entry)
		}
	}
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: gateTargets(&model.FileRoot{Base: model.RootXDGConfig, Path: "sync-root", Kind: model.SelectionDirectory}), Entries: entries}
	require.NoError(t, snapshot.Validate())
	_ = backend
	return snapshot
}

func actorCapture(t *testing.T, role string, paths map[string]string, counts map[string]int) gateCapture {
	t.Helper()
	selection := os.Getenv("DOTTIE_GATE_SELECTION")
	if os.Getenv("DOTTIE_GATE_SEED_SENTINELS") == "true" {
		seedGateSentinels(t)
	}
	settingsCapture := actorCaptureSettings(t, paths, selection)
	if os.Getenv("DOTTIE_GATE_MACHINE") == "b" && selection == "all" {
		assertGateDefaults(t, gateVendorResetDefaults(), true)
		for key, value := range gateVendorResetDefaults() {
			assert.NotEqual(t, gateCanonicalResetDefaults()[key], value, "vendor default must differ for reset key %s", key)
		}
	}
	fileCapture := actorCaptureFiles(t)
	capture := gateCapture{Settings: settingsCapture.Entries, Unknown: settingsCapture.Unknown, Errors: settingsCapture.Errors, File: fileCapture.Observations}
	counts["captured_entries"] = len(settingsCapture.Entries)
	counts["capture_unknowns"] = len(settingsCapture.Unknown)
	for _, entry := range settingsCapture.Entries {
		if entry.Setting.State == model.SettingPresent {
			counts["captured_present"]++
		} else {
			counts["captured_reset"]++
		}
	}
	for _, failure := range settingsCapture.Errors {
		if failure.Reason == gnome.CaptureMissingKey {
			counts["missing_key_unknowns"]++
		}
		if failure.Reason == gnome.CaptureMissingSchema {
			counts["missing_schema_unknowns"]++
		}
	}
	counts["file_entries"] = countPresentObservations(fileCapture.Observations)
	for _, observation := range fileCapture.Observations {
		if observation.State == model.ObservationUnknown {
			counts["file_unknowns"]++
		}
	}
	if os.Getenv("DOTTIE_GATE_SEED_SENTINELS") == "true" {
		counts["sentinel_values"] = 3
	}
	_ = role
	return capture
}

func actorCaptureSettings(t *testing.T, paths map[string]string, selection string) gnome.CaptureResult {
	t.Helper()
	keys := gateSelection(selection)
	result, err := gnome.Capture(context.Background(), gnome.CaptureRequest{TargetID: "gnome-desktop", Keys: keys})
	require.NoError(t, err)
	return result
}

func actorCaptureFiles(t *testing.T) files.Result {
	t.Helper()
	result, err := files.Capture(files.Root{TargetID: "selected-files", Path: filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "sync-root"), Kind: model.SelectionDirectory})
	require.NoError(t, err)
	return result
}

func countPresentObservations(observations []model.Observation) int {
	count := 0
	for _, observation := range observations {
		if observation.State == model.ObservationPresent {
			count++
		}
	}
	return count
}

func gateSettingKey(name string) (model.EntryKey, bool) {
	for _, key := range gateSelection("all") {
		if key.Key == name {
			return model.EntryKey{TargetID: "gnome-desktop", Source: model.SourceGNOME, SchemaID: key.SchemaID, SettingsPath: key.Path, SettingKey: name}, true
		}
	}
	return model.EntryKey{}, false
}

func actorSetSetting(t *testing.T, key model.EntryKey, valueType, text string) error {
	t.Helper()
	backend, err := gnome.NewSettingsBackend()
	if err != nil {
		return err
	}
	defer func() { assert.NoError(t, backend.Close()) }()
	if err := backend.Set(context.Background(), key, valueType, text); err != nil {
		return err
	}
	return nil
}

func seedGateSentinels(t *testing.T) {
	t.Helper()
	backend, err := gnome.NewSettingsBackend()
	require.NoError(t, err)
	defer func() { assert.NoError(t, backend.Close()) }()
	values := []struct {
		key      string
		typeName string
		text     string
	}{
		{"enabled", "b", "true"}, {"vendor-text", "s", "'unrelated sentinel'"}, {"signed", "x", "int64 44"},
	}
	for _, item := range values {
		key := model.EntryKey{TargetID: "unrelated", Source: model.SourceGNOME, SchemaID: "org.dottie.Test", SettingsPath: "/org/dottie/test/", SettingKey: item.key}
		require.NoError(t, backend.Set(context.Background(), key, item.typeName, item.text))
	}
}

func actorBackend(t *testing.T) *gnome.SettingsBackend {
	t.Helper()
	backend, err := gnome.NewSettingsBackend()
	require.NoError(t, err)
	return backend
}

func readGateInput(t *testing.T) gateApplyInput {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("DOTTIE_GATE_INPUT"))
	require.NoError(t, err)
	var input gateApplyInput
	require.NoError(t, json.Unmarshal(data, &input))
	return input
}

func actorApply(t *testing.T, paths map[string]string, counts map[string]int) {
	t.Helper()
	input := readGateInput(t)
	store := openActorStore(t, paths)
	defer func() { assert.NoError(t, store.Close()) }()
	settings := actorBackend(t)
	defer func() { assert.NoError(t, settings.Close()) }()
	request := syncengine.ApplyRequest{Preview: input.Preview, Roots: input.Roots, ModePolicy: syncengine.ModePolicy{Default: 0o600}, Content: input.Content, Settings: settings, SettingPostimages: input.Settings, Now: gateClock}
	assertPreviewActionCounts(t, input.Preview, counts)
	require.NoError(t, syncengine.Apply(context.Background(), store, request), "first mixed restore apply must succeed")
	journal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	counts["applied_rows"] = len(journal)
	for _, entry := range journal {
		if entry.Identity.Source == model.SourceFiles {
			counts["applied_file_rows"]++
		} else if entry.Identity.Source == model.SourceGNOME {
			counts["applied_setting_rows"]++
		}
		assert.Equal(t, "applied", entry.State)
		assert.Equal(t, state.JournalStageVerified, entry.Stage)
	}
	capture := actorCapture(t, "after-apply", paths, counts)
	local, observations := actorLocalView(t, capture, "all")
	bindings := make([]syncengine.TargetBinding, 0, len(input.Snapshot.Targets))
	for _, target := range input.Snapshot.Targets {
		binding, err := syncengine.NewTargetBinding(target)
		require.NoError(t, err)
		bindings = append(bindings, binding)
	}
	plan, err := syncengine.Reconcile(syncengine.BaseView{Status: syncengine.BaseKnown, Entries: input.Snapshot.Entries}, local, input.Snapshot.Entries, syncengine.Options{Bindings: bindings})
	require.NoError(t, err)
	converged, err := syncengine.BuildPreview(plan, input.Snapshot.Targets, observations)
	require.NoError(t, err)
	counts["convergence_actions"] = countGatePreviewActions(converged)
	counts["convergence_unknowns"] = converged.UnresolvedEntries
	assert.True(t, converged.Complete)
	assert.Equal(t, 0, counts["convergence_actions"])
	assert.Equal(t, 0, converged.UnresolvedEntries)
	assert.Equal(t, len(input.Snapshot.Entries), countGatePreviewEntries(converged), "convergence must retain the complete expected identity inventory")
	second := syncengine.ApplyRequest{Preview: converged, Roots: input.Roots, ModePolicy: syncengine.ModePolicy{Default: 0o600}, Settings: settings, Now: gateClock}
	beforeRows := len(journal)
	require.NoError(t, syncengine.Apply(context.Background(), store, second), "second converged apply must be a no-op")
	after, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	counts["second_apply_rows_added"] = len(after) - beforeRows
	assert.Equal(t, beforeRows, len(after))
}

func actorLocalView(t *testing.T, capture gateCapture, selection string) (syncengine.LocalView, []model.Observation) {
	t.Helper()
	local := syncengine.LocalView{Coverage: []string{"selected-files"}}
	observations := append([]model.Observation(nil), capture.File...)
	for _, observation := range capture.File {
		if observation.State == model.ObservationPresent {
			require.NotNil(t, observation.Entry)
			local.Entries = append(local.Entries, *observation.Entry)
		} else if observation.State == model.ObservationUnknown {
			local.Unknown = append(local.Unknown, observation.Identity)
		}
	}
	for _, entry := range capture.Settings {
		local.Entries = append(local.Entries, entry)
		observations = append(observations, model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry})
	}
	for _, key := range capture.Unknown {
		identity := model.EntryKey{TargetID: "gnome-desktop", Source: model.SourceGNOME, SchemaID: key.SchemaID, SettingsPath: key.Path, SettingKey: key.Key}
		local.Unknown = append(local.Unknown, identity)
		observations = append(observations, model.Observation{State: model.ObservationUnknown, Identity: identity})
	}
	if len(capture.Unknown) == 0 && len(capture.Settings) == len(gateSelection(selection)) {
		local.Coverage = append(local.Coverage, "gnome-desktop")
	}
	return local, observations
}

func assertPreviewActionCounts(t *testing.T, preview syncengine.Preview, counts map[string]int) {
	t.Helper()
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Action == "" {
				if entry.Key.Source == model.SourceFiles && entry.State == syncengine.PreviewStateUnchanged {
					if entry.Key.FilePath == "." || entry.Key.FilePath == "nested" {
						counts["directory_unchanged"]++
					}
				}
				continue
			}
			counts["preview_actions_total"]++
			if entry.Key.Source == model.SourceFiles {
				counts["preview_actions_files"]++
			} else {
				counts["preview_actions_settings"]++
			}
		}
	}
	wantSettings := 7
	if os.Getenv("DOTTIE_GATE_ROLE") == "subset-apply" {
		wantSettings = 6
	}
	assert.Equal(t, 2+wantSettings, counts["preview_actions_total"])
	assert.Equal(t, 2, counts["preview_actions_files"])
	assert.Equal(t, wantSettings, counts["preview_actions_settings"])
	assert.Equal(t, 1, counts["directory_unchanged"])
}

func countGatePreviewEntries(preview syncengine.Preview) int {
	count := 0
	for _, target := range preview.Targets {
		count += len(target.Entries)
	}
	return count
}

func actorVerify(t *testing.T, paths map[string]string, counts map[string]int) {
	t.Helper()
	input := readGateInput(t)
	capture := actorCaptureSettings(t, paths, os.Getenv("DOTTIE_GATE_SELECTION"))
	actual := gateSettingsByName(capture.Entries)
	for key, value := range gateSourceValues() {
		if _, presentInSnapshot := gateSettingsByName(input.Snapshot.Entries)[key]; !presentInSnapshot {
			continue
		}
		entry, ok := actual[key]
		require.True(t, ok)
		assert.Equal(t, model.SettingPresent, entry.Setting.State)
		assert.Equal(t, &value, entry.Setting.Value)
		counts["verified_present_values"]++
	}
	defaults := gateVendorResetDefaults()
	if os.Getenv("DOTTIE_GATE_SELECTION") == "subset" {
		defaults = gateCanonicalResetDefaults()
	}
	snapshotSettings := gateSettingsByName(input.Snapshot.Entries)
	selectedDefaults := make(map[string]string)
	for key, value := range defaults {
		if entry, present := snapshotSettings[key]; present && entry.Setting.State == model.SettingReset {
			selectedDefaults[key] = value
			counts["verified_reset_absent"]++
		}
	}
	assertGateDefaults(t, selectedDefaults, true)
	assertActorSentinels(t)
	counts["sentinel_values"] = 3
	for _, entry := range input.Snapshot.Entries {
		if entry.File == nil || entry.File.Kind != model.FileRegular {
			continue
		}
		path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "sync-root", filepath.FromSlash(entry.File.Path))
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, entry.File.Content, data)
		counts["verified_file_contents"]++
	}
	assert.Equal(t, 2, counts["verified_file_contents"])
}

func assertActorSentinels(t *testing.T) {
	t.Helper()
	backend, err := gnome.NewSettingsBackend()
	require.NoError(t, err)
	defer func() { assert.NoError(t, backend.Close()) }()
	for _, expected := range []struct{ key, typeName, text string }{{"enabled", "b", "true"}, {"vendor-text", "s", "'unrelated sentinel'"}, {"signed", "x", "int64 44"}} {
		identity := model.EntryKey{TargetID: "unrelated", Source: model.SourceGNOME, SchemaID: "org.dottie.Test", SettingsPath: "/org/dottie/test/", SettingKey: expected.key}
		value, observeErr := backend.Observe(context.Background(), identity)
		assert.NoError(t, observeErr)
		if observeErr == nil {
			assert.True(t, value.Present)
			assert.Equal(t, expected.typeName, value.Type)
			assert.Equal(t, expected.text, value.Text)
		}
	}
}

func actorEditNewer(t *testing.T, backend *gnome.SettingsBackend, paths map[string]string, counts map[string]int) {
	t.Helper()
	key, ok := gateSettingKey("gtk-theme")
	require.True(t, ok)
	require.NoError(t, backend.Set(context.Background(), key, "s", "'newer user setting'"))
	assertActorSentinels(t)
	counts["sentinel_values"] = 3
}

func actorRollback(t *testing.T, backend *gnome.SettingsBackend, paths map[string]string, counts map[string]int) {
	t.Helper()
	input := readGateInput(t)
	store := openActorStore(t, paths)
	defer func() { assert.NoError(t, store.Close()) }()
	report, err := syncengine.RollbackAppliedWithSettings(context.Background(), store, nil, backend, gateClock)
	require.NoError(t, err)
	counts["rollback_rows"] = len(report.Entries)
	for _, result := range report.Entries {
		if (result.Key.Source == model.SourceGNOME && result.Key.SettingKey == "gtk-theme") || (result.Key.Source == model.SourceFiles && result.Key.FilePath == "prefs.ini") {
			assert.Equal(t, "skipped-newer-edit", result.Outcome)
		} else {
			assert.Equal(t, "rolled-back", result.Outcome)
		}
		if result.Outcome == "skipped-newer-edit" {
			counts["rollback_skipped_newer"]++
		} else if result.Outcome == "rolled-back" {
			counts["rollback_restored"]++
			if result.Key.Source == model.SourceGNOME && result.Key.SettingKey != "gtk-theme" {
				counts["rollback_setting_reset"]++
			}
			if result.Key.Source == model.SourceFiles {
				counts["rollback_file_restored"]++
			}
		}
	}
	assert.Equal(t, 9, len(report.Entries))
	for _, entry := range input.Snapshot.Entries {
		if entry.Setting == nil {
			continue
		}
		observed, observeErr := backend.Observe(context.Background(), entry.Identity())
		assert.NoError(t, observeErr)
		if entry.Setting.Key == "gtk-theme" {
			assert.True(t, observed.Present)
			assert.Equal(t, "'newer user setting'", observed.Text)
		} else if values := gateSourceValues(); values[entry.Setting.Key].Type != "" {
			assert.False(t, observed.Present, "applied setting %s must return to absent preimage", entry.Setting.Key)
		}
	}
	assertActorSentinels(t)
	counts["sentinel_values"] = 3
}

func actorRefusal(t *testing.T, backend *gnome.SettingsBackend, paths map[string]string, counts map[string]int) {
	t.Helper()
	input := readGateInput(t)
	before := actorCaptureSettings(t, paths, os.Getenv("DOTTIE_GATE_SELECTION"))
	store := openActorStore(t, paths)
	defer func() { assert.NoError(t, store.Close()) }()
	request := syncengine.ApplyRequest{Preview: input.Preview, Roots: input.Roots, ModePolicy: syncengine.ModePolicy{Default: 0o600}, Settings: backend, Now: gateClock}
	applyErr := syncengine.Apply(context.Background(), store, request)
	var blocked *syncengine.NotActionableError
	require.ErrorAs(t, applyErr, &blocked)
	require.ErrorIs(t, applyErr, syncengine.ErrNotActionable)
	assert.Equal(t, model.EntryKey{TargetID: "gnome-desktop", Source: model.SourceGNOME, SchemaID: os.Getenv("DOTTIE_GATE_BLOCKED_SCHEMA"), SettingsPath: os.Getenv("DOTTIE_GATE_BLOCKED_PATH"), SettingKey: os.Getenv("DOTTIE_GATE_BLOCKED_KEY")}, blocked.Key)
	journal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, journal)
	after := actorCaptureSettings(t, paths, os.Getenv("DOTTIE_GATE_SELECTION"))
	assert.Equal(t, before, after, "refusal must not mutate any setting")
	counts["capture_unknowns"] = len(before.Unknown)
	for _, captureErr := range before.Errors {
		if captureErr.Reason == gnome.CaptureMissingKey {
			counts["missing_key_unknowns"]++
		}
		if captureErr.Reason == gnome.CaptureMissingSchema {
			counts["missing_schema_unknowns"]++
		}
	}
}

func actorLocked(t *testing.T, backend *gnome.SettingsBackend, paths map[string]string, counts map[string]int) {
	t.Helper()
	input := readGateInput(t)
	key := input.Preview.Targets[0].Entries[0].Key
	decorator := &gateLockedBackend{delegate: backend, key: key}
	store := openActorStore(t, paths)
	defer func() { assert.NoError(t, store.Close()) }()
	applyErr := syncengine.Apply(context.Background(), store, syncengine.ApplyRequest{Preview: input.Preview, Settings: decorator, SettingPostimages: input.Settings, Now: gateClock})
	require.Error(t, applyErr)
	var notActionable *syncengine.NotActionableError
	assert.False(t, errors.As(applyErr, &notActionable))
	assert.NotErrorIs(t, applyErr, syncengine.ErrNotActionable)
	assert.Contains(t, applyErr.Error(), "not writable")
	assert.Equal(t, 1, decorator.observations)
	assert.Zero(t, decorator.writes)
	counts["locked_observations"] = decorator.observations
	counts["locked_writes"] = decorator.writes
	journal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, journal)
	observed, err := backend.Observe(context.Background(), key)
	require.NoError(t, err)
	assert.False(t, observed.Present)
}

type gateLockedBackend struct {
	delegate     syncengine.SettingsBackend
	key          model.EntryKey
	observations int
	writes       int
}

func (backend *gateLockedBackend) Observe(ctx context.Context, key model.EntryKey) (syncengine.SettingValue, error) {
	backend.observations++
	value, err := backend.delegate.Observe(ctx, key)
	if err == nil && key == backend.key {
		value.Writable = false
	}
	return value, err
}

func (backend *gateLockedBackend) Canonicalize(ctx context.Context, key model.EntryKey, valueType, text string) (syncengine.SettingValue, error) {
	return backend.delegate.Canonicalize(ctx, key, valueType, text)
}

func (backend *gateLockedBackend) Set(ctx context.Context, key model.EntryKey, valueType, text string) error {
	backend.writes++
	return backend.delegate.Set(ctx, key, valueType, text)
}

func (backend *gateLockedBackend) Reset(ctx context.Context, key model.EntryKey) error {
	backend.writes++
	return backend.delegate.Reset(ctx, key)
}

func actorLockedPositive(t *testing.T, backend *gnome.SettingsBackend, paths map[string]string, counts map[string]int) {
	t.Helper()
	input := readGateInput(t)
	store := openActorStore(t, paths)
	defer func() { assert.NoError(t, store.Close()) }()
	require.NoError(t, syncengine.Apply(context.Background(), store, syncengine.ApplyRequest{Preview: input.Preview, Settings: backend, SettingPostimages: input.Settings, Now: gateClock}))
	journal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, journal, 1)
	assert.Equal(t, state.JournalStageVerified, journal[0].Stage)
	value, err := backend.Observe(context.Background(), input.Preview.Targets[0].Entries[0].Key)
	require.NoError(t, err)
	assert.True(t, value.Present)
	assert.Equal(t, "'locked positive value'", value.Text)
	counts["applied_rows"] = 1
	counts["applied_setting_rows"] = 1
	counts["verified_present_values"] = 1
}

func openActorStore(t *testing.T, paths map[string]string) *state.Store {
	t.Helper()
	store, err := state.Open(platform.Paths{Home: paths["home"], StateHome: paths["state"]})
	require.NoError(t, err)
	for _, target := range []state.TargetDescriptor{
		{ID: "selected-files", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, LogicalBase: model.RootXDGConfig, LogicalPath: "sync-root", Kind: model.SelectionDirectory, Mode: "review", CreatedAt: 1},
		{ID: "gnome-desktop", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 1},
	} {
		require.NoError(t, store.PutTarget(context.Background(), target))
	}
	return store
}

func gateClock() time.Time {
	return time.Unix(100, 0)
}

func findDconfService() string {
	for _, path := range []string{"/usr/share/dbus-1/services/ca.desrt.dconf.service", "/usr/local/share/dbus-1/services/ca.desrt.dconf.service"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func readGateTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			result[filepath.ToSlash(relative)] = fmt.Sprintf("dir:%o", info.Mode().Perm())
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = fmt.Sprintf("file:%o:%x", info.Mode().Perm(), data)
		return nil
	})
	require.NoError(t, err)
	return result
}

func mustReadGateFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func assertMainGateFiles(t *testing.T, layout gateLayout, snapshot model.Snapshot) {
	t.Helper()
	for _, entry := range snapshot.Entries {
		if entry.File == nil || entry.File.Kind != model.FileRegular {
			continue
		}
		got := mustReadGateFile(t, filepath.Join(layout.Config, "sync-root", filepath.FromSlash(entry.File.Path)))
		assert.Equal(t, entry.File.Content, got)
	}
}

func assertMainGateJournal(t *testing.T, layout gateLayout, snapshot model.Snapshot, stateFilter string) {
	t.Helper()
	store, err := state.Open(platform.Paths{Home: layout.Home, StateHome: layout.State})
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	rows, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, rows, 9)
	wantIdentities := make(map[model.EntryKey]bool)
	for _, item := range snapshot.Entries {
		if item.Setting != nil && item.Setting.State == model.SettingPresent {
			wantIdentities[item.Identity()] = true
		}
		if item.File != nil && item.File.Kind == model.FileRegular {
			wantIdentities[item.Identity()] = true
		}
	}
	counts := map[model.SourceKind]int{}
	for _, row := range rows {
		counts[row.Identity.Source]++
		assert.True(t, wantIdentities[row.Identity], "journal identity must match a downloaded snapshot identity")
		delete(wantIdentities, row.Identity)
		if row.Identity.Source == model.SourceGNOME && row.Identity.SettingKey == "gtk-theme" && stateFilter == "rolled-back" {
			assert.Equal(t, "applied", row.State)
			assert.Equal(t, state.JournalStageRollbackSkipped, row.Stage)
			continue
		}
		if row.Identity.Source == model.SourceFiles && row.Identity.FilePath == "prefs.ini" && stateFilter == "rolled-back" {
			assert.Equal(t, "applied", row.State)
			assert.Equal(t, state.JournalStageRollbackSkipped, row.Stage)
			continue
		}
		assert.Equal(t, stateFilter, row.State)
		if stateFilter == "applied" {
			assert.Equal(t, state.JournalStageVerified, row.Stage)
		} else {
			assert.Equal(t, state.JournalStageRolledBack, row.Stage)
		}
	}
	assert.Equal(t, 7, counts[model.SourceGNOME])
	assert.Equal(t, 2, counts[model.SourceFiles])
	assert.Empty(t, wantIdentities)
}

func assertGateTreeSkeleton(t *testing.T, root string) {
	t.Helper()
	for path, mode := range map[string]os.FileMode{".": 0o750, "nested": 0o710} {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(path)))
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, mode, info.Mode().Perm())
	}
}

func invokeUnmarkedActor(t *testing.T, artifactPath string) {
	t.Helper()
	_ = os.Remove(artifactPath)
	executable, err := os.Executable()
	require.NoError(t, err)
	command := exec.Command(executable, "-test.run=^TestGNOMERestoreGateActor$")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}
	output, err := command.CombinedOutput()
	require.NoError(t, err, "unmarked actor must return cleanly: %s", output)
	_, err = os.Stat(artifactPath)
	assert.True(t, errors.Is(err, os.ErrNotExist), "unmarked actor must not create receipt")
	_, err = validateGateReceipt(nil, "role", "keyfile", map[string]string{}, gateExpectedCounts(nil))
	assert.Error(t, err, "validator must reject the missing negative-control receipt")
}

func runGateRefusalScenarios(t *testing.T, root, sharedState, artifacts, fixtureRoot string, snapshot model.Snapshot) {
	t.Helper()
	for _, test := range []struct {
		name          string
		kind          string
		selection     string
		unknown       int
		missingKey    int
		missingSchema int
		blocked       string
	}{
		{name: "older-surface", kind: "older", selection: "all", unknown: 2, missingKey: 2, blocked: "accent-color"},
		{name: "missing-schema", kind: "no-calendar", selection: "all", unknown: 1, missingSchema: 1, blocked: "show-weekdate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			caseRoot := filepath.Join(root, test.name)
			layout := newGateLayout(t, caseRoot, test.name, "keyfile", test.kind, filepath.Join(caseRoot, "state"))
			prepareGateSchemas(t, layout, fixtureRoot, test.kind)
			portable := model.FileRoot{Base: model.RootXDGConfig, Path: "sync-root", Kind: model.SelectionDirectory}
			prepareEmptySkeleton(t, layout, portable)
			captureRole := "extra-capture"
			captureName := test.name + "-capture"
			captureOut := filepath.Join(artifacts, captureName+".json")
			receipt := runGateActorParent(t, gateActorSpec{layout: layout, role: captureRole, artifacts: artifacts, selection: test.selection, captureName: captureName}, captureRole, "keyfile", map[string]int{
				"captured_entries": 14 - test.unknown, "captured_reset": 14 - test.unknown,
				"capture_unknowns": test.unknown, "missing_key_unknowns": test.missingKey, "missing_schema_unknowns": test.missingSchema, "file_entries": 1,
			})
			assertGateReceiptPaths(t, receipt, layout)
			capture := readGateCapture(t, captureOut)
			require.Len(t, capture.Unknown, test.unknown)
			if test.kind == "older" {
				assert.Equal(t, []matrix.KeyRef{{SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "accent-color"}, {SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "color-scheme"}}, capture.Unknown)
				for _, captureErr := range capture.Errors {
					assert.Equal(t, gnome.CaptureMissingKey, captureErr.Reason)
				}
			} else {
				assert.Equal(t, []matrix.KeyRef{{SchemaID: "org.gnome.desktop.calendar", Path: "/org/gnome/desktop/calendar/", Key: "show-weekdate"}}, capture.Unknown)
				assert.Equal(t, []gnome.CaptureError{{Key: capture.Unknown[0], Reason: gnome.CaptureMissingSchema}}, capture.Errors)
			}
			local, observations := gateLocalView(t, gateTargets(&portable), capture, test.selection)
			local = gateSettingsOnlyLocalView(local)
			settingsRemote := make([]model.Entry, 0)
			for _, entry := range snapshot.Entries {
				if entry.Setting != nil {
					settingsRemote = append(settingsRemote, entry)
				}
			}
			settingsTargets := []model.Target{{ID: "gnome-desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}}
			plan, preview, _ := gateReconcile(t, settingsTargets, settingsRemote, local, filterSettingObservations(observations), syncengine.BaseMissing)
			blockedKey := findBlockedKey(t, plan)
			assert.Equal(t, test.blocked, blockedKey.SettingKey)
			assert.False(t, preview.Complete)
			assert.Equal(t, test.unknown, preview.UnresolvedEntries)
			input := gateApplyInput{Snapshot: model.Snapshot{Version: model.SnapshotVersion, Targets: settingsTargets, Entries: settingsRemote}, Preview: preview}
			inputPath := filepath.Join(artifacts, test.name+"-refusal-input.json")
			writeGateJSON(t, inputPath, input)
			refusalRole := test.name + "-refusal"
			spec := gateActorSpec{layout: layout, role: "refusal", artifacts: artifacts, input: inputPath, selection: test.selection}
			refusalReceipt := runGateActorParentWithBlocked(t, spec, refusalRole, test.unknown, test.missingKey, test.missingSchema, blockedKey)
			assertGateReceiptPaths(t, refusalReceipt, layout)
			assertNoFilesAdded(t, layout, portable)
		})
	}
}

func gateSettingsOnlyLocalView(local syncengine.LocalView) syncengine.LocalView {
	result := syncengine.LocalView{}
	for _, entry := range local.Entries {
		if entry.Setting != nil {
			result.Entries = append(result.Entries, entry)
		}
	}
	for _, key := range local.Unknown {
		if key.Source == model.SourceGNOME {
			result.Unknown = append(result.Unknown, key)
		}
	}
	if len(result.Unknown) == 0 {
		result.Coverage = []string{"gnome-desktop"}
	}
	return result
}

func filterSettingObservations(observations []model.Observation) []model.Observation {
	result := make([]model.Observation, 0)
	for _, observation := range observations {
		if observation.Identity.Source == model.SourceGNOME {
			result = append(result, observation)
		}
	}
	return result
}

func findBlockedKey(t *testing.T, plan syncengine.Plan) model.EntryKey {
	t.Helper()
	for _, decision := range plan.Decisions {
		if decision.Action == syncengine.ActionBlocked {
			return decision.Key
		}
	}
	require.FailNow(t, "plan has no blocked key")
	return model.EntryKey{}
}

func runGateActorParentWithBlocked(t *testing.T, spec gateActorSpec, role string, unknown, missingKeys, missingSchemas int, blocked model.EntryKey) gateReceipt {
	t.Helper()
	spec.role = "refusal"
	spec.layout.Backend = "keyfile"
	spec.invocation++
	receiptPath := filepath.Join(spec.artifacts, role+"-"+spec.layout.Name+".json")
	_ = os.Remove(receiptPath)
	environment := gateEnvironment(spec)
	environment = setGateEnvironment(environment, map[string]string{
		"DOTTIE_GATE_RECEIPT": receiptPath, "DOTTIE_GATE_BLOCKED_SCHEMA": blocked.SchemaID,
		"DOTTIE_GATE_BLOCKED_PATH": blocked.SettingsPath, "DOTTIE_GATE_BLOCKED_KEY": blocked.SettingKey,
	})
	executable, err := os.Executable()
	require.NoError(t, err)
	command := exec.Command(executable, "-test.run=^TestGNOMERestoreGateActor$")
	command.Env = environment
	output, runErr := command.CombinedOutput()
	require.NoError(t, runErr, "refusal actor failed: %s", output)
	data, err := os.ReadFile(receiptPath)
	require.NoError(t, err)
	counts := gateExpectedCounts(map[string]int{"capture_unknowns": unknown, "missing_key_unknowns": missingKeys, "missing_schema_unknowns": missingSchemas})
	receipt, err := validateGateReceipt(data, "refusal", "keyfile", spec.layout.Paths, counts)
	require.NoError(t, err)
	return receipt
}

func setGateEnvironment(environment []string, values map[string]string) []string {
	result := make([]string, 0, len(environment)+len(values))
	for _, item := range environment {
		name, _, _ := strings.Cut(item, "=")
		if _, replace := values[name]; !replace {
			result = append(result, item)
		}
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	sort.Strings(result)
	return result
}

func prepareEmptySkeleton(t *testing.T, layout gateLayout, root model.FileRoot) {
	t.Helper()
	for path, mode := range map[string]os.FileMode{".": 0o750, "nested": 0o710} {
		directory := filepath.Join(layout.Config, root.Path, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(directory, mode))
		require.NoError(t, os.Chmod(directory, mode))
	}
}

func assertNoFilesAdded(t *testing.T, layout gateLayout, root model.FileRoot) {
	t.Helper()
	filesTree := readGateTree(t, filepath.Join(layout.Config, root.Path))
	assert.Equal(t, map[string]string{"nested": "dir:710"}, filesTree)
}

func runGateSubsetScenario(t *testing.T, root, sharedState, artifacts, fixtureRoot string, source model.Snapshot, fileRoot *model.FileRoot) {
	t.Helper()
	subsetRoot := filepath.Join(root, "subset")
	layout := newGateLayout(t, subsetRoot, "c", "keyfile", "older", filepath.Join(subsetRoot, "state"))
	prepareGateSchemas(t, layout, fixtureRoot, "older")
	prepareEmptySkeleton(t, layout, *fileRoot)
	role := "subset-capture"
	capturePath := filepath.Join(artifacts, role+".json")
	receipt := runGateActorParent(t, gateActorSpec{layout: layout, role: role, artifacts: artifacts, selection: "subset", seedSentinels: true}, role, "keyfile", map[string]int{
		"captured_entries": 12, "capture_unknowns": 0, "captured_reset": 12, "file_entries": 1, "sentinel_values": 3,
	})
	assertGateReceiptPaths(t, receipt, layout)
	capture := readGateCapture(t, capturePath)
	filteredEntries := make([]model.Entry, 0)
	for _, entry := range source.Entries {
		if entry.Setting == nil || (entry.Setting.Key != "color-scheme" && entry.Setting.Key != "accent-color") {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	subsetSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: source.Targets, Entries: filteredEntries}
	require.NoError(t, subsetSnapshot.Validate())
	settingCount := 0
	for _, entry := range subsetSnapshot.Entries {
		if entry.Setting == nil {
			continue
		}
		settingCount++
		assert.NotEqual(t, "color-scheme", entry.Setting.Key)
		assert.NotEqual(t, "accent-color", entry.Setting.Key)
		if entry.Setting.SchemaID == "org.gnome.desktop.calendar" {
			assert.Equal(t, "show-weekdate", entry.Setting.Key)
		}
	}
	assert.Equal(t, 12, settingCount)
	local, observations := gateLocalView(t, source.Targets, capture, "subset")
	_, preview, _ := gateReconcile(t, source.Targets, subsetSnapshot.Entries, local, observations, syncengine.BaseMissing)
	assert.True(t, preview.Complete)
	assert.Equal(t, 8, countGatePreviewActions(preview))
	assert.Equal(t, 6, countGateSettingsActions(preview))
	input := gateBuildApplyInput(t, subsetSnapshot, preview, source.Targets, layout)
	inputPath := filepath.Join(artifacts, "subset-apply-input.json")
	writeGateJSON(t, inputPath, input)
	applyReceipt := runGateActorParent(t, gateActorSpec{layout: layout, role: "subset-apply", artifacts: artifacts, input: inputPath, selection: "subset"}, "subset-apply", "keyfile", map[string]int{
		"captured_entries": 12, "captured_present": 6, "captured_reset": 6, "file_entries": 3,
		"preview_actions_files": 2, "preview_actions_settings": 6, "preview_actions_total": 8, "directory_unchanged": 1,
		"applied_file_rows": 2, "applied_setting_rows": 6, "applied_rows": 8, "convergence_actions": 0, "convergence_unknowns": 0, "second_apply_rows_added": 0,
	})
	assertGateReceiptPaths(t, applyReceipt, layout)
	verifyReceipt := runGateActorParent(t, gateActorSpec{layout: layout, role: "subset-verify", artifacts: artifacts, input: inputPath, selection: "subset"}, "subset-verify", "keyfile", map[string]int{
		"verified_present_values": 6, "verified_reset_absent": 6, "sentinel_values": 3, "verified_file_contents": 2,
	})
	assertGateReceiptPaths(t, verifyReceipt, layout)
}

func countGateSettingsActions(preview syncengine.Preview) int {
	count := 0
	for _, target := range preview.Targets {
		for _, entry := range target.Entries {
			if entry.Key.Source == model.SourceGNOME && entry.Action != "" {
				count++
			}
		}
	}
	return count
}

func runGateLockedScenario(t *testing.T, root, fixtureRoot, artifacts string) {
	t.Helper()
	keyfileRoot := filepath.Join(root, "lock-tests")
	layout := newGateLayout(t, keyfileRoot, "locked", "keyfile", "vendor", filepath.Join(keyfileRoot, "state"))
	prepareGateSchemas(t, layout, fixtureRoot, "vendor")
	key, ok := gateSettingKey("gtk-theme")
	require.True(t, ok)
	localEntry := model.Entry{TargetID: key.TargetID, Setting: &model.SettingEntry{SchemaID: key.SchemaID, Path: key.SettingsPath, Key: key.SettingKey, State: model.SettingReset}}
	remoteEntry := model.Entry{TargetID: key.TargetID, Setting: &model.SettingEntry{SchemaID: key.SchemaID, Path: key.SettingsPath, Key: key.SettingKey, State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'locked positive value'"}}}
	targets := []model.Target{{ID: "gnome-desktop", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}}
	binding, err := syncengine.NewTargetBinding(targets[0])
	require.NoError(t, err)
	observation := model.Observation{State: model.ObservationPresent, Identity: localEntry.Identity(), Entry: &localEntry}
	plan, err := syncengine.Reconcile(syncengine.BaseView{Status: syncengine.BaseMissing}, syncengine.LocalView{Entries: []model.Entry{localEntry}, Coverage: []string{"gnome-desktop"}}, []model.Entry{remoteEntry}, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
	require.NoError(t, err)
	preview, err := syncengine.BuildPreview(plan, targets, []model.Observation{observation})
	require.NoError(t, err)
	assert.Equal(t, 1, countGatePreviewActions(preview))
	assert.Equal(t, 1, countGateSettingsActions(preview))
	postimage := syncengine.SettingPostimage{TargetID: remoteEntry.TargetID, SchemaID: remoteEntry.Setting.SchemaID, SettingsPath: remoteEntry.Setting.Path, SettingKey: remoteEntry.Setting.Key, State: remoteEntry.Setting.State, Value: remoteEntry.Setting.Value}
	input := gateApplyInput{Snapshot: model.Snapshot{Version: model.SnapshotVersion, Targets: targets, Entries: []model.Entry{remoteEntry}}, Preview: preview, Settings: []syncengine.SettingPostimage{postimage}}
	inputPath := filepath.Join(artifacts, "locked-input.json")
	writeGateJSON(t, inputPath, input)
	lockedReceipt := runGateActorParent(t, gateActorSpec{layout: layout, role: "locked", artifacts: artifacts, input: inputPath, selection: "all"}, "locked", "keyfile", map[string]int{"locked_observations": 1, "locked_writes": 0})
	assertGateReceiptPaths(t, lockedReceipt, layout)

	positive := newGateLayout(t, keyfileRoot, "positive", "keyfile", "vendor", filepath.Join(keyfileRoot, "positive-state"))
	prepareGateSchemas(t, positive, fixtureRoot, "vendor")
	positiveInput := input
	positivePath := filepath.Join(artifacts, "locked-positive-input.json")
	writeGateJSON(t, positivePath, positiveInput)
	positiveReceipt := runGateActorParent(t, gateActorSpec{layout: positive, role: "locked-positive", artifacts: artifacts, input: positivePath, selection: "all"}, "locked-positive", "keyfile", map[string]int{
		"applied_rows": 1, "applied_setting_rows": 1, "verified_present_values": 1,
	})
	assertGateReceiptPaths(t, positiveReceipt, positive)
}
