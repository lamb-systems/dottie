//go:build linux && cgo && gsettings

package gnome

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const isolatedTestMarker = "DOTTIE_GNOME_NATIVE_TEST_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(isolatedTestMarker) == "1" {
		if os.Getenv("G_DEBUG") != "fatal-warnings" {
			fmt.Fprintln(os.Stderr, "native test child requires G_DEBUG=fatal-warnings")
			os.Exit(2)
		}
		os.Exit(m.Run())
	}
	root, err := os.MkdirTemp("", "dottie-gnome-native-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, dir := range []string{"home", "tmp", "config", "data", "cache"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			_ = os.RemoveAll(root)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"TMPDIR=" + filepath.Join(root, "tmp"),
		"HOME=" + filepath.Join(root, "home"),
		"XDG_CONFIG_HOME=" + filepath.Join(root, "config"),
		"XDG_DATA_HOME=" + filepath.Join(root, "data"),
		"XDG_CACHE_HOME=" + filepath.Join(root, "cache"),
		"LANG=C.UTF-8",
		"G_DEBUG=fatal-warnings",
		isolatedTestMarker + "=1",
	}
	command := exec.Command(os.Args[0], os.Args[1:]...)
	command.Env = env
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	runErr := command.Run()
	cleanupErr := os.RemoveAll(root)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "isolated native test process failed: %v\n", runErr)
		os.Exit(1)
	}
	if cleanupErr != nil {
		fmt.Fprintf(os.Stderr, "clean isolated native test environment: %v\n", cleanupErr)
		os.Exit(2)
	}
	os.Exit(0)
}

func schemaDirectory(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "locate native test source")
	fixture := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../tests/testdata/gsettings"))
	compiled := filepath.Join(t.TempDir(), "schemas")
	require.NoError(t, os.MkdirAll(compiled, 0700))
	command := exec.Command("glib-compile-schemas", "--strict", "--targetdir", compiled, fixture)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "compile synthetic schemas: %s", output)
	return compiled
}

func openMemory(t *testing.T, schemas string, observed ...string) *Settings {
	t.Helper()
	settings, err := Open(schemas, "org.dottie.Test", "", MemoryBackend, observed)
	require.NoError(t, err)
	t.Cleanup(func() { _ = settings.Close() })
	return settings
}

func readKey(t *testing.T, settings *Settings, key string) Snapshot {
	t.Helper()
	value, err := settings.Read(key)
	require.NoError(t, err)
	return value
}

func requireNoUserValue(t *testing.T, settings *Settings, key string) Snapshot {
	t.Helper()
	value := readKey(t, settings, key)
	require.Nil(t, value.User, "key %q unexpectedly has user value", key)
	return value
}

func TestDefaultsAndOverrideFidelity(t *testing.T) {
	settings := openMemory(t, schemaDirectory(t), "enabled", "vendor-text", "items")
	initial := requireNoUserValue(t, settings, "enabled")
	require.Equal(t, "b", initial.Effective.Type)
	require.Equal(t, "false", initial.Effective.Text)
	require.Equal(t, "false", initial.Default.Text)
	vendor := requireNoUserValue(t, settings, "vendor-text")
	require.Equal(t, "'vendor-default'", vendor.Default.Text, "vendor override was not loaded: %#v", vendor)

	require.NoError(t, settings.Set("enabled", "b", "true"))
	changed := readKey(t, settings, "enabled")
	require.Equal(t, "true", changed.Effective.Text)
	require.NotNil(t, changed.User)
	require.Equal(t, "true", changed.User.Text, "set value was not preserved: %#v", changed)
	require.NoError(t, settings.Reset("enabled"))
	value := requireNoUserValue(t, settings, "enabled")
	require.Equal(t, "false", value.Effective.Text, "reset did not restore default: %#v", value)

	require.NoError(t, settings.Set("enabled", "b", "false"))
	equalDefault := readKey(t, settings, "enabled")
	require.NotNil(t, equalDefault.User)
	require.True(t, equalDefault.User.Present)
	require.Equal(t, equalDefault.Default.Text, equalDefault.User.Text)
	require.Equal(t, equalDefault.Default.Text, equalDefault.Effective.Text, "equal-to-default user override was not distinguishable: %#v", equalDefault)
	require.NoError(t, settings.Reset("enabled"))
	value = requireNoUserValue(t, settings, "enabled")
	require.Equal(t, value.Default.Text, value.Effective.Text, "reset retained equal-default override: %#v", value)

	vendorDefault := requireNoUserValue(t, settings, "vendor-text")
	require.Equal(t, "'vendor-default'", vendorDefault.Default.Text, "unexpected vendor default before equality test: %#v", vendorDefault)
	require.NoError(t, settings.Set("vendor-text", "s", "'vendor-default'"))
	equalVendorDefault := readKey(t, settings, "vendor-text")
	require.NotNil(t, equalVendorDefault.User)
	require.Equal(t, equalVendorDefault.Default.Text, equalVendorDefault.User.Text)
	require.Equal(t, equalVendorDefault.Default.Text, equalVendorDefault.Effective.Text, "equal-to-vendor-default user override was not preserved: %#v", equalVendorDefault)
	require.NoError(t, settings.Reset("vendor-text"))
	value = requireNoUserValue(t, settings, "vendor-text")
	require.Equal(t, value.Default.Text, value.Effective.Text, "reset retained vendor-default override: %#v", value)

	require.NoError(t, settings.Set("vendor-text", "s", "''"))
	emptyString := readKey(t, settings, "vendor-text")
	require.NotNil(t, emptyString.User)
	require.Equal(t, "''", emptyString.User.Text)
	require.Equal(t, "''", emptyString.Effective.Text, "empty string override was not distinguished from absence: %#v", emptyString)
	require.NoError(t, settings.Reset("vendor-text"))
	require.NoError(t, settings.Set("items", "as", "[]"))
	emptyArray := readKey(t, settings, "items")
	require.NotNil(t, emptyArray.User)
	require.Equal(t, "as", emptyArray.User.Type)
	require.Equal(t, emptyArray.Effective.Text, emptyArray.User.Text)
	require.Contains(t, emptyArray.Effective.Text, "[]", "empty array override was not distinguished from absence: %#v", emptyArray)
	equal, err := variantTextEqual("as", "[]", emptyArray.Effective.Text)
	require.NoError(t, err)
	require.True(t, equal, "empty array override changed semantic value")
	require.NoError(t, settings.Reset("items"))
	value = requireNoUserValue(t, settings, "items")
	require.Equal(t, "['alpha']", value.Default.Text, "array reset did not restore vendor default: %#v", value)
}

func TestTypedVariantTextRoundTrips(t *testing.T) {
	settings := openMemory(t, schemaDirectory(t))
	cases := []struct {
		name     string
		key      string
		typeName string
		text     string
	}{
		{name: "boolean", key: "enabled", typeName: "b", text: "true"},
		{name: "signed-minimum", key: "signed", typeName: "x", text: "-9223372036854775808"},
		{name: "signed-maximum", key: "signed", typeName: "x", text: "9223372036854775807"},
		{name: "unsigned-maximum", key: "unsigned", typeName: "t", text: "18446744073709551615"},
		{name: "utf8-string", key: "vendor-text", typeName: "s", text: "'héllo'"},
		{name: "string-array", key: "items", typeName: "as", text: "['one', 'two']"},
		{name: "tuple", key: "pair", typeName: "(is)", text: "(7, 'seven')"},
		{name: "variant-dictionary", key: "dictionary", typeName: "a{sv}", text: "{'answer': <uint64 42>, 'kind': <'fixture'>}"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.NoError(t, settings.Set(testCase.key, testCase.typeName, testCase.text))
			value := readKey(t, settings, testCase.key)
			require.Equal(t, testCase.typeName, value.Effective.Type)
			require.NotNil(t, value.User)
			require.Equal(t, testCase.typeName, value.User.Type)
			require.Equal(t, value.Effective.Text, value.User.Text, "typed text round trip changed type or user/effective consistency: %#v", value)
			equal, err := variantTextEqual(testCase.typeName, testCase.text, value.Effective.Text)
			require.NoError(t, err)
			require.True(t, equal, "typed text round trip changed semantic value: value=%#v", value)
		})
	}
}

func requireRejectedWithoutMutation(t *testing.T, settings *Settings, witnessKey string, attempt func() error) {
	t.Helper()
	before := readKey(t, settings, witnessKey)
	require.Error(t, attempt(), "invalid operation was accepted")
	after := readKey(t, settings, witnessKey)
	require.Equal(t, before, after, "rejected operation mutated %q", witnessKey)
}

func TestValidationDoesNotMutateAndSchemaSourceDoesNotFallback(t *testing.T) {
	schemas := schemaDirectory(t)
	settings := openMemory(t, schemas)
	invalid := []struct {
		name     string
		key      string
		typeName string
		text     string
	}{
		{name: "wrong-type", key: "limited", typeName: "s", text: "'wrong'"},
		{name: "bad-type-syntax", key: "limited", typeName: "(??", text: "()"},
		{name: "malformed", key: "limited", typeName: "i", text: "not-an-int"},
		{name: "trailing-junk", key: "limited", typeName: "i", text: "4 trailing"},
		{name: "range", key: "limited", typeName: "i", text: "11"},
		{name: "enum", key: "color", typeName: "s", text: "'purple'"},
		{name: "unknown-key", key: "absent", typeName: "i", text: "4"},
	}
	for _, testCase := range invalid {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			witnessKey := testCase.key
			if witnessKey == "absent" {
				witnessKey = "limited"
			}
			requireRejectedWithoutMutation(t, settings, witnessKey, func() error {
				return settings.Set(testCase.key, testCase.typeName, testCase.text)
			})
		})
	}
	requireRejectedWithoutMutation(t, settings, "limited", func() error {
		return settings.Set("limited", "i", "4\x00junk")
	})
	requireRejectedWithoutMutation(t, settings, "limited", func() error {
		return settings.Set("limited", strings.Repeat("i", maxFieldBytes+1), "3")
	})
	requireRejectedWithoutMutation(t, settings, "vendor-text", func() error {
		return settings.Set("vendor-text", "s", string([]byte{0xff}))
	})
	requireRejectedWithoutMutation(t, settings, "vendor-text", func() error {
		return settings.Set("vendor-text", "s", strings.Repeat("x", maxValueBytes+1))
	})
	requireRejectedWithoutMutation(t, settings, "limited", func() error {
		_, err := settings.Read("absent")
		return err
	})
	requireRejectedWithoutMutation(t, settings, "limited", func() error {
		return settings.Reset("absent")
	})
	rejectOpen := func(t *testing.T, schemaID, path string, observed []string) {
		t.Helper()
		requireRejectedWithoutMutation(t, settings, "limited", func() error {
			opened, err := Open(schemas, schemaID, path, MemoryBackend, observed)
			if err == nil {
				_ = opened.Close()
			}
			return err
		})
	}
	t.Run("conflicting-fixed-path", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test", "/conflicting/path/", nil)
	})
	t.Run("relocatable-path-required", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test.Relocatable", "", nil)
	})
	t.Run("relocatable-double-slash", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test.Relocatable", "/invalid//path/", nil)
	})
	t.Run("relocatable-missing-leading-slash", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test.Relocatable", "org/dottie/path/", nil)
	})
	t.Run("relocatable-missing-trailing-slash", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test.Relocatable", "/org/dottie/path", nil)
	})
	t.Run("relocatable-path-nul", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test.Relocatable", "/org/dottie/path/\x00tail/", nil)
	})
	t.Run("unknown-observed-key", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test", "", []string{"missing-key"})
	})
	t.Run("missing-schema", func(t *testing.T) {
		rejectOpen(t, "org.dottie.Test.missing", "", nil)
	})
	t.Run("missing-schema-directory", func(t *testing.T) {
		requireRejectedWithoutMutation(t, settings, "limited", func() error {
			opened, err := Open(filepath.Join(schemas, "missing"), "org.dottie.Test", "", MemoryBackend, nil)
			if err == nil {
				_ = opened.Close()
			}
			return err
		})
	})
	for _, corrupt := range []struct {
		name string
		data []byte
	}{{name: "empty", data: nil}, {name: "invalid", data: []byte("not a compiled schema")}} {
		corrupt := corrupt
		t.Run(corrupt.name+"-compiled", func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "gschemas.compiled"), corrupt.data, 0600))
			requireRejectedWithoutMutation(t, settings, "limited", func() error {
				opened, err := Open(dir, "org.dottie.Test", "", MemoryBackend, nil)
				if err == nil {
					_ = opened.Close()
				}
				return err
			})
		})
	}
	for _, path := range []string{"/org/dottie/test/profiles:/", "/"} {
		path := path
		t.Run("valid-relocatable-path-"+strings.ReplaceAll(path, "/", "root"), func(t *testing.T) {
			validRelocatable, err := Open(schemas, "org.dottie.Test.Relocatable", path, MemoryBackend, nil)
			require.NoError(t, err, "valid relocatable path %q was rejected", path)
			defer validRelocatable.Close()
			value, err := validRelocatable.Read("label")
			require.NoError(t, err, "valid relocatable schema read failed at %q", path)
			require.Equal(t, "'relocatable'", value.Effective.Text, "valid relocatable schema read failed at %q: %#v", path, value)
		})
	}
}

func TestNullBackendIsReadOnly(t *testing.T) {
	schemas := schemaDirectory(t)
	settings, err := Open(schemas, "org.dottie.Test", "", NullBackend, []string{"enabled"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = settings.Close() })
	before := readKey(t, settings, "enabled")
	require.False(t, before.Writable)
	require.Nil(t, before.User, "null backend was not read-only: %#v", before)
	require.Error(t, settings.Set("enabled", "b", "true"), "null backend accepted Set")
	require.Error(t, settings.Reset("enabled"), "null backend accepted Reset")
	after := readKey(t, settings, "enabled")
	require.Equal(t, before, after, "null backend mutation changed state")
}

func drainFully(t *testing.T, settings *Settings) map[string]int {
	t.Helper()
	seen := make(map[string]int)
	for i := 0; i < 8; i++ {
		result, err := settings.Drain()
		require.NoError(t, err)
		for _, key := range result.Keys {
			seen[key]++
		}
		if !result.MoreWork {
			return seen
		}
	}
	require.FailNow(t, "private context still had work after bounded re-drains")
	return nil
}

func TestSharedBackendPeerNotificationsAndPrivateContext(t *testing.T) {
	schemas := schemaDirectory(t)
	settings, err := openSharedForTest(schemas, "org.dottie.Test", "", []string{"vendor-text", "enabled", "items"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = settings.Close() })
	sentinel, err := newDefaultSentinel()
	require.NoError(t, err)
	defer sentinel.close()

	require.NoError(t, settings.peerSet("vendor-text", "s", "'peer-first'"))
	require.NoError(t, settings.peerSet("vendor-text", "s", "'peer-final'"))
	require.NoError(t, settings.peerSet("enabled", "b", "true"))
	require.NoError(t, settings.peerSet("items", "as", "['peer']"))
	hints := drainFully(t, settings)
	for _, key := range []string{"vendor-text", "enabled", "items"} {
		require.Equal(t, 1, hints[key], "expected one coalesced hint for distinct key %q", key)
	}
	require.False(t, sentinel.fired(), "private drain dispatched the default-context sentinel")
	value := readKey(t, settings, "vendor-text")
	require.Equal(t, "'peer-final'", value.Effective.Text)
	require.NotNil(t, value.User)
	require.Equal(t, "'peer-final'", value.User.Text, "observer did not read peer's shared-backend state: %#v", value)
	value = readKey(t, settings, "enabled")
	require.Equal(t, "true", value.Effective.Text)
	require.NotNil(t, value.User)
	require.Equal(t, "true", value.User.Text, "observer did not read peer's boolean state: %#v", value)
	value = readKey(t, settings, "items")
	require.Equal(t, "['peer']", value.Effective.Text)
	require.NotNil(t, value.User, "observer did not read peer's array state: %#v", value)
	require.NoError(t, settings.peerReset("vendor-text"))
	resetHints := drainFully(t, settings)
	require.Equal(t, 1, resetHints["vendor-text"], "peer reset did not produce a native observer hint: %#v", resetHints)
	value = requireNoUserValue(t, settings, "vendor-text")
	require.Equal(t, "'vendor-default'", value.Effective.Text, "observer did not read peer reset: %#v", value)
}

func TestIndependentMemoryHandlesAndAdmissionBounds(t *testing.T) {
	schemas := schemaDirectory(t)
	first := openMemory(t, schemas, "vendor-text")
	second := openMemory(t, schemas, "vendor-text")
	require.NoError(t, first.Set("vendor-text", "s", "'private-one'"))
	value := requireNoUserValue(t, second, "vendor-text")
	require.Equal(t, "'vendor-default'", value.Effective.Text, "independent memory handles leaked values: %#v", value)
	hints, err := second.Drain()
	require.NoError(t, err)
	require.Empty(t, hints.Keys, "independent memory handles leaked hints")
	tooMany := make([]string, maxObservedKeys+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("key-%d", i)
	}
	_, err = Open(schemas, "org.dottie.Test", "", MemoryBackend, tooMany)
	require.Error(t, err, "oversized observed-key set was accepted")
}

func TestPrivateDispatchBudgetCloseAndConcurrentLifetime(t *testing.T) {
	schemas := schemaDirectory(t)
	for i := 0; i < 20; i++ {
		settings, err := Open(schemas, "org.dottie.Test", "", MemoryBackend, nil)
		require.NoError(t, err)
		require.NoError(t, settings.Close())
	}
	settings := openMemory(t, schemas)
	require.NoError(t, settings.queueTestWork(200))
	first, err := settings.Drain()
	require.NoError(t, err)
	require.True(t, first.MoreWork, "dispatch budget exhaustion was not visible: %#v", first)
	for i := 0; i < 4; i++ {
		result, err := settings.Drain()
		require.NoError(t, err)
		if !result.MoreWork {
			break
		}
		if i == 3 {
			require.FailNow(t, "bounded re-drain did not exhaust queued test work")
		}
	}

	pending, err := openSharedForTest(schemas, "org.dottie.Test", "", []string{"enabled"})
	require.NoError(t, err)
	require.NoError(t, pending.peerSet("enabled", "b", "true"))
	require.NoError(t, pending.Close())
	require.NoError(t, pending.Close(), "double close failed")
	_, err = pending.Read("enabled")
	require.Error(t, err, "read after close succeeded")
	_, err = pending.Drain()
	require.Error(t, err, "drain after close succeeded")
	require.Error(t, pending.Set("enabled", "b", "true"), "set after close succeeded")
	require.Error(t, pending.Reset("enabled"), "reset after close succeeded")

	concurrent := openMemory(t, schemas, "enabled")
	var workers sync.WaitGroup
	ready := make(chan struct{}, 8)
	start := make(chan struct{})
	firstOperations := make(chan struct{}, 8)
	continueOperations := make(chan struct{})
	workerErrors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ready <- struct{}{}
			<-start
			for j := 0; j < 100; j++ {
				if _, err := concurrent.Read("enabled"); err != nil {
					if err.Error() != "GSettings handle is closed" {
						workerErrors <- err
					}
					return
				}
				if _, err := concurrent.Drain(); err != nil {
					if err.Error() != "GSettings handle is closed" {
						workerErrors <- err
					}
					return
				}
				if j == 0 {
					firstOperations <- struct{}{}
					<-continueOperations
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-ready
	}
	close(start)
	for i := 0; i < 8; i++ {
		<-firstOperations
	}
	close(continueOperations)
	require.NoError(t, concurrent.Close())
	workers.Wait()
	close(workerErrors)
	for err := range workerErrors {
		assert.NoError(t, err, "concurrent operation failed before close")
	}
}
