package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/dottorblaster/dottie/internal/platform"
)

func FuzzLoad(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("config_version = 1\n"),
		[]byte("config_version = 1\n[defaults]\nmode = 'review'\n[[targets]]\nid = 'gnome'\nsource = 'gnome'\n"),
		[]byte("config_version = 1\nfuture_key = true\n"),
		[]byte("config_version = 2\n"),
		[]byte("config_version = 'one'\n"),
		[]byte("config_version = 1\n[[targets]]\nid = 'files'\nsource = 'files'\n[targets.root]\nbase = 'home'\npath = '../outside'\nkind = 'directory'\n"),
		[]byte("config_version = 1\n[[targets]]\nid = 'files'\nsource = 'files'\n[targets.root]\nbase = 'home'\npath = '.'\nkind = 'directory'\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		root := t.TempDir()
		paths := fuzzPaths(root)
		if !pathsAreWithin(root, paths) {
			t.Fatal("fuzz paths escaped the iteration temp directory")
		}
		if err := os.MkdirAll(paths.AppConfigDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(paths.AppConfigDir(), FileName)

		if err := os.WriteFile(configPath, input, 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(paths)
		if err != nil {
			return
		}

		var decoded Config
		metadata, err := toml.Decode(string(input), &decoded)
		if err != nil {
			t.Fatalf("Load accepted TOML that the oracle could not decode: %v", err)
		}
		if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
			t.Fatalf("Load accepted a discarded key: %q", undecoded[0].String())
		}

		encoded, err := encodeConfig(loaded)
		if err != nil {
			t.Fatalf("cannot re-encode accepted config: %v", err)
		}
		var roundTrip Config
		reencodedMetadata, err := toml.Decode(string(encoded), &roundTrip)
		if err != nil {
			t.Fatalf("cannot decode re-encoded config: %v", err)
		}
		if undecoded := reencodedMetadata.Undecoded(); len(undecoded) != 0 {
			t.Fatalf("re-encoded config contains a discarded key: %q", undecoded[0].String())
		}
		if err := roundTrip.Validate(); err != nil {
			t.Fatalf("re-encoded config is invalid: %v", err)
		}
		if !reflect.DeepEqual(loaded, normalizeConfig(roundTrip)) {
			t.Fatalf("re-encoding changed accepted config: before %#v after %#v", loaded, roundTrip)
		}
	})
}

func fuzzPaths(root string) platform.Paths {
	return platform.Paths{
		Home:       filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "xdg-config"),
		StateHome:  filepath.Join(root, "xdg-state"),
		CacheHome:  filepath.Join(root, "xdg-cache"),
		DataHome:   filepath.Join(root, "xdg-data"),
	}
}

func pathsAreWithin(root string, paths platform.Paths) bool {
	root = filepath.Clean(root)
	for _, path := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
			return false
		}
	}
	return true
}

func knownInvalidTOML() []string {
	return []string{
		"config_version = 1\nfuture_key = true\n",
		"config_version = 2\n",
		"config_version = 'one'\n",
		"config_version = 1\n[defaults]\nmode = 'prompt'\n",
		"config_version = 1\n[[targets]]\nid = 'files'\nsource = 'files'\n[targets.root]\nbase = 'home'\npath = '../outside'\nkind = 'directory'\n",
		"config_version = 1\n[[targets]]\nid = 'files'\nsource = 'files'\n[targets.root]\nbase = 'home'\npath = '.'\nkind = 'directory'\n",
		"config_version = 1\n[[targets]]\nid = 'gnome'\nsource = 'gnome'\n[targets.root]\nbase = 'home'\npath = 'x'\nkind = 'directory'\n",
		"config_version = 1\n[[targets]]\nid = 'files'\nsource = 'files'\n[targets.root]\nbase = 'home'\npath = 'x'\nkind = 'directory'\nexclude = ['/absolute']\n",
	}
}

func TestLoadRejectsKnownInvalid(t *testing.T) {
	for _, invalid := range knownInvalidTOML() {
		t.Run(strings.ReplaceAll(strings.TrimSpace(invalid), "\n", " "), func(t *testing.T) {
			paths := fuzzPaths(t.TempDir())
			require.NoError(t, os.MkdirAll(paths.AppConfigDir(), 0o700))
			configPath := filepath.Join(paths.AppConfigDir(), FileName)
			require.NoError(t, os.WriteFile(configPath, []byte(invalid), 0o600))

			_, err := Load(paths)
			require.Error(t, err, "known-invalid TOML was accepted: %q", invalid)
		})
	}
}
