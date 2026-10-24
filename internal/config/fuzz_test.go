package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
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
		require.True(t, pathsAreWithin(root, paths), "fuzz paths escaped the iteration temp directory")
		require.NoError(t, os.MkdirAll(paths.AppConfigDir(), 0o700))
		configPath := filepath.Join(paths.AppConfigDir(), FileName)

		require.NoError(t, os.WriteFile(configPath, input, 0o600))
		loaded, err := Load(paths)
		if err != nil {
			return
		}

		var decoded Config
		metadata, err := toml.Decode(string(input), &decoded)
		require.NoError(t, err, "Load accepted TOML that the oracle could not decode")
		require.Empty(t, metadata.Undecoded(), "Load accepted a discarded key")

		encoded, err := encodeConfig(loaded)
		require.NoError(t, err, "cannot re-encode accepted config")
		var roundTrip Config
		reencodedMetadata, err := toml.Decode(string(encoded), &roundTrip)
		require.NoError(t, err, "cannot decode re-encoded config")
		require.Empty(t, reencodedMetadata.Undecoded(), "re-encoded config contains a discarded key")
		require.NoError(t, roundTrip.Validate(), "re-encoded config is invalid")
		assert.Equal(t, loaded, normalizeConfig(roundTrip), "re-encoding changed accepted config")
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
