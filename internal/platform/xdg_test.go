package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	tests := []struct {
		name string
		env  map[string]string
		want Paths
		bad  bool
	}{
		{name: "defaults", env: map[string]string{"HOME": home}, want: Paths{Home: home, ConfigHome: filepath.Join(home, ".config"), StateHome: filepath.Join(home, ".local", "state"), CacheHome: filepath.Join(home, ".cache"), DataHome: filepath.Join(home, ".local", "share")}},
		{name: "empty and relative XDG values ignored", env: map[string]string{"HOME": home, "XDG_CONFIG_HOME": "", "XDG_STATE_HOME": "relative", "XDG_CACHE_HOME": "cache", "XDG_DATA_HOME": "data/"}, want: Paths{Home: home, ConfigHome: filepath.Join(home, ".config"), StateHome: filepath.Join(home, ".local", "state"), CacheHome: filepath.Join(home, ".cache"), DataHome: filepath.Join(home, ".local", "share")}},
		{name: "absolute relocated values", env: map[string]string{"HOME": home, "XDG_CONFIG_HOME": "/tmp/config/../config/", "XDG_STATE_HOME": "/tmp/state", "XDG_CACHE_HOME": "/tmp/cache", "XDG_DATA_HOME": "/tmp/data"}, want: Paths{Home: home, ConfigHome: "/tmp/config", StateHome: "/tmp/state", CacheHome: "/tmp/cache", DataHome: "/tmp/data"}},
		{name: "missing home", env: map[string]string{}, bad: true},
		{name: "relative home", env: map[string]string{"HOME": "relative"}, bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(func(key string) string { return tt.env[key] })
			if tt.bad {
				require.Error(t, err, "Resolve succeeded")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "Resolve()")
		})
	}
}

func TestAppDirectories(t *testing.T) {
	p := Paths{ConfigHome: "/config", StateHome: "/state", CacheHome: "/cache", DataHome: "/data"}
	assert.Equal(t, "/config/dottie", p.AppConfigDir(), "AppConfigDir")
	assert.Equal(t, "/state/dottie", p.AppStateDir(), "AppStateDir")
	assert.Equal(t, "/cache/dottie", p.AppCacheDir(), "AppCacheDir")
	assert.Equal(t, "/data/dottie", p.AppDataDir(), "AppDataDir")
}

func TestRealPathLongestExistingAncestor(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0o700))
	link := filepath.Join(root, "linked")
	require.NoError(t, os.Symlink(real, link))

	got, err := RealPath(filepath.Join(link, "not-yet", "child"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(real, "not-yet", "child"), got, "RealPath()")
}

func TestRealPathFailsClosed(t *testing.T) {
	root := t.TempDir()
	broken := filepath.Join(root, "broken")
	require.NoError(t, os.Symlink(filepath.Join(root, "missing"), broken))
	for _, path := range []string{filepath.Join(broken, "tail"), filepath.Join(root, "regular", "tail")} {
		if path == filepath.Join(root, "regular", "tail") {
			require.NoError(t, os.WriteFile(filepath.Join(root, "regular"), []byte("x"), 0o600))
		}
		_, err := RealPath(path)
		assert.Error(t, err, "RealPath(%q) succeeded", path)
	}
	_, err := RealPath("relative")
	assert.Error(t, err, "relative path succeeded")
}

func TestRealPathSymlinkedXDGBase(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	actual := filepath.Join(root, "actual-config")
	require.NoError(t, os.MkdirAll(home, 0o700))
	require.NoError(t, os.Mkdir(actual, 0o700))
	link := filepath.Join(home, ".config")
	require.NoError(t, os.Symlink(actual, link))

	resolved, err := Resolve(func(key string) string {
		if key == "HOME" {
			return home
		}
		return ""
	})
	require.NoError(t, err)

	got, err := RealPath(filepath.Join(resolved.ConfigHome, "dottie"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(actual, "dottie"), got, "RealPath()")
}
