package platform

import (
	"os"
	"path/filepath"
	"testing"
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
				if err == nil {
					t.Fatal("Resolve succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Resolve() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestAppDirectories(t *testing.T) {
	p := Paths{ConfigHome: "/config", StateHome: "/state", CacheHome: "/cache", DataHome: "/data"}
	if p.AppConfigDir() != "/config/dottie" || p.AppStateDir() != "/state/dottie" || p.AppCacheDir() != "/cache/dottie" || p.AppDataDir() != "/data/dottie" {
		t.Fatalf("unexpected app directories: %#v", p)
	}
}

func TestRealPathLongestExistingAncestor(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := RealPath(filepath.Join(link, "not-yet", "child"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(real, "not-yet", "child")
	if got != want {
		t.Fatalf("RealPath() = %q, want %q", got, want)
	}
}

func TestRealPathFailsClosed(t *testing.T) {
	root := t.TempDir()
	broken := filepath.Join(root, "broken")
	if err := os.Symlink(filepath.Join(root, "missing"), broken); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(broken, "tail"), filepath.Join(root, "regular", "tail")} {
		if path == filepath.Join(root, "regular", "tail") {
			if err := os.WriteFile(filepath.Join(root, "regular"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := RealPath(path); err == nil {
			t.Errorf("RealPath(%q) succeeded", path)
		}
	}
	if _, err := RealPath("relative"); err == nil {
		t.Fatal("relative path succeeded")
	}
}

func TestRealPathSymlinkedXDGBase(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	actual := filepath.Join(root, "actual-config")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".config")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(func(key string) string {
		if key == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := RealPath(filepath.Join(resolved.ConfigHome, "dottie"))
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(actual, "dottie") {
		t.Fatalf("RealPath() = %q", got)
	}
}
