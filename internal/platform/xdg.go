package platform

import (
	"errors"
	"os"
	"path/filepath"
)

type Paths struct {
	Home       string
	ConfigHome string
	StateHome  string
	CacheHome  string
	DataHome   string
}

func Resolve(env func(string) string) (Paths, error) {
	if env == nil {
		return Paths{}, errors.New("environment lookup is required")
	}
	home := env("HOME")
	if home == "" || !filepath.IsAbs(home) {
		return Paths{}, errors.New("HOME must be an absolute path")
	}
	home = filepath.Clean(home)
	return Paths{
		Home:       home,
		ConfigHome: xdgPath(env("XDG_CONFIG_HOME"), filepath.Join(home, ".config")),
		StateHome:  xdgPath(env("XDG_STATE_HOME"), filepath.Join(home, ".local", "state")),
		CacheHome:  xdgPath(env("XDG_CACHE_HOME"), filepath.Join(home, ".cache")),
		DataHome:   xdgPath(env("XDG_DATA_HOME"), filepath.Join(home, ".local", "share")),
	}, nil
}

func xdgPath(value, fallback string) string {
	if value != "" && filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(fallback)
}

func RealPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	clean := filepath.Clean(path)
	candidate := clean
	var remainder []string
	for {
		_, err := os.Lstat(candidate)
		if err == nil {
			resolved, evalErr := filepath.EvalSymlinks(candidate)
			if evalErr != nil {
				return "", errors.New("cannot resolve existing path ancestor")
			}
			if len(remainder) > 0 {
				resolvedInfo, statErr := os.Stat(resolved)
				if statErr != nil || !resolvedInfo.IsDir() {
					return "", errors.New("existing path ancestor is not a directory")
				}
			}
			resolved, err = filepath.Abs(resolved)
			if err != nil {
				return "", errors.New("cannot make resolved path absolute")
			}
			resolved = filepath.Clean(resolved)
			if len(remainder) == 0 {
				return resolved, nil
			}
			for i := len(remainder) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, remainder[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("cannot inspect existing path ancestor")
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", errors.New("no existing path ancestor")
		}
		remainder = append(remainder, filepath.Base(candidate))
		candidate = parent
	}
}

func (p Paths) AppConfigDir() string {
	return filepath.Join(p.ConfigHome, "dottie")
}

func (p Paths) AppStateDir() string {
	return filepath.Join(p.StateHome, "dottie")
}

func (p Paths) AppCacheDir() string {
	return filepath.Join(p.CacheHome, "dottie")
}

func (p Paths) AppDataDir() string {
	return filepath.Join(p.DataHome, "dottie")
}
