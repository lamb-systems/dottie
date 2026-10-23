package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/dottorblaster/dottie/internal/platform"
)

var renameFile = os.Rename
var syncFile = func(file *os.File) error { return file.Sync() }
var syncDir = syncDirectory

func Load(paths platform.Paths) (Config, error) {
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	info, err := os.Stat(configPath)
	if err != nil {
		linkInfo, linkErr := os.Lstat(configPath)
		if linkErr == nil && linkInfo.Mode()&os.ModeSymlink != 0 {
			return Config{}, errors.New("configuration file is a symbolic link whose target cannot be resolved; restore the target or remove the link")
		}
		if errors.Is(err, os.ErrNotExist) && errors.Is(linkErr, os.ErrNotExist) {
			return Default(), nil
		}
		if linkErr != nil && !errors.Is(linkErr, os.ErrNotExist) {
			return Config{}, errors.New("cannot inspect configuration file; check filesystem permissions and availability")
		}
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, errors.New("cannot resolve configuration file; check that it exists and is accessible")
		}
		return Config{}, errors.New("cannot inspect configuration file; check filesystem permissions and availability")
	}
	if info.IsDir() {
		return Config{}, errors.New("configuration path is a directory; replace it with a regular configuration file")
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("configuration path is not a regular file; replace it with a regular configuration file")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, errors.New("cannot read configuration file; check filesystem permissions and availability")
	}
	var config Config
	metadata, err := toml.Decode(string(data), &config)
	if err != nil {
		return Config{}, fmt.Errorf("cannot decode configuration: %w", err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("unknown configuration key %q", undecoded[0].String())
	}
	config = normalizeConfig(config)
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func Save(paths platform.Paths, c Config) error {
	c = normalizeConfig(c)
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := encodeConfig(c)
	if err != nil {
		return fmt.Errorf("cannot encode configuration: %w", err)
	}
	directory := paths.AppConfigDir()
	if !filepath.IsAbs(directory) {
		return errors.New("configuration directory must be absolute")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("cannot create configuration directory")
	}
	if err := secureConfigDir(directory); err != nil {
		return err
	}
	destination := filepath.Join(directory, FileName)
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("configuration file is a symbolic link; Dottie will not replace it; moving the file or removing the link resolves this")
		}
		if info.IsDir() {
			return errors.New("refusing to replace a directory at the configuration file path")
		}
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular configuration file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect existing configuration file")
	}

	file, temporary, err := createTemp(directory)
	if err != nil {
		return errors.New("cannot create temporary configuration file")
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return errors.New("cannot secure temporary configuration file")
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		_ = file.Close()
		return errors.New("cannot write temporary configuration file")
	}
	if err := syncFile(file); err != nil {
		_ = file.Close()
		return errors.New("cannot sync temporary configuration file")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close temporary configuration file")
	}
	if err := renameFile(temporary, destination); err != nil {
		return errors.New("cannot replace configuration file")
	}
	committed = true
	if err := syncDir(directory); err != nil {
		return errors.New("configuration replaced, durability uncertain")
	}
	return nil
}

func encodeConfig(c Config) ([]byte, error) {
	var buffer bytes.Buffer
	if err := toml.NewEncoder(&buffer).Encode(c); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func createTemp(directory string) (*os.File, string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := filepath.Join(directory, ".config.toml.tmp-"+hex.EncodeToString(random[:]))
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate temporary file")
}

func secureConfigDir(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return errors.New("cannot inspect configuration directory")
	}
	if !info.IsDir() {
		return errors.New("configuration path is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("configuration directory is not owned by the current user")
	}
	if info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		if err := os.Chmod(directory, 0o700); err != nil {
			return errors.New("cannot secure configuration directory")
		}
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
