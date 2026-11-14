package config

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/lamb-systems/dottie/internal/platform"
)

const LockFileName = FileName + ".lock"

const maxRevision uint64 = math.MaxInt64

var (
	ErrConfigStale             = errors.New("configuration changed since it was read; re-run the command")
	ErrConfigRevisionExhausted = errors.New("configuration revision cannot be advanced; restore the file or remove the revision keys")
)

type Token [32]byte

type Snapshot struct {
	Config    Config
	Token     Token
	Selection DigestRevision
	Approval  DigestRevision
}

type Guard struct {
	file *os.File
}

var renameFile = os.Rename
var syncFile = func(file *os.File) error { return file.Sync() }
var syncDir = syncDirectory

func Load(paths platform.Paths) (Config, error) {
	snapshot, err := OpenSnapshot(paths)
	if err != nil {
		return Config{}, err
	}
	return snapshot.Config, nil
}

func OpenSnapshot(paths platform.Paths) (Snapshot, error) {
	data, present, err := readConfigFile(paths)
	if err != nil {
		return Snapshot{}, err
	}
	if !present {
		return snapshotOf(Default(), nil), nil
	}
	c, err := decodeConfig(data)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshotOf(c, data), nil
}

func AcquireReader(paths platform.Paths) (Snapshot, *Guard, error) {
	guard, err := lockConfigShared(paths)
	if err != nil {
		return Snapshot{}, nil, err
	}
	snapshot, err := OpenSnapshot(paths)
	if err != nil {
		guard.Release()
		return Snapshot{}, nil, err
	}
	return snapshot, guard, nil
}

func Update(paths platform.Paths, expected Token, mutate func(Config) (Config, error)) (Snapshot, error) {
	if mutate == nil {
		return Snapshot{}, errors.New("configuration update requires a mutation")
	}
	guard, err := lockConfig(paths, syscall.LOCK_EX, true)
	if err != nil {
		return Snapshot{}, err
	}
	defer guard.Release()
	if _, err := checkDestination(paths.AppConfigDir()); err != nil {
		return Snapshot{}, err
	}
	previous, err := OpenSnapshot(paths)
	if err != nil {
		return Snapshot{}, err
	}
	if previous.Token != expected {
		return Snapshot{}, ErrConfigStale
	}
	mutated, err := mutate(previous.Config)
	if err != nil {
		return Snapshot{}, err
	}
	next, err := advance(previous, mutated)
	if err != nil {
		return Snapshot{}, err
	}
	data, err := encodeConfig(next)
	if err != nil {
		return Snapshot{}, fmt.Errorf("cannot encode configuration: %w", err)
	}
	if err := writeConfigFile(paths, data); err != nil {
		return Snapshot{}, err
	}
	return snapshotOf(next, data), nil
}

func advance(previous Snapshot, mutated Config) (Config, error) {
	next := upgradeConfig(normalizeConfig(mutated))
	next.SelectionRevision = previous.Config.SelectionRevision
	next.ApprovalRevision = previous.Config.ApprovalRevision
	if err := next.Validate(); err != nil {
		return Config{}, err
	}
	var err error
	next.SelectionRevision, err = nextRevision(previous.Selection.Revision, selectionDigest(next) != previous.Selection.Digest)
	if err != nil {
		return Config{}, err
	}
	next.ApprovalRevision, err = nextRevision(previous.Approval.Revision, approvalDigest(next) != previous.Approval.Digest)
	if err != nil {
		return Config{}, err
	}
	return next, nil
}

func nextRevision(previous uint64, changed bool) (uint64, error) {
	if previous == 0 {
		return 1, nil
	}
	if !changed {
		return previous, nil
	}
	if previous >= maxRevision {
		return 0, ErrConfigRevisionExhausted
	}
	return previous + 1, nil
}

func snapshotOf(c Config, data []byte) Snapshot {
	snapshot := Snapshot{
		Config:    c,
		Selection: DigestRevision{Digest: selectionDigest(c), Revision: c.SelectionRevision},
		Approval:  DigestRevision{Digest: approvalDigest(c), Revision: c.ApprovalRevision},
	}
	if data != nil {
		snapshot.Token = Token(sha256.Sum256(data))
	}
	return snapshot
}

func decodeConfig(data []byte) (Config, error) {
	var c Config
	metadata, err := toml.Decode(string(data), &c)
	if err != nil {
		return Config{}, fmt.Errorf("cannot decode configuration: %w", err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("unknown configuration key %q", undecoded[0].String())
	}
	c = upgradeConfig(normalizeConfig(c))
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func readConfigFile(paths platform.Paths) ([]byte, bool, error) {
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	info, err := os.Stat(configPath)
	if err != nil {
		linkInfo, linkErr := os.Lstat(configPath)
		if linkErr == nil && linkInfo.Mode()&os.ModeSymlink != 0 {
			return nil, false, errors.New("configuration file is a symbolic link whose target cannot be resolved; restore the target or remove the link")
		}
		if errors.Is(err, os.ErrNotExist) && errors.Is(linkErr, os.ErrNotExist) {
			return nil, false, nil
		}
		if linkErr != nil && !errors.Is(linkErr, os.ErrNotExist) {
			return nil, false, errors.New("cannot inspect configuration file; check filesystem permissions and availability")
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, errors.New("cannot resolve configuration file; check that it exists and is accessible")
		}
		return nil, false, errors.New("cannot inspect configuration file; check filesystem permissions and availability")
	}
	if info.IsDir() {
		return nil, false, errors.New("configuration path is a directory; replace it with a regular configuration file")
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("configuration path is not a regular file; replace it with a regular configuration file")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, false, errors.New("cannot read configuration file; check filesystem permissions and availability")
	}
	return data, true, nil
}

func checkDestination(directory string) (string, error) {
	if !filepath.IsAbs(directory) {
		return "", errors.New("configuration directory must be absolute")
	}
	destination := filepath.Join(directory, FileName)
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("configuration file is a symbolic link; Dottie will not replace it; moving the file or removing the link resolves this")
		}
		if info.IsDir() {
			return "", errors.New("refusing to replace a directory at the configuration file path")
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("refusing to replace a non-regular configuration file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("cannot inspect existing configuration file")
	}
	return destination, nil
}

func writeConfigFile(paths platform.Paths, data []byte) error {
	directory := paths.AppConfigDir()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("cannot create configuration directory")
	}
	if err := secureConfigDir(directory); err != nil {
		return err
	}
	destination, err := checkDestination(directory)
	if err != nil {
		return err
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

func lockConfig(paths platform.Paths, mode int, create bool) (*Guard, error) {
	directory := paths.AppConfigDir()
	if !filepath.IsAbs(directory) {
		return nil, errors.New("configuration directory must be absolute")
	}
	if create {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, errors.New("cannot create configuration directory")
		}
		if err := secureConfigDir(directory); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(directory, LockFileName)
	flags := syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if create {
		flags |= syscall.O_CREAT | syscall.O_RDWR
	} else {
		flags |= syscall.O_RDONLY
	}
	fd, err := syscall.Open(path, flags, 0o600)
	if err != nil {
		if !create && errors.Is(err, syscall.ENOENT) {
			return &Guard{}, nil
		}
		return nil, errors.New("cannot open the configuration lock file")
	}
	file := os.NewFile(uintptr(fd), path)
	if create {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, errors.New("cannot secure the configuration lock file")
		}
	}
	if err := syscall.Flock(fd, mode); err != nil {
		_ = file.Close()
		return nil, errors.New("cannot acquire the configuration lock")
	}
	return &Guard{file: file}, nil
}

func lockConfigShared(paths platform.Paths) (*Guard, error) {
	directory := paths.AppConfigDir()
	if !filepath.IsAbs(directory) {
		return nil, errors.New("configuration directory must be absolute")
	}
	if _, err := os.Lstat(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Guard{}, nil
		}
		return nil, errors.New("cannot inspect the configuration directory")
	}
	return lockConfig(paths, syscall.LOCK_SH, true)
}

func (guard *Guard) Release() {
	if guard == nil || guard.file == nil {
		return
	}
	file := guard.file
	guard.file = nil
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func upgradeConfig(c Config) Config {
	if c.Version != 1 {
		return c
	}
	c = normalizeConfig(c)
	for index := range c.Targets {
		if c.Targets[index].Source == "gnome" && c.Targets[index].GNOMEPolicy == nil {
			c.Targets[index].GNOMEPolicy = &GNOMEPolicy{Approval: GNOMEApprovalPending}
		}
	}
	c.Version = Version
	return c
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
