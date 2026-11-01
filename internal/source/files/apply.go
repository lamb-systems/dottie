package files

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type ApplyFile interface {
	io.Reader
	io.Writer
	Stat() (os.FileInfo, error)
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

type ApplyRoot interface {
	Lstat(string) (os.FileInfo, error)
	OpenFile(string, int, os.FileMode) (ApplyFile, error)
	Rename(string, string) error
	Remove(string) error
	Close() error
}

type ApplyFileSystem interface {
	Lstat(string) (os.FileInfo, error)
	OpenRoot(string) (ApplyRoot, error)
}

type ApplyObservation struct {
	Exists bool
	Data   []byte
	Digest string
	Mode   uint32
}

type ApplyStage string

const (
	ApplyStageObserve       ApplyStage = "observe"
	ApplyStageCreateTemp    ApplyStage = "create-temp"
	ApplyStageSetMode       ApplyStage = "set-mode"
	ApplyStageWrite         ApplyStage = "write"
	ApplyStageSyncFile      ApplyStage = "sync-file"
	ApplyStageClose         ApplyStage = "close"
	ApplyStageRename        ApplyStage = "rename"
	ApplyStageSyncDirectory ApplyStage = "sync-directory"
	ApplyStageDelete        ApplyStage = "delete"
)

type ApplyError struct {
	Stage ApplyStage
	Err   error
}

func (e *ApplyError) Error() string {
	return fmt.Sprintf("filesystem apply %s: %v", e.Stage, e.Err)
}

func (e *ApplyError) Unwrap() error {
	return e.Err
}

type UnsupportedPathError struct {
	Path   string
	Reason string
}

func (e *UnsupportedPathError) Error() string {
	return fmt.Sprintf("unsupported apply path %q: %s", e.Path, e.Reason)
}

type osApplyFileSystem struct{}
type osApplyRoot struct{ root *os.Root }

type osApplyFile struct{ file *os.File }

func DefaultApplyFileSystem() ApplyFileSystem {
	return osApplyFileSystem{}
}

func (osApplyFileSystem) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func (osApplyFileSystem) OpenRoot(path string) (ApplyRoot, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return osApplyRoot{root: root}, nil
}

func (r osApplyRoot) Lstat(name string) (os.FileInfo, error) {
	return r.root.Lstat(name)
}

func (r osApplyRoot) OpenFile(name string, flag int, mode os.FileMode) (ApplyFile, error) {
	file, err := r.root.OpenFile(name, flag, mode)
	if err != nil {
		return nil, err
	}
	return osApplyFile{file: file}, nil
}

func (r osApplyRoot) Rename(oldname, newname string) error {
	return r.root.Rename(oldname, newname)
}

func (r osApplyRoot) Remove(name string) error {
	return r.root.Remove(name)
}

func (r osApplyRoot) Close() error {
	return r.root.Close()
}

func (f osApplyFile) Read(buffer []byte) (int, error)  { return f.file.Read(buffer) }
func (f osApplyFile) Write(buffer []byte) (int, error) { return f.file.Write(buffer) }
func (f osApplyFile) Stat() (os.FileInfo, error)       { return f.file.Stat() }
func (f osApplyFile) Chmod(mode os.FileMode) error     { return f.file.Chmod(mode) }
func (f osApplyFile) Sync() error                      { return f.file.Sync() }
func (f osApplyFile) Close() error                     { return f.file.Close() }

func ObserveFile(filesystem ApplyFileSystem, targetRoot, key string) (ApplyObservation, error) {
	location, err := openApplyLocation(filesystem, targetRoot, key)
	if err != nil {
		return ApplyObservation{}, err
	}
	defer location.close()
	info, err := location.root.Lstat(location.name)
	if errors.Is(err, fs.ErrNotExist) {
		return ApplyObservation{}, nil
	}
	if err != nil {
		return ApplyObservation{}, &ApplyError{Stage: ApplyStageObserve, Err: err}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ApplyObservation{}, &UnsupportedPathError{Path: key, Reason: "symbolic links are not applied"}
	}
	if !info.Mode().IsRegular() {
		return ApplyObservation{}, &UnsupportedPathError{Path: key, Reason: "only regular files are applied"}
	}
	file, err := location.root.OpenFile(location.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ApplyObservation{}, &ApplyError{Stage: ApplyStageObserve, Err: err}
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !sameIdentity(info, opened) || !sameVersion(info, opened) {
		_ = file.Close()
		if err != nil {
			return ApplyObservation{}, &ApplyError{Stage: ApplyStageObserve, Err: err}
		}
		return ApplyObservation{}, &UnsupportedPathError{Path: key, Reason: "file changed during inspection"}
	}
	data, readErr := io.ReadAll(file)
	fdAfter, fdErr := file.Stat()
	pathAfter, pathErr := location.root.Lstat(location.name)
	closeErr := file.Close()
	if readErr != nil {
		return ApplyObservation{}, &ApplyError{Stage: ApplyStageObserve, Err: readErr}
	}
	if fdErr != nil || pathErr != nil || closeErr != nil || !fdAfter.Mode().IsRegular() || !pathAfter.Mode().IsRegular() || !sameIdentity(opened, fdAfter) || !sameVersion(opened, fdAfter) || !sameIdentity(opened, pathAfter) || !sameVersion(opened, pathAfter) {
		return ApplyObservation{}, &UnsupportedPathError{Path: key, Reason: "file changed during inspection"}
	}
	digest := sha256.Sum256(data)
	return ApplyObservation{Exists: true, Data: data, Digest: hex.EncodeToString(digest[:]), Mode: uint32(opened.Mode().Perm() & 0o777)}, nil
}

func ReplaceFile(filesystem ApplyFileSystem, targetRoot, key string, data []byte, mode os.FileMode) error {
	if err := validateApplyMode(mode); err != nil {
		return &ApplyError{Stage: ApplyStageSetMode, Err: err}
	}
	location, err := openApplyLocation(filesystem, targetRoot, key)
	if err != nil {
		return err
	}
	defer location.close()
	if info, statErr := location.root.Lstat(location.name); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return &UnsupportedPathError{Path: key, Reason: "destination is not a regular file"}
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return &ApplyError{Stage: ApplyStageObserve, Err: statErr}
	}
	temporary, err := temporaryName(location.name)
	if err != nil {
		return &ApplyError{Stage: ApplyStageCreateTemp, Err: err}
	}
	file, err := location.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return &ApplyError{Stage: ApplyStageCreateTemp, Err: err}
	}
	committed := false
	defer func() {
		if !committed {
			_ = location.root.Remove(temporary)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return &ApplyError{Stage: ApplyStageSetMode, Err: err}
	}
	if err := writeAll(file, data); err != nil {
		_ = file.Close()
		return &ApplyError{Stage: ApplyStageWrite, Err: err}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return &ApplyError{Stage: ApplyStageSyncFile, Err: err}
	}
	if err := file.Close(); err != nil {
		return &ApplyError{Stage: ApplyStageClose, Err: err}
	}
	if err := location.root.Rename(temporary, location.name); err != nil {
		return &ApplyError{Stage: ApplyStageRename, Err: err}
	}
	committed = true
	directory, err := location.root.OpenFile(location.directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return &ApplyError{Stage: ApplyStageSyncDirectory, Err: err}
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return &ApplyError{Stage: ApplyStageSyncDirectory, Err: syncErr}
	}
	if closeErr != nil {
		return &ApplyError{Stage: ApplyStageSyncDirectory, Err: closeErr}
	}
	return nil
}

func DeleteFile(filesystem ApplyFileSystem, targetRoot, key string) error {
	location, err := openApplyLocation(filesystem, targetRoot, key)
	if err != nil {
		return err
	}
	defer location.close()
	info, err := location.root.Lstat(location.name)
	if err != nil {
		return &ApplyError{Stage: ApplyStageDelete, Err: err}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return &UnsupportedPathError{Path: key, Reason: "only regular files can be deleted"}
	}
	if err := location.root.Remove(location.name); err != nil {
		return &ApplyError{Stage: ApplyStageDelete, Err: err}
	}
	directory, err := location.root.OpenFile(location.directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return &ApplyError{Stage: ApplyStageSyncDirectory, Err: err}
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return &ApplyError{Stage: ApplyStageSyncDirectory, Err: syncErr}
	}
	if closeErr != nil {
		return &ApplyError{Stage: ApplyStageSyncDirectory, Err: closeErr}
	}
	return nil
}

type applyLocation struct {
	root      ApplyRoot
	name      string
	directory string
	closeRoot func() error
}

func (l applyLocation) close() {
	if l.closeRoot != nil {
		_ = l.closeRoot()
	}
}

func openApplyLocation(filesystem ApplyFileSystem, targetRoot, key string) (applyLocation, error) {
	if filesystem == nil {
		filesystem = DefaultApplyFileSystem()
	}
	if !filepath.IsAbs(targetRoot) {
		return applyLocation{}, errors.New("apply target root must be absolute")
	}
	targetRoot = filepath.Clean(targetRoot)
	if !validRelativePath(key, true) {
		return applyLocation{}, errInvalidRelativePath
	}
	rootInfo, rootErr := filesystem.Lstat(targetRoot)
	fileRoot := errors.Is(rootErr, fs.ErrNotExist) || (rootErr == nil && rootInfo.Mode().IsRegular())
	if rootErr != nil && !errors.Is(rootErr, fs.ErrNotExist) {
		return applyLocation{}, rootErr
	}
	if rootErr == nil && rootInfo.Mode()&os.ModeSymlink != 0 {
		return applyLocation{}, &UnsupportedPathError{Path: key, Reason: "target root is a symbolic link"}
	}
	var anchor, name string
	if fileRoot {
		if key != "." {
			return applyLocation{}, &UnsupportedPathError{Path: key, Reason: "single-file targets only support the root entry"}
		}
		anchor = filepath.Dir(targetRoot)
		name = filepath.Base(targetRoot)
	} else {
		if !rootInfo.IsDir() {
			return applyLocation{}, &UnsupportedPathError{Path: key, Reason: "target root is not a directory or regular file"}
		}
		if key == "." {
			return applyLocation{}, &UnsupportedPathError{Path: key, Reason: "the selected directory itself is not an apply entry"}
		}
		anchor = targetRoot
		name = key
	}
	root, err := filesystem.OpenRoot(anchor)
	if err != nil {
		return applyLocation{}, err
	}
	rootInfo, err = filesystem.Lstat(anchor)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		_ = rootClose(root)
		if err != nil {
			return applyLocation{}, err
		}
		return applyLocation{}, errors.New("apply anchor is not a real directory")
	}
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[:i], "/")
		info, statErr := root.Lstat(parent)
		if statErr != nil {
			_ = rootClose(root)
			return applyLocation{}, statErr
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = rootClose(root)
			return applyLocation{}, &UnsupportedPathError{Path: key, Reason: "parent path is not a real directory"}
		}
	}
	directory := filepath.ToSlash(filepath.Dir(name))
	if directory == "" {
		directory = "."
	}
	return applyLocation{root: root, name: name, directory: directory, closeRoot: func() error { return rootClose(root) }}, nil
}

func rootClose(root ApplyRoot) error {
	return root.Close()
}

func temporaryName(destination string) (string, error) {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	base := filepath.Base(destination)
	directory := filepath.ToSlash(filepath.Dir(destination))
	if directory == "" {
		directory = "."
	}
	name := "." + base + ".dottie-" + hex.EncodeToString(buffer) + ".tmp"
	if directory != "." {
		name = directory + "/" + name
	}
	return name, nil
}

func writeAll(file ApplyFile, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if written < 0 || written > len(data) {
			return errors.New("filesystem returned an invalid write count")
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validateApplyMode(mode os.FileMode) error {
	if mode&^(os.FileMode(0o777)) != 0 {
		return errors.New("destination mode contains unsupported bits")
	}
	return nil
}
