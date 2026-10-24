package files

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/dottorblaster/dottie/internal/model"
)

type Budget struct {
	MaxEntries    int
	MaxDepth      int
	MaxFileBytes  int
	MaxTotalBytes int
}

type BudgetError struct {
	Limit    string
	Path     string
	Observed int64
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf("capture budget %s exceeded at %q: observed %d", e.Limit, e.Path, e.Observed)
}

type SkipReason string

const (
	SkipSymlink     SkipReason = "symlink"
	SkipSpecialFile SkipReason = "special-file"
)

type Skip struct {
	Path   string
	Reason SkipReason
}

type Root struct {
	TargetID string
	Path     string
	Kind     model.SelectionKind
	Budget   Budget
}

type Result struct {
	Observations []model.Observation
	Skipped      []Skip
}

var statPath = func(root *os.Root, name string) (os.FileInfo, error) {
	return root.Lstat(name)
}
var listDirectory = func(root *os.Root, name string, inspected os.FileInfo) ([]os.DirEntry, error) {
	directory, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := directory.Stat()
	if statErr != nil || !opened.IsDir() || !sameIdentity(inspected, opened) {
		_ = directory.Close()
		if statErr != nil {
			return nil, statErr
		}
		return nil, errors.New("directory changed during capture")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return entries, nil
}
var readFile = func(root *os.Root, name string, file *os.File, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(file, limit))
}

func DefaultBudget() Budget {
	return Budget{MaxEntries: 20000, MaxDepth: 32, MaxFileBytes: 8 * 1024 * 1024, MaxTotalBytes: 256 * 1024 * 1024}
}

func Capture(selection Root) (Result, error) {
	if !filepath.IsAbs(selection.Path) {
		return Result{}, errors.New("capture root path must be absolute")
	}
	if selection.Kind != model.SelectionFile && selection.Kind != model.SelectionDirectory {
		return Result{}, errors.New("capture root kind is invalid")
	}
	if selection.Budget == (Budget{}) {
		selection.Budget = DefaultBudget()
	}
	if selection.Budget.MaxEntries <= 0 || selection.Budget.MaxDepth <= 0 || selection.Budget.MaxFileBytes <= 0 || selection.Budget.MaxTotalBytes <= 0 {
		return Result{}, errors.New("capture budget limits must be positive")
	}
	selection.Path = filepath.Clean(selection.Path)
	identity := model.EntryKey{TargetID: selection.TargetID, Source: model.SourceFiles, FilePath: "."}
	if err := identity.Validate(); err != nil {
		return Result{}, fmt.Errorf("invalid capture target: %w", err)
	}

	anchorPath := selection.Path
	name := "."
	if selection.Kind == model.SelectionFile {
		anchorPath = filepath.Dir(selection.Path)
		name = filepath.Base(selection.Path)
		if name == "." || name == ".." || name == string(filepath.Separator) {
			return Result{}, errors.New("invalid single-file selection name")
		}
	}
	anchoredRoot, err := os.OpenRoot(anchorPath)
	state := captureState{root: selection, handle: anchoredRoot}
	if err != nil {
		if addErr := state.addUnknown("."); addErr != nil {
			return Result{}, addErr
		}
		return state.finish()
	}
	defer anchoredRoot.Close()

	info, err := statPath(anchoredRoot, name)
	if err != nil {
		if addErr := state.addUnknown("."); addErr != nil {
			return Result{}, addErr
		}
		return state.finish()
	}
	if info.Mode()&os.ModeSymlink != 0 {
		state.result.Skipped = append(state.result.Skipped, Skip{Path: ".", Reason: SkipSymlink})
		return state.finish()
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		state.result.Skipped = append(state.result.Skipped, Skip{Path: ".", Reason: SkipSpecialFile})
		return state.finish()
	}

	switch selection.Kind {
	case model.SelectionFile:
		if !info.Mode().IsRegular() {
			if err := state.addUnknown("."); err != nil {
				return Result{}, err
			}
			return state.finish()
		}
		if err := state.consume(".", 0); err != nil {
			return Result{}, err
		}
		if err := state.captureRegular(name, ".", info); err != nil {
			return Result{}, err
		}
	case model.SelectionDirectory:
		if !info.IsDir() {
			if err := state.addUnknown("."); err != nil {
				return Result{}, err
			}
			return state.finish()
		}
		if err := state.captureDirectory(name, ".", info, 0, true); err != nil {
			return Result{}, err
		}
	}
	return state.finish()
}

type captureState struct {
	root       Root
	handle     *os.Root
	result     Result
	entries    int
	totalBytes int64
}

func (s *captureState) finish() (Result, error) {
	sort.Slice(s.result.Observations, func(i, j int) bool {
		return pathLess(s.result.Observations[i].Identity.FilePath, s.result.Observations[j].Identity.FilePath)
	})
	sort.Slice(s.result.Skipped, func(i, j int) bool {
		return pathLess(s.result.Skipped[i].Path, s.result.Skipped[j].Path)
	})
	for _, observation := range s.result.Observations {
		if err := observation.Validate(); err != nil {
			return Result{}, fmt.Errorf("invalid capture observation: %w", err)
		}
	}
	return s.result, nil
}

func pathLess(a, b string) bool {
	depthA := pathDepth(a)
	depthB := pathDepth(b)
	if depthA != depthB {
		return depthA < depthB
	}
	return a < b
}

func pathDepth(path string) int {
	if path == "." {
		return 0
	}
	return strings.Count(path, "/") + 1
}

func (s *captureState) consume(path string, depth int) error {
	if depth > s.root.Budget.MaxDepth {
		return &BudgetError{Limit: "MaxDepth", Path: path, Observed: int64(depth)}
	}
	s.entries++
	if s.entries > s.root.Budget.MaxEntries {
		return &BudgetError{Limit: "MaxEntries", Path: path, Observed: int64(s.entries)}
	}
	return nil
}

func (s *captureState) captureDirectory(name, relative string, inspected os.FileInfo, depth int, root bool) error {
	entries, err := listDirectory(s.handle, name, inspected)
	if err != nil {
		return s.addUnknown(relative)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		childName := joinRelative(name, entry.Name())
		childRelative := joinRelative(relative, entry.Name())
		childDepth := depth + 1
		if err := s.consume(childRelative, childDepth); err != nil {
			return err
		}
		childInfo, statErr := statPath(s.handle, childName)
		if statErr != nil {
			if err := s.addUnknown(childRelative); err != nil {
				return err
			}
			continue
		}
		if childInfo.Mode()&os.ModeSymlink != 0 {
			s.result.Skipped = append(s.result.Skipped, Skip{Path: childRelative, Reason: SkipSymlink})
			continue
		}
		switch {
		case childInfo.IsDir():
			if err := s.captureDirectory(childName, childRelative, childInfo, childDepth, false); err != nil {
				return err
			}
		case childInfo.Mode().IsRegular():
			if err := s.captureRegular(childName, childRelative, childInfo); err != nil {
				return err
			}
		default:
			s.result.Skipped = append(s.result.Skipped, Skip{Path: childRelative, Reason: SkipSpecialFile})
		}
	}
	if !root {
		if err := s.addPresent(relative, model.FileEntry{Path: relative, State: model.FilePresent, Kind: model.FileDirectory, Mode: uint32(inspected.Mode().Perm() & 0o777)}); err != nil {
			return err
		}
	}
	return nil
}

func (s *captureState) captureRegular(name, relative string, inspected os.FileInfo) error {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			var err error
			inspected, err = statPath(s.handle, name)
			if err != nil || !inspected.Mode().IsRegular() {
				return s.addUnknown(relative)
			}
		}
		if inspected.Size() > int64(s.root.Budget.MaxFileBytes) {
			return &BudgetError{Limit: "MaxFileBytes", Path: relative, Observed: inspected.Size()}
		}
		file, err := s.handle.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return s.addUnknown(relative)
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !sameIdentity(inspected, opened) {
			_ = file.Close()
			return s.addUnknown(relative)
		}
		if opened.Size() > int64(s.root.Budget.MaxFileBytes) {
			_ = file.Close()
			return &BudgetError{Limit: "MaxFileBytes", Path: relative, Observed: opened.Size()}
		}
		if !sameVersion(inspected, opened) {
			_ = file.Close()
			if attempt == 0 {
				continue
			}
			return s.addUnknown(relative)
		}
		if err := syscall.SetNonblock(int(file.Fd()), false); err != nil {
			_ = file.Close()
			return s.addUnknown(relative)
		}
		content, readErr := readFile(s.handle, name, file, int64(s.root.Budget.MaxFileBytes)+1)
		if readErr != nil {
			_ = file.Close()
			return s.addUnknown(relative)
		}
		if len(content) > s.root.Budget.MaxFileBytes {
			_ = file.Close()
			return &BudgetError{Limit: "MaxFileBytes", Path: relative, Observed: int64(len(content))}
		}
		fdAfter, fdErr := file.Stat()
		pathAfter, pathErr := statPath(s.handle, name)
		closeErr := file.Close()
		if fdErr != nil || pathErr != nil || closeErr != nil || !fdAfter.Mode().IsRegular() || !pathAfter.Mode().IsRegular() {
			return s.addUnknown(relative)
		}
		if !sameVersion(inspected, fdAfter) || !sameVersion(inspected, pathAfter) {
			if attempt == 0 {
				continue
			}
			return s.addUnknown(relative)
		}
		observedTotal := s.totalBytes + int64(len(content))
		if observedTotal > int64(s.root.Budget.MaxTotalBytes) {
			return &BudgetError{Limit: "MaxTotalBytes", Path: relative, Observed: observedTotal}
		}
		s.totalBytes = observedTotal
		if content == nil {
			content = []byte{}
		}
		return s.addPresent(relative, model.FileEntry{Path: relative, State: model.FilePresent, Kind: model.FileRegular, Content: content, Mode: uint32(inspected.Mode().Perm() & 0o777)})
	}
	return s.addUnknown(relative)
}

func (s *captureState) addUnknown(path string) error {
	observation := model.Observation{State: model.ObservationUnknown, Identity: model.EntryKey{TargetID: s.root.TargetID, Source: model.SourceFiles, FilePath: path}}
	if err := observation.Validate(); err != nil {
		return fmt.Errorf("invalid unknown capture observation: %w", err)
	}
	s.result.Observations = append(s.result.Observations, observation)
	return nil
}

func (s *captureState) addPresent(path string, file model.FileEntry) error {
	entry := model.Entry{TargetID: s.root.TargetID, File: &file}
	observation := model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}
	if err := observation.Validate(); err != nil {
		return fmt.Errorf("invalid present capture observation: %w", err)
	}
	s.result.Observations = append(s.result.Observations, observation)
	return nil
}

func joinRelative(parent, name string) string {
	if parent == "." {
		return name
	}
	return parent + "/" + name
}

func sameIdentity(a, b os.FileInfo) bool {
	statA, okA := a.Sys().(*syscall.Stat_t)
	statB, okB := b.Sys().(*syscall.Stat_t)
	return okA && okB && statA.Dev == statB.Dev && statA.Ino == statB.Ino
}

func sameVersion(a, b os.FileInfo) bool {
	return sameIdentity(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
