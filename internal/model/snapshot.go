package model

import (
	"errors"
	"strings"
)

type Snapshot struct {
	Version uint32   `json:"version"`
	Targets []Target `json:"targets"`
	Entries []Entry  `json:"entries"`
}

func (s Snapshot) Validate() error {
	if s.Version != SnapshotVersion {
		return errors.New("unsupported snapshot version")
	}
	targets := make(map[string]Target, len(s.Targets))
	for _, target := range s.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
		if _, exists := targets[target.ID]; exists {
			return errors.New("duplicate target identifier")
		}
		targets[target.ID] = target
	}

	keys := make(map[EntryKey]struct{}, len(s.Entries))
	for _, entry := range s.Entries {
		if err := entry.Validate(); err != nil {
			return err
		}
		key := entry.Identity()
		if _, exists := keys[key]; exists {
			return errors.New("duplicate entry identity")
		}
		keys[key] = struct{}{}
		target, exists := targets[entry.TargetID]
		if !exists {
			return errors.New("entry references an unknown target")
		}
		if entry.File != nil {
			if target.Source != SourceFiles || target.Root == nil {
				return errors.New("file entry does not match target source")
			}
			if target.Root.Kind == SelectionFile && entry.File.Path != "." {
				return errors.New("file entry escapes single-file target identity")
			}
		} else if target.Source != SourceGNOME {
			return errors.New("setting entry does not match target source")
		}
	}
	return validatePresentFileTrees(s.Entries)
}

func validatePresentFileTrees(entries []Entry) error {
	present := make(map[string]map[string]FileKind)
	for _, entry := range entries {
		if entry.File == nil || entry.File.State != FilePresent {
			continue
		}
		if present[entry.TargetID] == nil {
			present[entry.TargetID] = make(map[string]FileKind)
		}
		present[entry.TargetID][entry.File.Path] = entry.File.Kind
	}
	for _, paths := range present {
		for path := range paths {
			if path == "." {
				continue
			}
			ancestor := "."
			for _, segment := range strings.Split(path, "/") {
				if kind, exists := paths[ancestor]; exists && kind != FileDirectory {
					return errors.New("present file has a non-directory ancestor")
				}
				if ancestor == "." {
					ancestor = segment
				} else {
					ancestor += "/" + segment
				}
			}
		}
	}
	return nil
}

type ObservationState string

const (
	ObservationPresent   ObservationState = "present"
	ObservationMissing   ObservationState = "missing"
	ObservationUnknown   ObservationState = "unknown"
	ObservationUntracked ObservationState = "untracked"
)

type Observation struct {
	State    ObservationState `json:"state"`
	Identity EntryKey         `json:"identity"`
	Entry    *Entry           `json:"entry,omitempty"`
}

func (o Observation) Validate() error {
	if err := o.Identity.Validate(); err != nil {
		return err
	}
	switch o.State {
	case ObservationPresent:
		if o.Entry == nil {
			return errors.New("present observation requires an entry")
		}
		if err := o.Entry.Validate(); err != nil {
			return err
		}
		if o.Entry.Identity() != o.Identity {
			return errors.New("observation entry identity does not match")
		}
		if (o.Entry.File != nil && o.Entry.File.State != FilePresent) || (o.Entry.Setting != nil && o.Entry.Setting.State != SettingPresent) {
			return errors.New("present observation requires a present entry")
		}
	case ObservationMissing, ObservationUnknown, ObservationUntracked:
		if o.Entry != nil {
			return errors.New("non-present observation cannot carry an entry")
		}
	default:
		return errors.New("unsupported observation state")
	}
	return nil
}
