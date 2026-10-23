package model

import "errors"

const (
	SnapshotVersion         uint32 = 1
	SourceVersion           uint32 = 1
	MaxTargetIDBytes               = 128
	MaxRelativePathBytes           = 4096
	MaxSettingSchemaIDBytes        = 255
	MaxSettingKeyBytes             = 255
	MaxVariantTypeBytes            = 255
	MaxVariantTextBytes            = 64 * 1024
	MaxSymlinkTargetBytes          = 4096
)

type SourceKind string

const (
	SourceFiles SourceKind = "files"
	SourceGNOME SourceKind = "gnome"
)

type RootBase string

const (
	RootHome      RootBase = "home"
	RootXDGConfig RootBase = "xdg-config"
)

type SelectionKind string

const (
	SelectionFile      SelectionKind = "file"
	SelectionDirectory SelectionKind = "directory"
)

type Target struct {
	ID            string     `json:"id"`
	Source        SourceKind `json:"source"`
	SourceVersion uint32     `json:"source_version"`
	Root          *FileRoot  `json:"root,omitempty"`
}

type FileRoot struct {
	Base RootBase      `json:"base"`
	Path string        `json:"path"`
	Kind SelectionKind `json:"kind"`
}

func (t Target) Validate() error {
	if !validText(t.ID, MaxTargetIDBytes) {
		return errors.New("invalid target identifier")
	}
	if t.SourceVersion != SourceVersion {
		return errors.New("unsupported target source version")
	}
	switch t.Source {
	case SourceFiles:
		if t.Root == nil {
			return errors.New("file target requires a root")
		}
		return t.Root.Validate()
	case SourceGNOME:
		if t.Root != nil {
			return errors.New("GNOME target cannot have a filesystem root")
		}
		return nil
	default:
		return errors.New("unsupported target source")
	}
}

func (r FileRoot) Validate() error {
	switch r.Base {
	case RootHome, RootXDGConfig:
	default:
		return errors.New("unsupported filesystem root base")
	}
	if !validRelativePath(r.Path, true) {
		return errors.New("invalid filesystem selection path")
	}
	switch r.Kind {
	case SelectionFile:
		if r.Path == "." {
			return errors.New("file selection cannot name the base directory")
		}
	case SelectionDirectory:
	default:
		return errors.New("unsupported filesystem selection kind")
	}
	return nil
}
