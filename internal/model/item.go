package model

import "errors"

type FileState string

const (
	FilePresent FileState = "present"
	FileDeleted FileState = "deleted"
)

type FileKind string

const (
	FileRegular   FileKind = "regular"
	FileDirectory FileKind = "directory"
	FileSymlink   FileKind = "symlink"
)

type SettingState string

const (
	SettingPresent SettingState = "present"
	SettingReset   SettingState = "reset"
)

type Entry struct {
	TargetID string        `json:"target_id"`
	File     *FileEntry    `json:"file,omitempty"`
	Setting  *SettingEntry `json:"setting,omitempty"`
}

type FileEntry struct {
	Path       string    `json:"path"`
	State      FileState `json:"state"`
	Kind       FileKind  `json:"kind,omitempty"`
	Content    []byte    `json:"content"`
	Mode       uint32    `json:"mode,omitempty"`
	LinkTarget string    `json:"link_target,omitempty"`
}

type SettingEntry struct {
	SchemaID string        `json:"schema_id"`
	Path     string        `json:"path"`
	Key      string        `json:"key"`
	State    SettingState  `json:"state"`
	Value    *VariantValue `json:"value,omitempty"`
}

type VariantValue struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type EntryKey struct {
	TargetID     string     `json:"target_id"`
	Source       SourceKind `json:"source"`
	FilePath     string     `json:"file_path,omitempty"`
	SchemaID     string     `json:"schema_id,omitempty"`
	SettingsPath string     `json:"settings_path,omitempty"`
	SettingKey   string     `json:"setting_key,omitempty"`
}

func (e Entry) Identity() EntryKey {
	key := EntryKey{TargetID: e.TargetID}
	if e.File != nil {
		key.Source = SourceFiles
		key.FilePath = e.File.Path
	} else if e.Setting != nil {
		key.Source = SourceGNOME
		key.SchemaID = e.Setting.SchemaID
		key.SettingsPath = e.Setting.Path
		key.SettingKey = e.Setting.Key
	}
	return key
}

func (k EntryKey) Validate() error {
	if !validText(k.TargetID, MaxTargetIDBytes) {
		return errors.New("invalid entry identity target")
	}
	switch k.Source {
	case SourceFiles:
		if !validRelativePath(k.FilePath, true) || k.SchemaID != "" || k.SettingsPath != "" || k.SettingKey != "" {
			return errors.New("invalid file entry identity")
		}
	case SourceGNOME:
		if k.FilePath != "" || !validSettingLocator(k.SchemaID, k.SettingsPath, k.SettingKey) {
			return errors.New("invalid setting entry identity")
		}
	default:
		return errors.New("unsupported entry identity source")
	}
	return nil
}

func (e Entry) Validate() error {
	if !validText(e.TargetID, MaxTargetIDBytes) {
		return errors.New("invalid entry target identifier")
	}
	if (e.File == nil) == (e.Setting == nil) {
		return errors.New("entry must have exactly one source payload")
	}
	if e.File != nil {
		return e.File.Validate()
	}
	return e.Setting.Validate()
}

func (f FileEntry) Validate() error {
	if !validRelativePath(f.Path, true) {
		return errors.New("invalid file entry path")
	}
	switch f.State {
	case FileDeleted:
		if f.Kind != "" || f.Content != nil || f.Mode != 0 || f.LinkTarget != "" {
			return errors.New("deleted file entry cannot carry a payload")
		}
		return nil
	case FilePresent:
	default:
		return errors.New("unsupported file state")
	}
	if f.Mode & ^uint32(0o777) != 0 {
		return errors.New("invalid file permission bits")
	}
	switch f.Kind {
	case FileRegular:
		if f.Content == nil || f.LinkTarget != "" {
			return errors.New("invalid regular file payload")
		}
	case FileDirectory:
		if f.Content != nil || f.LinkTarget != "" {
			return errors.New("invalid directory payload")
		}
	case FileSymlink:
		if f.Content != nil || f.Mode != 0 || !validRelativeLink(f.LinkTarget) {
			return errors.New("invalid symlink payload")
		}
	default:
		return errors.New("unsupported present file kind")
	}
	return nil
}

func (s SettingEntry) Validate() error {
	if !validSettingLocator(s.SchemaID, s.Path, s.Key) {
		return errors.New("invalid setting identity")
	}
	switch s.State {
	case SettingPresent:
		if s.Value == nil || !validText(s.Value.Type, MaxVariantTypeBytes) || !validText(s.Value.Text, MaxVariantTextBytes) {
			return errors.New("invalid present setting payload")
		}
	case SettingReset:
		if s.Value != nil {
			return errors.New("reset setting cannot carry a value")
		}
	default:
		return errors.New("unsupported setting state")
	}
	return nil
}

func validSettingLocator(schemaID, path, key string) bool {
	return validText(schemaID, MaxSettingSchemaIDBytes) &&
		validGSettingsPath(path) &&
		validText(key, MaxSettingKeyBytes) &&
		!containsSlash(key)
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}
