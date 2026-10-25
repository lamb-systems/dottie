package preset

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/dottorblaster/dottie/internal/config"
	"github.com/dottorblaster/dottie/internal/ignore"
	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
)

var (
	ErrUnknownPreset       = errors.New("unknown preset")
	ErrSourceNotCapturable = errors.New("preset source is not capturable")
	ErrConsentConflict     = errors.New("preset conflicts with existing consent or selection")
)

//go:embed data/*.toml
var catalogFiles embed.FS

type Preset struct {
	ID         string
	Name       string
	Source     model.SourceKind
	Risk       string
	Notes      []string
	Roots      []Root
	Categories []string
}

type Root struct {
	Base    model.RootBase
	Path    string
	Kind    model.SelectionKind
	Exclude []string
}

type Preview struct {
	Preset        Preset
	ResolvedRoots []string
	Excludes      []string
	EffectiveMode config.Mode
	Unsupported   error
}

type UnsupportedReason struct {
	Source   model.SourceKind
	Boundary string
}

func (r *UnsupportedReason) Error() string {
	return fmt.Sprintf("%s: source %q is not capturable until %s", ErrSourceNotCapturable, r.Source, r.Boundary)
}

func (r *UnsupportedReason) Is(target error) bool {
	return target == ErrSourceNotCapturable
}

type document struct {
	SchemaVersion uint32   `toml:"schema_version"`
	ID            string   `toml:"id"`
	Name          string   `toml:"name"`
	Source        string   `toml:"source"`
	Risk          string   `toml:"risk"`
	Notes         []string `toml:"notes"`
	Roots         []struct {
		Base    string   `toml:"base"`
		Path    string   `toml:"path"`
		Kind    string   `toml:"kind"`
		Exclude []string `toml:"exclude"`
	} `toml:"roots"`
	Categories []string `toml:"categories"`
}

func Catalog() ([]Preset, error) {
	presets, err := readCatalog(catalogFiles)
	if err != nil {
		return nil, err
	}
	result := make([]Preset, len(presets))
	for i := range presets {
		result[i] = clonePreset(presets[i])
	}
	return result, nil
}

func Lookup(id string) (Preset, error) {
	presets, err := Catalog()
	if err != nil {
		return Preset{}, err
	}
	known := make([]string, 0, len(presets))
	for _, preset := range presets {
		known = append(known, preset.ID)
		if preset.ID == id {
			return clonePreset(preset), nil
		}
	}
	return Preset{}, fmt.Errorf("%w %q (known ids: %s)", ErrUnknownPreset, id, strings.Join(known, ", "))
}

func BuildPreview(p Preset, paths platform.Paths) (Preview, error) {
	if err := validatePreset(p); err != nil {
		return Preview{}, err
	}
	p = clonePreset(p)
	current, err := config.Load(paths)
	if err != nil {
		return Preview{}, fmt.Errorf("preset %q key \"preview\": cannot load destination config: %w", p.ID, err)
	}
	preview := Preview{
		Preset:        p,
		EffectiveMode: (config.Target{}).ModeOrDefault(current.Defaults),
	}
	if p.Source == model.SourceGNOME {
		unsupported := &UnsupportedReason{Source: p.Source, Boundary: "DOT-G01"}
		preview.Unsupported = unsupported
		return preview, unsupported
	}
	for index, root := range p.Roots {
		var base string
		switch root.Base {
		case model.RootHome:
			base = paths.Home
		case model.RootXDGConfig:
			base = paths.ConfigHome
		}
		if base == "" || !filepath.IsAbs(base) {
			return Preview{}, fmt.Errorf("preset %q key \"roots[%d].base\": destination base must be absolute", p.ID, index)
		}
		preview.ResolvedRoots = append(preview.ResolvedRoots, filepath.Clean(filepath.Join(base, filepath.FromSlash(root.Path))))
		preview.Excludes = append(preview.Excludes, root.Exclude...)
	}
	return preview, nil
}

func Materialize(p Preset, c config.Config, paths platform.Paths) (config.Config, error) {
	if err := validatePreset(p); err != nil {
		return config.Config{}, err
	}
	if err := c.Validate(); err != nil {
		return config.Config{}, fmt.Errorf("preset %q key \"config\": destination config is invalid: %w", p.ID, err)
	}
	proposal := cloneConfig(c)
	if p.Source == model.SourceGNOME {
		return proposal, &UnsupportedReason{Source: p.Source, Boundary: "DOT-G01"}
	}
	for index, root := range p.Roots {
		existing, found := matchingRoot(proposal, root)
		if found {
			if !sameExcludes(existing.Root.Exclude, root.Exclude) {
				return config.Config{}, fmt.Errorf("%w: preset %q key \"roots[%d].exclude\" differs from existing target %q", ErrConsentConflict, p.ID, index, existing.ID)
			}
			continue
		}
		id := config.DeriveID(root.Base, root.Path)
		added := config.Target{
			ID:     id,
			Source: model.SourceFiles,
			Root: &config.Root{
				Base:    root.Base,
				Path:    root.Path,
				Kind:    root.Kind,
				Exclude: append([]string(nil), root.Exclude...),
			},
		}
		if err := config.CheckAddition(proposal, paths, added); err != nil {
			return config.Config{}, fmt.Errorf("preset %q key \"roots[%d]\": %w", p.ID, index, err)
		}
		candidate := cloneConfig(proposal)
		candidate.Targets = append(candidate.Targets, cloneTarget(added))
		if err := candidate.Validate(); err != nil {
			return config.Config{}, fmt.Errorf("preset %q key \"roots[%d]\": proposed target is invalid: %w", p.ID, index, err)
		}
		proposal = candidate
	}
	return proposal, nil
}

func readCatalog(source fs.FS) ([]Preset, error) {
	files, err := fs.Glob(source, "data/*.toml")
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate preset catalog: %w", err)
	}
	sort.Strings(files)
	presets := make([]Preset, 0, len(files))
	ids := make(map[string]struct{}, len(files))
	for _, file := range files {
		data, err := fs.ReadFile(source, file)
		if err != nil {
			return nil, fmt.Errorf("cannot read preset file %q: %w", file, err)
		}
		preset, err := decodePreset(data)
		if err != nil {
			return nil, fmt.Errorf("preset file %q: %w", file, err)
		}
		if _, exists := ids[preset.ID]; exists {
			return nil, fmt.Errorf("preset %q key \"id\": duplicate preset id", preset.ID)
		}
		ids[preset.ID] = struct{}{}
		presets = append(presets, preset)
	}
	sort.Slice(presets, func(i, j int) bool { return presets[i].ID < presets[j].ID })
	return presets, nil
}

func decodePreset(data []byte) (Preset, error) {
	var partial struct {
		ID string `toml:"id"`
	}
	_, _ = toml.Decode(string(data), &partial)
	var doc document
	metadata, err := toml.Decode(string(data), &doc)
	if err != nil {
		return Preset{}, validationError(partial.ID, tomlErrorKey(err), err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
		key := undecoded[0].String()
		return Preset{}, validationError(doc.ID, key, errors.New("unknown key"))
	}
	preset := Preset{
		ID:         doc.ID,
		Name:       doc.Name,
		Source:     model.SourceKind(doc.Source),
		Risk:       doc.Risk,
		Notes:      append([]string(nil), doc.Notes...),
		Categories: append([]string(nil), doc.Categories...),
		Roots:      make([]Root, len(doc.Roots)),
	}
	for i, root := range doc.Roots {
		preset.Roots[i] = Root{
			Base:    model.RootBase(root.Base),
			Path:    root.Path,
			Kind:    model.SelectionKind(root.Kind),
			Exclude: append([]string(nil), root.Exclude...),
		}
	}
	if doc.SchemaVersion != 1 {
		return Preset{}, validationError(preset.ID, "schema_version", fmt.Errorf("unsupported schema version %d", doc.SchemaVersion))
	}
	if err := validatePreset(preset); err != nil {
		return Preset{}, err
	}
	return preset, nil
}

func validatePreset(p Preset) error {
	if !validPresetID(p.ID) {
		return validationError(p.ID, "id", errors.New("must be a non-empty lowercase identifier using letters, digits and hyphens"))
	}
	if !validText(p.Name, 256) {
		return validationError(p.ID, "name", errors.New("must be non-empty valid UTF-8 text"))
	}
	if p.Source != model.SourceFiles && p.Source != model.SourceGNOME {
		return validationError(p.ID, "source", fmt.Errorf("unknown source %q", p.Source))
	}
	switch p.Risk {
	case "executable-config", "desktop-preferences":
	default:
		return validationError(p.ID, "risk", fmt.Errorf("unknown risk %q", p.Risk))
	}
	for index, note := range p.Notes {
		if !validText(note, 4096) {
			return validationError(p.ID, fmt.Sprintf("notes[%d]", index), errors.New("must be non-empty valid UTF-8 text"))
		}
	}
	for index, category := range p.Categories {
		if !validText(category, 256) {
			return validationError(p.ID, fmt.Sprintf("categories[%d]", index), errors.New("must be non-empty valid UTF-8 text"))
		}
	}
	switch p.Source {
	case model.SourceFiles:
		if len(p.Roots) == 0 {
			return validationError(p.ID, "roots", errors.New("files preset requires at least one root"))
		}
		if len(p.Categories) > 0 {
			return validationError(p.ID, "categories", errors.New("files presets cannot declare GNOME categories"))
		}
	case model.SourceGNOME:
		if len(p.Roots) != 0 {
			return validationError(p.ID, "roots", errors.New("GNOME preset cannot declare filesystem roots"))
		}
	}
	seenRoots := make(map[string]struct{}, len(p.Roots))
	for index, root := range p.Roots {
		key := fmt.Sprintf("roots[%d]", index)
		portable := model.FileRoot{Base: root.Base, Path: root.Path, Kind: root.Kind}
		if err := portable.Validate(); err != nil {
			return validationError(p.ID, key, err)
		}
		logical := string(root.Base) + "\x00" + root.Path + "\x00" + string(root.Kind)
		if _, duplicate := seenRoots[logical]; duplicate {
			return validationError(p.ID, key, errors.New("duplicate logical root"))
		}
		seenRoots[logical] = struct{}{}
		if _, err := ignore.Compile(root.Exclude); err != nil {
			return validationError(p.ID, key+".exclude", err)
		}
	}
	return nil
}

func validationError(id, key string, err error) error {
	if id == "" {
		id = "<unknown>"
	}
	return fmt.Errorf("preset %q key %q: %w", id, key, err)
}

func tomlErrorKey(err error) string {
	message := err.Error()
	if index := strings.Index(message, " (last key "); index >= 0 {
		remainder := message[index+len(" (last key "):]
		if end := strings.IndexByte(remainder, ')'); end >= 0 {
			return strings.Trim(remainder[:end], "\"")
		}
	}
	return "document"
}

func validPresetID(id string) bool {
	if id == "" || len(id) > model.MaxTargetIDBytes || !utf8.ValidString(id) {
		return false
	}
	for i, character := range id {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && i > 0)) {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func clonePreset(p Preset) Preset {
	p.Notes = append([]string(nil), p.Notes...)
	p.Categories = append([]string(nil), p.Categories...)
	p.Roots = append([]Root(nil), p.Roots...)
	for i := range p.Roots {
		p.Roots[i].Exclude = append([]string(nil), p.Roots[i].Exclude...)
	}
	return p
}

func cloneConfig(c config.Config) config.Config {
	c.Targets = append([]config.Target(nil), c.Targets...)
	for i := range c.Targets {
		c.Targets[i] = cloneTarget(c.Targets[i])
	}
	return c
}

func cloneTarget(target config.Target) config.Target {
	if target.Root != nil {
		root := *target.Root
		root.Exclude = append([]string(nil), root.Exclude...)
		target.Root = &root
	}
	return target
}

func matchingRoot(c config.Config, root Root) (config.Target, bool) {
	for _, target := range c.Targets {
		if target.Source == model.SourceFiles && target.Root != nil && target.Root.Base == root.Base && target.Root.Path == root.Path && target.Root.Kind == root.Kind {
			return target, true
		}
	}
	return config.Target{}, false
}

func sameExcludes(a, b []string) bool {
	left := normalizedExcludes(a)
	right := normalizedExcludes(b)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func normalizedExcludes(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}
