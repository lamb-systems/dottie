package publication

import (
	"math"
	"path"

	"github.com/lamb-systems/dottie/internal/model"
)

func validateSnapshotTargets(entries []SnapshotEntry, targets []model.Target) error {
	if len(targets) != 1 {
		return violation(ErrInvalidRecord, "targets", "count")
	}
	target := targets[0]
	if target.Source != model.SourceFiles || target.Root == nil || target.Validate() != nil {
		return violation(ErrInvalidRecord, "targets.target", "unsupported")
	}
	switch target.Root.Kind {
	case model.SelectionFile:
		if len(entries) != 1 || entries[0].Path != path.Base(target.Root.Path) {
			return violation(ErrInvalidRecord, "targets.root", "mismatch")
		}
	case model.SelectionDirectory:
	default:
		return violation(ErrInvalidRecord, "targets.root.kind", "unsupported")
	}
	return nil
}

func encodeSnapshotTargets(targets []model.Target) []any {
	encoded := make([]any, 0, len(targets))
	for _, target := range targets {
		value := map[string]any{
			"id":             target.ID,
			"source":         string(target.Source),
			"source_version": int64(target.SourceVersion),
		}
		if target.Root != nil {
			value["root"] = map[string]any{
				"base": string(target.Root.Base),
				"path": target.Root.Path,
				"kind": string(target.Root.Kind),
			}
		}
		encoded = append(encoded, value)
	}
	return encoded
}

func decodeSnapshotTargets(value any) ([]model.Target, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, violation(ErrInvalidRecord, "targets", "type")
	}
	targets := make([]model.Target, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, violation(ErrInvalidRecord, "targets", "type")
		}
		keys := []string{"id", "source", "source_version"}
		if _, present := object["root"]; present {
			keys = append(keys, "root")
		}
		if err := exactKeys(object, keys...); err != nil {
			return nil, err
		}
		id, ok := object["id"].(string)
		if !ok {
			return nil, violation(ErrInvalidRecord, "targets.id", "type")
		}
		source, ok := object["source"].(string)
		if !ok {
			return nil, violation(ErrInvalidRecord, "targets.source", "type")
		}
		version, ok := integer(object["source_version"])
		if !ok || version < 0 || version > math.MaxUint32 {
			return nil, violation(ErrInvalidRecord, "targets.source_version", "range")
		}
		target := model.Target{
			ID: id, Source: model.SourceKind(source), SourceVersion: uint32(version),
		}
		if value, present := object["root"]; present {
			rootObject, ok := value.(map[string]any)
			if !ok {
				return nil, violation(ErrInvalidRecord, "targets.root", "type")
			}
			if err := exactKeys(rootObject, "base", "path", "kind"); err != nil {
				return nil, err
			}
			base, ok := rootObject["base"].(string)
			if !ok {
				return nil, violation(ErrInvalidRecord, "targets.root.base", "type")
			}
			rootPath, ok := rootObject["path"].(string)
			if !ok {
				return nil, violation(ErrInvalidRecord, "targets.root.path", "type")
			}
			kind, ok := rootObject["kind"].(string)
			if !ok {
				return nil, violation(ErrInvalidRecord, "targets.root.kind", "type")
			}
			target.Root = &model.FileRoot{
				Base: model.RootBase(base), Path: rootPath, Kind: model.SelectionKind(kind),
			}
		}
		targets = append(targets, target)
	}
	return targets, nil
}
