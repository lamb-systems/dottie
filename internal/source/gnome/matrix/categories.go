package matrix

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	Version     uint32 = 1
	ReviewedMin uint32 = 42
	ReviewedMax uint32 = 51
)

var (
	ErrUnknownCategory  = errors.New("unknown GNOME category")
	ErrInvalidSelection = errors.New("invalid GNOME category selection")
)

type CategoryKey struct {
	KeyRef
	Type  string
	Since uint32
}

type Category struct {
	ID   string
	Keys []CategoryKey
}

func (category Category) VersionFloor() uint32 {
	floor := ReviewedMin
	for _, key := range category.Keys {
		if key.Since > floor {
			floor = key.Since
		}
	}
	return floor
}

const (
	interfaceSchema = "org.gnome.desktop.interface"
	calendarSchema  = "org.gnome.desktop.calendar"
)

var categoryMatrix = []Category{
	{
		ID: "appearance",
		Keys: []CategoryKey{
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "gtk-theme"}, Type: "s"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "icon-theme"}, Type: "s"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "cursor-theme"}, Type: "s"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "color-scheme"}, Type: "s", Since: 42},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "accent-color"}, Type: "s", Since: 47},
		},
	},
	{
		ID: "fonts",
		Keys: []CategoryKey{
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "font-name"}, Type: "s"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "document-font-name"}, Type: "s"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "monospace-font-name"}, Type: "s"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "text-scaling-factor"}, Type: "d"},
		},
	},
	{
		ID: "clock",
		Keys: []CategoryKey{
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "clock-format"}, Type: "s"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "clock-show-date"}, Type: "b"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "clock-show-seconds"}, Type: "b"},
			{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "clock-show-weekday"}, Type: "b"},
			{KeyRef: KeyRef{SchemaID: calendarSchema, Key: "show-weekdate"}, Type: "b"},
		},
	},
}

var (
	matrixOnce sync.Once
	matrixErr  error
)

func Categories() ([]Category, error) {
	categories, err := validatedCategories()
	if err != nil {
		return nil, err
	}
	result := make([]Category, len(categories))
	for index := range categories {
		result[index] = Category{ID: categories[index].ID, Keys: append([]CategoryKey(nil), categories[index].Keys...)}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func LookupCategory(id string) (Category, error) {
	categories, err := validatedCategories()
	if err != nil {
		return Category{}, err
	}
	known := make([]string, 0, len(categories))
	for _, category := range categories {
		known = append(known, category.ID)
		if category.ID == id {
			return Category{ID: category.ID, Keys: append([]CategoryKey(nil), category.Keys...)}, nil
		}
	}
	sort.Strings(known)
	return Category{}, fmt.Errorf("%w %q (known categories: %s)", ErrUnknownCategory, id, strings.Join(known, ", "))
}

func SelectCategories(ids []string) ([]KeyRef, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: at least one category is required", ErrInvalidSelection)
	}
	categories, err := validatedCategories()
	if err != nil {
		return nil, err
	}
	byID := make(map[string]Category, len(categories))
	known := make([]string, 0, len(categories))
	for _, category := range categories {
		byID[category.ID] = category
		known = append(known, category.ID)
	}
	sort.Strings(known)
	seen := make(map[string]struct{}, len(ids))
	keys := make([]KeyRef, 0, len(ids)*4)
	for index, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate category %q at index %d", ErrInvalidSelection, id, index)
		}
		category, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("%w: category %q at index %d (known categories: %s)", ErrUnknownCategory, id, index, strings.Join(known, ", "))
		}
		seen[id] = struct{}{}
		for _, key := range category.Keys {
			keys = append(keys, key.KeyRef)
		}
	}
	SortKeys(keys)
	return keys, nil
}

func validatedCategories() ([]Category, error) {
	matrixOnce.Do(func() {
		matrixErr = validateCategoryMatrix(categoryMatrix)
	})
	if matrixErr != nil {
		return nil, matrixErr
	}
	return categoryMatrix, nil
}

func validateCategoryMatrix(categories []Category) error {
	if len(categories) == 0 {
		return errors.New("GNOME category matrix is empty")
	}
	ids := make(map[string]struct{}, len(categories))
	keys := make(map[KeyRef]struct{})
	total := 0
	for index, category := range categories {
		if !validCategoryID(category.ID) {
			return fmt.Errorf("category %d has an invalid identifier", index)
		}
		if _, duplicate := ids[category.ID]; duplicate {
			return fmt.Errorf("category %q is duplicated", category.ID)
		}
		ids[category.ID] = struct{}{}
		if len(category.Keys) == 0 {
			return fmt.Errorf("category %q has no keys", category.ID)
		}
		for keyIndex, key := range category.Keys {
			if err := key.KeyRef.Validate(); err != nil {
				return fmt.Errorf("category %q keys[%d]: %w", category.ID, keyIndex, err)
			}
			if !validKeyType(key.Type) {
				return fmt.Errorf("category %q keys[%d]: unsupported variant type %q", category.ID, keyIndex, key.Type)
			}
			if key.Since != 0 && (key.Since < ReviewedMin || key.Since > ReviewedMax) {
				return fmt.Errorf("category %q keys[%d]: introduction %d is outside the reviewed range %d-%d", category.ID, keyIndex, key.Since, ReviewedMin, ReviewedMax)
			}
			if _, duplicate := keys[key.KeyRef]; duplicate {
				return fmt.Errorf("category %q keys[%d]: duplicate setting reference", category.ID, keyIndex)
			}
			keys[key.KeyRef] = struct{}{}
			total++
		}
	}
	if total > MaxKeys {
		return fmt.Errorf("GNOME category matrix contains more than %d keys", MaxKeys)
	}
	return nil
}

func validCategoryID(id string) bool {
	if id == "" {
		return false
	}
	for index, character := range id {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && index > 0)) {
			return false
		}
	}
	return true
}

func validKeyType(valueType string) bool {
	switch valueType {
	case "b", "s", "d":
		return true
	default:
		return false
	}
}
