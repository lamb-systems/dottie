package matrix

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixtureSchema struct {
	ID   string       `xml:"id,attr"`
	Path string       `xml:"path,attr"`
	Keys []fixtureKey `xml:"key"`
}

type fixtureKey struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Enum    string `xml:"enum,attr"`
	Default string `xml:"default"`
}

type fixtureSchemalist struct {
	Schemas []fixtureSchema `xml:"schema"`
}

func TestCategoryMatrixIsBoundedAndClosed(t *testing.T) {
	categories, err := Categories()
	require.NoError(t, err)
	ids := make([]string, len(categories))
	total := 0
	seen := make(map[KeyRef]string)
	for index, category := range categories {
		ids[index] = category.ID
		require.NotEmpty(t, category.Keys)
		for _, key := range category.Keys {
			require.NoError(t, key.KeyRef.Validate())
			assert.LessOrEqual(t, key.Since, ReviewedMax)
			assert.True(t, key.Since == 0 || key.Since >= ReviewedMin, "introduction %d is below the reviewed floor", key.Since)
			previous, duplicate := seen[key.KeyRef]
			assert.False(t, duplicate, "key is owned by %q and %q", previous, category.ID)
			seen[key.KeyRef] = category.ID
			assert.NotEqual(t, "", key.Type)
			total++
		}
	}
	assert.Equal(t, []string{"appearance", "clock", "fonts"}, ids)
	assert.Equal(t, 14, total)
	assert.Equal(t, uint32(1), Version)
	assert.Equal(t, uint32(42), ReviewedMin)
	assert.Equal(t, uint32(51), ReviewedMax)
}

func TestCategoryVersionFloors(t *testing.T) {
	floors := make(map[string]uint32)
	for _, category := range mustCategories(t) {
		floors[category.ID] = category.VersionFloor()
		assert.LessOrEqual(t, category.VersionFloor(), ReviewedMax)
	}
	assert.Equal(t, map[string]uint32{"appearance": 47, "clock": 42, "fonts": 42}, floors)

	synthetic := Category{ID: "later", Keys: []CategoryKey{
		{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "one"}, Type: "b", Since: 47},
		{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "two"}, Type: "b", Since: 50},
	}}
	assert.Equal(t, uint32(50), synthetic.VersionFloor())
}

func TestCategoryMatrixGoldenSelection(t *testing.T) {
	keys, err := SelectCategories([]string{"appearance", "fonts", "clock"})
	require.NoError(t, err)
	assert.Equal(t, []KeyRef{
		{SchemaID: calendarSchema, Key: "show-weekdate"},
		{SchemaID: interfaceSchema, Key: "accent-color"},
		{SchemaID: interfaceSchema, Key: "clock-format"},
		{SchemaID: interfaceSchema, Key: "clock-show-date"},
		{SchemaID: interfaceSchema, Key: "clock-show-seconds"},
		{SchemaID: interfaceSchema, Key: "clock-show-weekday"},
		{SchemaID: interfaceSchema, Key: "color-scheme"},
		{SchemaID: interfaceSchema, Key: "cursor-theme"},
		{SchemaID: interfaceSchema, Key: "document-font-name"},
		{SchemaID: interfaceSchema, Key: "font-name"},
		{SchemaID: interfaceSchema, Key: "gtk-theme"},
		{SchemaID: interfaceSchema, Key: "icon-theme"},
		{SchemaID: interfaceSchema, Key: "monospace-font-name"},
		{SchemaID: interfaceSchema, Key: "text-scaling-factor"},
	}, keys)
}

func TestCategoryMatrixMatchesFixtureSurface(t *testing.T) {
	schemas := readFixtureSchemas(t, fixtureDirectory(t, "gsettings"))
	used := make(map[string]struct{})
	for _, category := range mustCategories(t) {
		for _, key := range category.Keys {
			used[key.SchemaID] = struct{}{}
			schema, ok := schemas[key.SchemaID]
			require.True(t, ok, "fixture schema %q is missing", key.SchemaID)
			assert.NotEmpty(t, schema.Path)
			valueType, ok := schemaKeyType(schema, key.Key)
			require.True(t, ok, "fixture schema %q has no key %q", key.SchemaID, key.Key)
			assert.Equal(t, key.Type, valueType, "fixture type for %s/%s", key.SchemaID, key.Key)
		}
	}
	for schemaID, schema := range schemas {
		if _, tracked := used[schemaID]; !tracked {
			continue
		}
		shipped := make(map[string]struct{})
		for _, category := range mustCategories(t) {
			for _, key := range category.Keys {
				if key.SchemaID == schemaID {
					shipped[key.Key] = struct{}{}
				}
			}
		}
		for _, key := range schema.Keys {
			_, ok := shipped[key.Name]
			assert.True(t, ok, "fixture schema %q has an untracked key %q", schemaID, key.Name)
		}
	}
}

func TestVendorFixtureMatchesSurfaceAndChangesDefaults(t *testing.T) {
	canonical := readFixtureSchemas(t, fixtureDirectory(t, "gsettings"))
	vendor := readFixtureSchemas(t, fixtureDirectory(t, "gsettings-vendor"))
	for _, schemaID := range []string{interfaceSchema, calendarSchema} {
		canonicalSchema, ok := canonical[schemaID]
		require.True(t, ok, "canonical fixture schema %q is required", schemaID)
		vendorSchema, ok := vendor[schemaID]
		require.True(t, ok, "vendor fixture schema %q is required", schemaID)
		assert.Equal(t, canonicalSchema.Path, vendorSchema.Path)
		assert.Len(t, vendorSchema.Keys, len(canonicalSchema.Keys))
		for _, canonicalKey := range canonicalSchema.Keys {
			var vendorKey *fixtureKey
			for index := range vendorSchema.Keys {
				if vendorSchema.Keys[index].Name == canonicalKey.Name {
					vendorKey = &vendorSchema.Keys[index]
					break
				}
			}
			require.NotNil(t, vendorKey, "vendor fixture schema %q is missing key %q", schemaID, canonicalKey.Name)
			canonicalType, canonicalFound := schemaKeyType(canonicalSchema, canonicalKey.Name)
			vendorType, vendorFound := schemaKeyType(vendorSchema, canonicalKey.Name)
			assert.True(t, canonicalFound)
			assert.True(t, vendorFound)
			assert.Equal(t, canonicalType, vendorType)
			assert.NotEqual(t, canonicalKey.Default, vendorKey.Default, "vendor fixture default must differ for %s/%s", schemaID, canonicalKey.Name)
		}
	}
	assert.Equal(t, "'Adwaita'", fixtureKeyDefault(t, canonical[interfaceSchema], "icon-theme"))
	assert.Equal(t, "'Vendor Icons'", fixtureKeyDefault(t, vendor[interfaceSchema], "icon-theme"))
	assert.Equal(t, "'default'", fixtureKeyDefault(t, canonical[interfaceSchema], "color-scheme"))
	assert.Equal(t, "'prefer-light'", fixtureKeyDefault(t, vendor[interfaceSchema], "color-scheme"))
	assert.Equal(t, "false", fixtureKeyDefault(t, canonical[calendarSchema], "show-weekdate"))
	assert.Equal(t, "true", fixtureKeyDefault(t, vendor[calendarSchema], "show-weekdate"))
}

func fixtureKeyDefault(t *testing.T, schema fixtureSchema, name string) string {
	t.Helper()
	for _, key := range schema.Keys {
		if key.Name == name {
			return key.Default
		}
	}
	require.FailNow(t, "fixture key is missing", "%s", name)
	return ""
}

func TestOlderFixtureMatchesIntroductionBounds(t *testing.T) {
	older := readFixtureSchemas(t, fixtureDirectory(t, "gsettings-older"))
	tracked := make(map[KeyRef]CategoryKey)
	for _, category := range mustCategories(t) {
		for _, key := range category.Keys {
			tracked[key.KeyRef] = key
			schema, ok := older[key.SchemaID]
			if key.Since == 0 {
				require.True(t, ok, "older fixture schema %q is missing", key.SchemaID)
				valueType, present := schemaKeyType(schema, key.Key)
				require.True(t, present, "older fixture schema %q has no key %q", key.SchemaID, key.Key)
				assert.Equal(t, key.Type, valueType, "older fixture type for %s/%s", key.SchemaID, key.Key)
				continue
			}
			if !ok {
				continue
			}
			_, present := schemaKeyType(schema, key.Key)
			assert.False(t, present, "older fixture ships %s/%s introduced in %d", key.SchemaID, key.Key, key.Since)
		}
	}
	for schemaID, schema := range older {
		for _, key := range schema.Keys {
			_, ok := tracked[KeyRef{SchemaID: schemaID, Key: key.Name}]
			assert.True(t, ok, "older fixture schema %q has an untracked key %q", schemaID, key.Name)
		}
	}
}

func TestCategoryMatrixKeepsDeviceAndCommandPreferencesLocal(t *testing.T) {
	allowed := map[string]struct{}{
		interfaceSchema: {},
		calendarSchema:  {},
	}
	for _, category := range mustCategories(t) {
		for _, key := range category.Keys {
			_, ok := allowed[key.SchemaID]
			assert.True(t, ok, "category %q ships an unreviewed schema %q", category.ID, key.SchemaID)
			assert.NotContains(t, key.Key, "binding")
			assert.NotContains(t, key.Key, "command")
			assert.NotContains(t, key.Key, "custom-")
		}
	}
}

func TestValidateCategoryMatrixRejectsMalformedMatrices(t *testing.T) {
	for _, test := range []struct {
		name   string
		matrix []Category
		want   string
	}{
		{name: "empty matrix", matrix: nil, want: "empty"},
		{name: "empty category", matrix: []Category{{ID: "appearance"}}, want: "no keys"},
		{name: "empty category identifier", matrix: categoryWith("", matrixKey("one")), want: "invalid identifier"},
		{name: "uppercase category identifier", matrix: categoryWith("Appearance", matrixKey("one")), want: "invalid identifier"},
		{name: "duplicate category identifier", matrix: []Category{{ID: "appearance", Keys: []CategoryKey{matrixKey("one")}}, {ID: "appearance", Keys: []CategoryKey{matrixKey("two")}}}, want: "duplicated"},
		{name: "duplicate reference within category", matrix: categoryWith("appearance", matrixKey("one"), matrixKey("one")), want: "duplicate setting reference"},
		{name: "duplicate reference across categories", matrix: []Category{{ID: "appearance", Keys: []CategoryKey{matrixKey("one")}}, {ID: "fonts", Keys: []CategoryKey{matrixKey("one")}}}, want: "duplicate setting reference"},
		{name: "empty schema identifier", matrix: categoryWith("appearance", CategoryKey{KeyRef: KeyRef{Key: "one"}, Type: "b"}), want: "invalid GSettings reference"},
		{name: "key containing slash", matrix: categoryWith("appearance", CategoryKey{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "one/two"}, Type: "b"}), want: "invalid GSettings reference"},
		{name: "relative path", matrix: categoryWith("appearance", CategoryKey{KeyRef: KeyRef{SchemaID: interfaceSchema, Path: "relative/", Key: "one"}, Type: "b"}), want: "reference path"},
		{name: "unsupported type", matrix: categoryWith("appearance", CategoryKey{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "one"}, Type: "u"}), want: "unsupported variant type"},
		{name: "introduction below floor", matrix: categoryWith("appearance", CategoryKey{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "one"}, Type: "b", Since: ReviewedMin - 1}), want: "outside the reviewed range"},
		{name: "introduction above reviewed surface", matrix: categoryWith("appearance", CategoryKey{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: "one"}, Type: "b", Since: ReviewedMax + 1}), want: "outside the reviewed range"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCategoryMatrix(test.matrix)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.want)
		})
	}
}

func TestValidateCategoryMatrixEnforcesKeyLimit(t *testing.T) {
	require.NoError(t, validateCategoryMatrix(syntheticMatrix(MaxKeys)))
	err := validateCategoryMatrix(syntheticMatrix(MaxKeys + 1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("more than %d keys", MaxKeys))
}

func TestSelectCategoriesResolvesSortedKeys(t *testing.T) {
	keys, err := SelectCategories([]string{"fonts", "appearance"})
	require.NoError(t, err)
	require.Len(t, keys, 9)
	assert.Equal(t, KeyRef{SchemaID: interfaceSchema, Key: "accent-color"}, keys[0])
	assert.Equal(t, KeyRef{SchemaID: interfaceSchema, Key: "text-scaling-factor"}, keys[len(keys)-1])
	reversed, err := SelectCategories([]string{"appearance", "fonts"})
	require.NoError(t, err)
	assert.Equal(t, keys, reversed)

	all, err := SelectCategories([]string{"appearance", "fonts", "clock"})
	require.NoError(t, err)
	require.Len(t, all, 14)
	for index := 1; index < len(all); index++ {
		assert.True(t, keyRefLess(all[index-1], all[index]), "selection must be ordered")
	}
}

func TestSelectCategoriesRejectsInvalidSelections(t *testing.T) {
	_, err := SelectCategories(nil)
	require.ErrorIs(t, err, ErrInvalidSelection)

	_, err = SelectCategories([]string{"appearance", "appearance"})
	require.ErrorIs(t, err, ErrInvalidSelection)
	assert.Contains(t, err.Error(), "duplicate")

	_, err = SelectCategories([]string{"appearance", "Appearance"})
	require.ErrorIs(t, err, ErrUnknownCategory)
	assert.Contains(t, err.Error(), "appearance, clock, fonts")

	_, err = SelectCategories([]string{"wallpaper"})
	require.ErrorIs(t, err, ErrUnknownCategory)
	assert.Contains(t, err.Error(), "known categories: appearance, clock, fonts")
}

func TestLookupCategoryReturnsCopy(t *testing.T) {
	category, err := LookupCategory("clock")
	require.NoError(t, err)
	require.NotEmpty(t, category.Keys)
	category.Keys[0].Key = "mutated"
	fresh, err := LookupCategory("clock")
	require.NoError(t, err)
	assert.NotEqual(t, "mutated", fresh.Keys[0].Key)
}

func mustCategories(t *testing.T) []Category {
	t.Helper()
	categories, err := Categories()
	require.NoError(t, err)
	return categories
}

func categoryWith(id string, keys ...CategoryKey) []Category {
	return []Category{{ID: id, Keys: keys}}
}

func matrixKey(name string) CategoryKey {
	return CategoryKey{KeyRef: KeyRef{SchemaID: interfaceSchema, Key: name}, Type: "b"}
}

func syntheticMatrix(count int) []Category {
	keys := make([]CategoryKey, count)
	for index := range keys {
		keys[index] = matrixKey(fmt.Sprintf("key-%d", index))
	}
	return categoryWith("synthetic", keys...)
}

func fixtureDirectory(t *testing.T, name string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "locate fixture directory")
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../../tests/testdata", name))
}

func readFixtureSchemas(t *testing.T, directory string) map[string]fixtureSchema {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(directory, "*.gschema.xml"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	schemas := make(map[string]fixtureSchema)
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		var list fixtureSchemalist
		require.NoError(t, xml.Unmarshal(data, &list), "parse fixture %s", file)
		for _, schema := range list.Schemas {
			schemas[schema.ID] = schema
		}
	}
	return schemas
}

func schemaKeyType(schema fixtureSchema, name string) (string, bool) {
	for _, key := range schema.Keys {
		if key.Name != name {
			continue
		}
		if key.Enum != "" {
			return "s", true
		}
		return key.Type, true
	}
	return "", false
}
