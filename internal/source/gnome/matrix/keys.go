package matrix

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lamb-systems/dottie/internal/model"
)

const MaxKeys = 256

type KeyRef struct {
	SchemaID string
	Path     string
	Key      string
}

func (key KeyRef) Validate() error {
	if !validCaptureField(key.SchemaID, model.MaxSettingSchemaIDBytes) ||
		!validCaptureField(key.Key, model.MaxSettingKeyBytes) ||
		strings.ContainsRune(key.Key, '/') {
		return errors.New("invalid GSettings reference")
	}
	if key.Path != "" && (!validCaptureField(key.Path, model.MaxRelativePathBytes) || !validCapturePath(key.Path)) {
		return errors.New("invalid GSettings reference path")
	}
	return nil
}

func validCaptureField(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validCapturePath(path string) bool {
	return strings.HasPrefix(path, "/") && strings.HasSuffix(path, "/") && !strings.Contains(path, "//")
}

func SortKeys(keys []KeyRef) {
	sort.Slice(keys, func(i, j int) bool { return keyRefLess(keys[i], keys[j]) })
}

func keyRefLess(left, right KeyRef) bool {
	if left.SchemaID != right.SchemaID {
		return left.SchemaID < right.SchemaID
	}
	if left.Path != right.Path {
		return left.Path < right.Path
	}
	return left.Key < right.Key
}
