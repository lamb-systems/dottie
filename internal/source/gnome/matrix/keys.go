package matrix

import (
	"crypto/sha256"
	"encoding/binary"
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

func KeySetDigest(keys []KeyRef) ([32]byte, error) {
	if len(keys) == 0 || len(keys) > MaxKeys {
		return [32]byte{}, errors.New("invalid GSettings key set size")
	}
	canonical := append([]KeyRef(nil), keys...)
	for _, key := range canonical {
		if err := key.Validate(); err != nil {
			return [32]byte{}, err
		}
	}
	SortKeys(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return [32]byte{}, errors.New("duplicate GSettings reference")
		}
	}
	encoded := []byte("dottie/v1/gnome-key-set\x00")
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(canonical)))
	encoded = append(encoded, count[:]...)
	for _, key := range canonical {
		for _, field := range []string{key.SchemaID, key.Path, key.Key} {
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(len(field)))
			encoded = append(encoded, length[:]...)
			encoded = append(encoded, field...)
		}
	}
	return sha256.Sum256(encoded), nil
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
