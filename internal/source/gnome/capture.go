//go:build linux && cgo && gsettings

package gnome

import (
	"context"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
)

type KeyRef = matrix.KeyRef

type CaptureRequest struct {
	TargetID string
	Keys     []KeyRef
}

type CaptureReason string

const (
	CaptureMissingSchema CaptureReason = "missing-schema"
	CaptureMissingKey    CaptureReason = "missing-key"
	CaptureNotWritable   CaptureReason = "not-writable"
	CaptureReadFailed    CaptureReason = "read-failed"
	CaptureInvalidRef    CaptureReason = "invalid-reference"
)

type CaptureError struct {
	Key    KeyRef
	Reason CaptureReason
}

type CaptureResult struct {
	Entries []model.Entry
	Unknown []KeyRef
	Errors  []CaptureError
}

var openSettings = OpenDefault

func Capture(ctx context.Context, request CaptureRequest) (CaptureResult, error) {
	if err := ctx.Err(); err != nil {
		return CaptureResult{}, err
	}
	if err := validateCaptureRequest(request); err != nil {
		return CaptureResult{}, err
	}
	keys := append([]KeyRef(nil), request.Keys...)
	matrix.SortKeys(keys)
	result := CaptureResult{}
	for start := 0; start < len(keys); {
		if err := ctx.Err(); err != nil {
			return CaptureResult{}, err
		}
		end := start + 1
		for end < len(keys) && keys[end].SchemaID == keys[start].SchemaID && keys[end].Path == keys[start].Path {
			end++
		}
		settings, err := openSettings(keys[start].SchemaID, keys[start].Path)
		if err != nil {
			if settings != nil {
				_ = settings.Close()
			}
			if errors.Is(err, ErrSchemaNotFound) {
				for _, key := range keys[start:end] {
					addUnknown(&result, key, CaptureMissingSchema)
				}
				start = end
				continue
			}
			return CaptureResult{}, err
		}
		if settings == nil {
			return CaptureResult{}, errors.New("open GSettings returned no handle")
		}
		for _, key := range keys[start:end] {
			if err := ctx.Err(); err != nil {
				_ = settings.Close()
				return CaptureResult{}, err
			}
			user, readErr := settings.ReadUser(key.Key)
			if err := ctx.Err(); err != nil {
				_ = settings.Close()
				return CaptureResult{}, err
			}
			if errors.Is(readErr, ErrKeyNotFound) {
				addUnknown(&result, key, CaptureMissingKey)
				continue
			}
			if readErr != nil {
				addUnknown(&result, key, CaptureReadFailed)
				continue
			}
			if !user.Writable {
				addUnknown(&result, key, CaptureNotWritable)
				continue
			}
			setting := &model.SettingEntry{
				SchemaID: key.SchemaID,
				Path:     settings.Path(),
				Key:      key.Key,
			}
			if user.Present {
				setting.State = model.SettingPresent
				setting.Value = &model.VariantValue{Type: user.Type, Text: user.Text}
			} else {
				setting.State = model.SettingReset
			}
			entry := model.Entry{TargetID: request.TargetID, Setting: setting}
			if err := entry.Validate(); err != nil {
				_ = settings.Close()
				return CaptureResult{}, fmt.Errorf("captured GSettings entry is invalid: %w", err)
			}
			if err := entry.Identity().Validate(); err != nil {
				_ = settings.Close()
				return CaptureResult{}, fmt.Errorf("captured GSettings entry identity is invalid: %w", err)
			}
			result.Entries = append(result.Entries, entry)
		}
		if err := settings.Close(); err != nil {
			return CaptureResult{}, fmt.Errorf("close GSettings handle: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return CaptureResult{}, err
		}
		start = end
	}
	return result, nil
}

func validateCaptureRequest(request CaptureRequest) error {
	if !validCaptureField(request.TargetID, model.MaxTargetIDBytes) {
		return errors.New("invalid capture target identifier")
	}
	target := model.Target{ID: request.TargetID, Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	if err := target.Validate(); err != nil {
		return fmt.Errorf("invalid capture target: %w", err)
	}
	if len(request.Keys) > matrix.MaxKeys {
		return fmt.Errorf("capture contains more than %d selected keys", matrix.MaxKeys)
	}
	seen := make(map[KeyRef]struct{}, len(request.Keys))
	for index, key := range request.Keys {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("invalid capture reference at index %d", index)
		}
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate capture reference at index %d", index)
		}
		seen[key] = struct{}{}
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

func addUnknown(result *CaptureResult, key KeyRef, reason CaptureReason) {
	result.Unknown = append(result.Unknown, key)
	result.Errors = append(result.Errors, CaptureError{Key: key, Reason: reason})
}
