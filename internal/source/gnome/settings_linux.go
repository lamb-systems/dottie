//go:build linux && cgo && gsettings

package gnome

/*
#cgo pkg-config: gio-2.0
#include <stdlib.h>
#include "settings.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"
)

const (
	maxFieldBytes   = 4096
	maxValueBytes   = 65536
	maxObservedKeys = 64
)

type Backend uint8

const (
	MemoryBackend Backend = iota + 1
	NullBackend
)

type Value struct {
	Type    string
	Text    string
	Present bool
}

type Snapshot struct {
	Effective Value
	Default   Value
	User      *Value
	Writable  bool
}

type DrainResult struct {
	Keys     []string
	MoreWork bool
}

type Settings struct {
	mu     sync.Mutex
	ptr    *C.DottieSettings
	closed bool
}

func Open(schemaDir, schemaID, path string, backend Backend, observedKeys []string) (*Settings, error) {
	if err := validateField("schema directory", schemaDir, maxFieldBytes); err != nil {
		return nil, err
	}
	if err := validateField("schema id", schemaID, maxFieldBytes); err != nil {
		return nil, err
	}
	if err := validateField("schema path", path, maxFieldBytes); err != nil {
		return nil, err
	}
	if backend != MemoryBackend && backend != NullBackend {
		return nil, errors.New("backend must be explicitly memory or null")
	}
	if len(observedKeys) > maxObservedKeys {
		return nil, fmt.Errorf("at most %d observed keys are allowed", maxObservedKeys)
	}
	seen := make(map[string]struct{}, len(observedKeys))
	for _, key := range observedKeys {
		if err := validateField("observed key", key, maxFieldBytes); err != nil {
			return nil, err
		}
		if strings.ContainsRune(key, '\n') {
			return nil, errors.New("observed key contains a line separator")
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate observed key: %s", key)
		}
		seen[key] = struct{}{}
	}
	var backendKind C.int
	switch backend {
	case MemoryBackend:
		backendKind = 1
	case NullBackend:
		backendKind = 2
	}
	return openNative(schemaDir, schemaID, path, backendKind, strings.Join(observedKeys, "\n"), false)
}

func validateField(name, value string, maximum int) error {
	if len(value) > maximum || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s is invalid or exceeds %d bytes", name, maximum)
	}
	return nil
}

func openNative(schemaDir, schemaID, path string, backendKind C.int, observed string, makePeer bool) (*Settings, error) {
	cSchemaDir := C.CString(schemaDir)
	defer C.free(unsafe.Pointer(cSchemaDir))
	cSchemaID := C.CString(schemaID)
	defer C.free(unsafe.Pointer(cSchemaID))
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cObserved := C.CString(observed)
	defer C.free(unsafe.Pointer(cObserved))
	var cError *C.char
	ptr := C.dottie_settings_open(cSchemaDir, cSchemaID, cPath, backendKind, cObserved, cbool(makePeer), &cError)
	if ptr == nil {
		return nil, nativeError(cError, "open GSettings handle failed")
	}
	if cError != nil {
		C.dottie_free(unsafe.Pointer(cError))
	}
	return &Settings{ptr: ptr}, nil
}

func cbool(value bool) C.gboolean {
	if value {
		return 1
	}
	return 0
}

func nativeError(message *C.char, fallback string) error {
	if message == nil {
		return errors.New(fallback)
	}
	text := C.GoString(message)
	C.dottie_free(unsafe.Pointer(message))
	return errors.New(text)
}

func (settings *Settings) Read(key string) (Snapshot, error) {
	if err := validateField("key", key, maxFieldBytes); err != nil {
		return Snapshot{}, err
	}
	settings.mu.Lock()
	defer settings.mu.Unlock()
	if settings.closed || settings.ptr == nil {
		return Snapshot{}, errors.New("GSettings handle is closed")
	}
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	var cError *C.char
	readValue := C.dottie_settings_read(settings.ptr, cKey, &cError)
	if readValue == nil {
		return Snapshot{}, nativeError(cError, "read GSettings value failed")
	}
	defer C.dottie_read_free(readValue)
	result := Snapshot{
		Effective: Value{Type: C.GoString(readValue.effective_type), Text: C.GoString(readValue.effective_text), Present: true},
		Default:   Value{Type: C.GoString(readValue.default_type), Text: C.GoString(readValue.default_text), Present: true},
		Writable:  readValue.writable != 0,
	}
	if readValue.user_present != 0 {
		result.User = &Value{Type: C.GoString(readValue.user_type), Text: C.GoString(readValue.user_text), Present: true}
	}
	return result, nil
}

func (settings *Settings) Set(key, variantType, text string) error {
	if err := validateField("key", key, maxFieldBytes); err != nil {
		return err
	}
	if err := validateField("variant type", variantType, maxFieldBytes); err != nil {
		return err
	}
	if err := validateField("variant text", text, maxValueBytes); err != nil {
		return err
	}
	settings.mu.Lock()
	defer settings.mu.Unlock()
	if settings.closed || settings.ptr == nil {
		return errors.New("GSettings handle is closed")
	}
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	cType := C.CString(variantType)
	defer C.free(unsafe.Pointer(cType))
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))
	var cError *C.char
	if C.dottie_settings_set(settings.ptr, cKey, cType, cText, &cError) == 0 {
		return nativeError(cError, "set GSettings value failed")
	}
	if cError != nil {
		C.dottie_free(unsafe.Pointer(cError))
	}
	return nil
}

func (settings *Settings) Reset(key string) error {
	if err := validateField("key", key, maxFieldBytes); err != nil {
		return err
	}
	settings.mu.Lock()
	defer settings.mu.Unlock()
	if settings.closed || settings.ptr == nil {
		return errors.New("GSettings handle is closed")
	}
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	var cError *C.char
	if C.dottie_settings_reset(settings.ptr, cKey, &cError) == 0 {
		return nativeError(cError, "reset GSettings value failed")
	}
	if cError != nil {
		C.dottie_free(unsafe.Pointer(cError))
	}
	return nil
}

func (settings *Settings) Drain() (DrainResult, error) {
	settings.mu.Lock()
	defer settings.mu.Unlock()
	if settings.closed || settings.ptr == nil {
		return DrainResult{}, errors.New("GSettings handle is closed")
	}
	var more C.gboolean
	var cError *C.char
	text := C.dottie_settings_drain(settings.ptr, &more, &cError)
	if text == nil {
		return DrainResult{}, nativeError(cError, "drain GSettings notifications failed")
	}
	defer C.dottie_free(unsafe.Pointer(text))
	result := DrainResult{MoreWork: more != 0}
	if value := C.GoString(text); value != "" {
		result.Keys = strings.Split(value, "\n")
	}
	if cError != nil {
		C.dottie_free(unsafe.Pointer(cError))
	}
	return result, nil
}

func (settings *Settings) Close() error {
	settings.mu.Lock()
	defer settings.mu.Unlock()
	if settings.closed {
		return nil
	}
	if settings.ptr != nil {
		C.dottie_settings_close(settings.ptr)
		settings.ptr = nil
	}
	settings.closed = true
	return nil
}
