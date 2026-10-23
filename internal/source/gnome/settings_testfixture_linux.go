//go:build linux && cgo && gsettings

package gnome

/*
#include <stdlib.h>
#include "settings.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

func openSharedForTest(schemaDir, schemaID, path string, observedKeys []string) (*Settings, error) {
	if len(observedKeys) > maxObservedKeys {
		return nil, errors.New("too many observed keys")
	}
	return openNative(schemaDir, schemaID, path, 1, joinObservedKeys(observedKeys), true)
}

func joinObservedKeys(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	joined := keys[0]
	for _, key := range keys[1:] {
		joined += "\n" + key
	}
	return joined
}

func (settings *Settings) peerSet(key, variantType, text string) error {
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
	if C.dottie_settings_peer_set(settings.ptr, cKey, cType, cText, &cError) == 0 {
		return nativeError(cError, "shared-backend peer set failed")
	}
	if cError != nil {
		C.dottie_free(unsafe.Pointer(cError))
	}
	return nil
}

func (settings *Settings) peerReset(key string) error {
	settings.mu.Lock()
	defer settings.mu.Unlock()
	if settings.closed || settings.ptr == nil {
		return errors.New("GSettings handle is closed")
	}
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	var cError *C.char
	if C.dottie_settings_peer_reset(settings.ptr, cKey, &cError) == 0 {
		return nativeError(cError, "shared-backend peer reset failed")
	}
	if cError != nil {
		C.dottie_free(unsafe.Pointer(cError))
	}
	return nil
}

func (settings *Settings) queueTestWork(count uint) error {
	settings.mu.Lock()
	defer settings.mu.Unlock()
	if settings.closed || settings.ptr == nil {
		return errors.New("GSettings handle is closed")
	}
	var cError *C.char
	if C.dottie_settings_queue_test_work(settings.ptr, C.guint(count), &cError) == 0 {
		return nativeError(cError, "queue test work failed")
	}
	if cError != nil {
		C.dottie_free(unsafe.Pointer(cError))
	}
	return nil
}

func variantTextEqual(variantType, first, second string) (bool, error) {
	if err := validateField("variant type", variantType, maxFieldBytes); err != nil {
		return false, err
	}
	if err := validateField("first variant text", first, maxValueBytes); err != nil {
		return false, err
	}
	if err := validateField("second variant text", second, maxValueBytes); err != nil {
		return false, err
	}
	cType := C.CString(variantType)
	defer C.free(unsafe.Pointer(cType))
	cFirst := C.CString(first)
	defer C.free(unsafe.Pointer(cFirst))
	cSecond := C.CString(second)
	defer C.free(unsafe.Pointer(cSecond))
	var cError *C.char
	equal := C.dottie_test_variant_text_equal(cType, cFirst, cSecond, &cError)
	if cError != nil {
		return false, nativeError(cError, "compare test GVariant text failed")
	}
	return equal != 0, nil
}

type defaultSentinel struct {
	ptr *C.DottieSentinel
}

func newDefaultSentinel() (*defaultSentinel, error) {
	ptr := C.dottie_sentinel_new()
	if ptr == nil {
		return nil, errors.New("create default-context sentinel failed")
	}
	return &defaultSentinel{ptr: ptr}, nil
}

func (sentinel *defaultSentinel) fired() bool {
	return sentinel != nil && sentinel.ptr != nil && C.dottie_sentinel_fired(sentinel.ptr) != 0
}

func (sentinel *defaultSentinel) close() {
	if sentinel != nil && sentinel.ptr != nil {
		C.dottie_sentinel_free(sentinel.ptr)
		sentinel.ptr = nil
	}
}
