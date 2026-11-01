package platform

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/vault"
)

type fakeKeyringBackend struct {
	items map[string][]byte
	err   error
}

func (f *fakeKeyringBackend) Save(_ context.Context, name string, payload []byte) error {
	if f.err != nil {
		return f.err
	}
	f.items[name] = append([]byte(nil), payload...)
	return nil
}

func (f *fakeKeyringBackend) Load(_ context.Context, name string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	payload, ok := f.items[name]
	if !ok {
		return nil, ErrKeyringItemNotFound
	}
	return append([]byte(nil), payload...), nil
}

func (f *fakeKeyringBackend) Delete(_ context.Context, name string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.items, name)
	return nil
}

func TestKeyringSaveReplacesExistingSameNamedItem(t *testing.T) {
	backend := &fakeKeyringBackend{items: map[string][]byte{"client-did": []byte("old")}}
	keyring, err := NewKeyringWithBackend(backend)
	require.NoError(t, err)
	require.NoError(t, keyring.Save(context.Background(), "client-did", []byte("new")))
	require.Len(t, backend.items, 1, "save did not replace the matching item: %#v", backend.items)
	require.Equal(t, "new", string(backend.items["client-did"]), "save did not replace the matching item: %#v", backend.items)
	loaded, err := keyring.Load(context.Background(), "client-did")
	require.NoError(t, err, "load = %q, %v", loaded, err)
	require.Equal(t, "new", string(loaded), "load = %q, %v", loaded, err)
	require.NoError(t, keyring.Delete(context.Background(), "client-did"))
	err = keyring.Delete(context.Background(), "client-did")
	require.NoError(t, err, "delete must be idempotent: %v", err)
}

func TestDeviceKeysUseOneNamedKeyringItem(t *testing.T) {
	backend := &fakeKeyringBackend{items: map[string][]byte{}}
	keyring, err := NewKeyringWithBackend(backend)
	require.NoError(t, err)
	vaultID := [32]byte(bytes.Repeat([]byte{0x41}, 32))
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	recipient, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	require.NoError(t, err)
	material := vault.DeviceMaterial{DeviceID: "device-a", KeyID: []byte("key-a"), Signing: signing, Recipient: recipient}
	require.NoError(t, keyring.StoreDeviceKeys(context.Background(), vaultID, material))
	name := "dottie:device:" + hex.EncodeToString(vaultID[:]) + ":device-a"
	require.Len(t, backend.items, 1, "device key material was not stored in exactly one item")
	_, exists := backend.items[name]
	require.True(t, exists, "device key item name did not include vault and device identity")
	loaded, err := keyring.LoadDeviceKeys(context.Background(), vaultID, "device-a")
	require.NoError(t, err)
	assert.Equal(t, material.DeviceID, loaded.DeviceID, "device id")
	assert.Equal(t, material.KeyID, loaded.KeyID, "key id")
	assert.Equal(t, material.Signing, loaded.Signing, "signing private key")
	assert.Equal(t, material.Recipient.Bytes(), loaded.Recipient.Bytes(), "recipient private key")
}

func TestDeviceKeysReturnTypedAbsenceAndUnavailableErrors(t *testing.T) {
	vaultID := [32]byte(bytes.Repeat([]byte{0x51}, 32))
	missing, err := NewKeyringWithBackend(&fakeKeyringBackend{items: map[string][]byte{}})
	require.NoError(t, err)
	_, err = missing.LoadDeviceKeys(context.Background(), vaultID, "absent")
	require.ErrorIs(t, err, ErrKeyringItemNotFound, "missing item error")

	unavailable, err := NewKeyringWithBackend(&fakeKeyringBackend{items: map[string][]byte{}, err: ErrKeyringUnavailable})
	require.NoError(t, err)
	_, err = unavailable.LoadDeviceKeys(context.Background(), vaultID, "device-a")
	require.ErrorIs(t, err, ErrKeyringUnavailable, "unavailable item error")
	err = unavailable.StoreDeviceKeys(context.Background(), vaultID, vault.DeviceMaterial{
		DeviceID: "device-a", KeyID: []byte("key-a"), Signing: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize)),
		Recipient: mustPlatformRecipient(t, 0x33),
	})
	require.ErrorIs(t, err, ErrKeyringUnavailable, "unavailable store error")
}

func mustPlatformRecipient(t *testing.T, seed byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	return key
}

func TestKeyringPreservesLockedAndUnavailableErrors(t *testing.T) {
	for _, failure := range []error{ErrKeyringLocked, ErrKeyringUnavailable} {
		t.Run(failure.Error(), func(t *testing.T) {
			keyring, err := NewKeyringWithBackend(&fakeKeyringBackend{items: map[string][]byte{}, err: failure})
			require.NoError(t, err)
			err = keyring.Save(context.Background(), "item", []byte("secret"))
			require.ErrorIs(t, err, failure, "Save error = %v, want %v", err, failure)
			_, err = keyring.Load(context.Background(), "item")
			require.ErrorIs(t, err, failure, "Load error = %v, want %v", err, failure)
			err = keyring.Delete(context.Background(), "item")
			require.ErrorIs(t, err, failure, "Delete error = %v, want %v", err, failure)
		})
	}
}

func TestKeyringErrorsCarryNoRemoteText(t *testing.T) {
	secret := "opaque-key-material-9f2c"
	hostile := dbus.Error{Name: "org.freedesktop.Secret.Error", Body: []any{secret}}
	for _, err := range []error{
		fmt.Errorf("%w: connect to session bus: %s", ErrKeyringUnavailable, keyringErrorClass(hostile)),
		fmt.Errorf("%w: %s", ErrKeyringUnavailable, keyringErrorClass(hostile)),
	} {
		assert.NotContains(t, err.Error(), secret,
			"a service that echoes a payload in its error body must not leak it into our message")
		assert.Contains(t, err.Error(), "org.freedesktop.Secret.Error",
			"the D-Bus error name is kept, so the failure stays diagnosable")
	}
	assert.Equal(t, "transport", keyringErrorClass(errors.New("plain failure")))
	assert.Equal(t, "context", keyringErrorClass(context.DeadlineExceeded))
}
