package platform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
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
		return nil, ErrKeyringUnavailable
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
