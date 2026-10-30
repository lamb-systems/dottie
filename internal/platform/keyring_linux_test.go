package platform

import (
	"context"
	"errors"
	"testing"
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
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(context.Background(), "client-did", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if len(backend.items) != 1 || string(backend.items["client-did"]) != "new" {
		t.Fatalf("save did not replace the matching item: %#v", backend.items)
	}
	loaded, err := keyring.Load(context.Background(), "client-did")
	if err != nil || string(loaded) != "new" {
		t.Fatalf("load = %q, %v", loaded, err)
	}
	if err := keyring.Delete(context.Background(), "client-did"); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Delete(context.Background(), "client-did"); err != nil {
		t.Fatalf("delete must be idempotent: %v", err)
	}
}

func TestKeyringPreservesLockedAndUnavailableErrors(t *testing.T) {
	for _, failure := range []error{ErrKeyringLocked, ErrKeyringUnavailable} {
		t.Run(failure.Error(), func(t *testing.T) {
			keyring, err := NewKeyringWithBackend(&fakeKeyringBackend{items: map[string][]byte{}, err: failure})
			if err != nil {
				t.Fatal(err)
			}
			if err := keyring.Save(context.Background(), "item", []byte("secret")); !errors.Is(err, failure) {
				t.Fatalf("Save error = %v, want %v", err, failure)
			}
			if _, err := keyring.Load(context.Background(), "item"); !errors.Is(err, failure) {
				t.Fatalf("Load error = %v, want %v", err, failure)
			}
			if err := keyring.Delete(context.Background(), "item"); !errors.Is(err, failure) {
				t.Fatalf("Delete error = %v, want %v", err, failure)
			}
		})
	}
}
