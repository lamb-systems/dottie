package platform

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

var ErrKeyringLocked = errors.New("Dottie keyring collection is locked")
var ErrKeyringUnavailable = errors.New("Dottie keyring is unavailable")
var ErrKeyringItemNotFound = errors.New("Dottie keyring item was not found")

const (
	secretServiceName         = "org.freedesktop.secrets"
	secretServicePath         = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceInterface    = "org.freedesktop.Secret.Service"
	secretCollectionInterface = "org.freedesktop.Secret.Collection"
	secretItemInterface       = "org.freedesktop.Secret.Item"
	secretPropertiesInterface = "org.freedesktop.DBus.Properties"
	secretDefaultAlias        = "default"
)

type KeyringBackend interface {
	Save(context.Context, string, []byte) error
	Load(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

type Keyring struct {
	backend KeyringBackend
}

func NewKeyring() (*Keyring, error) {
	connection, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("%w: connect to session bus: %v", ErrKeyringUnavailable, err)
	}
	backend := &secretServiceBackend{connection: connection}
	if _, err := backend.collection(context.Background()); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return &Keyring{backend: backend}, nil
}

func NewKeyringWithBackend(backend KeyringBackend) (*Keyring, error) {
	if backend == nil {
		return nil, ErrKeyringUnavailable
	}
	return &Keyring{backend: backend}, nil
}

func (k *Keyring) Save(ctx context.Context, itemName string, payload []byte) error {
	if k == nil || k.backend == nil || itemName == "" {
		return ErrKeyringUnavailable
	}
	return classifyKeyringError(k.backend.Save(ctx, itemName, append([]byte(nil), payload...)))
}

func (k *Keyring) Load(ctx context.Context, itemName string) ([]byte, error) {
	if k == nil || k.backend == nil || itemName == "" {
		return nil, ErrKeyringUnavailable
	}
	payload, err := k.backend.Load(ctx, itemName)
	if err != nil {
		return nil, classifyKeyringError(err)
	}
	return append([]byte(nil), payload...), nil
}

func (k *Keyring) Delete(ctx context.Context, itemName string) error {
	if k == nil || k.backend == nil || itemName == "" {
		return ErrKeyringUnavailable
	}
	return classifyKeyringError(k.backend.Delete(ctx, itemName))
}

func (k *Keyring) Close() error {
	if k == nil || k.backend == nil {
		return nil
	}
	if closer, ok := k.backend.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func classifyKeyringError(err error) error {
	if err == nil || errors.Is(err, ErrKeyringLocked) || errors.Is(err, ErrKeyringUnavailable) || errors.Is(err, ErrKeyringItemNotFound) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrKeyringUnavailable, err)
}

type secretServiceBackend struct {
	connection *dbus.Conn
	mu         sync.Mutex
}

type secretItemValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func (b *secretServiceBackend) Close() error {
	if b.connection == nil {
		return nil
	}
	return b.connection.Close()
}

func (b *secretServiceBackend) collection(ctx context.Context) (dbus.ObjectPath, error) {
	object := b.connection.Object(secretServiceName, secretServicePath)
	var collection dbus.ObjectPath
	if err := object.CallWithContext(ctx, secretServiceInterface+".ReadAlias", 0, secretDefaultAlias).Store(&collection); err != nil {
		return "", fmt.Errorf("%w: read default collection alias: %v", ErrKeyringUnavailable, err)
	}
	if collection == "/" || collection == "" {
		return "", fmt.Errorf("%w: no default secret collection; unlock or create one in the desktop keyring", ErrKeyringUnavailable)
	}
	if err := b.ensureUnlocked(ctx, collection); err != nil {
		return "", err
	}
	return collection, nil
}

func (b *secretServiceBackend) ensureUnlocked(ctx context.Context, path dbus.ObjectPath) error {
	var locked dbus.Variant
	if err := b.connection.Object(secretServiceName, path).CallWithContext(ctx, secretPropertiesInterface+".Get", 0, secretCollectionInterface, "Locked").Store(&locked); err != nil {
		return fmt.Errorf("%w: read collection lock state: %v", ErrKeyringUnavailable, err)
	}
	value, ok := locked.Value().(bool)
	if !ok {
		return fmt.Errorf("%w: collection lock state is not a boolean", ErrKeyringUnavailable)
	}
	if value {
		return ErrKeyringLocked
	}
	return nil
}

func (b *secretServiceBackend) openSession(ctx context.Context) (dbus.ObjectPath, error) {
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := b.connection.Object(secretServiceName, secretServicePath).CallWithContext(ctx, secretServiceInterface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil || session == "/" {
		return "", fmt.Errorf("%w: open secret session: %v", ErrKeyringUnavailable, err)
	}
	return session, nil
}

func (b *secretServiceBackend) search(ctx context.Context, collection dbus.ObjectPath, itemName string) ([]dbus.ObjectPath, error) {
	var property dbus.Variant
	if err := b.connection.Object(secretServiceName, collection).CallWithContext(ctx, secretPropertiesInterface+".Get", 0, secretCollectionInterface, "Items").Store(&property); err != nil {
		return nil, ErrKeyringUnavailable
	}
	items, ok := property.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, ErrKeyringUnavailable
	}
	matches := make([]dbus.ObjectPath, 0, 1)
	for _, item := range items {
		var attributes dbus.Variant
		if err := b.connection.Object(secretServiceName, item).CallWithContext(ctx, secretPropertiesInterface+".Get", 0, secretItemInterface, "Attributes").Store(&attributes); err != nil {
			return nil, ErrKeyringUnavailable
		}
		values, ok := attributes.Value().(map[string]string)
		if !ok {
			return nil, ErrKeyringUnavailable
		}
		if values["application"] == "dottie" && values["name"] == itemName {
			matches = append(matches, item)
		}
	}
	return matches, nil
}

func (b *secretServiceBackend) Save(ctx context.Context, itemName string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	collection, err := b.collection(ctx)
	if err != nil {
		return err
	}
	session, err := b.openSession(ctx)
	if err != nil {
		return err
	}
	defer b.closeSession(session)
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant("Dottie session"),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{"application": "dottie", "name": itemName}),
	}
	secret := secretItemValue{Session: session, Value: append([]byte(nil), payload...), ContentType: "application/octet-stream"}
	var item, prompt dbus.ObjectPath
	if err := b.connection.Object(secretServiceName, collection).CallWithContext(ctx, secretCollectionInterface+".CreateItem", 0, properties, secret, true).Store(&item, &prompt); err != nil {
		return ErrKeyringUnavailable
	}
	if prompt != "/" {
		return ErrKeyringLocked
	}
	return nil
}

func (b *secretServiceBackend) Load(ctx context.Context, itemName string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	collection, err := b.collection(ctx)
	if err != nil {
		return nil, err
	}
	items, err := b.search(ctx, collection, itemName)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrKeyringItemNotFound
	}
	if err := b.ensureItemUnlocked(ctx, items[0]); err != nil {
		return nil, err
	}
	session, err := b.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer b.closeSession(session)
	var secret secretItemValue
	if err := b.connection.Object(secretServiceName, items[0]).CallWithContext(ctx, secretItemInterface+".GetSecret", 0, session).Store(&secret); err != nil {
		return nil, ErrKeyringUnavailable
	}
	return append([]byte(nil), secret.Value...), nil
}

func (b *secretServiceBackend) ensureItemUnlocked(ctx context.Context, item dbus.ObjectPath) error {
	var locked dbus.Variant
	if err := b.connection.Object(secretServiceName, item).CallWithContext(ctx, secretPropertiesInterface+".Get", 0, secretItemInterface, "Locked").Store(&locked); err != nil {
		return ErrKeyringUnavailable
	}
	isLocked, ok := locked.Value().(bool)
	if !ok {
		return ErrKeyringUnavailable
	}
	if isLocked {
		return ErrKeyringLocked
	}
	return nil
}

func (b *secretServiceBackend) Delete(ctx context.Context, itemName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	collection, err := b.collection(ctx)
	if err != nil {
		return err
	}
	items, err := b.search(ctx, collection, itemName)
	if err != nil {
		return err
	}
	for _, item := range items {
		var prompt dbus.ObjectPath
		if err := b.connection.Object(secretServiceName, item).CallWithContext(ctx, secretItemInterface+".Delete", 0).Store(&prompt); err != nil {
			return ErrKeyringUnavailable
		}
		if prompt != "/" {
			return ErrKeyringLocked
		}
	}
	return nil
}

func (b *secretServiceBackend) closeSession(session dbus.ObjectPath) {
	_ = b.connection.Object(secretServiceName, secretServicePath).Call(secretServiceInterface+".CloseSession", 0, session).Err
}
