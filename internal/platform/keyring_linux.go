package platform

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"

	"github.com/lamb-systems/dottie/internal/vault"
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

type keyringItemLister interface {
	ListItems(context.Context, string) ([]string, error)
}

func keyringErrorClass(err error) string {
	var dbusErr dbus.Error
	if errors.As(err, &dbusErr) {
		return dbusErr.Name
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "context"
	}
	return "transport"
}

func NewKeyring() (*Keyring, error) {
	connection, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("%w: connect to session bus: %s", ErrKeyringUnavailable, keyringErrorClass(err))
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

func (k *Keyring) StoreDeviceKeys(ctx context.Context, vaultID [32]byte, material vault.DeviceMaterial) error {
	if k == nil || k.backend == nil || material.DeviceID == "" || len(material.DeviceID) > vault.MaxDeviceIDBytes || !utf8.ValidString(material.DeviceID) || len(material.KeyID) == 0 || len(material.KeyID) > vault.MaxKeyIDBytes || material.Recipient == nil || len(material.Signing) != ed25519.PrivateKeySize || len(material.Recipient.Bytes()) != 32 || !validDeviceSigningKey(material.Signing) {
		return ErrKeyringUnavailable
	}
	name := deviceKeyringItemName(vaultID, material.DeviceID)
	payload := encodeDeviceKeyMaterial(material)
	return k.Save(ctx, name, payload)
}

func (k *Keyring) LoadDeviceKeys(ctx context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if k == nil || k.backend == nil || deviceID == "" || len(deviceID) > vault.MaxDeviceIDBytes || !utf8.ValidString(deviceID) {
		return vault.DeviceMaterial{}, ErrKeyringUnavailable
	}
	payload, err := k.Load(ctx, deviceKeyringItemName(vaultID, deviceID))
	if err != nil {
		return vault.DeviceMaterial{}, err
	}
	material, err := decodeDeviceKeyMaterial(deviceID, payload)
	if err != nil {
		return vault.DeviceMaterial{}, fmt.Errorf("%w: invalid device key item", ErrKeyringUnavailable)
	}
	return material, nil
}

func (k *Keyring) DeleteDeviceKeys(ctx context.Context, vaultID [32]byte, deviceID string) error {
	if k == nil || k.backend == nil || deviceID == "" || len(deviceID) > vault.MaxDeviceIDBytes || !utf8.ValidString(deviceID) {
		return ErrKeyringUnavailable
	}
	return k.Delete(ctx, deviceKeyringItemName(vaultID, deviceID))
}

func (k *Keyring) LoadDeviceKeysForVault(ctx context.Context, vaultID [32]byte) ([]vault.DeviceMaterial, error) {
	if k == nil || k.backend == nil || vaultID == ([32]byte{}) {
		return nil, ErrKeyringUnavailable
	}
	lister, ok := k.backend.(keyringItemLister)
	if !ok {
		return nil, ErrKeyringUnavailable
	}
	prefix := "dottie:device:" + hex.EncodeToString(vaultID[:]) + ":"
	names, err := lister.ListItems(ctx, prefix)
	if err != nil {
		return nil, classifyKeyringError(err)
	}
	materials := make([]vault.DeviceMaterial, 0, len(names))
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			return nil, ErrKeyringUnavailable
		}
		deviceID := strings.TrimPrefix(name, prefix)
		if deviceID == "" || len(deviceID) > vault.MaxDeviceIDBytes || !utf8.ValidString(deviceID) {
			return nil, ErrKeyringUnavailable
		}
		material, err := k.LoadDeviceKeys(ctx, vaultID, deviceID)
		if err != nil {
			return nil, err
		}
		materials = append(materials, material)
	}
	if len(materials) == 0 {
		return nil, ErrKeyringItemNotFound
	}
	return materials, nil
}

func deviceKeyringItemName(vaultID [32]byte, deviceID string) string {
	return "dottie:device:" + hex.EncodeToString(vaultID[:]) + ":" + deviceID
}

func encodeDeviceKeyMaterial(material vault.DeviceMaterial) []byte {
	payload := make([]byte, 0, 4+2+len(material.KeyID)+ed25519.PrivateKeySize+32)
	payload = append(payload, 'D', 'D', 'K', 1)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(material.KeyID)))
	payload = append(payload, length[:]...)
	payload = append(payload, material.KeyID...)
	payload = append(payload, material.Signing...)
	payload = append(payload, material.Recipient.Bytes()...)
	return payload
}

func decodeDeviceKeyMaterial(deviceID string, payload []byte) (vault.DeviceMaterial, error) {
	if len(payload) < 4+2+1+ed25519.PrivateKeySize+32 || string(payload[:4]) != "DDK\x01" {
		return vault.DeviceMaterial{}, ErrKeyringUnavailable
	}
	keyIDLength := int(binary.BigEndian.Uint16(payload[4:6]))
	if keyIDLength == 0 || keyIDLength > vault.MaxKeyIDBytes || len(payload) != 4+2+keyIDLength+ed25519.PrivateKeySize+32 {
		return vault.DeviceMaterial{}, ErrKeyringUnavailable
	}
	offset := 6
	keyID := append([]byte(nil), payload[offset:offset+keyIDLength]...)
	offset += keyIDLength
	signing := append(ed25519.PrivateKey(nil), payload[offset:offset+ed25519.PrivateKeySize]...)
	if !validDeviceSigningKey(signing) {
		return vault.DeviceMaterial{}, ErrKeyringUnavailable
	}
	offset += ed25519.PrivateKeySize
	recipient, err := ecdh.X25519().NewPrivateKey(payload[offset:])
	if err != nil {
		return vault.DeviceMaterial{}, err
	}
	return vault.DeviceMaterial{DeviceID: deviceID, KeyID: keyID, Signing: signing, Recipient: recipient}, nil
}

func validDeviceSigningKey(key ed25519.PrivateKey) bool {
	return len(key) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key)
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
	return fmt.Errorf("%w: %s", ErrKeyringUnavailable, keyringErrorClass(err))
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
		return "", fmt.Errorf("%w: read default collection alias: %s", ErrKeyringUnavailable, keyringErrorClass(err))
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
		return fmt.Errorf("%w: read collection lock state: %s", ErrKeyringUnavailable, keyringErrorClass(err))
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
		return "", fmt.Errorf("%w: open secret session: %s", ErrKeyringUnavailable, keyringErrorClass(err))
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

func (b *secretServiceBackend) ListItems(ctx context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	collection, err := b.collection(ctx)
	if err != nil {
		return nil, err
	}
	var property dbus.Variant
	if err := b.connection.Object(secretServiceName, collection).CallWithContext(ctx, secretPropertiesInterface+".Get", 0, secretCollectionInterface, "Items").Store(&property); err != nil {
		return nil, ErrKeyringUnavailable
	}
	items, ok := property.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, ErrKeyringUnavailable
	}
	names := make([]string, 0)
	for _, item := range items {
		var attributes dbus.Variant
		if err := b.connection.Object(secretServiceName, item).CallWithContext(ctx, secretPropertiesInterface+".Get", 0, secretItemInterface, "Attributes").Store(&attributes); err != nil {
			return nil, ErrKeyringUnavailable
		}
		values, ok := attributes.Value().(map[string]string)
		if !ok {
			return nil, ErrKeyringUnavailable
		}
		name := values["name"]
		if values["application"] == "dottie" && strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
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
