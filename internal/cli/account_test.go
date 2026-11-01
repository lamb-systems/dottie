package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/vault"
)

type memoryAccountKeyring struct {
	items map[string]vault.DeviceMaterial
	err   error
}

func (k *memoryAccountKeyring) StoreDeviceKeys(_ context.Context, vaultID [32]byte, material vault.DeviceMaterial) error {
	if k.err != nil {
		return k.err
	}
	cloned, err := cloneAccountMaterial(material)
	if err != nil {
		return err
	}
	k.items[accountItemKey(vaultID, material.DeviceID)] = cloned
	return nil
}

func (k *memoryAccountKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if k.err != nil {
		return vault.DeviceMaterial{}, k.err
	}
	material, ok := k.items[accountItemKey(vaultID, deviceID)]
	if !ok {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	return cloneAccountMaterial(material)
}

func (k *memoryAccountKeyring) Close() error {
	return nil
}

func cloneAccountMaterial(material vault.DeviceMaterial) (vault.DeviceMaterial, error) {
	recipient, err := ecdh.X25519().NewPrivateKey(material.Recipient.Bytes())
	if err != nil {
		return vault.DeviceMaterial{}, err
	}
	return vault.DeviceMaterial{
		DeviceID: material.DeviceID, KeyID: bytes.Clone(material.KeyID),
		Signing: bytes.Clone(material.Signing), Recipient: recipient,
	}, nil
}

func accountItemKey(vaultID [32]byte, deviceID string) string {
	return hex.EncodeToString(vaultID[:]) + ":" + deviceID
}

func TestAccountBootstrapStoresKeysAndPrintsFingerprints(t *testing.T) {
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	open := func() (accountKeyring, error) { return keyring, nil }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"bootstrap", "--vault-name", "personal", "--device-id", "root-device"}, &stdout, &stderr, open)
	require.Equal(t, 0, code, "exit code")
	assert.Empty(t, stderr.String(), "stderr")
	assert.Contains(t, stdout.String(), "vault fingerprint:", "vault fingerprint")
	assert.Contains(t, stdout.String(), "anchor fingerprint:", "anchor fingerprint")
	assert.Contains(t, stdout.String(), "checkpoint fingerprint:", "checkpoint fingerprint")
	assert.Contains(t, stdout.String(), "kit public-key fingerprint:", "kit public-key fingerprint")
	kitLine := strings.SplitN(stdout.String(), "recovery kit (keep offline): ", 2)
	require.Len(t, kitLine, 2, "recovery kit was not displayed")
	groupedKit := strings.Fields(kitLine[1])[0]
	decodedKit, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(groupedKit, "-", ""))
	require.NoError(t, err)
	require.Len(t, decodedKit, 32, "displayed recovery kit size")
	require.Len(t, keyring.items, 1, "root device keys were not stored")
}

func TestAccountEnrollRequiresMatchingTranscriptFingerprint(t *testing.T) {
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	open := func() (accountKeyring, error) { return keyring, nil }
	vaultID := bytes.Repeat([]byte{0x55}, 32)
	baseArgs := []string{"enroll", "--vault", hex.EncodeToString(vaultID), "--device-id", "new-device", "--role", "publisher"}
	var firstOut, firstErr bytes.Buffer
	code := runAccount(baseArgs, &firstOut, &firstErr, open)
	require.Equal(t, 1, code, "an unconfirmed transcript must not succeed")
	assert.Contains(t, firstOut.String(), "device id: new-device", "device id transcript")
	assert.Contains(t, firstOut.String(), "key id:", "key id transcript")
	assert.Contains(t, firstOut.String(), "requested role: publisher", "role transcript")
	assert.Contains(t, firstOut.String(), "signing public key fingerprint:", "signing fingerprint")
	assert.Contains(t, firstOut.String(), "recipient public key fingerprint:", "recipient fingerprint")
	assert.Contains(t, firstErr.String(), "transcript fingerprint confirmation required", "missing confirmation")
	fingerprintParts := strings.SplitN(firstOut.String(), "transcript fingerprint: ", 2)
	require.Len(t, fingerprintParts, 2, "transcript fingerprint line")
	fingerprint := strings.Fields(fingerprintParts[1])[0]

	confirmedArgs := append(append([]string(nil), baseArgs...), "--confirm", fingerprint)
	var confirmedOut, confirmedErr bytes.Buffer
	code = runAccount(confirmedArgs, &confirmedOut, &confirmedErr, open)
	require.Equal(t, 0, code, "matching confirmation must pass")
	assert.Contains(t, confirmedOut.String(), "transcript confirmed", "confirmation result")
	assert.Empty(t, confirmedErr.String(), "stderr")

	wrong := strings.Repeat("0", 64)
	if wrong == fingerprint {
		wrong = strings.Repeat("1", 64)
	}
	substitutedArgs := append(append([]string(nil), baseArgs...), "--confirm", wrong)
	var substitutedOut, substitutedErr bytes.Buffer
	code = runAccount(substitutedArgs, &substitutedOut, &substitutedErr, open)
	require.Equal(t, 1, code, "substituted transcript confirmation must fail")
	assert.Contains(t, substitutedErr.String(), "confirmation mismatch", "substitution error")
}

func TestAccountDoesNotDegradeWhenKeyringIsUnavailable(t *testing.T) {
	open := func() (accountKeyring, error) { return nil, platform.ErrKeyringUnavailable }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"enroll", "--vault", strings.Repeat("1", 64), "--device-id", "device", "--role", "publisher"}, &stdout, &stderr, open)
	require.Equal(t, 1, code, "keyring failure exit code")
	assert.Empty(t, stdout.String(), "unavailable keyring did not print a transcript")
	assert.Contains(t, stderr.String(), "keyring is unavailable", "typed keyring failure")
}

func TestAccountRejectsRootEnrollment(t *testing.T) {
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	open := func() (accountKeyring, error) { return keyring, nil }
	vaultID := strings.Repeat("1", 64)
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"enroll", "--vault", vaultID, "--device-id", "device", "--role", "root"}, &stdout, &stderr, open)
	require.Equal(t, 2, code, "root role usage exit code")
	assert.Contains(t, stderr.String(), "role must be publisher or restore_only", "root enrollment rejection")
}

func TestAccountKeyringFactoryErrorDoesNotExposeDetails(t *testing.T) {
	open := func() (accountKeyring, error) { return nil, errors.New("synthetic backend detail") }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"bootstrap", "--vault-name", "vault", "--device-id", "root"}, &stdout, &stderr, open)
	require.Equal(t, 1, code, "keyring error exit code")
	assert.NotContains(t, stderr.String(), "synthetic backend detail", "keyring detail leaked")
}
