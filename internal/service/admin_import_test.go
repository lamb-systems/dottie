package service

import (
	"bytes"
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorOnboardingBundlePredecessorRefusalsWriteNoState(t *testing.T) {
	fixture := newPushFixture(t)
	newcomer, publicDevice := newAdminNewcomer(t, "tampered-import-newcomer")
	bundle := enrollWithFixture(t, fixture, newcomer, publicDevice)
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"missing policy", func(input []byte) []byte { return renameOnboardingField(input, "predecessor_policy") }},
		{"missing control", func(input []byte) []byte { return renameOnboardingField(input, "predecessor_control") }},
		{"missing head", func(input []byte) []byte { return renameOnboardingField(input, "predecessor_head") }},
		{"missing snapshot", func(input []byte) []byte { return renameOnboardingField(input, "predecessor_snapshot") }},
		{"missing certificates", func(input []byte) []byte { return renameOnboardingField(input, "predecessor_certificates") }},
		{"policy signature mismatch", func(input []byte) []byte { return changeOnboardingObjectLastHex(input, "predecessor_policy") }},
		{"control signature mismatch", func(input []byte) []byte { return changeOnboardingObjectLastHex(input, "predecessor_control") }},
		{"head signature mismatch", func(input []byte) []byte { return changeOnboardingObjectLastHex(input, "predecessor_head") }},
		{"snapshot signature mismatch", func(input []byte) []byte { return changeOnboardingObjectLastHex(input, "predecessor_snapshot") }},
		{"certificate signature mismatch", func(input []byte) []byte { return changeOnboardingCertificateLastHex(input) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store, paths := openCoordinatorStateWithPaths(t)
			keyring := &pushDeviceKeyring{devices: map[string]vault.DeviceMaterial{newcomer.DeviceID: newcomer}}
			coordinator := newNewcomerCoordinator(t, fixture, store, paths, keyring)
			input := test.mutate(bytes.Clone(bundle.EncodedBundle))
			_, err := vault.DecodeOnboardingBundle(input)
			require.Error(t, err)
			err = coordinator.ImportOnboarding(context.Background(), input, fixture.genesis.Vault, fixture.genesis.Anchor, newcomer.DeviceID)
			require.Error(t, err)
			selections, err := store.VaultSelections(context.Background())
			require.NoError(t, err)
			assert.Empty(t, selections)
			_, err = store.VaultCheckpoint(context.Background(), fixture.genesis.Vault)
			assert.ErrorIs(t, err, state.ErrVaultCheckpointNotFound)
			_, err = store.AuthenticatedPositionEvidenceAtEpoch(context.Background(), fixture.genesis.Vault, 0)
			assert.ErrorIs(t, err, state.ErrAuthenticatedPositionEvidenceNotFound)
		})
	}
}

func renameOnboardingField(encoded []byte, field string) []byte {
	oldField := []byte(`"` + field + `":`)
	newField := []byte(`"removed_` + field + `":`)
	return bytes.Replace(encoded, oldField, newField, 1)
}

func changeOnboardingObjectLastHex(encoded []byte, field string) []byte {
	prefix := []byte(`"` + field + `":"`)
	start := bytes.Index(encoded, prefix)
	if start < 0 {
		return encoded
	}
	start += len(prefix)
	end := bytes.IndexByte(encoded[start:], '"')
	if end <= 0 {
		return encoded
	}
	position := start + end - 1
	encoded[position] = flipHex(encoded[position])
	return encoded
}

func changeOnboardingCertificateLastHex(encoded []byte) []byte {
	prefix := []byte(`"predecessor_certificates":["`)
	start := bytes.Index(encoded, prefix)
	if start < 0 {
		return encoded
	}
	start += len(prefix)
	end := bytes.IndexByte(encoded[start:], '"')
	if end <= 0 {
		return encoded
	}
	position := start + end - 1
	encoded[position] = flipHex(encoded[position])
	return encoded
}

func flipHex(value byte) byte {
	if value == '0' {
		return '1'
	}
	return '0'
}
