package publicationstate

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzStrictPrivateWireJSON(f *testing.F) {
	wire := stateTokenWire{Version: 1, DatabaseID: bytes.Repeat([]byte{0x5a}, 32), Revision: 1, Generation: 1, Binding: bindingWire{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: string(BackendPublicRepo), Repository: "at://did:plc:abcdefghijklmnopqrstuvwx", Vault: bytes.Repeat([]byte{0x31}, 32), Profile: storageProfile}, Limits: limitsToWire(DefaultLimits()), Floor: nil}
	valid, err := canonicalJSON(wire)
	require.NoError(f, err)
	f.Add(valid)
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 32<<10 {
			return
		}
		var decoded stateTokenWire
		if err := strictJSON(encoded, &decoded); err != nil {
			return
		}
		canonical, err := canonicalJSON(decoded)
		require.NoError(t, err)
		assert.Equal(t, canonical, encoded)
	})
}
