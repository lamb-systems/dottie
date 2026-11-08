package publicationstate

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptEventWireGolden(t *testing.T) {
	var state [32]byte
	for index := range state {
		state[index] = 1
	}
	body, digest, err := makeAttemptEvent([16]byte{}, 1, "created", nil, nil, state)
	require.NoError(t, err)
	expected := []byte(`{"version":1,"ordinal":1,"kind":"created","previousDigest":null,"evidence":null,"stateDigest":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`)
	assert.Equal(t, expected, body)
	assert.Equal(t, "4cca5c1ed41e941993eed3c77c2caf12e14beb471355ed19ecc92830150a97b0", hex.EncodeToString(digest))
}

func TestPublicationAttemptEvidenceWireRejectsNoncanonicalAndUnknownData(t *testing.T) {
	wire := attemptEvidenceWire{Version: 1, Role: "retirement", AttemptedKey: "0000000000000000", AttemptedRecord: []byte{1, 2, 3}, Outcome: string(OutcomeNotSubmitted)}
	encoded, err := encodeAttemptEvidence(wire)
	require.NoError(t, err)
	var decoded attemptEvidenceWire
	require.NoError(t, strictJSON(encoded, &decoded))
	assert.Equal(t, wire, decoded)

	unknown := bytes.Clone(encoded)
	unknown[len(unknown)-1] = ','
	unknown = append(unknown, []byte(`"unknown":true}`)...)
	assert.Error(t, strictJSON(unknown, &decoded))
	duplicate := append([]byte(`{"version":1,`), encoded[1:]...)
	assert.Error(t, strictJSON(duplicate, &decoded))
	noncanonical := append([]byte{' '}, encoded...)
	assert.Error(t, strictJSON(noncanonical, &decoded))
	assert.Error(t, strictJSON([]byte{0xff}, &decoded))
}

func FuzzPublicationAttemptEvidenceWire(f *testing.F) {
	valid, err := encodeAttemptEvidence(attemptEvidenceWire{Version: 1, Role: "retirement", AttemptedKey: "0000000000000000", AttemptedRecord: []byte{1}, Outcome: string(OutcomeNotSubmitted)})
	require.NoError(f, err)
	f.Add(valid)
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte(`{"version":1,"unknown":true}`))
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		var wire attemptEvidenceWire
		if strictJSON(data, &wire) == nil {
			canonical, err := canonicalJSON(wire)
			require.NoError(t, err)
			assert.Equal(t, data, canonical)
		}
	})
}
