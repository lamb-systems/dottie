package atproto

import (
	"encoding/json"
	"fmt"
)

const redactionMarker = "[REDACTED]"

type Secret struct {
	value []byte
}

func NewSecret(value string) Secret {
	return Secret{value: []byte(value)}
}

func (s Secret) Reveal() string {
	return string(s.value)
}

func (s Secret) Bytes() []byte {
	return append([]byte(nil), s.value...)
}

func (Secret) String() string {
	return redactionMarker
}

func (Secret) GoString() string {
	return redactionMarker
}

func (Secret) Format(state fmt.State, verb rune) {
	_, _ = state.Write([]byte(redactionMarker))
}

func (Secret) MarshalText() ([]byte, error) {
	return []byte(redactionMarker), nil
}

func (Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactionMarker)
}
