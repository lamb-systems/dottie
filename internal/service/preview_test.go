package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetentionBindingForPositionRejectsShortPolicyDigest(t *testing.T) {
	binding, err := retentionBindingForPosition(context.Background(), nil, VaultSelection{}, 1, []byte("snapshot"), []byte{0x5a, 0x7c}, []byte("control"))
	require.NoError(t, err)
	assert.Nil(t, binding)
}
