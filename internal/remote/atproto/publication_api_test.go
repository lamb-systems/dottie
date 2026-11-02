package atproto_test

import (
	"reflect"
	"testing"

	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/stretchr/testify/assert"
)

func TestCommitPublicationAcceptsOnlyConcretePublicationIO(t *testing.T) {
	commitParameter := reflect.TypeOf(atproto.CommitPublication).In(1)
	assert.Equal(t, reflect.TypeOf(atproto.ATProtoPublicationIO{}), commitParameter)
}
