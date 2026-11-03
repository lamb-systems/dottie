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

func TestTransitionCommitAndResolutionAcceptOnlyConcreteTransitionIO(t *testing.T) {
	concrete := reflect.TypeOf(atproto.ATProtoTransitionIO{})
	commitParameter := reflect.TypeOf(atproto.CommitTransition).In(1)
	assert.Equal(t, concrete, commitParameter)
	resolveParameter := reflect.TypeOf(atproto.ResolveTransitionAttempt).In(1)
	assert.Equal(t, concrete, resolveParameter)
}
