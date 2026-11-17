package atproto_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

func TestCommitPublicationAcceptsOnlyConcretePublicationIO(t *testing.T) {
	commitParameter := reflect.TypeOf(atproto.CommitPublication).In(1)
	assert.Equal(t, reflect.TypeFor[atproto.PublicationIO](), commitParameter)
}

func TestTransitionCommitAndResolutionAcceptOnlyConcreteTransitionIO(t *testing.T) {
	concrete := reflect.TypeFor[atproto.TransitionIO]()
	commitParameter := reflect.TypeOf(atproto.CommitTransition).In(1)
	assert.Equal(t, concrete, commitParameter)
	resolveParameter := reflect.TypeOf(atproto.ResolveTransitionAttempt).In(1)
	assert.Equal(t, concrete, resolveParameter)
}
