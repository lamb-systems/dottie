package publicationstate

import "context"

func AcceptMaterialForCompositionTest(ctx context.Context, store *Store, mode Mode, expectedStateToken [32]byte, observation Observation, payload []byte, confirmation [32]byte) (Floor, error) {
	return store.acceptMaterial(ctx, mode, expectedStateToken, observation, payload, confirmation)
}
