package publication

import (
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/vault"
)

func DecodePayload(payload []byte, reference BlobReference) (model.Snapshot, error) {
	if err := VerifyPayload(payload, reference); err != nil {
		return model.Snapshot{}, err
	}
	snapshot, err := vault.UnpackPayload(payload)
	if err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}
