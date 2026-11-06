package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/model"
)

const defaultMaxPackedBytes int64 = 402653184

var (
	ErrPayloadLimits  = errors.New("invalid payload limits")
	ErrPayloadBound   = errors.New("payload bound exceeded")
	ErrInvalidPayload = errors.New("invalid payload")
)

type PayloadLimits struct {
	MaxPackedBytes int64
	Snapshot       Limits
}

type PayloadError struct {
	Stage  string
	Reason string
	Kind   string
	cause  error
}

func (e *PayloadError) Error() string {
	if e.Kind != "" {
		return fmt.Sprintf("payload: %s: %s: %s", e.Stage, e.Reason, e.Kind)
	}
	return fmt.Sprintf("payload: %s: %s", e.Stage, e.Reason)
}

func (e *PayloadError) Unwrap() error {
	return e.cause
}

func DefaultPayloadLimits() PayloadLimits {
	return PayloadLimits{MaxPackedBytes: defaultMaxPackedBytes, Snapshot: DefaultLimits()}
}

func UnpackPayload(payload []byte) (model.Snapshot, error) {
	return UnpackPayloadWithLimits(payload, DefaultPayloadLimits())
}

func UnpackPayloadWithLimits(payload []byte, limits PayloadLimits) (model.Snapshot, error) {
	if err := validatePayloadLimits(limits); err != nil {
		return model.Snapshot{}, newPayloadError("limits", "invalid", "", ErrPayloadLimits)
	}
	if len(payload) == 0 {
		return model.Snapshot{}, newPayloadError("size", "invalid", "", ErrInvalidPayload)
	}
	if int64(len(payload)) > limits.MaxPackedBytes {
		return model.Snapshot{}, newPayloadError("size", "bound", "MaxPackedBytes", ErrPayloadBound)
	}

	counts, err := inspectPayloadManifest(payload, limits.Snapshot)
	if err != nil {
		return model.Snapshot{}, err
	}
	blob := Blob{
		Version:        Version,
		Codec:          CodecNone,
		Payload:        payload,
		Digest:         sha256.Sum256(payload),
		PlaintextBytes: counts.plaintextBytes,
		EntryCount:     counts.entries,
	}
	snapshot, err := UnpackWithLimits(blob, limits.Snapshot)
	if err != nil {
		var bound *BoundError
		if errors.As(err, &bound) && payloadBoundKind(bound.Kind) {
			return model.Snapshot{}, newPayloadError("validate", "bound", bound.Kind, ErrPayloadBound)
		}
		return model.Snapshot{}, newPayloadError("validate", "malformed", "", ErrInvalidPayload)
	}
	return snapshot, nil
}

func validatePayloadLimits(limits PayloadLimits) error {
	defaults := DefaultPayloadLimits()
	if limits.MaxPackedBytes <= 0 || limits.MaxPackedBytes > defaults.MaxPackedBytes {
		return ErrPayloadLimits
	}
	if limits.Snapshot.MaxEntries > defaults.Snapshot.MaxEntries ||
		limits.Snapshot.MaxDepth > defaults.Snapshot.MaxDepth ||
		limits.Snapshot.MaxEntryBytes > defaults.Snapshot.MaxEntryBytes ||
		limits.Snapshot.MaxTotalBytes > defaults.Snapshot.MaxTotalBytes ||
		limits.Snapshot.MaxManifestBytes > defaults.Snapshot.MaxManifestBytes ||
		limits.Snapshot.MaxPathBytes > defaults.Snapshot.MaxPathBytes {
		return ErrPayloadLimits
	}
	if err := validateLimits(limits.Snapshot); err != nil {
		return ErrPayloadLimits
	}
	return nil
}

func newPayloadError(stage, reason, kind string, cause error) *PayloadError {
	return &PayloadError{Stage: stage, Reason: reason, Kind: kind, cause: cause}
}

func payloadInspectMalformed() error {
	return newPayloadError("inspect", "malformed", "", ErrInvalidPayload)
}

func payloadInspectUnsupported() error {
	return newPayloadError("inspect", "unsupported_profile", "", ErrInvalidPayload)
}

func payloadInspectBound(kind string) error {
	return newPayloadError("inspect", "bound", kind, ErrPayloadBound)
}

func payloadBoundKind(kind string) bool {
	switch kind {
	case "MaxPackedBytes", "MaxManifestBytes", "MaxEntries", "MaxDepth", "MaxEntryBytes", "MaxTotalBytes", "MaxPathBytes":
		return true
	default:
		return false
	}
}
