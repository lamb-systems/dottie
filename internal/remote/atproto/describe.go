package atproto

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

var (
	ErrBlobUploadLimitUnavailable = errors.New("provider blob upload limit is unavailable")
)

type BlobUploadLimitError struct {
	Kind error
}

func (e *BlobUploadLimitError) Error() string {
	if e == nil || e.Kind == nil {
		return ErrBlobUploadLimitUnavailable.Error()
	}
	return e.Kind.Error()
}

func (e *BlobUploadLimitError) Unwrap() error {
	if e == nil || e.Kind == nil {
		return ErrBlobUploadLimitUnavailable
	}
	return e.Kind
}

func DescribeBlobUploadLimit(ctx context.Context, transport Transport) (int64, error) {
	if transport == nil {
		return 0, &BlobUploadLimitError{Kind: ErrBlobUploadLimitUnavailable}
	}
	status, body, err := transport.Do(ctx, "GET", "com.atproto.server.describeServer", nil, nil, "")
	if err != nil || status < 200 || status >= 300 {
		return 0, &BlobUploadLimitError{Kind: ErrBlobUploadLimitUnavailable}
	}
	var description struct {
		BlobUploadLimit json.RawMessage `json:"blobUploadLimit"`
	}
	if err := json.Unmarshal(body, &description); err != nil {
		return 0, &BlobUploadLimitError{Kind: ErrBlobUploadLimitUnavailable}
	}
	value := strings.TrimSpace(string(description.BlobUploadLimit))
	if value == "" || value == "null" {
		return 0, &BlobUploadLimitError{Kind: ErrBlobUploadLimitUnadvertised}
	}
	limit, err := strconv.ParseInt(value, 10, 64)
	if err != nil || limit <= 0 {
		return 0, &BlobUploadLimitError{Kind: ErrBlobUploadLimitUnavailable}
	}
	return limit, nil
}
