package service

import (
	"context"

	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

type VaultReader struct {
	Reader atproto.VaultReader
}

func (reader VaultReader) Read(ctx context.Context, request atproto.ReadRequest) (atproto.ReadResult, error) {
	return reader.Reader.Read(ctx, request)
}

func (reader VaultReader) FetchBlob(ctx context.Context, did string, blobCID []byte, size int64) ([]byte, error) {
	return reader.Reader.FetchBlob(ctx, did, blobCID, size)
}
