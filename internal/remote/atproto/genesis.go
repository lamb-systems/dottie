package atproto

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrGenesisRepositoryNotEmpty   = errors.New("genesis requires an empty verified repository")
	ErrGenesisPreflightUnavailable = errors.New("genesis preflight could not verify the repository")
)

func CheckGenesisRepositoryEmpty(ctx context.Context, reader RevisionReader, transport Transport, did string) error {
	if transport == nil || did == "" || !validDID(did) || reader.DIDDocumentID != did {
		return fmt.Errorf("%w: authenticated revision reader and DID are required", ErrBatchRejected)
	}
	reader.Transport = transport
	revision, err := reader.Read(ctx, did)
	if err != nil {
		return fmt.Errorf("%w: cannot verify empty genesis repository: %w", ErrGenesisPreflightUnavailable, err)
	}
	if len(revision.Membership()) != 0 {
		return ErrGenesisRepositoryNotEmpty
	}
	return nil
}
