package atproto

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/lamb-systems/dottie/internal/publication"
)

var (
	ErrDottiePublicationPresent = errors.New(
		"genesis refused: the account repository already contains a Dottie publication",
	)
	ErrGenesisPreflightUnavailable = errors.New("genesis preflight could not verify the repository")
)

var dottiePublicationCollections = map[string]struct{}{
	VaultHeadNSID:            {},
	VaultControlNSID:         {},
	VaultSnapshotNSID:        {},
	VaultPolicyNSID:          {},
	VaultCertificateNSID:     {},
	VaultCheckpointNSID:      {},
	VaultAttestationNSID:     {},
	publication.HeadNSID:     {},
	publication.SnapshotNSID: {},
}

func CheckNoDottiePublication(ctx context.Context, reader RevisionReader, transport Transport, did string) error {
	if transport == nil || did == "" || !validDID(did) || reader.DIDDocumentID != did {
		return fmt.Errorf("%w: authenticated revision reader and DID are required", ErrBatchRejected)
	}
	reader.Transport = transport
	revision, err := reader.Read(ctx, did)
	if err != nil {
		return fmt.Errorf(
			"%w: cannot verify whether the repository holds a Dottie publication: %w",
			ErrGenesisPreflightUnavailable,
			err,
		)
	}
	collections := make([]string, 0, 2)
	for key := range revision.Membership() {
		if _, present := dottiePublicationCollections[key.Collection]; present {
			collections = append(collections, key.Collection)
		}
	}
	if len(collections) != 0 {
		sort.Strings(collections)
		return fmt.Errorf("%w: collections %s", ErrDottiePublicationPresent, strings.Join(collections, ", "))
	}
	return nil
}
