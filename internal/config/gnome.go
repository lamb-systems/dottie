package config

import (
	"encoding/hex"
	"sort"

	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
)

func ApprovedGNOMEPolicy(categories []string) (GNOMEPolicy, error) {
	keys, err := matrix.SelectCategories(categories)
	if err != nil {
		return GNOMEPolicy{}, err
	}
	digest, err := matrix.KeySetDigest(keys)
	if err != nil {
		return GNOMEPolicy{}, err
	}
	normalized := append([]string(nil), categories...)
	sort.Strings(normalized)
	return GNOMEPolicy{
		Approval:      GNOMEApprovalApproved,
		Categories:    normalized,
		MatrixVersion: matrix.Version,
		KeyDigest:     hex.EncodeToString(digest[:]),
	}, nil
}
