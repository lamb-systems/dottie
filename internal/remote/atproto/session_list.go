package atproto

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/lamb-systems/dottie/internal/platform"
)

const sessionItemPrefix = "session:"

var ErrSessionListingUnavailable = errors.New("stored account sessions cannot be listed")

type SessionItemLister interface {
	ListItems(context.Context, string) ([]string, error)
}

func (c *Client) ListSessionDIDs(ctx context.Context) ([]string, error) {
	if c.Store == nil {
		return nil, ErrSessionUnavailable
	}
	lister, ok := c.Store.(SessionItemLister)
	if !ok {
		return nil, ErrSessionListingUnavailable
	}
	names, err := lister.ListItems(ctx, sessionItemPrefix)
	if err != nil {
		if errors.Is(err, platform.ErrKeyringLocked) || errors.Is(err, platform.ErrKeyringUnavailable) {
			return nil, err
		}
		return nil, ErrSessionListingUnavailable
	}
	seen := make(map[string]struct{}, len(names))
	dids := make([]string, 0, len(names))
	for _, name := range names {
		if !strings.HasPrefix(name, sessionItemPrefix) || name == sessionItemPrefix {
			return nil, ErrSessionUnavailable
		}
		encoded, loadErr := c.Store.Load(ctx, name)
		if loadErr != nil {
			if errors.Is(loadErr, platform.ErrKeyringLocked) || errors.Is(loadErr, platform.ErrKeyringUnavailable) {
				return nil, loadErr
			}
			return nil, ErrSessionUnavailable
		}
		var header struct {
			Version int    `json:"version"`
			DID     string `json:"did"`
		}
		if json.Unmarshal(encoded, &header) != nil || header.Version != sessionEnvelopeVersion ||
			!validDID(header.DID) {
			return nil, ErrSessionUnavailable
		}
		if sessionItemName(c.ClientID, header.DID) != name {
			return nil, ErrSessionUnavailable
		}
		if _, duplicate := seen[header.DID]; duplicate {
			continue
		}
		seen[header.DID] = struct{}{}
		dids = append(dids, header.DID)
	}
	sort.Strings(dids)
	return dids, nil
}
