package atproto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/platform"
)

const sessionListTestClientID = "https://dottie.test/client-metadata.json"

type sessionListTestStore struct {
	items    map[string][]byte
	names    []string
	listErr  error
	saves    int
	deletes  int
	loadsErr error
}

func newSessionListTestStore() *sessionListTestStore {
	return &sessionListTestStore{items: map[string][]byte{}}
}

func (s *sessionListTestStore) Save(_ context.Context, name string, payload []byte) error {
	s.saves++
	s.items[name] = append([]byte(nil), payload...)
	return nil
}

func (s *sessionListTestStore) Load(_ context.Context, name string) ([]byte, error) {
	if s.loadsErr != nil {
		return nil, s.loadsErr
	}
	payload, ok := s.items[name]
	if !ok {
		return nil, platform.ErrKeyringItemNotFound
	}
	return append([]byte(nil), payload...), nil
}

func (s *sessionListTestStore) Delete(_ context.Context, name string) error {
	s.deletes++
	delete(s.items, name)
	return nil
}

func (s *sessionListTestStore) ListItems(_ context.Context, prefix string) ([]string, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	if len(s.names) > 0 {
		return append([]string(nil), s.names...), nil
	}
	names := make([]string, 0, len(s.items))
	for name := range s.items {
		if len(prefix) <= len(name) && name[:len(prefix)] == prefix {
			names = append(names, name)
		}
	}
	return names, nil
}

func (s *sessionListTestStore) add(t *testing.T, did string) string {
	t.Helper()
	name := sessionItemName(sessionListTestClientID, did)
	s.items[name] = []byte(`{"version":1,"did":"` + did + `"}`)
	return name
}

type plainSessionStore struct{}

func (plainSessionStore) Save(context.Context, string, []byte) error { return nil }
func (plainSessionStore) Load(context.Context, string) ([]byte, error) {
	return nil, platform.ErrKeyringItemNotFound
}
func (plainSessionStore) Delete(context.Context, string) error { return nil }

func newSessionListTestClient(t *testing.T, store SessionStore) *Client {
	t.Helper()
	client, err := NewClient(sessionListTestClientID, store)
	require.NoError(t, err)
	return client
}

func TestListSessionDIDsReportsEveryDistinctStoredAccount(t *testing.T) {
	store := newSessionListTestStore()
	first := store.add(t, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
	second := store.add(t, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
	client := newSessionListTestClient(t, store)
	dids, err := client.ListSessionDIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"}, dids)
	assert.Len(t, store.items, 2, "listing changed the stored sessions")
	assert.Zero(t, store.saves, "listing saved a session")
	assert.Zero(t, store.deletes, "listing deleted a session")
	assert.NotEmpty(t, store.items[first])
	assert.NotEmpty(t, store.items[second])
}

func TestListSessionDIDsReportsNoAccountForAnEmptyStore(t *testing.T) {
	client := newSessionListTestClient(t, newSessionListTestStore())
	dids, err := client.ListSessionDIDs(context.Background())
	require.NoError(t, err)
	assert.Empty(t, dids)
}

func TestListSessionDIDsCountsOneAccountPerDIDWhenAnItemIsListedTwice(t *testing.T) {
	store := newSessionListTestStore()
	name := store.add(t, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
	store.names = []string{name, name}
	client := newSessionListTestClient(t, store)
	dids, err := client.ListSessionDIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}, dids, "a duplicated item was counted as two accounts")
}

func TestListSessionDIDsRefusesAnUndecodableStoredItem(t *testing.T) {
	store := newSessionListTestStore()
	store.add(t, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
	store.items[sessionItemPrefix+"broken"] = []byte("not-json")
	client := newSessionListTestClient(t, store)
	dids, err := client.ListSessionDIDs(context.Background())
	assert.ErrorIs(t, err, ErrSessionUnavailable)
	assert.Empty(t, dids, "a partially readable store was read as an account count")
}

func TestListSessionDIDsRefusesAnItemWithoutADID(t *testing.T) {
	store := newSessionListTestStore()
	store.items[sessionItemPrefix+"unsigned"] = []byte(`{"version":1}`)
	client := newSessionListTestClient(t, store)
	dids, err := client.ListSessionDIDs(context.Background())
	assert.ErrorIs(t, err, ErrSessionUnavailable)
	assert.Empty(t, dids)
}

func TestListSessionDIDsRefusesAnItemNamedForAnotherDID(t *testing.T) {
	store := newSessionListTestStore()
	store.items[sessionItemName(sessionListTestClientID, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")] = []byte(`{"version":1,"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"}`)
	client := newSessionListTestClient(t, store)
	dids, err := client.ListSessionDIDs(context.Background())
	assert.ErrorIs(t, err, ErrSessionUnavailable)
	assert.Empty(t, dids)
}

func TestListSessionDIDsRefusesAStoreThatCannotList(t *testing.T) {
	client := newSessionListTestClient(t, plainSessionStore{})
	dids, err := client.ListSessionDIDs(context.Background())
	assert.ErrorIs(t, err, ErrSessionListingUnavailable)
	assert.Empty(t, dids)
}

func TestListSessionDIDsReportsTheKeyringFailureThatPreventedListing(t *testing.T) {
	store := newSessionListTestStore()
	store.listErr = platform.ErrKeyringLocked
	client := newSessionListTestClient(t, store)
	dids, err := client.ListSessionDIDs(context.Background())
	assert.ErrorIs(t, err, platform.ErrKeyringLocked)
	assert.Empty(t, dids)
}

func TestListSessionDIDsReportsAnUnreadableStoredItem(t *testing.T) {
	store := newSessionListTestStore()
	store.add(t, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
	store.loadsErr = platform.ErrKeyringUnavailable
	client := newSessionListTestClient(t, store)
	dids, err := client.ListSessionDIDs(context.Background())
	assert.ErrorIs(t, err, platform.ErrKeyringUnavailable)
	assert.Empty(t, dids)
}
