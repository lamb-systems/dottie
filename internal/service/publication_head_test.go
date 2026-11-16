package service

import (
	"context"
	"errors"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func publicationHeadConfig(repository *atprotoMaterialRepository, session *atproto.Session) PublicationHeadConfig {
	return PublicationHeadConfig{DID: atprotoMaterialDID, Session: session, Reader: repository.reader()}
}

func TestReadPublishedHeadReturnsTheVaultTheAccountPublishes(t *testing.T) {
	ctx := context.Background()
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	repository.setRecords(t, atprotoMaterialGenesisRecords(t, binding))
	session := &atproto.Session{DID: atprotoMaterialDID, Scopes: atproto.VaultScopes()}

	head, err := ReadPublishedHead(ctx, publicationHeadConfig(repository, session))
	require.NoError(t, err)
	assert.Equal(t, binding.Vault, head.Vault)
	assert.Equal(t, uint64(0), head.PublicationSeq)
	assert.Equal(t, publication.SchemaVersion, head.SchemaVersion)
}

func TestReadPublishedHeadRefusesAnAccountWithNoPublication(t *testing.T) {
	ctx := context.Background()
	repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	repository.setRecords(t, map[atproto.RecordKey][]byte{})
	session := &atproto.Session{DID: atprotoMaterialDID, Scopes: atproto.VaultScopes()}

	head, err := ReadPublishedHead(ctx, publicationHeadConfig(repository, session))
	require.ErrorIs(t, err, ErrPublicationHeadAbsent)
	assert.Equal(t, publication.HeadRecord{}, head)
	assert.Equal(t, 0, repository.uploadCount())
	assert.Equal(t, 0, repository.applyCount())
}

func TestReadPublishedHeadValidatesTheRecordItAdopts(t *testing.T) {
	ctx := context.Background()
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	session := &atproto.Session{DID: atprotoMaterialDID, Scopes: atproto.VaultScopes()}

	legacyRepository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	legacyRecords := atprotoMaterialGenesisRecords(t, binding)
	legacy, err := atprototest.BuildRecord(atproto.VaultHeadNSID, "self", map[string]any{"schemaVersion": int64(1)})
	require.NoError(t, err)
	legacyRecords[atproto.RecordKey{Collection: atproto.VaultHeadNSID, RKey: "self"}] = legacy.Data
	legacyRepository.setRecords(t, legacyRecords)
	legacyHead, legacyErr := ReadPublishedHead(ctx, publicationHeadConfig(legacyRepository, session))
	requireATProtoMaterialRefusal(t, legacyErr, ErrATProtoMaterialView, "legacy_profile")
	assert.Equal(t, publication.HeadRecord{}, legacyHead)

	detachedRepository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	detached := atprotoMaterialGenesisRecords(t, binding)
	delete(detached, atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey})
	detachedRepository.setRecords(t, detached)
	_, detachedErr := ReadPublishedHead(ctx, publicationHeadConfig(detachedRepository, session))
	require.ErrorIs(t, detachedErr, ErrPublicationHeadAbsent)

	misplacedRepository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	genesis := atprotoMaterialGenesisRecords(t, binding)
	misplaced := make(map[atproto.RecordKey][]byte, len(genesis))
	for key, data := range genesis {
		misplaced[key] = data
	}
	misplaced[atproto.RecordKey{Collection: publication.HeadNSID, RKey: "current"}] = genesis[atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey}]
	misplacedRepository.setRecords(t, misplaced)
	_, misplacedErr := ReadPublishedHead(ctx, publicationHeadConfig(misplacedRepository, session))
	requireATProtoMaterialRefusal(t, misplacedErr, ErrATProtoMaterialView, "head_key")
}

func TestReadPublishedHeadRefusesAnUnboundIdentityOrScopeSet(t *testing.T) {
	ctx := context.Background()
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
	repository.setRecords(t, atprotoMaterialGenesisRecords(t, binding))

	otherDID := "did:plc:zyxwvutsrqponmlkjihgfedc"
	for _, test := range []struct {
		name    string
		config  PublicationHeadConfig
		class   error
		reason  string
		network bool
	}{
		{name: "session-account-differs", config: PublicationHeadConfig{
			DID: atprotoMaterialDID, Session: &atproto.Session{DID: otherDID, Scopes: atproto.VaultScopes()}, Reader: repository.reader(),
		}, class: ErrPublicationHeadIdentity},
		{name: "document-id-differs", config: PublicationHeadConfig{
			DID: atprotoMaterialDID, Session: &atproto.Session{DID: atprotoMaterialDID, Scopes: atproto.VaultScopes()}, Reader: repository.readerFor(otherDID),
		}, class: ErrPublicationHeadIdentity},
		{name: "incomplete-configuration", config: PublicationHeadConfig{
			DID: atprotoMaterialDID, Session: nil, Reader: repository.reader(),
		}, class: ErrPublicationHeadInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			head, err := ReadPublishedHead(ctx, test.config)
			require.ErrorIs(t, err, test.class)
			assert.Equal(t, publication.HeadRecord{}, head)
		})
	}

	scopeless := make([]string, 0, len(atproto.VaultScopes()))
	for _, scope := range atproto.VaultScopes() {
		if scope == "repo:"+publication.HeadNSID || scope == "repo:"+publication.SnapshotNSID {
			continue
		}
		scopeless = append(scopeless, scope)
	}
	head, err := ReadPublishedHead(ctx, PublicationHeadConfig{
		DID: atprotoMaterialDID, Session: &atproto.Session{DID: atprotoMaterialDID, Scopes: scopeless}, Reader: repository.reader(),
	})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrPublicationHeadAbsent))
	assert.Equal(t, publication.HeadRecord{}, head)
}
