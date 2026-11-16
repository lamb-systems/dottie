package service

import (
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

var (
	ErrPublicationHeadInput    = errors.New("publication head configuration is incomplete")
	ErrPublicationHeadIdentity = errors.New("publication head reader refuses the configured identity")
	ErrPublicationHeadAbsent   = errors.New("the account publishes no v2 publication position")
)

type PublicationHeadConfig struct {
	DID     string
	Session *atproto.Session
	Reader  atproto.RevisionReader
}

func ReadPublishedHead(ctx context.Context, config PublicationHeadConfig) (publication.HeadRecord, error) {
	if ctx == nil || config.DID == "" || config.Session == nil || config.Reader.Transport == nil {
		return publication.HeadRecord{}, ErrPublicationHeadInput
	}
	if config.Reader.DIDDocumentID != config.DID || config.Session.DID != config.DID {
		return publication.HeadRecord{}, ErrPublicationHeadIdentity
	}
	if err := config.Session.RequirePublicationScopes(); err != nil {
		return publication.HeadRecord{}, err
	}
	if err := ctx.Err(); err != nil {
		return publication.HeadRecord{}, err
	}
	revision, err := config.Reader.Read(ctx, config.DID)
	if err != nil {
		return publication.HeadRecord{}, err
	}
	head, _, present, err := atprotoMaterialHead(revision)
	if err != nil {
		return publication.HeadRecord{}, err
	}
	if !present {
		return publication.HeadRecord{}, ErrPublicationHeadAbsent
	}
	return head, nil
}
