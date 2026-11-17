package service

import (
	"context"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

var (
	ErrPublicationReaderInput    = errors.New("publication reader configuration is incomplete")
	ErrPublicationReaderIdentity = errors.New("publication reader refuses the configured identity")
	ErrPublicationReaderAccepted = errors.New("publication reader refuses the accepted publication")
)

type PublicationReaderConfig struct {
	Binding publicationstate.Binding
	DID     string
	Session *atproto.Session
	Adapter *ATProtoMaterialTransport
	Blobs   atproto.VaultReader
}

type PublicationReader struct {
	binding publicationstate.Binding
	did     string
	session *atproto.Session
	adapter *ATProtoMaterialTransport
	blobs   atproto.VaultReader
}

type AcceptedPublication struct {
	View    publicationstate.SuppliedRepositoryView
	Payload publication.Payload
}

func NewPublicationReader(config PublicationReaderConfig) (*PublicationReader, error) {
	reader := &PublicationReader{
		binding: config.Binding, did: config.DID, session: config.Session,
		adapter: config.Adapter, blobs: config.Blobs,
	}
	if reader.did == "" || reader.session == nil || reader.adapter == nil || reader.blobs.Transport == nil {
		return nil, ErrPublicationReaderInput
	}
	return reader, nil
}

func (reader *PublicationReader) ReadView(ctx context.Context) (publicationstate.SuppliedRepositoryView, error) {
	if err := reader.authorize(); err != nil {
		return publicationstate.SuppliedRepositoryView{}, err
	}
	return reader.adapter.ReadView(ctx)
}

func (reader *PublicationReader) ReadAcceptedPayload(ctx context.Context) (AcceptedPublication, error) {
	view, err := reader.ReadView(ctx)
	if err != nil {
		return AcceptedPublication{}, err
	}
	if len(view.Head) == 0 || len(view.Snapshots) == 0 {
		return AcceptedPublication{}, errors.Join(ErrPublicationReaderAccepted, atproto.ErrReadRecordMissing)
	}
	selected := view.Snapshots[len(view.Snapshots)-1]
	record, err := publication.DecodeSnapshot(selected.Raw)
	if err != nil {
		return AcceptedPublication{}, errors.Join(ErrPublicationReaderAccepted, err)
	}
	payload, err := publication.ResolvePayload(
		record,
		publicationReaderPayloadLimits(),
		func(reference publication.BlobReference) ([]byte, error) {
			return reader.blobs.FetchBlob(ctx, reader.did, reference.CID, int64(reference.Size))
		},
	)
	if err != nil {
		return AcceptedPublication{}, errors.Join(ErrPublicationReaderAccepted, err)
	}
	return AcceptedPublication{View: view, Payload: payload}, nil
}

func publicationReaderPayloadLimits() publication.PayloadLimits {
	limits := publicationstate.DefaultAttemptLimits()
	return publication.PayloadLimits{
		MaxEntries:    int(limits.ManagedObjects),
		MaxEntryBytes: uint64(publicationApplyMaxObservedBytes),
		MaxTotalBytes: limits.CustodyBytes,
	}
}

func (reader *PublicationReader) authorize() error {
	if reader == nil || reader.session == nil || reader.adapter == nil || reader.blobs.Transport == nil {
		return ErrPublicationReaderInput
	}
	if err := reader.adapter.join(); err != nil {
		return err
	}
	if reader.did != reader.adapter.did || reader.binding != reader.adapter.binding ||
		reader.session.DID != reader.did {
		return ErrPublicationReaderIdentity
	}
	return reader.session.RequirePublicationScopes()
}
