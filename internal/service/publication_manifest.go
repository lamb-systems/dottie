package service

import (
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
)

var ErrManifestPublication = errors.New("manifest publication refused")

type manifestPublicationReason string

const (
	manifestPublicationReasonEntry       manifestPublicationReason = "entry_not_representable"
	manifestPublicationReasonSnapshot    manifestPublicationReason = "snapshot_not_representable"
	manifestPublicationReasonCount       manifestPublicationReason = "entry_count"
	manifestPublicationReasonUnavailable manifestPublicationReason = "publish_unavailable"
)

type manifestPublicationError struct {
	reason manifestPublicationReason
	entry  model.EntryKey
	detail string
	count  int
	limit  int
	cause  error
}

func (e *manifestPublicationError) Error() string {
	switch e.reason {
	case manifestPublicationReasonEntry:
		return fmt.Sprintf(
			"%v: %s cannot be represented as a manifest entry (%s)",
			ErrManifestPublication,
			formatEntryIdentity(e.entry),
			e.detail,
		)
	case manifestPublicationReasonSnapshot:
		return fmt.Sprintf(
			"%v: the publication cannot be represented as a manifest (%s)",
			ErrManifestPublication,
			e.detail,
		)
	case manifestPublicationReasonCount:
		return fmt.Sprintf(
			"%v: %d entries exceed the %d-entry limit of a manifest publication",
			ErrManifestPublication,
			e.count,
			e.limit,
		)
	default:
		return fmt.Sprintf("%v: publishing a manifest payload is not available in this build", ErrManifestPublication)
	}
}

func (e *manifestPublicationError) Is(target error) bool { return target == ErrManifestPublication }

func (e *manifestPublicationError) Unwrap() error { return e.cause }

func checkManifestPublication(configuration config.Config, snapshot model.Snapshot) error {
	if !configuration.HasManifestTarget() {
		return nil
	}
	if len(snapshot.Entries) > publication.MaxSnapshotEntries {
		return &manifestPublicationError{
			reason: manifestPublicationReasonCount,
			count:  len(snapshot.Entries),
			limit:  publication.MaxSnapshotEntries,
		}
	}
	if _, err := publication.SnapshotEntries(snapshot); err != nil {
		return manifestPublicationProjectionRefusal(err)
	}
	return &manifestPublicationError{reason: manifestPublicationReasonUnavailable}
}

func manifestPublicationProjectionRefusal(err error) error {
	refusal := &manifestPublicationError{reason: manifestPublicationReasonSnapshot, cause: err}
	if entryErr, ok := errors.AsType[*publication.ManifestEntryError](err); ok {
		refusal.reason = manifestPublicationReasonEntry
		refusal.entry = entryErr.Entry
		refusal.detail = entryErr.Field + ": " + entryErr.Reason
		return refusal
	}
	if violationErr, ok := errors.AsType[*publication.ViolationError](err); ok {
		refusal.detail = violationErr.Field() + ": " + violationErr.Reason()
	}
	return refusal
}
