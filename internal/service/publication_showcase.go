package service

import (
	"errors"
	"fmt"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
)

var ErrShowcasePublication = errors.New("showcase publication refused")

type showcasePublicationReason string

const (
	showcasePublicationReasonEntry       showcasePublicationReason = "entry_not_representable"
	showcasePublicationReasonSnapshot    showcasePublicationReason = "snapshot_not_representable"
	showcasePublicationReasonCount       showcasePublicationReason = "entry_count"
	showcasePublicationReasonUnavailable showcasePublicationReason = "publish_unavailable"
)

type showcasePublicationError struct {
	reason showcasePublicationReason
	entry  model.EntryKey
	detail string
	count  int
	limit  int
	cause  error
}

func (e *showcasePublicationError) Error() string {
	switch e.reason {
	case showcasePublicationReasonEntry:
		return fmt.Sprintf(
			"%v: %s cannot be represented as a showcase entry (%s)",
			ErrShowcasePublication,
			formatEntryIdentity(e.entry),
			e.detail,
		)
	case showcasePublicationReasonSnapshot:
		return fmt.Sprintf(
			"%v: the publication cannot be represented as a showcase manifest (%s)",
			ErrShowcasePublication,
			e.detail,
		)
	case showcasePublicationReasonCount:
		return fmt.Sprintf(
			"%v: %d entries exceed the %d-entry limit of a showcase publication",
			ErrShowcasePublication,
			e.count,
			e.limit,
		)
	default:
		return fmt.Sprintf("%v: publishing a showcase payload is not available in this build", ErrShowcasePublication)
	}
}

func (e *showcasePublicationError) Is(target error) bool { return target == ErrShowcasePublication }

func (e *showcasePublicationError) Unwrap() error { return e.cause }

func checkShowcasePublication(configuration config.Config, snapshot model.Snapshot) error {
	if !configuration.HasShowcaseTarget() {
		return nil
	}
	if len(snapshot.Entries) > publication.MaxSnapshotEntries {
		return &showcasePublicationError{
			reason: showcasePublicationReasonCount,
			count:  len(snapshot.Entries),
			limit:  publication.MaxSnapshotEntries,
		}
	}
	if _, err := publication.SnapshotEntries(snapshot); err != nil {
		return showcasePublicationProjectionRefusal(err)
	}
	return &showcasePublicationError{reason: showcasePublicationReasonUnavailable}
}

func showcasePublicationProjectionRefusal(err error) error {
	refusal := &showcasePublicationError{reason: showcasePublicationReasonSnapshot, cause: err}
	if entryErr, ok := errors.AsType[*publication.ShowcaseEntryError](err); ok {
		refusal.reason = showcasePublicationReasonEntry
		refusal.entry = entryErr.Entry
		refusal.detail = entryErr.Field + ": " + entryErr.Reason
		return refusal
	}
	if violationErr, ok := errors.AsType[*publication.ViolationError](err); ok {
		refusal.detail = violationErr.Field() + ": " + violationErr.Reason()
	}
	return refusal
}
