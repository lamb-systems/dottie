package service

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

var ErrPushBlocked = errors.New("push refused because reconciliation has unresolved entries")

type PushBlockedError struct {
	Identities []model.EntryKey
}

func (e *PushBlockedError) Error() string {
	return fmt.Sprintf("%v: %s", ErrPushBlocked, formatEntryIdentities(e.Identities))
}

func (e *PushBlockedError) Unwrap() error { return ErrPushBlocked }

type publicationBaseSource func(ctx context.Context, target config.Target, portable model.Target) ([]model.Entry, syncengine.BaseStatus, []model.EntryKey, error)

type publicationRemoteSource func(target config.Target) ([]model.Entry, []model.EntryKey)

type publicationLocalSource func(target config.Target, entries []model.Entry) []model.Entry

func (coordinator *Coordinator) composePublicationSnapshot(
	ctx context.Context,
	configuration config.Config,
	base publicationBaseSource,
	remote publicationRemoteSource,
	blocked []model.EntryKey,
) (model.Snapshot, []config.Target, error) {
	return coordinator.composePublicationSnapshotWithLocal(ctx, configuration, base, remote, nil, blocked)
}

func (coordinator *Coordinator) composePublicationSnapshotWithLocal(
	ctx context.Context,
	configuration config.Config,
	base publicationBaseSource,
	remote publicationRemoteSource,
	local publicationLocalSource,
	blocked []model.EntryKey,
) (model.Snapshot, []config.Target, error) {
	candidate := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: make([]model.Target, 0, len(configuration.Targets)),
	}
	composed := make([]config.Target, 0, len(configuration.Targets))
	blocked = append([]model.EntryKey(nil), blocked...)
	for _, target := range configuration.Targets {
		portable, err := targetFromConfig(target)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		candidate.Targets = append(candidate.Targets, portable)
		_, localEntries, unknown, coverage, err := coordinator.captureLocal(ctx, target)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		if local != nil {
			localEntries = local(target, localEntries)
		}
		baseEntries, baseStatus, baseUntracked, err := base(ctx, target, portable)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		untracked := baseUntracked
		remoteEntries, remoteUntracked := remote(target)
		untracked = append(untracked, remoteUntracked...)
		binding, err := syncengine.NewTargetBinding(portable)
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		plan, err := syncengine.Reconcile(syncengine.BaseView{Entries: baseEntries, Status: baseStatus},
			syncengine.LocalView{Entries: localEntries, Unknown: unknown, Untracked: untracked, Coverage: coverage},
			remoteEntries, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
		if err != nil {
			return model.Snapshot{}, nil, err
		}
		composed = append(composed, target)
		for _, decision := range plan.Decisions {
			switch decision.Action {
			case syncengine.ActionConflict, syncengine.ActionBlocked:
				blocked = append(blocked, decision.Key)
			case syncengine.ActionUpload, syncengine.ActionUnchanged:
				if decision.Local != nil && !entryIsFileTombstone(*decision.Local) {
					candidate.Entries = append(candidate.Entries, *decision.Local)
				}
			case syncengine.ActionDownload:
				if decision.Remote != nil && !entryIsFileTombstone(*decision.Remote) {
					candidate.Entries = append(candidate.Entries, *decision.Remote)
				}
			case syncengine.ActionDeleteLocal, syncengine.ActionDeleteRemote:
			default:
				return model.Snapshot{}, nil, errors.New("reconciliation produced an unsupported push action")
			}
		}
	}
	if len(blocked) != 0 {
		return model.Snapshot{}, nil, newPushBlockedError(blocked)
	}
	if err := candidate.Validate(); err != nil {
		return model.Snapshot{}, nil, fmt.Errorf("validate publication snapshot: %w", err)
	}
	return candidate, composed, nil
}

func entryIsFileTombstone(entry model.Entry) bool {
	return entry.File != nil && entry.File.State == model.FileDeleted
}

func newPushBlockedError(identities []model.EntryKey) error {
	unique := make(map[model.EntryKey]struct{}, len(identities))
	ordered := make([]model.EntryKey, 0, len(identities))
	for _, identity := range identities {
		if _, exists := unique[identity]; exists {
			continue
		}
		unique[identity] = struct{}{}
		ordered = append(ordered, identity)
	}
	sort.Slice(ordered, func(i, j int) bool {
		left := identitySortKey(ordered[i])
		right := identitySortKey(ordered[j])
		return left < right
	})
	return &PushBlockedError{Identities: ordered}
}

func identitySortKey(identity model.EntryKey) string {
	return identity.TargetID + "\x00" + string(
		identity.Source,
	) + "\x00" + identity.FilePath + "\x00" + identity.SchemaID + "\x00" + identity.SettingsPath + "\x00" + identity.SettingKey
}

func formatEntryIdentities(identities []model.EntryKey) string {
	parts := make([]string, 0, len(identities))
	for _, identity := range identities {
		if identity.Source == model.SourceFiles {
			parts = append(parts, fmt.Sprintf("%s/%s:%s", identity.TargetID, identity.Source, identity.FilePath))
		} else {
			parts = append(
				parts,
				fmt.Sprintf(
					"%s/%s:%s:%s:%s",
					identity.TargetID,
					identity.Source,
					identity.SchemaID,
					identity.SettingsPath,
					identity.SettingKey,
				),
			)
		}
	}
	return fmt.Sprintf("%v", parts)
}
