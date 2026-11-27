package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

var ErrPublicationSettings = errors.New("publication settings apply refused")

type PublicationSettingsRequest struct {
	Vault         [32]byte
	FloorRevision uint64
	Configuration config.Config
	Record        []byte
	Backend       syncengine.SettingsBackend
	Journal       *publicationstate.Journal
	ExpectedPlan  [32]byte
	Barrier       func(publicationstate.SettingsJournalEntry) error
}

type PublicationSettingsOperation struct {
	TargetID string
	SchemaID string
	Path     string
	Key      string
	Reset    bool
	Value    syncengine.SettingValue
}

type PublicationSettingsPlan struct {
	Operations []PublicationSettingsOperation
	Changes    int
	Digest     [32]byte
}

type PublicationSettingsEntry struct {
	TargetID string
	SchemaID string
	Path     string
	Key      string
	Reset    bool
	State    publicationstate.JournalState
}

type PublicationSettingsReport struct {
	Applied   int
	Unchanged int
	Entries   []PublicationSettingsEntry
}

func PlanPublicationSettings(
	ctx context.Context,
	request PublicationSettingsRequest,
) (PublicationSettingsPlan, error) {
	plan := PublicationSettingsPlan{Operations: make([]PublicationSettingsOperation, 0)}
	if request.Backend == nil || request.Vault == ([32]byte{}) {
		return plan, ErrPublicationSettings
	}
	record, err := publication.DecodeSnapshot(request.Record)
	if err != nil || record.Vault != request.Vault {
		return plan, ErrPublicationSettings
	}
	for _, segment := range record.Segments {
		if segment.Form != publication.SegmentFormSettings {
			continue
		}
		configured, ok := publicationSettingsTarget(request.Configuration, segment.Target.ID)
		if !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return plan, err
		}
		approved, err := publicationApprovedSettingKeys(configured)
		if err != nil {
			return plan, ErrPublicationSettings
		}
		for _, setting := range segment.Settings {
			identity := setting.SchemaID + "\x00" + setting.Key
			if _, permitted := approved[identity]; !permitted {
				return plan, ErrPublicationSettings
			}
			operation, err := publicationSettingsOperation(ctx, request.Backend, segment.Target.ID, setting)
			if err != nil {
				return plan, ErrPublicationSettings
			}
			observed, observeErr := request.Backend.Observe(ctx, publicationSettingEntryKey(operation))
			if observeErr != nil {
				return plan, ErrPublicationSettings
			}
			switch {
			case operation.Reset && observed.Present:
				plan.Changes++
			case !operation.Reset && !publicationSettingMatches(observed, operation.Value):
				plan.Changes++
			}
			plan.Operations = append(plan.Operations, operation)
		}
	}
	plan.Digest = publicationSettingsPlanDigest(plan.Operations)
	return plan, nil
}

func ApplyPublicationSettings(
	ctx context.Context,
	request PublicationSettingsRequest,
) (PublicationSettingsReport, error) {
	report := PublicationSettingsReport{Entries: make([]PublicationSettingsEntry, 0)}
	if request.Backend == nil || request.Journal == nil || request.Vault == ([32]byte{}) {
		return report, ErrPublicationSettings
	}
	plan, err := PlanPublicationSettings(ctx, request)
	if err != nil {
		return report, err
	}
	if request.ExpectedPlan != ([32]byte{}) && plan.Digest != request.ExpectedPlan {
		return report, ErrPublicationSettings
	}
	lease, err := request.Journal.AcquireApplyLease(ctx)
	if err != nil {
		return report, err
	}
	defer func() { _ = lease.Close() }()
	if err := request.Journal.CheckSettingsAdmission(ctx, request.FloorRevision); err != nil {
		return report, err
	}
	for _, operation := range plan.Operations {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		key := publicationSettingEntryKey(operation)
		observed, observeErr := request.Backend.Observe(ctx, key)
		if observeErr != nil {
			return report, ErrPublicationSettings
		}
		entry := PublicationSettingsEntry{
			TargetID: operation.TargetID, SchemaID: operation.SchemaID, Path: operation.Path,
			Key: operation.Key, Reset: operation.Reset,
		}
		if operation.Reset && !observed.Present {
			entry.State = publicationstate.JournalStateApplied
			report.Unchanged++
			report.Entries = append(report.Entries, entry)
			continue
		}
		if !operation.Reset && publicationSettingMatches(observed, operation.Value) {
			entry.State = publicationstate.JournalStateApplied
			report.Unchanged++
			report.Entries = append(report.Entries, entry)
			continue
		}
		journalEntry, journalErr := request.Journal.BeginSettingsJournal(
			ctx,
			publicationstate.SettingsJournalIntent{
				Vault: request.Vault,
				Anchor: publicationstate.SettingsJournalAnchor{
					TargetID: operation.TargetID, SchemaID: operation.SchemaID,
					Path: operation.Path, Key: operation.Key,
				},
				Prior:             publicationSettingsJournalValue(observed),
				Written:           publicationSettingsJournalValue(operation.Value),
				SeenFloorRevision: request.FloorRevision,
			},
		)
		if journalErr != nil {
			return report, journalErr
		}
		if request.Barrier != nil {
			if err := request.Barrier(journalEntry); err != nil {
				return report, err
			}
		}
		if err := publicationSettingsMutate(ctx, request.Backend, key, operation); err != nil {
			_ = request.Journal.FailSettingsJournal(ctx, journalEntry)
			return report, ErrPublicationSettings
		}
		written, verifyErr := request.Backend.Observe(ctx, key)
		if verifyErr != nil || !publicationSettingMatches(written, operation.Value) {
			_ = request.Journal.MarkSettingsIndeterminate(ctx, journalEntry)
			return report, ErrPublicationSettings
		}
		if err := request.Journal.CompleteSettingsJournal(
			ctx, journalEntry, publicationSettingsJournalValue(written),
		); err != nil {
			return report, err
		}
		entry.State = publicationstate.JournalStateApplied
		report.Applied++
		report.Entries = append(report.Entries, entry)
	}
	return report, nil
}

func publicationSettingsMutate(
	ctx context.Context,
	backend syncengine.SettingsBackend,
	key model.EntryKey,
	operation PublicationSettingsOperation,
) error {
	if operation.Reset {
		return backend.Reset(ctx, key)
	}
	return backend.Set(ctx, key, operation.Value.Type, operation.Value.Text)
}

func publicationSettingsJournalValue(value syncengine.SettingValue) publicationstate.SettingsValue {
	return publicationstate.SettingsValue{Present: value.Present, Type: value.Type, Text: value.Text}
}

func publicationSettingMatches(observed, written syncengine.SettingValue) bool {
	if observed.Present != written.Present {
		return false
	}
	if !observed.Present {
		return true
	}
	return observed.Type == written.Type && observed.Text == written.Text
}

func publicationSettingIdentity(operation PublicationSettingsOperation) string {
	return operation.TargetID + "\x00" + operation.SchemaID + "\x00" + operation.Path + "\x00" + operation.Key
}

func publicationSettingEntryKey(operation PublicationSettingsOperation) model.EntryKey {
	return model.EntryKey{
		TargetID: operation.TargetID, Source: model.SourceGNOME,
		SchemaID: operation.SchemaID, SettingsPath: operation.Path, SettingKey: operation.Key,
	}
}

func publicationSettingsTarget(configuration config.Config, targetID string) (config.Target, bool) {
	for _, target := range configuration.Targets {
		if target.ID == targetID && target.Source == model.SourceGNOME && target.GNOMEPolicy != nil {
			return target, true
		}
	}
	return config.Target{}, false
}

func publicationApprovedSettingKeys(target config.Target) (map[string]struct{}, error) {
	policy := target.GNOMEPolicy
	if policy == nil || policy.Approval != config.GNOMEApprovalApproved ||
		policy.MatrixVersion != matrix.Version {
		return nil, ErrPublicationSettings
	}
	keys, err := matrix.SelectCategories(policy.Categories)
	if err != nil || len(keys) == 0 {
		return nil, ErrPublicationSettings
	}
	digest, err := matrix.KeySetDigest(keys)
	if err != nil || hex.EncodeToString(digest[:]) != policy.KeyDigest {
		return nil, ErrPublicationSettings
	}
	approved := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		approved[key.SchemaID+"\x00"+key.Key] = struct{}{}
	}
	return approved, nil
}

func publicationSettingsOperation(
	ctx context.Context,
	backend syncengine.SettingsBackend,
	targetID string,
	setting publication.SnapshotSetting,
) (PublicationSettingsOperation, error) {
	operation := PublicationSettingsOperation{
		TargetID: targetID, SchemaID: setting.SchemaID, Path: setting.Path, Key: setting.Key,
	}
	if setting.State == model.SettingReset {
		if setting.Value != nil {
			return PublicationSettingsOperation{}, ErrPublicationSettings
		}
		operation.Reset = true
		return operation, nil
	}
	if setting.State != model.SettingPresent || setting.Value == nil {
		return PublicationSettingsOperation{}, ErrPublicationSettings
	}
	canonical, err := backend.Canonicalize(
		ctx, publicationSettingEntryKey(operation), setting.Value.Type, setting.Value.Text,
	)
	if err != nil || !canonical.Present || canonical.Type == "" {
		return PublicationSettingsOperation{}, ErrPublicationSettings
	}
	operation.Value = canonical
	return operation, nil
}

func publicationSettingsPlanDigest(operations []PublicationSettingsOperation) [32]byte {
	digest := sha256.New()
	var scratch [8]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint64(scratch[:], uint64(len(value)))
		_, _ = digest.Write(scratch[:])
		_, _ = digest.Write([]byte(value))
	}
	ordered := append([]PublicationSettingsOperation(nil), operations...)
	sort.Slice(ordered, func(left, right int) bool {
		return publicationSettingIdentity(ordered[left]) < publicationSettingIdentity(ordered[right])
	})
	for _, operation := range ordered {
		writeField(operation.TargetID)
		writeField(operation.SchemaID)
		writeField(operation.Path)
		writeField(operation.Key)
		if operation.Reset {
			writeField("reset")
			continue
		}
		writeField("present")
		writeField(operation.Value.Type)
		writeField(operation.Value.Text)
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func PublicationSettingsTargets(
	recordRaw []byte,
	configuration config.Config,
) ([]model.Target, error) {
	if len(recordRaw) == 0 {
		return nil, nil
	}
	record, err := publication.DecodeSnapshot(recordRaw)
	if err != nil {
		return nil, ErrPublicationSettings
	}
	targets := make([]model.Target, 0)
	for _, segment := range record.Segments {
		if segment.Form != publication.SegmentFormSettings {
			continue
		}
		if _, ok := publicationSettingsTarget(configuration, segment.Target.ID); !ok {
			continue
		}
		targets = append(targets, segment.Target)
	}
	return targets, nil
}
