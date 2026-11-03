package syncengine

import (
	"errors"
	"fmt"
	"sort"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/vault"
)

type PreviewAction string

const (
	PreviewCreate PreviewAction = "create"
	PreviewChange PreviewAction = "change"
	PreviewDelete PreviewAction = "delete"
)

type PreviewState string

const (
	PreviewStateUnknown   PreviewState = "unknown"
	PreviewStateMissing   PreviewState = "missing"
	PreviewStateConflict  PreviewState = "conflict"
	PreviewStateUnchanged PreviewState = "unchanged"
	PreviewStateUnmatched PreviewState = "unmatched"
)

type PreviewReason string

const (
	PreviewReasonConflict           PreviewReason = "conflict"
	PreviewReasonMissing            PreviewReason = "missing"
	PreviewReasonUnknown            PreviewReason = "unknown"
	PreviewReasonUntracked          PreviewReason = "untracked"
	PreviewReasonCoverageIncomplete PreviewReason = "coverage-incomplete"
	PreviewReasonEqual              PreviewReason = "equal"
	PreviewReasonLocalChanged       PreviewReason = "local-changed"
	PreviewReasonRemoteChanged      PreviewReason = "remote-changed"
	PreviewReasonDivergence         PreviewReason = "divergence"
	PreviewReasonBaseMissing        PreviewReason = "base-missing"
	PreviewReasonStaleBase          PreviewReason = "stale-base"
	PreviewReasonBothDeleted        PreviewReason = "both-deleted"
	PreviewReasonStructural         PreviewReason = "structural"
	PreviewReasonEscapingSymlink    PreviewReason = "escaping-symlink"
	PreviewReasonUnmatched          PreviewReason = "unmatched"
)

type PreviewPreimage struct {
	Digest string `json:"digest"`
	Mode   uint32 `json:"mode"`
}

type PreviewEntry struct {
	Key            model.EntryKey   `json:"key"`
	Action         PreviewAction    `json:"action,omitempty"`
	DecisionAction Action           `json:"decision_action,omitempty"`
	State          PreviewState     `json:"state,omitempty"`
	Reason         PreviewReason    `json:"reason,omitempty"`
	Detail         string           `json:"detail,omitempty"`
	Size           int64            `json:"size"`
	SnapshotBytes  int64            `json:"resulting_snapshot_bytes"`
	Preimage       *PreviewPreimage `json:"preimage,omitempty"`
	Risks          []PreviewReason  `json:"risks,omitempty"`
}

type PreviewTarget struct {
	ID      string         `json:"id"`
	Entries []PreviewEntry `json:"entries"`
}

type Preview struct {
	Targets                []PreviewTarget `json:"targets"`
	TransferBytes          int64           `json:"transfer_bytes"`
	ResultingSnapshotBytes int64           `json:"resulting_snapshot_bytes"`
	Complete               bool            `json:"complete"`
	UnresolvedEntries      int             `json:"unresolved_entries"`
}

func BuildPreview(plan Plan, targets []model.Target, observations []model.Observation) (Preview, error) {
	targetsByID := make(map[string]model.Target, len(targets))
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return Preview{}, fmt.Errorf("invalid preview target: %w", err)
		}
		if _, exists := targetsByID[target.ID]; exists {
			return Preview{}, errors.New("duplicate preview target")
		}
		targetsByID[target.ID] = target
	}
	observationsByKey := make(map[model.EntryKey]model.Observation, len(observations))
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return Preview{}, fmt.Errorf("invalid preview observation: %w", err)
		}
		target, exists := targetsByID[observation.Identity.TargetID]
		if !exists || target.Source != observation.Identity.Source {
			return Preview{}, errors.New("preview observation has no matching target")
		}
		if _, exists := observationsByKey[observation.Identity]; exists {
			return Preview{}, errors.New("duplicate preview observation")
		}
		observationsByKey[observation.Identity] = observation
	}
	orderedTargets := make([]model.Target, 0, len(targetsByID))
	for _, target := range targetsByID {
		orderedTargets = append(orderedTargets, target)
	}
	sort.Slice(orderedTargets, func(i, j int) bool { return orderedTargets[i].ID < orderedTargets[j].ID })
	preview := Preview{Targets: make([]PreviewTarget, 0, len(orderedTargets)), Complete: true}
	previewIndex := make(map[string]int, len(orderedTargets))
	for _, target := range orderedTargets {
		previewIndex[target.ID] = len(preview.Targets)
		preview.Targets = append(preview.Targets, PreviewTarget{ID: target.ID, Entries: make([]PreviewEntry, 0)})
	}
	seenDecisions := make(map[model.EntryKey]struct{}, len(plan.Decisions))
	transferEntries := make([]model.Entry, 0, len(plan.Decisions))
	resultEntries := make([]model.Entry, 0, len(plan.Decisions))
	for _, decision := range plan.Decisions {
		if err := decision.Binding.Validate(); err != nil {
			return Preview{}, fmt.Errorf("invalid preview decision binding: %w", err)
		}
		key := decision.Key
		if err := key.Validate(); err != nil {
			return Preview{}, fmt.Errorf("invalid preview decision identity: %w", err)
		}
		target, exists := targetsByID[key.TargetID]
		if !exists || targetFingerprint(target) != decision.Binding.Fingerprint || target.Source != key.Source {
			return Preview{}, errors.New("preview decision has no matching target")
		}
		if _, exists := seenDecisions[key]; exists {
			return Preview{}, errors.New("duplicate preview decision")
		}
		seenDecisions[key] = struct{}{}
		observation, hasObservation := observationsByKey[key]
		if err := validateDecisionObservation(decision, observation, hasObservation); err != nil {
			return Preview{}, err
		}
		entry, transferEntry, resultEntry, unresolved := previewDecision(decision, observation, hasObservation)
		if unresolved {
			preview.Complete = false
			preview.UnresolvedEntries++
		}
		if hasObservation && observation.State == model.ObservationPresent {
			fingerprint := fingerprintEntry(*observation.Entry)
			entry.Preimage = &PreviewPreimage{Digest: fingerprint.Digest, Mode: fingerprint.Mode}
		}
		if transferEntry != nil {
			estimate, err := estimatePreviewEntry(target, *transferEntry)
			if err != nil {
				return Preview{}, err
			}
			entry.Size = estimate.PlaintextBytes
			if len(estimate.EscapingLinks) != 0 {
				entry.Risks = append(entry.Risks, PreviewReasonEscapingSymlink)
			}
			transferEntries = append(transferEntries, *transferEntry)
		}
		if resultEntry != nil {
			if transferEntry != nil && entriesEqual(transferEntry, resultEntry) {
				entry.SnapshotBytes = entry.Size
			} else {
				estimate, err := estimatePreviewEntry(target, *resultEntry)
				if err != nil {
					return Preview{}, err
				}
				entry.SnapshotBytes = estimate.PlaintextBytes
				if len(estimate.EscapingLinks) != 0 && !containsPreviewReason(entry.Risks, PreviewReasonEscapingSymlink) {
					entry.Risks = append(entry.Risks, PreviewReasonEscapingSymlink)
				}
			}
			resultEntries = append(resultEntries, *resultEntry)
		}
		preview.Targets[previewIndex[key.TargetID]].Entries = append(preview.Targets[previewIndex[key.TargetID]].Entries, entry)
	}
	unknownKeys := make(map[model.EntryKey]struct{})
	for _, decision := range plan.Decisions {
		if decision.States.Local == ValueUnknown {
			unknownKeys[decision.Key] = struct{}{}
		}
	}
	for key, observation := range observationsByKey {
		if _, exists := seenDecisions[key]; exists {
			continue
		}
		if observation.State != model.ObservationMissing {
			return Preview{}, errors.New("preview observation has no reconciliation decision")
		}
		state := PreviewStateMissing
		reason := PreviewReasonMissing
		if hasAncestor(key, unknownKeys) {
			state = PreviewStateUnknown
			reason = PreviewReasonUnknown
		}
		preview.Targets[previewIndex[key.TargetID]].Entries = append(preview.Targets[previewIndex[key.TargetID]].Entries, PreviewEntry{
			Key:    key,
			State:  state,
			Reason: reason,
			Detail: "unmatched",
		})
		preview.Complete = false
		preview.UnresolvedEntries++
	}
	for index := range preview.Targets {
		sort.Slice(preview.Targets[index].Entries, func(i, j int) bool {
			return keyLess(preview.Targets[index].Entries[i].Key, preview.Targets[index].Entries[j].Key)
		})
	}
	if len(transferEntries) != 0 {
		estimate, err := vault.Estimate(model.Snapshot{Version: model.SnapshotVersion, Targets: orderedTargets, Entries: transferEntries})
		if err != nil {
			return Preview{}, fmt.Errorf("estimate preview transfer size: %w", err)
		}
		preview.TransferBytes = estimate.PlaintextBytes
	}
	if len(resultEntries) != 0 {
		estimate, err := vault.Estimate(model.Snapshot{Version: model.SnapshotVersion, Targets: orderedTargets, Entries: resultEntries})
		if err != nil {
			return Preview{}, fmt.Errorf("estimate resulting snapshot size: %w", err)
		}
		preview.ResultingSnapshotBytes = estimate.PlaintextBytes
	}
	return preview, nil
}

func estimatePreviewEntry(target model.Target, entry model.Entry) (vault.SizeEstimate, error) {
	estimate, err := vault.Estimate(model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{target}, Entries: []model.Entry{entry}})
	if err != nil {
		return vault.SizeEstimate{}, fmt.Errorf("estimate preview entry size: %w", err)
	}
	return estimate, nil
}

func containsPreviewReason(reasons []PreviewReason, want PreviewReason) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func validateDecisionObservation(decision Decision, observation model.Observation, hasObservation bool) error {
	if !hasObservation {
		if decision.Local != nil {
			return errors.New("preview decision is missing its local observation")
		}
		return nil
	}
	switch observation.State {
	case model.ObservationPresent:
		if decision.Local == nil || !entriesEqual(decision.Local, observation.Entry) {
			return errors.New("preview observation does not match its reconciliation decision")
		}
		fingerprint := fingerprintEntry(*observation.Entry)
		if decision.Fingerprints.Local == nil || *decision.Fingerprints.Local != fingerprint {
			return errors.New("preview observation preimage does not match its reconciliation decision")
		}
	case model.ObservationMissing, model.ObservationUnknown, model.ObservationUntracked:
		if decision.Local != nil {
			return errors.New("non-present preview observation has a local reconciliation entry")
		}
	default:
		return errors.New("preview observation has an unsupported state")
	}
	return nil
}

func previewDecision(decision Decision, observation model.Observation, hasObservation bool) (PreviewEntry, *model.Entry, *model.Entry, bool) {
	entry := PreviewEntry{Key: decision.Key, DecisionAction: decision.Action}
	if decision.States.Local == ValueUnknown || (hasObservation && observation.State == model.ObservationUnknown) {
		entry.State = PreviewStateUnknown
		entry.Reason = PreviewReasonUnknown
		return entry, nil, nil, true
	}
	if decision.Action == ActionConflict {
		entry.State = PreviewStateConflict
		entry.Reason = PreviewReasonConflict
		entry.Detail = string(decision.Reason)
		return entry, nil, nil, true
	}
	if decision.States.Local == ValueKnownAbsent || (hasObservation && observation.State == model.ObservationMissing) {
		entry.State = PreviewStateMissing
		entry.Reason = PreviewReasonMissing
	}
	switch decision.Action {
	case ActionUpload:
		candidate := decision.Local
		if !presentEntry(candidate) {
			entry.State = PreviewStateUnmatched
			entry.Reason = PreviewReasonUnmatched
			entry.Detail = "non-present result entry"
			return entry, nil, nil, true
		}
		entry.Action = PreviewChange
		if decision.States.Base == ValueKnownAbsent {
			entry.Action = PreviewCreate
		}
		return withDecisionReason(entry, decision), candidate, candidate, false
	case ActionDownload:
		candidate := decision.Remote
		if !presentEntry(candidate) {
			entry.State = PreviewStateUnmatched
			entry.Reason = PreviewReasonUnmatched
			entry.Detail = "non-present result entry"
			return entry, nil, nil, true
		}
		entry.Action = PreviewChange
		if decision.States.Local == ValueKnownAbsent || (hasObservation && observation.State == model.ObservationMissing) {
			entry.Action = PreviewCreate
		}
		return withDecisionReason(entry, decision), candidate, candidate, false
	case ActionDeleteLocal, ActionDeleteRemote:
		entry.Action = PreviewDelete
		return withDecisionReason(entry, decision), nil, nil, false
	case ActionUnchanged:
		if entry.State == "" {
			entry.State = PreviewStateUnchanged
		}
		candidate := decision.Local
		if !presentEntry(candidate) && presentEntry(decision.Remote) {
			candidate = decision.Remote
		}
		if !presentEntry(candidate) {
			candidate = nil
		}
		return withDecisionReason(entry, decision), nil, candidate, false
	case ActionBlocked:
		switch decision.Reason {
		case ReasonUnknown:
			entry.State = PreviewStateUnknown
			entry.Reason = PreviewReasonUnknown
			entry.Detail = string(decision.Reason)
			return entry, nil, nil, true
		case ReasonUntracked:
			entry.Action = PreviewCreate
			entry.Reason = PreviewReasonUntracked
			candidate := decision.Remote
			if !presentEntry(candidate) {
				candidate = decision.Base
			}
			if !presentEntry(candidate) {
				entry.State = PreviewStateUnmatched
				entry.Reason = PreviewReasonUnmatched
				entry.Detail = "no resolved present entry"
				return entry, nil, nil, true
			}
			return entry, candidate, candidate, false
		case ReasonCoverage:
			if entry.State != PreviewStateMissing {
				entry.Reason = PreviewReasonCoverageIncomplete
			}
			entry.Detail = string(decision.Reason)
			return entry, nil, nil, true
		default:
			entry.State = PreviewStateUnmatched
			entry.Reason = PreviewReasonUnmatched
			entry.Detail = string(decision.Reason)
			return entry, nil, nil, true
		}
	default:
		entry.State = PreviewStateUnmatched
		entry.Reason = PreviewReasonUnmatched
		entry.Detail = string(decision.Reason)
		return entry, nil, nil, true
	}
}

func presentEntry(entry *model.Entry) bool {
	if entry == nil {
		return false
	}
	if entry.File != nil {
		return entry.File.State == model.FilePresent
	}
	return entry.Setting != nil && (entry.Setting.State == model.SettingPresent || entry.Setting.State == model.SettingReset)
}

func withDecisionReason(entry PreviewEntry, decision Decision) PreviewEntry {
	if entry.State == PreviewStateMissing {
		entry.Detail = string(decision.Reason)
		return entry
	}
	switch decision.Reason {
	case ReasonEqual:
		entry.Reason = PreviewReasonEqual
	case ReasonLocalChanged:
		entry.Reason = PreviewReasonLocalChanged
	case ReasonRemoteChanged:
		entry.Reason = PreviewReasonRemoteChanged
	case ReasonDivergence:
		entry.Reason = PreviewReasonDivergence
	case ReasonBaseMissing:
		entry.Reason = PreviewReasonBaseMissing
	case ReasonStaleBase:
		entry.Reason = PreviewReasonStaleBase
	case ReasonUnknown:
		entry.Reason = PreviewReasonUnknown
	case ReasonUntracked:
		entry.Reason = PreviewReasonUntracked
	case ReasonCoverage:
		entry.Reason = PreviewReasonCoverageIncomplete
	case ReasonBothDeleted:
		entry.Reason = PreviewReasonBothDeleted
	case ReasonStructural:
		entry.Reason = PreviewReasonStructural
	}
	return entry
}
