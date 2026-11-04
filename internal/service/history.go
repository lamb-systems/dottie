package service

import (
	"context"
	"errors"
	"sort"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const (
	HistoryRemoteNotRequested HistoryRemoteStatus = "not-requested"
	HistoryRemoteVerified     HistoryRemoteStatus = "verified"
	HistoryRemoteUnavailable  HistoryRemoteStatus = "unavailable"
	HistoryRemoteAuthExpired  HistoryRemoteStatus = "auth-expired"
	maxHistoryVaults                              = 64
)

type HistoryRemoteStatus string

type HistoryReport struct {
	Targets     []HistoryTargetSummary
	Checkpoints []HistoryCheckpointSummary
	Remote      HistoryRemoteSummary
}

type HistoryTargetSummary struct {
	ID                  string
	JournalCount        int64
	JournalCounts       []state.JournalHistoryCount
	LatestJournalState  string
	LatestJournalReason string
	AppliedBaseCount    int64
	AppliedBaseRecorded int64
	AppliedBaseDigest   string
}

type HistoryCheckpointSummary struct {
	Vault        [32]byte
	Anchor       [32]byte
	Epoch        uint64
	PolicyDigest [32]byte
	RecordedAt   int64
}

type HistoryRemoteSummary struct {
	Status           HistoryRemoteStatus
	Epoch            uint64
	HeadCID          string
	PublicationCount uint64
	PolicyDigest     [32]byte
	Freshness        atproto.FreshnessStatus
	Currency         vault.CheckpointOutcome
}

func (coordinator *Coordinator) History(ctx context.Context, requested VaultSelection, checkRemote bool) (HistoryReport, error) {
	if err := coordinator.lock(ctx); err != nil {
		return HistoryReport{}, err
	}
	defer coordinator.mu.Unlock()
	if coordinator.deps.Config == nil || coordinator.deps.State == nil {
		return HistoryReport{}, errors.New("history coordinator ports are unavailable")
	}
	configuration, err := coordinator.deps.Config.Load(ctx)
	if err != nil {
		return HistoryReport{}, err
	}
	if err := configuration.Validate(); err != nil {
		return HistoryReport{}, err
	}
	local, err := coordinator.deps.State.LocalHistorySummaries(ctx, state.MaxLocalHistoryTargets)
	if err != nil {
		return HistoryReport{}, err
	}
	byTarget := make(map[string]state.LocalHistorySummary, len(local))
	for _, summary := range local {
		byTarget[summary.TargetID] = summary
	}
	targetIDs := make(map[string]struct{}, len(local)+len(configuration.Targets))
	for _, target := range configuration.Targets {
		targetIDs[target.ID] = struct{}{}
	}
	for _, summary := range local {
		targetIDs[summary.TargetID] = struct{}{}
	}
	if len(targetIDs) > state.MaxLocalHistoryTargets {
		return HistoryReport{}, errors.New("local history target limit exceeded")
	}
	orderedTargets := make([]string, 0, len(targetIDs))
	for targetID := range targetIDs {
		orderedTargets = append(orderedTargets, targetID)
	}
	sort.Strings(orderedTargets)
	report := HistoryReport{
		Targets: make([]HistoryTargetSummary, 0, len(orderedTargets)),
		Remote:  HistoryRemoteSummary{Status: HistoryRemoteNotRequested},
	}
	for _, targetID := range orderedTargets {
		summary := byTarget[targetID]
		report.Targets = append(report.Targets, HistoryTargetSummary{
			ID: targetID, JournalCount: summary.JournalCount, JournalCounts: append([]state.JournalHistoryCount(nil), summary.JournalCounts...),
			LatestJournalState: summary.LatestJournalState, LatestJournalReason: summary.LatestJournalStage,
			AppliedBaseCount: summary.AppliedBaseCount, AppliedBaseRecorded: summary.AppliedBaseRecorded, AppliedBaseDigest: summary.AppliedBaseDigest,
		})
	}
	selections, err := coordinator.deps.State.VaultSelectionsBounded(ctx, maxHistoryVaults)
	if err != nil {
		return HistoryReport{}, err
	}
	seenVaults := make(map[[32]byte]bool, len(selections))
	for _, selection := range selections {
		if requested.Vault != ([32]byte{}) && selection.Vault != requested.Vault || requested.DeviceID != "" && selection.DeviceID != requested.DeviceID || seenVaults[selection.Vault] {
			continue
		}
		checkpoint, checkpointErr := coordinator.deps.State.VaultCheckpoint(ctx, selection.Vault)
		if checkpointErr != nil {
			if errors.Is(checkpointErr, state.ErrVaultCheckpointNotFound) {
				continue
			}
			return HistoryReport{}, checkpointErr
		}
		report.Checkpoints = append(report.Checkpoints, historyCheckpoint(checkpoint))
		seenVaults[selection.Vault] = true
	}
	if requested.Vault != ([32]byte{}) && !seenVaults[requested.Vault] {
		checkpoint, checkpointErr := coordinator.deps.State.VaultCheckpoint(ctx, requested.Vault)
		if checkpointErr == nil {
			report.Checkpoints = append(report.Checkpoints, historyCheckpoint(checkpoint))
		} else if !errors.Is(checkpointErr, state.ErrVaultCheckpointNotFound) {
			return HistoryReport{}, checkpointErr
		}
	}
	sort.Slice(report.Checkpoints, func(i, j int) bool {
		return string(report.Checkpoints[i].Vault[:]) < string(report.Checkpoints[j].Vault[:])
	})
	if !checkRemote {
		return report, nil
	}
	pulled, readErr := coordinator.pullLocked(ctx, requested)
	if readErr != nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		report.Remote.Status = historyRemoteStatus(readErr)
		return report, nil
	}
	head, err := cid.Cast(pulled.Read.HeadCID)
	if err != nil {
		report.Remote.Status = HistoryRemoteUnavailable
		return report, nil
	}
	report.Remote = HistoryRemoteSummary{
		Status: HistoryRemoteVerified, Epoch: pulled.Read.EpochSeq, HeadCID: head.String(),
		PublicationCount: pulled.Read.PublicationCount, PolicyDigest: mustPolicyDigestBytes(pulled.Read),
		Freshness: pulled.Freshness, Currency: pulled.Currency.Outcome,
	}
	return report, nil
}

func historyCheckpoint(checkpoint state.VaultCheckpoint) HistoryCheckpointSummary {
	return HistoryCheckpointSummary{
		Vault: checkpoint.Vault, Anchor: checkpoint.Anchor, Epoch: checkpoint.Epoch,
		PolicyDigest: checkpoint.PolicyDigest, RecordedAt: checkpoint.RecordedAt,
	}
}

func historyRemoteStatus(err error) HistoryRemoteStatus {
	if errors.Is(err, atproto.ErrAuthMethodSession) || errors.Is(err, atproto.ErrAuthMethodToken) ||
		errors.Is(err, atproto.ErrSessionUnavailable) || errors.Is(err, atproto.ErrSessionRefreshPending) || errors.Is(err, atproto.ErrSessionNotFound) {
		return HistoryRemoteAuthExpired
	}
	return HistoryRemoteUnavailable
}
