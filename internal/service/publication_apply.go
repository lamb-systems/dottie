package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

var ErrPublicationApply = errors.New("publication apply refused")

var errPublicationApplyAnchor = errors.New("apply anchor identity changed")

const (
	publicationApplyWriteOperation               = "apply"
	publicationApplyDeleteOperation              = "delete"
	publicationApplyFileMode         os.FileMode = 0o600
	publicationApplyMaxObservedBytes int64       = 8 << 20
)

type publicationApplyHookStage string

const (
	publicationApplyHookJournaled publicationApplyHookStage = "journaled"
	publicationApplyHookMutated   publicationApplyHookStage = "mutated"
	publicationApplyHookCompleted publicationApplyHookStage = "completed"
)

var publicationApplyStageHook func(publicationApplyHookStage)

func publicationApplyStageReached(stage publicationApplyHookStage) {
	if publicationApplyStageHook != nil {
		publicationApplyStageHook(stage)
	}
}

const (
	publicationApplyStageInput       publicationReconciliationStage = "apply"
	publicationApplyStageResolve     publicationReconciliationStage = "apply-resolve"
	publicationApplyStagePlan        publicationReconciliationStage = "apply-plan"
	publicationApplyStageObserve     publicationReconciliationStage = "apply-observe"
	publicationApplyStageMutate      publicationReconciliationStage = "apply-mutate"
	publicationApplyStageObservation publicationReconciliationStage = "apply-observation"

	publicationApplyReasonRequestInvalid    publicationReconciliationReason = "request_invalid"
	publicationApplyReasonSnapshotInvalid   publicationReconciliationReason = "snapshot_invalid"
	publicationApplyReasonCanceled          publicationReconciliationReason = "canceled"
	publicationApplyReasonJournal           publicationReconciliationReason = "journal_unavailable"
	publicationApplyReasonLease             publicationReconciliationReason = "apply_lease_held"
	publicationApplyReasonUnobserved        publicationReconciliationReason = "journal_unobserved"
	publicationApplyReasonIndeterminate     publicationReconciliationReason = "journal_indeterminate"
	publicationApplyReasonTargetUnsupported publicationReconciliationReason = "target_unsupported"
	publicationApplyReasonUntracked         publicationReconciliationReason = "untracked_projection"
	publicationApplyReasonCaptureIncomplete publicationReconciliationReason = "capture_incomplete"
	publicationApplyReasonBounds            publicationReconciliationReason = "bounds_exceeded"
	publicationApplyReasonPlanUnresolved    publicationReconciliationReason = "plan_unresolved"
	publicationApplyReasonConfirmation      publicationReconciliationReason = "confirmation_mismatch"
	publicationApplyReasonRoot              publicationReconciliationReason = "root_mismatch"
	publicationApplyReasonContainment       publicationReconciliationReason = "containment_refused"
	publicationApplyReasonParent            publicationReconciliationReason = "missing_parent"
	publicationApplyReasonUnreadable        publicationReconciliationReason = "destination_unreadable"
	publicationApplyReasonPreimage          publicationReconciliationReason = "preimage_changed"
	publicationApplyReasonOversized         publicationReconciliationReason = "oversized"
	publicationApplyReasonModeUnsupported   publicationReconciliationReason = "mode_unsupported"
	publicationApplyReasonBackupOnly        publicationReconciliationReason = "backup_only"
	publicationApplyReasonMutation          publicationReconciliationReason = "mutation_failed"
)

type publicationApplyError struct {
	stage        publicationReconciliationStage
	reason       publicationReconciliationReason
	entry        int64
	cancellation error
}

func (e *publicationApplyError) Error() string {
	if e.entry != 0 {
		return fmt.Sprintf("publication apply: %s/%s: journal entry %d", e.stage, e.reason, e.entry)
	}
	return "publication apply: " + string(e.stage) + "/" + string(e.reason)
}

func (e *publicationApplyError) Is(target error) bool {
	return target == ErrPublicationApply || (target != nil && target == e.cancellation)
}

func (e *publicationApplyError) Stage() string  { return string(e.stage) }
func (e *publicationApplyError) Reason() string { return string(e.reason) }

type PublicationApplyPhase string
type PublicationApplyOperation string

const (
	PublicationApplyJournaled PublicationApplyPhase = "journaled"
	PublicationApplyMutated   PublicationApplyPhase = "mutated"
)

const (
	PublicationApplyWrite     PublicationApplyOperation = "write"
	PublicationApplyDelete    PublicationApplyOperation = "delete"
	PublicationApplyUnchanged PublicationApplyOperation = "unchanged"
)

type PublicationApplyRequest struct {
	Journal         *publicationstate.Journal
	Vault           [32]byte
	FloorRevision   uint64
	Configuration   config.Config
	BaseSnapshot    model.Snapshot
	RemoteSnapshot  model.Snapshot
	Roots           map[string]string
	Local           *PublicationLocalContext
	FileSystem      files.ApplyFileSystem
	Barrier         func(PublicationApplyPhase, publicationstate.JournalEntry) error
	ExpectedPlan    [32]byte
	ApplyRemoteOnly bool
}

type PublicationApplyPlan struct {
	Entries []PublicationApplyPlanEntry
	Changes int
	Digest  [32]byte
}

type PublicationApplyPlanEntry struct {
	TargetID  string
	Path      string
	Operation PublicationApplyOperation
	Size      uint64
}

type PublicationApplyEntry struct {
	TargetID  string
	Path      string
	Operation PublicationApplyOperation
	Journal   int64
	State     publicationstate.JournalState
	Digest    [32]byte
	Size      uint64
	Mode      uint32
	Backup    *[32]byte
}

type PublicationApplyReport struct {
	Entries      []PublicationApplyEntry
	Applied      int
	Unchanged    int
	BytesWritten uint64
	Stopped      *PublicationApplyEntry
}

type publicationApplyCapturedPreimage struct {
	present bool
	digest  [32]byte
	mode    uint32
}

type publicationApplyOperation struct {
	targetID         string
	root             string
	key              string
	path             string
	kind             PublicationApplyOperation
	journalOperation string
	content          []byte
	mode             os.FileMode
	post             publicationstate.ObservedFile
	captured         publicationApplyCapturedPreimage
	anchor           publicationstate.JournalAnchor
	destinationDir   string
	destinationPath  string
}

type publicationApplyBoundFileSystem struct {
	files.ApplyFileSystem
	anchor publicationstate.JournalAnchor
}

func (bound publicationApplyBoundFileSystem) OpenRoot(path string) (files.ApplyRoot, error) {
	if path != bound.anchor.Path {
		return nil, errPublicationApplyAnchor
	}
	root, err := bound.ApplyFileSystem.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(".")
	if err != nil || !info.IsDir() {
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		return nil, errPublicationApplyAnchor
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Dev) != bound.anchor.Device || int64(stat.Ino) != bound.anchor.Inode {
		_ = root.Close()
		return nil, errPublicationApplyAnchor
	}
	return root, nil
}

func ApplyPublication(ctx context.Context, request PublicationApplyRequest) (PublicationApplyReport, error) {
	report := PublicationApplyReport{Entries: make([]PublicationApplyEntry, 0)}
	if err := validatePublicationApplyRequest(ctx, request); err != nil {
		return report, err
	}
	fileSystem := request.FileSystem
	if fileSystem == nil {
		fileSystem = files.DefaultApplyFileSystem()
	}
	lease, err := request.Journal.AcquireApplyLease(ctx)
	if err != nil {
		reason := publicationApplyReasonJournal
		if errors.Is(err, publicationstate.ErrLocked) {
			reason = publicationApplyReasonLease
		}
		return report, publicationApplyFailure(ctx, publicationApplyStageInput, reason, err)
	}
	defer func() { _ = lease.Close() }()

	resolutions, err := request.Journal.ResolveInterrupted(ctx, func(entry publicationstate.JournalEntry) (publicationstate.ObservedFile, error) {
		return observePublicationApplyEntry(fileSystem, entry)
	})
	if err != nil {
		return report, publicationApplyFailure(ctx, publicationApplyStageResolve, publicationApplyReasonJournal, err)
	}
	for _, resolution := range resolutions {
		switch resolution.Outcome {
		case publicationstate.JournalOutcomeUnobserved:
			return report, &publicationApplyError{stage: publicationApplyStageResolve, reason: publicationApplyReasonUnobserved, entry: resolution.Entry}
		case publicationstate.JournalOutcomeIndeterminate:
			return report, &publicationApplyError{stage: publicationApplyStageResolve, reason: publicationApplyReasonIndeterminate, entry: resolution.Entry}
		}
	}
	if err := request.Journal.CheckAdmission(ctx, request.FloorRevision); err != nil {
		return report, err
	}

	operations, err := planPublicationApply(ctx, request, fileSystem)
	if err != nil {
		return report, err
	}
	if request.ExpectedPlan != ([32]byte{}) && publicationApplyPlanDigest(operations) != request.ExpectedPlan {
		return report, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonConfirmation, nil)
	}
	for _, operation := range operations {
		if err := ctx.Err(); err != nil {
			return report, publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonCanceled, err)
		}
		entry, applyErr := applyPublicationOperation(ctx, request, fileSystem, operation)
		if applyErr != nil {
			stopped := entry
			report.Stopped = &stopped
			return report, applyErr
		}
		report.Entries = append(report.Entries, entry)
		if entry.Operation == PublicationApplyUnchanged {
			report.Unchanged++
			continue
		}
		report.Applied++
		report.BytesWritten += entry.Size
	}
	return report, nil
}

func PlanPublicationApply(ctx context.Context, request PublicationApplyRequest) (PublicationApplyPlan, error) {
	plan := PublicationApplyPlan{Entries: make([]PublicationApplyPlanEntry, 0)}
	if err := validatePublicationApplyPlanRequest(ctx, request); err != nil {
		return plan, err
	}
	fileSystem := request.FileSystem
	if fileSystem == nil {
		fileSystem = files.DefaultApplyFileSystem()
	}
	operations, err := planPublicationApply(ctx, request, fileSystem)
	if err != nil {
		return plan, err
	}
	plan.Digest = publicationApplyPlanDigest(operations)
	for _, operation := range operations {
		plan.Entries = append(plan.Entries, PublicationApplyPlanEntry{
			TargetID: operation.targetID, Path: operation.path, Operation: operation.kind, Size: operation.post.Size,
		})
		if operation.kind != PublicationApplyUnchanged {
			plan.Changes++
		}
	}
	return plan, nil
}

func publicationApplyPlanDigest(operations []publicationApplyOperation) [32]byte {
	digest := sha256.New()
	var scratch [8]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint64(scratch[:], uint64(len(value)))
		_, _ = digest.Write(scratch[:])
		_, _ = digest.Write([]byte(value))
	}
	for _, operation := range operations {
		writeField(operation.targetID)
		writeField(operation.path)
		writeField(string(operation.kind))
		_, _ = digest.Write(operation.post.Digest[:])
		binary.BigEndian.PutUint64(scratch[:], operation.post.Size)
		_, _ = digest.Write(scratch[:])
		if operation.captured.present {
			_, _ = digest.Write([]byte{1})
			_, _ = digest.Write(operation.captured.digest[:])
			var mode [4]byte
			binary.BigEndian.PutUint32(mode[:], operation.captured.mode)
			_, _ = digest.Write(mode[:])
		} else {
			_, _ = digest.Write([]byte{0})
		}
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func validatePublicationApplyRequest(ctx context.Context, request PublicationApplyRequest) error {
	if request.Journal == nil {
		return publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonRequestInvalid, nil)
	}
	return validatePublicationApplyPlanRequest(ctx, request)
}

func validatePublicationApplyPlanRequest(ctx context.Context, request PublicationApplyRequest) error {
	if ctx == nil || request.Local == nil || len(request.Configuration.Targets) == 0 || request.Roots == nil {
		return publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonRequestInvalid, nil)
	}
	if request.Vault == ([32]byte{}) {
		return publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonRequestInvalid, nil)
	}
	if request.Configuration.Version != config.Version || request.Configuration.Validate() != nil {
		return publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonRequestInvalid, nil)
	}
	if request.BaseSnapshot.Validate() != nil || request.RemoteSnapshot.Validate() != nil {
		return publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonSnapshotInvalid, nil)
	}
	if len(request.Configuration.Targets) > publicationSelectionMaxTargets {
		return publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonBounds, nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationApplyFailure(ctx, publicationApplyStageInput, publicationApplyReasonCanceled, err)
	}
	return nil
}

func planPublicationApply(ctx context.Context, request PublicationApplyRequest, fileSystem files.ApplyFileSystem) ([]publicationApplyOperation, error) {
	targets := append([]config.Target(nil), request.Configuration.Targets...)
	sort.Slice(targets, func(left, right int) bool { return targets[left].ID < targets[right].ID })
	operations := make([]publicationApplyOperation, 0)
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonCanceled, err)
		}
		if target.Source != model.SourceFiles || target.Root == nil {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonTargetUnsupported, nil)
		}
		portable, err := target.Model()
		if err != nil {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonTargetUnsupported, nil)
		}
		selection, err := selectPublicationTarget(ctx, request.Local, request.Configuration, target.ID, portable)
		if err != nil {
			return nil, err
		}
		root, ok := request.Roots[target.ID]
		if !ok || !filepath.IsAbs(root) || filepath.Clean(root) != root || root != selection.resolvedPath {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonRoot, nil)
		}
		anchor, ok := publicationstate.NewJournalAnchor(selection.anchorPath, selection.anchorInfo)
		if !ok {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonRoot, nil)
		}
		remote, err := projectPublicationSnapshot(selection, request.RemoteSnapshot)
		if err != nil {
			return nil, err
		}
		if len(remote.untracked) != 0 {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonUntracked, nil)
		}
		baseEntries, defined := publicationSnapshotTargetEntries(request.BaseSnapshot, target.ID)
		baseView := syncengine.BaseView{Status: syncengine.BaseMissing}
		if defined {
			baseView = syncengine.BaseView{Status: syncengine.BaseKnown, Entries: baseEntries}
		}
		captured, err := capturePublicationTarget(ctx, selection)
		if err != nil {
			return nil, err
		}
		if !captured.complete {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonCaptureIncomplete, nil)
		}
		localEntries, unknown := publicationBaseLocalEntries(captured)
		if len(unknown) != 0 {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonCaptureIncomplete, nil)
		}
		localView := syncengine.LocalView{Entries: localEntries, Coverage: []string{target.ID}}
		if !publicationBaseWithinBounds(baseEntries, localView, remote.entries, nil) {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonBounds, nil)
		}
		binding, err := syncengine.NewTargetBinding(selection.portable)
		if err != nil {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPlanUnresolved, err)
		}
		plan, err := syncengine.Reconcile(baseView, localView, remote.entries, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
		if err != nil {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPlanUnresolved, err)
		}
		preview, err := syncengine.BuildPreview(plan, []model.Target{selection.portable}, captured.observations)
		if err != nil {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPlanUnresolved, err)
		}
		if !preview.Complete || len(preview.Targets) != 1 {
			return nil, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPlanUnresolved, nil)
		}
		content := make(map[model.EntryKey]model.Entry, len(remote.entries))
		for _, entry := range remote.entries {
			content[entry.Identity()] = entry
		}
		for _, previewEntry := range preview.Targets[0].Entries {
			operation, err := publicationApplyOperationFor(ctx, request, fileSystem, selection, root, anchor, previewEntry, content)
			if err != nil {
				return nil, err
			}
			operations = append(operations, operation)
		}
	}
	sort.SliceStable(operations, func(left, right int) bool {
		if operations[left].targetID != operations[right].targetID {
			return operations[left].targetID < operations[right].targetID
		}
		return operations[left].path < operations[right].path
	})
	return operations, nil
}

func publicationApplyOperationFor(ctx context.Context, request PublicationApplyRequest, fileSystem files.ApplyFileSystem, selection publicationSelection, root string, anchor publicationstate.JournalAnchor, previewEntry syncengine.PreviewEntry, content map[model.EntryKey]model.Entry) (publicationApplyOperation, error) {
	path := previewEntry.Key.FilePath
	operation := publicationApplyOperation{targetID: previewEntry.Key.TargetID, root: root, path: path, anchor: anchor}
	switch previewEntry.DecisionAction {
	case syncengine.ActionUnchanged:
		operation.kind = PublicationApplyUnchanged
		operation.key = path
		return operation, nil
	case syncengine.ActionDownload:
		if selection.mode == config.BackupOnly {
			return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonBackupOnly, nil)
		}
		entry, ok := content[previewEntry.Key]
		if !ok || entry.File == nil || entry.File.State != model.FilePresent || entry.File.Kind != model.FileRegular {
			return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonTargetUnsupported, nil)
		}
		if entry.File.Mode != uint32(publicationApplyFileMode) {
			return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonModeUnsupported, nil)
		}
		operation.kind = PublicationApplyWrite
		operation.journalOperation = publicationApplyWriteOperation
		operation.content = append([]byte(nil), entry.File.Content...)
		operation.mode = publicationApplyFileMode
		operation.post = publicationstate.ObservedJournalFile(operation.content)
	case syncengine.ActionDeleteLocal:
		if selection.mode == config.BackupOnly {
			return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonBackupOnly, nil)
		}
		operation.kind = PublicationApplyDelete
		operation.journalOperation = publicationApplyDeleteOperation
		operation.post = publicationstate.ObservedFile{}
	case syncengine.ActionUpload, syncengine.ActionDeleteRemote:
		if !request.ApplyRemoteOnly {
			return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPlanUnresolved, nil)
		}
		operation.kind = PublicationApplyUnchanged
		operation.key = path
		return operation, nil
	default:
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPlanUnresolved, nil)
	}
	captured, err := publicationApplyCaptured(previewEntry)
	if err != nil {
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPlanUnresolved, err)
	}
	operation.captured = captured
	if operation.kind == PublicationApplyDelete && !captured.present {
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonPreimage, nil)
	}
	if operation.kind == PublicationApplyWrite && captured.present && captured.digest == operation.post.Digest && captured.mode != uint32(publicationApplyFileMode) {
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonModeUnsupported, nil)
	}
	destinationDir, destinationPath, err := publicationApplyDestination(selection, path)
	if err != nil {
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonContainment, err)
	}
	if destinationDir != anchor.Path {
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonContainment, nil)
	}
	if err := validatePublicationApplyDestination(destinationDir, destinationPath); err != nil {
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonContainment, err)
	}
	operation.destinationDir = destinationDir
	operation.destinationPath = destinationPath
	operation.key = path
	if selection.portable.Root.Kind == model.SelectionFile {
		operation.key = "."
	}
	if err := publicationApplyParents(fileSystem, root, operation.key); err != nil {
		return publicationApplyOperation{}, publicationApplyFailure(ctx, publicationApplyStagePlan, publicationApplyReasonParent, err)
	}
	return operation, nil
}

func publicationApplyCaptured(entry syncengine.PreviewEntry) (publicationApplyCapturedPreimage, error) {
	if entry.Preimage == nil {
		return publicationApplyCapturedPreimage{}, nil
	}
	digest, err := hex.DecodeString(entry.Preimage.Digest)
	if err != nil || len(digest) != sha256.Size {
		return publicationApplyCapturedPreimage{}, errors.New("captured preimage digest is invalid")
	}
	captured := publicationApplyCapturedPreimage{present: true, mode: entry.Preimage.Mode}
	copy(captured.digest[:], digest)
	return captured, nil
}

func publicationApplyDestination(selection publicationSelection, path string) (string, string, error) {
	root := selection.resolvedPath
	switch selection.portable.Root.Kind {
	case model.SelectionFile:
		if path != "." {
			return "", "", errors.New("single-file apply target only supports the root entry")
		}
		return filepath.Dir(root), filepath.Base(root), nil
	case model.SelectionDirectory:
		if path == "." {
			return "", "", errors.New("the selected directory itself is not an apply entry")
		}
		return root, path, nil
	default:
		return "", "", errors.New("apply target kind is unsupported")
	}
}

func validatePublicationApplyDestination(directory, path string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("apply destination directory is not absolute and clean")
	}
	if path == "" || path == "." || path == ".." || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		return errors.New("apply destination path is not a relative file name")
	}
	return nil
}

func publicationApplyParents(fileSystem files.ApplyFileSystem, root, key string) error {
	if key == "." {
		parent, err := fileSystem.Lstat(filepath.Dir(root))
		if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
			return errors.New("apply destination parent is not a real directory")
		}
		return nil
	}
	parts := strings.Split(key, "/")
	for index := 1; index < len(parts); index++ {
		parent, err := fileSystem.Lstat(filepath.Join(root, strings.Join(parts[:index], "/")))
		if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
			return errors.New("apply destination parent is not a real directory")
		}
	}
	return nil
}

func applyPublicationOperation(ctx context.Context, request PublicationApplyRequest, fileSystem files.ApplyFileSystem, operation publicationApplyOperation) (PublicationApplyEntry, error) {
	entry := PublicationApplyEntry{TargetID: operation.targetID, Path: operation.path, Operation: operation.kind, Digest: operation.post.Digest, Size: operation.post.Size, Mode: uint32(operation.mode.Perm())}
	if operation.kind == PublicationApplyUnchanged {
		return entry, nil
	}
	bound := publicationApplyBoundFileSystem{ApplyFileSystem: fileSystem, anchor: operation.anchor}
	observed, err := files.ObserveFileBounded(bound, operation.root, operation.key, publicationApplyMaxObservedBytes)
	if err != nil {
		return entry, publicationApplyFailure(ctx, publicationApplyStageObserve, publicationApplyObservationReason(err), err)
	}
	if publicationApplySettled(operation, observed) {
		entry.Operation = PublicationApplyUnchanged
		return entry, nil
	}
	if !publicationApplyCapturedMatches(operation.captured, observed) {
		return entry, publicationApplyFailure(ctx, publicationApplyStageObserve, publicationApplyReasonPreimage, nil)
	}
	preimage := publicationstate.ObservedFile{Present: true, Digest: operation.captured.digest, Size: uint64(len(observed.Data))}
	intent := publicationstate.JournalIntent{
		Vault:             request.Vault,
		Operation:         operation.journalOperation,
		DestinationDir:    operation.destinationDir,
		DestinationPath:   operation.destinationPath,
		Anchor:            operation.anchor,
		Postimage:         operation.post,
		SeenFloorRevision: request.FloorRevision,
	}
	if operation.captured.present {
		intent.Preimage = &preimage
		intent.PreimageBytes = observed.Data
	}
	written, err := request.Journal.BeginJournal(ctx, intent)
	if err != nil {
		return entry, err
	}
	entry.Journal = written.Entry
	entry.State = written.State
	entry.Backup = written.BackupDigest
	publicationApplyStageReached(publicationApplyHookJournaled)
	if request.Barrier != nil {
		if err := request.Barrier(PublicationApplyJournaled, written); err != nil {
			return entry, err
		}
	}
	if err := publicationApplyContainment(operation.anchor, written.DestinationDir, written.DestinationPath); err != nil {
		return publicationApplyIndeterminate(ctx, request.Journal, written, entry, publicationApplyFailure(ctx, publicationApplyStageMutate, publicationApplyReasonContainment, err))
	}
	expected := files.ExpectedPreimage{Exists: operation.captured.present, Digest: hex.EncodeToString(operation.captured.digest[:]), Mode: operation.captured.mode, Size: preimage.Size}
	if operation.kind == PublicationApplyDelete {
		err = files.DeleteFile(bound, operation.root, operation.key, expected)
	} else {
		err = files.ReplaceFile(bound, operation.root, operation.key, operation.content, operation.mode, expected)
	}
	if err != nil {
		return publicationApplyIndeterminate(ctx, request.Journal, written, entry, publicationApplyFailure(ctx, publicationApplyStageMutate, publicationApplyMutationReason(err), err))
	}
	publicationApplyStageReached(publicationApplyHookMutated)
	if request.Barrier != nil {
		if err := request.Barrier(PublicationApplyMutated, written); err != nil {
			return entry, err
		}
	}
	completed, err := files.ObserveFileBounded(bound, operation.root, operation.key, publicationApplyMaxObservedBytes)
	if err != nil {
		return publicationApplyIndeterminate(ctx, request.Journal, written, entry, publicationApplyFailure(ctx, publicationApplyStageObservation, publicationApplyObservationReason(err), err))
	}
	if err := request.Journal.CompleteJournal(ctx, written, publicationApplyObserved(completed)); err != nil {
		return publicationApplyIndeterminate(ctx, request.Journal, written, entry, err)
	}
	publicationApplyStageReached(publicationApplyHookCompleted)
	entry.State = publicationstate.JournalStateApplied
	return entry, nil
}

func publicationApplyIndeterminate(ctx context.Context, journal *publicationstate.Journal, written publicationstate.JournalEntry, entry PublicationApplyEntry, cause error) (PublicationApplyEntry, error) {
	if err := journal.MarkIndeterminate(ctx, written); err != nil {
		return entry, errors.Join(cause, err)
	}
	entry.State = publicationstate.JournalStateIndeterminate
	return entry, cause
}

func publicationApplyContainment(anchor publicationstate.JournalAnchor, directory, path string) error {
	if err := validatePublicationApplyDestination(directory, path); err != nil {
		return err
	}
	if directory != anchor.Path {
		return errors.New("journal destination is not the recorded apply anchor")
	}
	if !publicationPathWithin(anchor.Path, filepath.Join(directory, path)) {
		return errors.New("journal destination escapes the apply root")
	}
	return nil
}

func publicationApplySettled(operation publicationApplyOperation, observed files.ApplyObservation) bool {
	switch operation.kind {
	case PublicationApplyDelete:
		return !observed.Exists
	case PublicationApplyWrite:
		if !observed.Exists {
			return false
		}
		return sha256.Sum256(observed.Data) == operation.post.Digest && uint64(len(observed.Data)) == operation.post.Size
	default:
		return true
	}
}

func publicationApplyCapturedMatches(captured publicationApplyCapturedPreimage, observed files.ApplyObservation) bool {
	if !captured.present {
		return !observed.Exists
	}
	if !observed.Exists {
		return false
	}
	return observed.Digest == hex.EncodeToString(captured.digest[:]) && observed.Mode == captured.mode
}

func publicationApplyObservationReason(err error) publicationReconciliationReason {
	var oversized *files.ObservationLimitError
	if errors.As(err, &oversized) {
		return publicationApplyReasonOversized
	}
	if errors.Is(err, errPublicationApplyAnchor) {
		return publicationApplyReasonContainment
	}
	return publicationApplyReasonUnreadable
}

func publicationApplyMutationReason(err error) publicationReconciliationReason {
	if errors.Is(err, errPublicationApplyAnchor) {
		return publicationApplyReasonContainment
	}
	return publicationApplyReasonMutation
}

func publicationApplyObserved(observation files.ApplyObservation) publicationstate.ObservedFile {
	if !observation.Exists {
		return publicationstate.ObservedFile{}
	}
	return publicationstate.ObservedFile{Present: true, Digest: sha256.Sum256(observation.Data), Size: uint64(len(observation.Data))}
}

func observePublicationApplyEntry(fileSystem files.ApplyFileSystem, entry publicationstate.JournalEntry) (publicationstate.ObservedFile, error) {
	if entry.DestinationDir != entry.Anchor.Path {
		return publicationstate.ObservedFile{}, errors.New("journal destination is not the recorded anchor")
	}
	bound := publicationApplyBoundFileSystem{ApplyFileSystem: fileSystem, anchor: entry.Anchor}
	observed, err := files.ObserveFileBounded(bound, entry.Anchor.Path, entry.DestinationPath, publicationApplyMaxObservedBytes)
	if err != nil {
		return publicationstate.ObservedFile{}, err
	}
	return publicationApplyObserved(observed), nil
}

func publicationApplyFailure(ctx context.Context, stage publicationReconciliationStage, reason publicationReconciliationReason, cause error) error {
	cancellation := error(nil)
	if ctx != nil {
		if err := ctx.Err(); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			cancellation = err
		}
	}
	if cancellation == nil {
		if errors.Is(cause, context.Canceled) {
			cancellation = context.Canceled
		} else if errors.Is(cause, context.DeadlineExceeded) {
			cancellation = context.DeadlineExceeded
		}
	}
	if cancellation != nil {
		reason = publicationApplyReasonCanceled
	}
	return &publicationApplyError{stage: stage, reason: reason, cancellation: cancellation}
}
