package syncengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/lamb-systems/dottie/internal/model"
)

type BaseStatus string

const (
	BaseKnown   BaseStatus = "known"
	BaseMissing BaseStatus = "missing"
	BaseStale   BaseStatus = "stale"
)

type BaseView struct {
	Entries []model.Entry
	Status  BaseStatus
}

type LocalView struct {
	Entries   []model.Entry
	Unknown   []model.EntryKey
	Untracked []model.EntryKey
	Coverage  []string
}

type TargetBinding struct {
	Target      model.Target
	Fingerprint string
}

type Options struct {
	Bindings []TargetBinding
}

type Action string

const (
	ActionUnchanged    Action = "unchanged"
	ActionUpload       Action = "upload"
	ActionDownload     Action = "download"
	ActionDeleteRemote Action = "delete-remote"
	ActionDeleteLocal  Action = "delete-local"
	ActionConflict     Action = "conflict"
	ActionBlocked      Action = "blocked"
)

type Reason string

const (
	ReasonEqual         Reason = "equal"
	ReasonLocalChanged  Reason = "local-changed"
	ReasonRemoteChanged Reason = "remote-changed"
	ReasonDivergence    Reason = "divergence"
	ReasonBaseMissing   Reason = "base-missing"
	ReasonStaleBase     Reason = "stale-base"
	ReasonUnknown       Reason = "unknown"
	ReasonUntracked     Reason = "untracked"
	ReasonCoverage      Reason = "coverage-incomplete"
	ReasonBothDeleted   Reason = "both-deleted"
	ReasonStructural    Reason = "structural"
)

type Fingerprint struct {
	State      string
	Kind       model.FileKind
	Mode       uint32
	LinkTarget string
	ValueType  string
	ValueText  string
	Size       int64
	Digest     string
}

type FingerprintSet struct {
	Base   *Fingerprint
	Local  *Fingerprint
	Remote *Fingerprint
}

type ValueState string

const (
	ValuePresent      ValueState = "present"
	ValueTombstone    ValueState = "tombstone"
	ValueSettingReset ValueState = "setting-reset"
	ValueKnownAbsent  ValueState = "known-absent"
	ValueUnknown      ValueState = "unknown"
	ValueUntracked    ValueState = "untracked"
)

type SideStates struct {
	Base   ValueState
	Local  ValueState
	Remote ValueState
}

type Decision struct {
	Key          model.EntryKey
	Action       Action
	Reason       Reason
	States       SideStates
	Binding      TargetBinding
	Fingerprints FingerprintSet
	Base         *model.Entry
	Local        *model.Entry
	Remote       *model.Entry
}

type Plan struct {
	Decisions []Decision
}

type DiagnosticDecision struct {
	Key          model.EntryKey `json:"key"`
	Action       Action         `json:"action"`
	Reason       Reason         `json:"reason"`
	BaseDigest   string         `json:"base_digest,omitempty"`
	LocalDigest  string         `json:"local_digest,omitempty"`
	RemoteDigest string         `json:"remote_digest,omitempty"`
}

type Diagnostic struct {
	Decisions []DiagnosticDecision `json:"decisions"`
}

func NewTargetBinding(target model.Target) (TargetBinding, error) {
	if err := target.Validate(); err != nil {
		return TargetBinding{}, fmt.Errorf("invalid target binding: %w", err)
	}
	target = cloneTarget(target)
	return TargetBinding{Target: target, Fingerprint: targetFingerprint(target)}, nil
}

func (b TargetBinding) Validate() error {
	if err := b.Target.Validate(); err != nil {
		return fmt.Errorf("invalid target binding: %w", err)
	}
	if b.Fingerprint == "" || b.Fingerprint != targetFingerprint(b.Target) {
		return errors.New("target binding fingerprint does not match target")
	}
	return nil
}

func Reconcile(base BaseView, local LocalView, remote []model.Entry, opts Options) (Plan, error) {
	bindings, err := validateBindings(opts.Bindings)
	if err != nil {
		return Plan{}, err
	}
	if base.Status != BaseKnown && base.Status != BaseMissing && base.Status != BaseStale {
		return Plan{}, errors.New("unsupported base status")
	}
	if base.Status == BaseMissing && len(base.Entries) != 0 {
		return Plan{}, errors.New("missing base cannot contain entries")
	}
	baseEntries, err := entryMap(base.Entries, "base", bindings)
	if err != nil {
		return Plan{}, err
	}
	localEntries, err := entryMap(local.Entries, "local", bindings)
	if err != nil {
		return Plan{}, err
	}
	remoteEntries, err := entryMap(remote, "remote", bindings)
	if err != nil {
		return Plan{}, err
	}
	unknown, err := keySet(local.Unknown, "unknown", bindings)
	if err != nil {
		return Plan{}, err
	}
	untracked, err := keySet(local.Untracked, "untracked", bindings)
	if err != nil {
		return Plan{}, err
	}
	for key := range unknown {
		if _, ok := untracked[key]; ok {
			return Plan{}, errors.New("local key cannot be both unknown and untracked")
		}
		if _, ok := localEntries[key]; ok {
			return Plan{}, errors.New("local key cannot be both present and unknown")
		}
	}
	for key := range untracked {
		if _, ok := localEntries[key]; ok {
			return Plan{}, errors.New("local key cannot be both present and untracked")
		}
	}
	coverage, err := targetSet(local.Coverage, bindings)
	if err != nil {
		return Plan{}, err
	}
	keys := make(map[model.EntryKey]struct{}, len(baseEntries)+len(localEntries)+len(remoteEntries)+len(unknown)+len(untracked))
	for _, entries := range []map[model.EntryKey]model.Entry{baseEntries, localEntries, remoteEntries} {
		for key := range entries {
			keys[key] = struct{}{}
		}
	}
	for key := range unknown {
		keys[key] = struct{}{}
	}
	for key := range untracked {
		keys[key] = struct{}{}
	}
	ordered := sortedKeys(keys)
	plan := Plan{Decisions: make([]Decision, 0, len(ordered))}
	for _, key := range ordered {
		binding := bindings[key.TargetID]
		baseEntry, hasBase := baseEntries[key]
		localEntry, hasLocal := localEntries[key]
		remoteEntry, hasRemote := remoteEntries[key]
		basePtr := entryPointer(baseEntry, hasBase)
		localPtr := entryPointer(localEntry, hasLocal)
		remotePtr := entryPointer(remoteEntry, hasRemote)
		localState, blockReason := classifyLocalState(key, localPtr, unknown, untracked)
		decision := Decision{
			Key:          key,
			States:       SideStates{Base: classifyEntry(basePtr), Local: localState, Remote: classifyEntry(remotePtr)},
			Binding:      cloneBinding(binding),
			Fingerprints: fingerprintSet(basePtr, localPtr, remotePtr),
			Base:         cloneEntryPointer(basePtr),
			Local:        cloneEntryPointer(localPtr),
			Remote:       cloneEntryPointer(remotePtr),
		}
		if blockReason != "" {
			decision.Action = ActionBlocked
			decision.Reason = blockReason
			plan.Decisions = append(plan.Decisions, decision)
			continue
		}
		decision.Action, decision.Reason = decide(base.Status, basePtr, localPtr, remotePtr, key.Source)
		if decision.Action == ActionDeleteLocal || decision.Action == ActionDeleteRemote {
			if _, covered := coverage[key.TargetID]; !covered {
				decision.Action = ActionBlocked
				decision.Reason = ReasonCoverage
			}
		}
		plan.Decisions = append(plan.Decisions, decision)
	}
	applyStructuralConflicts(&plan)
	return plan, nil
}

func (p Plan) Diagnostic() Diagnostic {
	diagnostic := Diagnostic{Decisions: make([]DiagnosticDecision, 0, len(p.Decisions))}
	for _, decision := range p.Decisions {
		item := DiagnosticDecision{Key: decision.Key, Action: decision.Action, Reason: decision.Reason}
		if decision.Fingerprints.Base != nil {
			item.BaseDigest = decision.Fingerprints.Base.Digest
		}
		if decision.Fingerprints.Local != nil {
			item.LocalDigest = decision.Fingerprints.Local.Digest
		}
		if decision.Fingerprints.Remote != nil {
			item.RemoteDigest = decision.Fingerprints.Remote.Digest
		}
		diagnostic.Decisions = append(diagnostic.Decisions, item)
	}
	return diagnostic
}

func EncodeDiagnostic(plan Plan) ([]byte, error) {
	return json.Marshal(plan.Diagnostic())
}

func decide(status BaseStatus, base, local, remote *model.Entry, source model.SourceKind) (Action, Reason) {
	if status == BaseMissing {
		return decideWithoutBase(local, remote, source)
	}
	if entriesEqual(local, remote) {
		return ActionUnchanged, ReasonEqual
	}
	localChanged := !entriesEqual(local, base)
	remoteChanged := !entriesEqual(remote, base)
	var action Action
	var reason Reason
	if localChanged && !remoteChanged {
		if status == BaseStale && sideDeleted(local, source) {
			action, reason = ActionConflict, ReasonStaleBase
		} else if sideDeleted(local, source) {
			action, reason = ActionDeleteRemote, ReasonLocalChanged
		} else {
			action, reason = ActionUpload, ReasonLocalChanged
		}
	} else if !localChanged && remoteChanged {
		if status == BaseStale && sideDeleted(remote, source) {
			action, reason = ActionConflict, ReasonStaleBase
		} else if sideDeleted(remote, source) {
			action, reason = ActionDeleteLocal, ReasonRemoteChanged
		} else {
			action, reason = ActionDownload, ReasonRemoteChanged
		}
	} else if localChanged && remoteChanged {
		if status == BaseStale {
			action, reason = ActionConflict, ReasonStaleBase
		} else {
			action, reason = ActionConflict, ReasonDivergence
		}
	} else {
		return ActionUnchanged, ReasonEqual
	}
	if bothFileDeleted(local, remote, source) {
		return ActionUnchanged, ReasonBothDeleted
	}
	return action, reason
}

func decideWithoutBase(local, remote *model.Entry, source model.SourceKind) (Action, Reason) {
	if entriesEqual(local, remote) {
		return ActionUnchanged, ReasonEqual
	}
	if bothFileDeleted(local, remote, source) {
		return ActionUnchanged, ReasonBothDeleted
	}
	if local == nil && remote != nil {
		return ActionDownload, ReasonBaseMissing
	}
	if remote == nil && local != nil {
		return ActionUpload, ReasonBaseMissing
	}
	return ActionConflict, ReasonBaseMissing
}

func entriesEqual(left, right *model.Entry) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if left.TargetID != right.TargetID || (left.File == nil) != (right.File == nil) {
		return false
	}
	if left.File != nil {
		a, b := left.File, right.File
		if a.State != b.State || a.Kind != b.Kind || a.Mode != b.Mode || a.LinkTarget != b.LinkTarget {
			return false
		}
		if a.State == model.FilePresent && a.Kind == model.FileRegular {
			leftDigest := sha256.Sum256(a.Content)
			rightDigest := sha256.Sum256(b.Content)
			return leftDigest == rightDigest
		}
		return true
	}
	a, b := left.Setting, right.Setting
	if a.SchemaID != b.SchemaID || a.Path != b.Path || a.Key != b.Key || a.State != b.State {
		return false
	}
	if a.Value == nil || b.Value == nil {
		return a.Value == nil && b.Value == nil
	}
	return a.Value.Type == b.Value.Type && a.Value.Text == b.Value.Text
}

func sideDeleted(entry *model.Entry, source model.SourceKind) bool {
	if entry == nil {
		return true
	}
	return source == model.SourceFiles && entry.File != nil && entry.File.State == model.FileDeleted
}

func bothFileDeleted(local, remote *model.Entry, source model.SourceKind) bool {
	return source == model.SourceFiles && sideDeleted(local, source) && sideDeleted(remote, source)
}

func classifyEntry(entry *model.Entry) ValueState {
	if entry == nil {
		return ValueKnownAbsent
	}
	if entry.File != nil {
		if entry.File.State == model.FileDeleted {
			return ValueTombstone
		}
		return ValuePresent
	}
	if entry.Setting.State == model.SettingReset {
		return ValueSettingReset
	}
	return ValuePresent
}

func classifyLocalState(key model.EntryKey, entry *model.Entry, unknown, untracked map[model.EntryKey]struct{}) (ValueState, Reason) {
	if hasAncestor(key, unknown) {
		return ValueUnknown, ReasonUnknown
	}
	if _, ok := untracked[key]; ok {
		return ValueUntracked, ReasonUntracked
	}
	return classifyEntry(entry), ""
}

func hasAncestor(key model.EntryKey, keys map[model.EntryKey]struct{}) bool {
	for ancestor := range keys {
		if ancestor.TargetID != key.TargetID || ancestor.Source != key.Source {
			continue
		}
		if ancestor == key {
			return true
		}
		if key.Source != model.SourceFiles {
			continue
		}
		if ancestor.FilePath == "." || strings.HasPrefix(key.FilePath, ancestor.FilePath+"/") {
			return true
		}
	}
	return false
}

func applyStructuralConflicts(plan *Plan) {
	marked := make(map[int]struct{})
	for parentIndex := range plan.Decisions {
		parent := &plan.Decisions[parentIndex]
		if parent.Key.Source != model.SourceFiles {
			continue
		}
		for side := 0; side < 2; side++ {
			parentResult, parentKnown := resultOnSide(*parent, side)
			if !parentKnown {
				continue
			}
			parentPresent := presentFile(parentResult)
			parentInvalid := parentPresent && parentResult.File.Kind != model.FileDirectory
			parentRemoved := !parentPresent && anyPresent(parent.Base, parent.Local, parent.Remote)
			if !parentInvalid && !parentRemoved {
				continue
			}
			for childIndex := range plan.Decisions {
				child := &plan.Decisions[childIndex]
				if child.Key.TargetID != parent.Key.TargetID || child.Key.Source != model.SourceFiles || !isDescendantPath(child.Key.FilePath, parent.Key.FilePath) {
					continue
				}
				childResult, childKnown := resultOnSide(*child, side)
				if childKnown && presentFile(childResult) {
					marked[parentIndex] = struct{}{}
					marked[childIndex] = struct{}{}
				}
			}
		}
	}
	for index := range marked {
		decision := &plan.Decisions[index]
		if decision.Action == ActionBlocked {
			continue
		}
		decision.Action = ActionConflict
		decision.Reason = ReasonStructural
	}
}

func resultOnSide(decision Decision, side int) (*model.Entry, bool) {
	localSide := side == 0
	switch decision.Action {
	case ActionBlocked, ActionConflict:
		return nil, false
	case ActionUnchanged:
		if localSide {
			return decision.Local, true
		}
		return decision.Remote, true
	case ActionUpload:
		return decision.Local, true
	case ActionDownload:
		return decision.Remote, true
	case ActionDeleteRemote:
		return decision.Local, true
	case ActionDeleteLocal:
		return decision.Remote, true
	default:
		return nil, false
	}
}

func presentFile(entry *model.Entry) bool {
	return entry != nil && entry.File != nil && entry.File.State == model.FilePresent
}

func anyPresent(entries ...*model.Entry) bool {
	for _, entry := range entries {
		if presentFile(entry) {
			return true
		}
	}
	return false
}

func fingerprintSet(base, local, remote *model.Entry) FingerprintSet {
	return FingerprintSet{Base: fingerprintPointer(base), Local: fingerprintPointer(local), Remote: fingerprintPointer(remote)}
}

func fingerprintPointer(entry *model.Entry) *Fingerprint {
	if entry == nil {
		return nil
	}
	fingerprint := fingerprintEntry(*entry)
	return &fingerprint
}

func fingerprintEntry(entry model.Entry) Fingerprint {
	var fingerprint Fingerprint
	var payload []byte
	if entry.File != nil {
		file := entry.File
		fingerprint.State = string(file.State)
		fingerprint.Kind = file.Kind
		fingerprint.Mode = file.Mode
		fingerprint.LinkTarget = file.LinkTarget
		if file.Kind == model.FileRegular && file.State == model.FilePresent {
			payload = file.Content
		} else if file.Kind == model.FileSymlink && file.State == model.FilePresent {
			payload = []byte(file.LinkTarget)
		} else {
			payload = nil
		}
		if file.Kind == model.FileRegular && file.State == model.FilePresent {
			fingerprint.Size = int64(len(payload))
		}
	} else {
		setting := entry.Setting
		fingerprint.State = string(setting.State)
		if setting.Value != nil {
			fingerprint.ValueType = setting.Value.Type
			fingerprint.ValueText = setting.Value.Text
			payload = []byte(setting.Value.Type + "\x00" + setting.Value.Text)
			fingerprint.Size = int64(len(setting.Value.Text))
		} else {
			payload = nil
		}
	}
	digest := sha256.Sum256(payload)
	fingerprint.Digest = hex.EncodeToString(digest[:])
	return fingerprint
}

func validateBindings(values []TargetBinding) (map[string]TargetBinding, error) {
	bindings := make(map[string]TargetBinding, len(values))
	for _, binding := range values {
		if err := binding.Validate(); err != nil {
			return nil, err
		}
		if _, exists := bindings[binding.Target.ID]; exists {
			return nil, errors.New("duplicate target binding")
		}
		bindings[binding.Target.ID] = cloneBinding(binding)
	}
	return bindings, nil
}

func entryMap(entries []model.Entry, name string, bindings map[string]TargetBinding) (map[model.EntryKey]model.Entry, error) {
	result := make(map[model.EntryKey]model.Entry, len(entries))
	for _, entry := range entries {
		if err := entry.Validate(); err != nil {
			return nil, fmt.Errorf("invalid %s entry: %w", name, err)
		}
		key := entry.Identity()
		binding, ok := bindings[key.TargetID]
		if !ok || binding.Target.Source != key.Source {
			return nil, fmt.Errorf("%s entry has no matching validated target binding", name)
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate %s entry identity", name)
		}
		result[key] = cloneEntry(entry)
	}
	return result, nil
}

func keySet(keys []model.EntryKey, name string, bindings map[string]TargetBinding) (map[model.EntryKey]struct{}, error) {
	result := make(map[model.EntryKey]struct{}, len(keys))
	for _, key := range keys {
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("invalid %s identity: %w", name, err)
		}
		binding, ok := bindings[key.TargetID]
		if !ok || binding.Target.Source != key.Source {
			return nil, fmt.Errorf("%s identity has no matching validated target binding", name)
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate %s identity", name)
		}
		result[key] = struct{}{}
	}
	return result, nil
}

func targetSet(values []string, bindings map[string]TargetBinding) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, targetID := range values {
		if _, ok := bindings[targetID]; !ok {
			return nil, errors.New("coverage refers to an unknown target binding")
		}
		if _, exists := result[targetID]; exists {
			return nil, errors.New("duplicate coverage target")
		}
		result[targetID] = struct{}{}
	}
	return result, nil
}

func isDescendantPath(path, parent string) bool {
	if parent == "." {
		return path != "."
	}
	return path != parent && strings.HasPrefix(path, parent+"/")
}

func sortedKeys(values map[model.EntryKey]struct{}) []model.EntryKey {
	keys := make([]model.EntryKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keyLess(keys[i], keys[j]) })
	return keys
}

func keyLess(left, right model.EntryKey) bool {
	if left.TargetID != right.TargetID {
		return left.TargetID < right.TargetID
	}
	if left.Source != right.Source {
		return left.Source < right.Source
	}
	if left.Source == model.SourceFiles {
		return left.FilePath < right.FilePath
	}
	if left.SchemaID != right.SchemaID {
		return left.SchemaID < right.SchemaID
	}
	if left.SettingsPath != right.SettingsPath {
		return left.SettingsPath < right.SettingsPath
	}
	return left.SettingKey < right.SettingKey
}

func entryPointer(entry model.Entry, ok bool) *model.Entry {
	if !ok {
		return nil
	}
	copy := cloneEntry(entry)
	return &copy
}

func cloneEntryPointer(entry *model.Entry) *model.Entry {
	if entry == nil {
		return nil
	}
	copy := cloneEntry(*entry)
	return &copy
}

func cloneEntry(entry model.Entry) model.Entry {
	copy := model.Entry{TargetID: entry.TargetID}
	if entry.File != nil {
		file := *entry.File
		if file.Content != nil {
			file.Content = bytes.Clone(file.Content)
		}
		copy.File = &file
	}
	if entry.Setting != nil {
		setting := *entry.Setting
		if setting.Value != nil {
			value := *setting.Value
			setting.Value = &value
		}
		copy.Setting = &setting
	}
	return copy
}

func cloneBinding(binding TargetBinding) TargetBinding {
	binding.Target = cloneTarget(binding.Target)
	return binding
}

func cloneTarget(target model.Target) model.Target {
	if target.Root != nil {
		root := *target.Root
		target.Root = &root
	}
	return target
}

func targetFingerprint(target model.Target) string {
	fields := []string{target.ID, string(target.Source), fmt.Sprint(target.SourceVersion)}
	if target.Root == nil {
		fields = append(fields, "-")
	} else {
		fields = append(fields, string(target.Root.Base), target.Root.Path, string(target.Root.Kind))
	}
	var canonical strings.Builder
	for _, field := range fields {
		fmt.Fprintf(&canonical, "%d:", len(field))
		canonical.WriteString(field)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}
