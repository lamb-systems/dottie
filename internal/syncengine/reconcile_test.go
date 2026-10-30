package syncengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
)

func fileBinding(t *testing.T) Options {
	t.Helper()
	binding, err := NewTargetBinding(model.Target{
		ID:            "files",
		Source:        model.SourceFiles,
		SourceVersion: model.SourceVersion,
		Root:          &model.FileRoot{Base: model.RootHome, Path: "prefs", Kind: model.SelectionDirectory},
	})
	if err != nil {
		t.Fatal(err)
	}
	return Options{Bindings: []TargetBinding{binding}}
}

func settingsBinding(t *testing.T) Options {
	t.Helper()
	binding, err := NewTargetBinding(model.Target{ID: "settings", Source: model.SourceGNOME, SourceVersion: model.SourceVersion})
	if err != nil {
		t.Fatal(err)
	}
	return Options{Bindings: []TargetBinding{binding}}
}

func regular(path, content string) model.Entry {
	return model.Entry{TargetID: "files", File: &model.FileEntry{Path: path, State: model.FilePresent, Kind: model.FileRegular, Content: []byte(content), Mode: 0o600}}
}

func directory(path string) model.Entry {
	return model.Entry{TargetID: "files", File: &model.FileEntry{Path: path, State: model.FilePresent, Kind: model.FileDirectory, Mode: 0o700}}
}

func symlink(path, target string) model.Entry {
	return model.Entry{TargetID: "files", File: &model.FileEntry{Path: path, State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: target}}
}

func tombstone(path string) model.Entry {
	return model.Entry{TargetID: "files", File: &model.FileEntry{Path: path, State: model.FileDeleted}}
}

func setting(state model.SettingState, valueType, text string) model.Entry {
	entry := model.Entry{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.example.Settings", Path: "/", Key: "enabled", State: state}}
	if state == model.SettingPresent {
		entry.Setting.Value = &model.VariantValue{Type: valueType, Text: text}
	}
	return entry
}

func entrySlice(entry *model.Entry) []model.Entry {
	if entry == nil {
		return nil
	}
	return []model.Entry{*entry}
}

func onlyDecision(t *testing.T, plan Plan) Decision {
	t.Helper()
	if len(plan.Decisions) != 1 {
		t.Fatalf("got %d decisions, want one", len(plan.Decisions))
	}
	return plan.Decisions[0]
}

func reconcileOne(t *testing.T, status BaseStatus, base, local, remote *model.Entry, options Options) Decision {
	t.Helper()
	coverage := make([]string, 0, len(options.Bindings))
	for _, binding := range options.Bindings {
		coverage = append(coverage, binding.Target.ID)
	}
	plan, err := Reconcile(
		BaseView{Status: status, Entries: entrySlice(base)},
		LocalView{Entries: entrySlice(local), Coverage: coverage},
		entrySlice(remote),
		options,
	)
	if err != nil {
		t.Fatal(err)
	}
	return onlyDecision(t, plan)
}

func TestReconcileDecisionTable(t *testing.T) {
	a := regular("config", "A")
	b := regular("config", "B")
	tomb := tombstone("config")
	absent := (*model.Entry)(nil)
	cases := []struct {
		name   string
		status BaseStatus
		base   *model.Entry
		local  *model.Entry
		remote *model.Entry
		action Action
		reason Reason
	}{
		{name: "known local tombstone against unchanged remote", status: BaseKnown, base: &a, local: &tomb, remote: &a, action: ActionDeleteRemote, reason: ReasonLocalChanged},
		{name: "known tombstone against divergent remote", status: BaseKnown, base: &a, local: &tomb, remote: &b, action: ActionConflict, reason: ReasonDivergence},
		{name: "known local absence against unchanged remote", status: BaseKnown, base: &a, local: absent, remote: &a, action: ActionDeleteRemote, reason: ReasonLocalChanged},
		{name: "known remote absence against unchanged local", status: BaseKnown, base: &a, local: &a, remote: absent, action: ActionDeleteLocal, reason: ReasonRemoteChanged},
		{name: "known one-sided local edit", status: BaseKnown, base: &a, local: &b, remote: &a, action: ActionUpload, reason: ReasonLocalChanged},
		{name: "known one-sided remote edit", status: BaseKnown, base: &a, local: &a, remote: &b, action: ActionDownload, reason: ReasonRemoteChanged},
		{name: "known two-sided edit", status: BaseKnown, base: &a, local: &b, remote: entryPtr(regular("config", "C")), action: ActionConflict, reason: ReasonDivergence},
		{name: "equal present values", status: BaseKnown, base: &a, local: &b, remote: &b, action: ActionUnchanged, reason: ReasonEqual},
		{name: "both file sides deleted differently", status: BaseKnown, base: &a, local: &tomb, remote: absent, action: ActionUnchanged, reason: ReasonBothDeleted},
		{name: "missing base remote content", status: BaseMissing, local: absent, remote: &a, action: ActionDownload, reason: ReasonBaseMissing},
		{name: "missing base local content", status: BaseMissing, local: &a, remote: absent, action: ActionUpload, reason: ReasonBaseMissing},
		{name: "missing base file tombstone and absence", status: BaseMissing, local: &tomb, remote: absent, action: ActionUnchanged, reason: ReasonBothDeleted},
		{name: "stale one-sided non-deletion edit", status: BaseStale, base: &a, local: &a, remote: &b, action: ActionDownload, reason: ReasonRemoteChanged},
		{name: "stale deletion is a conflict", status: BaseStale, base: &a, local: &tomb, remote: &a, action: ActionConflict, reason: ReasonStaleBase},
		{name: "stale divergence differs from ordinary conflict", status: BaseStale, base: &a, local: &b, remote: entryPtr(regular("config", "C")), action: ActionConflict, reason: ReasonStaleBase},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := fileBinding(t)
			if test.status == BaseMissing {
				test.base = nil
			}
			decision := reconcileOne(t, test.status, test.base, test.local, test.remote, options)
			if decision.Action != test.action || decision.Reason != test.reason {
				t.Fatalf("decision = %s/%s, want %s/%s", decision.Action, decision.Reason, test.action, test.reason)
			}
		})
	}
}

func TestReconcileKnownAbsentSettingsDeletionRequiresCoverage(t *testing.T) {
	options := settingsBinding(t)
	value := setting(model.SettingPresent, "b", "true")
	plan, err := Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{value}}, LocalView{}, []model.Entry{value}, options)
	if err != nil {
		t.Fatal(err)
	}
	decision := onlyDecision(t, plan)
	if decision.Action != ActionBlocked || decision.Reason != ReasonCoverage {
		t.Fatalf("uncovered setting deletion = %+v", decision)
	}
	plan, err = Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{value}}, LocalView{Coverage: []string{"settings"}}, []model.Entry{value}, options)
	if err != nil {
		t.Fatal(err)
	}
	decision = onlyDecision(t, plan)
	if decision.Action != ActionDeleteRemote || decision.States.Local != ValueKnownAbsent {
		t.Fatalf("covered setting deletion = %+v", decision)
	}
}

func TestReconcileSettingsResetAndCanonicalTypedText(t *testing.T) {
	options := settingsBinding(t)
	base := setting(model.SettingPresent, "b", "true")
	remote := setting(model.SettingPresent, "b", "true")
	reset := setting(model.SettingReset, "", "")
	plan, err := Reconcile(
		BaseView{Status: BaseKnown, Entries: []model.Entry{base}},
		LocalView{Entries: []model.Entry{reset}, Coverage: []string{"settings"}},
		[]model.Entry{remote}, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := onlyDecision(t, plan)
	if decision.Action != ActionUpload || decision.States.Local != ValueSettingReset {
		t.Fatalf("reset decision = %+v", decision)
	}
	remoteChange := setting(model.SettingPresent, "b", "false")
	plan, err = Reconcile(
		BaseView{Status: BaseKnown, Entries: []model.Entry{base}},
		LocalView{Entries: []model.Entry{reset}, Coverage: []string{"settings"}},
		[]model.Entry{remoteChange}, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision = onlyDecision(t, plan)
	if decision.Action != ActionConflict || decision.Reason != ReasonDivergence {
		t.Fatalf("reset versus present setting divergence = %+v", decision)
	}

	exact := setting(model.SettingPresent, "b", "true")
	textDifference := setting(model.SettingPresent, "b", " true ")
	typeDifference := setting(model.SettingPresent, "s", "true")
	exactCopy := setting(model.SettingPresent, "b", "true")
	if !entriesEqual(&exact, &exactCopy) {
		t.Fatal("same canonical type and text must be equal")
	}
	if entriesEqual(&exact, &textDifference) || entriesEqual(&exact, &typeDifference) {
		t.Fatal("setting equality must compare canonical Type and Text exactly")
	}
}

func TestReconcileUnknownPropagationAndUntracked(t *testing.T) {
	t.Run("unknown root blocks all target keys", func(t *testing.T) {
		options := fileBinding(t)
		root := directory(".")
		a := directory("a")
		child := regular("a/file", "child")
		other := regular("other", "other")
		rootKey := model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "."}
		plan, err := Reconcile(
			BaseView{Status: BaseMissing},
			LocalView{Unknown: []model.EntryKey{rootKey}},
			[]model.Entry{root, a, child, other}, options,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Decisions) != 4 {
			t.Fatalf("got %d decisions", len(plan.Decisions))
		}
		for _, decision := range plan.Decisions {
			if decision.Action != ActionBlocked || decision.Reason != ReasonUnknown || decision.States.Local != ValueUnknown {
				t.Fatalf("root unknown did not block %s: %+v", decision.Key.FilePath, decision)
			}
		}
	})

	t.Run("unknown directory blocks descendants only", func(t *testing.T) {
		options := fileBinding(t)
		aKey := model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "a"}
		plan, err := Reconcile(
			BaseView{Status: BaseMissing},
			LocalView{Unknown: []model.EntryKey{aKey}},
			[]model.Entry{directory("a"), regular("a/file", "child"), regular("other", "other")}, options,
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, decision := range plan.Decisions {
			if decision.Key.FilePath == "other" {
				if decision.Action != ActionDownload {
					t.Fatalf("unrelated key decision = %+v", decision)
				}
			} else if decision.Action != ActionBlocked || decision.Reason != ReasonUnknown {
				t.Fatalf("unknown directory did not block %s: %+v", decision.Key.FilePath, decision)
			}
		}
	})

	t.Run("untracking with base and remote entry blocks", func(t *testing.T) {
		options := fileBinding(t)
		value := regular("config", "still stored remotely")
		key := value.Identity()
		plan, err := Reconcile(
			BaseView{Status: BaseKnown, Entries: []model.Entry{value}},
			LocalView{Untracked: []model.EntryKey{key}, Coverage: []string{"files"}},
			[]model.Entry{value}, options,
		)
		if err != nil {
			t.Fatal(err)
		}
		decision := onlyDecision(t, plan)
		if decision.Action != ActionBlocked || decision.Reason != ReasonUntracked || decision.States.Local != ValueUntracked {
			t.Fatalf("untracked key decision = %+v", decision)
		}
	})
}

func TestReconcileCoverageBlocksDeletion(t *testing.T) {
	options := fileBinding(t)
	value := regular("config", "base")
	plan, err := Reconcile(
		BaseView{Status: BaseKnown, Entries: []model.Entry{value}},
		LocalView{},
		[]model.Entry{value}, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := onlyDecision(t, plan)
	if decision.Action != ActionBlocked || decision.Reason != ReasonCoverage {
		t.Fatalf("uncovered deletion = %+v", decision)
	}

	plan, err = Reconcile(
		BaseView{Status: BaseKnown, Entries: []model.Entry{value}},
		LocalView{Coverage: []string{"files"}},
		[]model.Entry{value}, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision = onlyDecision(t, plan)
	if decision.Action != ActionDeleteRemote {
		t.Fatalf("covered deletion = %+v", decision)
	}
}

func TestReconcileStaleBaseConservatism(t *testing.T) {
	options := fileBinding(t)
	base := regular("config", "base")
	localDeletion := tombstone("config")
	plan, err := Reconcile(
		BaseView{Status: BaseStale, Entries: []model.Entry{base}},
		LocalView{Entries: []model.Entry{localDeletion}, Coverage: []string{"files"}},
		[]model.Entry{base}, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := onlyDecision(t, plan)
	if decision.Action != ActionConflict || decision.Reason != ReasonStaleBase {
		t.Fatalf("stale deletion = %+v", decision)
	}
	if decision.Action == ActionDeleteLocal || decision.Action == ActionDeleteRemote {
		t.Fatalf("stale base emitted deletion action: %+v", decision)
	}

	local := regular("config", "local")
	remote := regular("config", "remote")
	stale, err := Reconcile(BaseView{Status: BaseStale, Entries: []model.Entry{base}}, LocalView{Entries: []model.Entry{local}, Coverage: []string{"files"}}, []model.Entry{remote}, options)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{base}}, LocalView{Entries: []model.Entry{local}, Coverage: []string{"files"}}, []model.Entry{remote}, options)
	if err != nil {
		t.Fatal(err)
	}
	if onlyDecision(t, stale).Reason != ReasonStaleBase || onlyDecision(t, ordinary).Reason != ReasonDivergence {
		t.Fatalf("stale and ordinary divergence were not distinguished: %s / %s", onlyDecision(t, stale).Reason, onlyDecision(t, ordinary).Reason)
	}
}

func TestReconcileStructuralPass(t *testing.T) {
	options := fileBinding(t)
	parent := directory("parent")
	child := regular("parent/child", "payload")
	cases := []struct {
		name        string
		localParent model.Entry
		wantLocal   ValueState
	}{
		{name: "parent directory replaced by symlink with surviving child", localParent: symlink("parent", "elsewhere"), wantLocal: ValuePresent},
		{name: "parent directory changed to regular file", localParent: regular("parent", "file"), wantLocal: ValuePresent},
		{name: "parent deleted with surviving child", localParent: tombstone("parent"), wantLocal: ValueTombstone},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Reconcile(
				BaseView{Status: BaseKnown, Entries: []model.Entry{parent, child}},
				LocalView{Entries: []model.Entry{test.localParent, child}, Coverage: []string{"files"}},
				[]model.Entry{parent, child}, options,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Decisions) != 2 {
				t.Fatalf("got %d decisions", len(plan.Decisions))
			}
			for _, decision := range plan.Decisions {
				if decision.Action != ActionConflict || decision.Reason != ReasonStructural {
					t.Fatalf("decision was not promoted to structural conflict: %+v", decision)
				}
				if decision.Key.FilePath == "parent" && decision.States.Local != test.wantLocal {
					t.Fatalf("parent local state = %s, want %s", decision.States.Local, test.wantLocal)
				}
			}
		})
	}
}

func TestReconcileBindingsFingerprintsAndValidation(t *testing.T) {
	options := fileBinding(t)
	base := regular("config", "base payload")
	local := regular("config", "local payload")
	decision := reconcileOne(t, BaseKnown, &base, &local, &base, options)
	if decision.Action != ActionUpload {
		t.Fatalf("decision = %+v", decision)
	}
	if err := decision.Binding.Validate(); err != nil {
		t.Fatalf("decision lost validated target binding: %v", err)
	}
	if decision.Binding.Fingerprint == "" || decision.Fingerprints.Base == nil || decision.Fingerprints.Local == nil || decision.Fingerprints.Remote == nil {
		t.Fatalf("decision lost target or entry fingerprints: %+v", decision)
	}
	baseDigest := sha256.Sum256([]byte("base payload"))
	if decision.Fingerprints.Base.Digest != hex.EncodeToString(baseDigest[:]) || decision.Fingerprints.Local.Size != int64(len("local payload")) {
		t.Fatalf("incorrect view fingerprints: %+v", decision.Fingerprints)
	}
	local.File.Content[0] = 'X'
	if string(decision.Local.File.Content) != "local payload" {
		t.Fatal("plan content aliases mutable input view")
	}

	bad := options.Bindings[0]
	bad.Fingerprint = strings.Repeat("0", 64)
	if _, err := Reconcile(BaseView{Status: BaseMissing}, LocalView{}, nil, Options{Bindings: []TargetBinding{bad}}); err == nil {
		t.Fatal("invalid target fingerprint accepted")
	}
}

func TestReconcileDiagnosticRedactsPayload(t *testing.T) {
	options := fileBinding(t)
	base := regular("config", "secret-base-payload")
	local := regular("config", "secret-local-payload")
	remote := regular("config", "secret-remote-payload")
	plan, err := Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{base}}, LocalView{Entries: []model.Entry{local}, Coverage: []string{"files"}}, []model.Entry{remote}, options)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeDiagnostic(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-base-payload", "secret-local-payload", "secret-remote-payload"} {
		if bytes.Contains(encoded, []byte(secret)) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) {
			t.Fatalf("diagnostic exposed payload %q: %s", secret, encoded)
		}
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(planJSON, []byte(base64.StdEncoding.EncodeToString([]byte("secret-local-payload")))) {
		t.Fatalf("test plan did not contain serializable payload bytes: %s", planJSON)
	}
	if bytes.Equal(encoded, planJSON) {
		t.Fatal("diagnostic encoder emitted the plan rather than the redacted diagnostic")
	}
	var diagnostic Diagnostic
	if err := json.Unmarshal(encoded, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if len(diagnostic.Decisions) != 1 || diagnostic.Decisions[0].LocalDigest == "" || diagnostic.Decisions[0].Action != ActionConflict {
		t.Fatalf("diagnostic omitted expected key/action/reason/digest data: %+v", diagnostic)
	}
}

func TestReconcileDeterminismAndClockIndependence(t *testing.T) {
	options := fileBinding(t)
	base := regular("config", "base")
	local := regular("config", "local")
	remote := regular("config", "remote")
	first, err := Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{base}}, LocalView{Entries: []model.Entry{local}, Coverage: []string{"files"}}, []model.Entry{remote}, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{base}}, LocalView{Entries: []model.Entry{local}, Coverage: []string{"files"}}, []model.Entry{remote}, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical inputs produced different plans: %+v / %+v", first, second)
	}
}

func TestReconcilePropertyTableAgainstIndependentOracle(t *testing.T) {
	options := fileBinding(t)
	values := []*model.Entry{
		nil,
		entryPtr(tombstone("config")),
		entryPtr(regular("config", "base-payload-000")),
		entryPtr(regular("config", "distinguishable-payload-111")),
		entryPtr(regular("config", "different-payload-222")),
	}
	statuses := []BaseStatus{BaseKnown, BaseStale}
	cases := 0
	for _, status := range statuses {
		for baseIndex, base := range values {
			for localIndex, local := range values {
				for remoteIndex, remote := range values {
					cases++
					baseCopy := base
					wantAction, wantReason := oracleDecision(status, baseCopy, local, remote)
					plan, err := Reconcile(
						BaseView{Status: status, Entries: entrySlice(baseCopy)},
						LocalView{Entries: entrySlice(local), Coverage: []string{"files"}},
						entrySlice(remote), options,
					)
					if err != nil {
						t.Fatalf("status=%s base=%d local=%d remote=%d: %v", status, baseIndex, localIndex, remoteIndex, err)
					}
					if baseCopy == nil && local == nil && remote == nil {
						if len(plan.Decisions) != 0 {
							t.Fatalf("empty inputs produced decisions: %+v", plan)
						}
						continue
					}
					repeated, err := Reconcile(
						BaseView{Status: status, Entries: entrySlice(baseCopy)},
						LocalView{Entries: entrySlice(local), Coverage: []string{"files"}},
						entrySlice(remote), options,
					)
					if err != nil || !reflect.DeepEqual(plan, repeated) {
						t.Fatalf("non-deterministic row: status=%s base=%d local=%d remote=%d: %v", status, baseIndex, localIndex, remoteIndex, err)
					}
					decision := onlyDecision(t, plan)
					if decision.Action != wantAction || decision.Reason != wantReason {
						t.Fatalf("status=%s base=%d local=%d remote=%d => %s/%s, oracle wants %s/%s", status, baseIndex, localIndex, remoteIndex, decision.Action, decision.Reason, wantAction, wantReason)
					}
					if status == BaseStale && (decision.Action == ActionDeleteLocal || decision.Action == ActionDeleteRemote) {
						t.Fatalf("stale case emitted deletion: status=%s base=%d local=%d remote=%d", status, baseIndex, localIndex, remoteIndex)
					}
				}
			}
		}
	}
	for baseIndex, base := range values[:1] {
		for localIndex, local := range values {
			for remoteIndex, remote := range values {
				cases++
				wantAction, wantReason := oracleDecision(BaseMissing, base, local, remote)
				plan, err := Reconcile(
					BaseView{Status: BaseMissing},
					LocalView{Entries: entrySlice(local), Coverage: []string{"files"}},
					entrySlice(remote), options,
				)
				if err != nil {
					t.Fatalf("missing base local=%d remote=%d: %v", localIndex, remoteIndex, err)
				}
				if local == nil && remote == nil {
					if len(plan.Decisions) != 0 {
						t.Fatalf("empty missing-base inputs produced decisions: %+v", plan)
					}
					continue
				}
				repeated, err := Reconcile(BaseView{Status: BaseMissing}, LocalView{Entries: entrySlice(local), Coverage: []string{"files"}}, entrySlice(remote), options)
				if err != nil || !reflect.DeepEqual(plan, repeated) {
					t.Fatalf("non-deterministic missing-base row local=%d remote=%d: %v", localIndex, remoteIndex, err)
				}
				decision := onlyDecision(t, plan)
				if decision.Action != wantAction || decision.Reason != wantReason {
					t.Fatalf("missing base=%d local=%d remote=%d => %s/%s, oracle wants %s/%s", baseIndex, localIndex, remoteIndex, decision.Action, decision.Reason, wantAction, wantReason)
				}
			}
		}
	}
	if cases != 275 {
		t.Fatalf("oracle checked %d cases, want 275", cases)
	}
}

func oracleDecision(status BaseStatus, base, local, remote *model.Entry) (Action, Reason) {
	if status == BaseMissing {
		if oracleEqual(local, remote) {
			return ActionUnchanged, ReasonEqual
		}
		if oracleFileDeleted(local) && oracleFileDeleted(remote) {
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
	if oracleEqual(local, remote) {
		return ActionUnchanged, ReasonEqual
	}
	localChanged := !oracleEqual(local, base)
	remoteChanged := !oracleEqual(remote, base)
	var action Action
	var reason Reason
	switch {
	case localChanged && !remoteChanged:
		if status == BaseStale && oracleFileDeleted(local) {
			action, reason = ActionConflict, ReasonStaleBase
		} else if oracleFileDeleted(local) {
			action, reason = ActionDeleteRemote, ReasonLocalChanged
		} else {
			action, reason = ActionUpload, ReasonLocalChanged
		}
	case !localChanged && remoteChanged:
		if status == BaseStale && oracleFileDeleted(remote) {
			action, reason = ActionConflict, ReasonStaleBase
		} else if oracleFileDeleted(remote) {
			action, reason = ActionDeleteLocal, ReasonRemoteChanged
		} else {
			action, reason = ActionDownload, ReasonRemoteChanged
		}
	case localChanged && remoteChanged:
		if status == BaseStale {
			action, reason = ActionConflict, ReasonStaleBase
		} else {
			action, reason = ActionConflict, ReasonDivergence
		}
	default:
		return ActionUnchanged, ReasonEqual
	}
	if oracleFileDeleted(local) && oracleFileDeleted(remote) {
		return ActionUnchanged, ReasonBothDeleted
	}
	return action, reason
}

func oracleEqual(left, right *model.Entry) bool {
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
		if a.Kind == model.FileRegular && a.State == model.FilePresent {
			return bytes.Equal(a.Content, b.Content)
		}
		return true
	}
	a, b := left.Setting, right.Setting
	if a.State != b.State {
		return false
	}
	if a.Value == nil || b.Value == nil {
		return a.Value == nil && b.Value == nil
	}
	return a.Value.Type == b.Value.Type && a.Value.Text == b.Value.Text
}

func oracleFileDeleted(entry *model.Entry) bool {
	return entry == nil || (entry.File != nil && entry.File.State == model.FileDeleted)
}

func entryPtr(entry model.Entry) *model.Entry {
	return &entry
}

func TestReconcileRejectsInvalidViews(t *testing.T) {
	options := fileBinding(t)
	valid := regular("config", "value")
	cases := []struct {
		name  string
		base  BaseView
		local LocalView
		other []model.Entry
	}{
		{name: "missing base carries entries", base: BaseView{Status: BaseMissing, Entries: []model.Entry{valid}}},
		{name: "duplicate remote key", base: BaseView{Status: BaseKnown}, other: []model.Entry{valid, valid}},
		{name: "unknown and present overlap", base: BaseView{Status: BaseKnown}, local: LocalView{Entries: []model.Entry{valid}, Unknown: []model.EntryKey{valid.Identity()}}},
		{name: "coverage refers to missing binding", base: BaseView{Status: BaseKnown}, local: LocalView{Coverage: []string{"missing"}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Reconcile(test.base, test.local, test.other, options); err == nil {
				t.Fatal("invalid view was accepted")
			}
		})
	}
}

func TestReconcileOrdering(t *testing.T) {
	options := fileBinding(t)
	root := directory(".")
	z := regular("z", "z")
	a := regular("a", "a")
	plan, err := Reconcile(BaseView{Status: BaseMissing}, LocalView{}, []model.Entry{z, root, a}, options)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(plan.Decisions))
	for index, decision := range plan.Decisions {
		got[index] = decision.Key.FilePath
	}
	want := []string{".", "a", "z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decision order %v, want %v", got, want)
	}
}

func TestReconcileNoLostEditUsesOracle(t *testing.T) {
	options := fileBinding(t)
	base := regular("config", "base-edit")
	local := regular("config", "local-edit")
	remote := regular("config", "remote-edit")
	wantAction, wantReason := oracleDecision(BaseKnown, &base, &local, &remote)
	if wantAction != ActionConflict {
		t.Fatalf("independent oracle did not preserve the concurrent edit: %s/%s", wantAction, wantReason)
	}
	plan, err := Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{base}}, LocalView{Entries: []model.Entry{local}, Coverage: []string{"files"}}, []model.Entry{remote}, options)
	if err != nil {
		t.Fatal(err)
	}
	decision := onlyDecision(t, plan)
	if decision.Action != wantAction || decision.Reason != wantReason {
		t.Fatalf("distinguishable concurrent edits disagree with oracle: got %s/%s, oracle %s/%s", decision.Action, decision.Reason, wantAction, wantReason)
	}
}

func TestReconcileFingerprintDoesNotDependOnClockOrInode(t *testing.T) {
	options := fileBinding(t)
	firstEntry := regular("config", "same payload")
	secondEntry := regular("config", "same payload")
	first := reconcileOne(t, BaseMissing, nil, &firstEntry, nil, options)
	second := reconcileOne(t, BaseMissing, nil, &secondEntry, nil, options)
	if !reflect.DeepEqual(first.Fingerprints.Local, second.Fingerprints.Local) {
		t.Fatalf("identical entry fingerprints differ: %+v / %+v", first.Fingerprints.Local, second.Fingerprints.Local)
	}
}

func TestReconcileAllStateClassifications(t *testing.T) {
	options := fileBinding(t)
	base := regular("config", "base")
	local := tombstone("config")
	plan, err := Reconcile(BaseView{Status: BaseKnown, Entries: []model.Entry{base}}, LocalView{Entries: []model.Entry{local}, Coverage: []string{"files"}}, []model.Entry{base}, options)
	if err != nil {
		t.Fatal(err)
	}
	decision := onlyDecision(t, plan)
	if decision.States != (SideStates{Base: ValuePresent, Local: ValueTombstone, Remote: ValuePresent}) {
		t.Fatalf("classification = %+v", decision.States)
	}

	root := model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "."}
	plan, err = Reconcile(BaseView{Status: BaseMissing}, LocalView{Unknown: []model.EntryKey{root}}, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	if onlyDecision(t, plan).States.Local != ValueUnknown {
		t.Fatalf("unknown was not classified: %+v", onlyDecision(t, plan).States)
	}

	plan, err = Reconcile(BaseView{Status: BaseMissing}, LocalView{Untracked: []model.EntryKey{root}}, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	if onlyDecision(t, plan).States.Local != ValueUntracked {
		t.Fatalf("untracked was not classified: %+v", onlyDecision(t, plan).States)
	}
}

func TestReconcileTargetSourceBinding(t *testing.T) {
	options := fileBinding(t)
	settingEntry := model.Entry{TargetID: "files", Setting: &model.SettingEntry{SchemaID: "org.example.Settings", Path: "/", Key: "enabled", State: model.SettingReset}}
	if _, err := Reconcile(BaseView{Status: BaseKnown}, LocalView{Entries: []model.Entry{settingEntry}}, nil, options); err == nil {
		t.Fatal("entry source mismatch accepted")
	}
}

func TestReconcileStateTableRowsAreTotal(t *testing.T) {
	options := fileBinding(t)
	for _, status := range []BaseStatus{BaseKnown, BaseStale} {
		for _, base := range []*model.Entry{nil, entryPtr(tombstone("config")), entryPtr(regular("config", "base"))} {
			for _, local := range []*model.Entry{nil, entryPtr(tombstone("config")), entryPtr(regular("config", "local"))} {
				for _, remote := range []*model.Entry{nil, entryPtr(tombstone("config")), entryPtr(regular("config", "remote"))} {
					plan, err := Reconcile(BaseView{Status: status, Entries: entrySlice(base)}, LocalView{Entries: entrySlice(local), Coverage: []string{"files"}}, entrySlice(remote), options)
					if err != nil {
						t.Fatalf("%s: %v", status, err)
					}
					if base == nil && local == nil && remote == nil {
						if len(plan.Decisions) != 0 {
							t.Fatalf("empty row produced decisions: %+v", plan)
						}
						continue
					}
					if len(plan.Decisions) != 1 || plan.Decisions[0].Action == "" {
						t.Fatalf("non-total row: status=%s base=%v local=%v remote=%v plan=%+v", status, base, local, remote, plan)
					}
				}
			}
		}
	}
}
