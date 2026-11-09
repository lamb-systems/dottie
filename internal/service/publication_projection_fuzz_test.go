package service

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	publicationProjectionFuzzMaxInputBytes = 128 << 10
	publicationProjectionFuzzMaxEntries    = 16
	publicationProjectionFuzzMaxValueBytes = 4 << 10
	publicationProjectionFuzzMaxTextBytes  = publicationProjectionFuzzMaxValueBytes - 2
)

type publicationProjectionFuzzSettings struct{}

func (publicationProjectionFuzzSettings) Resolve(context.Context, string, string, string) (string, error) {
	return "/synthetic/", nil
}

func (publicationProjectionFuzzSettings) Capture(context.Context, string, []SettingRef) (SettingsCapture, error) {
	return SettingsCapture{}, nil
}

func (publicationProjectionFuzzSettings) Backend() syncengine.SettingsBackend { return nil }

func FuzzProjectPublicationSnapshotBoundary(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0, 1, 0, 0})
	f.Add([]byte{1, 1, 0, 0, 0})
	f.Add([]byte{4, 1, 1, 0, 1, 'b', 0, 1, 0, 1, 'a', 0x80, 1, 0, 1, 'c', 0x81, 1, 0, 1, 'd'})
	f.Add([]byte{2, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{1, 0, 4, 0, 0})
	f.Add([]byte{1, 0x82, 0, 0, 0})
	f.Add([]byte{1, 0x83, 0, 0, 0})
	f.Add([]byte{0x81, 0, 1, 0, 1, 'x'})

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > publicationProjectionFuzzMaxInputBytes {
			return
		}

		selection, refs := publicationProjectionFuzzSelection(t)
		generated := publicationProjectionFuzzSnapshot(t, input, selection, refs)
		before := publicationProjectionFuzzCloneSnapshot(generated.snapshot)
		projected, err := projectPublicationSnapshot(selection, generated.snapshot)
		assert.Equal(t, before, generated.snapshot)

		if generated.reason != "" {
			assert.Equal(t, publicationProjection{}, projected)
			publicationProjectionFuzzAssertError(t, err, generated.reason)
			return
		}

		require.NoError(t, err)
		assert.Equal(t, generated.entries, projected.entries)
		assert.Equal(t, generated.untracked, projected.untracked)

		reversed := publicationProjectionFuzzCloneSnapshot(generated.snapshot)
		for left, right := 0, len(reversed.Entries)-1; left < right; left, right = left+1, right-1 {
			reversed.Entries[left], reversed.Entries[right] = reversed.Entries[right], reversed.Entries[left]
		}
		reversedBefore := publicationProjectionFuzzCloneSnapshot(reversed)
		reversedProjection, reverseErr := projectPublicationSnapshot(selection, reversed)
		assert.Equal(t, reversedBefore, reversed)
		require.NoError(t, reverseErr)
		assert.Equal(t, generated.entries, reversedProjection.entries)
		assert.Equal(t, generated.untracked, reversedProjection.untracked)

		for index := range generated.snapshot.Entries {
			entry := &generated.snapshot.Entries[index]
			if entry.Setting == nil {
				continue
			}
			entry.Setting.SchemaID = "org.example.Mutated"
			entry.Setting.Path = "/mutated/"
			entry.Setting.Key = "mutated"
			if entry.Setting.Value != nil {
				entry.Setting.Value.Type = "b"
				entry.Setting.Value.Text = "true"
			}
		}
		for index := range reversed.Entries {
			entry := &reversed.Entries[index]
			if entry.Setting == nil {
				continue
			}
			entry.Setting.SchemaID = "org.example.ReverseMutation"
			entry.Setting.Path = "/reverse/"
			entry.Setting.Key = "reverse"
			if entry.Setting.Value != nil {
				entry.Setting.Value.Type = "b"
				entry.Setting.Value.Text = "false"
			}
		}
		assert.Equal(t, generated.entries, projected.entries)
		assert.Equal(t, generated.untracked, projected.untracked)
		assert.Equal(t, generated.entries, reversedProjection.entries)
		assert.Equal(t, generated.untracked, reversedProjection.untracked)
	})
}

func publicationProjectionFuzzSelection(t *testing.T) (publicationSelection, []SettingRef) {
	t.Helper()
	categories := []string{"clock"}
	keys, err := matrix.SelectCategories(categories)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(keys), 2)
	digest, err := matrix.KeySetDigest(keys)
	require.NoError(t, err)
	target := config.Target{
		ID: "synthetic-desktop", Source: model.SourceGNOME,
		GNOMEPolicy: &config.GNOMEPolicy{
			Approval: config.GNOMEApprovalApproved, Categories: categories,
			MatrixVersion: matrix.Version, KeyDigest: hex.EncodeToString(digest[:]),
		},
	}
	portable, err := target.Model()
	require.NoError(t, err)
	paths := platform.Paths{
		Home: "/synthetic/home", ConfigHome: "/synthetic/config", StateHome: "/synthetic/state",
		CacheHome: "/synthetic/cache", DataHome: "/synthetic/data",
	}
	local, err := NewPublicationLocalContext(paths, nil, publicationProjectionFuzzSettings{})
	require.NoError(t, err)
	refs := make([]SettingRef, 0, len(keys))
	for _, key := range keys {
		refs = append(refs, SettingRef{SchemaID: key.SchemaID, Path: "/synthetic/", Key: key.Key})
	}
	sort.Slice(refs, func(left, right int) bool {
		if refs[left].SchemaID != refs[right].SchemaID {
			return refs[left].SchemaID < refs[right].SchemaID
		}
		if refs[left].Path != refs[right].Path {
			return refs[left].Path < refs[right].Path
		}
		return refs[left].Key < refs[right].Key
	})
	return publicationSelection{
		context: local, target: target, portable: portable,
		mode: config.Review, settingRefs: refs,
	}, refs
}

type publicationProjectionFuzzSnapshotResult struct {
	snapshot  model.Snapshot
	entries   []model.Entry
	untracked []model.EntryKey
	reason    publicationReconciliationReason
}

func publicationProjectionFuzzSnapshot(t *testing.T, input []byte, selection publicationSelection, refs []SettingRef) publicationProjectionFuzzSnapshotResult {
	t.Helper()
	result := publicationProjectionFuzzSnapshotResult{
		entries: make([]model.Entry, 0), untracked: make([]model.EntryKey, 0),
	}
	mismatch := len(input) > 0 && input[0]&0x80 != 0
	count := 0
	if len(input) > 0 {
		count = int(input[0]&0x7f) % (publicationProjectionFuzzMaxEntries + 1)
	}
	targetID := selection.portable.ID
	if mismatch {
		targetID = "synthetic-desktop-mismatch"
	}
	target := selection.portable
	target.ID = targetID
	result.snapshot = model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{target}, Entries: make([]model.Entry, 0, count)}
	seen := make(map[model.EntryKey]struct{}, count)
	malformed := false
	cursor := 1
	for index := 0; index < count; index++ {
		if len(input)-cursor < 4 {
			break
		}
		selector := input[cursor]
		shape := input[cursor+1]
		requested := int(binary.BigEndian.Uint16(input[cursor+2 : cursor+4]))
		cursor += 4
		valueBytes := requested
		if valueBytes > publicationProjectionFuzzMaxTextBytes {
			valueBytes = publicationProjectionFuzzMaxTextBytes
		}
		if valueBytes > len(input)-cursor {
			valueBytes = len(input) - cursor
		}
		valueText := publicationProjectionFuzzText(input[cursor : cursor+valueBytes])
		cursor += valueBytes

		ref, identityKind := publicationProjectionFuzzIdentity(selector, refs)
		key := model.EntryKey{
			TargetID: targetID, Source: model.SourceGNOME,
			SchemaID: ref.SchemaID, SettingsPath: ref.Path, SettingKey: ref.Key,
		}
		setting := &model.SettingEntry{SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key}
		switch shape % 5 {
		case 0:
			setting.State = model.SettingReset
		case 1:
			setting.State = model.SettingPresent
			setting.Value = &model.VariantValue{Type: "s", Text: valueText}
		case 2:
			setting.State = model.SettingReset
			setting.Value = &model.VariantValue{Type: "s", Text: valueText}
			malformed = true
		case 3:
			setting.State = model.SettingPresent
			malformed = true
		case 4:
			setting.State = model.SettingState("unknown")
			malformed = true
		}
		entry := model.Entry{TargetID: targetID, Setting: setting}
		result.snapshot.Entries = append(result.snapshot.Entries, entry)
		if _, duplicate := seen[key]; duplicate {
			malformed = true
		}
		seen[key] = struct{}{}

		switch identityKind {
		case publicationProjectionFuzzApproved:
			result.entries = append(result.entries, publicationProjectionFuzzCloneEntry(entry))
		case publicationProjectionFuzzUntracked:
			result.untracked = append(result.untracked, publicationProjectionFuzzCloneKey(key))
		case publicationProjectionFuzzMalformed:
			malformed = true
		default:
			require.FailNow(t, "unknown projection fuzz identity kind")
		}
	}
	if malformed {
		result.reason = publicationProjectionReasonSnapshot
		return result
	}
	if mismatch {
		result.reason = publicationProjectionReasonSelection
		return result
	}
	sort.Slice(result.entries, func(left, right int) bool {
		return publicationProjectionFuzzKeyLess(publicationProjectionFuzzEntryKey(result.entries[left]), publicationProjectionFuzzEntryKey(result.entries[right]))
	})
	sort.Slice(result.untracked, func(left, right int) bool {
		return publicationProjectionFuzzKeyLess(result.untracked[left], result.untracked[right])
	})
	return result
}

const (
	publicationProjectionFuzzApproved = iota
	publicationProjectionFuzzUntracked
	publicationProjectionFuzzMalformed
)

func publicationProjectionFuzzIdentity(selector byte, refs []SettingRef) (SettingRef, int) {
	switch selector {
	case 0x80:
		ref := refs[0]
		ref.Path = "/wrong-path/"
		return ref, publicationProjectionFuzzUntracked
	case 0x81:
		return SettingRef{SchemaID: "org.example.Foreign", Path: "/synthetic/", Key: "foreign"}, publicationProjectionFuzzUntracked
	case 0x82:
		ref := refs[0]
		ref.Path = "relative/"
		return ref, publicationProjectionFuzzMalformed
	case 0x83:
		ref := refs[0]
		ref.Key = "invalid/key"
		return ref, publicationProjectionFuzzMalformed
	default:
		return refs[int(selector)%len(refs)], publicationProjectionFuzzApproved
	}
}

func publicationProjectionFuzzText(input []byte) string {
	text := make([]byte, len(input)+2)
	text[0] = '\''
	for index, value := range input {
		text[index+1] = 'a' + value%26
	}
	text[len(text)-1] = '\''
	return string(text)
}

func publicationProjectionFuzzCloneSnapshot(snapshot model.Snapshot) model.Snapshot {
	out := snapshot
	out.Targets = append([]model.Target(nil), snapshot.Targets...)
	out.Entries = make([]model.Entry, len(snapshot.Entries))
	for index, entry := range snapshot.Entries {
		out.Entries[index] = publicationProjectionFuzzCloneEntry(entry)
	}
	return out
}

func publicationProjectionFuzzCloneEntry(entry model.Entry) model.Entry {
	out := entry
	if entry.Setting != nil {
		setting := *entry.Setting
		setting.SchemaID = string([]byte(entry.Setting.SchemaID))
		setting.Path = string([]byte(entry.Setting.Path))
		setting.Key = string([]byte(entry.Setting.Key))
		if entry.Setting.Value != nil {
			value := *entry.Setting.Value
			value.Type = string([]byte(entry.Setting.Value.Type))
			value.Text = string([]byte(entry.Setting.Value.Text))
			setting.Value = &value
		}
		out.Setting = &setting
	}
	return out
}

func publicationProjectionFuzzCloneKey(key model.EntryKey) model.EntryKey {
	return model.EntryKey{
		TargetID: string([]byte(key.TargetID)), Source: key.Source,
		FilePath: string([]byte(key.FilePath)), SchemaID: string([]byte(key.SchemaID)),
		SettingsPath: string([]byte(key.SettingsPath)), SettingKey: string([]byte(key.SettingKey)),
	}
}

func publicationProjectionFuzzEntryKey(entry model.Entry) model.EntryKey {
	key := model.EntryKey{TargetID: entry.TargetID}
	if entry.Setting != nil {
		key.Source = model.SourceGNOME
		key.SchemaID = entry.Setting.SchemaID
		key.SettingsPath = entry.Setting.Path
		key.SettingKey = entry.Setting.Key
	}
	return key
}

func publicationProjectionFuzzKeyLess(left, right model.EntryKey) bool {
	if left.TargetID != right.TargetID {
		return left.TargetID < right.TargetID
	}
	if left.Source != right.Source {
		return left.Source < right.Source
	}
	if left.FilePath != right.FilePath {
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

func publicationProjectionFuzzAssertError(t *testing.T, err error, reason publicationReconciliationReason) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublicationReconciliation)
	assert.IsType(t, &publicationReconciliationError{}, err)
	classified, ok := err.(*publicationReconciliationError)
	require.True(t, ok)
	assert.Equal(t, string(publicationProjectionStage), classified.Stage())
	assert.Equal(t, string(reason), classified.Reason())
	assert.Equal(t, "publication reconciliation: "+string(publicationProjectionStage)+"/"+string(reason), err.Error())
	assert.Nil(t, errors.Unwrap(err))
}
