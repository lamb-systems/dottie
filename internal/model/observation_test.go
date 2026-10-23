package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestObservationValidation(t *testing.T) {
	presentFile := Entry{TargetID: "files", File: &FileEntry{Path: "config", State: FilePresent, Kind: FileRegular, Content: []byte("data")}}
	fileObservation := Observation{State: ObservationPresent, Identity: presentFile.Identity(), Entry: &presentFile}
	assert.NoError(t, fileObservation.Validate())

	presentSetting := Entry{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingPresent, Value: &VariantValue{Type: "b", Text: "true"}}}
	assert.NoError(t, (Observation{State: ObservationPresent, Identity: presentSetting.Identity(), Entry: &presentSetting}).Validate())

	for _, state := range []ObservationState{ObservationMissing, ObservationUnknown, ObservationUntracked} {
		t.Run(string(state), func(t *testing.T) {
			assert.NoError(t, (Observation{State: state, Identity: fileObservation.Identity}).Validate())
		})
	}
}

func TestPresentObservationRequiresMatchingPresentEntry(t *testing.T) {
	identity := EntryKey{TargetID: "files", Source: SourceFiles, FilePath: "config"}
	deleted := Entry{TargetID: "files", File: &FileEntry{Path: "config", State: FileDeleted}}
	reset := Entry{TargetID: "settings", Setting: &SettingEntry{SchemaID: "org.example.Desktop", Path: "/", Key: "enabled", State: SettingReset}}
	invalid := []Observation{
		{State: ObservationPresent, Identity: identity},
		{State: ObservationPresent, Identity: identity, Entry: &deleted},
		{State: ObservationPresent, Identity: reset.Identity(), Entry: &reset},
		{State: ObservationPresent, Identity: identity, Entry: &Entry{TargetID: "files", File: &FileEntry{Path: "other", State: FilePresent, Kind: FileRegular, Content: []byte{}}}},
		{State: ObservationPresent, Identity: identity, Entry: &Entry{TargetID: "files", File: &FileEntry{Path: "config", State: FilePresent, Kind: FileRegular}}},
		{State: ObservationPresent, Identity: EntryKey{TargetID: "files", Source: SourceFiles, FilePath: "../invalid"}, Entry: &deleted},
		{State: ObservationState("other"), Identity: identity},
	}
	for i, observation := range invalid {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assert.Error(t, observation.Validate())
		})
	}
}

func TestNonPresentObservationsCannotCarryEntries(t *testing.T) {
	entry := Entry{TargetID: "files", File: &FileEntry{Path: "config", State: FilePresent, Kind: FileRegular, Content: []byte{}}}
	for _, state := range []ObservationState{ObservationMissing, ObservationUnknown, ObservationUntracked} {
		assert.Error(t, (Observation{State: state, Identity: entry.Identity(), Entry: &entry}).Validate())
	}
}
