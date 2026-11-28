package service

import (
	"bytes"
	"errors"
	"sort"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

var ErrPublicationCarry = errors.New("publication carry refused")

type PublicationCarry struct {
	Segments []publication.SnapshotSegment
	Payloads map[string][]byte
	Entries  map[string][]publication.PayloadEntry
}

func (carry PublicationCarry) Empty() bool {
	return len(carry.Segments) == 0
}

func (carry PublicationCarry) TargetIDs() []string {
	ids := make([]string, 0, len(carry.Segments))
	for _, segment := range carry.Segments {
		ids = append(ids, segment.Target.ID)
	}
	sort.Strings(ids)
	return ids
}

func publicationCarryOf(
	accepted publication.SnapshotRecord,
	material publicationstate.AcceptedMaterial,
	configuration config.Config,
	drop []string,
) (PublicationCarry, error) {
	carry := PublicationCarry{
		Payloads: make(map[string][]byte, len(accepted.Segments)),
		Entries:  make(map[string][]publication.PayloadEntry, len(accepted.Segments)),
	}
	configured := make(map[string]struct{}, len(configuration.Targets))
	for _, target := range configuration.Targets {
		configured[target.ID] = struct{}{}
	}
	dropped := make(map[string]struct{}, len(drop))
	for _, id := range drop {
		dropped[id] = struct{}{}
	}
	summaries := make(map[string]publicationstate.SegmentSummary, len(material.Segments))
	accepteds := make(map[string]publicationstate.AcceptedMaterialSegment, len(material.Segments))
	for _, segment := range material.Segments {
		summaries[segment.Summary.TargetID] = segment.Summary
		accepteds[segment.Summary.TargetID] = segment
	}
	for _, segment := range accepted.Segments {
		id := segment.Target.ID
		if _, ok := configured[id]; ok {
			continue
		}
		if _, ok := dropped[id]; ok {
			continue
		}
		summary, ok := summaries[id]
		if !ok || !publicationSegmentMatchesSummary(segment, summary) {
			return PublicationCarry{}, ErrPublicationCarry
		}
		carried := accepteds[id]
		switch segment.Form {
		case publication.SegmentFormPacked:
			if len(carried.Blob) == 0 || uint64(len(carried.Blob)) != segment.Blob.Size {
				return PublicationCarry{}, ErrPublicationCarry
			}
			cid, err := publication.RawPayloadCID(carried.Blob)
			if err != nil || !bytes.Equal(cid, segment.Blob.CID) {
				return PublicationCarry{}, ErrPublicationCarry
			}
			carry.Payloads[id] = bytes.Clone(carried.Blob)
		case publication.SegmentFormEntries:
			if len(carried.Entries) != len(segment.Entries) {
				return PublicationCarry{}, ErrPublicationCarry
			}
			entries := make([]publication.PayloadEntry, 0, len(carried.Entries))
			for index, entry := range carried.Entries {
				reference := summary.Entries[index]
				if entry.Path != reference.Path || uint64(len(entry.Content)) != reference.Size {
					return PublicationCarry{}, ErrPublicationCarry
				}
				cid, err := publication.RawPayloadCID(entry.Content)
				if err != nil || !bytes.Equal(cid, reference.CID) {
					return PublicationCarry{}, ErrPublicationCarry
				}
				entries = append(entries, publication.PayloadEntry{
					Path: entry.Path, Mode: entry.Mode,
					Size: uint64(len(entry.Content)), Content: bytes.Clone(entry.Content),
				})
			}
			carry.Entries[id] = entries
		case publication.SegmentFormSettings:
			if len(carried.Blob) != 0 || len(carried.Entries) != 0 {
				return PublicationCarry{}, ErrPublicationCarry
			}
		default:
			return PublicationCarry{}, ErrPublicationCarry
		}
		carry.Segments = append(carry.Segments, segment)
	}
	sort.Slice(carry.Segments, func(left, right int) bool {
		return carry.Segments[left].Target.ID < carry.Segments[right].Target.ID
	})
	return carry, nil
}

func publicationDropRefusal(
	drop []string,
	accepted publication.SnapshotRecord,
	configuration config.Config,
) error {
	if len(drop) == 0 {
		return nil
	}
	published := make(map[string]struct{}, len(accepted.Segments))
	for _, segment := range accepted.Segments {
		published[segment.Target.ID] = struct{}{}
	}
	for index, id := range drop {
		if id == "" {
			return ErrPublicationCarry
		}
		if index > 0 && drop[index-1] >= id {
			return ErrPublicationCarry
		}
		if _, ok := published[id]; !ok {
			return ErrPublicationCarry
		}
	}
	dropped := make(map[string]struct{}, len(drop))
	for _, id := range drop {
		dropped[id] = struct{}{}
	}
	union := 0
	for _, segment := range accepted.Segments {
		if _, ok := dropped[segment.Target.ID]; !ok {
			union++
		}
	}
	for _, target := range configuration.Targets {
		if _, ok := dropped[target.ID]; ok {
			continue
		}
		if _, ok := published[target.ID]; ok {
			continue
		}
		union++
	}
	if union == 0 {
		return ErrPublicationCarry
	}
	return nil
}

func publicationDropSet(drop []string) map[string]struct{} {
	dropped := make(map[string]struct{}, len(drop))
	for _, id := range drop {
		dropped[id] = struct{}{}
	}
	return dropped
}

func publicationConfigurationWithout(configuration config.Config, drop []string) config.Config {
	if len(drop) == 0 {
		return configuration
	}
	dropped := publicationDropSet(drop)
	targets := make([]config.Target, 0, len(configuration.Targets))
	for _, target := range configuration.Targets {
		if _, ok := dropped[target.ID]; ok {
			continue
		}
		targets = append(targets, target)
	}
	configuration.Targets = targets
	return configuration
}

func ValidatePublicationDrop(
	drop []string,
	recordRaw []byte,
	configuration config.Config,
) error {
	if len(drop) == 0 {
		return nil
	}
	record, err := publication.DecodeSnapshot(recordRaw)
	if err != nil {
		return ErrPublicationCarry
	}
	return publicationDropRefusal(drop, record, configuration)
}

func PublicationConfigurationWithoutDrop(configuration config.Config, drop []string) config.Config {
	return publicationConfigurationWithout(configuration, drop)
}

func PublicationCarryOfRecord(
	recordRaw []byte,
	configuration config.Config,
	drop []string,
) (PublicationCarry, error) {
	record, err := publication.DecodeSnapshot(recordRaw)
	if err != nil {
		return PublicationCarry{}, ErrPublicationCarry
	}
	carry := PublicationCarry{
		Payloads: make(map[string][]byte, len(record.Segments)),
		Entries:  make(map[string][]publication.PayloadEntry, len(record.Segments)),
	}
	configured := make(map[string]struct{}, len(configuration.Targets))
	for _, target := range configuration.Targets {
		configured[target.ID] = struct{}{}
	}
	dropped := publicationDropSet(drop)
	for _, segment := range record.Segments {
		if _, ok := configured[segment.Target.ID]; ok {
			continue
		}
		if _, ok := dropped[segment.Target.ID]; ok {
			continue
		}
		carry.Segments = append(carry.Segments, segment)
	}
	return carry, nil
}

func PublicationCarryOfAccepted(
	acceptedRecordRaw []byte,
	material publicationstate.AcceptedMaterial,
	configuration config.Config,
	drop []string,
) (PublicationCarry, error) {
	if len(acceptedRecordRaw) == 0 {
		return PublicationCarry{}, ErrPublicationCarry
	}
	record, err := publication.DecodeSnapshot(acceptedRecordRaw)
	if err != nil {
		return PublicationCarry{}, ErrPublicationCarry
	}
	return publicationCarryOf(record, material, configuration, drop)
}
