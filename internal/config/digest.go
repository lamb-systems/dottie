package config

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

const (
	selectionDigestTag = "dottie/config/selection/v1"
	approvalDigestTag  = "dottie/config/approval/v1"
)

type DigestRevision struct {
	Digest   [32]byte
	Revision uint64
}

type digestWriter struct {
	buffer []byte
}

func (writer *digestWriter) text(value string) {
	writer.length(uint64(len(value)))
	writer.buffer = append(writer.buffer, value...)
}

func (writer *digestWriter) length(value uint64) {
	var encoded [binary.MaxVarintLen64]byte
	written := binary.PutUvarint(encoded[:], value)
	writer.buffer = append(writer.buffer, encoded[:written]...)
}

func (writer *digestWriter) number(value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writer.buffer = append(writer.buffer, encoded[:]...)
}

func (writer *digestWriter) present(value bool) {
	if value {
		writer.buffer = append(writer.buffer, 1)
		return
	}
	writer.buffer = append(writer.buffer, 0)
}

func selectionDigest(c Config) [32]byte {
	writer := &digestWriter{}
	writer.text(selectionDigestTag)
	writer.text(string(defaultMode(c.Defaults)))
	targets := sortedTargets(c.Targets)
	writer.length(uint64(len(targets)))
	for _, target := range targets {
		writer.text(target.ID)
		writer.text(string(target.Source))
		writer.text(string(target.ModeOrDefault(c.Defaults)))
		writer.present(target.Root != nil)
		if target.Root != nil {
			writer.text(string(target.Root.Base))
			writer.text(target.Root.Path)
			writer.text(string(target.Root.Kind))
			excludes := canonicalList(target.Root.Exclude)
			writer.length(uint64(len(excludes)))
			for _, exclude := range excludes {
				writer.text(exclude)
			}
		}
		writer.present(target.GNOMEPolicy != nil)
		if target.GNOMEPolicy != nil {
			writer.text(string(target.GNOMEPolicy.Approval))
			categories := canonicalList(target.GNOMEPolicy.Categories)
			writer.length(uint64(len(categories)))
			for _, category := range categories {
				writer.text(category)
			}
			writer.number(uint64(target.GNOMEPolicy.MatrixVersion))
			writer.text(target.GNOMEPolicy.KeyDigest)
		}
	}
	return sha256.Sum256(writer.buffer)
}

func approvalDigest(c Config) [32]byte {
	writer := &digestWriter{}
	writer.text(approvalDigestTag)
	writer.length(uint64(len(policies(c.Targets))))
	for _, target := range policies(c.Targets) {
		writer.text(target.ID)
		writer.text(string(target.GNOMEPolicy.Approval))
		categories := canonicalList(target.GNOMEPolicy.Categories)
		writer.length(uint64(len(categories)))
		for _, category := range categories {
			writer.text(category)
		}
		writer.number(uint64(target.GNOMEPolicy.MatrixVersion))
		writer.text(target.GNOMEPolicy.KeyDigest)
	}
	return sha256.Sum256(writer.buffer)
}

func sortedTargets(targets []Target) []Target {
	sorted := append([]Target(nil), targets...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].ID < sorted[right].ID })
	return sorted
}

func policies(targets []Target) []Target {
	withPolicy := make([]Target, 0, len(targets))
	for _, target := range sortedTargets(targets) {
		if target.GNOMEPolicy != nil {
			withPolicy = append(withPolicy, target)
		}
	}
	return withPolicy
}

func canonicalList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	unique := sorted[:1]
	for _, value := range sorted[1:] {
		if value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	return unique
}

func defaultMode(defaults Defaults) Mode {
	if defaults.Mode != "" {
		return defaults.Mode
	}
	return Review
}
